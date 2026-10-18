#!/usr/bin/env python3
"""What selectors a deployed runtime dispatches on, and what they are probably called.

Deployed code whose source is not published is a documented blind spot: there is nothing to
read, so nothing gets reviewed. The dispatcher is the one part of such a runtime that can be
read back mechanically - it has to compare the incoming 4-byte selector against a constant for
every externally callable function - so this module recovers that list of constants and names
the ones that match a known signature.

What this is NOT: a selector is not proof that a function is reachable (a guard, a role check,
a paused flag or an unconditional revert can sit one instruction later), it is not proof of what
the function does, and it carries no severity. A name is a hypothesis: it says only that a known
signature hashes to the same four bytes.

The extraction is a local pattern match over decoded opcodes, not a decompiler. It reads what
the compilers it knows emit, and `notes` records what it could not account for.

The file is evm_selectors.py because a module named `selectors` beside these scripts shadows the
standard library module of that name, which subprocess imports: with that filename every script
in this directory stops starting. The CLI command is still `bounty.py selectors`.
"""
import importlib.util
from pathlib import Path


def load_keccak():
    """The bundled pure-stdlib keccak256, so naming a selector needs no install."""
    path = Path(__file__).resolve().parent / 'keccak.py'
    spec = importlib.util.spec_from_file_location('bp_keccak', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# runtime bytecode primitives
#
# bounty.py's compare_bytecode and this module need the same answers to "is this hex
# bytecode" and "where does the code section end", so the rules live here once and
# bounty.py calls them. Duplicating them is how a metadata tail gets stripped in one
# place and compared in the other.
# --------------------------------------------------------------------------- #

def code_bytes(code):
    if isinstance(code, (bytes, bytearray)):
        return bytes(code)
    text = code[2:] if code.startswith('0x') else code
    try:
        return bytes.fromhex(text)
    except ValueError:
        raise ValueError('bytecode is not hex - an unlinked library placeholder with no '
                         'linkReferences in the artifact, or not bytecode at all')


# solc appends a CBOR map then its own 2-byte big-endian length. The map starts with a
# CBOR major-type-5 header (0xa1..0xaf for 1..15 pairs) and names its hash algorithm.
METADATA_MARKERS = (b'solc', b'ipfs', b'bzzr0', b'bzzr1')
METADATA_MIN_BYTES = 0x20


def strip_metadata(code_hex):
    """Remove the trailing solc CBOR metadata, and only if the tail really is that.

    Stripping on the trailing length alone makes unrelated bytecodes compare equal: any two
    runtimes ending in the same small number would have their differing bodies cut away. So the
    tail must look like solc metadata before a single byte is removed.
    """
    raw = code_bytes(code_hex)
    if len(raw) < METADATA_MIN_BYTES + 2:
        return raw, 0
    length = int.from_bytes(raw[-2:], 'big')
    if not METADATA_MIN_BYTES <= length <= len(raw) - 2:
        return raw, 0
    blob = raw[-(length + 2):-2]
    if not blob or not 0xa1 <= blob[0] <= 0xaf:
        return raw, 0
    if not any(marker in blob for marker in METADATA_MARKERS):
        return raw, 0
    return raw[:-(length + 2)], length + 2


def instructions(raw):
    """Yield (pc, opcode, push operand), stepping over PUSH data so it never reads as code.

    A PUSH operand is data: decoding it as opcodes invents instructions that no execution ever
    reaches, which is how a 0x63 byte inside a constant turns into a selector comparison.
    """
    pc = 0
    while pc < len(raw):
        op = raw[pc]
        width = op - 0x5f if 0x60 <= op <= 0x7f else 0
        yield pc, op, raw[pc + 1:pc + 1 + width]
        pc += 1 + width


# --------------------------------------------------------------------------- #
# dispatcher extraction
# --------------------------------------------------------------------------- #

OP_PUSH0, OP_PUSH2, OP_PUSH4, OP_PUSH32 = 0x5f, 0x61, 0x63, 0x7f
OP_SUB, OP_LT, OP_GT, OP_EQ, OP_ISZERO, OP_XOR, OP_SHR, OP_DIV = (
    0x03, 0x10, 0x11, 0x14, 0x15, 0x18, 0x1c, 0x04)
OP_CALLDATALOAD, OP_CALLDATASIZE, OP_CALLVALUE, OP_POP = 0x35, 0x36, 0x34, 0x50
OP_AND, OP_OR = 0x16, 0x17
OP_JUMP, OP_JUMPI, OP_JUMPDEST = 0x56, 0x57, 0x5b
OP_CODECOPY = 0x39
OP_REVERT, OP_INVALID = 0xfd, 0xfe
# How a dispatcher tests the selector it loaded. solc's leaves use EQ; via_ir's last leaf
# subtracts and jumps when the difference is non-zero; Vyper asks the same question with XOR,
# sometimes negated by ISZERO. Its optimised binary search compares against a pivot with GT (or
# LT) and jumps to the matching half: a pivot is not itself a dispatched value, so the two kinds
# of comparison are counted apart.
EQUALITY_OPS = {OP_EQ: 'eq', OP_SUB: 'sub', OP_XOR: 'xor'}
PIVOT_OPS = {OP_GT: 'gt', OP_LT: 'lt'}
# Neither 0x00000000 nor 0xffffffff is a function selector here: the first is the zero word a
# dispatcher compares against to detect empty calldata, the second is the mask a compiler uses
# to cut four bytes out of a word.
NOT_SELECTORS = (0x00000000, 0xffffffff)
# A PUSH4 and its comparison can be separated by stack shuffling, and the comparison from its
# JUMPI by an ISZERO and the push of the destination. Both windows are deliberately short: the
# wider they are, the more ordinary arithmetic on a 4-byte constant reads as a dispatch.
SHUFFLE_WINDOW = 2
BRANCH_WINDOW = 8
# What may stand between the comparison and the jump. Vyper folds the argument calldata-size
# check into the same condition - `EQ PUSH1 0x03 CALLDATASIZE GT AND ISZERO PUSH2 dest JUMPI` -
# so those guard operations are allowed; anything else ends the match, because a comparison
# whose result is used for arithmetic was not deciding where to dispatch.
BRANCH_OPS = (OP_ISZERO, OP_CALLDATASIZE, OP_CALLVALUE, OP_AND, OP_OR, OP_GT, OP_LT)
# A selector with a leading zero byte is pushed in fewer bytes - solc emits `PUSH3 0x18eaa8`
# for 0x0018eaa8 - so narrower pushes have to be read too. On their own they are ordinary small
# constants, which is why one counts only inside the dispatcher: next to a comparison the same
# shape already matched, or just after an instruction that loads the selector. The window is
# measured in instructions and has to clear the `JUMPI PUSH0 DUP1 REVERT JUMPDEST DUP1` that
# the optimiser puts between two leaf blocks, which is nine.
NARROW_PUSH_WINDOW = 12
# How far a tail-function path is followed through unconditional jumps, and how many
# instructions of a block are read before deciding it is not an immediate revert.
JUMP_HOPS = 4
BLOCK_WINDOW = 8
# A runtime can hold more than one dispatcher: solc appends the creation code of every contract
# this one deploys, and that carries the deployed contract's own dispatcher as data. Comparisons
# this far apart (counted in instructions) belong to different regions, and a later region that
# loads a selector of its own is a second dispatcher, not a continuation of the first.
REGION_GAP = 96
REGION_ANCHOR_WINDOW = 40
# Vyper >= 0.3.4 can dispatch through a table it copies out of its own code with CODECOPY,
# instead of comparing the selector against constants. How far after the selector load that
# copy may appear before it stops looking like one dispatcher.
TABLE_WINDOW = 12

NOTICE = (
    'This is the list of 4-byte values the runtime\'s dispatcher compares calldata against. '
    'It is not proof that any of them is reachable - a role check, a pause flag or a plain '
    'revert can sit one instruction after the jump - it says nothing about what the code does, '
    'and it establishes no severity. An unknown selector may be a function whose name is simply '
    'not published, an internal dispatch target, or a non-standard entry point. Naming is done '
    'by matching known signatures, so every name here is a hypothesis to confirm against source '
    'or against on-chain behaviour.')
EXTRACTION_LIMITS = (
    'extraction reads the dispatch shapes solc and Vyper emit; a hand-written assembly '
    'dispatcher, a selector held in a data table, and a selector computed at runtime are not '
    'visible to it. The dispatcher name is the shape that was recognised, not proof of which '
    'compiler produced the code: unoptimised Vyper compares selectors the same way solc does')


def _is_shuffle(op):
    return 0x80 <= op <= 0x9f          # DUP1..DUP16, SWAP1..SWAP16


def _is_push(op):
    return OP_PUSH0 <= op <= OP_PUSH32


def _selector_loads(ops):
    """Indices of the instructions that load a selector, so where a dispatcher may start.

    A dispatcher reads calldata at offset zero and moves the top four bytes down - with SHR, or
    a division by 2**224 in older output. Both halves count on their own, because via_ir
    compiles the shift into a block of its own, a jump away from the read. Neither is the same
    as reading calldata at an offset, which is how every function decodes its arguments: that
    distinction is what keeps Vyper's per-function selector checks from reading as a dispatcher
    of their own.
    """
    loads = []
    for index, (pc, op, data) in enumerate(ops):
        if op == OP_CALLDATALOAD and index:
            before, operand = ops[index - 1][1], ops[index - 1][2]
            if before == OP_PUSH0 or (_is_push(before) and not int.from_bytes(operand, 'big')):
                loads.append(index)
        elif op in (OP_SHR, OP_DIV) and index and _is_push(ops[index - 1][1]):
            shift = int.from_bytes(ops[index - 1][2], 'big') if ops[index - 1][2] else 0
            if shift in (0xe0, 1 << 224):
                loads.append(index)
    return loads


def _jump_table(ops, loads):
    """True when the selector is used to index a table copied out of the code itself.

    Vyper's optimised dispatchers read a jump destination - and, in its densest form, the
    selector to compare against - from a table in the code section. Those selectors are data,
    so no opcode walk can report them; recognising the shape is what turns an empty selector
    list into an explained one.
    """
    for start in loads:
        for ahead in range(start + 1, min(start + 1 + TABLE_WINDOW, len(ops))):
            if ops[ahead][1] == OP_CODECOPY:
                return True
    return False


def _candidates(ops, anchors):
    """Every pushed value whose neighbouring opcodes form a dispatch comparison.

    Shape: the constant, optional stack shuffling, a comparison, then a conditional jump.
    Requiring the JUMPI is what keeps a `bytes4` constant compared inside a function body - an
    ERC-165 interface id, say - out of the list: that comparison feeds a boolean, and Solidity
    keeps such a constant left-aligned (shifted up by 224 bits), not as a bare PUSH4.

    A two- or three-byte push can still be a selector that has leading zero bytes, but on its
    own it is an ordinary small constant, so it counts only inside a dispatcher - see
    _in_dispatcher. A one-byte push is never read as a selector: comparing a small number and
    branching on it is everywhere in compiled code, while a selector below 0x00000100 is a
    one-in-sixteen-million coincidence. Measured on the corpus, reading one-byte pushes as
    selectors was the only source of false positives there.
    """
    found = []
    for index, (pc, op, data) in enumerate(ops):
        if not (OP_PUSH2 <= op <= OP_PUSH4) or len(data) != op - 0x5f:
            continue
        value = int.from_bytes(data, 'big')
        if value in NOT_SELECTORS:
            continue
        step = index + 1
        while step < len(ops) and step - index <= SHUFFLE_WINDOW and _is_shuffle(ops[step][1]):
            step += 1
        if step >= len(ops):
            continue
        compare = ops[step][1]
        kind = EQUALITY_OPS.get(compare) or PIVOT_OPS.get(compare)
        if kind is None:
            continue
        negated, branch = False, False
        for ahead in range(step + 1, min(step + 1 + BRANCH_WINDOW, len(ops))):
            op_ahead = ops[ahead][1]
            if op_ahead == OP_JUMPI:
                branch = True
                break
            if op_ahead == OP_ISZERO:
                negated = True
            elif not (_is_shuffle(op_ahead) or _is_push(op_ahead) or op_ahead in BRANCH_OPS):
                break
        if branch:
            found.append({'pc': pc, 'index': index, 'value': value, 'kind': kind,
                          'negated': negated, 'width': op - 0x5f})
    return _in_dispatcher(found, anchors)


def _in_dispatcher(found, anchors):
    """Drop narrow pushes that are not part of a dispatch chain.

    A four-byte push that is compared and branched on is taken as it stands. A narrower one is
    kept only where a dispatcher actually is: just after the instruction that loads the
    selector, or next to another accepted comparison - which is how a run of leading-zero
    selectors at the start of a chain joins the four-byte leaves that follow it.
    """
    kept = [item['width'] == 4
            or any(0 <= item['index'] - anchor <= NARROW_PUSH_WINDOW for anchor in anchors)
            for item in found]
    growing = True
    while growing:
        growing = False
        for position, item in enumerate(found):
            if kept[position]:
                continue
            for neighbour in (position - 1, position + 1):
                if not 0 <= neighbour < len(found) or not kept[neighbour]:
                    continue
                if abs(item['index'] - found[neighbour]['index']) <= NARROW_PUSH_WINDOW:
                    kept[position] = growing = True
                    break
    return [item for position, item in enumerate(found) if kept[position]]


def _dispatch_regions(found, anchors):
    """Split the comparisons into this address's own dispatcher and any later dispatcher.

    The code that runs at an address starts at its first instruction, and both compilers put
    that dispatcher ahead of the function bodies, so the first region is the address's own. A
    later region means something different: a factory runtime carries the creation code of what
    it deploys, and the selectors in there belong to the deployed contract. Such a region is
    separated only when it loads a selector out of the first calldata word itself -
    otherwise it stays in the first, because dropping a real selector is the worse mistake of
    the two, and Vyper tests the selector inside each function block, right next to the
    ordinary calldata reads that decode its arguments.
    """
    groups = []
    for item in found:
        if groups and item['index'] - groups[-1][-1]['index'] <= REGION_GAP:
            groups[-1].append(item)
        else:
            groups.append([item])
    primary = list(groups[0]) if groups else []
    secondary = []
    for group in groups[1:]:
        low, high = group[0]['index'], group[-1]['index']
        own_load = any(low - REGION_ANCHOR_WINDOW <= anchor <= high for anchor in anchors)
        if own_load and any(item['kind'] in EQUALITY_OPS.values() for item in group):
            secondary.append(group)
        else:
            primary.extend(group)
    return primary, secondary


def _selector_hex(value):
    return '0x' + format(value, '08x')


def _block_is_revert(ops, start, by_pc):
    """True when the block at this index does nothing but revert (through at most a few hops).

    Solidity ends a dispatcher that has no fallback with a bare revert block, so "the no-match
    path reverts" is the signal that no tail function exists. Only straight-line pushes and
    stack shuffling may precede the REVERT; anything else means code runs there.
    """
    for _ in range(JUMP_HOPS):
        if start is None or start >= len(ops):
            return False
        index, steps = start, 0
        while index < len(ops) and steps < BLOCK_WINDOW:
            op = ops[index][1]
            if op in (OP_REVERT, OP_INVALID):
                return True
            if op == OP_JUMP:                       # `PUSH <dest> JUMP` into a shared block
                target = _jump_target(ops, index)
                start = by_pc.get(target)
                break
            if not (_is_push(op) or _is_shuffle(op) or op in (OP_JUMPDEST, OP_POP)):
                return False
            index += 1
            steps += 1
        else:
            return False
    return False


def _jump_target(ops, index):
    """The constant a `PUSH <dest> JUMP/JUMPI` jumps to, or None when it is computed."""
    for back in range(index - 1, max(index - 3, -1), -1):
        op, data = ops[back][1], ops[back][2]
        if _is_push(op) and data:
            return int.from_bytes(data, 'big')
        if not _is_shuffle(op):
            break
    return None


def _tail_functions(ops, by_pc):
    """(has_fallback, has_receive), or (None, None) when the no-match path is not recognised.

    Both compilers guard the dispatcher with `calldatasize < 4`, because a shorter call cannot
    carry a selector. Where that branch leads is where unmatched calls go: a bare revert means
    neither tail function exists; a CALLDATASIZE test there separates `receive()` (empty
    calldata) from `fallback()`, so its presence is what distinguishes the two. A path this
    does not recognise is reported as unknown rather than guessed at.
    """
    for index, (pc, op, data) in enumerate(ops):
        if op != OP_CALLDATASIZE or index == 0:
            continue
        before = ops[index - 1]
        if not (_is_push(before[1]) and before[2] and int.from_bytes(before[2], 'big') == 4):
            continue
        step = index + 1
        if step >= len(ops) or ops[step][1] != OP_LT:
            continue
        step += 1
        inverted = step < len(ops) and ops[step][1] == OP_ISZERO
        if inverted:
            step += 1
        jumpi = step + 1
        if jumpi >= len(ops) or ops[jumpi][1] != OP_JUMPI or not _is_push(ops[step][1]):
            continue
        # The short-calldata path: the jump destination, or - when the condition was inverted,
        # as via_ir writes it - the instruction after the JUMPI.
        if inverted:
            short = jumpi + 1
        else:
            short = by_pc.get(int.from_bytes(ops[step][2], 'big'))
        return _classify_tail(ops, by_pc, short)
    return None, None


def _classify_tail(ops, by_pc, short):
    """Read the short-calldata block: revert, a CALLDATASIZE split, or plain code."""
    if short is None or short >= len(ops):
        return None, None
    if _block_is_revert(ops, short, by_pc):
        return False, False
    index, steps = short, 0
    while index < len(ops) and steps < BLOCK_WINDOW:
        op = ops[index][1]
        if op == OP_CALLDATASIZE:
            # `CALLDATASIZE [ISZERO] PUSH <dest> JUMPI`: one side is the receive, the other is
            # the fallback. A receive-only contract still needs this test, so no test at all
            # means any unmatched call - empty or not - lands in a fallback.
            step = index + 1
            negated = step < len(ops) and ops[step][1] == OP_ISZERO
            if negated:
                step += 1
            while step < len(ops) and _is_push(ops[step][1]):
                step += 1
            if step >= len(ops) or ops[step][1] != OP_JUMPI:
                return None, None
            jumped = by_pc.get(_jump_target(ops, step))
            fallback_side = step + 1 if negated else jumped
            return (not _block_is_revert(ops, fallback_side, by_pc)), True
        if op in (OP_JUMPDEST, OP_POP) or _is_push(op) or _is_shuffle(op):
            index += 1
            steps += 1
            continue
        if op == OP_JUMP:
            target = by_pc.get(_jump_target(ops, index))
            if target is None or target == short:
                return None, None
            return _classify_tail(ops, by_pc, target)
        return True, False            # unmatched calldata runs code: a fallback
    return None, None


def extract_selectors(runtime_hex):
    """Selectors the dispatcher of this runtime compares against, with how it dispatches.

    Method: decode the code section (the solc CBOR metadata, when present, is data and is cut
    off first), then keep every PUSH4 constant that a comparison and a conditional jump turn
    into a dispatch test. The equality forms - solc's `DUP1 PUSH4 sel EQ PUSH2 dest JUMPI`,
    via_ir's trailing `PUSH4 sel SUB ... JUMPI`, Vyper's `XOR/SUB ... ISZERO ... JUMPI` - name
    a selector. The GT/LT form does not: solc's optimised dispatcher binary-searches on a pivot
    and the leaves below it test equality, so the pivots are reported separately and a pivot
    reaches the selector list only by also appearing as an equality test.

    Values of 0x00000000 and 0xffffffff are never reported: the first is how a dispatcher tests
    for empty calldata, the second is a mask. A push of one byte is not read as a selector
    either, because comparing a small number and branching is ordinary compiled code.

    What it cannot see: a dispatcher written in assembly that the entry block does not reach, a
    jump table, a selector built at runtime, and a selector a fallback handles in ordinary
    Solidity. The last one is worth knowing by name: OpenZeppelin's transparent proxy compares
    `msg.sig` with the admin's `upgradeToAndCall` selector inside its fallback, and Solidity
    keeps a `bytes4` left-aligned there, so that entry point is real and is not in this list.
    A proxy runtime in general exposes almost nothing of what callers can reach, because
    everything a delegatecall forwards lives in the implementation. The result is a lead, and
    `notes` records what was left unaccounted for.
    """
    raw = code_bytes(runtime_hex)
    body, metadata = strip_metadata(raw)
    ops = list(instructions(body))
    by_pc = {op[0]: index for index, op in enumerate(ops)}
    anchors = _selector_loads(ops)
    found, later = _dispatch_regions(_candidates(ops, anchors), anchors)
    equality = {item['value'] for item in found if item['kind'] in EQUALITY_OPS.values()}
    pivots = {item['value'] for item in found if item['kind'] in PIVOT_OPS.values()}
    table = _jump_table(ops, anchors)
    # XOR is Vyper's way of asking "are these equal"; solc emits EQ, and a single trailing SUB
    # in its via_ir output. A table dispatch is Vyper's too. Equality and GT/LT pivots are the
    # shapes both compilers share, so on their own they only say "solc-shaped".
    vyper_shaped = sum(1 for item in found if item['kind'] == 'xor') + (1 if table else 0)
    solc_shaped = sum(1 for item in found if item['kind'] in ('eq', 'sub'))
    notes = [EXTRACTION_LIMITS]
    if not body:
        notes.append('no runtime code: nothing is deployed at this code, or it is all metadata')
    if metadata:
        notes.append(f'{metadata} trailing bytes are solc metadata, not code')
    secondary = []
    for group in later:
        values = {item['value'] for item in group if item['kind'] in EQUALITY_OPS.values()}
        secondary.append({'from_pc': group[0]['pc'],
                          'selectors': sorted(_selector_hex(value) for value in values)})
    if secondary:
        notes.append('%d further dispatch region(s), each loading a selector of its own, sit '
                     'later in this runtime and are reported under secondary_dispatch rather '
                     'than counted above: the creation code of a contract this one deploys '
                     '(whose selectors belong to that contract, not to this address), or a '
                     'second dispatch this code runs itself, such as an assembly fallback. '
                     'Reading the code is the only way to tell which' % len(secondary))
    if pivots - equality:
        # Every pivot solc picks is one of the real selectors, so this is an anomaly worth
        # seeing rather than something to silently resolve either way.
        notes.append('%d value(s) are compared with GT/LT but never for equality, so they are '
                     'reported as pivots only: %s'
                     % (len(pivots - equality),
                        ', '.join(sorted(_selector_hex(v) for v in pivots - equality))))
    if vyper_shaped and pivots:
        dispatcher = 'mixed'
    elif vyper_shaped:
        dispatcher = 'vyper'
    elif pivots and solc_shaped:
        dispatcher = 'solc-binary-search'
    elif solc_shaped:
        dispatcher = 'solc-linear'
    else:
        dispatcher = 'unknown'
    if table:
        notes.append('the selector indexes a table this runtime copies out of its own code '
                     '(Vyper\'s optimised dispatch): the entries are data, not instructions, so '
                     'any selector held only in that table is missing from the list above. '
                     'Compiled for small code size, that is every selector'
                     + (' - and nothing was extracted here, so treat this list as empty rather '
                        'than as "no external functions"' if not equality else ''))
    if dispatcher == 'unknown' and body:
        notes.append('no dispatch comparison was recognised: a runtime with no external '
                     'functions (a forwarder, a library, a minimal clone), or a dispatcher '
                     'this does not read')
    has_fallback, has_receive = _tail_functions(ops, by_pc)
    if has_fallback is None:
        notes.append('the path taken by calldata that matches no selector was not recognised, '
                     'so fallback() and receive() are unknown here; the ABI or the source is '
                     'the authority on both')
    return {'selectors': sorted(_selector_hex(value) for value in equality),
            'count': len(equality),
            'dispatcher': dispatcher,
            'has_fallback': has_fallback,
            'has_receive': has_receive,
            'pivots': sorted(_selector_hex(value) for value in pivots),
            'secondary_dispatch': secondary,
            'code_section_bytes': len(body),
            'metadata_bytes': metadata,
            'notes': notes,
            'notice': NOTICE}


# --------------------------------------------------------------------------- #
# selectors from an ABI
# --------------------------------------------------------------------------- #

def canonical_type(entry):
    """The canonical ABI type of one input, with tuples expanded as the signature spells them.

    A struct is `(type,type)` in a signature, nested structs nest, and an array suffix stays on
    the outside: `(uint256,(address,bool))[2][]`. The name of the struct never appears.
    """
    if not isinstance(entry, dict):
        raise ValueError('an ABI input must be an object')
    declared = entry.get('type')
    if not isinstance(declared, str) or not declared:
        raise ValueError('an ABI input must carry a type')
    if not declared.startswith('tuple'):
        return declared
    suffix = declared[len('tuple'):]
    components = entry.get('components')
    if components is None:
        components = []
    if not isinstance(components, list):
        raise ValueError('tuple components must be a list')
    return '(' + ','.join(canonical_type(item) for item in components) + ')' + suffix


def canonical_signature(entry):
    """`name(type,type)` for one ABI function entry, or None when it is not a function.

    Only `function` entries have a selector. An event has a topic, an error has a 4-byte
    identifier of its own, and constructor/fallback/receive are never dispatched by selector.
    The ABI spec's default for a missing `type` is `function`.
    """
    if not isinstance(entry, dict):
        return None
    if entry.get('type', 'function') != 'function':
        return None
    name = entry.get('name')
    if not isinstance(name, str) or not name:
        raise ValueError('an ABI function entry must carry a name')
    inputs = entry.get('inputs')
    if inputs is None:
        inputs = []
    if not isinstance(inputs, list):
        raise ValueError('ABI inputs must be a list')
    return name + '(' + ','.join(canonical_type(item) for item in inputs) + ')'


def selectors_from_signatures(signatures):
    """{selector: signature} for canonical signatures, hashed with the bundled keccak.

    Two different signatures can in principle hash to the same four bytes; both are kept in
    the name, because dropping one would hide the collision from whoever reads the output.
    """
    keccak = load_keccak()
    out = {}
    for signature in signatures:
        text = ''.join(str(signature).split())
        if '(' not in text or not text.endswith(')'):
            raise ValueError('not a canonical signature: ' + str(signature)[:60])
        selector = keccak.selector(text)
        if selector in out and text not in out[selector].split(' / '):
            out[selector] = out[selector] + ' / ' + text
        else:
            out.setdefault(selector, text)
    return dict(sorted(out.items()))


def selectors_from_abi(abi):
    """{selector: signature} for every function in an ABI (a list, or an artifact holding one)."""
    if isinstance(abi, dict):
        for key in ('abi', 'ABI'):
            if isinstance(abi.get(key), list):
                abi = abi[key]
                break
        else:
            raise ValueError('this JSON object carries no "abi" array')
    if not isinstance(abi, list):
        raise ValueError('an ABI is a JSON array of entries')
    signatures = []
    for entry in abi:
        signature = canonical_signature(entry)
        if signature:
            signatures.append(signature)
    return selectors_from_signatures(signatures)


def abi_tail_functions(abi):
    """(has_fallback, has_receive) as the ABI declares them; for comparison, not for proof."""
    if isinstance(abi, dict):
        abi = abi.get('abi') if isinstance(abi.get('abi'), list) else []
    if not isinstance(abi, list):
        return False, False
    kinds = {entry.get('type') for entry in abi if isinstance(entry, dict)}
    return 'fallback' in kinds, 'receive' in kinds


# --------------------------------------------------------------------------- #
# naming
#
# Every selector below is derived from its signature at runtime with the bundled keccak.
# A pasted hex selector is a constant nobody can check; a derived one is wrong only if
# the signature is wrong, and that is visible.
# --------------------------------------------------------------------------- #

KNOWN_SIGNATURES = {
    'erc20': ('totalSupply()', 'balanceOf(address)', 'transfer(address,uint256)',
              'transferFrom(address,address,uint256)', 'approve(address,uint256)',
              'allowance(address,address)', 'name()', 'symbol()', 'decimals()',
              'mint(address,uint256)', 'burn(uint256)', 'burnFrom(address,uint256)',
              'increaseAllowance(address,uint256)', 'decreaseAllowance(address,uint256)'),
    'erc721': ('ownerOf(uint256)', 'getApproved(uint256)', 'setApprovalForAll(address,bool)',
               'isApprovedForAll(address,address)', 'safeTransferFrom(address,address,uint256)',
               'safeTransferFrom(address,address,uint256,bytes)',
               'tokenURI(uint256)', 'tokenOfOwnerByIndex(address,uint256)',
               'tokenByIndex(uint256)', 'safeMint(address,uint256)',
               'onERC721Received(address,address,uint256,bytes)'),
    'erc1155': ('balanceOf(address,uint256)', 'balanceOfBatch(address[],uint256[])',
                'uri(uint256)', 'safeTransferFrom(address,address,uint256,uint256,bytes)',
                'safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)',
                'onERC1155Received(address,address,uint256,uint256,bytes)',
                'onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)'),
    'erc4626': ('asset()', 'totalAssets()', 'convertToShares(uint256)',
                'convertToAssets(uint256)', 'maxDeposit(address)', 'previewDeposit(uint256)',
                'deposit(uint256,address)', 'maxMint(address)', 'previewMint(uint256)',
                'mint(uint256,address)', 'maxWithdraw(address)', 'previewWithdraw(uint256)',
                'withdraw(uint256,address,address)', 'maxRedeem(address)',
                'previewRedeem(uint256)', 'redeem(uint256,address,address)'),
    'erc165': ('supportsInterface(bytes4)',),
    'ownable': ('owner()', 'transferOwnership(address)', 'renounceOwnership()',
                'pendingOwner()', 'acceptOwnership()'),
    'access-control': ('hasRole(bytes32,address)', 'getRoleAdmin(bytes32)',
                       'grantRole(bytes32,address)', 'revokeRole(bytes32,address)',
                       'renounceRole(bytes32,address)', 'DEFAULT_ADMIN_ROLE()',
                       'getRoleMember(bytes32,uint256)', 'getRoleMemberCount(bytes32)'),
    'pausable': ('paused()', 'pause()', 'unpause()'),
    'proxy-upgrade': ('implementation()', 'upgradeTo(address)', 'upgradeToAndCall(address,bytes)',
                      'proxiableUUID()', 'UPGRADE_INTERFACE_VERSION()', 'admin()',
                      'changeAdmin(address)', 'upgradeAndCall(address,address,bytes)',
                      'masterCopy()', 'comptrollerImplementation()', 'initialize()'),
    'permit': ('permit(address,address,uint256,uint256,uint8,bytes32,bytes32)',
               'DOMAIN_SEPARATOR()', 'nonces(address)', 'eip712Domain()'),
    'erc1271': ('isValidSignature(bytes32,bytes)', 'isValidSignature(bytes,bytes)'),
    'multicall': ('multicall(bytes[])', 'multicall(uint256,bytes[])',
                  'multicall(bytes32,bytes[])', 'aggregate((address,bytes)[])'),
}


def known_signatures():
    """{selector: {'name': signature, 'standard': group}} for the built-in table."""
    out = {}
    for standard, signatures in KNOWN_SIGNATURES.items():
        for selector, signature in selectors_from_signatures(signatures).items():
            if selector not in out:
                out[selector] = {'name': signature, 'standard': standard}
    return out


def name_selectors(selectors, extra=None):
    """[{selector, name?, standard?}] for each selector, named from the table and `extra`.

    `extra` is {selector: signature} from an ABI or a signature file the hunter supplied; it
    wins over the built-in table, because it describes this very contract.
    """
    table = known_signatures()
    out = []
    for selector in selectors:
        item = {'selector': selector}
        supplied = (extra or {}).get(selector)
        if supplied:
            item['name'] = supplied
            item['source'] = 'supplied'
        elif selector in table:
            item['name'] = table[selector]['name']
            item['standard'] = table[selector]['standard']
            item['source'] = 'known-signature-table'
        out.append(item)
    return out


def diff_selectors(onchain, known):
    """What the chain dispatches and the ABI does not, and the other way round.

    `only_onchain` is the interesting half: an entry point that no published interface mentions.
    `only_known` is an ABI function the deployed dispatcher does not compare against - a
    different build, an abstract or inherited declaration that was never deployed, or a
    function reached only through something this extraction cannot read.
    """
    live, declared = set(onchain), set(known)
    shared = sorted(live & declared)
    only_onchain, only_known = sorted(live - declared), sorted(declared - live)
    return {'only_onchain': only_onchain, 'only_known': only_known, 'shared': shared,
            'counts': {'onchain': len(live), 'known': len(declared), 'shared': len(shared),
                       'only_onchain': len(only_onchain), 'only_known': len(only_known)}}
