#!/usr/bin/env python3
"""Read the deployed configuration of a protocol at one block, and flag the shapes that lost money.

Source review never sees configuration. The contract is correct; the value someone set on it after
deployment is not. The largest 2025-2026 losses reported publicly were of this kind, and every one
of them is a single storage read away from being visible:

- **KelpDAO, Apr 2026 (~$292M, as reported).** A LayerZero OApp whose receive-side ULN config
  required a single DVN - 1-of-1 verification - so one poisoned verifier was enough to forge an
  inbound message. `layerzero-oapp` reads `getReceiveLibrary` and `getConfig(.., 2)` and flags
  `requiredDVNCount + optionalDVNThreshold <= 1`.
- **CrossCurve, Feb 2026.** A cross-chain receiver with a confirmation threshold of one.
  **Bonzo, Jul 2026.** A pull-oracle verifier that accepted zero signatures. Both are a protocol
  specific getter: `getter` reads it and flags the threshold.
- **Resolv, Mar 2026.** A privileged mint with no on-chain cap: `getter` on the cap, flag 0 or
  uint256 max.
- **Drift, Apr 2026 (~$285M, as reported).** A 2-of-5 multisig with no timelock in front of it:
  `safe` flags a threshold that is half the owners or fewer, `timelock` flags a zero delay.
- **Term Finance, Aug 2026.** Governance quorum denominated in a wrapped supply: `getter` reads
  `quorum(block)` beside the token's `totalSupply()`.
- **Troves, Oct 2026.** A replaced rebalancer that kept its vault permissions: `access-control`
  rebuilds role membership from `RoleGranted`/`RoleRevoked` logs and flags a member that is not in
  the declared architecture.
- **Moonwell, Aug 2026 / Tectonic, Aug 2026.** A high collateral factor on illiquid collateral:
  `getter` on the market's risk parameters.

Loss figures and attributions are approximate and get revised; a report cites the protocol's own
post-mortem, never this docstring.

**Every flag is a lead.** A config value is read at one pinned block, and many programs exclude
admin, centralisation and trusted-role misuse outright. A configuration lead is reportable only
where an *unprivileged* actor gains from it, or where the program explicitly pays for
misconfiguration; read `program.json`'s exclusions before writing a word. Never act on a flag
against a live system. `references/config-snapshot.md` has the target format and triage path.

Only read-only JSON-RPC methods are ever sent (`READ_ONLY_METHODS`); nothing is signed or sent.
**The RPC URL is an argument only**: the output says `"endpoint": "not recorded"`, and the URL and
its bare hostname are scrubbed out of every error string, as `capability-probe` does.

Selectors, event topics and storage slots are **derived** from their signatures with the bundled
keccak, never pasted; the tests assert a few of them equal the published values.
"""
import argparse
import importlib.util
import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

SCHEMA_VERSION = 1

READ_ONLY_METHODS = frozenset({
    'eth_chainId', 'eth_blockNumber', 'eth_call', 'eth_getCode', 'eth_getStorageAt',
    'eth_getLogs', 'eth_getBalance', 'eth_getBlockByNumber',
})

KINDS = ('safe', 'timelock', 'ownable', 'access-control', 'erc1967-proxy', 'layerzero-oapp',
         'chainlink-feed', 'getter')

NOTICE = (
    'Values are read at one pinned block and may differ at any other. Every flag is a lead, not a '
    'finding. Many programs exclude admin/centralisation issues and trusted-role misuse; a '
    'configuration lead is reportable only where an UNPRIVILEGED actor gains, or where the '
    'program explicitly pays for misconfiguration - check program.json exclusions first. Prove '
    'it at a pinned block and in a fork test. Never act on a flag against a live system.'
)

ZERO_ADDRESS = '0x' + '0' * 40
UINT256_MAX = 2 ** 256 - 1
LOG_MAX_RANGE = 50_000
LOG_MAX_CHUNKS = 200
LOG_SPLIT_DEPTH = 3
RPC_TIMEOUT = 30
ULN_CONFIG_TYPE = 2
NIL_DVN_COUNT = 255   # LayerZero ULN: an explicit "zero DVNs" in a custom config


def load_keccak():
    """The bundled pure-stdlib keccak256; hashlib.sha3_256 uses different padding."""
    path = Path(__file__).resolve().parent / 'keccak.py'
    spec = importlib.util.spec_from_file_location('bp_keccak', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_KECCAK = load_keccak()


def selector(signature):
    return _KECCAK.selector(signature)


def topic(signature):
    return _KECCAK.keccak_hex(''.join(signature.split()))


def slot_minus_one(label):
    """bytes32(uint256(keccak256(label)) - 1), the EIP-1967 slot rule."""
    return '0x' + format(int.from_bytes(_KECCAK.keccak256(label), 'big') - 1, '064x')


def slot_plain(label):
    return _KECCAK.keccak_hex(label)


def role_id(name):
    if name == 'DEFAULT_ADMIN_ROLE':
        return '0x' + '00' * 32
    return _KECCAK.keccak_hex(name)


SLOTS = {
    'implementation': slot_minus_one('eip1967.proxy.implementation'),
    'admin': slot_minus_one('eip1967.proxy.admin'),
    'beacon': slot_minus_one('eip1967.proxy.beacon'),
    # Safe stores its guard at the plain hash, no minus-one (GuardManager.GUARD_STORAGE_SLOT).
    'safe_guard': slot_plain('guard_manager.guard.address'),
}

TOPICS = {
    'RoleGranted': topic('RoleGranted(bytes32,address,address)'),
    'RoleRevoked': topic('RoleRevoked(bytes32,address,address)'),
}

ROLE_NAMES = ('DEFAULT_ADMIN_ROLE', 'MINTER_ROLE', 'BURNER_ROLE', 'PAUSER_ROLE', 'UPGRADER_ROLE',
              'OPERATOR_ROLE', 'GUARDIAN_ROLE', 'KEEPER_ROLE', 'REBALANCER_ROLE', 'MANAGER_ROLE',
              'ADMIN_ROLE', 'PROPOSER_ROLE', 'EXECUTOR_ROLE', 'CANCELLER_ROLE',
              'TIMELOCK_ADMIN_ROLE', 'STRATEGIST_ROLE', 'VAULT_ROLE', 'ORACLE_ROLE')

SHAPES = {
    'single-signer': 'one key controls the contract',
    'minority-multisig': 'a minority of signers controls the Safe (Drift Apr 2026 ran 2-of-5, '
                         'no timelock, as reported)',
    'module-bypass': 'an enabled Safe module executes without owner signatures',
    'no-timelock': 'privileged changes take effect immediately (Drift Apr 2026 shape)',
    'eoa-admin': 'a single externally owned key holds admin power',
    'stale-permission': 'a role or owner outside the declared architecture keeps power (Troves Oct '
                        '2026: a replaced rebalancer kept vault permissions, as reported)',
    'dead-permission': 'power granted to an address with no code at this block',
    'unknown-implementation': 'the proxy runs code outside the declared architecture',
    'single-verifier': 'one verifier can forge a cross-chain message (the KelpDAO Apr 2026 shape: '
                       'a 1-of-1 required DVN, as reported)',
    'low-confirmations': 'a message is accepted after fewer source confirmations than expected',
    'unexpected-peer': 'the OApp trusts a remote peer that is zero or not the expected one',
    'stale-oracle': 'the feed has not updated within its heartbeat',
    'bad-oracle-answer': 'the feed answer is zero or negative',
    'risk-parameter': 'a protocol risk parameter holds a dangerous value (thresholds: CrossCurve '
                      'Feb 2026, Bonzo Jul 2026; mint cap: Resolv Mar 2026; quorum: Term Finance '
                      'Aug 2026; collateral factor: Moonwell / Tectonic Aug 2026 - as reported)',
}


# --------------------------------------------------------------------------- #
# endpoint hygiene

_SECRET_PARAM = re.compile(r'(?i)([?&](?:api[-_]?key|apikey|key|token|access[-_]?token|secret)'
                           r'=)[^&\s"\']+')


def scrub_endpoint(text, url):
    """Remove the endpoint this command was handed - whole, by host, and by its key-bearing path."""
    if not isinstance(text, str):
        text = '' if text is None else str(text)
    if isinstance(url, str) and url.strip():
        url = url.strip()
        text = text.replace(url, '<endpoint>')
        parts = urllib.parse.urlsplit(url)
        pieces = [parts.netloc, parts.hostname or '']
        path = parts.path.strip('/')
        if len(path) >= 6:
            pieces.append(path)
            pieces.extend(seg for seg in path.split('/') if len(seg) >= 12)
        if len(parts.query) >= 6:
            pieces.append(parts.query)
        if parts.password:
            pieces.append(parts.password)
        for piece in sorted({p for p in pieces if p}, key=len, reverse=True):
            text = re.sub(re.escape(piece), '<endpoint>', text, flags=re.I)
    return _SECRET_PARAM.sub(r'\1<redacted>', text)


class RpcFailure(Exception):
    """A read that did not produce a value; the message is scrubbed before it is recorded."""


def urllib_opener(url, timeout=RPC_TIMEOUT):
    """The default transport: callable(method, params) -> result, over plain JSON-RPC."""
    def call(method, params):
        payload = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method,
                              'params': params}).encode('utf-8')
        request = urllib.request.Request(url, data=payload, headers={
            'Content-Type': 'application/json', 'Accept': 'application/json',
            'User-Agent': 'bounty-pilot-config-snapshot'})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode('utf-8'))
        if isinstance(body, dict) and body.get('error'):
            raise RpcFailure(f'{method} returned an error: {body["error"]}')
        return body.get('result') if isinstance(body, dict) else None
    return call


# --------------------------------------------------------------------------- #
# minimal ABI

def _arg_types(signature):
    inner = signature[signature.index('(') + 1:signature.rindex(')')]
    return [t.strip() for t in inner.split(',') if t.strip()]


def _to_int(value):
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    if text in ('max', 'uint256_max', 'uint_max'):
        return UINT256_MAX
    return int(text, 16) if text.startswith('0x') else int(text)


def encode_static(abi_type, value):
    """One 32-byte head word for a static type."""
    if abi_type == 'address':
        text = str(value).lower()
        if not re.fullmatch(r'0x[0-9a-f]{40}', text):
            raise ValueError(f'not an address: {value!r}')
        return bytes(12) + bytes.fromhex(text[2:])
    if abi_type == 'bool':
        return int(bool(value) and value not in ('false', '0')).to_bytes(32, 'big')
    if abi_type.startswith('uint'):
        number = _to_int(value)
        if number < 0:
            raise ValueError(f'negative value for {abi_type}')
        return number.to_bytes(32, 'big')
    if abi_type.startswith('int'):
        return (_to_int(value) % 2 ** 256).to_bytes(32, 'big')
    if re.fullmatch(r'bytes([1-9]|[12][0-9]|3[0-2])', abi_type):
        raw = bytes.fromhex(str(value)[2:] if str(value).startswith('0x') else str(value))
        return raw.ljust(32, b'\0')[:32]
    raise ValueError(f'unsupported argument type {abi_type!r} (static types only)')


def encode_call(signature, args=()):
    types = _arg_types(signature)
    args = list(args or ())
    if len(types) != len(args):
        raise ValueError(f'{signature} takes {len(types)} argument(s), got {len(args)}')
    return selector(signature) + b''.join(encode_static(t, a) for t, a in zip(types, args)).hex()


def _hex_bytes(data):
    if not isinstance(data, str) or not data.startswith('0x'):
        raise RpcFailure('return data is not hex')
    return bytes.fromhex(data[2:])


def word(raw, index):
    chunk = raw[index * 32:index * 32 + 32]
    if len(chunk) != 32:
        raise RpcFailure('return data shorter than expected')
    return chunk


def dec_uint(raw, index=0):
    return int.from_bytes(word(raw, index), 'big')


def dec_int(raw, index=0):
    value = dec_uint(raw, index)
    return value - 2 ** 256 if value >= 2 ** 255 else value


def dec_address(raw, index=0):
    return '0x' + word(raw, index)[12:].hex()


def dec_bool(raw, index=0):
    return dec_uint(raw, index) != 0


def dec_bytes32(raw, index=0):
    return '0x' + word(raw, index).hex()


def _at(raw, offset):
    if offset % 32 or offset >= len(raw):
        raise RpcFailure('bad dynamic offset in return data')
    return offset // 32


def dec_address_array(raw, head_index=0, base=0):
    """address[] whose offset (relative to `base` bytes) sits in head word `head_index`."""
    start = base + dec_uint(raw, base // 32 + head_index)
    at = _at(raw, start)
    length = dec_uint(raw, at)
    if length > 10_000:
        raise RpcFailure('implausible array length in return data')
    return [dec_address(raw, at + 1 + i) for i in range(length)]


def dec_dynamic_bytes(raw, head_index=0):
    at = _at(raw, dec_uint(raw, head_index))
    length = dec_uint(raw, at)
    data = raw[(at + 1) * 32:(at + 1) * 32 + length]
    if len(data) != length:
        raise RpcFailure('dynamic bytes shorter than its length')
    return data


def dec_string(raw, head_index=0):
    return dec_dynamic_bytes(raw, head_index).decode('utf-8', 'replace')


DECODERS = {'uint256': dec_uint, 'int256': dec_int, 'address': dec_address, 'bool': dec_bool,
            'bytes32': dec_bytes32}


def decode_uln_config(raw):
    """abi.encode(UlnConfig): a dynamic tuple, so word 0 is the offset to its head."""
    base = dec_uint(raw, 0)
    head = _at(raw, base)
    required = dec_uint(raw, head + 1)
    return {
        'confirmations': dec_uint(raw, head),
        'required_dvn_count': 0 if required == NIL_DVN_COUNT else required,
        'required_dvn_count_raw': required,
        'optional_dvn_count': dec_uint(raw, head + 2),
        'optional_dvn_threshold': dec_uint(raw, head + 3),
        'required_dvns': dec_address_array(raw, 4, base),
        'optional_dvns': dec_address_array(raw, 5, base),
    }


def encode_uln_config(confirmations, required, optional, threshold):
    """The inverse of decode_uln_config, for tests and fixtures."""
    def w(n):
        return int(n).to_bytes(32, 'big')

    def arr(items):
        return w(len(items)) + b''.join(encode_static('address', a) for a in items)
    req_off = 6 * 32
    opt_off = req_off + 32 + 32 * len(required)
    tup = (w(confirmations) + w(len(required)) + w(len(optional)) + w(threshold)
           + w(req_off) + w(opt_off) + arr(required) + arr(optional))
    return w(32) + tup


# --------------------------------------------------------------------------- #
# reading context

class Reader:
    """Every read goes through here: the allowlist, the pinned block, scrubbed failures."""

    def __init__(self, transport, block_tag, rpc=None):
        self.transport = transport
        self.block_tag = block_tag
        self.rpc = rpc
        self._code = {}

    def raw(self, method, params):
        if method not in READ_ONLY_METHODS:
            raise RpcFailure(f'{method} is not a read-only method this tool may send')
        try:
            return self.transport(method, params)
        except RpcFailure:
            raise
        except Exception as exc:  # every transport failure becomes a scrubbed, recorded error
            raise RpcFailure(f'{method}: {scrub_endpoint(str(exc), self.rpc)[:300]}') from None

    def call(self, to, signature, args=()):
        data = self.raw('eth_call', [{'to': to, 'data': encode_call(signature, args)},
                                     self.block_tag])
        raw = _hex_bytes(data)
        if not raw:
            raise RpcFailure(f'{signature.split("(")[0]} returned no data (no code at {to}, '
                             'or the function does not exist)')
        return raw

    def try_call(self, to, signature, args=()):
        try:
            return self.call(to, signature, args)
        except RpcFailure:
            return None

    def code_size(self, address):
        address = address.lower()
        if address not in self._code:
            code = self.raw('eth_getCode', [address, self.block_tag])
            self._code[address] = len(_hex_bytes(code or '0x'))
        return self._code[address]

    def storage_word(self, address, slot):
        return _hex_bytes(self.raw('eth_getStorageAt', [address, slot, self.block_tag]) or '0x')

    def balance(self, address):
        return _to_int(self.raw('eth_getBalance', [address, self.block_tag]) or '0x0')


def _flag(code, detail, shape):
    return {'code': code, 'detail': detail, 'shape': f'{shape}: {SHAPES[shape]}'}


def _word_address(raw):
    raw = raw.rjust(32, b'\0')
    return '0x' + raw[-20:].hex()


def _expect_int(expect, key):
    if expect.get(key) is None:
        return None
    return _to_int(expect[key])


# --------------------------------------------------------------------------- #
# kinds — each fills `reads` as it goes, so a late failure keeps the early values

def read_safe(r, target, known, reads, flags):
    addr = target['address']
    expect = target.get('expect') or {}
    threshold = dec_uint(r.call(addr, 'getThreshold()'))
    reads['threshold'] = threshold
    owners = dec_address_array(r.call(addr, 'getOwners()'))
    reads['owners'] = [{'address': o, 'code_size': r.code_size(o),
                        'known': None if known is None else o in known} for o in owners]
    try:
        raw = r.call(addr, 'getModulesPaginated(address,uint256)',
                     ['0x0000000000000000000000000000000000000001', 100])
        reads['modules'] = dec_address_array(raw, 0)
        reads['modules_next'] = dec_address(raw, 1)
    except RpcFailure as exc:
        reads['modules'] = None
        reads['modules_error'] = str(exc)
    reads['guard'] = _word_address(r.storage_word(addr, SLOTS['safe_guard']))
    nonce = r.try_call(addr, 'nonce()')
    reads['nonce'] = dec_uint(nonce) if nonce else None

    if threshold <= 1:
        flags.append(_flag('SAFE_THRESHOLD_ONE', f'threshold {threshold} of {len(owners)} owners: '
                           'one signature executes any transaction', 'single-signer'))
    elif threshold * 2 <= len(owners):
        flags.append(_flag('SAFE_MINORITY_THRESHOLD', f'{threshold}-of-{len(owners)}: half the '
                           'owners or fewer can execute', 'minority-multisig'))
    if expect.get('min_threshold') is not None and threshold < _to_int(expect['min_threshold']):
        flags.append(_flag('SAFE_THRESHOLD_BELOW_EXPECTED', f'threshold {threshold} < expected '
                           f'{expect["min_threshold"]}', 'minority-multisig'))
    for module in reads.get('modules') or []:
        flags.append(_flag('SAFE_MODULE_ENABLED', f'module {module} (code size '
                           f'{r.code_size(module)}) can execute without owner signatures; read '
                           'what it allows and who can call it', 'module-bypass'))
    if reads['modules'] and reads.get('modules_next') not in (
            None, ZERO_ADDRESS, '0x0000000000000000000000000000000000000001'):
        reads['modules_truncated'] = True


def read_timelock(r, target, known, reads, flags):
    addr = target['address']
    expect = target.get('expect') or {}
    raw = r.try_call(addr, 'getMinDelay()')
    source = 'getMinDelay()'
    if raw is None:
        raw = r.call(addr, 'delay()')
        source = 'delay()'
    delay = dec_uint(raw)
    reads.update({'delay_seconds': delay, 'read_via': source})
    minimum = _expect_int(expect, 'min_delay')
    if delay == 0:
        flags.append(_flag('TIMELOCK_ZERO_DELAY', f'{source} is 0: queued changes execute '
                           'immediately', 'no-timelock'))
    elif minimum is not None and delay < minimum:
        flags.append(_flag('TIMELOCK_DELAY_BELOW_EXPECTED', f'{source} {delay}s < expected '
                           f'{minimum}s', 'no-timelock'))


def read_ownable(r, target, known, reads, flags):
    addr = target['address']
    owner = dec_address(r.call(addr, 'owner()'))
    reads['owner'] = owner
    pending = r.try_call(addr, 'pendingOwner()')
    reads['pending_owner'] = dec_address(pending) if pending else None
    reads['target_code_size'] = r.code_size(addr)
    if owner == ZERO_ADDRESS:
        reads['owner_note'] = 'ownership renounced (zero owner)'
        return
    size = r.code_size(owner)
    reads['owner_code_size'] = size
    if size == 0:
        try:
            reads['target_balance_wei'] = str(r.balance(addr))
        except RpcFailure:
            reads['target_balance_wei'] = None
        flags.append(_flag('OWNER_IS_EOA', f'owner {owner} has no code; it owns a contract of '
                           f'{reads["target_code_size"]} bytes', 'eoa-admin'))
    if known is not None and owner not in known:
        flags.append(_flag('OWNER_NOT_KNOWN', f'owner {owner} is not in the declared architecture',
                           'stale-permission'))
    pend = reads['pending_owner']
    if known is not None and pend and pend != ZERO_ADDRESS and pend not in known:
        flags.append(_flag('PENDING_OWNER_NOT_KNOWN', f'pending owner {pend} is not in the declared '
                           'architecture', 'stale-permission'))


def _get_logs(r, address, topics, start, end, max_range, depth=0):
    """Logs over [start, end] in one request, split on failure a few times before giving up."""
    try:
        return r.raw('eth_getLogs', [{'address': address, 'topics': topics,
                                      'fromBlock': hex(start), 'toBlock': hex(end)}]) or [], []
    except RpcFailure as exc:
        if depth >= LOG_SPLIT_DEPTH or end <= start:
            return [], [f'blocks {start}-{end}: {exc}']
        mid = (start + end) // 2
        left, e1 = _get_logs(r, address, topics, start, mid, max_range, depth + 1)
        right, e2 = _get_logs(r, address, topics, mid + 1, end, max_range, depth + 1)
        return left + right, e1 + e2


def scan_role_logs(r, address, from_block, to_block, max_range=LOG_MAX_RANGE,
                   max_chunks=LOG_MAX_CHUNKS):
    topics = [[TOPICS['RoleGranted'], TOPICS['RoleRevoked']]]
    logs, errors, chunks = [], [], 0
    start = from_block
    while start <= to_block and chunks < max_chunks:
        end = min(start + max_range - 1, to_block)
        got, errs = _get_logs(r, address, topics, start, end, max_range)
        logs.extend(got)
        errors.extend(errs)
        chunks += 1
        start = end + 1
    scan = {'from_block': from_block, 'to_block': to_block, 'chunk_size': max_range,
            'chunks': chunks, 'scanned_to': start - 1, 'truncated': start <= to_block or bool(errors)}
    if start <= to_block:
        scan['truncation'] = (f'blocks {start}-{to_block} were NOT scanned (max {max_chunks} '
                              f'chunks of {max_range}); role membership may be incomplete. Set '
                              'expect.from_block to the deployment block or raise expect.max_chunks.')
    if errors:
        scan['failed_ranges'] = errors
    return logs, scan


def read_access_control(r, target, known, reads, flags):
    addr = target['address']
    expect = target.get('expect') or {}
    block = int(r.block_tag, 16)
    logs, scan = scan_role_logs(r, addr, _to_int(expect.get('from_block', 0)), block,
                                _to_int(expect.get('max_range', LOG_MAX_RANGE)),
                                _to_int(expect.get('max_chunks', LOG_MAX_CHUNKS)))
    reads['log_scan'] = scan
    names = {role_id(n): n for n in list(ROLE_NAMES) + list(expect.get('role_names') or [])}

    def order(log):
        return (_to_int(log.get('blockNumber', '0x0')), _to_int(log.get('logIndex', '0x0')))
    members = {}
    for log in sorted(logs, key=order):
        tops = [t.lower() for t in log.get('topics') or []]
        if len(tops) < 3:
            continue
        role, account = tops[1], '0x' + tops[2][-40:]
        bucket = members.setdefault(role, {})
        if tops[0] == TOPICS['RoleGranted']:
            bucket[account] = True
        elif tops[0] == TOPICS['RoleRevoked']:
            bucket.pop(account, None)
    roles = {}
    reads['roles'] = roles
    if known is None:
        reads['known_note'] = 'no --known set given: membership is not compared to the architecture'
    for role, bucket in members.items():
        label = names.get(role, role)
        entries = []
        roles[label] = entries
        for account in sorted(bucket):
            has = r.try_call(addr, 'hasRole(bytes32,address)', [role, account])
            size = r.code_size(account)
            entries.append({'address': account, 'code_size': size,
                            'has_role_now': dec_bool(has) if has else None,
                            'known': None if known is None else account in known})
            if has is not None and not dec_bool(has):
                continue  # the logs missed a revocation; hasRole is the authority
            in_known = known is not None and account in known
            if label == 'DEFAULT_ADMIN_ROLE' and size == 0:
                flags.append(_flag('ADMIN_ROLE_EOA', f'DEFAULT_ADMIN_ROLE held by {account}, which '
                                   'has no code: one key can grant every role', 'eoa-admin'))
            elif size == 0 and known is not None and in_known:
                flags.append(_flag('ROLE_KNOWN_MEMBER_NO_CODE', f'{label} held by declared address '
                                   f'{account}, which has no code at this block (self-destructed, '
                                   'not yet deployed here, or the wrong chain)', 'dead-permission'))
            elif size == 0:
                flags.append(_flag('ROLE_MEMBER_NO_CODE', f'{label} held by {account}, which has no '
                                   'code: an EOA, or a contract that self-destructed or was never '
                                   'deployed (a CREATE2 address someone else may deploy)',
                                   'dead-permission'))
            if known is not None and not in_known and size > 0:
                flags.append(_flag('ROLE_MEMBER_NOT_KNOWN', f'{label} held by contract {account}, '
                                   'which is not in the declared architecture - a replaced '
                                   'component that kept its permission?', 'stale-permission'))


def read_erc1967(r, target, known, reads, flags):
    addr = target['address']
    impl = _word_address(r.storage_word(addr, SLOTS['implementation']))
    admin = _word_address(r.storage_word(addr, SLOTS['admin']))
    beacon = _word_address(r.storage_word(addr, SLOTS['beacon']))
    reads.update({'implementation': impl, 'admin': admin, 'beacon': beacon})
    if beacon != ZERO_ADDRESS:
        raw = r.try_call(beacon, 'implementation()')
        reads['beacon_implementation'] = dec_address(raw) if raw else None
    effective = impl if impl != ZERO_ADDRESS else reads.get('beacon_implementation')
    if impl == ZERO_ADDRESS and beacon == ZERO_ADDRESS:
        reads['note'] = 'no EIP-1967 implementation or beacon: not an EIP-1967 proxy at this block'
        return
    if effective:
        size = r.code_size(effective)
        reads['implementation_code_size'] = size
        if size == 0:
            flags.append(_flag('PROXY_IMPLEMENTATION_NO_CODE', f'implementation {effective} has no '
                               'code', 'dead-permission'))
        if known is not None and effective not in known:
            flags.append(_flag('PROXY_IMPLEMENTATION_NOT_KNOWN', f'implementation {effective} is '
                               'not in the declared architecture', 'unknown-implementation'))
    if admin != ZERO_ADDRESS:
        size = r.code_size(admin)
        reads['admin_code_size'] = size
        if size == 0:
            flags.append(_flag('PROXY_ADMIN_EOA', f'proxy admin {admin} has no code: one key can '
                               'upgrade the proxy', 'eoa-admin'))
        elif known is not None and admin not in known:
            flags.append(_flag('PROXY_ADMIN_NOT_KNOWN', f'proxy admin {admin} is not in the declared '
                               'architecture', 'stale-permission'))


def read_layerzero(r, target, known, reads, flags):
    oapp = target['address']
    expect = target.get('expect') or {}
    endpoint = str(expect.get('endpoint') or '').lower()
    eids = expect.get('eids') or []
    if not re.fullmatch(r'0x[0-9a-f]{40}', endpoint) or not eids:
        raise RpcFailure('layerzero-oapp needs expect.endpoint and a non-empty expect.eids')
    want_lib = str(expect.get('receive_library') or '').lower() or None
    min_conf = _expect_int(expect, 'min_confirmations')
    want_peers = {str(k): str(v).lower() for k, v in (expect.get('peers') or {}).items()}
    per_eid = {}
    reads['endpoint'] = endpoint
    reads['eids'] = per_eid
    errors = []
    for eid in eids:
        entry = {}
        per_eid[str(eid)] = entry
        try:
            peer = dec_bytes32(r.call(oapp, 'peers(uint32)', [eid]))
            entry['peer'] = peer
            if int(peer, 16) == 0:
                flags.append(_flag('LZ_PEER_ZERO', f'eid {eid}: no peer set', 'unexpected-peer'))
            elif str(eid) in want_peers:
                want = want_peers[str(eid)]
                if int(want, 16) != int(peer, 16):
                    flags.append(_flag('LZ_PEER_UNEXPECTED', f'eid {eid}: peer {peer} != expected '
                                       f'{want}', 'unexpected-peer'))
            elif known is not None and peer[:26] == '0x' + '0' * 24 and \
                    '0x' + peer[-40:] not in known:
                flags.append(_flag('LZ_PEER_NOT_KNOWN', f'eid {eid}: peer {peer} is not in the known '
                                   'set (the known set may list only this chain; give expect.peers)',
                                   'unexpected-peer'))

            raw = r.call(endpoint, 'getReceiveLibrary(address,uint32)', [oapp, eid])
            lib, is_default = dec_address(raw, 0), dec_bool(raw, 1)
            entry.update({'receive_library': lib, 'library_is_default': is_default})
            if want_lib and lib != want_lib:
                flags.append(_flag('LZ_RECEIVE_LIBRARY_UNEXPECTED', f'eid {eid}: receive library '
                                   f'{lib} != expected {want_lib}', 'single-verifier'))
            raw = r.call(endpoint, 'getConfig(address,address,uint32,uint32)',
                         [oapp, lib, eid, ULN_CONFIG_TYPE])
            uln = decode_uln_config(dec_dynamic_bytes(raw, 0))
            entry['uln_config'] = uln
            custom = r.try_call(lib, 'getAppUlnConfig(address,uint32)', [oapp, eid])
            if custom is None:
                entry['uln_config_source'] = 'undetermined'
            else:
                try:
                    c = decode_uln_config(custom)
                    blank = not (c['confirmations'] or c['required_dvn_count_raw']
                                 or c['optional_dvn_count'] or c['optional_dvn_threshold'])
                    entry['uln_config_source'] = 'default' if blank else 'custom'
                except RpcFailure:
                    entry['uln_config_source'] = 'undetermined'
            verifiers = uln['required_dvn_count'] + uln['optional_dvn_threshold']
            if verifiers <= 1:
                flags.append(_flag('LZ_SINGLE_VERIFIER', f'eid {eid}: {uln["required_dvn_count"]} '
                                   f'required DVN(s) + optional threshold '
                                   f'{uln["optional_dvn_threshold"]} = {verifiers}; one verifier '
                                   f'can attest a message (config: {entry["uln_config_source"]})',
                                   'single-verifier'))
            if min_conf is not None and uln['confirmations'] < min_conf:
                flags.append(_flag('LZ_LOW_CONFIRMATIONS', f'eid {eid}: {uln["confirmations"]} '
                                   f'confirmations < expected {min_conf}', 'low-confirmations'))
        except RpcFailure as exc:
            errors.append(f'eid {eid}: {exc}')
    if errors:
        raise RpcFailure('; '.join(errors))


def read_chainlink(r, target, known, reads, flags):
    addr = target['address']
    expect = target.get('expect') or {}
    raw = r.call(addr, 'latestRoundData()')
    answer, updated = dec_int(raw, 1), dec_uint(raw, 3)
    reads.update({'round_id': dec_uint(raw, 0), 'answer': str(answer), 'started_at': dec_uint(raw, 2),
                  'updated_at': updated, 'answered_in_round': dec_uint(raw, 4)})
    dec = r.try_call(addr, 'decimals()')
    reads['decimals'] = dec_uint(dec) if dec else None
    desc = r.try_call(addr, 'description()')
    try:
        reads['description'] = dec_string(desc) if desc else None
    except RpcFailure:
        reads['description'] = None
    block = r.raw('eth_getBlockByNumber', [r.block_tag, False]) or {}
    now = _to_int(block.get('timestamp', '0x0'))
    reads['block_timestamp'] = now
    reads['age_seconds'] = now - updated
    if answer <= 0:
        flags.append(_flag('FEED_NONPOSITIVE_ANSWER', f'answer {answer}', 'bad-oracle-answer'))
    heartbeat = _expect_int(expect, 'heartbeat')
    if heartbeat is None:
        reads['heartbeat_note'] = 'no expect.heartbeat: staleness not judged'
    elif now - updated > heartbeat:
        flags.append(_flag('FEED_STALE', f'updated {now - updated}s before the block, heartbeat '
                           f'{heartbeat}s', 'stale-oracle'))


_OPS = {'eq': lambda a, b: a == b, 'ne': lambda a, b: a != b, 'lt': lambda a, b: a < b,
        'gt': lambda a, b: a > b, 'lte': lambda a, b: a <= b, 'gte': lambda a, b: a >= b}


def _coerce(kind, value):
    if kind == 'address':
        return str(value).lower()
    if kind == 'bool':
        return value if isinstance(value, bool) else str(value).lower() in ('true', '1')
    if kind == 'bytes32':
        return int(str(value), 16)
    return _to_int(value)


def read_getter(r, target, known, reads, flags):
    addr = target['address']
    calls = (target.get('expect') or {}).get('calls') or []
    if not calls:
        raise RpcFailure('getter needs expect.calls')
    block = int(r.block_tag, 16)
    results = []
    reads['calls'] = results
    errors = []
    for spec in calls:
        sig = ''.join(str(spec.get('sig', '')).split())
        label = spec.get('label') or sig
        entry = {'label': label, 'sig': sig}
        results.append(entry)
        try:
            args = []
            for a in spec.get('args') or []:
                args.append(block if a == '$block' else block - 1 if a == '$block-1' else a)
            returns = spec.get('returns', 'uint256')
            types = returns if isinstance(returns, list) else [returns]
            for t in types:
                if t not in DECODERS:
                    raise RpcFailure(f'unsupported return type {t!r}')
            raw = r.call(str(spec.get('to') or addr).lower(), sig, args)
            values = [DECODERS[t](raw, i) for i, t in enumerate(types)]
            entry['values'] = [str(v) if isinstance(v, int) and not isinstance(v, bool) else v
                               for v in values]
            pick = int(spec.get('pick', 0))
            value, kind = values[pick], types[pick]
            cond = spec.get('flag_if') or {}
            for op, threshold in cond.items():
                if op not in _OPS:
                    raise RpcFailure(f'unknown flag_if operator {op!r}')
                lhs = int(value, 16) if kind == 'bytes32' else value
                if _OPS[op](lhs, _coerce(kind, threshold)):
                    flags.append(_flag('GETTER_CONDITION', f'{label} = {value} ({op} {threshold})'
                                       + (f': {spec["why"]}' if spec.get('why') else ''),
                                       'risk-parameter'))
        except (RpcFailure, ValueError) as exc:
            entry['error'] = str(exc)
            errors.append(f'{label}: {exc}')
    if errors:
        raise RpcFailure('; '.join(errors))


READERS = {'safe': read_safe, 'timelock': read_timelock, 'ownable': read_ownable,
           'access-control': read_access_control, 'erc1967-proxy': read_erc1967,
           'layerzero-oapp': read_layerzero, 'chainlink-feed': read_chainlink,
           'getter': read_getter}


# --------------------------------------------------------------------------- #
# snapshot

def _normalise_known(known):
    if known is None:
        return None
    out = set()
    for item in known:
        value = item.get('address') if isinstance(item, dict) else item
        if isinstance(value, str) and re.fullmatch(r'0x[0-9a-fA-F]{40}', value.strip()):
            out.add(value.strip().lower())
    return out


def _block_tag(block, reader):
    if block in (None, 'latest', ''):
        return hex(_to_int(reader.raw('eth_blockNumber', [])))
    return hex(_to_int(block))


def snapshot(rpc, targets, known=None, block='latest', opener=None):
    """Read every target at one pinned block. `opener` is callable(method, params) -> result.

    Without an opener, `rpc` is used for plain JSON-RPC over urllib. A target that fails records
    its scrubbed errors and keeps any values it read before failing; it never aborts the others.
    """
    transport = opener or urllib_opener(rpc)
    known_set = _normalise_known(known)
    result = {'schema_version': SCHEMA_VERSION, 'chain_id': None, 'block': None,
              'endpoint': 'not recorded', 'known_addresses': None if known_set is None
              else len(known_set), 'targets': [], 'errors': [], 'notice': NOTICE}
    reader = Reader(transport, 'latest', rpc)
    try:
        result['chain_id'] = _to_int(reader.raw('eth_chainId', []))
        reader.block_tag = _block_tag(block, reader)
        result['block'] = int(reader.block_tag, 16)
    except (RpcFailure, ValueError, TypeError) as exc:
        result['errors'].append(scrub_endpoint(f'could not pin a block: {exc}', rpc)[:300])
        for target in targets or []:
            result['targets'].append({'address': (target or {}).get('address'),
                                      'kind': (target or {}).get('kind'),
                                      'label': (target or {}).get('label'), 'reads': {},
                                      'flags': [], 'errors': ['not read: no pinned block']})
        return result
    for target in targets or []:
        target = dict(target or {})
        address = str(target.get('address') or '').strip().lower()
        kind = target.get('kind')
        entry = {'address': address, 'kind': kind, 'label': target.get('label'), 'reads': {},
                 'flags': [], 'errors': []}
        result['targets'].append(entry)
        if not re.fullmatch(r'0x[0-9a-f]{40}', address):
            entry['errors'].append('address is not a 20-byte hex address')
            continue
        if kind not in READERS:
            entry['errors'].append(f'unknown kind {kind!r}; known: {", ".join(KINDS)}')
            continue
        target['address'] = address
        try:
            READERS[kind](reader, target, known_set, entry['reads'], entry['flags'])
        except (RpcFailure, ValueError, TypeError, KeyError, IndexError) as exc:
            entry['errors'].append(scrub_endpoint(str(exc), rpc)[:600])
    return result


def summarise(result, out=None):
    codes = {}
    for target in result['targets']:
        for flag in target['flags']:
            codes[flag['code']] = codes.get(flag['code'], 0) + 1
    return {'schema_version': result['schema_version'], 'chain_id': result['chain_id'],
            'block': result['block'], 'endpoint': 'not recorded', 'out': out,
            'targets': len(result['targets']),
            'targets_flagged': sum(1 for t in result['targets'] if t['flags']),
            'targets_with_errors': sum(1 for t in result['targets'] if t['errors']),
            'flags': dict(sorted(codes.items())), 'errors': result['errors'],
            'notice': result['notice']}


def _load_json(path, what):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f'config-snapshot: cannot read {what} {path}: {exc}')


def build_parser():
    parser = argparse.ArgumentParser(
        prog='bounty.py config-snapshot',
        description='Read deployed configuration (Safe, timelock, owner, roles, proxy, LayerZero '
                    'ULN, Chainlink feed, getters) at one block and flag risky shapes. Every flag '
                    'is a lead. The RPC URL is never recorded.')
    parser.add_argument('--rpc', required=True, help='JSON-RPC URL (argument only; never written)')
    parser.add_argument('--targets', required=True,
                        help='JSON list of {address, kind, label?, expect?}')
    parser.add_argument('--known', help='JSON list of addresses in the declared architecture')
    parser.add_argument('--block', default='latest', help='block number or latest (pinned once)')
    parser.add_argument('--out', help='write the full snapshot here; print only a summary')
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    targets = _load_json(args.targets, 'targets')
    if isinstance(targets, dict):
        targets = targets.get('targets')
    if not isinstance(targets, list):
        print(json.dumps({'error': 'targets must be a JSON list (or {"targets": [...]})'}))
        return 2
    known = None
    if args.known:
        known = _load_json(args.known, 'known')
        if isinstance(known, dict):
            known = known.get('in_scope_addresses') or known.get('addresses') or []
        if not isinstance(known, list):
            print(json.dumps({'error': 'known must be a JSON list of addresses'}))
            return 2
    result = snapshot(args.rpc, targets, known=known, block=args.block)
    text = json.dumps(result, indent=2, sort_keys=False)
    # Belt and braces: nothing derived from the endpoint may leave this process.
    text = scrub_endpoint(text, args.rpc)
    if args.out:
        Path(args.out).write_text(text + '\n', encoding='utf-8')
        print(scrub_endpoint(json.dumps(summarise(result, args.out), indent=2), args.rpc))
    else:
        print(text)
    return 1 if result['block'] is None else 0


if __name__ == '__main__':
    sys.exit(main())
