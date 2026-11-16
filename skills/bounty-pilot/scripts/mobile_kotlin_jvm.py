#!/usr/bin/env python3
"""Optional offline Kotlin JVM classfile invocation alignment for lexical leads.

Only parses operator-provided class bytes; never loads/executes classes,
runs a compiler or trusts classfiles to match the current .kt source.
A compiled JVM callsite is stronger than a guessed lexical class name, but
cannot prove source/build freshness, taint, reachability or Android behavior.
"""
import hashlib
import re
import struct
from pathlib import Path

import mobile_lab

MAX_CLASSFILES = 350
MAX_CLASS_BYTES = 350000
MAX_BYTES = 8 * 1024 * 1024
MAX_CONSTANTS = 10000
MAX_CODE = 200000
MAX_INSTRUCTIONS = 30000

CALL_OPCODE = {0xb6: "INVOKEVIRTUAL", 0xb7: "INVOKESPECIAL",
               0xb8: "INVOKESTATIC", 0xb9: "INVOKEINTERFACE"}
LEN2 = {0x10, 0x12, 0xa9, 0xbc} | set(range(0x15, 0x1a)) | set(range(0x36, 0x3b))
LEN3 = ({0x11, 0x13, 0x14, 0x84, 0xbb, 0xbd, 0xc0, 0xc1, 0xc6, 0xc7}
        | set(range(0x99, 0xa9)) | set(range(0xb2, 0xb9)))
LEN4 = {0xc5}
LEN5 = {0xb9, 0xba, 0xc8, 0xc9}
VALID_DESCRIPTOR = "(Ljava/lang/String;)V"


class _Read:
    def __init__(self, data):
        self.data = data
        self.p = 0

    def take(self, n):
        if n < 0 or n > len(self.data) - self.p:
            raise ValueError("malformed JVM classfile length")
        out = self.data[self.p:self.p + n]
        self.p += n
        return out

    def u1(self):
        return self.take(1)[0]

    def u2(self):
        return struct.unpack(">H", self.take(2))[0]

    def u4(self):
        return struct.unpack(">I", self.take(4))[0]


def _cp_utf(cp, index):
    if not 0 < index < len(cp) or cp[index][0] != 1:
        raise ValueError("bad JVM Utf8 constant")
    return cp[index][1]


def _cp_class(cp, index):
    if not 0 < index < len(cp) or cp[index][0] != 7:
        raise ValueError("bad JVM Class constant")
    return _cp_utf(cp, cp[index][1])


def _call_ref(cp, index):
    if not 0 < index < len(cp) or cp[index][0] not in (10, 11):
        raise ValueError("bad JVM method reference")
    owner_idx, pair_idx = cp[index][1:]
    if not 0 < pair_idx < len(cp) or cp[pair_idx][0] != 12:
        raise ValueError("bad JVM NameAndType")
    method, descriptor = cp[pair_idx][1:]
    return _cp_class(cp, owner_idx), _cp_utf(cp, method), _cp_utf(cp, descriptor)


def _bytecode(data, cp, numbers):
    calls = []
    i = steps = 0
    while i < len(data):
        steps += 1
        if steps > MAX_INSTRUCTIONS:
            raise ValueError("too many JVM bytecode instructions")
        op = data[i]
        if op > 0xc9:
            raise ValueError("unknown JVM bytecode opcode")
        if op in (0xaa, 0xab):
            start = i + 1
            padded = start + ((4 - (start % 4)) % 4)
            if padded + (12 if op == 0xaa else 8) > len(data):
                raise ValueError("truncated JVM switch")
            if op == 0xaa:
                low, high = struct.unpack_from(">ii", data, padded + 4)
                n = high - low + 1
                if n < 0 or n > 5000:
                    raise ValueError("invalid JVM tableswitch range")
                end = padded + 12 + n * 4
            else:
                n = struct.unpack_from(">i", data, padded + 4)[0]
                if n < 0 or n > 5000:
                    raise ValueError("invalid JVM lookupswitch range")
                end = padded + 8 + n * 8
            if end > len(data):
                raise ValueError("truncated JVM switch entries")
            i = end
            continue
        if op == 0xc4:
            if i + 1 >= len(data):
                raise ValueError("truncated JVM wide")
            length = 6 if data[i + 1] == 0x84 else 4
        else:
            length = (2 if op in LEN2 else 3 if op in LEN3
                      else 4 if op in LEN4 else 5 if op in LEN5 else 1)
        if i + length > len(data):
            raise ValueError("truncated JVM bytecode")
        if op in CALL_OPCODE:
            cp_index = struct.unpack_from(">H", data, i + 1)[0]
            owner, name, descriptor = _call_ref(cp, cp_index)
            line = None
            for pc, source_line in numbers:
                if pc <= i:
                    line = source_line
                else:
                    break
            calls.append((line, owner, name, descriptor, CALL_OPCODE[op], i))
        i += length
    return calls


def _attributes(reader, cp):
    count = reader.u2()
    if count > 2000:
        raise ValueError("too many JVM attributes")
    result = {}
    for _ in range(count):
        name = _cp_utf(cp, reader.u2())
        data = reader.take(reader.u4())
        result.setdefault(name, []).append(data)
    return result


def _method_code(value, cp):
    reader = _Read(value)
    reader.u2()
    reader.u2()
    length = reader.u4()
    if length > MAX_CODE:
        raise ValueError("JVM method bytecode too long")
    code = reader.take(length)
    ex = reader.u2()
    reader.take(ex * 8)
    attrs = _attributes(reader, cp)
    if reader.p != len(value):
        raise ValueError("trailing JVM Code data")
    numbers = []
    for raw in attrs.get("LineNumberTable", []):
        lines = _Read(raw)
        count = lines.u2()
        if count > 10000:
            raise ValueError("too many JVM line entries")
        for _ in range(count):
            pc, line = lines.u2(), lines.u2()
            if pc > length or line == 0:
                raise ValueError("invalid JVM line table")
            numbers.append((pc, line))
        if lines.p != len(raw):
            raise ValueError("trailing JVM line table bytes")
    numbers.sort()
    return _bytecode(code, cp, numbers)


def parse_classfile(data):
    """Parse a bounded classfile; malformed/unknown constructs fail closed."""
    if len(data) > MAX_CLASS_BYTES:
        raise ValueError("JVM classfile is too large")
    r = _Read(data)
    if r.u4() != 0xcafebabe:
        raise ValueError("bad JVM classfile magic")
    r.u2()
    if not 45 <= r.u2() <= 70:
        raise ValueError("unsupported JVM class version")
    cp_size = r.u2()
    if not 1 < cp_size <= MAX_CONSTANTS:
        raise ValueError("invalid JVM constant pool size")
    cp = [None] * cp_size
    index = 1
    while index < cp_size:
        tag = r.u1()
        if tag == 1:
            raw = r.take(r.u2())
            cp[index] = (1, raw.decode("utf-8"))
        elif tag in (3, 4):
            r.take(4)
            cp[index] = (tag,)
        elif tag in (5, 6):
            r.take(8)
            cp[index] = (tag,)
            index += 1
        elif tag in (7, 8, 16, 19, 20):
            cp[index] = (tag, r.u2())
        elif tag in (9, 10, 11, 12, 17, 18):
            cp[index] = (tag, r.u2(), r.u2())
        elif tag == 15:
            cp[index] = (tag, r.u1(), r.u2())
        else:
            raise ValueError("unknown JVM constant pool tag")
        index += 1

    r.u2()
    own = _cp_class(cp, r.u2())
    r.u2()
    interfaces = r.u2()
    r.take(interfaces * 2)
    for _ in range(r.u2()):
        r.u2()
        r.u2()
        r.u2()
        _attributes(r, cp)
    methods = {}
    for _ in range(r.u2()):
        r.u2()
        name = _cp_utf(cp, r.u2())
        descriptor = _cp_utf(cp, r.u2())
        attrs = _attributes(r, cp)
        code = attrs.get("Code", [])
        if len(code) > 1:
            raise ValueError("duplicate JVM method Code")
        key = (name, descriptor)
        if key in methods:
            raise ValueError("ambiguous JVM method signature")
        methods[key] = _method_code(code[0], cp) if code else []
    attrs = _attributes(r, cp)
    if r.p != len(data):
        raise ValueError("JVM classfile trailing data")
    source = attrs.get("SourceFile", [])
    if len(source) != 1 or len(source[0]) != 2:
        raise ValueError("JVM classfile missing unique source file")
    source_name = _cp_utf(cp, struct.unpack(">H", source[0])[0])
    # Metadata is only an untrusted marker: this does NOT authenticate Kotlin
    # compiler provenance or that class bytes match current source content.
    metadata_marker = any(item is not None and item[0] == 1
                          and item[1] == "Lkotlin/Metadata;" for item in cp)
    return {"owner": own, "source_name": source_name,
            "kotlin_metadata_marker": metadata_marker, "methods": methods}


def _index_classes(root):
    supplied = Path(root).expanduser().absolute()
    if supplied.is_symlink() or not supplied.is_dir():
        raise ValueError("JVM classfile root must be a non-symlink directory")
    root = supplied.resolve(strict=True)
    indexed, duplicates = {}, set()
    skipped = total = scanned = 0
    truncated = False
    for path in sorted(root.rglob("*.class")):
        if path.is_symlink() or not path.is_file() or any(
                p.is_symlink() for p in path.parents if p != root):
            skipped += 1
            continue
        if scanned >= MAX_CLASSFILES or total >= MAX_BYTES:
            truncated = True
            break
        if path.stat().st_size > MAX_CLASS_BYTES:
            skipped += 1
            truncated = True
            continue
        data = mobile_lab._regular_file(path, MAX_CLASS_BYTES)
        if len(data) + total > MAX_BYTES:
            truncated = True
            break
        total += len(data)
        scanned += 1
        try:
            cls = parse_classfile(data)
        except (ValueError, UnicodeDecodeError):
            skipped += 1
            continue
        owner = cls["owner"]
        if owner in indexed:
            duplicates.add(owner)
        cls["sha256"] = hashlib.sha256(data).hexdigest()
        indexed[owner] = cls
    for owner in duplicates:
        indexed.pop(owner, None)
    return indexed, {"files_scanned": scanned, "source_bytes": total,
                     "skipped_files": skipped,
                     "duplicate_jvm_owners": len(duplicates),
                     "truncated": truncated}


def align_kotlin_leads(report, entries, class_root):
    """Compare lexical Kotlin-only callsites to independent JVM invokes.

    Classfiles are NOT rebuild-attested to the current Kotlin source.
    """
    indexed, coverage = _index_classes(class_root)
    by_path = {entry["path"]: entry for entry in entries}
    aligned = missing = non_kotlin = 0
    for lead in report["leads"]:
        hops = lead["hops"]
        if (not hops or any(by_path.get(h["caller_file"], {}).get("language") != "kotlin"
                            or by_path.get(h["callee_file"], {}).get("language") != "kotlin"
                            for h in hops)):
            lead["kotlin_jvm_alignment"] = {
                "status": "NOT_APPLICABLE_NOT_KOTLIN_ONLY",
                "source_build_freshness_verified": False,
                "runtime_effect_verified": False,
            }
            non_kotlin += 1
            continue
        edges = []
        for hop in hops:
            caller = by_path[hop["caller_file"]]
            callee = by_path[hop["callee_file"]]
            caller_owner = (caller["package"].replace(".", "/") + "/"
                            if caller["package"] else "") + caller["class"]
            callee_owner = (callee["package"].replace(".", "/") + "/"
                            if callee["package"] else "") + callee["class"]
            a, b = indexed.get(caller_owner), indexed.get(callee_owner)
            matched = []
            if (a and b and a["source_name"] == Path(caller["path"]).name
                    and b["source_name"] == Path(callee["path"]).name
                    and a["kotlin_metadata_marker"] and b["kotlin_metadata_marker"]):
                for (name, _), calls in a["methods"].items():
                    if name != hop["caller_method"]:
                        continue
                    for line, owner, method, desc, opcode, offset in calls:
                        if (line == hop["caller_line"] and owner == callee_owner
                                and method == hop["callee_method"]
                                and desc == VALID_DESCRIPTOR
                                and opcode == "INVOKEVIRTUAL"
                                and (hop["resolution"] in (
                                    "kotlin-explicit-final-instance",
                                    "kotlin-explicit-object-singleton"))):
                            if (hop["callee_method"], desc) in b["methods"]:
                                matched.append((offset, a["sha256"], b["sha256"]))
            # Do not guess among two JVM invokes on one source line.
            if len(matched) == 1:
                offset, caller_sha, callee_sha = matched[0]
                edges.append({"status": "EXACT_JVM_INVOKE_ALIGNED",
                              "caller_class_sha256": caller_sha,
                              "callee_class_sha256": callee_sha,
                              "opcode": "INVOKEVIRTUAL",
                              "callee_jvm_descriptor": VALID_DESCRIPTOR,
                              "bytecode_offset": offset})
            else:
                edges.append({"status": "NO_UNIQUE_JVM_INVOKE"})
        status = ("ALL_HOPS_JVM_BYTECODE_ALIGNED_UNATTESTED_SOURCE_BUILD"
                  if all(e["status"] == "EXACT_JVM_INVOKE_ALIGNED" for e in edges)
                  else "SOME_HOPS_NOT_JVM_ALIGNED")
        if status.startswith("ALL_HOPS"):
            aligned += 1
        else:
            missing += 1
        lead["kotlin_jvm_alignment"] = {
            "status": status, "edges": edges,
            "source_build_freshness_verified": False,
            "compiler_provenance_authenticated": False,
            "runtime_effect_verified": False,
            "taint_validated_by_bytecode": False,
        }
    report["kotlin_jvm_comparison"] = {
        "aligned_leads": aligned, "unaligned_kotlin_leads": missing,
        "non_kotlin_leads": non_kotlin, "coverage": coverage,
        "source_build_freshness_verified": False,
        "meaning": "JVM callsite matches pinned class bytes, not source rebuild or runtime proof",
    }
    return report
