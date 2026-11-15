"""Minimal read-only Android binary XML (AXML) manifest decoder.

Supports common compiled APK manifests. Does not interpret resource references,
component alias resolution, framework permissions, or runtime build variants.
Malformed/unsupported chunks fail closed rather than inventing a manifest.
"""
import struct
import xml.etree.ElementTree as ET

NO_INDEX = 0xffffffff


def _u16(buf, pos):
    if pos < 0 or pos + 2 > len(buf):
        raise ValueError("truncated AXML uint16")
    return struct.unpack_from("<H", buf, pos)[0]


def _u32(buf, pos):
    if pos < 0 or pos + 4 > len(buf):
        raise ValueError("truncated AXML uint32")
    return struct.unpack_from("<I", buf, pos)[0]


def _length8(buf, pos):
    first = buf[pos] if pos < len(buf) else None
    if first is None:
        raise ValueError("truncated UTF8 length")
    if first & 0x80:
        if pos + 1 >= len(buf):
            raise ValueError("truncated UTF8 length")
        return ((first & 0x7f) << 8) | buf[pos + 1], pos + 2
    return first, pos + 1


def _length16(buf, pos):
    first = _u16(buf, pos)
    if first & 0x8000:
        return ((first & 0x7fff) << 16) | _u16(buf, pos + 2), pos + 4
    return first, pos + 2


def _strings(data, off, chunk_size):
    header = _u16(data, off + 2)
    count = _u32(data, off + 8)
    flags = _u32(data, off + 16)
    begin = _u32(data, off + 20)
    if header < 28 or count > 200000 or header + count * 4 > chunk_size:
        raise ValueError("invalid AXML string pool")
    output = []
    for i in range(count):
        relative = _u32(data, off + header + i * 4)
        pos = off + begin + relative
        if not off <= pos < off + chunk_size:
            raise ValueError("AXML string points outside pool")
        if flags & 0x100:
            _, pos = _length8(data, pos)  # UTF-16 codepoint count
            length, pos = _length8(data, pos)
            end = pos + length
            if end >= off + chunk_size or data[end] != 0:
                raise ValueError("invalid AXML UTF8 value")
            output.append(data[pos:end].decode("utf-8"))
        else:
            length, pos = _length16(data, pos)
            end = pos + length * 2
            if end + 1 >= off + chunk_size or data[end:end + 2] != b"\0\0":
                raise ValueError("invalid AXML UTF16 value")
            output.append(data[pos:end].decode("utf-16le"))
    return output


def decode_manifest(data):
    """Return ElementTree root for a compiled binary AndroidManifest.xml."""
    if len(data) < 8 or _u16(data, 0) != 0x0003:
        raise ValueError("not Android binary XML")
    if _u32(data, 4) != len(data):
        raise ValueError("AXML declared size mismatch")
    strings = []
    stack = []
    root = None
    pos = _u16(data, 2)
    if not 8 <= pos <= len(data):
        raise ValueError("invalid AXML header")
    while pos < len(data):
        if pos + 8 > len(data):
            raise ValueError("truncated AXML chunk")
        kind, header, length = struct.unpack_from("<HHI", data, pos)
        if length < header or header < 8 or pos + length > len(data):
            raise ValueError("invalid AXML chunk boundary")
        if kind == 0x0001:
            strings = _strings(data, pos, length)
        elif kind == 0x0102:
            if header < 36 or not strings:
                raise ValueError("invalid AXML start element")
            ns, name = _u32(data, pos + 16), _u32(data, pos + 20)
            start, width, count = struct.unpack_from("<HHH", data, pos + 24)
            if name >= len(strings) or count > 10000 or width < 20:
                raise ValueError("invalid AXML element attributes")
            qname = strings[name]
            if ns != NO_INDEX:
                if ns >= len(strings):
                    raise ValueError("invalid AXML namespace")
                qname = "{" + strings[ns] + "}" + qname
            attributes = {}
            base = pos + 16 + start
            if base + count * width > pos + length:
                raise ValueError("AXML attributes exceed chunk")
            for i in range(count):
                cursor = base + i * width
                ans, aname, raw = struct.unpack_from("<III", data, cursor)
                kind_value = data[cursor + 15]
                val = _u32(data, cursor + 16)
                if aname >= len(strings):
                    raise ValueError("invalid AXML attribute name")
                key = strings[aname]
                if ans != NO_INDEX:
                    if ans >= len(strings):
                        raise ValueError("invalid AXML attribute namespace")
                    key = "{" + strings[ans] + "}" + key
                if raw != NO_INDEX:
                    if raw >= len(strings):
                        raise ValueError("invalid AXML raw attribute")
                    text = strings[raw]
                elif kind_value == 0x03 and val < len(strings):
                    text = strings[val]
                elif kind_value == 0x12:
                    text = "true" if val else "false"
                elif kind_value == 0x10:
                    text = str(val)
                elif kind_value in (0x01, 0x11):
                    text = "@0x%08x" % val
                else:
                    text = "typed:0x%02x:0x%08x" % (kind_value, val)
                attributes[key] = text
            element = ET.Element(qname, attributes)
            if stack:
                stack[-1].append(element)
            else:
                if root is not None:
                    raise ValueError("multiple AXML roots")
                root = element
            stack.append(element)
        elif kind == 0x0103:
            if not stack:
                raise ValueError("unmatched AXML end")
            stack.pop()
        pos += length
    if root is None or stack or root.tag != "manifest":
        raise ValueError("incomplete Android manifest")
    return root
