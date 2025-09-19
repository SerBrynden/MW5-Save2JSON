import datetime
import json
import os
import re
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple, Pattern

sys.setrecursionlimit(20000)


# -------------------- Byte helpers --------------------
def _unpack_le(fmt: str, size: int, buf: bytes, off: int) -> Tuple[Any, int]:
    """
    Internal helper to unpack a little-endian value with strict bounds checking.
    Returns (value, next_offset).
    """
    if off + size > len(buf):
        raise EOFError
    return struct.unpack_from(fmt, buf, off)[0], off + size


def i32_le(buf: bytes, off: int) -> Tuple[int, int]:
    return _unpack_le("<i", 4, buf, off)


def i64_le(buf: bytes, off: int) -> Tuple[int, int]:
    return _unpack_le("<q", 8, buf, off)


def f32_le(buf: bytes, off: int) -> Tuple[float, int]:
    val, next_off = _unpack_le("<f", 4, buf, off)
    return float(val), next_off


def f64_le(buf: bytes, off: int) -> Tuple[float, int]:
    val, next_off = _unpack_le("<d", 8, buf, off)
    return float(val), next_off


def read_bytes(buf: bytes, off: int, n: int) -> Tuple[bytes, int]:
    if off + n > len(buf): raise EOFError
    return buf[off:off + n], off + n


# -------------------- Patterns & utilities --------------------
TYPE_NAMES = [
    b"StrProperty", b"NameProperty", b"BoolProperty", b"IntProperty", b"Int64Property",
    b"ByteProperty", b"EnumProperty", b"Guid", b"FloatProperty", b"DoubleProperty",
    b"ObjectProperty", b"StructProperty", b"ArrayProperty", b"MapProperty",
]
TYPE_ALTS = {t: re.compile(re.escape(t)) for t in TYPE_NAMES}
NONE_RE_BIN = re.compile(rb"None")
PATH_RE = re.compile(rb"(/Game/\S+|/Script/\S+)")
ENUM_RE = re.compile(rb"[A-Za-z_][A-Za-z0-9_]*::[A-Za-z_][A-Za-z0-9_]*")
QUOTED_RE = re.compile(rb'"(.*?)"')  # ASCII quotes only (bytes-safe)
INT_RE = re.compile(rb"[-+]?\d+")
FLOAT_RE = re.compile(rb"[-+]?(?:\d+\.\d*|\.\d+)(?:[eE][-+]?\d+)?")
GUID_HEX_BYTES_RE = re.compile(rb"(?:[0-9A-Fa-f]{2}\s*){16,}")
# Explicit MW5 binary layout constants to replace magic numbers
SIZE_PREFIX_LEN = 9  # 8-byte LE size + 1 empty byte before payload
BOOL_PREFIX_PAD = 8  # 8 empty bytes before a 1-byte bool value


def to_ascii(s: bytes) -> str:
    try:
        return s.decode("utf-8", "ignore")
    except Exception:
        return s.decode("latin-1", "ignore")


def best_match(pat: Pattern[bytes], buf: bytes) -> Optional[bytes]:
    m = pat.search(buf)
    return m.group(0) if m else None


def best_group(pat: Pattern[bytes], buf: bytes) -> Optional[bytes]:
    m = pat.search(buf)
    return m.group(1) if m else None


# -------------------- Backward key finder --------------------
def find_key_before(buf: bytes, type_pos: int, max_back: int = 160) -> Optional[str]:
    """
    Scan backwards from 'type_pos' to find an ASCII identifier immediately preceding it,
    skipping arbitrary control bytes. Returns the key as a str or None.
    """
    start = max(0, type_pos - max_back)
    window = buf[start:type_pos]
    i = len(window) - 1

    def is_ident(c: int) -> bool:
        return (65 <= c <= 90) or (97 <= c <= 122) or (48 <= c <= 57) or c == 95

    while i >= 0 and not is_ident(window[i]): i -= 1
    if i < 0: return None
    end = i + 1
    while i >= 0 and is_ident(window[i]): i -= 1
    ident = window[i + 1:end]
    if not ident: return None
    if not ((65 <= ident[0] <= 90) or (97 <= ident[0] <= 122) or ident[0] == 95):
        return None
    return to_ascii(ident)


# -------------------- MW5 numeric payload heuristics --------------------
def _read_after_size_prefix(block: bytes, reader) -> Optional[Any]:
    """
    Shared helper for MW5 patterns where payload follows a size+pad prefix.
    Calls 'reader(block, offset)' and returns the value or None on error.
    """
    try:
        if len(block) < SIZE_PREFIX_LEN:
            return None
        val, _ = reader(block, SIZE_PREFIX_LEN)
        return val
    except Exception:
        return None


def try_mw5_int32_pattern(block: bytes) -> Optional[int]:
    # Pattern: [8-byte LE size][1 empty byte][4-byte LE int32]
    return _read_after_size_prefix(block, i32_le)


def try_mw5_int64_pattern(block: bytes) -> Optional[int]:
    # Pattern: [8-byte LE size][1 empty byte][8-byte LE int64]
    return _read_after_size_prefix(block, i64_le)


def try_mw5_float(block: bytes) -> Optional[float]:
    # Pattern: [8-byte LE size][1 empty byte][4-byte LE float]
    val = _read_after_size_prefix(block, f32_le)
    return float(val) if val is not None else None


def try_mw5_double(block: bytes) -> Optional[float]:
    # Pattern: [8-byte LE size][1 empty byte][8-byte LE double]
    val = _read_after_size_prefix(block, f64_le)
    return float(val) if val is not None else None


def try_mw5_bool(block: bytes) -> Optional[bool]:
    # Pattern: [8 empty bytes][1-byte bool value]
    try:
        if len(block) < BOOL_PREFIX_PAD + 1:
            return None
        raw_byte, _ = read_bytes(block, BOOL_PREFIX_PAD, 1)
        return bool(raw_byte[0])
    except Exception:
        return None


def try_mw5_byte_property(block: bytes) -> Optional[int]:
    try:
        # Pattern: [4-byte LE int][1 empty terminating byte] (some payloads may omit terminator in slice)
        if len(block) < 4:
            return None
        val, _ = i32_le(block, 0)
        return val
    except Exception:
        return None


# -------------------- DateTime (.NET ticks) --------------------
DOTNET_EPOCH = datetime.datetime(1, 1, 1, tzinfo=datetime.timezone.utc)


def ticks_to_iso(ticks: int) -> str:
    try:
        # .NET ticks are 100 ns; convert to integer microseconds to avoid float rounding
        return (DOTNET_EPOCH + datetime.timedelta(microseconds=ticks // 10)).isoformat()
    except Exception:
        return f"<<invalid ticks={ticks}>>"


def try_mw5_datetime(block: bytes) -> Optional[dict]:
    """
    MW5 DateTime struct payload:
      - ASCII token 'DateTime' appears in the slice
      - immediately after the token there is an empty byte (0x00)
      - then 17 empty filler bytes (0x00)
      - then the 8-byte LE ticks value
    """
    p = block.find(b"DateTime")
    if p != -1:
        ticks_off = p + len(b"DateTime") + 1 + 17  # 1 empty after type name + 17 filler zeros
        if ticks_off + 8 <= len(block):
            try:
                ticks, _ = i64_le(block, ticks_off)
                return {"ticks": ticks, "unit": "ticks_100ns", "value": ticks_to_iso(ticks)}
            except Exception:
                pass
    # Fallback to generic Int64-after-size-prefix layout
    val = try_mw5_int64_pattern(block)
    if val is not None:
        return {"ticks": val, "unit": "ticks_100ns", "value": ticks_to_iso(val)}
    return None


# -------------------- Fallback decoders --------------------
def slice_guid(block: bytes) -> Optional[str]:
    m = GUID_HEX_BYTES_RE.search(block)
    if m:
        raw = re.sub(rb"\s+", b"", m.group(0))
        return to_ascii(raw)[:32]
    if len(block) >= 16:
        return block[:16].hex()
    return None


def _decode_stringlike_structured(block: bytes) -> Optional[str]:
    """
    Attempt to decode ObjectProperty / StrProperty / NameProperty payloads with pattern:
      [8 bytes outer size][4 bytes inner size][inner bytes including 0x00 terminator]
    Returns a clean string (without embedded NULs) if the pattern matches.
    """
    try:
        # Need at least 12 bytes for sizes
        if len(block) < 12:
            return None

        # Try a few starting offsets in case of a leading padding/flag byte
        for base_off in (0, 1, 2, 3, 4):
            if len(block) < base_off + 12:
                break
            outer_size, off = _unpack_le("<Q", 8, block, base_off)
            inner_size, off = _unpack_le("<I", 4, block, off)

            # Sanity checks
            if inner_size <= 0 or inner_size > len(block) - off:
                continue
            # Outer size may include header bytes; require it at least to be big enough to contain inner
            if outer_size and outer_size < 4 + inner_size:
                continue

            raw, _ = read_bytes(block, off, inner_size)

            # If terminator present, drop it
            if raw and raw[-1] == 0x00:
                raw = raw[:-1]

            # Decode and sanitize NULs just in case
            s = to_ascii(raw).replace("\x00", "").strip()
            return s if s is not None else ""

        return None
    except Exception:
        return None


def slice_stringlike(block: bytes) -> Optional[str]:
    # Try structured pattern first to avoid leaking NULs into JSON
    structured = _decode_stringlike_structured(block)
    if structured is not None:
        return structured

    # If a NUL appears early, treat it as end-of-string to avoid swallowing following headers
    nul_pos = block.find(b"\x00")
    if 0 <= nul_pos < len(block):
        head = block[:nul_pos]
        txt = to_ascii(head).strip()
        if txt:
            return txt

    p = best_match(PATH_RE, block)
    if p:
        return to_ascii(p)
    q = best_group(QUOTED_RE, block)
    if q:
        return to_ascii(q).strip()
    # Fallback: decode whole block but strip NULs and collapse whitespace
    txt = " ".join(to_ascii(block).replace("\x00", "").split())
    return txt if txt else None


def slice_enum(block: bytes) -> Optional[str]:
    e = best_match(ENUM_RE, block)
    return to_ascii(e) if e else slice_stringlike(block)


# -------------------- Parser core --------------------
def attach_value(container: Any, key: str, value: Any) -> None:
    if isinstance(container, list):
        container.append(value)
        return
    if key in container:
        if not isinstance(container[key], list):
            container[key] = [container[key]]
        container[key].append(value)
    else:
        container[key] = value


def parse_mixed(buf: bytes) -> Dict[str, Any]:
    # Find all occurrences of property type tokens in bytes
    hits = []
    for tname, pat in TYPE_ALTS.items():
        for m in pat.finditer(buf):
            hits.append((m.start(), m.end(), tname))
    if not hits:
        return {}
    hits.sort(key=lambda x: x[0])

    # Build tokens with backward key recovery
    tokens = []
    for s, e, tname in hits:
        key = find_key_before(buf, s, max_back=160)
        if key:
            tokens.append((key, tname, s, e))
    if not tokens:
        return {}

    root: Dict[str, Any] = {}
    stack: List[Any] = [root]

    for i, (key, tname, s, e) in enumerate(tokens):
        prev_end = tokens[i - 1][3] if i > 0 else 0
        gap = buf[prev_end:s]
        none_count = len(list(NONE_RE_BIN.finditer(gap)))
        for _ in range(min(none_count, max(0, len(stack) - 1))):
            stack.pop()

        nxt_start = tokens[i + 1][2] if i + 1 < len(tokens) else len(buf)
        # Account for an empty byte (0x00) immediately following every type name token
        block_start = e + 1 if e < len(buf) and buf[e] == 0x00 else e
        block = buf[block_start:nxt_start]
        cur = stack[-1]

        if tname == b"Int64Property":
            val = try_mw5_int64_pattern(block)
            attach_value(cur, key, val)
            # Special: StartingDateTicks -> also add StartingDate
            if key == "StartingDateTicks" and isinstance(val, int):
                attach_value(cur, "StartingDate", ticks_to_iso(val))

        elif tname == b"IntProperty":
            attach_value(cur, key, try_mw5_int32_pattern(block))

        elif tname == b"BoolProperty":
            attach_value(cur, key, try_mw5_bool(block))

        elif tname == b"ByteProperty":
            v = try_mw5_byte_property(block)
            if v is None:
                v = block[0] if block else None
            attach_value(cur, key, v)

        elif tname == b"FloatProperty":
            attach_value(cur, key, try_mw5_float(block))

        elif tname == b"DoubleProperty":
            attach_value(cur, key, try_mw5_double(block))

        elif tname in (b"StrProperty", b"NameProperty", b"ObjectProperty"):
            attach_value(cur, key, slice_stringlike(block))

        elif tname == b"EnumProperty":
            attach_value(cur, key, slice_enum(block))

        elif tname == b"Guid":
            attach_value(cur, key, slice_guid(block))

        elif tname == b"StructProperty":
            # Explicit DateTime handling
            if b"DateTime" in block:
                dt = try_mw5_datetime(block)
                if dt is not None:
                    attach_value(cur, key, {"__type": "DateTime", **dt})
                    continue
            node = {"__type": key}
            attach_value(cur, key, node)
            stack.append(node)

        elif tname == b"ArrayProperty":
            node = {"__type": key, "items": []}
            attach_value(cur, key, node)
            stack.append(node["items"])

        elif tname == b"MapProperty":
            node = {"__type": key, "entries": {}}
            attach_value(cur, key, node)
            stack.append(node)

        else:
            attach_value(cur, key, slice_stringlike(block))

    return root


# -------------------- Safe JSON exporter --------------------
def safe_export(obj: Any, max_depth: int = 1200, max_list: int = 2000,
                seen: Optional[set] = None, depth: int = 0) -> Any:
    if seen is None: seen = set()
    oid = id(obj)
    if oid in seen: return "<<cycle>>"
    if depth > max_depth: return f"<<truncated depth {max_depth}>>"
    if isinstance(obj, (str, int, float, type(None), bool)): return obj
    seen.add(oid)
    try:
        if isinstance(obj, list):
            out = [safe_export(v, max_depth, max_list, seen, depth + 1)
                   for v in obj[:max_list]]
            if len(obj) > max_list:
                out.append(f"<<truncated list, total={len(obj)}>>")
            return out
        if isinstance(obj, dict):
            return {str(k): safe_export(v, max_depth, max_list, seen, depth + 1)
                    for k, v in obj.items()}
        return repr(obj)
    finally:
        seen.discard(oid)


# -------------------- Main --------------------
def _strip_outer_quotes(p: str) -> str:
    p = p.strip()
    if len(p) >= 2 and ((p[0] == p[-1] == '"') or (p[0] == p[-1] == "'")):
        return p[1:-1]
    return p


def main():
    in_path = input("Enter the path to your MechWarrior 5 save file (.sav): ").strip()
    in_path = _strip_outer_quotes(in_path)  # handle pasted paths in quotes
    if not os.path.isfile(in_path):
        print(f"Error: file not found: {in_path}")
        return
    base, _ = os.path.splitext(in_path)
    out_path = base + ".json"

    with open(in_path, "rb") as f:
        bs = f.read()

    result = parse_mixed(bs)

    safe = safe_export(result, max_depth=1200, max_list=2000)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(safe, f, ensure_ascii=False, indent=2)

    print(f"Conversion complete. JSON written to: {out_path}")


if __name__ == "__main__":
    main()
