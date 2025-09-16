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


def u16_le(buf: bytes, off: int) -> Tuple[int, int]:
    return _unpack_le("<H", 2, buf, off)


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
# Int64Property: u16==0x0800 (2048), 8x 0x00, then 8-byte LE value
# IntProperty:   u16==0x0400 (1024), 8x 0x00, then 4-byte LE value, then +4 bytes (ignored)
def try_mw5_int64_pattern(block: bytes) -> Optional[int]:
    try:
        for skip in range(0, 5):  # allow a few noise bytes before the tag
            if len(block) < skip + 2 + 8 + 8:
                continue
            tag, off = u16_le(block, skip)
            if tag != 0x0800:
                continue
            zeros, off2 = read_bytes(block, off, 8)
            if any(zeros):
                continue
            val, _ = i64_le(block, off2)
            return val
    except Exception:
        pass
    return None


def try_mw5_int32_pattern(block: bytes) -> Optional[int]:
    try:
        for skip in range(0, 5):
            if len(block) < skip + 2 + 8 + 4:
                continue
            tag, off = u16_le(block, skip)
            if tag != 0x0400:
                continue
            zeros, off2 = read_bytes(block, off, 8)
            if any(zeros):
                continue
            val, _ = i32_le(block, off2)
            # trailing 4 bytes often present; ignore
            return val
    except Exception:
        pass
    return None


def try_mw5_float(block: bytes) -> Optional[float]:
    try:
        if len(block) >= 10 + 4:
            val, _ = f32_le(block, 10)
            return float(val)
    except Exception:
        pass
    return None


def try_mw5_double(block: bytes) -> Optional[float]:
    try:
        if len(block) >= 10 + 8:
            val, _ = f64_le(block, 10)
            return float(val)
    except Exception:
        pass
    return None


def try_mw5_bool(block: bytes) -> Optional[bool]:
    try:
        if len(block) >= 9 + 1:
            raw_byte, _ = read_bytes(block, 9, 1)
            return bool(raw_byte[0])
    except Exception:
        pass
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
      - exactly 18 bytes later begins the int64 LE ticks value
    Fallback to the 0x0800 + 8x00 + int64 pattern if needed.
    """
    p = block.find(b"DateTime")
    if p != -1:
        ticks_off = p + len(b"DateTime") + 18
        if ticks_off + 8 <= len(block):
            try:
                ticks, _ = i64_le(block, ticks_off)
                return {"ticks": ticks, "unit": "ticks_100ns", "value": ticks_to_iso(ticks)}
            except Exception:
                pass
    val = try_mw5_int64_pattern(block)
    if val is not None:
        return {"ticks": val, "unit": "ticks_100ns", "value": ticks_to_iso(val)}
    return None


# -------------------- Fallback decoders --------------------
def slice_bool_fallback(block: bytes) -> Optional[bool]:
    if b"\x01" in block: return True
    if b"\x00" in block: return False
    s = " " + to_ascii(block).lower() + " "
    if " true " in s: return True
    if " false " in s: return False
    return None


def slice_guid(block: bytes) -> Optional[str]:
    m = GUID_HEX_BYTES_RE.search(block)
    if m:
        raw = re.sub(rb"\s+", b"", m.group(0))
        return to_ascii(raw)[:32]
    if len(block) >= 16:
        return block[:16].hex()
    return None


def slice_stringlike(block: bytes) -> Optional[str]:
    p = best_match(PATH_RE, block)
    if p:
        return to_ascii(p)
    q = best_group(QUOTED_RE, block)
    if q:
        return to_ascii(q).strip()
    txt = " ".join(to_ascii(block).split())
    return txt if txt else None


def slice_enum(block: bytes) -> Optional[str]:
    e = best_match(ENUM_RE, block)
    return to_ascii(e) if e else slice_stringlike(block)


def slice_float_fallback(block: bytes) -> Optional[float]:
    try:
        v, _ = f32_le(block, 0)
        return float(v)
    except Exception:
        pass
    m = FLOAT_RE.search(block)
    if m:
        try:
            return float(to_ascii(m.group(0)))
        except Exception:
            return None
    return None


def slice_double_fallback(block: bytes) -> Optional[float]:
    try:
        v, _ = f64_le(block, 0)
        return float(v)
    except Exception:
        pass
    m = FLOAT_RE.search(block)
    if m:
        try:
            return float(to_ascii(m.group(0)))
        except Exception:
            return None
    return None


def slice_int_fallback(block: bytes) -> Optional[int]:
    m = INT_RE.search(block)
    if m:
        try:
            return int(m.group(0))
        except Exception:
            return None
    return None


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
        block = buf[e:nxt_start]
        cur = stack[-1]

        if tname == b"Int64Property":
            val = try_mw5_int64_pattern(block)
            if val is None:
                try:
                    val, _ = i64_le(block, 0)
                except Exception:
                    val = slice_int_fallback(block)
            attach_value(cur, key, val)
            # Special: StartingDateTicks -> also add StartingDate
            if key == "StartingDateTicks" and isinstance(val, int):
                attach_value(cur, "StartingDate", ticks_to_iso(val))

        elif tname == b"IntProperty":
            val = try_mw5_int32_pattern(block)
            if val is None:
                try:
                    val, _ = i32_le(block, 0)
                except Exception:
                    val = slice_int_fallback(block)
            attach_value(cur, key, val)

        elif tname == b"BoolProperty":
            val = try_mw5_bool(block)
            if val is None:
                val = slice_bool_fallback(block)
            attach_value(cur, key, val)

        elif tname == b"ByteProperty":
            v = try_mw5_int32_pattern(block)  # sometimes same header pattern shows up
            if v is None:
                v = block[0] if block else None
            attach_value(cur, key, v)

        elif tname == b"FloatProperty":
            v = try_mw5_float(block)
            if v is None:
                v = slice_float_fallback(block)
            attach_value(cur, key, v)

        elif tname == b"DoubleProperty":
            v = try_mw5_double(block)
            if v is None:
                v = slice_double_fallback(block)
            attach_value(cur, key, v)

        elif tname in (b"StrProperty", b"NameProperty", b"ObjectProperty"):
            attach_value(cur, key, slice_stringlike(block))

        elif tname == b"EnumProperty":
            attach_value(cur, key, slice_enum(block))

        elif tname == b"Guid":
            attach_value(cur, key, slice_guid(block))

        elif tname == b"StructProperty":
            # Explicit DateTime handling with "DateTime" plus 18 bytes plus ticks
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

    nested = parse_mixed(bs)
    result = {"detected_format": "mw5-mixed", "nested": nested}

    safe = safe_export(result, max_depth=1200, max_list=2000)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(safe, f, ensure_ascii=False, indent=2)

    print(f"Conversion complete. JSON written to: {out_path}")


if __name__ == "__main__":
    main()
