#!/usr/bin/env python3
"""
Game Client Pre-Launch Resource Validator & Shared Tooling Helpers (tools/validate_resources.py)

Audits an extracted Game Client `Resources/` directory (.lua, .plistb, .xmlb, .pb,
.pvr.ccz, .png, .jpg/.jpeg, and SQLite 3 .db tables) using read-only RFC 8089 URIs,
and exposes shared path/JSON/SQLite utilities reused by sibling `tools/*.py` scripts.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from collections import Counter, defaultdict
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple, Union

BT_ENCRYPT_MAGIC = b"\xfe\xfe\xfe\xfe"
LUAJIT_MAGIC = b"\x1bLJ"
LUA_BYTECODE_MAGIC = b"\x1bLua"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPG_MAGIC = b"\xff\xd8\xff"
CCZ_MAGIC = b"CCZ!"
SQLITE3_MAGIC = b"SQLite format 3\x00"
VALID_BT_KEY_COUNT = 16  # 16-key bt_decrypt XOR table (indices 0..15)


# ============================================================================
# Shared Path / JSON / SQLite Helpers (reused by tools/run_cobalt_relay_e2e.py)
# ============================================================================


def resolve_existing_file(candidates: Iterable[Optional[Union[str, Path]]]) -> Optional[Path]:
    """Return the first resolved regular file path among candidate strings/Paths."""
    for raw in candidates:
        if not raw:
            continue
        p = Path(raw).expanduser().resolve()
        if p.is_file():
            return p
    return None


def write_json_report(out_path: Path, payload: Any) -> None:
    """Write formatted UTF-8 JSON creating parent directories if needed."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def build_sqlite_ro_uri(db_path: Path) -> str:
    """Build a valid cross-platform SQLite RFC 3986 / 8089 read-only URI (handles C:/, spaces, Unicode, ?/#)."""
    base_uri = db_path.resolve().as_uri()
    sep = "&" if "?" in base_uri else "?"
    return f"{base_uri}{sep}mode=ro&immutable=1"


@contextmanager
def open_sqlite_readonly(db_path: Path, raw_bytes: bool = True) -> Iterator[sqlite3.Connection]:
    """Open an immutable read-only SQLite3 connection via RFC 8089 URI and guarantee close."""
    conn = sqlite3.connect(build_sqlite_ro_uri(db_path), uri=True)
    if raw_bytes:
        conn.text_factory = bytes
    try:
        yield conn
    finally:
        conn.close()


def _append_sample(samples: List[str], message: str, limit: int = 10) -> None:
    if len(samples) < limit:
        samples.append(message)


# ============================================================================
# Audit Data Models
# ============================================================================


@dataclass
class LuaStats:
    total: int = 0
    plaintext: int = 0
    luajit_bytecode: int = 0
    lua51_bytecode: int = 0
    lua_other_bytecode: int = 0
    bt_encrypted: int = 0
    empty_or_unknown: int = 0
    bt_key_indices: Dict[int, int] = field(default_factory=dict)
    bytecode_samples: List[str] = field(default_factory=list)


@dataclass
class BinaryAssetStats:
    total: int = 0
    plain_or_raw: int = 0
    bt_encrypted: int = 0
    empty: int = 0
    bt_key_indices: Dict[int, int] = field(default_factory=dict)


@dataclass
class PvrCczStats:
    total: int = 0
    valid_ccz: int = 0
    bt_encrypted: int = 0
    unexpected_header: int = 0
    bt_key_indices: Dict[int, int] = field(default_factory=dict)


@dataclass
class ImageStats:
    total: int = 0
    plaintext_valid: int = 0
    bt_encrypted: int = 0
    invalid_or_mismatched: int = 0
    bt_key_indices: Dict[int, int] = field(default_factory=dict)


@dataclass
class DbStats:
    total: int = 0
    valid_sqlite3: int = 0
    invalid_magic: int = 0
    bt_encrypted_file: int = 0
    open_or_query_errors: int = 0
    tables_inspected: int = 0
    dbs_with_hex_fefefefe_last_col: int = 0
    dbs_plaintext_last_col_only: int = 0
    dbs_empty_tables: int = 0
    last_col_bt_key_indices: Dict[int, int] = field(default_factory=dict)
    error_samples: List[str] = field(default_factory=list)


@dataclass
class AuditReport:
    resources_dir: str
    total_files_scanned: int = 0
    lua: LuaStats = field(default_factory=LuaStats)
    plistb: BinaryAssetStats = field(default_factory=BinaryAssetStats)
    xmlb: BinaryAssetStats = field(default_factory=BinaryAssetStats)
    pb: BinaryAssetStats = field(default_factory=BinaryAssetStats)
    pvr_ccz: PvrCczStats = field(default_factory=PvrCczStats)
    png: ImageStats = field(default_factory=ImageStats)
    jpg: ImageStats = field(default_factory=ImageStats)
    db: DbStats = field(default_factory=DbStats)
    mobile_compressed_textures: Dict[str, int] = field(default_factory=dict)
    out_of_range_key_indices: List[str] = field(default_factory=list)
    blockers: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    verdict: str = "READY"


# ============================================================================
# Header & Encryption Inspection
# ============================================================================


def read_header(path: Path, n: int = 64) -> bytes:
    with path.open("rb") as f:
        return f.read(n)


def parse_bt_key_index(header: bytes) -> Optional[int]:
    """Extract the 1-byte bt_decrypt keyIndex at header[9] ([0..3]=magic, [4..7]=payloadSize, [8]=algoIndex, [9]=keyIndex)."""
    if len(header) >= 10 and header[:4] == BT_ENCRYPT_MAGIC:
        return header[9]
    return None


def looks_like_plaintext_lua(header: bytes) -> bool:
    if not header:
        return False
    sample = header[3:] if header.startswith(b"\xef\xbb\xbf") else header
    if not sample:
        return True
    if b"\x00" in sample:
        return False
    for trim_len in (0, 1, 2, 3):
        candidate = sample if trim_len == 0 else sample[:-trim_len]
        if not candidate:
            break
        try:
            candidate.decode("utf-8", errors="strict")
            return True
        except UnicodeDecodeError:
            continue
    return False


def try_decode_hex_fefefefe(value: object) -> Tuple[bool, Optional[int]]:
    """Detect either raw binary `0xFEFEFEFE` blobs or hex-encoded `fefefefe...` text in SQLite last columns."""
    if value is None:
        return False, None
    if isinstance(value, bytes):
        if len(value) >= 10 and value[:4] == BT_ENCRYPT_MAGIC:
            return True, parse_bt_key_index(value)
        try:
            text = value.decode("ascii")
        except UnicodeDecodeError:
            return False, None
    elif isinstance(value, str):
        text = value
    else:
        return False, None

    text = text.strip()
    if len(text) < 20 or (len(text) % 2) != 0 or text[:8].lower() != "fefefefe":
        return False, None
    try:
        decoded_prefix = bytes.fromhex(text[:20])
        bytes.fromhex(text)
    except ValueError:
        return False, None
    return True, parse_bt_key_index(decoded_prefix)


def audit_db_file(
    db_path: Path,
    rel_path: str,
    sample_rows: int,
    stats: DbStats,
    db_key_counter: Counter,
    out_of_range_keys: List[str],
) -> None:
    stats.total += 1
    try:
        header = read_header(db_path, 16)
    except OSError as exc:
        stats.open_or_query_errors += 1
        _append_sample(stats.error_samples, f"{rel_path}: read error ({exc})")
        return

    if header.startswith(BT_ENCRYPT_MAGIC):
        stats.bt_encrypted_file += 1
        stats.invalid_magic += 1
        _append_sample(stats.error_samples, f"{rel_path}: encrypted with 0xFEFEFEFE (expected plaintext SQLite 3)")
        return

    if header != SQLITE3_MAGIC:
        stats.invalid_magic += 1
        _append_sample(stats.error_samples, f"{rel_path}: invalid SQLite 3 magic ({header[:8].hex()})")
        return

    stats.valid_sqlite3 += 1
    try:
        with open_sqlite_readonly(db_path, raw_bytes=True) as conn:
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            tables = [row[0].decode("utf-8", errors="replace") for row in cur.fetchall()]
            if not tables:
                stats.dbs_empty_tables += 1
                return

            found_encrypted_last_col = False
            saw_any_row = False
            for table in tables:
                stats.tables_inspected += 1
                safe_table = table.replace('"', '""')
                sql = f'SELECT * FROM "{safe_table}"' + (f" LIMIT {sample_rows}" if sample_rows > 0 else "")
                cur.execute(sql)
                rows = cur.fetchall()
                if not rows:
                    continue
                saw_any_row = True
                for row in rows:
                    if not row:
                        continue
                    is_enc, key_idx = try_decode_hex_fefefefe(row[-1])
                    if is_enc:
                        found_encrypted_last_col = True
                        if key_idx is not None:
                            db_key_counter[key_idx] += 1
                            if key_idx >= VALID_BT_KEY_COUNT:
                                _append_sample(out_of_range_keys, f"{rel_path} (table {table}): key_idx={key_idx}")

            if not saw_any_row:
                stats.dbs_empty_tables += 1
            elif found_encrypted_last_col:
                stats.dbs_with_hex_fefefefe_last_col += 1
            else:
                stats.dbs_plaintext_last_col_only += 1
    except sqlite3.Error as exc:
        stats.open_or_query_errors += 1
        _append_sample(stats.error_samples, f"{rel_path}: SQLite error ({exc})")


def audit_resources(resources_dir: Path, db_sample_rows: int = 5) -> AuditReport:
    report = AuditReport(resources_dir=str(resources_dir))
    key_counters: Dict[str, Counter] = defaultdict(Counter)
    mobile_tex_counter: Counter = Counter()

    def record_key(bucket: str, key_idx: Optional[int], rel: str) -> None:
        if key_idx is not None:
            key_counters[bucket][key_idx] += 1
            if key_idx >= VALID_BT_KEY_COUNT:
                _append_sample(report.out_of_range_key_indices, f"{rel}: key_idx={key_idx}")

    def classify_image(stats: ImageStats, bucket: str, magic: bytes, hdr: bytes, rel: str) -> None:
        stats.total += 1
        if hdr.startswith(BT_ENCRYPT_MAGIC):
            stats.bt_encrypted += 1
            record_key(bucket, parse_bt_key_index(hdr), rel)
        elif hdr.startswith(magic):
            stats.plaintext_valid += 1
        else:
            stats.invalid_or_mismatched += 1

    bin_targets = {".plistb": report.plistb, ".xmlb": report.xmlb, ".pb": report.pb}

    for root, _, filenames in os.walk(resources_dir):
        root_path = Path(root)
        for fname in filenames:
            report.total_files_scanned += 1
            fpath = root_path / fname
            rel = str(fpath.relative_to(resources_dir)).replace("\\", "/")
            lower = fname.lower()

            if lower.endswith(".pvr.ccz"):
                report.pvr_ccz.total += 1
                try:
                    header = read_header(fpath, 16)
                except OSError as exc:
                    report.pvr_ccz.unexpected_header += 1
                    report.warnings.append(f"Unreadable .pvr.ccz {rel}: {exc}")
                    continue
                if header.startswith(BT_ENCRYPT_MAGIC):
                    report.pvr_ccz.bt_encrypted += 1
                    record_key("ccz", parse_bt_key_index(header), rel)
                elif header.startswith(CCZ_MAGIC):
                    report.pvr_ccz.valid_ccz += 1
                else:
                    report.pvr_ccz.unexpected_header += 1
                continue

            ext = ".db" if lower == ".db" else os.path.splitext(lower)[1]
            if ext == ".db":
                audit_db_file(
                    fpath, rel, db_sample_rows, report.db, key_counters["db"], report.out_of_range_key_indices
                )
                continue
            if ext in (".pkm", ".ktx", ".etc", ".pvr"):
                mobile_tex_counter[ext] += 1
                continue
            if ext not in (".lua", ".plistb", ".xmlb", ".pb", ".png", ".jpg", ".jpeg"):
                continue

            try:
                header = read_header(fpath, 64 if ext == ".lua" else 16)
            except OSError as exc:
                report.warnings.append(f"Unreadable asset {rel}: {exc}")
                continue

            if ext == ".lua":
                report.lua.total += 1
                if not header:
                    report.lua.empty_or_unknown += 1
                elif header.startswith(BT_ENCRYPT_MAGIC):
                    report.lua.bt_encrypted += 1
                    record_key("lua", parse_bt_key_index(header), rel)
                elif header.startswith(LUAJIT_MAGIC):
                    report.lua.luajit_bytecode += 1
                    _append_sample(report.lua.bytecode_samples, f"{rel} (LuaJIT)")
                elif header.startswith(LUA_BYTECODE_MAGIC):
                    ver = header[4] if len(header) > 4 else 0
                    if ver == 0x51:
                        report.lua.lua51_bytecode += 1
                    else:
                        report.lua.lua_other_bytecode += 1
                    _append_sample(report.lua.bytecode_samples, f"{rel} (Lua 0x{ver:02x})")
                elif looks_like_plaintext_lua(header):
                    report.lua.plaintext += 1
                else:
                    report.lua.empty_or_unknown += 1
            elif ext in bin_targets:
                target = bin_targets[ext]
                target.total += 1
                if not header:
                    target.empty += 1
                elif header.startswith(BT_ENCRYPT_MAGIC):
                    target.bt_encrypted += 1
                    record_key(ext, parse_bt_key_index(header), rel)
                else:
                    target.plain_or_raw += 1
            elif ext == ".png":
                classify_image(report.png, "png", PNG_MAGIC, header, rel)
            else:
                classify_image(report.jpg, "jpg", JPG_MAGIC, header, rel)

    for attr, key_name in (
        (report.lua, "lua"),
        (report.plistb, ".plistb"),
        (report.xmlb, ".xmlb"),
        (report.pb, ".pb"),
        (report.pvr_ccz, "ccz"),
        (report.png, "png"),
        (report.jpg, "jpg"),
    ):
        attr.bt_key_indices = dict(sorted(key_counters[key_name].items()))
    report.db.last_col_bt_key_indices = dict(sorted(key_counters["db"].items()))
    report.mobile_compressed_textures = dict(sorted(mobile_tex_counter.items()))

    if report.total_files_scanned == 0:
        report.blockers.append("Resources directory is empty (0 files scanned).")
    if report.lua.total == 0:
        report.blockers.append("No .lua scripts found in Resources/.")
    if report.lua.luajit_bytecode > 0:
        report.warnings.append(
            f"{report.lua.luajit_bytecode} LuaJIT bytecode file(s) detected; "
            "ensure the client links LuaJIT (lua51.dll) rather than PUC-Rio Lua 5.1."
        )
    if report.lua.lua_other_bytecode > 0:
        report.blockers.append(f"{report.lua.lua_other_bytecode} non-5.1 Lua bytecode file(s) detected.")
    if report.lua.lua51_bytecode > 0:
        report.warnings.append(
            f"{report.lua.lua51_bytecode} Lua 5.1 bytecode file(s) detected; "
            "verify pointer/size_t header compatibility."
        )
    if report.db.invalid_magic > 0 or report.db.open_or_query_errors > 0:
        report.blockers.append(
            f"{report.db.invalid_magic} .db file(s) failed SQLite 3 magic check and "
            f"{report.db.open_or_query_errors} failed to open/query."
        )
    if report.out_of_range_key_indices:
        report.blockers.append(
            f"Found bt_decrypt key index >= {VALID_BT_KEY_COUNT} outside the 16-key table "
            f"(e.g., {report.out_of_range_key_indices[0]})."
        )
    if report.png.invalid_or_mismatched > 0 or report.jpg.invalid_or_mismatched > 0:
        report.warnings.append(
            f"Unexpected image headers: {report.png.invalid_or_mismatched} .png, "
            f"{report.jpg.invalid_or_mismatched} .jpg/.jpeg."
        )
    if report.pvr_ccz.unexpected_header > 0:
        report.warnings.append(f"{report.pvr_ccz.unexpected_header} .pvr.ccz file(s) lack CCZ! or 0xFEFEFEFE magic.")
    if report.mobile_compressed_textures:
        summary = ", ".join(f"{k}:{v}" for k, v in report.mobile_compressed_textures.items())
        report.warnings.append(
            f"Mobile-compressed textures detected ({summary}); desktop OpenGL will use software RGBA8888 decode."
        )

    report.verdict = (
        "NOT READY (BLOCKED)"
        if report.blockers
        else ("READY WITH WARNINGS" if report.warnings else "READY")
    )
    return report


def format_key_histogram(hist: Dict[int, int]) -> str:
    return ", ".join(f"k{k}:{v}" for k, v in sorted(hist.items())) if hist else "-"


def print_concise_report(report: AuditReport, verbose: bool = False) -> None:
    sep_eq, sep_dash = "=" * 76, "-" * 76
    print(f"{sep_eq}\nGame Client Win32 Resource Readiness Audit\n{sep_eq}")
    print(f"Directory : {report.resources_dir}\nScanned   : {report.total_files_scanned:,} total files\nVerdict   : {report.verdict}\n{sep_dash}")
    print(f"{'Category':<12} {'Total':>7}  Breakdown\n{sep_dash}")

    rows = [
        (".lua", report.lua.total, f"plain={report.lua.plaintext}, bt_enc={report.lua.bt_encrypted}, lua51_bc={report.lua.lua51_bytecode}, luajit_bc={report.lua.luajit_bytecode}, other_bc={report.lua.lua_other_bytecode}, bad={report.lua.empty_or_unknown}"),
        (".plistb", report.plistb.total, f"raw={report.plistb.plain_or_raw}, bt_enc={report.plistb.bt_encrypted}, empty={report.plistb.empty}"),
        (".xmlb", report.xmlb.total, f"raw={report.xmlb.plain_or_raw}, bt_enc={report.xmlb.bt_encrypted}, empty={report.xmlb.empty}"),
        (".pb", report.pb.total, f"raw={report.pb.plain_or_raw}, bt_enc={report.pb.bt_encrypted}, empty={report.pb.empty}"),
        (".pvr.ccz", report.pvr_ccz.total, f"ccz={report.pvr_ccz.valid_ccz}, bt_enc={report.pvr_ccz.bt_encrypted}, bad={report.pvr_ccz.unexpected_header}"),
        (".png", report.png.total, f"plain={report.png.plaintext_valid}, bt_enc={report.png.bt_encrypted}, bad={report.png.invalid_or_mismatched}"),
        (".jpg/.jpeg", report.jpg.total, f"plain={report.jpg.plaintext_valid}, bt_enc={report.jpg.bt_encrypted}, bad={report.jpg.invalid_or_mismatched}"),
        (".db", report.db.total, f"sqlite3={report.db.valid_sqlite3}, invalid={report.db.invalid_magic}, err={report.db.open_or_query_errors}, last_col_FE={report.db.dbs_with_hex_fefefefe_last_col}, last_col_plain={report.db.dbs_plaintext_last_col_only}"),
    ]
    for label, count, breakdown in rows:
        print(f"{label:<12} {count:>7}  {breakdown}")

    print(f"{sep_dash}\n0xFEFEFEFE bt_decrypt Key Index Distribution (expected 0..15):")
    for label, hist in (
        (".png", report.png.bt_key_indices),
        (".jpg/.jpeg", report.jpg.bt_key_indices),
        (".lua", report.lua.bt_key_indices),
        (".pvr.ccz", report.pvr_ccz.bt_key_indices),
        (".db lastcol", report.db.last_col_bt_key_indices),
    ):
        print(f"  {label:<11}: {format_key_histogram(hist)}")

    for heading, prefix, items in (("BLOCKERS:", "[!]", report.blockers), ("WARNINGS:", "[*]", report.warnings)):
        if items:
            print(f"{sep_dash}\n{heading}")
            for item in items:
                print(f"  {prefix} {item}")

    if verbose:
        for title, samples in (
            ("Lua Bytecode Samples:", report.lua.bytecode_samples),
            ("DB Error Samples:", report.db.error_samples),
            ("Out-of-Range bt_decrypt Key Index Samples:", report.out_of_range_key_indices),
        ):
            if samples:
                print(f"{sep_dash}\n{title}")
                for sample in samples:
                    print(f"  - {sample}")
    print(sep_eq)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Audit an extracted Game Client Resources/ directory.")
    parser.add_argument("resources_dir", type=Path, help="Path to the extracted Game Client Resources/ directory.")
    parser.add_argument("--db-sample-rows", type=int, default=5, help="Rows to sample per SQLite table (0 = all rows, default: 5).")
    parser.add_argument("--json", type=Path, default=None, help="Optional output path to write the structured JSON audit report.")
    parser.add_argument("--verbose", action="store_true", help="Print sample file paths for bytecode, DB errors, and key-index anomalies.")
    parser.add_argument("--strict", action="store_true", help="Exit with code 1 if any warnings are present (not just blockers).")
    args = parser.parse_args(argv)

    if not args.resources_dir.is_dir():
        print(f"Error: resources_dir does not exist or is not a directory: {args.resources_dir}", file=sys.stderr)
        return 2

    report = audit_resources(args.resources_dir, db_sample_rows=max(0, args.db_sample_rows))
    print_concise_report(report, verbose=args.verbose)

    if args.json is not None:
        write_json_report(args.json, asdict(report))
        print(f"JSON report written to: {args.json}")

    if report.blockers or (args.strict and report.warnings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
