#!/usr/bin/env python3
"""Cross-project E2E test orchestrator wiring kestrel-canvas (C++20) <-> cobalt-relay (Rust).

Runs offline C++ self-tests, resolves or builds `cobalt-relay` (`gserver`), executes all live
cross-project gameplay domains over ephemeral ports, and verifies cold WAL restart recovery.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional, Tuple

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from validate_resources import resolve_existing_file  # noqa: E402

READY_RE = re.compile(r"GSERVER_READY\s+http=([\d\.]+):(\d+)\s+tcp=([\d\.]+):(\d+)")


def find_cargo() -> Optional[str]:
    found = resolve_existing_file([
        shutil.which("cargo"),
        Path.home() / ".cargo" / "bin" / ("cargo.exe" if os.name == "nt" else "cargo"),
        Path.home() / ".local" / "bin" / "cargo",
    ])
    return str(found) if found else None


def _build_gserver(crate_root: Path, cargo: str, exe_name: str, allow_online: bool = False) -> Optional[Path]:
    cmd = [cargo, "build", "--release", "-p", "gserver", "--offline"]
    res = subprocess.run(cmd, cwd=str(crate_root))
    if res.returncode != 0 and allow_online:
        res = subprocess.run(cmd[:-1], cwd=str(crate_root))
    if res.returncode != 0:
        return None
    return resolve_existing_file([crate_root / "target" / "release" / exe_name])


def resolve_cobalt_relay(
    explicit_bin: Optional[str],
    explicit_dir: Optional[str],
    repo_root: Path,
    temp_root: Path,
    auto_clone: bool,
) -> Tuple[Optional[Path], Optional[Path]]:
    exe_name = "gserver.exe" if os.name == "nt" else "gserver"

    direct_bin = resolve_existing_file([explicit_bin, os.environ.get("COBALT_RELAY_BIN")])
    if direct_bin is not None:
        return direct_bin, direct_bin.parent.parent.parent

    candidate_dirs = [
        Path(d).resolve()
        for d in (explicit_dir, os.environ.get("COBALT_RELAY_DIR"), str(repo_root.parent / "cobalt-relay"))
        if d
    ]
    cargo = find_cargo()
    for cdir in candidate_dirs:
        if (cdir / "Cargo.toml").is_file():
            existing = resolve_existing_file([cdir / "target" / prof / exe_name for prof in ("release", "debug")])
            if existing is not None:
                return existing, cdir
            if cargo:
                print(f"[orchestrator] Building gserver in {cdir} ...", flush=True)
                built = _build_gserver(cdir, cargo, exe_name, allow_online=False)
                if built is None:
                    raise subprocess.CalledProcessError(1, [cargo, "build", "--release", "-p", "gserver", "--offline"])
                return built, cdir

    if auto_clone and cargo and shutil.which("git"):
        clone_url = os.environ.get("COBALT_RELAY_GIT_URL", "https://github.com/v0ntr3n/cobalt-relay.git")
        clone_dir = temp_root / "cobalt-relay-ci"
        preferred_ref = os.environ.get("COBALT_RELAY_GIT_REF", "feat/active-events-and-instant-buy")
        print(f"[orchestrator] Attempting ephemeral clone of {clone_url} (ref={preferred_ref}) ...", flush=True)
        res = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", preferred_ref, clone_url, str(clone_dir)],
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            shutil.rmtree(clone_dir, ignore_errors=True)
            res = subprocess.run(["git", "clone", "--depth", "1", clone_url, str(clone_dir)], capture_output=True, text=True)
        if res.returncode == 0 and (clone_dir / "Cargo.toml").is_file():
            built = _build_gserver(clone_dir, cargo, exe_name, allow_online=True)
            if built is not None:
                return built, clone_dir
        else:
            print("[orchestrator] Ephemeral clone unavailable (private or offline environment).", flush=True)

    return None, None


def start_strict_gserver(gserver_bin: Path, data_dir: Path) -> Tuple[subprocess.Popen, str, int, str, int]:
    cmd = [
        str(gserver_bin), "--strict-all",
        "--http-addr", "127.0.0.1:0",
        "--tcp-addr", "127.0.0.1:0",
        "--public-host", "127.0.0.1",
        "--data-dir", str(data_dir),
        "--print-bound-addrs",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    deadline = time.monotonic() + 15.0
    assert proc.stdout is not None
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                raise RuntimeError(f"gserver exited prematurely with code {proc.returncode}")
            time.sleep(0.05)
            continue
        sys.stdout.write(f"[gserver] {line}")
        sys.stdout.flush()
        m = READY_RE.search(line)
        if m:
            return proc, m.group(1), int(m.group(2)), m.group(3), int(m.group(4))
    proc.kill()
    raise RuntimeError("Timed out waiting for GSERVER_READY line from cobalt-relay")


def stop_process(proc: Optional[subprocess.Popen]) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def _run_live_client_suite(
    client_bin: Path,
    addrs: Tuple[str, int, str, int],
    fixture_args: List[str],
    verify_restart: bool = False,
) -> None:
    http_h, http_p, tcp_h, tcp_p = addrs
    cmd = [str(client_bin)]
    if verify_restart:
        cmd.append("--verify-restart")
    cmd.extend([
        "--http-host", http_h, "--http-port", str(http_p),
        "--tcp-host", tcp_h, "--tcp-port", str(tcp_p),
        *fixture_args,
    ])
    subprocess.run(cmd, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run kestrel-canvas <-> cobalt-relay strict E2E suite")
    parser.add_argument("--client-test-bin", required=True, help="Compiled test_cobalt_relay_e2e binary")
    parser.add_argument("--gserver-bin", default=None, help="Path to cobalt-relay gserver binary")
    parser.add_argument("--cobalt-relay-dir", default=None, help="Path to cobalt-relay workspace root")
    parser.add_argument("--require-relay", action="store_true", help="Fail if gserver binary is absent")
    parser.add_argument("--auto-clone-relay", action="store_true", help="Attempt ephemeral git clone when local sibling is absent")
    args = parser.parse_args()

    repo_root = TOOLS_DIR.parent
    client_bin = resolve_existing_file([args.client_test_bin])
    if client_bin is None:
        print(f"[FAIL] Missing client E2E binary: {Path(args.client_test_bin).resolve()}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="kestrel_cobalt_e2e_") as tmp_str:
        tmp_root = Path(tmp_str)
        gserver_bin, relay_dir = resolve_cobalt_relay(
            args.gserver_bin, args.cobalt_relay_dir, repo_root, tmp_root, args.auto_clone_relay
        )

        extra_fixture_args: List[str] = []
        if relay_dir is not None:
            vec_dir = relay_dir / "crates" / "gserver-data" / "data" / "test_vectors"
            enc_p = resolve_existing_file([vec_dir / "MainTownSceneReader.lua.enc"])
            dec_p = resolve_existing_file([vec_dir / "MainTownSceneReader.lua.dec"])
            if enc_p and dec_p:
                extra_fixture_args = ["--enc-lua", str(enc_p), "--dec-lua", str(dec_p)]

        print("[orchestrator] Step 1: Running offline C++20 self-tests ...", flush=True)
        subprocess.run([str(client_bin), "--self-test", *extra_fixture_args], check=True)

        if gserver_bin is None:
            if args.require_relay:
                print("[FAIL] --require-relay specified, but cobalt-relay gserver binary was not found.", file=sys.stderr)
                return 1
            print("[orchestrator] cobalt-relay binary not present in isolated build; offline self-tests passed.", flush=True)
            return 0

        data_dir = tmp_root / "wal_data"
        data_dir.mkdir(parents=True, exist_ok=True)

        proc1 = proc2 = None
        try:
            print(f"[orchestrator] Step 2: Spawning strict cobalt-relay ({gserver_bin}) ...", flush=True)
            proc1, *addrs1 = start_strict_gserver(gserver_bin, data_dir)

            print("[orchestrator] Step 3: Executing live C++ <-> Rust gameplay campaign ...", flush=True)
            _run_live_client_suite(client_bin, tuple(addrs1), extra_fixture_args, verify_restart=False)  # type: ignore[arg-type]

            print("[orchestrator] Step 4: Stopping gserver & verifying cold WAL restart recovery ...", flush=True)
            stop_process(proc1)
            proc1 = None

            proc2, *addrs2 = start_strict_gserver(gserver_bin, data_dir)
            _run_live_client_suite(client_bin, tuple(addrs2), extra_fixture_args, verify_restart=True)  # type: ignore[arg-type]
        finally:
            stop_process(proc1)
            stop_process(proc2)

    print("[orchestrator] SUCCESS: All strict cross-project C++ <-> Rust gameplay & WAL tests passed!", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
