#!/usr/bin/env python3
"""Cross-project E2E test orchestrator wiring kestrel-canvas (C++17) <-> cobalt-relay (Rust).

1. Runs offline C++17 `BtDecryptHook` + `LCPacket` + `Amf3Module` self-tests first.
2. Resolves `cobalt-relay` (`gserver`) from `--gserver-bin`, `$COBALT_RELAY_BIN`, sibling
   `../cobalt-relay`, or (on CI runners with git + cargo) an ephemeral temp clone of
   `https://github.com/v0ntr3n/cobalt-relay.git` outside the source tree.
3. Spawns `gserver --strict-all --http-addr 127.0.0.1:0 --tcp-addr 127.0.0.1:0 --print-bound-addrs`
   over a fresh `--data-dir`, executes all 13 live cross-project gameplay domains from the compiled
   `kestrel-canvas` C++ binary (`CNetwork` + `CConnection` + `LCPacket`), terminates `gserver`,
   cold-restarts `gserver --strict-all` over the exact same WAL `--data-dir`, and runs the 14th
   post-restart verification check!
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
from typing import Optional, Tuple

READY_RE = re.compile(r"GSERVER_READY\s+http=([\d\.]+):(\d+)\s+tcp=([\d\.]+):(\d+)")


def find_cargo() -> Optional[str]:
    for cand in [
        shutil.which("cargo"),
        str(Path.home() / ".cargo" / "bin" / ("cargo.exe" if os.name == "nt" else "cargo")),
        str(Path.home() / ".local" / "bin" / "cargo"),
    ]:
        if cand and Path(cand).is_file():
            return cand
    return None


def resolve_cobalt_relay(
    explicit_bin: Optional[str],
    explicit_dir: Optional[str],
    repo_root: Path,
    temp_root: Path,
    auto_clone: bool,
) -> Tuple[Optional[Path], Optional[Path]]:
    exe_name = "gserver.exe" if os.name == "nt" else "gserver"

    for raw in [explicit_bin, os.environ.get("COBALT_RELAY_BIN")]:
        if raw:
            p = Path(raw).resolve()
            if p.is_file():
                return p, p.parent.parent.parent

    candidate_dirs = []
    if explicit_dir:
        candidate_dirs.append(Path(explicit_dir).resolve())
    if os.environ.get("COBALT_RELAY_DIR"):
        candidate_dirs.append(Path(os.environ["COBALT_RELAY_DIR"]).resolve())
    candidate_dirs.append((repo_root.parent / "cobalt-relay").resolve())

    cargo = find_cargo()
    for cdir in candidate_dirs:
        if (cdir / "Cargo.toml").is_file():
            for prof in ("release", "debug"):
                b = cdir / "target" / prof / exe_name
                if b.is_file():
                    return b, cdir
            if cargo:
                print(f"[orchestrator] Building gserver in {cdir} ...", flush=True)
                subprocess.run(
                    [cargo, "build", "--release", "-p", "gserver", "--offline"],
                    cwd=str(cdir),
                    check=True,
                )
                b = cdir / "target" / "release" / exe_name
                if b.is_file():
                    return b, cdir

    if auto_clone and cargo and shutil.which("git"):
        clone_url = os.environ.get(
            "COBALT_RELAY_GIT_URL", "https://github.com/v0ntr3n/cobalt-relay.git"
        )
        clone_dir = temp_root / "cobalt-relay-ci"
        preferred_ref = os.environ.get("COBALT_RELAY_GIT_REF", "test/issue-3-live-e2e")
        print(f"[orchestrator] Attempting ephemeral clone of {clone_url} (ref={preferred_ref}) ...", flush=True)
        res = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", preferred_ref, clone_url, str(clone_dir)],
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            shutil.rmtree(clone_dir, ignore_errors=True)
            res = subprocess.run(
                ["git", "clone", "--depth", "1", clone_url, str(clone_dir)],
                capture_output=True,
                text=True,
            )
        if res.returncode == 0 and (clone_dir / "Cargo.toml").is_file():
            build = subprocess.run(
                [cargo, "build", "--release", "-p", "gserver", "--offline"],
                cwd=str(clone_dir),
            )
            if build.returncode != 0:
                build = subprocess.run(
                    [cargo, "build", "--release", "-p", "gserver"],
                    cwd=str(clone_dir),
                )
            b = clone_dir / "target" / "release" / exe_name
            if build.returncode == 0 and b.is_file():
                return b, clone_dir
        else:
            print(
                "[orchestrator] Ephemeral clone unavailable (private or offline environment).",
                flush=True,
            )

    return None, None


def start_strict_gserver(gserver_bin: Path, data_dir: Path) -> Tuple[subprocess.Popen, str, int, str, int]:
    cmd = [
        str(gserver_bin),
        "--strict-all",
        "--http-addr",
        "127.0.0.1:0",
        "--tcp-addr",
        "127.0.0.1:0",
        "--public-host",
        "127.0.0.1",
        "--data-dir",
        str(data_dir),
        "--print-bound-addrs",
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Run kestrel-canvas <-> cobalt-relay strict E2E suite")
    parser.add_argument("--client-test-bin", required=True, help="Compiled test_cobalt_relay_e2e binary")
    parser.add_argument("--gserver-bin", default=None, help="Path to cobalt-relay gserver binary")
    parser.add_argument("--cobalt-relay-dir", default=None, help="Path to cobalt-relay workspace root")
    parser.add_argument("--require-relay", action="store_true", help="Fail if gserver binary is absent")
    parser.add_argument(
        "--auto-clone-relay",
        action="store_true",
        help="Attempt ephemeral git clone of v0ntr3n/cobalt-relay when local sibling is absent",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    client_bin = Path(args.client_test_bin).resolve()
    if not client_bin.is_file():
        print(f"[FAIL] Missing client E2E binary: {client_bin}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="kestrel_cobalt_e2e_") as tmp_str:
        tmp_root = Path(tmp_str)
        gserver_bin, relay_dir = resolve_cobalt_relay(
            args.gserver_bin,
            args.cobalt_relay_dir,
            repo_root,
            tmp_root,
            args.auto_clone_relay,
        )

        extra_fixture_args = []
        if relay_dir is not None:
            enc_p = relay_dir / "crates" / "gserver-data" / "data" / "test_vectors" / "MainTownSceneReader.lua.enc"
            dec_p = relay_dir / "crates" / "gserver-data" / "data" / "test_vectors" / "MainTownSceneReader.lua.dec"
            if enc_p.is_file() and dec_p.is_file():
                extra_fixture_args = ["--enc-lua", str(enc_p), "--dec-lua", str(dec_p)]

        print("[orchestrator] Step 1: Running offline C++17 self-tests ...", flush=True)
        subprocess.run([str(client_bin), "--self-test", *extra_fixture_args], check=True)

        if gserver_bin is None:
            if args.require_relay:
                print(
                    "[FAIL] --require-relay specified, but cobalt-relay gserver binary was not found.",
                    file=sys.stderr,
                )
                return 1
            print(
                "[orchestrator] cobalt-relay binary not present in isolated build; offline self-tests passed.",
                flush=True,
            )
            return 0

        data_dir = tmp_root / "wal_data"
        data_dir.mkdir(parents=True, exist_ok=True)

        proc1 = None
        proc2 = None
        try:
            print(f"[orchestrator] Step 2: Spawning strict cobalt-relay ({gserver_bin}) ...", flush=True)
            proc1, http_h, http_p, tcp_h, tcp_p = start_strict_gserver(gserver_bin, data_dir)

            print("[orchestrator] Step 3: Executing 13-stage live C++ <-> Rust gameplay campaign ...", flush=True)
            subprocess.run(
                [
                    str(client_bin),
                    "--http-host",
                    http_h,
                    "--http-port",
                    str(http_p),
                    "--tcp-host",
                    tcp_h,
                    "--tcp-port",
                    str(tcp_p),
                    *extra_fixture_args,
                ],
                check=True,
            )

            print("[orchestrator] Step 4: Stopping gserver & verifying cold WAL restart recovery ...", flush=True)
            stop_process(proc1)
            proc1 = None

            proc2, http_h2, http_p2, tcp_h2, tcp_p2 = start_strict_gserver(gserver_bin, data_dir)
            subprocess.run(
                [
                    str(client_bin),
                    "--verify-restart",
                    "--http-host",
                    http_h2,
                    "--http-port",
                    str(http_p2),
                    "--tcp-host",
                    tcp_h2,
                    "--tcp-port",
                    str(tcp_p2),
                    *extra_fixture_args,
                ],
                check=True,
            )
        finally:
            stop_process(proc1)
            stop_process(proc2)

    print("[orchestrator] SUCCESS: All strict cross-project C++ <-> Rust gameplay & WAL tests passed!", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
