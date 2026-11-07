#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Flash a ret-client hardware build the way Zephyr Tools does.

Mirrors the probe-rs flash sequence of the Zephyr Tools VS Code extension
(github.com/circuitdojo/zephyr-tools, src/commands/flash.ts and
src/build/{flash-hex,uicr}.ts) so a CLI flash matches an IDE flash:

1. Image: Partition Manager builds flash merged.hex - the TF-M secure image
   plus the application. Flashing only the app (e.g. `west flash`) leaves
   whatever TF-M was on the chip, and PSA calls then fail.
2. nRF91: `recovery --unlock-only` (no-op on an unlocked chip).
3. nRF91 UICR: it can only be cleared by a full chip erase, and probe-rs
   cannot reprogram a written word. Compare the UICR words the hex programs
   with the device; strip them from the download when already there, or
   erase the chip (`recovery --erase-only --force`) when they differ. An
   erase clears all internal flash, so it needs --erase or a typed "erase".
4. `probe-rs download`, then `probe-rs reset`.

    uv run ret-client/scripts/flash.py build/ret_nrf9151 [--chip nRF9151_xxAA] [--probe ID]
"""

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

UICR_START = 0x00FF8000
UICR_SIZE = 0x1000
ERASED = 0xFFFFFFFF
WORK_DIR = "zephyr-tools"


def die(msg: str) -> None:
    print(f"flash: {msg}", file=sys.stderr)
    sys.exit(1)


def run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    print("+ " + " ".join(cmd), flush=True)
    try:
        return subprocess.run(cmd, check=False, timeout=timeout, capture_output=True, text=True)
    except subprocess.TimeoutExpired:
        die(f"{Path(cmd[0]).name} {cmd[1]} timed out after {timeout} s")
    except OSError as e:
        die(f"could not run {cmd[0]}: {e}")


def resolve_image(build: Path) -> Path:
    """flash-hex.ts resolveFlashImages, Partition Manager branch."""
    dot_config = build / "zephyr" / ".config"
    if not dot_config.is_file():
        die(f"no build output in {build} (missing {dot_config})")
    config = dot_config.read_text()
    if re.search(r"^SB_CONFIG_PARTITION_MANAGER=y\s*$", config, re.MULTILINE):
        hex_path = build / "merged.hex"
    elif re.search(r"^CONFIG_PARTITION_MANAGER_ENABLED=y\s*$", config, re.MULTILINE):
        hex_path = build / "zephyr" / "merged.hex"
    else:
        die(
            "not a Partition Manager build. Sysbuild without Partition Manager splits "
            "images by domains.yaml flash_order; flash it with Zephyr Tools."
        )
    if not hex_path.is_file():
        die(f"Partition Manager build has no {hex_path}; build first")
    return hex_path


def hex_records(text: str):
    """Yield (line, type, absolute base, offset, data) for each record."""
    base = 0
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith(":"):
            continue
        raw = bytes.fromhex(line[1:])
        count, offset, rtype = raw[0], int.from_bytes(raw[1:3], "big"), raw[3]
        data = raw[4 : 4 + count]
        if rtype == 0x04:
            base = int.from_bytes(data, "big") << 16
        elif rtype == 0x02:
            base = int.from_bytes(data, "big") << 4
        yield line, rtype, base, offset, data


def uicr_words(text: str) -> dict[int, int]:
    """uicr.ts extractUicrWords: bytes the hex leaves unset stay 0xFF."""
    words: dict[int, int] = {}
    for _line, rtype, base, offset, data in hex_records(text):
        if rtype != 0x00:
            continue
        for i, byte in enumerate(data):
            addr = base + offset + i
            if not UICR_START <= addr < UICR_START + UICR_SIZE:
                continue
            word, shift = addr & ~3, (addr & 3) * 8
            cur = words.get(word, ERASED)
            words[word] = (cur & ~(0xFF << shift) | (byte << shift)) & 0xFFFFFFFF
    return words


def data_record(offset: int, data: bytes) -> str:
    body = bytes([len(data)]) + offset.to_bytes(2, "big") + b"\x00" + data
    return ":" + (body + bytes([(-sum(body)) & 0xFF])).hex().upper()


def strip_uicr(text: str) -> str:
    """uicr.ts stripHexRange: drop data bytes inside UICR, keep the rest."""
    out = []
    for line, rtype, base, offset, data in hex_records(text):
        if rtype != 0x00:
            out.append(line)
            continue
        run_off, run = -1, bytearray()
        for i, byte in enumerate(data):
            if UICR_START <= base + offset + i < UICR_START + UICR_SIZE:
                if run:
                    out.append(data_record(run_off, bytes(run)))
                run = bytearray()
                continue
            if not run:
                run_off = offset + i
            run.append(byte)
        if run:
            out.append(data_record(run_off, bytes(run)))
    return "\n".join(out) + "\n"


def parse_read32(stdout: str, start: int) -> dict[int, int]:
    """uicr.ts parseProbeRsRead32: addressed rows or bare words."""
    words, addr = {}, start
    for line in stdout.splitlines():
        m = re.match(r"^\s*([0-9a-fA-F]+):\s+(.*)$", line)
        if m:
            addr = int(m.group(1), 16)
        values = (m.group(2) if m else line).strip()
        for v in values.split():
            words[addr] = int(v, 16)
            addr += 4
    return words


def plan_uicr(hex_words: dict[int, int], device_words: dict[int, int]) -> tuple[str, list[int]]:
    """uicr.ts planUicr: ("none" | "skip" | "erase", addresses to write).

    Words the hex leaves erased are ignored (runtime counters); any other
    word not already on the device needs an erase.
    """
    if not hex_words:
        return "none", []
    differ = sorted(a for a, v in hex_words.items() if v != ERASED and device_words.get(a) != v)
    return ("erase", differ) if differ else ("skip", [])


def parse_probe_list(stdout: str) -> list[str | None]:
    """probe-manager.ts: the --probe identifier of each `probe-rs list` entry.

    CMSIS-DAP entries carry it after "--" (VID:PID); others are built from
    VID/PID and serial. None when an entry has neither.
    """
    probes: list[str | None] = []
    for line in stdout.splitlines():
        line = line.strip()
        m = re.match(r"\[([^\]]+)\]:\s*(.+)", line)
        if not m:
            continue
        desc = m.group(2)
        cmsis = re.search(r"--\s*([0-9a-fA-F:]+)", desc)
        vidpid = re.search(r"VID:\s*([0-9a-fA-F]{4})\s*PID:\s*([0-9a-fA-F]{4})", desc)
        serial = re.search(r"Serial:\s*([^,\s)]+)", desc)
        if cmsis:
            probes.append(cmsis.group(1))
        elif vidpid and serial:
            probes.append(f"{vidpid.group(1)}:{vidpid.group(2)}:{serial.group(1)}")
        elif serial:
            probes.append(serial.group(1))
        else:
            probes.append(None)
    return probes


def resolve_probe(probe_rs: str, requested: str | None) -> str:
    """One concrete probe for both recovery and probe-rs, as Zephyr Tools
    does; otherwise each tool would pick its own default."""
    if requested:
        return requested
    res = run([probe_rs, "list"], timeout=30)
    if res.returncode != 0:
        die(f"probe-rs list failed: {res.stderr.strip()}")
    probes = parse_probe_list(res.stdout)
    if not probes:
        die("no debug probe found")
    if len(probes) > 1:
        die(f"{len(probes)} probes attached; pick one with --probe:\n{res.stdout.strip()}")
    if probes[0] is None:
        die(f"cannot derive a probe id from:\n{res.stdout.strip()}\nPass --probe")
    return probes[0]


def recovery_probe_args(probe: str | None) -> list[str]:
    """flash.ts recoveryProbeArgs: VID:PID[:serial] hex -> decimal options."""
    if not probe:
        return []
    parts = probe.split(":")
    if len(parts) >= 2 and all(re.fullmatch(r"[0-9a-fA-F]{4}", p) for p in parts[:2]):
        args = ["--vendor-id", str(int(parts[0], 16)), "--product-id", str(int(parts[1], 16))]
        if len(parts) > 2:
            args += ["--serial", ":".join(parts[2:])]
        return args
    return ["--serial", probe]


def recovery(binary: str, mode: str, probe: str | None) -> None:
    """flash.ts runRecovery."""
    args = ["--erase-only", "--force"] if mode == "erase" else ["--unlock-only"]
    cmd = [binary, *args, "--no-reset", "--timeout", "10000", *recovery_probe_args(probe)]
    res = run(cmd, timeout=60)
    if res.returncode != 0:
        last = (res.stdout.strip().splitlines() or [""])[-1]
        die(f"recovery {mode} failed: {res.stderr.strip() or res.returncode} (last step: {last})")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("build", type=Path, help="build directory (the -d of west build)")
    ap.add_argument("--chip", default="nRF9151_xxAA")
    ap.add_argument("--probe", help="probe-rs probe id (VID:PID[:serial]); default: the only probe")
    ap.add_argument("--probe-rs", default=shutil.which("probe-rs") or "probe-rs")
    ap.add_argument(
        "--recovery",
        default=str(Path.home() / ".zephyrtools" / "recovery" / "recovery"),
        help="nRF91 recovery tool (installed by Zephyr Tools setup)",
    )
    ap.add_argument("--erase", action="store_true", help="allow a full chip erase if UICR differs")
    ap.add_argument("--verify", action="store_true", help="verify after programming")
    args = ap.parse_args()

    hex_path = resolve_image(args.build)
    probe_id = resolve_probe(args.probe_rs, args.probe)
    probe = ["--probe", probe_id]
    is_nrf91 = args.chip.lower().startswith("nrf91")

    if is_nrf91:
        if not Path(args.recovery).is_file():
            die(
                f"nRF91 recovery tool not found at {args.recovery} (Zephyr Tools: Setup installs it)"
            )
        recovery(args.recovery, "unlock", probe_id)

        text = hex_path.read_text()
        hex_uicr = uicr_words(text)
        if hex_uicr:
            res = run(
                [
                    args.probe_rs,
                    "read",
                    "b32",
                    hex(UICR_START),
                    str(UICR_SIZE // 4),
                    "--chip",
                    args.chip,
                    *probe,
                ],
                timeout=30,
            )
            if res.returncode != 0:
                die(f"reading device UICR failed: {res.stderr.strip()}")
            action, differ = plan_uicr(hex_uicr, parse_read32(res.stdout, UICR_START))
            if action == "erase":
                print("UICR differs from the build at " + ", ".join(f"0x{a:08x}" for a in differ))
                if not args.erase:
                    try:
                        answer = input(
                            "Erase the chip to flash? This clears all internal flash. "
                            "Type 'erase': "
                        )
                    except EOFError:
                        die("UICR needs a chip erase; rerun with --erase to allow it")
                    if answer.strip() != "erase":
                        die("not erasing; nothing flashed")
                recovery(args.recovery, "erase", probe_id)
            else:
                print("UICR already matches the build; skipping UICR writes")
                stripped = args.build / WORK_DIR / "uicr-stripped" / hex_path.name
                stripped.parent.mkdir(parents=True, exist_ok=True)
                stripped.write_text(strip_uicr(text))
                hex_path = stripped

    cmd = [
        args.probe_rs,
        "download",
        "--chip",
        args.chip,
        "--binary-format",
        "hex",
        str(hex_path),
        *probe,
    ]
    if args.verify:
        cmd.append("--verify")
    res = run(cmd, timeout=300)
    sys.stdout.write(res.stdout)
    if res.returncode != 0:
        die(f"probe-rs download failed: {res.stderr.strip()}")

    # Best effort, as in Zephyr Tools: firmware that sleeps or locks the
    # debug port right away can make this fail after a good flash.
    res = run([args.probe_rs, "reset", "--chip", args.chip, *probe], timeout=60)
    if res.returncode != 0:
        print(
            f"flash: reset failed ({res.stderr.strip()}); the new firmware is flashed",
            file=sys.stderr,
        )
    print(f"flashed {hex_path}")


if __name__ == "__main__":
    main()
