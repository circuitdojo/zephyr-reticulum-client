#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyyaml>=6"]
# ///
"""Flash a ret-client hardware build the way Zephyr Tools does.

Mirrors the probe-rs flash sequence of the Zephyr Tools VS Code extension
(github.com/circuitdojo/zephyr-tools 0.7.0, src/commands/flash.ts and
src/build/{flash-hex,intel-hex,uicr}.ts) so a CLI flash matches an IDE flash:

1. Images (flash-hex.ts resolveFlashImages):
   - Partition Manager builds (NCS <= 3.4, detected from zephyr/.config):
     merged.hex, the TF-M secure image plus the application.
   - Sysbuild without Partition Manager (NCS 3.5+): each domain in
     domains.yaml flash_order names its hex in <domain>/zephyr/runners.yaml
     (tfm_merged.hex for a TF-M app). The non-default images (b0, MCUboot,
     uicr_debug_access_open, ...) are merged into one bootloader hex, flashed
     first with --preverify; then the application image.
   - Single-image builds: the hex named in zephyr/runners.yaml.
   Flashing only the app (e.g. `west flash` of zephyr.hex) leaves whatever
   TF-M was on the chip, and PSA calls then fail.
2. nRF91: `recovery --unlock-only`: a no-op on an unlocked chip; a locked one
   is unlocked by an ERASEALL, which wipes its internal flash (as in Zephyr
   Tools; settings live on the external NOR).
3. nRF91 UICR: it can only be cleared by a full chip erase, and probe-rs
   cannot reprogram a written word. Compare the UICR words the images program
   with the device; strip them from the download when already there (dropping
   images left empty), or erase the chip through CTRL-AP ERASEALL
   (`recovery --erase-only --force`) when they differ. An erase clears all
   internal flash, so it needs --erase or a typed "erase".
4. `probe-rs download` per image in flash order, then `probe-rs reset`.

    uv run ret-client/scripts/flash.py build/ret_nrf9151 [--chip nRF9151_xxAA] [--probe ID]
    uv run ret-client/scripts/flash.py build/ret_nrf9151 --dry-run   # print the plan only
"""

import argparse
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

UICR_START = 0x00FF8000
UICR_SIZE = 0x1000
ERASED = 0xFFFFFFFF
WORK_DIR = "zephyr-tools"
# probe-rs erases whole sectors, so two downloads must not share one. 4 KiB
# is the flash page size on nRF5x/nRF91.
FLASH_PAGE_SIZE = 0x1000


class FlashError(Exception):
    """A build that cannot be flashed; the message says why."""


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


# --- Intel HEX (intel-hex.ts) ---------------------------------------------


def hex_records(text: str):
    """Yield (line, type, absolute base, offset, data) for each record.

    Extended segment (02) and extended linear (04) address records update the
    base address.
    """
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


def record(rtype: int, offset: int, data: bytes) -> str:
    body = bytes([len(data)]) + offset.to_bytes(2, "big") + bytes([rtype]) + data
    return ":" + (body + bytes([(-sum(body)) & 0xFF])).hex().upper()


def data_record(offset: int, data: bytes) -> str:
    return record(0x00, offset, data)


def read_hex_bytes(text: str) -> dict[int, int]:
    """Every data byte in a hex file by absolute address."""
    out: dict[int, int] = {}
    for _line, rtype, base, offset, data in hex_records(text):
        if rtype == 0x00:
            for i, byte in enumerate(data):
                out[base + offset + i] = byte
    return out


def hex_ranges(text: str) -> list[tuple[int, int]]:
    """Contiguous [start, end) address ranges covered by a hex file's data."""
    ranges = sorted(
        (base + offset, base + offset + len(data))
        for _line, rtype, base, offset, data in hex_records(text)
        if rtype == 0x00 and data
    )
    merged: list[list[int]] = []
    for start, end in ranges:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(s, e) for s, e in merged]


def ranges_overlap(a: list[tuple[int, int]], b: list[tuple[int, int]]) -> bool:
    return any(a0 < b1 and b0 < a1 for a0, a1 in a for b0, b1 in b)


def hex_has_data(text: str) -> bool:
    return any(rtype == 0x00 and data for _l, rtype, _b, _o, data in hex_records(text))


def write_hex(data: dict[int, int]) -> str:
    """Serialize bytes as Intel HEX with 16-byte data records."""
    addresses = sorted(data)
    lines: list[str] = []
    upper = -1
    i = 0
    while i < len(addresses):
        start = addresses[i]
        chunk = bytearray([data[start]])
        # Extend while contiguous, within 16 bytes and within the same 64 KiB page.
        while (
            i + len(chunk) < len(addresses)
            and len(chunk) < 16
            and addresses[i + len(chunk)] == start + len(chunk)
            and (start + len(chunk)) & 0xFFFF != 0
        ):
            chunk.append(data[start + len(chunk)])
        if start >> 16 != upper:
            upper = start >> 16
            lines.append(record(0x04, 0, upper.to_bytes(2, "big")))
        lines.append(data_record(start & 0xFFFF, bytes(chunk)))
        i += len(chunk)
    lines.append(":00000001FF")
    return "\n".join(lines) + "\n"


def merge_hex_texts(texts: list[str]) -> str:
    """Merge hex files in order; later files replace earlier data at the same
    address (mergehex.py --overlap replace)."""
    merged: dict[int, int] = {}
    for text in texts:
        merged.update(read_hex_bytes(text))
    return write_hex(merged)


# --- Image selection (flash-hex.ts) ---------------------------------------


@dataclass(frozen=True)
class FlashImage:
    label: str
    hex_path: Path
    # Bootloader images rarely change between builds; preverify them so
    # probe-rs skips programming when the device already matches.
    preverify: bool = False


def partition_manager_layout(dot_config: str) -> str | None:
    """ "sysbuild" (merged.hex in the build root), "child-image" (merged.hex in
    zephyr/) or None. Read from the current config, not files on disk: an SDK
    upgrade without a pristine build leaves the old merged.hex behind."""
    if re.search(r"^SB_CONFIG_PARTITION_MANAGER=y\s*$", dot_config, re.MULTILINE):
        return "sysbuild"
    if re.search(r"^CONFIG_PARTITION_MANAGER_ENABLED=y\s*$", dot_config, re.MULTILINE):
        return "child-image"
    return None


def parse_domains_yaml(text: str) -> tuple[str, list[str]]:
    """(default domain, flash_order) from a sysbuild domains.yaml."""
    parsed = yaml.safe_load(text)
    if not isinstance(parsed, dict) or not isinstance(parsed.get("default"), str):
        raise FlashError("domains.yaml has no default domain")
    order = parsed.get("flash_order")
    if not isinstance(order, list) or not order or not all(isinstance(n, str) for n in order):
        raise FlashError("domains.yaml has no flash_order")
    return parsed["default"], order


def runners_yaml_hex_file(text: str) -> str | None:
    """config.hex_file from a runners.yaml."""
    parsed = yaml.safe_load(text)
    config = parsed.get("config") if isinstance(parsed, dict) else None
    hex_file = config.get("hex_file") if isinstance(config, dict) else None
    return hex_file if isinstance(hex_file, str) and hex_file else None


def hex_from_runners_yaml(zephyr_dir: Path, image: str) -> Path:
    runners = zephyr_dir / "runners.yaml"
    if not runners.is_file():
        raise FlashError(f'image "{image}" has no {runners}; build first')
    hex_file = runners_yaml_hex_file(runners.read_text())
    if not hex_file:
        raise FlashError(f"{runners} has no hex_file")
    hex_path = zephyr_dir / hex_file  # an absolute hex_file replaces zephyr_dir
    if not hex_path.is_file():
        raise FlashError(f'hex for image "{image}" not found at {hex_path}; build first')
    return hex_path


def _pages(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    return [
        (s // FLASH_PAGE_SIZE * FLASH_PAGE_SIZE, -(-e // FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE)
        for s, e in ranges
    ]


def split_sysbuild_images(
    default: str, images: list[tuple[str, Path, str]]
) -> tuple[list[str], str | None, tuple[str, Path, str]]:
    """Split (name, hex path, hex text) images in flash order into the
    bootloader names, their merged hex (None if there are none) and the app.

    Fails if a bootloader shares a flash page with the app, since two
    downloads would then erase or overwrite each other.
    """
    app = next((img for img in images if img[0] == default), None)
    if app is None:
        raise FlashError(f'the default image "{default}" is not in domains.yaml flash_order')
    boots = [img for img in images if img is not app]
    if not boots:
        return [], None, app
    boot_hex = merge_hex_texts([text for _n, _p, text in boots])
    if ranges_overlap(_pages(hex_ranges(boot_hex)), _pages(hex_ranges(app[2]))):
        names = ", ".join(n for n, _p, _t in boots)
        raise FlashError(f'images {names} share flash pages with the application image "{app[0]}"')
    return [n for n, _p, _t in boots], boot_hex, app


def _resolve_sysbuild(build: Path) -> list[FlashImage]:
    try:
        default, order = parse_domains_yaml((build / "domains.yaml").read_text())
    except FlashError as e:
        raise FlashError(f"{build / 'domains.yaml'}: {e}") from None
    images = []
    for name in order:
        hex_path = hex_from_runners_yaml(build / name / "zephyr", name)
        images.append((name, hex_path, hex_path.read_text()))
    boot_names, boot_hex, app = split_sysbuild_images(default, images)
    plan = []
    if boot_hex is not None:
        boot_path = build / WORK_DIR / "bootloaders.hex"
        boot_path.parent.mkdir(parents=True, exist_ok=True)
        boot_path.write_text(boot_hex)
        plan.append(FlashImage(f"bootloaders ({', '.join(boot_names)})", boot_path, True))
    plan.append(FlashImage(app[0], app[1]))
    return plan


def resolve_flash_images(build: Path) -> list[FlashImage]:
    """flash-hex.ts resolveFlashImages: the images to download, in order."""
    dot_config = build / "zephyr" / ".config"
    if not dot_config.is_file():
        raise FlashError(f"no build output in {build} (missing {dot_config}); build first")
    layout = partition_manager_layout(dot_config.read_text())
    if layout:
        hex_path = build / "merged.hex" if layout == "sysbuild" else build / "zephyr" / "merged.hex"
        if not hex_path.is_file():
            raise FlashError(f"Partition Manager build has no {hex_path}; build first")
        return [FlashImage("merged.hex", hex_path)]
    if (build / "domains.yaml").is_file():
        return _resolve_sysbuild(build)
    if (build / "zephyr" / "runners.yaml").is_file():
        hex_path = hex_from_runners_yaml(build / "zephyr", "zephyr")
        return [FlashImage(hex_path.name, hex_path)]
    raise FlashError(f"no build output in {build}; build first")


# --- nRF91 UICR (uicr.ts) -------------------------------------------------


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


def images_uicr_words(images: list[FlashImage]) -> dict[int, int]:
    """UICR words programmed by all images; later images win, as in flash order."""
    words: dict[int, int] = {}
    for image in images:
        words.update(uicr_words(image.hex_path.read_text()))
    return words


def strip_uicr_images(build: Path, images: list[FlashImage]) -> list[FlashImage]:
    """flash.ts prepareNrf91Uicr, skip branch: UICR stripped from each image
    that programs it (written under zephyr-tools/uicr-stripped/); images left
    with no data are dropped."""
    out = []
    for image in images:
        text = image.hex_path.read_text()
        if not uicr_words(text):
            out.append(image)
            continue
        stripped = strip_uicr(text)
        if not hex_has_data(stripped):
            continue
        path = build / WORK_DIR / "uicr-stripped" / image.hex_path.name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(stripped)
        out.append(FlashImage(image.label, path, image.preverify))
    return out


# --- Probes and recovery (probe-manager.ts, flash.ts) ---------------------


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


def recovery_cmd(binary: str, mode: str, probe: str | None) -> list[str]:
    """flash.ts runRecovery arguments.

    --timeout 10000: the probe's USB interface can still be held briefly by
    the previous probe-rs run. --no-reset: probe-rs resets the device when it
    flashes. --force on erase: always go through CTRL-AP ERASEALL, whose open
    debug port survives resets until a power-on or pin reset; a port opened
    by the firmware closes on the next reset once flash is blank, leaving
    probe-rs facing a locked chip.
    """
    args = ["--erase-only", "--force"] if mode == "erase" else ["--unlock-only"]
    return [binary, *args, "--no-reset", "--timeout", "10000", *recovery_probe_args(probe)]


def recovery(binary: str, mode: str, probe: str | None) -> None:
    # Worst case: 10 s to open the probe plus 3 unlock/erase retries.
    res = run(recovery_cmd(binary, mode, probe), timeout=60)
    if res.returncode != 0:
        last = (res.stdout.strip().splitlines() or [""])[-1]
        die(f"recovery {mode} failed: {res.stderr.strip() or res.returncode} (last step: {last})")


# --- probe-rs commands (flash.ts flashProbeRsCommand) ---------------------


def read_uicr_cmd(probe_rs: str, chip: str, probe: str) -> list[str]:
    return [
        probe_rs,
        "read",
        "b32",
        hex(UICR_START),
        str(UICR_SIZE // 4),
        "--chip",
        chip,
        "--probe",
        probe,
    ]


def download_cmd(
    probe_rs: str, chip: str, image: FlashImage, probe: str, preverify: bool, verify: bool
) -> list[str]:
    cmd = [probe_rs, "download", "--chip", chip, "--binary-format", "hex", str(image.hex_path)]
    cmd += ["--probe", probe]
    if preverify or image.preverify:
        cmd.append("--preverify")
    if verify:
        cmd.append("--verify")
    return cmd


def reset_cmd(probe_rs: str, chip: str, probe: str) -> list[str]:
    return [probe_rs, "reset", "--chip", chip, "--probe", probe]


def print_plan(args: argparse.Namespace, images: list[FlashImage], is_nrf91: bool) -> None:
    """--dry-run: what would run, with no probe or device access."""
    probe = args.probe or "<probe>"
    print(f"build: {args.build}")
    print("images, in flash order:")
    for image in images:
        words = uicr_words(image.hex_path.read_text())
        uicr = ", ".join(f"0x{a:08x}=0x{v:08x}" for a, v in sorted(words.items())) or "none"
        flag = " (preverify)" if image.preverify else ""
        print(f"  {image.label}{flag}: {image.hex_path}")
        print(f"    UICR words: {uicr}")
    print("commands:")
    if not args.probe:
        print(f"  {args.probe_rs} list   # pick the only probe")
    if is_nrf91:
        print("  " + " ".join(recovery_cmd(args.recovery, "unlock", probe)))
        if images_uicr_words(images):
            print("  " + " ".join(read_uicr_cmd(args.probe_rs, args.chip, probe)))
            print("  # device already has every UICR word: download UICR-stripped copies")
            print("  #   (zephyr-tools/uicr-stripped/), dropping images left empty")
            print("  # otherwise, after --erase or a typed 'erase':")
            print("  " + " ".join(recovery_cmd(args.recovery, "erase", probe)))
    for image in images:
        cmd = download_cmd(args.probe_rs, args.chip, image, probe, args.preverify, args.verify)
        print("  " + " ".join(cmd))
    print("  " + " ".join(reset_cmd(args.probe_rs, args.chip, probe)))


def prepare_nrf91_uicr(
    args: argparse.Namespace, images: list[FlashImage], probe: str
) -> list[FlashImage]:
    """flash.ts prepareNrf91Uicr."""
    hex_uicr = images_uicr_words(images)
    if not hex_uicr:
        return images
    res = run(read_uicr_cmd(args.probe_rs, args.chip, probe), timeout=30)
    if res.returncode != 0:
        die(f"reading device UICR failed: {res.stderr.strip()}")
    action, differ = plan_uicr(hex_uicr, parse_read32(res.stdout, UICR_START))
    if action == "erase":
        print("UICR differs from the build at " + ", ".join(f"0x{a:08x}" for a in differ))
        if not args.erase:
            try:
                answer = input(
                    "Erase the chip to flash? This clears all internal flash. Type 'erase': "
                )
            except EOFError:
                die("UICR needs a chip erase; rerun with --erase to allow it")
            if answer.strip() != "erase":
                die("not erasing; nothing flashed")
        recovery(args.recovery, "erase", probe)
        return images
    print("UICR already matches the build; skipping UICR writes")
    return strip_uicr_images(args.build, images)


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
    ap.add_argument(
        "--preverify",
        action="store_true",
        help="preverify every image (bootloader images always are)",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="print the images and commands; touch no probe or device",
    )
    args = ap.parse_args()

    try:
        images = resolve_flash_images(args.build)
    except FlashError as e:
        die(str(e))
    is_nrf91 = args.chip.lower().startswith("nrf91")

    if args.dry_run:
        print_plan(args, images, is_nrf91)
        return

    probe = resolve_probe(args.probe_rs, args.probe)

    if is_nrf91:
        if not Path(args.recovery).is_file():
            die(
                f"nRF91 recovery tool not found at {args.recovery} (Zephyr Tools: Setup installs it)"
            )
        recovery(args.recovery, "unlock", probe)
        images = prepare_nrf91_uicr(args, images, probe)

    for image in images:
        cmd = download_cmd(args.probe_rs, args.chip, image, probe, args.preverify, args.verify)
        res = run(cmd, timeout=300)
        sys.stdout.write(res.stdout)
        if res.returncode != 0:
            die(f"probe-rs download of {image.label} failed: {res.stderr.strip()}")

    # Best effort, as in Zephyr Tools: firmware that sleeps or locks the
    # debug port right away can make this fail after a good flash.
    res = run(reset_cmd(args.probe_rs, args.chip, probe), timeout=60)
    if res.returncode != 0:
        print(
            f"flash: reset failed ({res.stderr.strip()}); the new firmware is flashed",
            file=sys.stderr,
        )
    print("flashed " + ", ".join(str(image.hex_path) for image in images))


if __name__ == "__main__":
    main()
