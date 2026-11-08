"""Tests for scripts/flash.py, ported from Zephyr Tools' own suites
(zephyr-tools/src/test/suite/{uicr,flash-hex,intel-hex,flash-command}.test.ts)
so the two stay in agreement.

    uv run --with pytest --with pyyaml pytest ret-client/scripts
"""

import importlib.util
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location("flash", Path(__file__).with_name("flash.py"))
flash = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(flash)

DEBUG_ACCESS_HEX = """\
:020000040002F8
:0400000001020304F2
:0200000400FFFB
:04800000FA50FA50E8
:04802C00FA50FA50BC
:00000001FF
"""


def test_uicr_words_reads_little_endian_words_in_range_only():
    assert flash.uicr_words(DEBUG_ACCESS_HEX) == {0x00FF8000: 0x50FA50FA, 0x00FF802C: 0x50FA50FA}


def test_strip_removes_uicr_and_keeps_the_rest():
    stripped = flash.strip_uicr(DEBUG_ACCESS_HEX)
    assert flash.uicr_words(stripped) == {}
    assert ":0400000001020304F2" in stripped
    assert ":00000001FF" in stripped


def test_strip_splits_a_record_straddling_the_boundary():
    hexfile = ":0200000400FFFB\n:047FFE00AABBCCDD71\n:00000001FF\n"
    stripped = flash.strip_uicr(hexfile)
    assert ":027FFE00AABB1C" in stripped
    assert flash.uicr_words(stripped) == {}


def test_read32_addressed_rows():
    words = flash.parse_read32("00ff8000: 50fa50fa ffffffff\n00ff8008: 00000001\n", 0x00FF8000)
    assert words == {0x00FF8000: 0x50FA50FA, 0x00FF8004: 0xFFFFFFFF, 0x00FF8008: 1}


def test_read32_unaddressed_probe_rs_029_output():
    words = flash.parse_read32("50fa50fa ffffffff 00000001 \n", 0x00FF8000)
    assert words == {0x00FF8000: 0x50FA50FA, 0x00FF8004: 0xFFFFFFFF, 0x00FF8008: 1}


def test_plan_skips_when_device_holds_every_word():
    hexw = flash.uicr_words(DEBUG_ACCESS_HEX)
    device = flash.parse_read32("00ff8000: 50fa50fa\n00ff802c: 50fa50fa\n", 0x00FF8000)
    assert flash.plan_uicr(hexw, device) == ("skip", [])


def test_plan_ignores_words_the_hex_leaves_erased():
    hexw = {0x00FF8000: 0x50FA50FA, 0x00FF8158: 0xFFFFFFFF}
    device = {0x00FF8000: 0x50FA50FA, 0x00FF8158: 0xFFFFFFFC}
    assert flash.plan_uicr(hexw, device) == ("skip", [])


def test_plan_erases_when_a_word_differs_or_is_blank():
    hexw = {0x00FF8000: 0x50FA50FA, 0x00FF8140: 0x0C9007A0}
    device = {0x00FF8000: 0xFFFFFFFF, 0x00FF8140: 0x4C1D9430}
    assert flash.plan_uicr(hexw, device) == ("erase", [0x00FF8000, 0x00FF8140])


def test_plan_none_without_uicr():
    assert flash.plan_uicr({}, {}) == ("none", [])


def test_probe_list_cmsis_dap_feather():
    out = (
        "The following debug probes were found:\n"
        "[0]: Debug Probe (CMSIS-DAP) -- 2e8a:000c-0:E664B012CF809B28 (CMSIS-DAP)\n"
    )
    assert flash.parse_probe_list(out) == ["2e8a:000c"]


def test_probe_list_vid_pid_serial_and_two_probes():
    out = (
        "[0]: J-Link (VID: 1366 PID: 0105 Serial: 000123456789)\n"
        "[1]: Debug Probe (CMSIS-DAP) -- 2e8a:000c-0:E664B012CF809B28 (CMSIS-DAP)\n"
    )
    assert flash.parse_probe_list(out) == ["1366:0105:000123456789", "2e8a:000c"]


def test_recovery_probe_args_translates_hex_ids():
    assert flash.recovery_probe_args("2e8a:000c:E664B012CF809B28") == [
        "--vendor-id",
        "11914",
        "--product-id",
        "12",
        "--serial",
        "E664B012CF809B28",
    ]
    assert flash.recovery_probe_args("000123456789") == ["--serial", "000123456789"]


def test_recovery_probe_args_without_serial_and_without_probe():
    assert flash.recovery_probe_args("1366:1015") == [
        "--vendor-id",
        "4966",
        "--product-id",
        "4117",
    ]
    assert flash.recovery_probe_args(None) == []


def test_recovery_cmd_unlock_and_ctrl_ap_erase():
    # a27d842: no final reset, 10 s probe open timeout. b20adc3: erase with
    # --force so recovery always goes through CTRL-AP ERASEALL.
    assert flash.recovery_cmd("rec", "unlock", "2e8a:000c") == [
        "rec",
        "--unlock-only",
        "--no-reset",
        "--timeout",
        "10000",
        "--vendor-id",
        "11914",
        "--product-id",
        "12",
    ]
    assert flash.recovery_cmd("rec", "erase", None) == [
        "rec",
        "--erase-only",
        "--force",
        "--no-reset",
        "--timeout",
        "10000",
    ]


def test_download_cmd_preverifies_bootloaders_and_honours_flags():
    boot = flash.FlashImage("bootloaders (b0)", Path("/b/boot.hex"), True)
    app = flash.FlashImage("app", Path("/b/app.hex"))
    base = ["pr", "download", "--chip", "nRF9151_xxAA", "--binary-format", "hex"]
    assert flash.download_cmd("pr", "nRF9151_xxAA", boot, "P", False, False) == [
        *base,
        "/b/boot.hex",
        "--probe",
        "P",
        "--preverify",
    ]
    assert flash.download_cmd("pr", "nRF9151_xxAA", app, "P", False, False) == [
        *base,
        "/b/app.hex",
        "--probe",
        "P",
    ]
    assert flash.download_cmd("pr", "nRF9151_xxAA", app, "P", True, True)[-2:] == [
        "--preverify",
        "--verify",
    ]


# --- intel-hex.test.ts ----------------------------------------------------


def test_write_hex_round_trips_across_a_64k_boundary():
    data = {0x0000FFF0 + i: i for i in range(40)}
    data[0x00FF8000] = 0xFA
    text = flash.write_hex(data)
    assert flash.read_hex_bytes(text) == data
    # No data record may cross into the next 64 KiB page.
    assert ":020000040001F9" in text
    assert text.strip().endswith(":00000001FF")


def test_merge_hex_texts_later_files_replace_earlier_data():
    a = flash.write_hex({0x100: 1, 0x101: 2})
    b = flash.write_hex({0x101: 9, 0x102: 3})
    assert flash.read_hex_bytes(flash.merge_hex_texts([a, b])) == {0x100: 1, 0x101: 9, 0x102: 3}


def test_hex_ranges_coalesces_contiguous_records():
    text = flash.write_hex({0x200 + i: 0 for i in range(40)})
    assert flash.hex_ranges(text) == [(0x200, 0x228)]


def test_hex_has_data_false_for_address_and_eof_records_only():
    assert not flash.hex_has_data(":0200000400FFFB\n:00000001FF\n")
    assert flash.hex_has_data(flash.write_hex({0: 1}))


# --- flash-hex.test.ts ----------------------------------------------------

BOOT_HEX = ":020000040000FA\n:0400000001020304F2\n:00000001FF\n"
APP_HEX = ":020000040002F8\n:0400000005060708E6\n:00000001FF\n"
PROVISION_HEX = ":0200000400FFFB\n:04813000AABBCCDD3D\n:00000001FF\n"
UICR_ONLY_HEX = ":0200000400FFFB\n:04800000FA50FA50E8\n:04802C00FA50FA50BC\n:00000001FF\n"


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def _image(build: Path, name: str, hex_name: str, text: str) -> None:
    _write(build / name / "zephyr" / hex_name, text)
    _write(build / name / "zephyr" / "runners.yaml", f"config:\n  hex_file: {hex_name}\n")


def test_parse_domains_yaml_reads_default_and_flash_order():
    text = "default: app\nflash_order:\n  - mcuboot\n  - app\n"
    assert flash.parse_domains_yaml(text) == ("app", ["mcuboot", "app"])
    with pytest.raises(flash.FlashError):
        flash.parse_domains_yaml("default: app\n")


def test_runners_yaml_hex_file_reads_config_hex_file():
    assert flash.runners_yaml_hex_file("config:\n  hex_file: zephyr.signed.hex\n") == (
        "zephyr.signed.hex"
    )
    assert flash.runners_yaml_hex_file("config:\n  elf_file: zephyr.elf\n") is None
    # Zephyr writes `elf_file: ` with no value for a prebuilt hex image.
    assert flash.runners_yaml_hex_file("config:\n  elf_file: \n  hex_file: \n") is None


def test_split_sysbuild_images_merges_non_app_images_and_rejects_overlap():
    boot = ("b0", Path("b0.hex"), BOOT_HEX)
    app = ("app", Path("app.hex"), APP_HEX)
    names, boot_hex, got_app = flash.split_sysbuild_images("app", [boot, app])
    assert names == ["b0"] and got_app is app
    assert ":0400000001020304F2" in boot_hex

    with pytest.raises(flash.FlashError):
        flash.split_sysbuild_images("app", [("mcuboot", Path("m.hex"), APP_HEX), app])
    # Different bytes in the same 4 KiB page as the app still conflict.
    same_page = ":020000040002F8\n:04010000AABBCCDDED\n:00000001FF\n"
    with pytest.raises(flash.FlashError):
        flash.split_sysbuild_images("app", [("mcuboot", Path("m.hex"), same_page), app])
    with pytest.raises(flash.FlashError):
        flash.split_sysbuild_images("missing", [boot])


def test_partition_manager_layout_reads_sysbuild_and_child_image_configs():
    assert flash.partition_manager_layout("SB_CONFIG_PARTITION_MANAGER=y\r\n") == "sysbuild"
    assert flash.partition_manager_layout("CONFIG_PARTITION_MANAGER_ENABLED=y\n") == "child-image"
    assert (
        flash.partition_manager_layout(
            "# SB_CONFIG_PARTITION_MANAGER is not set\nSB_CONFIG_MERGED_HEX_FILES=y\n"
        )
        is None
    )


def test_partition_manager_build_flashes_merged_hex_ignoring_cpunet(tmp_path):
    _write(tmp_path / "zephyr" / ".config", "SB_CONFIG_PARTITION_MANAGER=y\n")
    _write(tmp_path / "partitions.yml", "")
    _write(tmp_path / "domains.yaml", "default: app\nflash_order: [app]\n")
    _write(tmp_path / "merged.hex", APP_HEX)
    _write(tmp_path / "merged_CPUNET.hex", BOOT_HEX)
    assert flash.resolve_flash_images(tmp_path) == [
        flash.FlashImage("merged.hex", tmp_path / "merged.hex", False)
    ]


def test_child_image_partition_manager_build_flashes_zephyr_merged_hex(tmp_path):
    _write(tmp_path / "zephyr" / ".config", "CONFIG_PARTITION_MANAGER_ENABLED=y\n")
    _write(tmp_path / "partitions.yml", "")
    _write(tmp_path / "zephyr" / "merged.hex", APP_HEX)
    images = flash.resolve_flash_images(tmp_path)
    assert [i.hex_path for i in images] == [tmp_path / "zephyr" / "merged.hex"]


def test_sysbuild_partition_manager_ignores_leftover_zephyr_merged_hex(tmp_path):
    _write(tmp_path / "zephyr" / ".config", "SB_CONFIG_PARTITION_MANAGER=y\n")
    _write(tmp_path / "merged.hex", APP_HEX)
    _write(tmp_path / "zephyr" / "merged.hex", BOOT_HEX)
    assert [i.hex_path for i in flash.resolve_flash_images(tmp_path)] == [tmp_path / "merged.hex"]
    (tmp_path / "merged.hex").unlink()
    with pytest.raises(flash.FlashError):
        flash.resolve_flash_images(tmp_path)


def test_sysbuild_flashes_bootloaders_then_app_from_domains_yaml(tmp_path):
    _write(
        tmp_path / "domains.yaml",
        "default: app\nflash_order:\n  - b0\n  - app\n  - app_provision\n",
    )
    _image(tmp_path, "b0", "zephyr.hex", BOOT_HEX)
    _image(tmp_path, "app", "zephyr.signed.hex", APP_HEX)
    # Absolute hex_file, like app_provision in NCS 3.5.
    provision = _write(tmp_path / "app_provision.hex", PROVISION_HEX)
    _write(
        tmp_path / "app_provision" / "zephyr" / "runners.yaml",
        f"config:\n  hex_file: {provision}\n",
    )
    # Leftovers from a Partition Manager build before an SDK upgrade without a
    # pristine build must be ignored: the current config has no PM.
    _write(tmp_path / "zephyr" / ".config", "SB_CONFIG_MERGED_HEX_FILES=y\n")
    _write(tmp_path / "partitions.yml", "")
    _write(tmp_path / "merged.hex", BOOT_HEX)

    images = flash.resolve_flash_images(tmp_path)
    assert [(i.label, i.preverify) for i in images] == [
        ("bootloaders (b0, app_provision)", True),
        ("app", False),
    ]
    assert images[0].hex_path == tmp_path / "zephyr-tools" / "bootloaders.hex"
    assert images[1].hex_path == tmp_path / "app" / "zephyr" / "zephyr.signed.hex"
    boot = images[0].hex_path.read_text()
    assert ":0400000001020304F2" in boot
    assert ":04813000AABBCCDD3D" in boot


def test_sysbuild_image_with_missing_hex_is_an_error(tmp_path):
    _write(tmp_path / "zephyr" / ".config", "")
    _write(tmp_path / "domains.yaml", "default: app\nflash_order: [app]\n")
    _write(tmp_path / "app" / "zephyr" / "runners.yaml", "config:\n  hex_file: zephyr.hex\n")
    with pytest.raises(flash.FlashError):
        flash.resolve_flash_images(tmp_path)


def test_single_image_build_flashes_the_runners_yaml_hex(tmp_path):
    _write(tmp_path / "zephyr" / ".config", 'CONFIG_BOARD_TARGET="x"\n')
    _write(tmp_path / "zephyr" / "zephyr.hex", APP_HEX)
    _write(tmp_path / "zephyr" / "runners.yaml", "config:\n  hex_file: zephyr.hex\n")
    images = flash.resolve_flash_images(tmp_path)
    assert [i.hex_path for i in images] == [tmp_path / "zephyr" / "zephyr.hex"]


def test_empty_build_directory_is_an_error(tmp_path):
    with pytest.raises(flash.FlashError):
        flash.resolve_flash_images(tmp_path)


# --- flash.ts prepareNrf91Uicr, NCS 3.5 Feather layout ------------------


def _ncs35_feather_build(tmp_path: Path) -> Path:
    """build/ret_basic_nrf9151 shape: TF-M app plus the nfed UICR image,
    whose runners.yaml names an absolute hex in the board directory."""
    _write(tmp_path / "zephyr" / ".config", 'SB_CONFIG_BOARD="circuitdojo_feather_nrf9151"\n')
    _write(
        tmp_path / "domains.yaml",
        "default: ret_basic\nbuild_dir: x\ndomains:\n  - name: ret_basic\n    build_dir: x\n"
        "flash_order:\n  - ret_basic\n  - uicr_debug_access_open\n",
    )
    _image(tmp_path, "ret_basic", "tfm_merged.hex", APP_HEX)
    _write(tmp_path / "ret_basic" / "zephyr" / "zephyr.hex", BOOT_HEX)
    uicr = _write(tmp_path / "board" / "uicr_debug_access_open.hex", UICR_ONLY_HEX)
    _write(
        tmp_path / "uicr_debug_access_open" / "zephyr" / "runners.yaml",
        f"config:\n  elf_file: \n  hex_file: {uicr}\n",
    )
    return tmp_path


def test_ncs35_feather_build_flashes_uicr_image_then_tfm_merged(tmp_path):
    build = _ncs35_feather_build(tmp_path)
    images = flash.resolve_flash_images(build)
    assert [(i.label, i.preverify) for i in images] == [
        ("bootloaders (uicr_debug_access_open)", True),
        ("ret_basic", False),
    ]
    assert images[1].hex_path == build / "ret_basic" / "zephyr" / "tfm_merged.hex"
    assert flash.images_uicr_words(images) == {0x00FF8000: 0x50FA50FA, 0x00FF802C: 0x50FA50FA}


def test_strip_uicr_images_drops_images_left_empty(tmp_path):
    build = _ncs35_feather_build(tmp_path)
    images = flash.resolve_flash_images(build)
    assert flash.strip_uicr_images(build, images) == [images[1]]


def test_strip_uicr_images_writes_stripped_copy_of_mixed_image(tmp_path):
    mixed = flash.FlashImage("merged.hex", _write(tmp_path / "merged.hex", DEBUG_ACCESS_HEX))
    plain = flash.FlashImage("app", _write(tmp_path / "app.hex", APP_HEX))
    out = flash.strip_uicr_images(tmp_path, [mixed, plain])
    assert out[1] is plain
    assert out[0].hex_path == tmp_path / "zephyr-tools" / "uicr-stripped" / "merged.hex"
    text = out[0].hex_path.read_text()
    assert flash.uicr_words(text) == {}
    assert ":0400000001020304F2" in text


# --- The erase gate (prepare_nrf91_uicr) ------------------------------------
#
# A chip erase wipes all internal flash: it must only happen with --erase
# or the exact typed answer, never on EOF, and never when UICR matches.


def _gate(tmp_path, monkeypatch, device_rows, erase_flag=False, answer=None):
    uicr = tmp_path / "uicr.hex"
    uicr.write_text(DEBUG_ACCESS_HEX)
    images = [flash.FlashImage("uicr", uicr)]
    calls = []

    def fake_run(cmd, timeout):
        calls.append(("run", cmd))
        return flash.subprocess.CompletedProcess(cmd, 0, stdout=device_rows, stderr="")

    def fake_recovery(binary, mode, probe):
        calls.append(("recovery", mode))

    def fake_input(prompt):
        calls.append(("input", prompt))
        if answer is None:
            raise EOFError
        return answer

    monkeypatch.setattr(flash, "run", fake_run)
    monkeypatch.setattr(flash, "recovery", fake_recovery)
    monkeypatch.setattr("builtins.input", fake_input)
    args = flash.argparse.Namespace(
        probe_rs="probe-rs",
        chip="nRF9151_xxAA",
        erase=erase_flag,
        recovery="recovery",
        build=tmp_path,
    )
    return calls, (lambda: flash.prepare_nrf91_uicr(args, images, "1234"))


DIFFERENT_UICR = "00ff8000: ffffffff\n00ff802c: ffffffff\n"
MATCHING_UICR = "00ff8000: 50fa50fa\n00ff802c: 50fa50fa\n"


def test_erase_gate_eof_aborts_without_erasing(tmp_path, monkeypatch):
    calls, go = _gate(tmp_path, monkeypatch, DIFFERENT_UICR, answer=None)
    with pytest.raises(SystemExit):
        go()
    assert ("recovery", "erase") not in calls


def test_erase_gate_wrong_answer_aborts(tmp_path, monkeypatch):
    calls, go = _gate(tmp_path, monkeypatch, DIFFERENT_UICR, answer="yes")
    with pytest.raises(SystemExit):
        go()
    assert ("recovery", "erase") not in calls


def test_erase_gate_typed_erase_erases(tmp_path, monkeypatch):
    calls, go = _gate(tmp_path, monkeypatch, DIFFERENT_UICR, answer="erase")
    go()
    assert ("recovery", "erase") in calls


def test_erase_gate_flag_erases_without_asking(tmp_path, monkeypatch):
    calls, go = _gate(tmp_path, monkeypatch, DIFFERENT_UICR, erase_flag=True)
    go()
    assert ("recovery", "erase") in calls
    assert not [c for c in calls if c[0] == "input"]


def test_erase_gate_matching_uicr_never_erases(tmp_path, monkeypatch):
    calls, go = _gate(tmp_path, monkeypatch, MATCHING_UICR, erase_flag=True)
    images = go()
    assert ("recovery", "erase") not in calls
    # The fixture also writes outside UICR: a UICR-stripped copy is kept.
    assert len(images) == 1
    assert images[0].hex_path.parent.name == "uicr-stripped"
    assert flash.uicr_words(images[0].hex_path.read_text()) == {}
