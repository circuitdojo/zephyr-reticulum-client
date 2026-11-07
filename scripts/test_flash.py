"""Tests for scripts/flash.py, ported from Zephyr Tools' own suites
(zephyr-tools/src/test/suite/uicr.test.ts, flash-hex.test.ts) so the two
stay in agreement.

    uv run --with pytest pytest ret-client/scripts
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


def _build(tmp_path: Path, config: str, hexes: dict[str, str]) -> Path:
    (tmp_path / "zephyr").mkdir()
    (tmp_path / "zephyr" / ".config").write_text(config)
    for rel, text in hexes.items():
        (tmp_path / rel).write_text(text)
    return tmp_path


def test_resolve_sysbuild_partition_manager(tmp_path):
    b = _build(tmp_path, "SB_CONFIG_PARTITION_MANAGER=y\n", {"merged.hex": ":00000001FF\n"})
    assert flash.resolve_image(b) == b / "merged.hex"


def test_resolve_child_image_partition_manager(tmp_path):
    b = _build(
        tmp_path, "CONFIG_PARTITION_MANAGER_ENABLED=y\n", {"zephyr/merged.hex": ":00000001FF\n"}
    )
    assert flash.resolve_image(b) == b / "zephyr" / "merged.hex"


def test_resolve_refuses_non_partition_manager(tmp_path):
    b = _build(tmp_path, "CONFIG_FOO=y\n", {})
    with pytest.raises(SystemExit):
        flash.resolve_image(b)
