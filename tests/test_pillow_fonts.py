"""Pillow's font module is the only thing that loads the Brotli it bundles (FreeType reads WOFF2
with it), and Brotli 1.2.0 has CVE-2026-111497 (Oct 2026). The AppImage build leaves the module and
its libraries out, and stops if anything still needs them. That holds only while the app draws no
text with Pillow."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = (ROOT / "packaging/appimage/build.sh").read_text()


def test_the_font_module_and_its_libraries_are_left_out_of_the_appimage():
    for part in ("PIL/_imagingft.*.so", "pillow.libs/libfreetype-*.so*",
                 "pillow.libs/libharfbuzz-*.so*", "pillow.libs/libbrotli*.so*"):
        assert part in BUILD
    assert "readelf -d" in BUILD


def test_the_app_draws_no_text_with_pillow():
    for path in (ROOT / "src").rglob("*.py"):
        text = path.read_text()
        for used in ("ImageFont", "_imagingft", "truetype("):
            assert used not in text, f"{path.relative_to(ROOT)} uses Pillow's fonts, which the AppImage leaves out"
        assert not ("ImageDraw" in text and ".text(" in text), f"{path.relative_to(ROOT)} draws text with Pillow"
