"""Render the ThreatKey SVG master as transparent Chrome extension icons.

Requires librsvg's rsvg-convert (macOS: brew install librsvg).
Run with: python3 generate_icons.py
"""

from pathlib import Path
import shutil
import subprocess


def main():
    renderer = shutil.which("rsvg-convert")
    if renderer is None:
        raise SystemExit(
            "rsvg-convert is required. Install librsvg "
            "(macOS: brew install librsvg), then run this script again."
        )

    icons_dir = Path(__file__).resolve().parent / "icons"
    source = icons_dir / "threatkey.svg"
    for size in (16, 32, 48, 128):
        output = icons_dir / f"icon-{size}.png"
        subprocess.run(
            [renderer, "--width", str(size), "--height", str(size),
             "--output", str(output), str(source)],
            check=True,
        )
        print(f"Generated: {output}")


if __name__ == "__main__":
    main()
