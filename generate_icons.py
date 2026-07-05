"""Generate ThreatKey extension icons - blue crosshair only."""
from PIL import Image, ImageDraw
import math


def draw_icon(size):
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    s = size / 128.0

    # Background: rounded dark rectangle
    pad = int(8 * s)
    draw.rounded_rectangle(
        [pad, pad, size - pad, size - pad],
        radius=int(20 * s),
        fill=(20, 25, 35, 255),
    )

    blue = (0, 200, 255, 255)

    # Crosshair centered
    cx = size // 2
    cy = size // 2
    outer_r = int(38 * s)
    inner_r = int(16 * s)
    line_w = max(int(4 * s), 2)
    cross_ext = int(10 * s)

    # Outer circle
    draw.ellipse(
        [cx - outer_r, cy - outer_r, cx + outer_r, cy + outer_r],
        outline=blue,
        width=line_w,
    )

    # Inner circle
    draw.ellipse(
        [cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r],
        outline=blue,
        width=max(int(3 * s), 1),
    )

    # Crosshair lines
    draw.line([(cx, cy - outer_r - cross_ext), (cx, cy - inner_r)],
              fill=blue, width=line_w)
    draw.line([(cx, cy + inner_r), (cx, cy + outer_r + cross_ext)],
              fill=blue, width=line_w)
    draw.line([(cx - outer_r - cross_ext, cy), (cx - inner_r, cy)],
              fill=blue, width=line_w)
    draw.line([(cx + inner_r, cy), (cx + outer_r + cross_ext, cy)],
              fill=blue, width=line_w)

    # Center dot
    dot_r = max(int(4 * s), 2)
    draw.ellipse(
        [cx - dot_r, cy - dot_r, cx + dot_r, cy + dot_r],
        fill=blue,
    )

    return img


if __name__ == '__main__':
    import os
    out_dir = os.path.join(os.path.dirname(__file__), 'icons')
    os.makedirs(out_dir, exist_ok=True)

    for size in [16, 48, 128]:
        img = draw_icon(size)
        path = os.path.join(out_dir, f'icon-{size}.png')
        img.save(path)
        print(f'Generated: {path}')
