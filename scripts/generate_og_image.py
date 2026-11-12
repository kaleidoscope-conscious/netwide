#!/usr/bin/env python3
"""
Generate the NetPulse Open Graph / Twitter Card image (1200x630).

Used as og:image / twitter:image so every shared link renders a rich preview
instead of a bare URL. Shares the visual language of the Play Store assets.
"""

from __future__ import annotations

import pathlib
import sys

from PIL import Image, ImageDraw

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_play_store_assets import (  # noqa: E402
    BG_DARK, BG_CARD, CYAN, CYAN_DIM, EMERALD, PURPLE, TEXT_MAIN, _draw_grid, _draw_radar_graphic, _font,
)

OUT = ROOT / "docs" / "assets" / "og_image_1200x630.png"


def build() -> pathlib.Path:
    W, H = 1200, 630
    img = Image.new("RGB", (W, H), BG_DARK)
    draw = ImageDraw.Draw(img)
    _draw_grid(draw, W, H, step=40)

    # Accent frame
    draw.rectangle([0, 0, W - 1, H - 1], outline=CYAN_DIM, width=3)

    # Radar panel on the right
    _draw_radar_graphic(draw, 860, 318, 175)

    # Wordmark
    draw.rounded_rectangle([54, 52, 300, 92], radius=9, fill=(10, 44, 62), outline=CYAN, width=2)
    draw.text((68, 62), "NETPULSE v4.6", fill=CYAN, font=_font(17, bold=True, mono=True))
    draw.text((54, 112), "SEE EVERY DEVICE", fill=TEXT_MAIN, font=_font(52, bold=True))
    draw.text((54, 176), "ON YOUR NETWORK", fill=TEXT_MAIN, font=_font(52, bold=True))
    draw.text((56, 248), "Hidden SSIDs · rogue cameras · crypto audits · live DPI · one-click quarantine",
              fill=EMERALD, font=_font(16, bold=True, mono=True))

    bullets = [
        ("10-STAGE DE-CLOAKER", "Unmask hidden & spoofed gadgets"),
        ("WIRE DPI + JA3", "See what every device really talks"),
        ("ACTIVE DEFENSE", "Quarantine the freeloader in one click"),
        ("100% ON-DEVICE", "No cloud. No account. No telemetry."),
    ]
    y = 300
    for tag, desc in bullets:
        draw.rounded_rectangle([54, y, 300, y + 34], radius=7, fill=BG_CARD, outline=CYAN_DIM, width=2)
        draw.text((66, y + 9), tag, fill=CYAN, font=_font(14, bold=True, mono=True))
        draw.text((314, y + 9), desc, fill=(200, 214, 232), font=_font(15, mono=False))
        y += 44

    # Footer bar
    draw.rectangle([0, H - 62, W, H], fill=(8, 13, 24))
    draw.line([(0, H - 62), (W, H - 62)], fill=CYAN_DIM, width=2)
    draw.text((54, H - 44), "kaleidoscope-conscious.github.io/netpulse", fill=CYAN, font=_font(17, bold=True, mono=True))
    draw.text((640, H - 44), "LINUX · DOCKER · ANDROID · FREE TIER FOREVER", fill=(148, 163, 184),
              font=_font(14, mono=True))
    draw.text((1090, H - 44), "v4.6", fill=PURPLE, font=_font(16, bold=True, mono=True))

    OUT.parent.mkdir(parents=True, exist_ok=True)
    img.save(OUT)
    return OUT


if __name__ == "__main__":
    path = build()
    print(f"Generated {path} ({path.stat().st_size // 1024} KB)")
