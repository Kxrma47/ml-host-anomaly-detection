"""Render deterministic README marketing assets from verified demo results."""

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont, ImageFilter


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "docs" / "assets"
FONT = "/System/Library/Fonts/Menlo.ttc"


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(FONT, size=size, index=1 if bold else 0)


def render_social_preview() -> None:
    source = Image.open(ASSETS / "social-preview-background.png").convert("RGB")
    ratio = max(1280 / source.width, 640 / source.height)
    source = source.resize((round(source.width * ratio), round(source.height * ratio)))
    left = (source.width - 1280) // 2
    top = (source.height - 640) // 2
    canvas = source.crop((left, top, left + 1280, top + 640))
    draw = ImageDraw.Draw(canvas)
    draw.rounded_rectangle((55, 70, 61, 342), radius=3, fill="#42e8e0")
    draw.text((88, 84), "ML HOST", font=font(66, True), fill="#f7fbff")
    draw.text((88, 162), "ANOMALY DETECTION", font=font(58, True), fill="#f7fbff")
    draw.text((91, 257), "REPRODUCIBLE UEBA / AUTOENCODER / JSONL", font=font(21, True), fill="#42e8e0")
    draw.text((91, 307), "26/26 INJECTED ANOMALIES DETECTED  ·  RECALL 1.0", font=font(17), fill="#b7c7d9")
    draw.text((88, 535), "github.com/Kxrma47/ml-host-anomaly-detection", font=font(17), fill="#8b9caf")
    canvas.save(ASSETS / "social-preview.png", optimize=True)


def terminal_frame(lines: list[tuple[str, str]], cursor: bool) -> Image.Image:
    canvas = Image.new("RGB", (960, 540), "#06101b")
    glow = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
    glow_draw = ImageDraw.Draw(glow)
    glow_draw.ellipse((730, -100, 1090, 260), fill=(25, 202, 211, 35))
    canvas = Image.alpha_composite(canvas.convert("RGBA"), glow.filter(ImageFilter.GaussianBlur(70))).convert("RGB")
    draw = ImageDraw.Draw(canvas)
    draw.rounded_rectangle((24, 22, 936, 518), radius=16, fill="#081521", outline="#244154", width=2)
    draw.rectangle((24, 22, 936, 69), fill="#0d1d2b")
    for x, color in ((48, "#ff6b6b"), (73, "#ffd166"), (98, "#48d597")):
        draw.ellipse((x - 6, 40, x + 6, 52), fill=color)
    draw.text((132, 34), "ueba-detector :: verified demo", font=font(16, True), fill="#91a7b8")
    draw.text((782, 35), "● LIVE", font=font(14, True), fill="#48d597")

    y = 92
    for text, color in lines:
        draw.text((52, y), text, font=font(17, color == "#42e8e0"), fill=color)
        y += 34
    if cursor:
        draw.rectangle((52, y + 3, 64, y + 25), fill="#42e8e0")
    draw.text((52, 476), "DETERMINISTIC SEED 47    PYTHON 3.10+    MIT LICENSE", font=font(13), fill="#60788b")
    return canvas


def render_demo_gif() -> None:
    sequence = [
        ([("$ make demo", "#42e8e0")], 8),
        ([("$ make demo", "#42e8e0"), ("generating deterministic telemetry...", "#91a7b8")], 8),
        ([("$ make demo", "#42e8e0"), ("training compact neural autoencoder...", "#91a7b8"), ("calibrating anomaly threshold...", "#91a7b8")], 8),
        ([("$ make demo", "#42e8e0"), ("train samples                 360", "#c6d4df"), ("test samples                  120", "#c6d4df"), ("injected anomalies          26/26", "#48d597")], 10),
        ([("$ make demo", "#42e8e0"), ("injected anomalies          26/26", "#48d597"), ("normal false positives        3/94", "#c6d4df"), ("false negatives                  0", "#48d597"), ("recall                         1.0", "#48d597"), ("✓ JSONL report written", "#8b5cf6")], 24),
    ]
    frames: list[Image.Image] = []
    for lines, count in sequence:
        for index in range(count):
            frames.append(terminal_frame(lines, cursor=index % 6 < 3))
    frames[0].save(
        ASSETS / "terminal-demo.gif",
        save_all=True,
        append_images=frames[1:],
        duration=100,
        loop=0,
        optimize=True,
    )


if __name__ == "__main__":
    ASSETS.mkdir(parents=True, exist_ok=True)
    render_social_preview()
    render_demo_gif()
