# -*- coding: utf-8 -*-
"""Alternative, copyright-clean wolf mark for HenkerDPI.

Not the icon the app currently ships. The mark is drawn from scratch here - a
front-facing, mirror-symmetric wolf head on the app's dark disc, in the graphite
theme accent - so it is free of any third-party rights. Kept as a drop-in
replacement: run this, then copy tools/wolf_mark.* over icon.* in the repo root.

    py -3 tools/make_wolf_mark.py            # writes tools/wolf_mark.png + .ico
    py -3 tools/make_wolf_mark.py --preview  # also writes tools/wolf_mark_sizes.png
"""
import os
import sys
from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

S = 2048                          # supersampled canvas
K = S / 1000.0                    # design space (1000x1000) -> canvas
CX, CY, R = 500.0, 500.0, 352.0   # disc
SC, DY = 0.92, 70.0               # head fit inside the disc

DISC = "#0c0e12"                  # theme bg
RIM = "#294a99"                   # theme accent_dim
FUR_TOP = "#f2f6fb"
FUR_BOT = "#a9bad0"
EYE = "#4d8bff"                   # theme accent

# right half of the head, top centre -> chin; the left half is mirrored
HALF = [
    (500, 250),   # dip between the ears
    (572, 222),   # ear inner base
    (668, 104),   # ear tip
    (706, 276),   # ear outer base
    (742, 372),   # temple, widest point
    (712, 452),   # cheek
    (768, 500),   # ruff spike
    (676, 556),
    (712, 596),   # second ruff spike
    (612, 638),
    (574, 698),   # muzzle side
    (546, 752),
    (500, 776),   # chin
]

EAR_IN = [(590, 250), (664, 160), (688, 276)]
EYE_Q = [(712, 442), (598, 492), (642, 508)]
NOSE = [(500, 800), (452, 700), (548, 700)]

ICO_SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]


def mirror(pts):
    return [(1000 - x, y) for x, y in pts]


def tx(pts):
    return [(((x - CX) * SC + CX) * K, ((y - CY) * SC + CY + DY * SC) * K) for x, y in pts]


def hexrgb(h):
    return tuple(int(h[i:i + 2], 16) for i in (1, 3, 5))


def build(size=512):
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    box = [(CX - R) * K, (CY - R) * K, (CX + R) * K, (CY + R) * K]
    d.ellipse(box, fill=DISC)
    d.ellipse(box, outline=RIM, width=int(7 * K))

    mask = Image.new("L", (S, S), 0)
    m = ImageDraw.Draw(mask)
    m.polygon(tx(HALF + mirror(HALF)[::-1]), fill=255)
    m.polygon(tx(EAR_IN), fill=0)
    m.polygon(tx(mirror(EAR_IN)), fill=0)
    m.polygon(tx(NOSE), fill=0)

    grad = Image.new("RGB", (1, S))
    gp = grad.load()
    c0, c1 = hexrgb(FUR_TOP), hexrgb(FUR_BOT)
    for y in range(S):
        f = y / (S - 1.0)
        gp[0, y] = tuple(int(c0[i] + (c1[i] - c0[i]) * f) for i in range(3))
    img.paste(grad.resize((S, S)), (0, 0), mask)

    d = ImageDraw.Draw(img)
    d.polygon(tx(EYE_Q), fill=EYE)
    d.polygon(tx(mirror(EYE_Q)), fill=EYE)
    return img.resize((size, size), Image.LANCZOS)


if __name__ == "__main__":
    here = os.path.join(ROOT, "tools")
    # 1024, because that is the largest entry macOS' iconset table asks for
    # (icon_512x512@2x). Mastering at 512 meant the macOS build ran
    # `sips -z 1024 1024` over it, so the icon a Retina Mac shows in the Dock
    # and in Finder was an upscale of half the resolution it needed. The canvas
    # is supersampled at S = 2048, so 1024 costs nothing and invents nothing.
    master = build(1024)
    master.save(os.path.join(here, "wolf_mark.png"))
    master.resize((256, 256), Image.LANCZOS).save(
        os.path.join(here, "wolf_mark.ico"), sizes=ICO_SIZES)
    print("wrote tools/wolf_mark.png (1024) and .ico", [s[0] for s in ICO_SIZES])

    if "--preview" not in sys.argv:
        raise SystemExit(0)

    # side-by-side size check for review
    sheet = Image.new("RGB", (1240, 320), (26, 26, 30))
    sheet.paste(master.resize((280, 280), Image.LANCZOS), (10, 20),
                master.resize((280, 280), Image.LANCZOS))
    x = 310
    for s in (128, 64, 48, 32, 24, 16):
        big = master.resize((s, s), Image.LANCZOS).resize((s * 2, s * 2), Image.NEAREST)
        sheet.paste(big, (x, 20), big)
        light = Image.new("RGB", (s * 2, s * 2), (238, 240, 244))
        light.paste(big, (0, 0), big)
        sheet.paste(light, (x, 20 + 270 - s * 2))
        x += s * 2 + 16
    sheet.save(os.path.join(here, "wolf_mark_sizes.png"))
