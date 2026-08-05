"""Render assets/social-preview.png, the 1280x640 GitHub social-preview card.

Run after changing icon.png so the shared-link card matches the app icon:
    py assets/make_social_preview.py

Colours are lifted from the app's default Graphite theme so the card, the exe
icon and the running UI read as one thing.
"""
import os
from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "assets", "social-preview.png")

W, H = 1280, 640
BG = (10, 11, 13)            # Graphite bg  #0a0b0d
CARD = (20, 21, 24)          # Graphite card #141518
ACCENT = (77, 139, 255)      # Graphite accent #4d8bff
FG = (244, 246, 249)         # Graphite fg
FG2 = (148, 153, 166)        # Graphite fg2

B = r"C:\Windows\Fonts\segoeuib.ttf"
SB = r"C:\Windows\Fonts\seguisb.ttf"
R = r"C:\Windows\Fonts\segoeui.ttf"

img = Image.new("RGB", (W, H), BG)

# Soft accent glow behind the logo, so the card has depth without a busy image.
glow = Image.new("RGB", (W, H), BG)
gd = ImageDraw.Draw(glow)
gcx, gcy, gr = 360, H // 2, 300
gd.ellipse([gcx - gr, gcy - gr, gcx + gr, gcy + gr], fill=(30, 52, 105))
glow = glow.filter(ImageFilter.GaussianBlur(130))
img = Image.blend(img, glow, 0.85)

draw = ImageDraw.Draw(img)

# Faint diagonal streaks, a nod to fragmented packets on the wire.
for i in range(-2, 14):
    x = i * 110
    draw.line([(x, H), (x + 240, 0)], fill=(18, 20, 26), width=2)

# --- Logo ---
logo = Image.open(os.path.join(ROOT, "icon.png")).convert("RGBA")
LS = 300
logo = logo.resize((LS, LS), Image.LANCZOS)
lx, ly = 150, (H - LS) // 2
img.paste(logo, (lx, ly), logo)

# --- Text block ---
tx = lx + LS + 78

f_title = ImageFont.truetype(B, 104)
f_tag = ImageFont.truetype(SB, 34)
f_sub = ImageFont.truetype(R, 27)

draw.text((tx, 196), "HenkerDPI", font=f_title, fill=FG)

# Accent rule between wordmark and tagline. Segoe UI Bold at 104px descends to
# roughly y+130, so the rule sits below that to read as a separator rather than
# a stray underline on the first few glyphs.
draw.rounded_rectangle([tx + 3, 338, tx + 111, 343], radius=3, fill=ACCENT)

draw.text((tx + 3, 366), "DPI bypass for Windows", font=f_tag, fill=ACCENT)

draw.text((tx + 3, 424),
          "Access blocked sites without a VPN.",
          font=f_sub, fill=FG2)
draw.text((tx + 3, 458),
          "Kernel-level TLS fragmentation — no external servers.",
          font=f_sub, fill=FG2)

os.makedirs(os.path.dirname(OUT), exist_ok=True)
img.save(OUT, "PNG", optimize=True)
print("yazildi:", OUT, img.size, f"{os.path.getsize(OUT):,} bayt")
