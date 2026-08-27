"""
HenkerDPI - Modern GUI
Features: Mode selector (All/Selective), category toggles, Secure DNS switch, 4 themes
"""

import customtkinter as ctk
from tkinter import messagebox
import tkinter as tk
import threading
import queue
import subprocess
import json
import os
import plistlib
import sys
import time
import math
import webbrowser

IS_MAC = sys.platform == "darwin"

if IS_MAC:
    # Same interface, different machinery: a local desync proxy instead of a
    # packet-level filter, because macOS has no WinDivert. The macOS build
    # never repoints system DNS, so there is no DNS journal to replay either.
    from macos.engine import BypassEngine, is_admin

    def restore_dns_from_journal(log=print):
        return False
else:
    from main import BypassEngine, is_admin
    from doh import restore_dns_from_journal
from lang import LANGUAGES, load_lang_pref, save_lang_pref, t
from config import (
    load_custom_domains, save_custom_domains, load_settings, save_settings,
    CATEGORIES, DOH_PROVIDERS, MODE_ALL, MODE_SELECTIVE, resolve_pref,
    APP_VERSION,
)
import updater

try:
    from PIL import Image, ImageDraw, ImageTk, ImageFilter
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import pystray
    HAS_TRAY = True
except ImportError:
    HAS_TRAY = False

if IS_MAC:
    # pystray's macOS backend drives an NSStatusItem, and AppKit only allows
    # that from the main thread — which tkinter's event loop already owns, so
    # _show_tray would start it in a worker and it would not appear. The Mac
    # gets its menu-bar item from Tk's own `tk systray` instead (see
    # _create_tray_mac); this flag governs the pystray path only.
    HAS_TRAY = False

ctk.set_appearance_mode("dark")

SERVICE_NAME = "HenkerDPI"
# How long quitting waits for the engine thread to undo its system changes.
# Generous enough for someone to read a password dialog and type into it, short
# enough that a dialog left unanswered does not look like a hung app.
QUIT_JOIN_TIMEOUT = 25.0
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Writable dir for user prefs. SCRIPT_DIR is the read-only _MEIxxxx temp dir in
# a frozen onefile build (it also holds the bundled icons), so theme/lang prefs
# must live next to the exe like config.py's settings.json — otherwise they
# reset to defaults on every launch.
if getattr(sys, "frozen", False):
    _APP_DIR = os.path.dirname(sys.executable)
else:
    _APP_DIR = SCRIPT_DIR
# Native system UI font: Segoe UI on Windows (far cleaner than the Helvetica
# alias, which falls back to Arial), Helvetica on macOS. One swap modernises
# every label without touching a single widget.
FONT = "Helvetica" if IS_MAC else "Segoe UI"

GREEN = "#4ade80"
RED = "#f87171"

# Hide console windows for subprocess calls. The flag exists only on Windows;
# on macOS there is no console to hide and passing it would raise.
_CF = getattr(subprocess, "CREATE_NO_WINDOW", 0)


# macOS login item. A LaunchAgent in the user's own directory, so it needs no
# privileges to install and cannot affect anyone else on the machine.
LAUNCH_AGENT_LABEL = "com.henkerr.henkerdpi"


def _launch_agent_path() -> str:
    return os.path.join(os.path.expanduser("~"), "Library", "LaunchAgents",
                        LAUNCH_AGENT_LABEL + ".plist")


def _autostart_argv_mac() -> list:
    """What launchd should run at login.

    Frozen, this is the bundle's own executable — never SCRIPT_DIR, which in a
    packaged app points inside the read-only bundle payload rather than at
    something launchable.
    """
    if getattr(sys, "frozen", False):
        return [sys.executable, "--autostart"]
    return [sys.executable, os.path.join(SCRIPT_DIR, "gui.py"), "--autostart"]


def _autostart_target():
    """Build the command Task Scheduler runs at logon.

    When frozen (PyInstaller onefile) we MUST point at the real installed
    .exe via sys.executable. SCRIPT_DIR then resolves to an ephemeral
    %TEMP%\\_MEIxxxx extraction folder that Windows deletes on exit, so a
    task pointing there fails every boot with "file not found" (result 2).

    --autostart tells the app to start the engine and drop to the tray
    instead of opening the window.
    """
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --autostart'
    # Dev / loose-script mode: use the current interpreter (no hardcoded
    # path), preferring pythonw.exe so no console window flashes on boot.
    pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    if not os.path.exists(pyw):
        pyw = sys.executable
    return f'"{pyw}" "{os.path.join(SCRIPT_DIR, "gui.py")}" --autostart'

# Premium palettes (redesigned for public release). Pick via the settings dots.
THEMES = {
    "graphite": {
        "name": "Graphite",
        "bg": "#0a0b0d", "card": "#141518", "border": "#24262b",
        "accent": "#4d8bff", "accent_dim": "#294a99",
        "secondary": "#38bdf8", "tertiary": "#6ea3ff",
        "fg": "#f4f6f9", "fg2": "#9499a6", "fg3": "#6d7280",
        "glow_active": (77, 139, 255), "glow_hover": (48, 108, 224),
        "ring_hover": (130, 175, 255),
    },
    "iris": {
        "name": "Iris",
        "bg": "#0a0a0f", "card": "#14141f", "border": "#26263a",
        "accent": "#6d6af2", "accent_dim": "#3a3499",
        "secondary": "#8b87ff", "tertiary": "#5b78f0",
        "fg": "#f6f7fb", "fg2": "#aaacbe", "fg3": "#72748c",
        "glow_active": (109, 106, 242), "glow_hover": (88, 82, 214),
        "ring_hover": (150, 148, 255),
    },
    "halcyon": {
        "name": "Halcyon",
        "bg": "#070b0e", "card": "#0e161a", "border": "#1e2c33",
        "accent": "#2dd4bf", "accent_dim": "#0f766e",
        "secondary": "#38cfe0", "tertiary": "#5eead4",
        "fg": "#eef5f5", "fg2": "#8fa5aa", "fg3": "#5f767b",
        "glow_active": (45, 212, 191), "glow_hover": (24, 180, 164),
        "ring_hover": (124, 237, 222),
    },
    "gold": {
        "name": "Obsidian",
        "bg": "#0a0906", "card": "#12100c", "border": "#282219",
        "accent": "#e8b25a", "accent_dim": "#7a5424",
        "secondary": "#e0954e", "tertiary": "#cdaa6e",
        "fg": "#f7f3ea", "fg2": "#a39a86", "fg3": "#8b8271",
        "glow_active": (232, 178, 90), "glow_hover": (196, 142, 62),
        "ring_hover": (246, 206, 140),
    },
}

DEFAULT_THEME = "graphite"
THEME_FILE = resolve_pref("theme_pref.json")

NUM_HOVER_FRAMES = 4
HOVER_ANIM_MS = 60
# Breathing-glow loop for the running power button: rendered once, looped on a
# timer. A smooth 0->1->0 cosine cycle so the light swells and fades like breath.
PULSE_FRAMES = 18
PULSE_MS = 62

# Windows sends the tray icon's callback message with this lparam when the user
# CLICKS a notification we raised (it lands in the Action Center, so the click
# can come long after). pystray 0.19.5 only handles the mouse events, so without
# the hook in _hook_balloon_click a clicked notification would do nothing.
NIN_BALLOONUSERCLICK = 0x0400 + 5

# Points, not pixels: the macOS menu bar is 22 points tall and Tk hands the
# image to AppKit at its natural size, so anything larger is cropped or pushes
# the bar's other items around.
TRAY_ICON_PX = 22


def _load_theme():
    try:
        with open(THEME_FILE, "r") as f:
            key = json.load(f).get("theme", DEFAULT_THEME)
            if key in THEMES:
                return key
    except Exception:
        pass
    return DEFAULT_THEME


def _save_theme(key):
    with open(THEME_FILE, "w") as f:
        json.dump({"theme": key}, f)


def _hex_to_rgb(h):
    return (int(h[1:3], 16), int(h[3:5], 16), int(h[5:7], 16))


def _lerp(a, b, t):
    return a + (b - a) * t


def _lerp_color(c1, c2, t):
    return tuple(int(_lerp(a, b, t)) for a, b in zip(c1, c2))


def _make_power_button(size, active, hover=0.0, theme_key="phantom"):
    """Power button with themed glow animation."""
    th = THEMES[theme_key]
    s = size * 3
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx, cy = s // 2, s // 2

    ga = th["glow_active"]
    gh = th["glow_hover"]
    rh = th["ring_hover"]

    accent_rgb = _hex_to_rgb(th["accent"])
    border_rgb = _hex_to_rgb(th["border"])
    card_rgb = _hex_to_rgb(th["card"])
    icon_bright = tuple(min(c + 60, 255) for c in accent_rgb)
    inner_active = (accent_rgb[0] // 12, accent_rgb[1] // 12, accent_rgb[2] // 12)
    inner_dim = card_rgb
    inner_dim_hover = tuple(min(c + 10, 255) for c in card_rgb)

    if active:
        # Wider glow range so the running "breathing" pulse is clearly visible.
        ring_col = _lerp_color((*ga, 255), (*[min(c + 30, 255) for c in ga], 255), hover)
        glow_col = (*ga, int(_lerp(70, 165, hover)))
        icon_col = _lerp_color((*accent_rgb, 255), (*icon_bright, 255), hover)
        inner_col = (*inner_active, 255)
    else:
        # OFF, but never dead: tint the ring and glyph toward the theme accent
        # so an idle power button reads as a branded, tappable control rather
        # than a flat grey circle, and keep a faint accent halo at rest.
        base_ring = _lerp_color(
            tuple(min(c + 40, 255) for c in border_rgb),
            _hex_to_rgb(th["accent_dim"]), 0.45)
        ring_col = _lerp_color((*base_ring, 255), (*rh, 255), hover)
        glow_col = (*gh, int(_lerp(24, 82, hover)))
        icon_base = _lerp_color(tuple(min(c + 22, 255) for c in border_rgb),
                                accent_rgb, 0.30)
        icon_col = _lerp_color((*icon_base, 225), (255, 255, 255, 255), hover)
        inner_col = _lerp_color((*inner_dim, 255), (*inner_dim_hover, 255), hover)

    # Hero glow: a big soft ambient bloom PLUS a tighter bright core, so the
    # card fills with light rather than showing a thin ring. OFF at rest keeps a
    # faint halo; the bloom swells with the pulse/hover for a living light.
    glow = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    amb_r = int(s * (0.44 + 0.07 * hover))
    amb_a = int(glow_col[3] * 0.5)
    gd.ellipse([cx - amb_r, cy - amb_r, cx + amb_r, cy + amb_r],
               fill=(glow_col[0], glow_col[1], glow_col[2], amb_a))
    core_r = int(s * (0.32 + 0.06 * hover))
    gd.ellipse([cx - core_r, cy - core_r, cx + core_r, cy + core_r], fill=glow_col)
    blur_r = max(1, int(s * 0.10))
    glow = glow.filter(ImageFilter.GaussianBlur(radius=blur_r))
    img = Image.alpha_composite(img, glow)
    draw = ImageDraw.Draw(img)

    rr = int(s * 0.40)
    rw = int(s * _lerp(0.020, 0.026, hover))
    draw.ellipse([cx - rr, cy - rr, cx + rr, cy + rr],
                 outline=ring_col, width=rw)

    ir = int(s * 0.32)
    draw.ellipse([cx - ir, cy - ir, cx + ir, cy + ir],
                 fill=inner_col, outline=(30, 28, 50, 120), width=int(s * 0.008))

    pw_r = int(s * 0.13)
    pw_w = int(s * 0.025)
    draw.arc([cx - pw_r, cy - pw_r, cx + pw_r, cy + pw_r],
             start=310, end=230, fill=icon_col, width=pw_w)
    line_top = cy - int(s * 0.16)
    line_bot = cy - int(s * 0.03)
    draw.line([cx, line_top, cx, line_bot], fill=icon_col, width=pw_w)

    img = img.resize((size, size), Image.LANCZOS)
    return img


class HenkerDPIApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self._lang = load_lang_pref()
        self._theme = _load_theme()
        self._settings = load_settings()

        self.title("HenkerDPI")
        self.geometry("420x600")
        self.minsize(400, 520)
        self.configure(fg_color=THEMES[self._theme]["bg"])

        # Soft launch: start transparent and fade in. Skipped when the boot task
        # sends us straight to the tray (nothing to fade), so the window is never
        # left invisible when later reopened from the tray.
        self._will_fade = ("--autostart" not in sys.argv
                           and "--minimized" not in sys.argv)
        if self._will_fade:
            try:
                self.attributes("-alpha", 0.0)
            except Exception:
                self._will_fade = False

        icon_path = os.path.join(SCRIPT_DIR, "icon.ico")
        self._icon_png = os.path.join(SCRIPT_DIR, "icon.png")
        # .ico is a Windows format and iconbitmap() does nothing on Aqua; the
        # Mac's icon comes from the bundle's icon.icns instead.
        if not IS_MAC and os.path.exists(icon_path):
            self.iconbitmap(icon_path)

        self._engine = None
        self._thread = None
        self._log_queue = queue.Queue()
        self._running = False
        self._tray_icon = None
        # Tk drops an image the moment nothing in Python refers to it, and a
        # menu-bar icon whose image has been collected renders as blank.
        self._tray_image = None
        self._start_time = None

        self._hover_frame = 0
        self._hover_anim_id = None
        self._pulse_id = None
        self._pulse_i = 0
        self._render_power_frames()
        self._theme_dots = []
        self._update_info = None
        self._update_busy = False
        self._update_retried = False

        self._build_ui()
        self._poll_log_queue()
        self._check_autostart()
        self._highlight_active_theme()

        # Drop the exe the previous update replaced, then look for a new one.
        updater.cleanup_old_version()
        self.after(2500, self._check_update_async)

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        if IS_MAC:
            # Cmd-Q and Dock > Quit do NOT go through WM_DELETE_WINDOW. Tk
            # turns the Apple Event into Tcl_Exit unless ::tk::mac::Quit
            # exists, which would skip _quit() and the engine-thread join
            # behind it — leaving the Mac pointed at a proxy that is gone, the
            # exact failure the restore path was written to prevent.
            self.createcommand("::tk::mac::Quit", self._quit)
            # Clicking the Dock icon of an app whose window is withdrawn does
            # nothing unless this exists, so it is the second way back from the
            # menu bar - and the safety net if the icon ever fails to appear.
            self.createcommand("::tk::mac::ReopenApplication", self._restore)
        else:
            # Minimising to the tray is a Windows idiom; on macOS the Dock
            # already owns it, and there is no tray icon in this build to
            # restore the window from.
            self.bind("<Unmap>", self._on_minimize)

        # Launched by the boot task (schtasks --autostart): start the engine
        # and go straight to the tray without showing the window.
        if "--autostart" in sys.argv or "--minimized" in sys.argv:
            self.after(400, self._enter_background)
        else:
            if self._will_fade:
                self._fade_in_window()
            # --run: keep the window on screen AND start the engine, so the
            # bypass keeps protecting while the redesigned UI is visible.
            if "--run" in sys.argv:
                self.after(500, self._start)

    def _fade_in_window(self, steps=10, ms=16):
        """Ramp window opacity 0 -> 1 for a soft launch."""
        def _step(i):
            try:
                self.attributes("-alpha", min(1.0, i / steps))
            except Exception:
                return
            if i < steps:
                self.after(ms, _step, i + 1)
        _step(1)

    def _enter_background(self):
        """Boot autostart: start the bypass and drop to the system tray."""
        if not self._running and self._settings.get("autostart_engine", False):
            self._start()
        if self._show_tray():
            self.withdraw()
            return
        self.iconify()                   # fallback: minimise, stay reachable

    def _render_power_frames(self):
        self._apply_pil_frames(*self._render_pil_frames())

    def _render_pil_frames(self):
        pil_off = []
        pil_on = []
        for i in range(NUM_HOVER_FRAMES + 1):
            h = i / NUM_HOVER_FRAMES
            pil_off.append(_make_power_button(198, False, h, self._theme))
            pil_on.append(_make_power_button(198, True, h, self._theme))
        pil_pulse = []
        for i in range(PULSE_FRAMES):
            h = 0.5 - 0.5 * math.cos(2 * math.pi * i / PULSE_FRAMES)
            pil_pulse.append(_make_power_button(198, True, h, self._theme))
        return pil_off, pil_on, pil_pulse

    def _apply_pil_frames(self, pil_off, pil_on, pil_pulse):
        self._frames_off = [ImageTk.PhotoImage(img) for img in pil_off]
        self._frames_on = [ImageTk.PhotoImage(img) for img in pil_on]
        self._frames_pulse = [ImageTk.PhotoImage(img) for img in pil_pulse]
        self._img_off = self._frames_off[0]
        self._img_on = self._frames_on[0]

    def _render_power_frames_async(self):
        theme_key = self._theme
        def _worker():
            frames = self._render_pil_frames()
            self.after(0, lambda: self._on_async_render_done(theme_key, *frames))
        threading.Thread(target=_worker, daemon=True).start()

    def _on_async_render_done(self, theme_key, pil_off, pil_on, pil_pulse):
        if self._theme != theme_key:
            return
        self._apply_pil_frames(pil_off, pil_on, pil_pulse)
        if self._running:
            self._start_pulse()
        else:
            self._stop_pulse()
            self._hover_frame = 0
            self._power_label.configure(image=self._frames_off[0])

    # --- Breathing pulse (running state) ---
    def _start_pulse(self):
        self._stop_pulse()
        self._pulse_i = 0
        self._pulse_step()

    def _pulse_step(self):
        if not self._running or not getattr(self, "_frames_pulse", None):
            return
        self._power_label.configure(image=self._frames_pulse[self._pulse_i])
        self._pulse_i = (self._pulse_i + 1) % len(self._frames_pulse)
        self._pulse_id = self.after(PULSE_MS, self._pulse_step)

    def _stop_pulse(self):
        pid = getattr(self, "_pulse_id", None)
        if pid:
            try:
                self.after_cancel(pid)
            except Exception:
                pass
        self._pulse_id = None

    def _fade_status_color(self, target_hex, text=None, steps=6, ms=28):
        """Ease the status label from its current colour to target_hex, so the
        on/off flip glides instead of snapping. Sets the text up front."""
        if text is not None:
            self._status_text.configure(text=text)
        try:
            cur = self._status_text.cget("text_color")
            c0 = _hex_to_rgb(cur if isinstance(cur, str) else cur[-1])
            c1 = _hex_to_rgb(target_hex)
        except Exception:
            self._status_text.configure(text_color=target_hex)
            return
        self._status_fade_seq = getattr(self, "_status_fade_seq", 0) + 1
        seq = self._status_fade_seq

        def _step(i):
            if seq != self._status_fade_seq:
                return
            col = _lerp_color(c0, c1, i / steps)
            self._status_text.configure(text_color="#%02x%02x%02x" % col)
            if i < steps:
                self.after(ms, _step, i + 1)
        _step(1)

    def _build_ui(self):
        th = THEMES[self._theme]

        # === Scrollable Main ===
        self._scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self._scroll.pack(fill="both", expand=True)

        # === Header ===
        self._header = ctk.CTkFrame(self._scroll, fg_color=th["card"], corner_radius=0, height=40)
        self._header.pack(fill="x")
        self._header.pack_propagate(False)

        self._henker_label = ctk.CTkLabel(self._header, text="HENKER",
                     font=ctk.CTkFont(FONT, 17, "bold"), text_color=th["fg"])
        self._henker_label.pack(side="left", padx=(16, 0))
        self._dpi_label = ctk.CTkLabel(self._header, text="DPI",
                     font=ctk.CTkFont(FONT, 17, "bold"), text_color=th["accent"])
        self._dpi_label.pack(side="left", padx=(2, 0))

        self._badge = ctk.CTkLabel(
            self._header, text=t("badge_offline", self._lang),
            font=ctk.CTkFont(FONT, 10), text_color=th["fg3"],
            fg_color=th["border"], corner_radius=8)
        self._badge.pack(side="right", padx=(0, 16))

        # Settings (gear) — reveals the advanced panel below the home screen.
        # Theme + language now live inside that panel so the header stays clean.
        self._settings_open = False
        self._gear_btn = ctk.CTkButton(
            self._header, text="⚙", width=32, height=26,
            font=ctk.CTkFont(FONT, 16),
            fg_color="transparent", hover_color=th["border"],
            text_color=th["fg2"], command=self._toggle_settings)
        self._gear_btn.pack(side="right", padx=(0, 12))

        # Thin accent rule under the header — a touch of structure/depth so the
        # top bar reads as a distinct surface rather than floating.
        self._header_sep = ctk.CTkFrame(self._scroll, fg_color=th["accent_dim"],
                                        height=2, corner_radius=0)
        self._header_sep.pack(fill="x")

        # === Update banner (hidden until a newer release is found) ===
        self._update_bar = ctk.CTkFrame(self._scroll, fg_color=th["accent_dim"],
                                        corner_radius=0, height=38)
        self._update_bar.pack_propagate(False)
        self._update_msg = ctk.CTkLabel(
            self._update_bar, text="", font=ctk.CTkFont(FONT, 11, "bold"),
            text_color="#ffffff")
        self._update_msg.pack(side="left", padx=(16, 0))
        self._update_close = ctk.CTkButton(
            self._update_bar, text="✕", width=26, height=24,
            font=ctk.CTkFont(FONT, 12), fg_color="transparent",
            hover_color=th["accent"], text_color="#ffffff",
            command=self._dismiss_update)
        self._update_close.pack(side="right", padx=(0, 10))
        self._update_btn = ctk.CTkButton(
            self._update_bar, text="", width=90, height=24,
            font=ctk.CTkFont(FONT, 11, "bold"), corner_radius=6,
            fg_color="#ffffff", hover_color="#e6e6e6",
            text_color=th["accent_dim"], command=self._do_update)
        self._update_btn.pack(side="right", padx=(0, 8))
        self._update_notes = ctk.CTkButton(
            self._update_bar, text="", width=110, height=24,
            font=ctk.CTkFont(FONT, 11), fg_color="transparent",
            hover_color=th["accent"], text_color="#ffffff",
            command=self._open_release_notes)
        self._update_notes.pack(side="right", padx=(0, 4))

        # === Main Content ===
        main = ctk.CTkFrame(self._scroll, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=16, pady=(12, 6))

        # --- Power Button Card ---
        self._btn_card = ctk.CTkFrame(main, fg_color=th["card"], corner_radius=18,
                                 border_width=1, border_color=th["border"])
        self._btn_card.pack(fill="x")

        self._status_text = ctk.CTkLabel(
            self._btn_card, text=t("status_off", self._lang),
            font=ctk.CTkFont(FONT, 24, "bold"), text_color=th["fg2"])
        self._status_text.pack(pady=(24, 0))

        self._status_desc = ctk.CTkLabel(
            self._btn_card, text=t("desc_off", self._lang),
            font=ctk.CTkFont(FONT, 12), text_color=th["fg3"])
        self._status_desc.pack(pady=(5, 0))

        self._power_label = tk.Label(self._btn_card, image=self._img_off,
                                      bg=th["card"], cursor="hand2",
                                      bd=0, highlightthickness=0)
        self._power_label.pack(pady=(14, 24))
        self._power_label.bind("<Button-1>", self._on_power_click)
        self._power_label.bind("<Enter>", self._on_hover_enter)
        self._power_label.bind("<Leave>", self._on_hover_leave)
        self._click_ok = True

        # --- Mode Selector Card ---
        self._mode_card = ctk.CTkFrame(main, fg_color=th["card"], corner_radius=10,
                                        border_width=1, border_color=th["border"])
        self._mode_card.pack(fill="x", pady=(10, 0))

        mode_header = ctk.CTkFrame(self._mode_card, fg_color="transparent")
        mode_header.pack(fill="x", padx=10, pady=(8, 4))

        self._mode_title = ctk.CTkLabel(
            mode_header, text=t("mode_label", self._lang),
            font=ctk.CTkFont(FONT, 11, "bold"), text_color=th["fg2"])
        self._mode_title.pack(side="left")

        # Mode toggle: All | Selective
        mode_row = ctk.CTkFrame(self._mode_card, fg_color=th["bg"], corner_radius=8)
        mode_row.pack(fill="x", padx=10, pady=(0, 8))

        current_mode = self._settings.get("mode", MODE_ALL)
        self._mode_btns = {}
        for mode_key, label_key in [(MODE_ALL, "mode_all"), (MODE_SELECTIVE, "mode_selective")]:
            is_active = (mode_key == current_mode)
            btn = ctk.CTkButton(
                mode_row, text=t(label_key, self._lang),
                height=30, font=ctk.CTkFont(FONT, 11, "bold"),
                fg_color=th["accent"] if is_active else "transparent",
                hover_color=th["border"],
                text_color=th["fg"] if is_active else th["fg3"],
                corner_radius=6,
                command=lambda m=mode_key: self._set_mode(m))
            btn.pack(side="left", expand=True, fill="x", padx=2, pady=2)
            self._mode_btns[mode_key] = btn

        # --- Categories Card (sadece selective modda) ---
        self._cat_card = ctk.CTkFrame(main, fg_color=th["card"], corner_radius=10,
                                       border_width=1, border_color=th["border"])
        self._cat_card.pack(fill="x", pady=(10, 0))

        cat_header = ctk.CTkFrame(self._cat_card, fg_color="transparent")
        cat_header.pack(fill="x", padx=10, pady=(8, 4))

        self._cat_title = ctk.CTkLabel(
            cat_header, text=t("categories", self._lang),
            font=ctk.CTkFont(FONT, 11, "bold"), text_color=th["fg2"])
        self._cat_title.pack(side="left")

        # Kategori toggle'ları
        self._cat_vars = {}
        self._cat_switches = {}
        enabled_cats = self._settings.get("enabled_categories", list(CATEGORIES.keys()))
        cat_grid = ctk.CTkFrame(self._cat_card, fg_color="transparent")
        cat_grid.pack(fill="x", padx=10, pady=(0, 8))

        for i, (cat_key, cat_data) in enumerate(CATEGORIES.items()):
            var = ctk.BooleanVar(value=cat_key in enabled_cats)
            self._cat_vars[cat_key] = var

            row = ctk.CTkFrame(cat_grid, fg_color="transparent")
            row.pack(fill="x", pady=1)

            switch = ctk.CTkSwitch(
                row, text=f"{cat_data['name']} ({len(cat_data['domains'])})",
                font=ctk.CTkFont(FONT, 10), variable=var,
                progress_color=th["accent"], button_color=th["fg3"],
                button_hover_color=th["fg2"],
                command=self._save_categories,
                width=40)
            switch.pack(side="left", padx=4)
            self._cat_switches[cat_key] = switch

        # ALL modda kategorileri gizle
        if current_mode == MODE_ALL:
            self._cat_card.pack_forget()

        # --- Stats Row ---
        stats = ctk.CTkFrame(main, fg_color="transparent")
        stats.pack(fill="x", pady=(10, 0))

        self._cards = {}
        self._card_labels = {}
        self._stat_bars = {}
        self._stat_frames = {}
        self._stat_title_labels = []
        self._stat_value_labels = []
        _stat_defs = [
            ("bypass", "stat_bypass", th["secondary"]),
            ("uptime", "stat_uptime", th["tertiary"]),
        ]
        for i, (key, title_key, accent) in enumerate(_stat_defs):
            card = ctk.CTkFrame(stats, fg_color=th["card"], corner_radius=12,
                                border_width=1, border_color=th["border"])
            px = (0 if i == 0 else 3, 0 if i == len(_stat_defs) - 1 else 3)
            card.pack(side="left", expand=True, fill="x", padx=px)
            self._stat_frames[key] = card

            bar = ctk.CTkFrame(card, fg_color=accent, height=2, corner_radius=0)
            bar.pack(fill="x", padx=10, pady=(8, 0))
            self._stat_bars[key] = bar
            title_lbl = ctk.CTkLabel(card, text=t(title_key, self._lang),
                                     font=ctk.CTkFont(FONT, 10), text_color=th["fg3"])
            title_lbl.pack(anchor="w", padx=10, pady=(4, 0))
            self._card_labels[key] = (title_lbl, title_key)
            self._stat_title_labels.append(title_lbl)
            lbl = ctk.CTkLabel(card, text="0" if key != "uptime" else "—",
                               font=ctk.CTkFont(FONT, 24, "bold"), text_color=accent)
            lbl.pack(anchor="w", padx=10, pady=(0, 8))
            self._cards[key] = lbl
            self._stat_value_labels.append(lbl)

        # (Removed the technical "TTL Fake / 2 bytes / RST Kernel / QUIC DROP"
        # info bar — internal jargon that meant nothing to users and read as
        # cluttered/amateur. Kept as empty lists so i18n/theme loops no-op.)
        self._info_labels = []
        self._info_value_labels = []
        self._info_key_labels = []

        # === Settings panel (hidden by default; toggled by the header gear) ===
        # Keeps the home screen to just power + status + stats + mode. Every
        # technical control lives here, so the default view stays clean and
        # consumer-friendly. Created but NOT packed -> hidden until toggled.
        self._settings_panel = ctk.CTkFrame(main, fg_color="transparent")

        # --- Appearance (theme dots + language) ---
        appear_card = ctk.CTkFrame(self._settings_panel, fg_color=th["card"],
                                   corner_radius=10, border_width=1,
                                   border_color=th["border"])
        appear_card.pack(fill="x", pady=(10, 0))
        appear_row = ctk.CTkFrame(appear_card, fg_color="transparent")
        appear_row.pack(fill="x", padx=10, pady=8)
        self._theme_frame = ctk.CTkFrame(appear_row, fg_color="transparent")
        self._theme_frame.pack(side="left")
        for key, tdata in THEMES.items():
            dot = ctk.CTkButton(
                self._theme_frame, text="", width=22, height=22,
                corner_radius=11, fg_color=tdata["accent"],
                hover_color=tdata["accent"], border_width=0,
                command=lambda k=key: self._change_theme(k))
            dot.pack(side="left", padx=4)
            self._theme_dots.append((key, dot))
        self._lang_menu = ctk.CTkOptionMenu(
            appear_row, values=[LANGUAGES[k]["name"] for k in LANGUAGES],
            width=96, height=24, font=ctk.CTkFont(FONT, 10),
            fg_color=th["border"], button_color=th["accent_dim"],
            button_hover_color=th["accent"], dropdown_fg_color=th["card"],
            command=self._change_lang)
        self._lang_menu.set(LANGUAGES[self._lang]["name"])
        self._lang_menu.pack(side="right")

        # --- DoH Card ---
        self._doh_card = ctk.CTkFrame(self._settings_panel, fg_color=th["card"], corner_radius=10,
                                       border_width=1, border_color=th["border"])
        self._doh_card.pack(fill="x", pady=(10, 0))

        doh_row = ctk.CTkFrame(self._doh_card, fg_color="transparent")
        doh_row.pack(fill="x", padx=10, pady=8)

        self._doh_var = ctk.BooleanVar(value=self._settings.get("doh_enabled", True))
        self._doh_switch = ctk.CTkSwitch(
            doh_row, text=t("doh_label", self._lang),
            font=ctk.CTkFont(FONT, 11, "bold"), variable=self._doh_var,
            progress_color=th["accent"], button_color=th["fg3"],
            button_hover_color=th["fg2"],
            command=self._save_doh)
        self._doh_switch.pack(side="left")

        # DoH provider dropdown
        provider_names = [v["name"] for v in DOH_PROVIDERS.values()]
        current_provider = DOH_PROVIDERS.get(
            self._settings.get("doh_provider", "cloudflare"), {"name": "Cloudflare"})["name"]
        self._doh_menu = ctk.CTkOptionMenu(
            doh_row, values=provider_names, width=110, height=24,
            font=ctk.CTkFont(FONT, 10),
            fg_color=th["border"], button_color=th["accent_dim"],
            button_hover_color=th["accent"], dropdown_fg_color=th["card"],
            command=self._change_doh_provider)
        self._doh_menu.set(current_provider)
        self._doh_menu.pack(side="right")

        doh_desc_row = ctk.CTkFrame(self._doh_card, fg_color="transparent")
        doh_desc_row.pack(fill="x", padx=10, pady=(0, 8))
        self._doh_desc = ctk.CTkLabel(
            doh_desc_row, text=t("doh_desc", self._lang),
            font=ctk.CTkFont(FONT, 9), text_color=th["fg3"])
        self._doh_desc.pack(side="left")

        # --- Custom Domains ---
        self._domain_card = ctk.CTkFrame(self._settings_panel, fg_color=th["card"], corner_radius=10,
                                          border_width=1, border_color=th["border"])
        self._domain_card.pack(fill="x", pady=(10, 0))

        domain_header = ctk.CTkFrame(self._domain_card, fg_color="transparent")
        domain_header.pack(fill="x", padx=10, pady=(8, 4))

        self._domain_title = ctk.CTkLabel(
            domain_header, text=t("custom_domains", self._lang),
            font=ctk.CTkFont(FONT, 11, "bold"), text_color=th["fg2"])
        self._domain_title.pack(side="left")

        domain_input_row = ctk.CTkFrame(self._domain_card, fg_color="transparent")
        domain_input_row.pack(fill="x", padx=10, pady=(0, 4))

        self._domain_entry = ctk.CTkEntry(
            domain_input_row, height=28, font=ctk.CTkFont(FONT, 11),
            placeholder_text=t("domain_placeholder", self._lang),
            fg_color=th["bg"], border_color=th["border"], text_color=th["fg"])
        self._domain_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self._domain_entry.bind("<Return>", lambda e: self._add_domain())

        self._add_btn = ctk.CTkButton(
            domain_input_row, text=t("add_domain", self._lang),
            width=60, height=28, font=ctk.CTkFont(FONT, 10),
            fg_color=th["accent"], hover_color=th["accent_dim"],
            command=self._add_domain)
        self._add_btn.pack(side="right")

        self._domain_list_frame = ctk.CTkFrame(self._domain_card, fg_color="transparent")
        self._domain_list_frame.pack(fill="x", padx=10, pady=(0, 8))
        self._domain_widgets = []
        self._refresh_domain_list()

        # --- Log ---
        self._log_card = ctk.CTkFrame(self._settings_panel, fg_color=th["card"], corner_radius=10,
                                 border_width=1, border_color=th["border"])
        self._log_card.pack(fill="both", expand=True, pady=(10, 0))

        log_h = ctk.CTkFrame(self._log_card, fg_color="transparent")
        log_h.pack(fill="x", padx=8, pady=(6, 2))

        self._log_filter = "all"
        self._log_entries = []
        self._filter_btns = {}
        filter_frame = ctk.CTkFrame(log_h, fg_color=th["bg"], corner_radius=6)
        filter_frame.pack(side="left")
        for key, label_key in [("all", "log"), ("bypass", "stat_bypass"), ("block", "log_block")]:
            btn = ctk.CTkButton(
                filter_frame, text=t(label_key, self._lang),
                width=50, height=22, font=ctk.CTkFont(FONT, 9, "bold"),
                fg_color=th["accent"] if key == "all" else "transparent",
                hover_color=th["border"], corner_radius=5,
                text_color=th["fg"] if key == "all" else th["fg3"],
                command=lambda k=key: self._set_log_filter(k))
            btn.pack(side="left", padx=1, pady=1)
            self._filter_btns[key] = btn

        self._clear_btn = ctk.CTkButton(
            log_h, text=t("clear", self._lang), width=50, height=22,
            font=ctk.CTkFont(FONT, 9),
            fg_color="transparent", hover_color=th["border"],
            text_color=th["fg3"], command=self._clear_log)
        self._clear_btn.pack(side="right")

        self._log_search = ctk.CTkEntry(
            log_h, height=22, width=100, font=ctk.CTkFont(FONT, 9),
            placeholder_text="🔍",
            fg_color=th["bg"], border_color=th["border"],
            text_color=th["fg"], corner_radius=5)
        self._log_search.pack(side="right", padx=(0, 4))
        self._log_search.bind("<KeyRelease>", lambda e: self._apply_log_filter())

        self._log_widget = tk.Text(
            self._log_card, bg=th["card"], fg=th["fg2"], font=(FONT, 10),
            relief="flat", state="disabled", wrap="word",
            padx=10, pady=4, borderwidth=0, height=8,
            insertbackground=th["fg"], selectbackground=th["accent_dim"])
        self._log_widget.tag_configure("bypass", foreground=th["secondary"])
        self._log_widget.tag_configure("info", foreground=th["accent"])
        self._log_widget.tag_configure("error", foreground=RED)
        self._log_widget.tag_configure("time", foreground=th["fg3"])
        self._log_widget.pack(fill="both", expand=True, padx=4, pady=(0, 4))

        # --- Bottom (autostart + version) ---
        bottom = ctk.CTkFrame(self._settings_panel, fg_color="transparent")
        bottom.pack(fill="x", pady=(10, 0))

        self._auto_var = ctk.BooleanVar()
        self._auto_switch = ctk.CTkSwitch(
            bottom, text=t("autostart", self._lang),
            font=ctk.CTkFont(FONT, 10),
            variable=self._auto_var, command=self._toggle_auto,
            progress_color=th["accent"], button_color=th["fg3"],
            button_hover_color=th["fg2"])
        self._auto_switch.pack(side="left")
        self._version_label = ctk.CTkLabel(bottom, text=f"v{APP_VERSION}",
                     font=ctk.CTkFont(FONT, 9), text_color=th["fg3"])
        self._version_label.pack(side="right")

        # A second row, macOS only: what the login item does once it has opened
        # the app. Windows has nothing to ask here — its scheduled task runs
        # elevated and silently, so it always starts the engine. On a Mac that
        # same step needs an administrator prompt, and whether one should appear
        # by itself at every login is the user's call, not ours.
        self._auto_engine_switch = None
        if IS_MAC:
            engine_row = ctk.CTkFrame(self._settings_panel,
                                      fg_color="transparent")
            engine_row.pack(fill="x", pady=(6, 0))
            self._auto_engine_var = ctk.BooleanVar(
                value=self._settings.get("autostart_engine", False))
            self._auto_engine_switch = ctk.CTkSwitch(
                engine_row, text=t("autostart_engine", self._lang),
                font=ctk.CTkFont(FONT, 10),
                variable=self._auto_engine_var,
                command=self._save_autostart_engine,
                progress_color=th["accent"], button_color=th["fg3"],
                button_hover_color=th["fg2"])
            self._auto_engine_switch.pack(side="left")

    def _toggle_settings(self):
        """Show/hide the advanced settings panel. Default view stays clean."""
        if self._settings_open:
            self._settings_panel.pack_forget()
            self._settings_open = False
            self._gear_btn.configure(text="⚙")
        else:
            self._settings_panel.pack(fill="both", expand=True)
            self._settings_open = True
            self._gear_btn.configure(text="✕")

    # === Mode ===

    def _set_mode(self, mode):
        th = THEMES[self._theme]
        self._settings["mode"] = mode
        save_settings(self._settings)

        for m, btn in self._mode_btns.items():
            if m == mode:
                btn.configure(fg_color=th["accent"], text_color=th["fg"])
            else:
                btn.configure(fg_color="transparent", text_color=th["fg3"])

        # Kategorileri göster/gizle
        if mode == MODE_ALL:
            self._cat_card.pack_forget()
        else:
            # info_frame'den sonra pack et
            self._cat_card.pack(fill="x", pady=(10, 0),
                                after=self._mode_card)

        # Engine çalışıyorsa ayarları güncelle
        if self._engine:
            self._engine.reload_settings()

        self._log_queue.put(f"[*] Mode → {mode.upper()}")

    def _save_categories(self):
        enabled = [k for k, v in self._cat_vars.items() if v.get()]
        self._settings["enabled_categories"] = enabled
        save_settings(self._settings)
        if self._engine:
            self._engine.reload_settings()

    # === DoH ===

    def _save_doh(self):
        self._settings["doh_enabled"] = self._doh_var.get()
        save_settings(self._settings)

    def _change_doh_provider(self, selected_name):
        for key, data in DOH_PROVIDERS.items():
            if data["name"] == selected_name:
                self._settings["doh_provider"] = key
                save_settings(self._settings)
                break

    # === Language ===

    def _change_lang(self, selected_name):
        for code, data in LANGUAGES.items():
            if data["name"] == selected_name:
                self._lang = code
                save_lang_pref(code)
                self._apply_lang()
                break

    def _apply_lang(self):
        L = self._lang
        if self._running:
            self._badge.configure(text=t("badge_online", L))
            self._status_text.configure(text=t("status_on", L))
            self._status_desc.configure(text=t("desc_on", L))
        else:
            self._badge.configure(text=t("badge_offline", L))
            self._status_text.configure(text=t("status_off", L))
            self._status_desc.configure(text=t("desc_off", L))
        for key, (lbl, title_key) in self._card_labels.items():
            lbl.configure(text=t(title_key, L))
        for lbl, lbl_key in self._info_labels:
            lbl.configure(text=t(lbl_key, L))
        self._mode_title.configure(text=t("mode_label", L))
        for m, lk in [(MODE_ALL, "mode_all"), (MODE_SELECTIVE, "mode_selective")]:
            self._mode_btns[m].configure(text=t(lk, L))
        self._cat_title.configure(text=t("categories", L))
        self._doh_switch.configure(text=t("doh_label", L))
        self._doh_desc.configure(text=t("doh_desc", L))
        self._domain_title.configure(text=t("custom_domains", L))
        self._add_btn.configure(text=t("add_domain", L))
        self._domain_entry.configure(placeholder_text=t("domain_placeholder", L))
        for key, label_key in [("all", "log"), ("bypass", "stat_bypass"), ("block", "log_block")]:
            if key in self._filter_btns:
                self._filter_btns[key].configure(text=t(label_key, L))
        self._clear_btn.configure(text=t("clear", L))
        self._auto_switch.configure(text=t("autostart", L))
        if self._auto_engine_switch is not None:
            self._auto_engine_switch.configure(text=t("autostart_engine", L))
        if self._tray_icon:
            self._hide_tray()
            self._show_tray()

    # === Theme ===

    def _change_theme(self, key):
        if key == self._theme:
            return
        self._theme = key
        _save_theme(key)
        self._apply_theme()

    def _highlight_active_theme(self):
        th = THEMES[self._theme]
        for key, dot in self._theme_dots:
            if key == self._theme:
                dot.configure(width=24, height=24, corner_radius=12,
                              border_width=2, border_color=th["fg"])
            else:
                dot.configure(width=22, height=22, corner_radius=11,
                              border_width=0, border_color=th["card"])

    def _apply_theme(self):
        th = THEMES[self._theme]
        self._highlight_active_theme()
        self.configure(fg_color=th["bg"])

        self._header.configure(fg_color=th["card"])
        self._header_sep.configure(fg_color=th["accent_dim"])
        self._henker_label.configure(text_color=th["fg"])
        self._dpi_label.configure(text_color=th["accent"])

        self._update_bar.configure(fg_color=th["accent_dim"])
        self._update_btn.configure(fg_color="#ffffff", hover_color="#e6e6e6",
                                   text_color=th["accent_dim"])
        self._update_close.configure(hover_color=th["accent"])
        self._update_notes.configure(hover_color=th["accent"])
        if not self._running:
            self._badge.configure(text_color=th["fg3"], fg_color=th["border"])
        self._lang_menu.configure(fg_color=th["border"], button_color=th["accent_dim"],
                                   button_hover_color=th["accent"],
                                   dropdown_fg_color=th["card"])

        self._btn_card.configure(fg_color=th["card"], border_color=th["border"])
        if not self._running:
            self._status_text.configure(text_color=th["fg2"])
        self._status_desc.configure(text_color=th["fg3"])
        self._power_label.configure(bg=th["card"])
        self._render_power_frames_async()

        # Mode card
        self._mode_card.configure(fg_color=th["card"], border_color=th["border"])
        self._mode_title.configure(text_color=th["fg2"])
        current_mode = self._settings.get("mode", MODE_ALL)
        for m, btn in self._mode_btns.items():
            if m == current_mode:
                btn.configure(fg_color=th["accent"], text_color=th["fg"],
                              hover_color=th["border"])
            else:
                btn.configure(fg_color="transparent", text_color=th["fg3"],
                              hover_color=th["border"])

        # Category card
        self._cat_card.configure(fg_color=th["card"], border_color=th["border"])
        self._cat_title.configure(text_color=th["fg2"])
        for switch in self._cat_switches.values():
            switch.configure(progress_color=th["accent"], button_color=th["fg3"],
                             button_hover_color=th["fg2"])

        # DoH card
        self._doh_card.configure(fg_color=th["card"], border_color=th["border"])
        self._doh_switch.configure(progress_color=th["accent"], button_color=th["fg3"],
                                    button_hover_color=th["fg2"])
        self._doh_menu.configure(fg_color=th["border"], button_color=th["accent_dim"],
                                  button_hover_color=th["accent"],
                                  dropdown_fg_color=th["card"])
        self._doh_desc.configure(text_color=th["fg3"])

        # Stats
        stat_colors = [th["secondary"], th["tertiary"]]
        for idx, key in enumerate(["bypass", "uptime"]):
            self._stat_frames[key].configure(fg_color=th["card"], border_color=th["border"])
            self._stat_bars[key].configure(fg_color=stat_colors[idx])
        for lbl in self._stat_title_labels:
            lbl.configure(text_color=th["fg3"])
        for lbl, col in zip(self._stat_value_labels, stat_colors):
            lbl.configure(text_color=col)

        # Custom domains
        self._domain_card.configure(fg_color=th["card"], border_color=th["border"])
        self._domain_title.configure(text_color=th["fg2"])
        self._domain_entry.configure(fg_color=th["bg"], border_color=th["border"],
                                      text_color=th["fg"])
        self._add_btn.configure(fg_color=th["accent"], hover_color=th["accent_dim"])
        self._refresh_domain_list()

        # Log
        self._clear_btn.configure(hover_color=th["border"], text_color=th["fg3"])
        self._log_card.configure(fg_color=th["card"], border_color=th["border"])
        self._log_search.configure(fg_color=th["bg"], border_color=th["border"],
                                    text_color=th["fg"])
        for k, btn in self._filter_btns.items():
            if k == self._log_filter:
                btn.configure(fg_color=th["accent"], text_color=th["fg"],
                              hover_color=th["border"])
            else:
                btn.configure(fg_color="transparent", text_color=th["fg3"],
                              hover_color=th["border"])
        self._log_widget.configure(bg=th["card"], fg=th["fg2"],
                            insertbackground=th["fg"], selectbackground=th["accent_dim"])
        self._log_widget.tag_configure("bypass", foreground=th["secondary"])
        self._log_widget.tag_configure("info", foreground=th["accent"])
        self._log_widget.tag_configure("time", foreground=th["fg3"])

        # Bottom
        self._auto_switch.configure(progress_color=th["accent"],
                                     button_color=th["fg3"],
                                     button_hover_color=th["fg2"])
        if self._auto_engine_switch is not None:
            self._auto_engine_switch.configure(progress_color=th["accent"],
                                               button_color=th["fg3"],
                                               button_hover_color=th["fg2"])
        self._version_label.configure(text_color=th["fg3"])

    # === Power Button ===

    def _on_power_click(self, event=None):
        if not self._click_ok:
            return
        self._click_ok = False
        self.after(600, self._reset_click)
        self._toggle()

    def _reset_click(self):
        self._click_ok = True

    def _on_hover_enter(self, event=None):
        if self._running:
            return
        self._animate_hover(NUM_HOVER_FRAMES)

    def _on_hover_leave(self, event=None):
        if self._running:
            return
        self._animate_hover(0)

    def _animate_hover(self, target):
        if self._hover_anim_id:
            self.after_cancel(self._hover_anim_id)
            self._hover_anim_id = None
        if self._hover_frame == target:
            return
        step = 1 if target > self._hover_frame else -1
        self._hover_frame += step
        frames = self._frames_on if self._running else self._frames_off
        self._power_label.configure(image=frames[self._hover_frame])
        if self._hover_frame != target:
            self._hover_anim_id = self.after(HOVER_ANIM_MS, self._animate_hover, target)

    def _toggle(self):
        if self._running:
            self._stop()
        else:
            self._start()

    def _start(self):
        if self._running:
            return

        # Ayarları yeniden yükle
        self._settings = load_settings()

        def _engine_thread():
            try:
                self._engine.start()
            except Exception as e:
                self._log_queue.put(f"[!] {e}")
            finally:
                self.after(100, self._on_engine_stopped)

        self._engine = BypassEngine(
            log_callback=lambda m: self._log_queue.put(m), verbose=True)
        self._thread = threading.Thread(target=_engine_thread, daemon=True)
        self._thread.start()

        self._running = True
        self._start_time = time.time()
        self._bypass_shown = 0
        self._cards["bypass"].configure(text="0")
        self._hover_frame = NUM_HOVER_FRAMES
        self._start_pulse()
        self._fade_status_color(GREEN, t("status_on", self._lang))
        self._status_desc.configure(text=t("desc_on", self._lang))
        th = THEMES[self._theme]
        self._badge.configure(text=t("badge_online", self._lang), text_color=GREEN,
                               fg_color=th["accent_dim"])
        self._tick_stats()
        self._update_tray_menu()
        # Retry the update check now that traffic goes through the bypass —
        # this is the attempt that succeeds when the ISP blocks GitHub. Forced
        # past the daily throttle, but only once per session and only if the
        # startup attempt actually failed to reach GitHub.
        if not self._update_retried and updater.last_check_failed():
            self._update_retried = True
            self.after(3000, lambda: self._check_update_async(force=True))

    def _on_engine_stopped(self):
        if not self._running:
            return
        self._running = False
        self._engine = None
        self._thread = None
        self._start_time = None
        self._stop_pulse()
        self._hover_frame = 0
        self._power_label.configure(image=self._frames_off[0])
        th = THEMES[self._theme]
        self._fade_status_color(th["fg2"], t("status_off", self._lang))
        self._status_desc.configure(text=t("desc_off", self._lang))
        self._badge.configure(text=t("badge_offline", self._lang), text_color=th["fg3"],
                               fg_color=th["border"])
        self._cards["uptime"].configure(text="—")

    def _stop(self):
        if not self._running:
            return
        if self._engine:
            self._engine.stop()
        self._running = False
        self._engine = None
        self._thread = None
        self._start_time = None
        self._stop_pulse()
        self._hover_frame = 0
        self._power_label.configure(image=self._frames_off[0])
        th = THEMES[self._theme]
        self._fade_status_color(th["fg2"], t("status_off", self._lang))
        self._status_desc.configure(text=t("desc_off", self._lang))
        self._badge.configure(text=t("badge_offline", self._lang), text_color=th["fg3"],
                               fg_color=th["border"])
        self._cards["uptime"].configure(text="—")
        self._update_tray_menu()

    # === Stats ===

    def _animate_bypass(self, target, steps=8, ms=22):
        """Tween the bypass counter to its new value so it ticks up instead of
        jumping — lively when a page fires dozens of handshakes at once."""
        start = getattr(self, "_bypass_shown", 0)
        if target == start:
            return
        self._bypass_anim_seq = getattr(self, "_bypass_anim_seq", 0) + 1
        seq = self._bypass_anim_seq

        def _step(i):
            if seq != self._bypass_anim_seq:
                return
            if not self._running or i >= steps:
                self._bypass_shown = target
                self._cards["bypass"].configure(text=str(target))
                return
            val = int(start + (target - start) * (i / steps))
            self._bypass_shown = val
            self._cards["bypass"].configure(text=str(val))
            self.after(ms, _step, i + 1)
        _step(1)

    def _tick_stats(self):
        if not self._running or not self._engine:
            return
        s = self._engine.stats
        self._animate_bypass(s["bypassed"])
        if self._start_time:
            el = int(time.time() - self._start_time)
            m, sec = divmod(el, 60)
            h, m = divmod(m, 60)
            if h:
                txt = t("uptime_fmt", self._lang, h=h, m=m)
            else:
                txt = t("uptime_fmt_short", self._lang, m=m, s=sec)
            self._cards["uptime"].configure(text=txt)
        self.after(1000, self._tick_stats)

    # === Custom Domains ===

    def _add_domain(self):
        raw = self._domain_entry.get().strip().lower()
        if raw.startswith("http://"):
            raw = raw[7:]
        elif raw.startswith("https://"):
            raw = raw[8:]
        domain = raw.split("/")[0].split("?")[0].split("#")[0]
        if not domain or "." not in domain:
            self._log_queue.put(t("domain_invalid", self._lang))
            return
        customs = load_custom_domains()
        if domain in customs:
            self._log_queue.put(t("domain_exists", self._lang, domain=domain))
            return
        customs.append(domain)
        save_custom_domains(customs)
        self._domain_entry.delete(0, "end")
        self._refresh_domain_list()
        self._log_queue.put(t("domain_added", self._lang, domain=domain))

    def _remove_domain(self, domain):
        customs = load_custom_domains()
        if domain in customs:
            customs.remove(domain)
            save_custom_domains(customs)
            self._refresh_domain_list()
            self._log_queue.put(t("domain_removed", self._lang, domain=domain))

    def _refresh_domain_list(self):
        for w in self._domain_widgets:
            w.destroy()
        self._domain_widgets.clear()
        th = THEMES[self._theme]
        customs = load_custom_domains()
        for domain in customs:
            row = ctk.CTkFrame(self._domain_list_frame, fg_color=th["bg"],
                               corner_radius=6, height=26)
            row.pack(fill="x", pady=1)
            row.pack_propagate(False)
            lbl = ctk.CTkLabel(row, text=domain,
                               font=ctk.CTkFont(FONT, 10), text_color=th["fg2"])
            lbl.pack(side="left", padx=8)
            btn = ctk.CTkButton(
                row, text="✕", width=24, height=20,
                font=ctk.CTkFont(FONT, 10),
                fg_color="transparent", hover_color=th["border"],
                text_color=th["fg3"],
                command=lambda d=domain: self._remove_domain(d))
            btn.pack(side="right", padx=4)
            self._domain_widgets.append(row)

    # === Log ===

    def _set_log_filter(self, key):
        self._log_filter = key
        th = THEMES[self._theme]
        for k, btn in self._filter_btns.items():
            if k == key:
                btn.configure(fg_color=th["accent"], text_color=th["fg"])
            else:
                btn.configure(fg_color="transparent", text_color=th["fg3"])
        self._apply_log_filter()

    def _apply_log_filter(self):
        search = self._log_search.get().strip().lower()
        self._log_widget.config(state="normal")
        self._log_widget.delete("1.0", "end")
        for ts, tag, msg in self._log_entries:
            if self._log_filter == "bypass" and tag != "bypass":
                continue
            if self._log_filter == "block" and tag != "error":
                continue
            if search and search not in msg.lower():
                continue
            self._log_widget.insert("end", f"{ts}  ", "time")
            self._log_widget.insert("end", msg + "\n", tag)
        self._log_widget.see("end")
        self._log_widget.config(state="disabled")

    def _poll_log_queue(self):
        try:
            while True:
                msg = self._log_queue.get_nowait()
                ts = time.strftime("%H:%M:%S")
                tag = "bypass" if "[BYPASS]" in msg else \
                      "error" if "[!]" in msg else "info"
                self._log_entries.append((ts, tag, msg))
                if len(self._log_entries) > 500:
                    self._log_entries = self._log_entries[-500:]
                search = self._log_search.get().strip().lower()
                show = True
                if self._log_filter == "bypass" and tag != "bypass":
                    show = False
                if self._log_filter == "block" and tag != "error":
                    show = False
                if search and search not in msg.lower():
                    show = False
                if show:
                    self._log_widget.config(state="normal")
                    self._log_widget.insert("end", f"{ts}  ", "time")
                    self._log_widget.insert("end", msg + "\n", tag)
                    lc = int(self._log_widget.index("end-1c").split(".")[0])
                    if lc > 500:
                        self._log_widget.delete("1.0", f"{lc-500}.0")
                    self._log_widget.see("end")
                    self._log_widget.config(state="disabled")
        except queue.Empty:
            pass
        self.after(150, self._poll_log_queue)

    def _clear_log(self):
        self._log_entries.clear()
        self._log_widget.config(state="normal")
        self._log_widget.delete("1.0", "end")
        self._log_widget.config(state="disabled")

    # === Updates ===

    def _check_update_async(self, force: bool = False):
        """Look for a newer release off the UI thread; stay silent on failure.

        Runs once at startup and again when the bypass is switched on: if the
        ISP blocks GitHub, the first attempt fails and the second — now going
        through the bypass — usually succeeds. updater throttles to one real
        request per day, so the extra call costs nothing.
        """
        if self._update_busy or self._update_info:
            return
        if not self._settings.get("update_check_enabled", True):
            return
        if not updater.due_for_check(force):
            return

        def worker():
            info = updater.check_for_update(force)
            self.after(0, lambda: self._on_update_checked(info, force))

        threading.Thread(target=worker, daemon=True).start()

    def _on_update_checked(self, info, forced=False):
        if not info:
            if forced:
                self._log_queue.put(t("update_none", self._lang))
            return
        if not forced and updater.is_skipped(info.version):
            return
        self._update_info = info
        self._show_update_bar(t("update_available", self._lang).format(
            version=info.version))
        self._update_btn.configure(text=t("update_button", self._lang),
                                   state="normal")
        self._update_notes.configure(text=t("update_notes", self._lang))
        self._update_close.configure(state="normal")
        self._notify_update(info)

    def _notify_update(self, info):
        """Raise a Windows notification for an update found while in the tray.

        Only meaningful with a live tray icon: pystray can raise a balloon only
        from a running icon, and with the window open the banner above is
        already on screen. This is the case the banner alone could not cover —
        the app runs from the boot task and the user never opens the window.
        """
        icon = self._tray_icon
        if icon is None:
            return
        try:
            icon.notify(
                t("update_notify", self._lang).format(version=info.version),
                "HenkerDPI")
        except Exception:
            pass          # a notification is never worth breaking the app for

    def _update_from_notification(self):
        """The notification was clicked: show the window, then update.

        The window is restored first on purpose. This is an elevated tool
        replacing its own executable, so the download / verify / restart steps
        belong on screen in the banner rather than happening invisibly.
        """
        if self._update_busy or not self._update_info:
            return
        self._restore()
        self._do_update()

    def _show_update_bar(self, message: str):
        self._update_msg.configure(text=message)
        if not self._update_bar.winfo_ismapped():
            # Directly under the header, above everything else.
            self._update_bar.pack(fill="x", after=self._header)

    def _hide_update_bar(self):
        if self._update_bar.winfo_ismapped():
            self._update_bar.pack_forget()

    def _open_release_notes(self):
        if self._update_info:
            webbrowser.open(self._update_info.notes_url)

    def _dismiss_update(self):
        """Hide the banner and stay quiet until a version newer than this one."""
        if self._update_busy:
            return
        if self._update_info:
            updater.skip_version(self._update_info.version)
        self._update_info = None
        self._hide_update_bar()

    def _do_update(self):
        if self._update_busy or not self._update_info:
            return
        if not updater.can_self_update():
            # Running from source, or the macOS bundle, which is replaced by
            # downloading a new DMG rather than swapped in place: show the
            # release page instead.
            self._open_release_notes()
            return

        info = self._update_info
        self._update_busy = True
        self._update_btn.configure(state="disabled")
        self._update_close.configure(state="disabled")

        # Stop the engine FIRST and on the UI thread: BypassEngine.stop()
        # restores the system DNS and closes the WinDivert handles. Replacing
        # the exe while it still owns them would leave the user pinned to a
        # public resolver with the journal's owning process gone.
        if self._running:
            self._show_update_bar(t("update_stopping", self._lang))
            self._stop()

        def worker():
            try:
                def on_progress(done, total):
                    pct = int(done * 100 / total) if total else 0
                    self.after(0, lambda: self._show_update_bar(
                        t("update_downloading", self._lang).format(pct=pct)))

                path = updater.download_update(info, progress=on_progress)
                self.after(0, lambda: self._show_update_bar(
                    t("update_verifying", self._lang)))
                updater.apply_update(path)
                self.after(0, self._finish_update)
            except Exception as e:
                self.after(0, lambda: self._update_failed(e))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_update(self):
        self._show_update_bar(t("update_restarting", self._lang))
        self._hide_tray()
        try:
            _release_single_instance()   # let the new process take the mutex
            updater.relaunch()
        except Exception as e:
            self._update_failed(e)
            return
        self.after(400, self.destroy)

    def _update_failed(self, err):
        self._update_busy = False
        self._log_queue.put(f"[!] {t('update_failed', self._lang)}: {err}")
        self._show_update_bar(t("update_failed", self._lang))
        self._update_btn.configure(state="normal",
                                   text=t("update_button", self._lang))
        self._update_close.configure(state="normal")

    # === Autostart ===

    def _migrate_legacy_autostart(self) -> bool:
        """Remove the pre-rename 'HenkerDPI_V2' logon task.

        Returns True if one existed, so the caller can re-register it under the
        current name — otherwise upgrading users silently lose autostart.
        """
        legacy = "HenkerDPI_V2"
        try:
            r = subprocess.run(["schtasks", "/query", "/tn", legacy],
                               capture_output=True, text=True,
                               creationflags=_CF)
            if r.returncode != 0:
                return False
            subprocess.run(["schtasks", "/delete", "/tn", legacy, "/f"],
                           capture_output=True, creationflags=_CF)
            return True
        except Exception:
            return False

    def _check_autostart(self):
        """Reflect autostart state, treating a task that points elsewhere as OFF.

        A task registered by a previous install still 'exists' after the exe is
        moved, renamed or reinstalled to another folder — but it fails every
        logon with "file not found". Showing the toggle ON then hides a broken
        autostart, so compare the task's action against the current target and
        re-register when they differ.
        """
        if IS_MAC:
            self._check_autostart_mac()
            return
        had_legacy = self._migrate_legacy_autostart()
        try:
            r = subprocess.run(
                ["schtasks", "/query", "/tn", SERVICE_NAME, "/fo", "list", "/v"],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", creationflags=_CF)
            if r.returncode != 0:
                if had_legacy:
                    # Carry the old "start on boot" choice over to the new name.
                    self._auto_var.set(True)
                    self._toggle_auto()
                return
            # Locale-independent: match the exe path itself, not the field label
            # (a Turkish Windows prints "Görev Yolu", not "Task To Run").
            target = _autostart_target()
            exe = target.split('"')[1] if target.startswith('"') else target
            if exe.lower() in (r.stdout or "").lower():
                self._auto_var.set(True)
            else:
                self._auto_var.set(True)
                self._toggle_auto()   # rewrite the stale task to the real path
        except Exception:
            pass

    def _toggle_auto(self):
        if IS_MAC:
            self._toggle_auto_mac()
            return
        if self._auto_var.get():
            r = subprocess.run([
                "schtasks", "/create", "/tn", SERVICE_NAME,
                "/tr", _autostart_target(),
                "/sc", "onlogon", "/rl", "highest", "/f"
            ], capture_output=True, text=True, creationflags=_CF)
            if r.returncode == 0:
                self._log_queue.put(t("autostart_added", self._lang))
            else:
                self._auto_var.set(False)
                if r.stderr:
                    self._log_queue.put(f"[!] {r.stderr.strip()}")
        else:
            subprocess.run(["schtasks", "/delete", "/tn", SERVICE_NAME, "/f"],
                           capture_output=True, creationflags=_CF)
            self._log_queue.put(t("autostart_removed", self._lang))

    # === Autostart (macOS) ===

    def _check_autostart_mac(self):
        """Reflect the login item, treating one that points elsewhere as off.

        Same rule as the Windows task: an agent left behind by a build that has
        since been moved or reinstalled still exists, and still fails at every
        login. Showing the switch on would hide that, so the stale one is
        rewritten to the path this build actually runs from.
        """
        try:
            with open(_launch_agent_path(), "rb") as f:
                saved = plistlib.load(f).get("ProgramArguments") or []
        except (OSError, ValueError, plistlib.InvalidFileException):
            self._auto_var.set(False)
            return
        self._auto_var.set(True)
        if list(saved) != _autostart_argv_mac():
            self._toggle_auto_mac()

    def _toggle_auto_mac(self):
        path = _launch_agent_path()
        service = "gui/%d/%s" % (os.getuid(), LAUNCH_AGENT_LABEL)
        domain = "gui/%d" % os.getuid()
        if not self._auto_var.get():
            subprocess.run(["launchctl", "bootout", service], capture_output=True)
            try:
                os.remove(path)
            except OSError:
                pass
            self._log_queue.put(t("autostart_removed", self._lang))
            return

        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                plistlib.dump({
                    "Label": LAUNCH_AGENT_LABEL,
                    "ProgramArguments": _autostart_argv_mac(),
                    "RunAtLoad": True,
                    # Aqua only: launchd would otherwise be entitled to start a
                    # windowed app in a session that has no screen to put it on.
                    "LimitLoadToSessionType": "Aqua",
                    "ProcessType": "Interactive",
                }, f)
        except OSError as e:
            self._auto_var.set(False)
            self._log_queue.put(f"[!] {e}")
            return

        # Re-register so the change applies now rather than at the next login.
        # bootout first because bootstrap refuses a label that is already
        # loaded; on a clean system it fails and that is the expected path, so
        # neither result is checked.
        subprocess.run(["launchctl", "bootout", service], capture_output=True)
        subprocess.run(["launchctl", "bootstrap", domain, path],
                       capture_output=True)
        self._log_queue.put(t("autostart_added", self._lang))

    def _save_autostart_engine(self):
        self._settings["autostart_engine"] = self._auto_engine_var.get()
        save_settings(self._settings)

    # === Tray ===

    def _tray_supported(self) -> bool:
        """Is there a place to put an icon the user can actually click?

        This decides whether the window may be hidden at all. Withdrawing it
        with no icon to bring it back leaves the app running, invisible and
        unreachable - and the single-instance lock then refuses a relaunch, so
        the only way out is Force Quit. Never hide without asking this first.
        """
        if IS_MAC:
            try:
                return bool(self.tk.call("info", "commands", "::tk::systray"))
            except tk.TclError:
                return False
        return HAS_TRAY and HAS_PIL

    def _create_tray_mac(self) -> bool:
        """Put an item in the menu bar. True only if one really appeared.

        Tk's aqua systray arrived in Tk 9; the 8.6 build has no such command at
        all, which is why the interpreter is pinned in the macOS workflow. The
        aqua implementation also takes no -menu, only click callbacks, so the
        menu is posted by hand from the right-click one.
        """
        try:
            if HAS_PIL and os.path.exists(self._icon_png):
                # Resample rather than subsample. Tk's subsample() is
                # nearest-neighbour: going from 512 to 22 it keeps one pixel in
                # 23 and discards the other 22, which turns a detailed logo into
                # noise at exactly the size where detail matters most.
                art = Image.open(self._icon_png).convert("RGBA")
                art = art.resize((TRAY_ICON_PX, TRAY_ICON_PX), Image.LANCZOS)
                self._tray_image = ImageTk.PhotoImage(art, master=self)
            else:
                source = tk.PhotoImage(file=self._icon_png, master=self)
                factor = max(1, min(source.width() // TRAY_ICON_PX,
                                    source.height() // TRAY_ICON_PX))
                self._tray_image = source.subsample(factor, factor)
            self.tk.call("tk", "systray", "create",
                         "-image", self._tray_image,
                         "-text", "HenkerDPI",
                         "-button1", self.register(self._restore),
                         "-button3", self.register(self._post_tray_menu))
            return True
        except (tk.TclError, OSError) as e:
            # Never silent: without an icon the window must not be hidden, so
            # this failure changes what closing the window does. Saying why
            # beats leaving someone to wonder where their app went.
            self._tray_image = None
            self._log_queue.put(f"[!] menu bar item: {e}")
            return False

    def _post_tray_menu(self):
        """Build and post the menu-bar menu.

        Built fresh on every right-click rather than kept and updated, so the
        start/stop entry can never disagree with the engine.
        """
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label=t("tray_show", self._lang), command=self._restore)
        menu.add_command(
            label=t("tray_stop" if self._running else "tray_start", self._lang),
            command=self._toggle)
        menu.add_separator()
        menu.add_command(label=t("tray_quit", self._lang), command=self._quit)
        try:
            menu.tk_popup(self.winfo_pointerx(), self.winfo_pointery())
        finally:
            menu.grab_release()

    def _create_tray(self):
        if not HAS_TRAY or not HAS_PIL:
            return None
        img = Image.open(self._icon_png) if os.path.exists(self._icon_png) \
            else Image.new("RGB", (64, 64), (42, 16, 80))
        menu = pystray.Menu(
            pystray.MenuItem(t("tray_show", self._lang),
                             lambda *a: self.after(0, self._restore), default=True),
            pystray.MenuItem(
                lambda i: t("tray_stop", self._lang) if self._running
                else t("tray_start", self._lang),
                lambda *a: self.after(0, self._toggle)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(t("tray_quit", self._lang),
                             lambda *a: self.after(0, self._quit)),
        )
        icon = pystray.Icon("HenkerDPI", img, "HenkerDPI", menu)
        self._hook_balloon_click(icon)
        return icon

    def _hook_balloon_click(self, icon):
        """Make a click on our Windows notification install the update.

        pystray builds its win32 message map out of BOUND methods inside
        Icon.__init__, so replacing icon._on_notify afterwards would never be
        seen — the entry in that map is what has to be wrapped. This is private
        pystray API, so any failure must stay harmless: the notification still
        appears, it just stops being clickable.
        """
        if os.name != "nt":
            return
        try:
            from pystray._util import win32 as _pswin32
            handlers = icon._message_handlers
            original = handlers[_pswin32.WM_NOTIFY]
        except Exception:
            return

        def on_notify(wparam, lparam):
            if lparam == NIN_BALLOONUSERCLICK:
                # Hop to the Tk thread: this runs inside the icon's own window
                # procedure, and the update path stops that very icon.
                self.after(0, self._update_from_notification)
                return
            return original(wparam, lparam)

        try:
            handlers[_pswin32.WM_NOTIFY] = on_notify
        except Exception:
            pass

    def _show_tray(self) -> bool:
        """Raise the icon. Returns whether one is now there to be clicked."""
        if self._tray_icon:
            return True
        if not self._tray_supported():
            return False
        if IS_MAC:
            if not self._create_tray_mac():
                return False
            self._tray_icon = "systray"      # sentinel; Tk owns the real object
            return True
        self._tray_icon = self._create_tray()
        if not self._tray_icon:
            return False
        threading.Thread(target=self._tray_icon.run, daemon=True).start()
        return True

    def _hide_tray(self):
        icon, self._tray_icon = self._tray_icon, None
        if not icon:
            return
        if IS_MAC:
            try:
                self.tk.call("tk", "systray", "destroy")
            except tk.TclError:
                pass
            self._tray_image = None
            return
        icon.stop()

    def _update_tray_menu(self):
        # The macOS menu is built at the moment it is posted, so it is never
        # stale and there is nothing to refresh.
        if self._tray_icon and not IS_MAC:
            self._tray_icon.update_menu()

    def _restore(self):
        self._hide_tray()
        self.deiconify()
        self.lift()
        self.focus_force()

    def _to_background(self):
        """Hide the window, but only once there is an icon to bring it back."""
        if self._show_tray():
            self.withdraw()

    def _on_minimize(self, event=None):
        if self.state() == "iconic" and self._tray_supported():
            self.after(100, self._to_background)

    def _on_close(self):
        # On macOS closing a window is not quitting. Once there is a menu-bar
        # item the app lives there, bypass running or not, and quitting is Cmd-Q
        # or the item's own Quit entry — anything else surprises people, and it
        # surprised the first person to try it. On Windows, closing with the
        # engine off has always meant quit, and that behaviour stays.
        if (IS_MAC or self._running) and self._show_tray():
            self.withdraw()
            return
        if self._running:
            if messagebox.askyesno("HenkerDPI", t("close_confirm", self._lang)):
                self._quit()
        else:
            self._quit()

    def _quit(self):
        engine_thread = self._thread       # _stop() drops the reference
        self._stop()
        self._hide_tray()
        # Let the engine thread put the system back before the interpreter
        # starts freezing daemon threads. stop() only sets an event; on macOS
        # the restore behind it is a privileged call the user still has to
        # approve, and quitting out from under it leaves the Mac pointed at a
        # proxy that no longer exists.
        if engine_thread is not None and engine_thread.is_alive():
            engine_thread.join(timeout=QUIT_JOIN_TIMEOUT)
        self.destroy()


_MUTEX_NAME = "Global\\HenkerDPI_SingleInstance"
_mutex_handle = None


def _release_single_instance():
    """Drop the single-instance mutex so a relaunched build can claim it.

    Called only on the update path: the replacement process starts while this
    one is still alive, and would otherwise bounce off its own guard.
    """
    global _mutex_handle
    h, _mutex_handle = _mutex_handle, None
    if not h:
        return
    if IS_MAC:
        try:
            h.close()               # releases the flock with the descriptor
        except Exception:
            pass
        return
    import ctypes as ct
    try:
        ct.windll.kernel32.ReleaseMutex(h)
        ct.windll.kernel32.CloseHandle(h)
    except Exception:
        pass


def _claim_single_instance_mac(deadline):
    """An exclusive flock on a file in the user's own state directory.

    The lock is released by the kernel when the process dies however it dies,
    so a crashed run cannot lock the user out of their own app.
    """
    global _mutex_handle
    import fcntl
    from config import STATE_DIR
    path = os.path.join(STATE_DIR, "henkerdpi.lock")
    while True:
        handle = open(path, "w")
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            _mutex_handle = handle
            return True
        except OSError:
            handle.close()
            if time.time() >= deadline:
                return False
            time.sleep(0.5)


def main():
    global _mutex_handle

    # Runs inside the built bundle in CI. It has to come before the GUI and the
    # instance guard, because the point is to prove the frozen app can import
    # its own engine on a machine with no display and no user.
    if "--selftest" in sys.argv:
        if IS_MAC:
            from macos.selftest import run
            sys.exit(run())
        print("--selftest is macOS-only")
        sys.exit(0)

    # After an update the outgoing process may still be exiting, so --updated
    # waits for it rather than reporting a false "already running".
    deadline = time.time() + (15 if "--updated" in sys.argv else 0)

    if IS_MAC:
        if not _claim_single_instance_mac(deadline):
            messagebox.showinfo("HenkerDPI", t("already_running"))
            sys.exit(0)
    else:
        import ctypes as ct
        # Global\ so the guard also blocks a second ELEVATED instance in another
        # user session (Fast User Switching) — both would otherwise race the
        # same machine-wide DNS journal. Admin token carries
        # SeCreateGlobalPrivilege.
        while True:
            _mutex_handle = ct.windll.kernel32.CreateMutexW(
                None, True, _MUTEX_NAME)
            if ct.windll.kernel32.GetLastError() != 183:
                break
            if _mutex_handle:
                ct.windll.kernel32.CloseHandle(_mutex_handle)
                _mutex_handle = None
            if time.time() >= deadline:
                messagebox.showinfo("HenkerDPI", t("already_running"))
                sys.exit(0)
            time.sleep(0.5)

    if not is_admin():
        messagebox.showerror("HenkerDPI", t("admin_required"))
        sys.exit(1)

    if not IS_MAC:
        ct.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "Henkerr.HenkerDPI.V2")

    # Heal DNS left pinned by a previous crashed/force-killed run, so a stale
    # 1.1.1.1 override is reverted as soon as the app launches — even if the
    # user never starts the engine this session.
    try:
        restore_dns_from_journal()
    except Exception:
        pass

    app = HenkerDPIApp()
    app.mainloop()


if __name__ == "__main__":
    main()
