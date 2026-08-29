# -*- mode: python ; coding: utf-8 -*-
# On-demand WebView build: the always-on core (app.py) opens the window as a
# second process. In a onefile exe there is no ui.py on disk, so app.py re-runs
# THIS exe with --ui (see app.show_ui / app.main). hook-webview + hook-clr from
# pyinstaller-hooks-contrib bundle pywebview, pythonnet and the WebView2 DLLs.

a = Analysis(
    ['app.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('ui', 'ui'),                 # all 5 theme pages + bridge.js + css + logo
        ('icon.ico', '.'),
        ('icon.png', '.'),
        ('licenses', 'licenses'),
        ('THIRD-PARTY-NOTICES.md', '.'),
        ('LICENSE', '.'),
    ],
    hiddenimports=[
        'ui',                          # imported only inside the --ui branch
        'webview.platforms.edgechromium',
        'webview.platforms.winforms',
        'pystray._win32',
        'clr',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['macos'],               # Windows build: the macOS engine is dead weight
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='HenkerDPI-webview',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon='icon.ico',
    uac_admin=True,
    version='version_info.txt',
)
