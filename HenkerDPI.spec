# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['gui.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('icon.ico', '.'),
        ('icon.png', '.'),
        # LGPL v3 requires the license text to travel with the binary that
        # embeds WinDivert/pystray — a link in the repo is not sufficient.
        ('licenses', 'licenses'),
        ('THIRD-PARTY-NOTICES.md', '.'),
        ('LICENSE', '.'),
    ],
    hiddenimports=[
        'pystray._win32',
        'customtkinter',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='HenkerDPI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon='icon.ico',
    uac_admin=True,
    version='version_info.txt',
)
