# -*- mode: python ; coding: utf-8 -*-
# Standalone diagnostic: measures which desync strategy beats the user's ISP and
# writes a report to their Desktop. Console app, admin-manifested (WinDivert).
# Paths are relative to this file, so it lives next to HenkerDPI.spec.

a = Analysis(
    ['tools/teshis.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('licenses', 'licenses'),
        ('THIRD-PARTY-NOTICES.md', '.'),
        ('LICENSE', '.'),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['customtkinter', 'pystray', 'PIL'],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='HenkerDPI-Teshis',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    icon='icon.ico',
    uac_admin=True,
)
