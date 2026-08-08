# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the macOS bundle.

Deliberately NOT --onefile. A onefile build unpacks to a fresh temporary
directory on every launch, and macOS asks for microphone/network consent and
signs Gatekeeper decisions per binary path — so a onefile app re-prompts, and
its ad-hoc signature covers a stub rather than the code that actually runs.
A .app directory signs and launches predictably.
"""

block_cipher = None

a = Analysis(
    ['gui.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('icon.png', '.'),
        ('licenses', 'licenses'),
        ('THIRD-PARTY-NOTICES.md', '.'),
        ('LICENSE', '.'),
    ],
    hiddenimports=[
        'customtkinter',
        # The macOS engine is reached through a runtime sys.platform branch in
        # gui.py, so PyInstaller's static analysis never sees these imports.
        'macos.engine',
        'macos.proxy',
        'macos.desync',
        'macos.sysproxy',
        'macos.autotune_mac',
        'dnsq',
        'tunecache',
        'sni',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # pydivert is Windows-only and would abort the build if collected; the
    # macOS engine never imports it.
    excludes=['pydivert', 'main', 'doh', 'autotune', 'strategies'],
    noarchive=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='HenkerDPI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    name='HenkerDPI',
)

app = BUNDLE(
    coll,
    name='HenkerDPI.app',
    icon='icon.icns',
    bundle_identifier='com.henkerr.henkerdpi',
    info_plist={
        'CFBundleName': 'HenkerDPI',
        'CFBundleDisplayName': 'HenkerDPI',
        'CFBundleShortVersionString': '2.7.0',
        'CFBundleVersion': '2.7.0',
        'NSHighResolutionCapable': True,
        # Tkinter is not a background-only app; without this the window can
        # open behind everything else with no Dock icon to click.
        'LSUIElement': False,
        'LSMinimumSystemVersion': '11.0',
        'NSHumanReadableCopyright': 'MIT licensed',
    },
)
