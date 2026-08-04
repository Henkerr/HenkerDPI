# Third-Party Notices

HenkerDPI is licensed under the MIT License (see `LICENSE`). It bundles and
depends on the following third-party components, whose own licenses apply to
those components.

## WinDivert (bundled in the executable)

The Windows packet-capture/injection driver `WinDivert64.dll` and
`WinDivert64.sys` are embedded, unmodified, inside the distributed executable
(collected at build time via pydivert).

- Project: https://github.com/basil00/Divert
- License: dual-licensed under **LGPL v3** and **GPL v2**.
- Full text: [`licenses/LGPL-3.0.txt`](licenses/LGPL-3.0.txt) and
  [`licenses/GPL-2.0.txt`](licenses/GPL-2.0.txt), also shipped inside the
  executable under `licenses/`.

WinDivert is used unmodified, as a dynamically loaded library (`WinDivert64.dll`),
via pydivert's ctypes bindings. As required by LGPL v3 §4, you may replace it with
a modified version: extract the onefile executable (or build from source with
`pip install -r requirements.txt -r requirements-build.txt` and
`python -m PyInstaller HenkerDPI.spec`) and substitute your own
`WinDivert64.dll` / `WinDivert64.sys`. HenkerDPI's own source is MIT and published
in full at https://github.com/Henkerr/HenkerDPI-V2, so relinking is unrestricted.

## pydivert

Python bindings for WinDivert.

- Project: https://github.com/ffalcinelli/pydivert
- License: dual-licensed under **LGPL v3** and **GPL v2**.
- Full text: [`licenses/LGPL-3.0.txt`](licenses/LGPL-3.0.txt) and
  [`licenses/GPL-2.0.txt`](licenses/GPL-2.0.txt).

## Other Python dependencies

| Component | License | Project |
|-----------|---------|---------|
| customtkinter | MIT | https://github.com/TomSchimansky/CustomTkinter |
| Pillow | MIT-CMU | https://github.com/python-pillow/Pillow |
| pystray | LGPL v3 / GPL v3 | https://github.com/moses-palmer/pystray |

pystray is used unmodified and imported as a normal Python package; its LGPL v3 /
GPL v3 texts are in [`licenses/LGPL-3.0.txt`](licenses/LGPL-3.0.txt) and
[`licenses/GPL-3.0.txt`](licenses/GPL-3.0.txt).

The experimental macOS port (branch `macos-experimental`) additionally uses
**scapy** (GPL v2 — https://github.com/secdev/scapy).
