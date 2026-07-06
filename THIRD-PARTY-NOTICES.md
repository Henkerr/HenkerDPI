# Third-Party Notices

HenkerDPI V2 is licensed under the MIT License (see `LICENSE`). It bundles and
depends on the following third-party components, whose own licenses apply to
those components.

## WinDivert (bundled in the executable)

The Windows packet-capture/injection driver `WinDivert64.dll` and
`WinDivert64.sys` are embedded, unmodified, inside the distributed executable
(collected at build time via pydivert).

- Project: https://github.com/basil00/Divert
- License: dual-licensed under **LGPL v3** and **GPL v2**.
- Full text: https://github.com/basil00/Divert/blob/master/LICENSE

## pydivert

Python bindings for WinDivert.

- Project: https://github.com/ffalcinelli/pydivert
- License: dual-licensed under **LGPL v3** and **GPL v2**.

## Other Python dependencies

| Component | License | Project |
|-----------|---------|---------|
| customtkinter | MIT | https://github.com/TomSchimansky/CustomTkinter |
| Pillow | MIT-CMU | https://github.com/python-pillow/Pillow |
| pystray | LGPL v3 / GPL v3 | https://github.com/moses-palmer/pystray |

The macOS build additionally uses **scapy** (GPL v2 — https://github.com/secdev/scapy).
