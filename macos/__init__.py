"""macOS-specific half of HenkerDPI.

Everything in this package is code that genuinely differs on macOS. The shared
logic — settings, categories, translations, ClientHello parsing, the bypass
scope decision, DoH — is imported from the repository root, never copied. An
earlier attempt at a macOS port duplicated those modules into this directory and
the duplicate was seventeen commits stale by the time it was abandoned; that is
the mistake this package exists to avoid repeating.
"""
