"""Locates the bundled native library for the running platform.

The package ships one wheel for all platforms, with the cdylib for each
platform under ``natives/<os>-<arch>/`` (the same layout the JVM bindings use
inside their jar). The uniffi-generated modules are patched at build time to
resolve the library through :func:`native_library_dir` instead of the package
root.
"""

from __future__ import annotations

import os
import platform
import sys

_ARCH_ALIASES = {
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "amd64": "x86-64",
    "x86_64": "x86-64",
}


def _os_token() -> str:
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform.startswith("win"):
        return "win32"
    if sys.platform.startswith("linux"):
        return "linux"
    raise RuntimeError(f"cloudformation-validate has no native library for operating system {sys.platform!r}")


def _arch_token() -> str:
    machine = platform.machine().lower()
    try:
        return _ARCH_ALIASES[machine]
    except KeyError:
        raise RuntimeError(f"cloudformation-validate has no native library for architecture {machine!r}") from None


def native_library_dir() -> str:
    """Returns the directory containing the native library for this platform.

    Raises:
        RuntimeError: if the wheel does not bundle a library for this platform.
    """
    natives_root = os.path.join(os.path.dirname(__file__), "natives")
    lib_dir = os.path.join(natives_root, f"{_os_token()}-{_arch_token()}")
    if not os.path.isdir(lib_dir):
        try:
            bundled = sorted(entry for entry in os.listdir(natives_root))
        except OSError:
            bundled = []
        raise RuntimeError(
            f"cloudformation-validate has no native library for {_os_token()}-{_arch_token()} "
            f"(bundled platforms: {', '.join(bundled) if bundled else 'none'})"
        )
    return lib_dir
