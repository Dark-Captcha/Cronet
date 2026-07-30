"""Loading libcronet.so, and proving it is the library this package speaks to.

The declarations themselves are not written here. They are generated into
`_abi` from native/cronet.h by scripts/generate_binding.py, because a hand-kept
second copy of an ABI is a copy that eventually disagrees with the first — and
a struct read at the wrong offset corrupts silently instead of failing.

What is left here is the policy around loading: where the library is, that it
exports everything the header promised, and that its ABI version is the one
these declarations describe. All three are checked once, at import, so a
mismatched library says so immediately rather than misbehaving later.

The library is loaded with ctypes.CDLL, which releases the GIL for the duration
of every call — that is what lets a blocking request run without stopping the
rest of the interpreter, on both the usual build of Python and the
free-threaded one.
"""

import ctypes
import os
import sys
from pathlib import Path

from . import _abi


def _library_path() -> Path:
    """Where libcronet.so lives.

    The shipped library sits beside this file; CRONET_LIBRARY overrides that,
    which is what a build tree uses before anything is installed.
    """
    override = os.environ.get("CRONET_LIBRARY")
    if override:
        return Path(override)
    return Path(__file__).resolve().parent / "libcronet.so"


def _why_it_would_not_load(path: Path, failure: OSError) -> str:
    """A diagnosis for a library that is present but will not load.

    Two causes account for nearly every occurrence, and the loader's own message
    names neither: the wheel was installed somewhere its Linux x86-64 library
    cannot run, or the system is missing the shared libraries it links.

    Args:
        path: Where the library was loaded from.
        failure: What the dynamic loader reported.

    Returns:
        The message to raise, with the loader's own text kept at the end.
    """
    platform = f"{sys.platform}, {os.uname().machine}"
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        return (
            f"{path} is a Linux x86-64 shared library, but this is {platform}. "
            "Only Linux x86-64 is shipped; there is no build for this platform."
        )
    return (
        f"{path} could not be loaded on {platform}: {failure}. It links the "
        "system's GLib and NSS, which a slim image often lacks — install "
        "libglib2.0-0 and libnss3 (Debian, Ubuntu) or glib2 and nss (Arch, "
        "Fedora)."
    )


def _load() -> ctypes.CDLL:
    """The library, with every signature applied and its exports checked."""
    path = _library_path()
    if not path.exists():
        raise ImportError(
            f"libcronet.so was not found at {path}. Build it with "
            "scripts/build_native.sh, or point CRONET_LIBRARY at a copy."
        )
    try:
        library = ctypes.CDLL(str(path))
    except OSError as failure:
        raise ImportError(_why_it_would_not_load(path, failure)) from failure
    missing = [name for name in _abi.FUNCTIONS if not hasattr(library, name)]
    if missing:
        raise ImportError(
            f"{path} does not export {', '.join(missing)}, which native/cronet.h "
            "declares. The library was built from a different header; rebuild it "
            "with scripts/build_native.sh."
        )
    _abi.bind(library)
    return library


lib = _load()

# The declarations above describe one memory layout. A library built to a
# different one does not fail on the first call — it reads every field at the
# wrong offset and corrupts quietly, so the version is checked before anything
# is read through it.
_built_abi: int = lib.cronet_abi_version()
if _built_abi != _abi.ABI_VERSION:
    raise ImportError(
        f"{_library_path()} was built for ABI version {_built_abi}, but this "
        f"package speaks version {_abi.ABI_VERSION}. Rebuild the library with "
        "scripts/build_native.sh."
    )


def version() -> str:
    """The Chromium version the library was built from."""
    raw: bytes = lib.cronet_version()
    return raw.decode()


def last_error() -> str:
    """Why the last call on this thread failed."""
    raw: bytes = lib.cronet_last_error()
    return raw.decode(errors="replace")
