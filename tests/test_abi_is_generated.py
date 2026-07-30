"""The ctypes ABI must be what native/cronet.h currently says.

`src/cronet/_abi.py` is generated from the header. Nothing stops someone
editing the header and not regenerating, and the consequence is the worst kind:
a struct whose fields no longer line up is not a crash, it is every later read
landing at the wrong offset. So the check is mechanical and runs with the
tests — the header and its binding cannot disagree and still be green.
"""

import subprocess
import sys
from pathlib import Path

import pytest

from cronet import _abi, _binding

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GENERATOR = PROJECT_ROOT / "scripts" / "generate_binding.py"


def test_the_committed_binding_matches_the_header() -> None:
    finished = subprocess.run(
        [sys.executable, str(GENERATOR), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert finished.returncode == 0, (
        f"src/cronet/_abi.py is stale.\n{finished.stderr}"
        "Run scripts/generate_binding.py and commit the result."
    )


def _generate(header: Path, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(GENERATOR),
            "--header",
            str(header),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_a_changed_header_is_caught(tmp_path: Path) -> None:
    # The claim the whole gate rests on: edit the header, and the committed
    # binding stops matching. A gate that cannot fail proves nothing.
    header = tmp_path / "cronet.h"
    header.write_text(
        (PROJECT_ROOT / "native" / "cronet.h")
        .read_text(encoding="utf-8")
        .replace("int32_t status_code;", "int32_t status_code;\n  int32_t added;"),
        encoding="utf-8",
    )
    output = tmp_path / "_abi.py"

    assert _generate(header, output).returncode == 0
    assert '("added", ctypes.c_int32)' in output.read_text(encoding="utf-8")

    stale = subprocess.run(
        [sys.executable, str(GENERATOR), "--check", "--header", str(header)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert stale.returncode == 1, "a changed header must fail the check"
    assert "out of date" in stale.stderr


def test_generating_twice_gives_the_same_bytes(tmp_path: Path) -> None:
    # Nondeterministic output would make the staleness check flake, which
    # teaches people to ignore it.
    first, second = tmp_path / "a.py", tmp_path / "b.py"
    header = PROJECT_ROOT / "native" / "cronet.h"

    assert _generate(header, first).returncode == 0
    assert _generate(header, second).returncode == 0

    assert first.read_text(encoding="utf-8") == second.read_text(encoding="utf-8")


def test_the_generator_refuses_a_type_it_does_not_know(tmp_path: Path) -> None:
    # Silently skipping an unmapped field is the exact failure this generator
    # exists to prevent, so it must stop instead.
    header = tmp_path / "cronet.h"
    header.write_text(
        (PROJECT_ROOT / "native" / "cronet.h")
        .read_text(encoding="utf-8")
        .replace("int32_t status_code;", "long double status_code;"),
        encoding="utf-8",
    )

    finished = _generate(header, tmp_path / "_abi.py")

    assert finished.returncode != 0
    assert "no ctypes mapping" in finished.stderr


def test_the_library_exports_every_function_the_header_declares() -> None:
    missing = [name for name in _abi.FUNCTIONS if not hasattr(_binding.lib, name)]

    assert not missing, f"libcronet.so is missing {missing}"


def test_every_declared_function_has_its_signature_applied() -> None:
    # Left unset, ctypes guesses an int return, which truncates a 64-bit
    # pointer silently. Every function the header declares must be pinned.
    unset = [
        name for name in _abi.FUNCTIONS if getattr(_binding.lib, name).argtypes is None
    ]

    assert not unset, f"these have no argtypes: {unset}"


def test_the_abi_version_is_the_headers() -> None:
    header = (PROJECT_ROOT / "native" / "cronet.h").read_text(encoding="utf-8")
    declared = next(
        int(line.split()[-1])
        for line in header.splitlines()
        if line.startswith("#define CRONET_ABI_VERSION")
    )

    assert declared == _abi.ABI_VERSION
    assert _binding.lib.cronet_abi_version() == declared, (
        "the bundled libcronet.so was built from a different header"
    )


@pytest.mark.parametrize(
    ("struct", "size"),
    [
        ("CronetHeader", 16),
        ("CronetQuicHint", 16),
        ("CronetEngineConfig", 104),
        ("CronetRequest", 64),
        ("CronetMetrics", 112),
        # 192 since ABI 3: the body left the struct and is streamed instead.
        ("CronetResponse", 192),
    ],
)
def test_struct_layouts_are_what_the_library_was_built_against(
    struct: str, size: int
) -> None:
    # Measured against the shipped library on x86-64. A change here means the
    # ABI version must be bumped, because an old library and a new package
    # would otherwise read each other's fields at the wrong offsets.
    import ctypes

    assert ctypes.sizeof(getattr(_abi, struct)) == size, (
        f"{struct} changed shape; bump CRONET_ABI_VERSION in native/cronet.h"
    )
