#!/usr/bin/env python3
"""Generate the ctypes ABI module from native/cronet.h.

The C header is the one description of the ABI. Transcribing it into ctypes by
hand — six structs, field by field, in order — is the kind of work that looks
finished long before it is correct: a field of the wrong width, or two swapped,
does not raise. It makes every later read land at the wrong offset and corrupt
quietly, which is exactly the failure the header warns about.

So the transcription is done here instead, and `src/cronet/_abi.py` is its
output. Running this after touching the header is not optional bookkeeping;
`tests/test_abi_is_generated.py` regenerates and compares, so a header that has
moved without its binding fails the test gate rather than shipping.

    scripts/generate_binding.py            # write src/cronet/_abi.py
    scripts/generate_binding.py --check    # exit 1 if it is out of date

`--header` and `--output` exist for that test rather than for daily use: they
let it generate from a deliberately broken copy of the header, in a temporary
directory, and check that the generator refuses it.

Anything in the header this does not understand is an error, never a silent
omission — a binding missing a field is the bug this exists to prevent.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
HEADER = PROJECT_ROOT / "native" / "cronet.h"
OUTPUT = PROJECT_ROOT / "src" / "cronet" / "_abi.py"

# C spellings that map straight onto a ctypes primitive. A pointer to a struct
# is resolved against the structs found in the header, and anything left over
# stops the generator rather than being guessed at.
PRIMITIVES = {
    "void": "None",
    "int": "ctypes.c_int",
    "int32_t": "ctypes.c_int32",
    "int64_t": "ctypes.c_int64",
    "size_t": "ctypes.c_size_t",
    "char *": "ctypes.c_char_p",
    "uint8_t *": "ctypes.POINTER(ctypes.c_ubyte)",
}

# Constants worth republishing; the include guard and the visibility macro are
# not part of the ABI.
SKIPPED_DEFINES = frozenset({"CRONET_H_", "CRONET_EXPORT"})


class HeaderError(Exception):
    """The header contains something this generator will not guess at."""


def strip_comments(source: str) -> str:
    """`source` with C block and line comments removed."""
    without_blocks = re.sub(r"/\*.*?\*/", " ", source, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", without_blocks)


def normalize_type(spelling: str) -> str:
    """A C type as a canonical string: no const, one space before each star."""
    spaced = spelling.replace("*", " * ")
    words = [word for word in spaced.split() if word != "const"]
    joined = " ".join(words)
    # "cronet_header *" rather than "cronet_header  *" or "cronet_header*".
    return re.sub(r"\s+", " ", joined).strip()


def split_declarator(declaration: str) -> tuple[str, str]:
    """A declaration as its type and its name.

    Args:
        declaration: One declarator, without its semicolon, such as
            "const cronet_header* headers".

    Returns:
        The normalized type and the declared name.

    Raises:
        HeaderError: The declaration has no name to bind.
    """
    words = normalize_type(declaration).split()
    if len(words) < 2:
        raise HeaderError(f"cannot read a name out of {declaration!r}")
    return " ".join(words[:-1]), words[-1]


def pascal_case(c_name: str) -> str:
    """`cronet_engine_config` as `CronetEngineConfig`."""
    return "".join(part.title() for part in c_name.split("_"))


class Abi:
    """Everything the header declares, in the order it declares it."""

    def __init__(self) -> None:
        self.constants: list[tuple[str, int]] = []
        self.enum_members: list[tuple[str, int]] = []
        self.opaque: list[str] = []
        self.structs: list[tuple[str, list[tuple[str, str]]]] = []
        self.functions: list[tuple[str, str, list[str]]] = []

    @property
    def struct_names(self) -> set[str]:
        return {name for name, _ in self.structs}

    def ctypes_for(self, c_type: str) -> str:
        """The ctypes spelling of a C type used in this header.

        Raises:
            HeaderError: The type is not one the generator maps.
        """
        if c_type in PRIMITIVES:
            return PRIMITIVES[c_type]
        pointee = c_type.removesuffix(" *").strip()
        if c_type.endswith("*"):
            # An opaque handle has no layout to describe, so it crosses as a
            # bare address; a struct the header defines crosses as a pointer to
            # the class generated for it.
            if pointee in self.opaque:
                return "ctypes.c_void_p"
            if pointee in self.struct_names:
                return f"ctypes.POINTER({pascal_case(pointee)})"
        elif c_type in self.struct_names:
            return pascal_case(c_type)
        raise HeaderError(
            f"no ctypes mapping for {c_type!r}; add it to PRIMITIVES or declare "
            "the struct in the header before it is used"
        )


def parse(source: str) -> Abi:
    """Read the ABI out of the header text.

    Raises:
        HeaderError: A declaration is malformed, or an exported function was
            not recognised — the generator refuses to emit a partial binding.
    """
    directives = strip_comments(source)
    abi = Abi()

    for name, value in re.findall(
        r"#define\s+(CRONET_\w+)\s+(\(?-?\d+\)?)", directives
    ):
        if name in SKIPPED_DEFINES:
            continue
        abi.constants.append((name.removeprefix("CRONET_"), int(value.strip("()"))))

    # The declarations are read from the header with its preprocessor lines
    # taken out, so that `#define CRONET_EXPORT ...` cannot be mistaken for the
    # start of an exported function.
    text = re.sub(r"^[ \t]*#.*$", "", directives, flags=re.MULTILINE)

    for name in re.findall(r"typedef\s+struct\s+(cronet_\w+)\s+\1\s*;", text):
        abi.opaque.append(name)

    for body, _name in re.findall(
        r"typedef\s+enum\s*\{(.*?)\}\s*(cronet_\w+)\s*;", text, flags=re.DOTALL
    ):
        for member, value in re.findall(r"(CRONET_\w+)\s*=\s*(-?\d+)", body):
            abi.enum_members.append((member.removeprefix("CRONET_"), int(value)))

    for body, name in re.findall(
        r"typedef\s+struct\s*\{(.*?)\}\s*(cronet_\w+)\s*;", text, flags=re.DOTALL
    ):
        fields = [
            split_declarator(field)[::-1]
            for field in (part.strip() for part in body.split(";"))
            if field
        ]
        abi.structs.append((name, [(n, t) for n, t in fields]))

    exported = re.findall(r"CRONET_EXPORT\s+(.*?)\s*;", text, flags=re.DOTALL)
    for declaration in exported:
        match = re.fullmatch(
            r"(?P<returns>.+?)\s*\b(?P<name>cronet_\w+)\s*\((?P<args>.*)\)",
            declaration,
            flags=re.DOTALL,
        )
        if not match:
            raise HeaderError(f"cannot read the exported declaration {declaration!r}")
        raw_args = match["args"].strip()
        arguments = (
            []
            if normalize_type(raw_args) == "void"
            else [split_declarator(arg)[0] for arg in raw_args.split(",")]
        )
        abi.functions.append(
            (match["name"], normalize_type(match["returns"]), arguments)
        )

    if not abi.functions:
        raise HeaderError("the header declared no exported functions")
    return abi


def render(abi: Abi) -> str:
    """The ABI as the source of `src/cronet/_abi.py`."""
    lines = [
        '"""The C ABI of libcronet.so, as ctypes declarations.',
        "",
        "Generated from native/cronet.h by scripts/generate_binding.py.",
        "Do not edit: change the header and regenerate, or the two descriptions",
        "of one ABI drift apart and every read lands at the wrong offset.",
        '"""',
        "",
        "import ctypes",
        "",
    ]

    for name, value in abi.constants:
        lines.append(f"{name} = {value}")
    lines.append("")
    for name, value in abi.enum_members:
        lines.append(f"{name} = {value}")
    lines.append("")

    for name, fields in abi.structs:
        lines += ["", f"class {pascal_case(name)}(ctypes.Structure):"]
        lines.append(f'    """Mirrors `{name}`."""')
        lines.append("")
        lines.append("    _fields_ = [")
        for field_name, field_type in fields:
            lines.append(f'        ("{field_name}", {abi.ctypes_for(field_type)}),')
        lines.append("    ]")
        lines.append("")

    lines += [
        "",
        "def bind(library: ctypes.CDLL) -> None:",
        '    """Apply every signature in this ABI to `library`.',
        "",
        "    ctypes defaults to guessing an int return and unchecked arguments,",
        # Counted rather than written out, because a number in prose beside a
        # generated list is one that goes stale the first time the list grows.
        f"    which on a 64-bit pointer truncates silently. Declaring all "
        f"{len(abi.functions)}",
        "    is what makes a wrong call fail loudly at the boundary.",
        '    """',
    ]
    for name, returns, arguments in abi.functions:
        mapped = [abi.ctypes_for(argument) for argument in arguments]
        lines.append(f"    library.{name}.restype = {abi.ctypes_for(returns)}")
        lines.append(f"    library.{name}.argtypes = [{', '.join(mapped)}]")

    lines += [
        "",
        "",
        "#: Every function this ABI declares, for checking the library has them.",
        "FUNCTIONS = (",
    ]
    for name, _returns, _arguments in abi.functions:
        lines.append(f'    "{name}",')
    lines.append(")")
    return "\n".join(lines) + "\n"


def ruff_format(source: str, filename: Path) -> str:
    """`source` as the project's formatter would write it.

    Emitting anything else would leave the generator and `ruff format` undoing
    each other's work for ever, and the staleness check calling it drift.

    Raises:
        HeaderError: ruff is not installed, so the output cannot be normalised.
    """
    executable = Path(sys.executable).parent / "ruff"
    try:
        finished = subprocess.run(
            [
                str(executable) if executable.exists() else "ruff",
                "format",
                "--stdin-filename",
                str(filename),
                "-",
            ],
            input=source,
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as failure:
        raise HeaderError(
            f"could not run ruff to format the generated binding: {failure}"
        ) from failure
    return finished.stdout


def generate(header: Path, output: Path) -> str:
    """The source `output` should contain, given `header`."""
    return ruff_format(render(parse(header.read_text(encoding="utf-8"))), output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit non-zero if the committed binding is stale",
    )
    parser.add_argument(
        "--header", type=Path, default=HEADER, help="the C header to read"
    )
    parser.add_argument(
        "--output", type=Path, default=OUTPUT, help="the module to write"
    )
    arguments = parser.parse_args()

    generated = generate(arguments.header, arguments.output)
    if arguments.check:
        current = (
            arguments.output.read_text(encoding="utf-8")
            if arguments.output.exists()
            else ""
        )
        if current == generated:
            return 0
        print(
            f"{arguments.output} is out of date with {arguments.header}. "
            "Run scripts/generate_binding.py.",
            file=sys.stderr,
        )
        return 1

    abi = parse(arguments.header.read_text(encoding="utf-8"))
    arguments.output.write_text(generated, encoding="utf-8")
    print(
        f"Wrote {arguments.output}: {len(abi.functions)} functions, "
        f"{len(abi.structs)} structs, "
        f"{len(abi.constants) + len(abi.enum_members)} constants."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
