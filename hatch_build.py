"""Tags the wheel for the platform its bundled library actually runs on.

The package is pure Python, but it carries a compiled `libcronet.so`, so a
default `py3-none-any` wheel would install anywhere and then fail at the first
import. The tag below is what stops that: pip on macOS, Windows or aarch64
declines the wheel instead of installing a library it cannot load.

`linux_x86_64` rather than one of the `manylinux` tags, because manylinux
promises a wheel that leans on nothing outside its own allowlist, and this one
links the system's GLib and NSS. Claiming manylinux would make the wheel
uploadable to PyPI and wrong; this tag is honest and installs from a file, a
URL, or a release asset.
"""

from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

# What scripts/build_native.sh produces, and the only platform native/ is built
# for. A build for another platform changes this line together with the library.
WHEEL_TAG = "py3-none-linux_x86_64"


class CustomBuildHook(BuildHookInterface[Any]):
    """Marks the wheel as platform-specific rather than pure Python."""

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        """Set the wheel's tag before hatchling names the file.

        Args:
            version: The build version hatchling is running for.
            build_data: Hatchling's mutable build description.
        """
        build_data["pure_python"] = False
        build_data["tag"] = WHEEL_TAG
