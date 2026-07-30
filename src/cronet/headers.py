"""An ordered, case-insensitive view of HTTP headers.

Order is kept because it is part of what this package exists to control: the
sequence a server sees is as much a fingerprint as the values themselves. Names
match without regard to case, as HTTP requires, and a name may appear more than
once.
"""

from collections.abc import Iterable, Iterator, Mapping


class Headers(Mapping[str, str]):
    """Headers in the order they were sent or received.

    Indexing returns the value; where a name appears more than once the values
    are joined with ", ", as HTTP defines for repeated fields. Use `get_list`
    to see them separately, and `items` to walk every pair in wire order.
    """

    __slots__ = ("_pairs",)

    def __init__(
        self,
        headers: Mapping[str, str] | Iterable[tuple[str, str]] | None = None,
    ) -> None:
        pairs: list[tuple[str, str]] = []
        if headers is not None:
            source = headers.items() if isinstance(headers, Mapping) else headers
            for name, value in source:
                pairs.append((str(name), str(value)))
        self._pairs: tuple[tuple[str, str], ...] = tuple(pairs)

    def __getitem__(self, name: str) -> str:
        values = self.get_list(name)
        if not values:
            raise KeyError(name)
        return ", ".join(values)

    def __iter__(self) -> Iterator[str]:
        seen: set[str] = set()
        for name, _ in self._pairs:
            folded = name.lower()
            if folded not in seen:
                seen.add(folded)
                yield name

    def __len__(self) -> int:
        return len({name.lower() for name, _ in self._pairs})

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, str):
            return False
        folded = name.lower()
        return any(existing.lower() == folded for existing, _ in self._pairs)

    def get_list(self, name: str) -> list[str]:
        """Every value sent under `name`, in order."""
        folded = name.lower()
        return [value for existing, value in self._pairs if existing.lower() == folded]

    # Mapping.items() promises a view of distinct keys, which is exactly what
    # this class exists not to be: a repeated name has to survive as two pairs,
    # in the position each was sent. Widening the return type is the deliberate
    # part — the narrower promise would lose the ordering this package controls.
    def items(self) -> tuple[tuple[str, str], ...]:  # type: ignore[override]
        """Every pair, in wire order, repeats included."""
        return self._pairs

    def with_defaults(self, defaults: Headers) -> Headers:
        """These headers laid over `defaults`.

        A name present in both keeps the position it holds in `defaults` and
        takes the value from `self`, which is how Chromium's own request
        headers behave — so the order a session establishes is not disturbed by
        overriding one value on a single request.
        """
        own = {name.lower() for name, _ in self._pairs}
        emitted: set[str] = set()
        result: list[tuple[str, str]] = []
        for name, value in defaults.items():
            folded = name.lower()
            if folded not in own:
                result.append((name, value))
            elif folded not in emitted:
                emitted.add(folded)
                result.extend(p for p in self._pairs if p[0].lower() == folded)
        result.extend(p for p in self._pairs if p[0].lower() not in emitted)
        return Headers(result)

    def __repr__(self) -> str:
        return f"Headers({list(self._pairs)!r})"
