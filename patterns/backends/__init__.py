"""
The targets the IR is compiled for, registered by name.

A backend is a module that defines a `Backend` subclass and registers it with
`@register`. The command line and the tests find it through `get` and `names`,
so adding a target is one module here and one line in the import list at the
bottom of this file. docs/api.md says what else to do (a workflow step, a page).
"""

from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, List, Optional

from patterns.ir import IR


@dataclass
class Decision:
    """
    What a backend did with one rule, recorded where it decided.

    Attributes:
        index: The position of the rule in `ir.rules`.
        emitted: Whether the rule is in the output.
        reason: For a rule that is not, why: a code from `patterns.coverage.REASONS`.
        detail: For a rule that is not, what the reason refers to: the operator,
            the location, the request it matched.
        location: For a rule that is, the location the backend matched it on, in
            the IR's terms (`query-string`, `user-agent`, ...).
        pattern: For a rule that is, the regular expression that was written.
    """

    index: int
    emitted: bool
    reason: Optional[str] = None
    detail: Optional[str] = None
    location: Optional[str] = None
    pattern: Optional[str] = None


@dataclass
class Compiled:
    """The files of a target, and one Decision per rule of the IR, in order."""

    files: Dict[str, str]
    decisions: List[Decision] = field(default_factory=list)


@dataclass(frozen=True)
class Capabilities:
    """
    What a target can express, as data the coverage matrix reads.

    This describes what the backend writes today, not what the target could
    do: ModSecurity can apply a transformation, and the Apache backend does not
    write one. tests/test_coverage.py holds the declarations to the output.

    Attributes:
        dialect: The regular expression dialect the target compiles (`pcre`,
            `re2`). See patterns.dialects.
        operators: The operators the backend writes as that operator, not negated.
        transformations: The transformations the output reproduces.
        case_insensitive: Whether a `(?i)` pattern is matched without regard to
            case in the output.
        locations: For each location the backend matches on, by the lower-case
            name the IR folds it to (`query-string`, `user-agent`, ...), the
            component of the target it becomes and what that leaves out.
        faithful: Maps the regular expression CRS wrote to the one the backend
            should write if it changes nothing that matters, such as removing a
            `(?i)` it handles another way. A different output is a rewrite.
    """

    dialect: str
    operators: FrozenSet[str]
    transformations: FrozenSet[str]
    case_insensitive: bool
    locations: Dict[str, "Target"]
    faithful: Callable[[str], str] = lambda argument: argument


@dataclass(frozen=True)
class Target:
    """
    A request component of a target: what it is called there, and what it does
    not see of some of the variables that fold to it.

    Attributes:
        name: The component in the target's terms.
        note: What the component leaves out.
        partial: The IR variables (by name) the note applies to. A variable the
            component matches exactly is not in it.
    """

    name: str
    note: Optional[str] = None
    partial: FrozenSet[str] = frozenset()


class Backend:
    """
    One target: what it is called and how to turn the IR into its files.

    Attributes:
        name: What `--target` takes, and the directory under the output root.
        title: How the target is named in the header of a generated file.
        capabilities: What the target can express. See `Capabilities`.
    """

    name: str = ""
    title: str = ""
    capabilities: Capabilities = None

    def compile(self, ir: IR) -> Compiled:
        """
        Builds the target's files from the IR, and records what happened to each
        rule. Writes nothing.

        Returns:
            The content of each file by its path relative to the target's
            directory, and a Decision per rule. The same IR gives the same
            result, byte for byte.
        """
        raise NotImplementedError

    def render(self, ir: IR) -> Dict[str, str]:
        """The files `compile` builds, without the record of what happened."""
        return self.compile(ir).files


_REGISTRY: Dict[str, Backend] = {}


def register(cls):
    """Registers a Backend subclass under its name. Use as a class decorator."""
    backend = cls()
    if not backend.name:
        raise ValueError(f"{cls.__name__} has no name")
    if backend.name in _REGISTRY:
        raise ValueError(f"a backend named {backend.name!r} is already registered")
    _REGISTRY[backend.name] = backend
    return cls


def names() -> List[str]:
    """The registered targets, in the order they were registered."""
    return list(_REGISTRY)


def get(name: str) -> Backend:
    """
    Returns the backend registered under `name`.

    Raises:
        KeyError: There is none. The message lists the ones there are.
    """
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"unknown target {name!r}; known targets: {', '.join(names())}") from None


# Importing a module registers its backend. The order is the order `--all` builds in.
from patterns.backends import nginx, apache, traefik, haproxy  # noqa: E402,F401
