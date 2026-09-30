"""
The targets the IR is compiled for, registered by name.

A backend is a module that defines a `Backend` subclass and registers it with
`@register`. The command line and the tests find it through `get` and `names`,
so adding a target is one module here and one line in the import list at the
bottom of this file. docs/api.md says what else to do (a workflow step, a page).
"""

from typing import Dict, List

from patterns.ir import IR


class Backend:
    """
    One target: what it is called and how to turn the IR into its files.

    Attributes:
        name: What `--target` takes, and the directory under the output root.
        title: How the target is named in the header of a generated file.
    """

    name: str = ""
    title: str = ""

    def render(self, ir: IR) -> Dict[str, str]:
        """
        Builds the target's files from the IR. Writes nothing.

        Returns:
            The content of each file by its path relative to the target's
            directory. The same IR gives the same content, byte for byte.
        """
        raise NotImplementedError


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
