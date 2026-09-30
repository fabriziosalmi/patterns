"""
Patterns: the OWASP Core Rule Set, compiled for web servers.

`owasp2json.py` reads the CRS into the IR (docs/ir.md). Everything here goes
from the IR to a server's configuration:

    patterns.ir        loads the IR and checks it against its schema
    patterns.backends  one module per target, registered by name
    patterns.cli       `python3 -m patterns build --target nginx`
"""
