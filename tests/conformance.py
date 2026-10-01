"""
What the conformance tests share: traffic, a running server, and a verdict.

`test_nginx_blocking.py` started nginx, sent `patterns/corpus.py` through it and
counted. That is how it found that the nginx output loaded and blocked nothing
(#44). The other three targets had a check that their files were well formed, or
none, and so shipped configuration that their server refuses to load (#55). This
is the part of that test that does not depend on nginx, so each target's test
can do the same with its own server.

A test has three phases, and what each proves is different:

  load     the real server reads the generated configuration. Until it does,
           nothing below it means anything.
  benign   no ordinary request is refused. An invariant: a rule that refuses
           ordinary traffic is an outage.
  attacks  how many attacks are refused, in clear and percent-encoded, against a
           floor. A floor rather than an exact figure, because CRS changes
           upstream every few weeks and the daily workflow regenerates from it.

What a target does today is written down next to its test as `EXPECTED`, with the
issue that tracks it, and the test passes when the target does exactly that. A
known defect does not turn CI red, and does not go unnoticed either: when it is
fixed the test fails and says to update the expectation. That is what makes the
test honest about a target that cannot load yet, and strict about one that can.
"""

import http.client
import shutil
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from patterns.corpus import ATTACKS, BENIGN, wanted_user_agents  # noqa: E402


def in_clear(entry: Dict[str, str]) -> Dict[str, str]:
    """
    The same attack with nothing hidden: what is sent when there is no reason
    to encode. Control characters stay encoded because they cannot travel in a
    request line, and `&` and `#` stay encoded because decoding them would
    change the request rather than the payload.
    """
    decoded = urllib.parse.unquote(entry["args"])
    decoded = decoded.replace(" ", "+").replace("&", "%26").replace("#", "%23")
    decoded = "".join(c if c.isprintable() else "%%%02X" % ord(c) for c in decoded)
    return dict(entry, args=decoded,
                request_uri=f"{entry['path']}?{decoded}" if decoded else entry["path"])


def send(port: int, entry: Dict[str, str], refused: int = 403) -> int:
    """Sends one corpus entry to 127.0.0.1:port and returns the status code."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Host": entry["host"]}
    if entry["user_agent"]:
        headers["User-Agent"] = entry["user_agent"]
    if entry["referer"]:
        headers["Referer"] = entry["referer"]
    if entry["content_type"]:
        headers["Content-Type"] = entry["content_type"]
    body = entry.get("body") or None
    try:
        connection.request(entry.get("method") or "GET", entry["request_uri"],
                           body=body.encode("utf-8") if body else None, headers=headers)
        return connection.getresponse().status
    finally:
        connection.close()


@dataclass
class Traffic:
    """What a running server did with the corpus."""

    benign_refused: List[str] = field(default_factory=list)
    caught_clear: List[str] = field(default_factory=list)
    caught_encoded: List[str] = field(default_factory=list)
    benign_errors: List[str] = field(default_factory=list)


def measure(port: int) -> Traffic:
    """
    Sends the whole corpus and counts what was refused (403).

    A request that gets a server error is not counted as refused, and is named in
    `benign_errors` when it was an ordinary one: a server that fails on ordinary
    traffic is not one that let it through.
    """
    traffic = Traffic()
    for entry in BENIGN:
        status = send(port, entry)
        if status == 403:
            traffic.benign_refused.append(entry["name"])
        elif status >= 500:
            traffic.benign_errors.append(f"{entry['name']} ({status})")
    traffic.caught_encoded = [e["name"] for e in ATTACKS if send(port, e) == 403]
    traffic.caught_clear = [e["name"] for e in ATTACKS if send(port, in_clear(e)) == 403]
    return traffic


# Agents a bad-bot list is meant to refuse. They are in the public lists it is written
# from, and no ordinary client sends them. If one of these is ever let through, the list
# has been emptied rather than narrowed.
BAD_BOTS = ("sqlmap/1.8#stable", "AhrefsBot/7.0", "SemrushBot/7", "MJ12bot/v1.4.8")


def user_agent_request(user_agent: str, path: str) -> Dict[str, str]:
    """A request that is nothing but a User-Agent, for a list that reads only that."""
    return {"host": "example.com", "user_agent": user_agent, "referer": "", "content_type": "",
            "request_uri": path, "method": "GET", "body": ""}


def report_bots(check: "Checker", refuses: Callable[[str], bool]) -> None:
    """
    Asserts what a bad-bot list does to a running server, which is three things.

    It refuses a scanner and the bots it is made of: a list that refuses nothing is
    not narrowed, it is gone. It refuses no client a site wants: a browser, a search
    engine, a link preview, a monitor (#78). And it refuses the HTTP libraries, which is
    what the list is for and is said so in docs/badbots.md, so that a library that
    stops being refused is as much a change as a search engine that starts.

    Args:
        check: Where to record failures.
        refuses: Sends a User-Agent to the server and says whether it was refused.
    """
    let_through = [a for a in BAD_BOTS if not refuses(a)]
    check.expect("lets through no bot it is made of", let_through, [])
    wanted = wanted_user_agents()
    check.expect("refuses no client a site wants", sorted(n for n, a in wanted.items() if refuses(a)), [])
    libraries = sorted(e["name"] for e in BENIGN if e["category"] == "libraries")
    refused = sorted(e["name"] for e in BENIGN if e["category"] == "libraries" and refuses(e["user_agent"]))
    check.expect("refuses HTTP libraries, on purpose", refused, libraries)


def docker() -> Optional[str]:
    """The docker binary if there is one and its daemon answers, else None."""
    binary = shutil.which("docker")
    if binary and subprocess.run([binary, "info"], capture_output=True).returncode == 0:
        return binary
    return None


class Container:
    """
    A detached container that is gone when the block ends.

    Usage:
        with Container(["haproxy:latest", "haproxy", "-f", "/cfg/h.cfg"],
                       publish={18000: 8080}, volumes={cfg_dir: "/cfg"}) as c:
            ...
    """

    def __init__(self, command: List[str], publish: Dict[int, int],
                 volumes: Dict[Path, str], env: Optional[Dict[str, str]] = None):
        self.command = command
        self.publish = publish
        self.volumes = volumes
        self.env = env or {}
        self.id = ""

    def __enter__(self) -> "Container":
        args = ["docker", "run", "-d", "--rm"]
        for host, inside in self.publish.items():
            args += ["-p", f"127.0.0.1:{host}:{inside}"]
        for host_path, inside in self.volumes.items():
            args += ["-v", f"{host_path}:{inside}:ro"]
        for key, value in self.env.items():
            args += ["-e", f"{key}={value}"]
        started = subprocess.run(args + self.command, capture_output=True, text=True)
        if started.returncode != 0:
            raise RuntimeError(started.stderr.strip())
        self.id = started.stdout.strip()
        return self

    def __exit__(self, *exc) -> None:
        subprocess.run(["docker", "rm", "-f", self.id], capture_output=True)

    def logs(self) -> str:
        done = subprocess.run(["docker", "logs", self.id], capture_output=True, text=True)
        return (done.stdout + done.stderr).strip()

    def wait(self, port: int, timeout: float = 30.0) -> bool:
        """Waits until the published port answers HTTP, or the container stops."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            running = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", self.id],
                                     capture_output=True, text=True).stdout.strip()
            if running != "true":
                return False
            try:
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                connection.request("GET", "/")
                connection.getresponse()
                return True
            except (OSError, http.client.HTTPException):
                time.sleep(0.5)
        return False


def run_once(image: str, command: List[str], volumes: Dict[Path, str],
             env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    """Runs a command in a container to completion, for a configuration test."""
    args = ["docker", "run", "--rm"]
    for host_path, inside in volumes.items():
        args += ["-v", f"{host_path}:{inside}:ro"]
    for key, value in (env or {}).items():
        args += ["-e", f"{key}={value}"]
    return subprocess.run(args + [image] + command, capture_output=True, text=True)


class Checker:
    """Counts what a conformance test asserts, and prints what it found."""

    def __init__(self, title: str):
        self.title = title
        self.failures = 0
        print(f"\n{title}")

    def ok(self, message: str) -> None:
        print(f"  ok    {message}")

    def fail(self, message: str) -> None:
        self.failures += 1
        print(f"  FAIL  {message}")

    def note(self, message: str) -> None:
        print(f"        {message}")

    def loads(self, server: str, observed: bool, expected: bool, issue: Optional[str] = None) -> bool:
        """
        Whether the server loads the generated configuration, against what is
        known. A server that does not, and is known not to, is not a failure: it
        is a defect with an issue. One that starts to is, so the expectation gets
        updated and the traffic phase gets its floors.
        """
        if observed == expected:
            if observed:
                self.ok(f"{server} loads it")
            else:
                self.ok(f"{server} does not load it, as known ({issue})")
            return True
        if observed:
            self.fail(f"{server} loads it now: update EXPECTED, add the floors"
                      + (f", and close {issue}" if issue else ""))
        else:
            self.fail(f"{server} does not load it")
        return False

    def expect(self, description: str, observed, expected) -> bool:
        """Passes when observed is expected. A known defect is an expectation too."""
        if observed == expected:
            self.ok(f"{description}: {observed}")
            return True
        self.fail(f"{description}: expected {expected!r}, got {observed!r}")
        return False


def report_traffic(check: Checker, traffic: Traffic, expected_benign: List[str],
                   floor_clear: int, floor_encoded: int) -> None:
    """
    Prints and asserts what the corpus did against a running server.

    Args:
        check: Where to record failures.
        traffic: What `measure` found.
        expected_benign: The ordinary requests that are refused today, by name.
            Empty for a target that refuses none.
        floor_clear: The fewest attacks refused, sent in clear.
        floor_encoded: The fewest refused, sent percent-encoded.
    """
    print(f"\nordinary traffic ({len(BENIGN)} requests)")
    check.expect("refused", sorted(traffic.benign_refused), sorted(expected_benign))
    if traffic.benign_errors:
        check.fail(f"{len(traffic.benign_errors)} ordinary requests got a server error: "
                   f"{', '.join(traffic.benign_errors[:5])}")

    print(f"\nattacks ({len(ATTACKS)} requests, each sent twice)")
    print(f"  in clear:          {len(traffic.caught_clear)}/{len(ATTACKS)} refused")
    print(f"  percent-encoded:   {len(traffic.caught_encoded)}/{len(ATTACKS)} refused")
    for label, caught, floor in (("in clear", traffic.caught_clear, floor_clear),
                                 ("percent-encoded", traffic.caught_encoded, floor_encoded)):
        if len(caught) < floor:
            check.fail(f"{label}: {len(caught)} refused, floor is {floor}")
    if floor_clear or floor_encoded:
        if not check.failures:
            check.ok("both above the floor")
    missed = [e["name"] for e in ATTACKS if e["name"] not in traffic.caught_clear]
    if missed:
        print("\nnot caught in clear:")
        for name in missed:
            print(f"        {name}")


def finish(check: Checker) -> int:
    """The exit code: 0 when everything asserted held."""
    if check.failures:
        print(f"\n{check.failures} failing")
        return 1
    print("\nok")
    return 0
