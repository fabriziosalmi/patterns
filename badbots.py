import requests
import os
import logging
import json
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import re
from tqdm import tqdm  # Import tqdm for progress bar

from patterns import corpus, dialects
from patterns.backends._common import toml_string
from patterns.backends.traefik import PLUGIN

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Constants and Configuration
OUTPUT_DIRS = {
    "nginx": "waf_patterns/nginx/",
    "apache": "waf_patterns/apache/",
    "traefik": "waf_patterns/traefik/",
    "haproxy": "waf_patterns/haproxy/"
}

# Updated list of bot list sources
BOT_LIST_SOURCES = [
    "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list",
    "https://raw.githubusercontent.com/JayBizzle/Crawler-Detect/master/raw/Crawlers.txt",
    "https://raw.githubusercontent.com/piwik/referrer-spam-blacklist/master/spammers.txt"]

RATE_LIMIT_DELAY = 600
RETRY_DELAY = 5
MAX_RETRIES = 3
EXPONENTIAL_BACKOFF = True
BACKOFF_MULTIPLIER = 2
MAX_WORKERS = 4
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# Regex to detect IP addresses and domains
IP_REGEX = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
DOMAIN_REGEX = re.compile(r"\b([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


def fetch_with_retries(url: str) -> list:
    """
    Fetch bot patterns from a URL with retries and rate-limiting handling.
    """
    retries = 0
    headers = {}

    if GITHUB_TOKEN:
        headers['Authorization'] = f'token {GITHUB_TOKEN}'
        logging.info(f"Using GitHub token for {url}")

    while retries < MAX_RETRIES:
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                logging.info(f"Fetched from {url}")
                return parse_bot_list(url, response)
            
            if response.status_code == 403 and 'X-RateLimit-Remaining' in response.headers:
                reset_time = int(response.headers['X-RateLimit-Reset'])
                wait_time = max(reset_time - int(time.time()), RATE_LIMIT_DELAY)
                logging.warning(f"Rate limit exceeded for {url}. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                jitter = random.uniform(1, 3)
                wait_time = (RETRY_DELAY * (BACKOFF_MULTIPLIER ** retries) if EXPONENTIAL_BACKOFF else RETRY_DELAY) + jitter
                logging.warning(f"Retrying {url}... ({retries + 1}/{MAX_RETRIES}) in {wait_time:.2f} seconds.")
                time.sleep(wait_time)
                retries += 1
        except requests.RequestException as e:
            logging.error(f"Error fetching {url}: {e}")
            retries += 1

    logging.error(f"Failed to fetch {url} after {MAX_RETRIES} retries.")
    return []


def parse_bot_list(url: str, response: requests.Response) -> list:
    """
    Parse bot patterns from the fetched response (JSON or plain text).
    """
    bot_patterns = set()
    try:
        if url.endswith(".json"):
            json_data = response.json()
            if isinstance(json_data, list):
                for entry in json_data:
                    user_agent = entry.get('pattern') or entry.get('ua', '')
                    if user_agent and not user_agent.startswith("#"):
                        bot_patterns.add(user_agent)
            elif isinstance(json_data, dict):
                for entry in json_data.get('test_cases', []):
                    user_agent = entry.get('user_agent_string', '')
                    if user_agent and not user_agent.startswith("#"):
                        bot_patterns.add(user_agent)
        else:
            for line in response.text.splitlines():
                # Exclude comments, empty lines, IPs, and domains
                if line and not line.startswith("#") and len(line) > 3:
                    if not IP_REGEX.search(line) and not DOMAIN_REGEX.search(line):
                        bot_patterns.add(line)
    except (ValueError, json.JSONDecodeError) as e:
        logging.warning(f"Error parsing {url}: {e}")

    return list(bot_patterns)


def fetch_bot_list():
    """
    Fetch bot patterns from all sources using a thread pool.
    """
    bot_patterns = set()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Create a dictionary of futures to URLs
        future_to_url = {executor.submit(fetch_with_retries, url): url for url in BOT_LIST_SOURCES}

        # Use tqdm to show progress
        for future in tqdm(as_completed(future_to_url), total=len(BOT_LIST_SOURCES), desc="Fetching bot lists"):
            result = future.result()
            bot_patterns.update(result)

    if not bot_patterns:
        logging.error("❌ No bots were fetched from any source. Exiting...")
        exit(1)

    logging.info(f"✅ Total unique bots collected: {len(bot_patterns)}")
    return sorted(bot_patterns)


def matching_client(bot: str, wanted: dict):
    """
    The ordinary client an entry of the list would refuse, if there is one.

    An entry is read the two ways a target might: as the regular expression the
    source wrote, which is what nginx and Traefik do with it, and as the text it is
    found in, which is what Apache's `@contains` and HAProxy's `hdr_sub` do. It is
    left out if either one matches, since the list is written for all four.

    Args:
        bot: One entry of the list.
        wanted: Name and User-Agent of each client that must not be refused
            (`corpus.wanted_user_agents`).

    Returns:
        The name of the first client the entry matches, None if it matches none.
    """
    try:
        expression = re.compile(bot, re.IGNORECASE)
    except re.error:
        expression = None
    for name, agent in wanted.items():
        if bot.lower() in agent.lower() or (expression and expression.search(agent)):
            return name
    return None


def leave_out_wanted(bots: list):
    """
    Splits the list into what it should refuse and what would refuse a client a site wants.

    A bad-bot list written from public sources refused Google, Bing, every link
    preview and every uptime monitor, because one of its entries matches any agent with
    `bot` in it and others name a monitor or a messenger outright (#78). The corpus of
    ordinary traffic says who must not be refused, and an entry that matches one of them
    is left out, as a CRS rule that matches one is. HTTP libraries are not among them:
    refusing `curl` and `python-requests` is what the list is for.

    Returns:
        The entries to write, and the entries left out with the client each matched.
    """
    wanted = corpus.wanted_user_agents()
    kept, left_out = [], []
    for bot in bots:
        client = matching_client(bot, wanted)
        if client is None:
            kept.append(bot)
        else:
            left_out.append((bot, client))
    return kept, left_out


def left_out_note(left_out, comment: str = "# ") -> str:
    """What was left out and why, as comment lines at the top of a file."""
    return "".join(f"{comment}Left out, an ordinary client would be refused: {bot} (matches {client})\n"
                   for bot, client in left_out)


def write_to_file(path: Path, content: str):
    """
    Write content to a file at the specified path.
    """
    try:
        with path.open("w") as f:
            f.write(content)
        logging.info(f"Generated file: {path}")
    except IOError as e:
        logging.error(f"Failed to write to {path}: {e}")


def generate_nginx_conf(bots, left_out=()):
    """
    Generate Nginx WAF configuration for blocking bots.
    """
    path = Path(OUTPUT_DIRS['nginx'], "bots.conf")
    content = left_out_note(left_out) + "map $http_user_agent $bad_bot {\n"
    for bot in bots:
        content += f'    "~*{bot}" 1;\n'
    content += "    default 0;\n}\n"
    write_to_file(path, content)


def generate_apache_conf(bots, left_out=()):
    """
    Generate Apache WAF configuration for blocking bots.
    """
    path = Path(OUTPUT_DIRS['apache'], "bots.conf")
    content = left_out_note(left_out) + "SecRuleEngine On\n"
    for bot in bots:
        content += f'SecRule REQUEST_HEADERS:User-Agent "@contains {bot}" "id:3000,phase:1,deny,status:403"\n'
    write_to_file(path, content)


def generate_traefik_conf(bots, left_out=()):
    """
    Generate Traefik WAF configuration for blocking bots.
    """
    path = Path(OUTPUT_DIRS['traefik'], "bots.toml")
    # The plugin the Traefik output is written for (patterns/backends/traefik.py): a
    # list of Go regular expressions for the User-Agent, in TOML that means what it
    # says. Case is ignored, as the nginx list does it.
    # An entry the plugin's engine cannot compile stops the whole middleware from
    # starting (the list had `Yandex(?!Search)`, and Go's RE2 has no lookahead), so
    # it is left out, and said so.
    written, skipped = [], []
    for bot in bots:
        expression = "(?i)" + bot
        problem = dialects.check("re2", expression)
        if problem:
            skipped.append((bot, problem))
        else:
            written.append(expression)
    content = left_out_note(left_out)
    for bot, problem in skipped:
        content += f"# Not written: {bot} {problem}\n"
        logging.warning(f"Traefik: leaving out {bot!r}: {problem}")
    content += ("[http.middlewares]\n[http.middlewares.bad_bot_block]\n"
                f"  [http.middlewares.bad_bot_block.plugin.{PLUGIN}]\n    regex = [\n")
    for expression in written:
        content += f"      {toml_string(expression)},\n"
    content += "    ]\n"
    write_to_file(path, content)


def haproxy_word(entry: str) -> str:
    """
    An entry as one word of an HAProxy configuration line.

    A space ends a word, so `Ask Jeeves` was two patterns, `Ask` and `Jeeves`, and the
    271 entries of the list that hold a space split into their words, among them `U`, `v`,
    `-` and `+`: every browser matches one, and the list refused all of them. A space
    that a backslash does not already protect is protected.
    """
    return re.sub(r"(?<!\\)([ \t])", r"\\\1", entry)


def generate_haproxy_conf(bots, left_out=()):
    """
    Generate HAProxy WAF configuration for blocking bots.
    """
    path = Path(OUTPUT_DIRS['haproxy'], "bots.acl")
    content = "# HAProxy WAF - Bad Bot Blocker\n" + left_out_note(left_out)
    for bot in bots:
        content += f'acl bad_bot hdr_sub(User-Agent) -i {haproxy_word(bot)}\n'
    content += "http-request deny if bad_bot\n"
    write_to_file(path, content)


if __name__ == "__main__":
    # Ensure output directories exist
    for output_dir in OUTPUT_DIRS.values():
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Fetch bot patterns
    bots = fetch_bot_list()
    bots, left_out = leave_out_wanted(bots)
    logging.info(f"Left out {len(left_out)} entries that would refuse an ordinary client.")
    for bot, client in left_out:
        logging.info(f"  {bot!r} matches {client}")

    # Generate WAF configurations
    generate_nginx_conf(bots, left_out)
    generate_apache_conf(bots, left_out)
    generate_traefik_conf(bots, left_out)
    generate_haproxy_conf(bots, left_out)

    logging.info("[✔] Bot blocking configurations generated for all platforms.")