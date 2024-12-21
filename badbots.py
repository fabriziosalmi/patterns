import requests
import os
import logging

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Output directories
OUTPUT_DIRS = {
    "nginx": "waf_patterns/nginx/",
    "caddy": "waf_patterns/caddy/",
    "apache": "waf_patterns/apache/",
    "traefik": "waf_patterns/traefik/",
    "haproxy": "waf_patterns/haproxy/"
}

# Primary and fallback bot lists
BOT_LIST_SOURCES = [
    "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list",  # Primary
    "https://raw.githubusercontent.com/atmire/COUNTER-Robots/master/COUNTER_Robots_list.txt",  # Fallback 1
    "https://raw.githubusercontent.com/monperrus/crawler-user-agents/master/crawler-user-agents.json"  # Fallback 2 (JSON)
]

def fetch_bot_list():
    for source in BOT_LIST_SOURCES:
        try:
            logging.info(f"Fetching bad bot list from {source}...")
            response = requests.get(source, timeout=10)
            response.raise_for_status()

            # Handle JSON fallback source
            if source.endswith(".json"):
                bots = [item['pattern'] for item in response.json()]
            else:
                bots = response.text.splitlines()

            logging.info(f"Successfully fetched {len(bots)} bots from {source}")
            return bots

        except (requests.RequestException, ValueError) as e:
            logging.warning(f"Failed to fetch from {source}. Reason: {e}")

    logging.error("❌ All bot lists failed to fetch. Exiting...")
    exit(1)

def generate_nginx_conf(bots):
    path = os.path.join(OUTPUT_DIRS['nginx'], "bots.conf")
    with open(path, "w") as f:
        f.write("# Nginx WAF - Bad Bot Blocker\n")
        f.write("map $http_user_agent $bad_bot {\n")
        for bot in bots:
            f.write(f'    "~*{bot}" 1;\n')
        f.write("    default 0;\n}\n")
        f.write("if ($bad_bot) {\n    return 403;\n}\n")
    logging.info(f"[+] Generated Nginx bot blocker: {path}")

def generate_caddy_conf(bots):
    path = os.path.join(OUTPUT_DIRS['caddy'], "bots.conf")
    with open(path, "w") as f:
        f.write("# Caddy WAF - Bad Bot Blocker\n")
        f.write("@bad_bot {\n")
        for bot in bots:
            f.write(f'    header User-Agent *{bot}*\n')
        f.write("}\nrespond @bad_bot 403\n")
    logging.info(f"[+] Generated Caddy bot blocker: {path}")

def generate_apache_conf(bots):
    path = os.path.join(OUTPUT_DIRS['apache'], "bots.conf")
    with open(path, "w") as f:
        f.write("# Apache ModSecurity - Bad Bot Blocker\n")
        f.write("SecRuleEngine On\n")
        for bot in bots:
            f.write(f'SecRule REQUEST_HEADERS:User-Agent "@contains {bot}" "id:3000,phase:1,deny,status:403,log,msg:\'Bad Bot Blocked\'"\n')
    logging.info(f"[+] Generated Apache bot blocker: {path}")

def generate_traefik_conf(bots):
    path = os.path.join(OUTPUT_DIRS['traefik'], "bots.toml")
    with open(path, "w") as f:
        f.write("[http.middlewares]\n")
        f.write("[http.middlewares.bad_bot_block]\n")
        f.write("  [http.middlewares.bad_bot_block.plugin.badbot]\n")
        f.write("    userAgent = [\n")
        for bot in bots:
            f.write(f'      "{bot}",\n')
        f.write("    ]\n")
    logging.info(f"[+] Generated Traefik bot blocker: {path}")

def generate_haproxy_conf(bots):
    path = os.path.join(OUTPUT_DIRS['haproxy'], "bots.acl")
    with open(path, "w") as f:
        f.write("# HAProxy WAF - Bad Bot Blocker\n")
        for bot in bots:
            f.write(f'acl bad_bot hdr_sub(User-Agent) -i {bot}\n')
        f.write("http-request deny if bad_bot\n")
    logging.info(f"[+] Generated HAProxy bot blocker: {path}")

if __name__ == "__main__":
    # Ensure output directories exist
    for path in OUTPUT_DIRS.values():
        os.makedirs(path, exist_ok=True)

    # Fetch bot list
    bots = fetch_bot_list()

    # Generate bot blocker configs for each platform
    generate_nginx_conf(bots)
    generate_caddy_conf(bots)
    generate_apache_conf(bots)
    generate_traefik_conf(bots)
    generate_haproxy_conf(bots)

    logging.info("[✔] Bot blocking configurations generated for all platforms.")