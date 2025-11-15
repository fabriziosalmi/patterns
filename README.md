# 🔒 Patterns: OWASP CRS and Bad Bot Detection for Web Servers  

Automate the scraping of **OWASP Core Rule Set (CRS)** patterns and convert them into **Apache, Nginx, Traefik, and HAProxy** WAF configurations.  
Additionally, **Bad Bot/User-Agent detection** is integrated to block malicious web crawlers and scrapers.  

> 🚀 **Protect your servers against SQL Injection (SQLi), XSS, RCE, LFI, and malicious bots – with automated daily updates.**  

---

## 📌 Project Highlights  
- **🛡️ OWASP CRS Protection** – Leverages OWASP Core Rule Set for web application firewall (WAF) defense.  
- **🤖 Bad Bot Blocking** – Blocks known malicious bots using public bot lists.  
- **⚙️ Multi-Web Server Support** – Generates WAF configs for **Apache, Nginx, Traefik, and HAProxy**.  
- **🔄 Automatic Updates** – GitHub Actions fetch new rules **daily** and push updated configs.  
- **📦 Pre-Generated Configurations** – Download ready-to-use WAF configurations from [GitHub Releases](https://github.com/fabriziosalmi/patterns/releases).  
- **🧩 Scalable and Modular** – Easily extendable to support other web servers or load balancers.  

---

## 🌐 Supported Web Servers  
- **🔵 Nginx**  
- **🟠 Apache (ModSecurity)**  
- **🟣 Traefik**  
- **🔴 HAProxy**  

> [!NOTE]
> If you are using Caddy, check the [caddy-waf](https://github.com/fabriziosalmi/caddy-waf) project.

---

## 📂 Project Structure  
```
patterns/
├── waf_patterns/           # 🔧 Generated WAF config files
│   ├── nginx/              # Nginx WAF configs
│   ├── apache/             # Apache WAF configs (ModSecurity)
│   ├── traefik/            # Traefik WAF configs
│   └── haproxy/            # HAProxy WAF configs
├── import_apache_waf.py    # 📥 Import Apache WAF configurations
├── import_haproxy_waf.py   # 📥 Import HAProxy WAF configurations
├── import_nginx_waf.py     # 📥 Import Nginx WAF configurations
├── import_traefik_waf.py   # 📥 Import Traefik WAF configurations
├── owasp2json.py           # 🕵️ OWASP scraper (fetch CRS rules)
├── json2nginx.py           # 🔄 Convert OWASP JSON to Nginx WAF configs
├── json2apache.py          # 🔄 Convert OWASP JSON to Apache ModSecurity configs
├── json2traefik.py         # 🔄 Convert OWASP JSON to Traefik WAF configs
├── json2haproxy.py         # 🔄 Convert OWASP JSON to HAProxy WAF configs
├── badbots.py              # 🤖 Generate WAF configs to block bad bots
├── requirements.txt        # 📄 Required dependencies
└── .github/workflows/      # 🤖 GitHub Actions for automation
    └── update_patterns.yml
```

---

## 🛠️ How It Works  
### 🔹 1. Scraping OWASP Rules  
- **`owasp2json.py`** scrapes the latest OWASP CRS patterns from GitHub.  
- Extracts **SQLi, XSS, RCE, LFI** patterns from OWASP CRS `.conf` files.  

### 🔹 2. Generating WAF Configs for Each Platform  
- **`json2nginx.py`** – Generates **Nginx WAF** configurations.  
- **`json2apache.py`** – Outputs **Apache ModSecurity** rules.  
- **`json2traefik.py`** – Creates **Traefik WAF** rules.  
- **`json2haproxy.py`** – Builds **HAProxy ACL** files.  

### 🔹 3. Bad Bot/User-Agent Detection  
- **`badbots.py`** fetches public bot lists and generates bot-blocking configs.  
- Supports fallback lists to ensure reliable detection.  

---

## ⚙️ Installation  

### Option 1: Download Pre-Generated Configurations  
You can download the latest pre-generated WAF configurations directly from the [GitHub Releases](https://github.com/fabriziosalmi/patterns/releases) page.  

1. Go to the [Releases](https://github.com/fabriziosalmi/patterns/releases) section.  
2. Download the zip file for your web server (e.g., `nginx_waf.zip`, `apache_waf.zip`).  
3. Extract the files and follow the integration instructions below.  

### Option 2: Build from Source  
If you prefer to generate the configurations yourself:  

**1. Clone the Repository:**  
```bash
git clone https://github.com/fabriziosalmi/patterns.git  
cd patterns
```

**2. Install Dependencies:**  
```bash
pip install -r requirements.txt
```

**3. Run Manually (Optional):**  
```bash
python owasp2json.py
python json2nginx.py
python json2apache.py
python json2haproxy.py
python json2traefik.py
python badbots.py
```

---

## 🚀 Usage (Web Server Integration)  

### 🔹 1. Nginx WAF Integration  
1. Download the `nginx_waf.zip` file from the [Releases](https://github.com/fabriziosalmi/patterns/releases) page.  
2. Extract the files to your Nginx configuration directory.  
3. Include the generated `.conf` files in your Nginx configuration:  
   ```nginx
   include /path/to/waf_patterns/nginx/*.conf;
   ```

### 🔹 2. Apache WAF Integration  
1. Download the `apache_waf.zip` file from the [Releases](https://github.com/fabriziosalmi/patterns/releases) page.  
2. Extract the files to your Apache configuration directory.  
3. Include the generated `.conf` files in your Apache configuration:  
   ```apache
   Include /path/to/waf_patterns/apache/*.conf
   ```

### 🔹 3. Traefik WAF Integration  
1. Download the `traefik_waf.zip` file from the [Releases](https://github.com/fabriziosalmi/patterns/releases) page.  
2. Extract the files and use the `middleware.toml` file in your Traefik configuration.  

### 🔹 4. HAProxy WAF Integration  
1. Download the `haproxy_waf.zip` file from the [Releases](https://github.com/fabriziosalmi/patterns/releases) page.  
2. Extract the files and include the `waf.acl` file in your HAProxy configuration.  

---

## 🔧 Example Output (Bot Blocker – Nginx)  
```nginx
map $http_user_agent $bad_bot {
    "~*AhrefsBot" 1;
    "~*SemrushBot" 1;
    "~*MJ12bot" 1;
    default 0;
}
if ($bad_bot) {
    return 403;
}
```

---

## 🤖 Automation (GitHub Workflow)  
- **🕛 Daily Updates** – GitHub Actions fetch the latest OWASP CRS rules every day.  
- **🔄 Auto Deployment** – Pushes new `.conf` files directly to `waf_patterns/`.  
- **📦 Release Automation** – Automatically creates a new release with pre-generated configurations.  
- **🎯 Manual Trigger** – Updates can also be triggered manually.  

---

## 🤝 Contributing  
1. **Fork** the repository.  
2. Create a **feature branch** (`feature/new-patterns`).  
3. **Commit** and push changes.  
4. Open a **Pull Request**.  

---

## 📄 License  
This project is licensed under the **MIT License**.  
See the [LICENSE](LICENSE) file for details.  

---

## Other Projects

If you like this project, you may also like these:

- [caddy-waf](https://github.com/fabriziosalmi/caddy-waf) Caddy WAF (Regex Rules, IP and DNS filtering, Rate Limiting, GeoIP, Tor, Anomaly Detection) 
- [blacklists](https://github.com/fabriziosalmi/blacklists) Hourly updated domains blacklist 🚫 
- [proxmox-vm-autoscale](https://github.com/fabriziosalmi/proxmox-vm-autoscale) Automatically scale virtual machines resources on Proxmox hosts 
- [UglyFeed](https://github.com/fabriziosalmi/UglyFeed) Retrieve, aggregate, filter, evaluate, rewrite and serve RSS feeds using Large Language Models for fun, research and learning purposes 
- [proxmox-lxc-autoscale](https://github.com/fabriziosalmi/proxmox-lxc-autoscale) Automatically scale LXC containers resources on Proxmox hosts 
- [DevGPT](https://github.com/fabriziosalmi/DevGPT) Code togheter, right now! GPT powered code assistant to build project in minutes
- [websites-monitor](https://github.com/fabriziosalmi/websites-monitor) Websites monitoring via GitHub Actions (expiration, security, performances, privacy, SEO)
- [caddy-mib](https://github.com/fabriziosalmi/caddy-mib) Track and ban client IPs generating repetitive errors on Caddy 
- [zonecontrol](https://github.com/fabriziosalmi/zonecontrol) Cloudflare Zones Settings Automation using GitHub Actions 
- [lws](https://github.com/fabriziosalmi/lws) linux (containers) web services
- [cf-box](https://github.com/fabriziosalmi/cf-box) cf-box is a set of Python tools to play with API and multiple Cloudflare accounts.
- [limits](https://github.com/fabriziosalmi/limits) Automated rate limits implementation for web servers 
- [dnscontrol-actions](https://github.com/fabriziosalmi/dnscontrol-actions) Automate DNS updates and rollbacks across multiple providers using DNSControl and GitHub Actions 
- [proxmox-lxc-autoscale-ml](https://github.com/fabriziosalmi/proxmox-lxc-autoscale-ml) Automatically scale the LXC containers resources on Proxmox hosts with AI
- [csv-anonymizer](https://github.com/fabriziosalmi/csv-anonymizer) CSV fuzzer/anonymizer
- [iamnotacoder](https://github.com/fabriziosalmi/iamnotacoder) AI code generation and improvement

---
## 📞 Need Help?  
- **Issues?** Open a ticket in the [Issues Tab](https://github.com/fabriziosalmi/patterns/issues).  

---

## 🌐 Resources  
- [OWASP CRS](https://github.com/coreruleset/coreruleset)  
- [Apache ModSecurity](https://modsecurity.org/)  
- [Nginx](https://nginx.org/)  
- [Traefik](https://github.com/traefik/traefik)  
- [HaProxy](https://www.haproxy.org/)  
