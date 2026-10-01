# Contributing to Patterns

Thank you for your interest in contributing to the Patterns project! We appreciate your help in making this project better.

## How to Contribute

### Reporting Issues

If you find a bug or have a suggestion for improvement:

1. Check if the issue already exists in the [Issues](https://github.com/fabriziosalmi/patterns/issues) section.
2. If not, create a new issue with a clear title and description.
3. Include relevant details such as:
   - Steps to reproduce (for bugs)
   - Expected vs. actual behavior
   - Your environment (OS, Python version, web server type)

### Submitting Pull Requests

We welcome pull requests! Here's how to submit one:

1. **Fork the Repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/patterns.git
   cd patterns
   ```

2. **Create a Feature Branch**
   
   Use descriptive branch names following this convention:
   - `feature/description` - For new features
   - `fix/description` - For bug fixes
   - `docs/description` - For documentation changes
   - `refactor/description` - For code refactoring
   
   Example:
   ```bash
   git checkout -b feature/add-caddy-support
   ```

3. **Make Your Changes**
   - Write clear, concise commit messages
   - Follow the existing code style and conventions
   - Add comments where necessary
   - Update documentation if you're changing functionality

4. **Test Your Changes**
   
   Before submitting, ensure your code works correctly:
   ```bash
   # Install dependencies
   pip install -r requirements.txt
   
   # Test the OWASP scraper
   python owasp2json.py

   # Check what the extractor reads from a rule, and the format of owasp_rules.json
   python3 tests/test_ir_extraction.py
   python3 tests/test_ir_schema.py
   
   # Test the converters
   python3 -m patterns build --all
   python3 tests/test_cli.py
   
   # Test bad bot generation
   python badbots.py
   ```
   
   For web server specific testing, check the respective workflow files in `.github/workflows/`.
   The conformance tests load the generated configuration in the real server and send it the
   corpus; they need `docker` (nginx needs the `nginx` binary):
   ```bash
   python3 tests/test_nginx_blocking.py
   python3 tests/test_apache_blocking.py
   python3 tests/test_haproxy_blocking.py
   python3 tests/test_envoy_blocking.py
   python3 tests/test_traefik_blocking.py
   ```
   What each target does today is `EXPECTED` at the top of its test, with the issue that tracks it.

   **Run what GitHub will run, before you push.** `scripts/ci-local.sh` reproduces the workflows
   locally: it reads the commands from `.github/workflows/*.yml`, so it cannot drift from them, and
   runs them on a Linux box that has what CI has (Python 3.11 and 3.13, nginx, Docker, Node 20). The
   box is the `ci-patterns` LXC, provisioned by `scripts/ci-local-setup.sh`; from your machine,
   `scripts/ci-remote.sh` sends the working tree there (committed or not) and runs it:
   ```bash
   export CI_HOST=ci@<address of the ci-patterns box>
   scripts/ci-remote.sh --list                 # the stages
   scripts/ci-remote.sh fast                   # the IR, the committed output, nginx: ~20 s
   scripts/ci-remote.sh ci                     # everything the PR checks run, apache/haproxy/traefik/envoy in docker
   scripts/ci-remote.sh apache envoy           # any stages
   ```
   On a Linux box that has the tools, run `scripts/ci-local.sh` directly.

   If you change the format of `owasp_rules.json`, change `schema/ir.schema.json` and raise its `schema_version`: [Intermediate representation](docs/ir.md) says how.

5. **Commit and Push**
   ```bash
   git add .
   git commit -m "feat: add support for Caddy web server"
   git push origin feature/add-caddy-support
   ```

6. **Open a Pull Request**
   - Go to the original repository on GitHub
   - Click "New Pull Request"
   - Select your branch
   - Provide a clear title and description of your changes
   - Reference any related issues

### Reporting or fixing a false positive

A rule that refuses ordinary traffic is an outage, and what keeps it out of the output is
`patterns/corpus.py`: the nginx backend does not emit a rule that matches a request in
`BENIGN`. So a false positive starts as an entry there, not as a change to a rule:

1. Add the request to `BENIGN` with `benign(category, name, why, path, query, ...)`. Pick the
   category it is an instance of (`CATEGORIES`), and write one line on why it is there: what it
   could be mistaken for.
2. Make it up, or take it from public documentation. Never paste real traffic: hosts are
   `example.*`, people are `@example.com`, addresses are in the documentation ranges.
   `tests/test_corpus.py` checks this.
3. Run `python3 tests/test_nginx_blocking.py` **before rebuilding**. The output in the
   repository was built without your request, so the test fails and names it: that is the false
   positive, reproduced. (`name=O'Brien+and+sons` was refused by CRS 942521 until it was added.)
4. Rebuild (`python3 -m patterns build --all`) and run the test again. It passes, and the rule
   that refused your request is listed under "rules kept out because they match ordinary
   traffic", with the request next to it. Commit the entry and the rebuilt output together.

## Code Style Guidelines

- Use Python 3.11 or higher
- Follow PEP 8 style guidelines
- Use meaningful variable and function names
- Add docstrings to functions and classes
- Keep functions focused and modular
- Handle errors gracefully with try-except blocks

## Adding Support for New Web Servers

If you want to add support for a new web server:

1. Create a new converter script: `json2WEBSERVER.py`
2. Create output directory: `waf_patterns/WEBSERVER/`
3. Add README.md with integration instructions
4. Update the main README.md to include the new web server
5. Update the GitHub Actions workflow to include the new converter
6. Add example configurations

## Questions?

If you have questions about contributing, feel free to:
- Open an issue for discussion
- Contact the maintainers

Thank you for contributing!
