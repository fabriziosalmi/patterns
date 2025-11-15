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
   
   # Test the converters
   python json2nginx.py
   python json2apache.py
   python json2traefik.py
   python json2haproxy.py
   
   # Test bad bot generation
   python badbots.py
   ```
   
   For web server specific testing, check the respective workflow files in `.github/workflows/`.

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
