# Secscan 🔒

[![Tests](https://github.com/z3robytek-lang/Secscan/actions/workflows/tests.yml/badge.svg)](https://github.com/z3robytek-lang/Secscan/actions/workflows/tests.yml)

Security Configuration Validator — validate Nginx, Docker, Kubernetes and more against security best practices and CIS Benchmarks.

Secscan is a defensive security tool designed to help pentesters, security engineers, DevOps teams and students review infrastructure configuration files and detect common security weaknesses.

## ✨ Features

- 🔍 Multi-platform support: Nginx and Docker currently implemented
- 🎯 Security focused: checks inspired by CIS Benchmarks and hardening best practices
- 🚀 Easy to use: simple CLI interface
- 📊 Detailed reports: text and JSON output formats
- 🔄 Batch scanning: scan entire directories
- 💡 Actionable recommendations: clear guidance on how to fix issues
- 🎨 Colorized output: easy-to-read terminal output
- ✅ Tested: unit tests and GitHub Actions workflow included

## 🚀 Quick Start

### Installation from source

```bash
git clone https://github.com/z3robytek-lang/Secscan.git
cd Secscan
pip install -r requirements.txt
pip install -e .
```

### Development installation

```bash
git clone https://github.com/z3robytek-lang/Secscan.git
cd Secscan

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
pip install -r requirements-dev.txt
pip install -e .

pytest
```

### Via pip

```bash
pip install secscan
```

> PyPI publishing is planned for a future release.

## ⚡ Basic Usage

Validate a Nginx configuration:

```bash
secscan nginx /etc/nginx/nginx.conf
```

Validate a Dockerfile:

```bash
secscan docker Dockerfile
```

Validate docker-compose:

```bash
secscan docker docker-compose.yml
```

Scan an entire directory:

```bash
secscan scan /etc/nginx/
```

Generate a JSON report:

```bash
secscan nginx /etc/nginx/nginx.conf --format json --output report.json
```

Show version information:

```bash
secscan version
```

## 📖 Commands

### `secscan nginx`

Validates Nginx configuration files against security best practices.

```bash
secscan nginx <config_path> [OPTIONS]
```

Options:

```txt
--format [text|json]  Output format. Default: text
--output PATH         Save output to file
```

Checks include:

- SSL/TLS configuration
- SSL cipher configuration
- HSTS header
- Security headers
- Server token exposure
- Logging configuration
- Timeout settings
- Authentication mechanisms
- File permissions

### `secscan docker`

Validates Dockerfile and docker-compose.yml files.

```bash
secscan docker <config_path> [OPTIONS]
```

Options:

```txt
--format [text|json]  Output format. Default: text
--output PATH         Save output to file
```

Dockerfile checks include:

- Base image configuration
- Specific image tags
- User privileges
- Health checks
- Secrets in environment variables
- Sudo usage
- Package cleanup after apt-get

docker-compose checks include:

- Privileged mode usage
- Hardcoded secrets
- Network isolation
- Resource limits

### `secscan scan`

Batch scan a directory for configuration files.

```bash
secscan scan <directory> [OPTIONS]
```

Options:

```txt
--format [text|json]  Output format. Default: text
```

### `secscan version`

Show version information.

```bash
secscan version
```

## 📊 Output Examples

### Text output

```txt
============================================================
Nginx Configuration Security Validation
============================================================

Critical Issues: 2
High Issues: 1
Warnings: 3
Passed Checks: 8

============================================================
ISSUES
============================================================

[CRITICAL] SSL/TLS Protocols
  ❌ Issue: ssl_protocols directive is missing
  💡 Recommendation: Add 'ssl_protocols TLSv1.2 TLSv1.3;' to your nginx config
  📋 CIS Benchmark: 2.2.1

[HIGH] HSTS
  ❌ Issue: Strict-Transport-Security header is missing
  💡 Recommendation: Add 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'
  📋 CIS Benchmark: 2.5.1

============================================================
WARNINGS
============================================================

⚠ Server Tokens
  Issue: Server tokens are not explicitly disabled
  Recommendation: Add 'server_tokens off;' to hide nginx version

============================================================
PASSED CHECKS
============================================================

✓ Access Logging: Access logging is configured
✓ Error Logging: Error logging is configured
✓ Timeouts: Timeout configuration: 4/4 configured

============================================================
```

### JSON output

```json
{
  "status": "completed",
  "platform": "nginx",
  "critical_issues": 1,
  "high_issues": 1,
  "medium_warnings": 1,
  "warnings": 3,
  "passes": 4,
  "issues": [
    {
      "severity": "critical",
      "check": "SSL/TLS Protocols",
      "issue": "ssl_protocols directive is missing",
      "recommendation": "Add 'ssl_protocols TLSv1.2 TLSv1.3;' to your nginx config",
      "cis_benchmark": "2.2.1"
    }
  ],
  "warnings_list": [
    {
      "severity": "medium",
      "check": "Server Tokens",
      "issue": "Server tokens are not explicitly disabled",
      "recommendation": "Add 'server_tokens off;' to hide nginx version",
      "cis_benchmark": "2.2.2"
    }
  ],
  "passed_checks": [
    {
      "check": "Access Logging",
      "message": "Access logging is configured"
    }
  ]
}
```

## 📋 Security Checks Reference

### Nginx checks

| Check | Severity | Benchmark |
|---|---:|---|
| SSL/TLS Protocols | Critical | 2.2.1 |
| SSL Ciphers | Warning | N/A |
| HSTS Header | High | 2.5.1 |
| Security Headers | High | 2.5.2 |
| Server Tokens | Medium | 2.2.2 |
| Access Logging | Medium | 2.4.1 |
| Error Logging | Medium | N/A |
| Timeouts | Medium | N/A |
| Authentication | Medium | N/A |
| File Permissions | Medium | 2.1.1 |

### Docker checks

| Check | Severity | Benchmark |
|---|---:|---|
| Base Image | Critical | 4.1 |
| Base Image Tag | Medium | 4.1 |
| User Privileges | High | 4.2 |
| Secrets Management | Critical | 4.9 |
| Health Check | Medium | N/A |
| Sudo Usage | Medium | N/A |
| Image Size | Medium | N/A |
| Privileged Mode | Critical | 5.4 |
| Resource Limits | Medium | N/A |
| Network Isolation | Medium | N/A |

## 🛠️ Development

### Project structure

```txt
Secscan/
├── .github/
│   └── workflows/
│       └── tests.yml
├── secscan/
│   ├── __init__.py
│   ├── cli.py
│   └── validators/
│       ├── __init__.py
│       ├── nginx_validator.py
│       └── docker_validator.py
├── examples/
│   ├── nginx.conf
│   ├── Dockerfile
│   └── docker-compose.yml
├── tests/
│   ├── test_cli.py
│   ├── test_nginx_validator.py
│   └── test_docker_validator.py
├── requirements.txt
├── requirements-dev.txt
├── setup.py
├── .gitignore
└── README.md
```

### Setting up the development environment

```bash
git clone https://github.com/z3robytek-lang/Secscan.git
cd Secscan

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
pip install -r requirements-dev.txt
pip install -e .

pytest
secscan --help
```

### Running tests

```bash
pytest
```

Current test coverage includes:

- Nginx validator detection for server token exposure
- Docker validator detection for `latest` image tags
- CLI version command

### GitHub Actions

This project includes a GitHub Actions workflow that runs the test suite automatically on:

- Push
- Pull request

Workflow file:

```txt
.github/workflows/tests.yml
```

## ➕ Adding a New Validator

To add a new validator:

1. Create a new file in `secscan/validators/`, for example `apache_validator.py`.
2. Implement a validator class with a `validate(config_path: str) -> Dict` method.
3. Add the import to `secscan/validators/__init__.py`.
4. Add a new command to `secscan/cli.py`.
5. Add examples in the `examples/` directory.
6. Add tests in the `tests/` directory.
7. Update this README.

Example:

```python
from typing import Dict


class ApacheValidator:
    def validate(self, config_path: str) -> Dict:
        """Validate Apache configuration."""
        # Implementation here
        pass
```

## 🤝 Contributing

Contributions are welcome.

You can help by:

- Reporting bugs
- Suggesting new validators
- Improving documentation
- Adding tests
- Improving existing checks
- Adding CI/CD integration examples

### Contribution workflow

```bash
git checkout -b feature/amazing-feature
git add .
git commit -m "Add amazing feature"
git push origin feature/amazing-feature
```

Then open a Pull Request on GitHub.

## 📝 Roadmap

- Kubernetes validator
- Apache validator
- Ansible playbook validator
- Custom rule support
- Web UI dashboard
- Database integration for reporting
- CI/CD integration examples
- Expand test coverage
- PyPI release

## 📚 Resources

- CIS Benchmarks
- OWASP Top 10
- Nginx Documentation
- Docker Security Best Practices

## ⚖️ License

This project is intended to be released under the MIT License.

If a `LICENSE` file is not present yet, add one before publishing a stable release.

## 👨‍💻 Author

**z3robytek-lang** — Junior Developer

GitHub: `@z3robytek-lang`

## ⚠️ Disclaimer

Secscan is intended for defensive security auditing, configuration review and educational purposes.

Only scan systems, files and environments that you own or have explicit permission to assess.

## 🙏 Acknowledgments

- CIS Benchmarks community
- OWASP security guidelines
- Open source security tools for inspiration

## 📞 Support

- Issues: GitHub Issues
- Discussions: GitHub Discussions

Security is a journey, not a destination. Keep your configurations secure! 🔐
EOF
