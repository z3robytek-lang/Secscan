# Secscan 🔒

[![Tests](https://github.com/z3robytek-lang/Secscan/actions/workflows/tests.yml/badge.svg)](https://github.com/z3robytek-lang/Secscan/actions/workflows/tests.yml)

Security Configuration Validator — validate Nginx, Docker, Kubernetes and more against security best practices.

Secscan is a defensive security tool designed to help pentesters, security engineers, DevOps teams and students review infrastructure configuration files and detect common security weaknesses.

## ✨ Features

- 🔍 Multi-platform support: Nginx, Docker and Kubernetes
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

Validate a Kubernetes manifest:

```bash
secscan k8s deployment.yml
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

### `secscan k8s`

Validates Kubernetes YAML manifests.

```bash
secscan k8s <config_path> [OPTIONS]
```

Options:

```txt
--format [text|json]  Output format. Default: text
--output PATH         Save output to file
```

Kubernetes checks include:

- Host namespace usage
- Privileged containers
- Image tag pinning
- Privilege escalation
- Running as non-root
- Read-only root filesystem
- Resource limits
- Possible hardcoded secrets in environment variables

### `secscan scan`

Batch scan a directory for supported configuration files.

```bash
secscan scan <directory> [OPTIONS]
```

Options:

```txt
--format [text|json]  Output format. Default: text
```

The scan command currently detects:

- `nginx.conf`
- `Dockerfile`
- `docker-compose.yml`
- Kubernetes `.yml` / `.yaml` files containing `apiVersion` and `kind`

### `secscan version`

Show version information.

```bash
secscan version
```

## 📊 Output Examples

### Text output

```txt
============================================================
Kubernetes Configuration Security Validation
============================================================

Critical Issues: 3
High Issues: 1
Warnings: 4
Passed Checks: 2

============================================================
ISSUES
============================================================

[CRITICAL] hostNetwork
  ❌ Issue: Host network namespace is enabled in Deployment/insecure-nginx
  💡 Recommendation: Avoid using hostNetwork: true unless it is strictly required.

[CRITICAL] Privileged Container
  ❌ Issue: Container nginx in Deployment/insecure-nginx runs in privileged mode
  💡 Recommendation: Set securityContext.privileged to false or remove it.

[HIGH] Run As Non Root
  ❌ Issue: Container nginx in Deployment/insecure-nginx is not explicitly configured to run as non-root
  💡 Recommendation: Set securityContext.runAsNonRoot: true.

[CRITICAL] Hardcoded Secrets
  ❌ Issue: Possible secret exposed in environment variable ADMIN_PASSWORD in container nginx
  💡 Recommendation: Use Kubernetes Secrets instead of hardcoded environment variables.

============================================================
WARNINGS
============================================================

⚠ Image Tag
  Issue: Container nginx in Deployment/insecure-nginx uses an unpinned image tag: nginx:latest
  Recommendation: Use a specific image version instead of latest or an implicit latest tag.

============================================================
```

### JSON output

```json
{
  "status": "completed",
  "platform": "kubernetes",
  "critical_issues": 3,
  "high_issues": 1,
  "medium_warnings": 4,
  "warnings": 4,
  "passes": 2,
  "issues": [
    {
      "severity": "critical",
      "check": "Privileged Container",
      "issue": "Container nginx in Deployment/insecure-nginx runs in privileged mode",
      "recommendation": "Set securityContext.privileged to false or remove it."
    }
  ],
  "warnings_list": [
    {
      "severity": "medium",
      "check": "Image Tag",
      "issue": "Container nginx in Deployment/insecure-nginx uses an unpinned image tag: nginx:latest",
      "recommendation": "Use a specific image version instead of latest or an implicit latest tag."
    }
  ],
  "passed_checks": [
    {
      "check": "hostPID",
      "message": "hostPID is not enabled in Deployment/insecure-nginx"
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

### Kubernetes checks

| Check | Severity |
|---|---:|
| hostNetwork | Critical |
| hostPID | Critical |
| hostIPC | Critical |
| Privileged Container | Critical |
| Hardcoded Secrets | Critical |
| Run As Non Root | High |
| Image Tag | Medium |
| Privilege Escalation | Medium |
| Read Only Root Filesystem | Medium |
| Resource Limits | Medium |

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
│       ├── docker_validator.py
│       └── kubernetes_validator.py
├── examples/
│   ├── nginx.conf
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── deployment.yml
├── tests/
│   ├── test_cli.py
│   ├── test_nginx_validator.py
│   ├── test_docker_validator.py
│   └── test_kubernetes_validator.py
├── requirements.txt
├── requirements-dev.txt
├── setup.py
├── LICENSE
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
- Nginx validator detection for missing SSL/TLS protocols
- Nginx validator pass check for disabled server tokens
- Docker validator detection for `latest` image tags
- Docker validator detection for missing `USER` instruction
- Kubernetes validator detection for privileged containers
- CLI version command
- CLI Kubernetes command

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

- Apache validator
- Ansible playbook validator
- Terraform validator
- Custom rule support
- SARIF output
- Web UI dashboard
- CI/CD integration examples
- Expand test coverage
- PyPI release

## 📚 Resources

- CIS Benchmarks
- OWASP Top 10
- Nginx Documentation
- Docker Security Best Practices
- Kubernetes Security Best Practices

## ⚖️ License

This project is released under the MIT License. See the `LICENSE` file for details.

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
