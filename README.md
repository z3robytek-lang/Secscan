# Secscan 🔒

**Security Configuration Validator** - Validate Nginx, Docker, Kubernetes & more against security best practices and CIS Benchmarks

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

## ✨ Features

- 🔍 **Multi-platform Support**: Nginx, Docker, Kubernetes
- 🎯 **Security Focused**: Validates against CIS Benchmarks and OWASP standards
- 🚀 **Easy to Use**: Simple CLI interface
- 📊 **Detailed Reports**: Text and JSON output formats
- 🔄 **Batch Scanning**: Scan entire directories
- 💡 **Actionable Recommendations**: Clear guidance on how to fix issues
- 🎨 **Colorized Output**: Easy to read terminal output

## 🚀 Quick Start

### Installation

#### From Source
```bash
git clone https://github.com/z3robytek-lang/secscan.git
cd secscan
pip install -r requirements.txt
pip install -e .
```

#### Via pip (when published)
```bash
pip install secscan
```

### Basic Usage

**Validate a Nginx configuration:**
```bash
secscan nginx /etc/nginx/nginx.conf
```

**Validate a Dockerfile:**
```bash
secscan docker Dockerfile
```

**Validate docker-compose:**
```bash
secscan docker docker-compose.yml
```

**Scan entire directory:**
```bash
secscan scan /etc/nginx/
```

**Generate JSON report:**
```bash
secscan nginx /etc/nginx/nginx.conf --format json --output report.json
```

## 📖 Documentation

### Commands

#### `secscan nginx`
Validates Nginx configuration files against security best practices.

```bash
secscan nginx <config_path> [OPTIONS]

Options:
  --format [text|json]  Output format (default: text)
  --output PATH         Save output to file
```

**Checks:**
- SSL/TLS configuration (protocols, ciphers)
- Security headers (HSTS, X-Frame-Options, CSP)
- Server token exposure
- Logging configuration
- Timeout settings
- Authentication mechanisms
- File permissions

---

#### `secscan docker`
Validates Dockerfile and docker-compose.yml files.

```bash
secscan docker <config_path> [OPTIONS]

Options:
  --format [text|json]  Output format (default: text)
  --output PATH         Save output to file
```

**Dockerfile Checks:**
- Base image configuration
- User privileges (non-root)
- Health checks
- Secret management
- Image size optimization
- Privilege escalation prevention

**docker-compose Checks:**
- Privileged mode usage
- Hardcoded secrets
- Network isolation
- Resource limits
- Container capabilities

---

#### `secscan scan`
Batch scan a directory for configuration files.

```bash
secscan scan <directory> [OPTIONS]

Options:
  --format [text|json]  Output format (default: text)
```

---

#### `secscan version`
Show version information.

```bash
secscan version
```

## 📊 Output Examples

### Text Output

```
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

[CRITICAL] HSTS
  ❌ Issue: Strict-Transport-Security header is missing
  💡 Recommendation: Add 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'
  📋 CIS Benchmark: 2.5.1

[HIGH] Security Headers
  ❌ Issue: Missing critical security headers
  💡 Recommendation: Add security headers: X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy
  📋 CIS Benchmark: 2.5.2

============================================================
WARNINGS
============================================================

⚠ Server Tokens
  Issue: Server tokens are not explicitly disabled
  Recommendation: Add 'server_tokens off;' to hide nginx version
  CIS Benchmark: 2.2.2

============================================================
PASSED CHECKS
============================================================

✓ Access Logging: Access logging is configured
✓ Error Logging: Error logging is configured
✓ Timeouts: Timeout configuration: 4/4 configured

============================================================
```

### JSON Output

```json
{
  "status": "completed",
  "platform": "nginx",
  "critical_issues": 2,
  "high_issues": 1,
  "warnings": 3,
  "passes": 8,
  "issues": [
    {
      "severity": "critical",
      "check": "SSL/TLS Protocols",
      "issue": "ssl_protocols directive is missing",
      "recommendation": "Add 'ssl_protocols TLSv1.2 TLSv1.3;' to your nginx config",
      "cis_benchmark": "2.2.1"
    }
  ]
}
```

## 📋 Security Checks Reference

### Nginx Checks

| Check | Severity | Benchmark |
|-------|----------|-----------|
| SSL/TLS Protocols | Critical | 2.2.1 |
| SSL Ciphers | Warning | N/A |
| HSTS Header | High | 2.5.1 |
| Security Headers | High | 2.5.2 |
| Server Tokens | Medium | 2.2.2 |
| Access Logging | Medium | 2.4.1 |
| Error Logging | Medium | N/A |
| Timeouts | Medium | N/A |
| File Permissions | Medium | 2.1.1 |

### Docker Checks

| Check | Severity | Benchmark |
|-------|----------|-----------|
| Base Image | Critical | 4.1 |
| User Privileges | High | 4.2 |
| Secrets Management | Critical | 4.9 |
| Health Check | Medium | N/A |
| Privileged Mode | Critical | 5.4 |
| Resource Limits | Medium | N/A |
| Network Isolation | Medium | N/A |

## 🛠️ Development

### Project Structure

```
secscan/
├── secscan/
│   ├── __init__.py
│   ├── cli.py                 # CLI interface
│   └── validators/
│       ├── __init__.py
│       ├── nginx_validator.py
│       └── docker_validator.py
├── examples/
│   ├── nginx.conf
│   ├── Dockerfile
│   └── docker-compose.yml
├── tests/                      # (Coming soon)
├── setup.py
├── requirements.txt
└── README.md
```

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/z3robytek-lang/secscan.git
cd secscan

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .

# Test the CLI
secscan --help
```

### Adding a New Validator

1. Create a new file in `secscan/validators/` (e.g., `apache_validator.py`)
2. Implement a class inheriting from a base validator pattern
3. Add import to `secscan/validators/__init__.py`
4. Add new command to `secscan/cli.py`
5. Update documentation

Example:
```python
class ApacheValidator:
    def validate(self, config_path: str) -> Dict:
        """Validate Apache configuration"""
        # Implementation here
        pass
```

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Report Issues**: Find a bug? Open an issue on GitHub
2. **Add Features**: Want a new validator? Submit a PR
3. **Improve Docs**: Better documentation helps everyone
4. **Add Tests**: Help increase code coverage

### Contribution Guidelines

- Fork the repository
- Create a feature branch (`git checkout -b feature/amazing-feature`)
- Commit your changes (`git commit -m 'Add amazing feature'`)
- Push to the branch (`git push origin feature/amazing-feature`)
- Open a Pull Request

## 📝 Roadmap

- [ ] Kubernetes validator
- [ ] Apache validator
- [ ] Ansible playbook validator
- [ ] Custom rule support
- [ ] Web UI dashboard
- [ ] Database integration for reporting
- [ ] CI/CD integration examples
- [ ] Comprehensive test suite

## 📚 Resources

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Nginx Documentation](https://nginx.org/en/docs/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)

## ⚖️ License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**z3robytek-lang** - Security Researcher & Developer

- GitHub: [@z3robytek-lang](https://github.com/z3robytek-lang)

## 🙏 Acknowledgments

- CIS Benchmarks community
- OWASP security guidelines
- Open source security tools for inspiration

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/z3robytek-lang/secscan/issues)
- **Discussions**: [GitHub Discussions](https://github.com/z3robytek-lang/secscan/discussions)

---

**Remember**: Security is a journey, not a destination. Keep your configurations secure! 🔐
