"""
Nginx Configuration Security Validator
Validates against Nginx hardening best practices and CIS benchmarks
"""

import re
from typing import List, Dict, Tuple


class NginxValidator:
    """Validates Nginx configurations for security issues"""

    def __init__(self):
        self.issues = []
        self.warnings = []
        self.passes = []
        self.config_lines = []

    def validate(self, config_path: str) -> Dict:
        """
        Validate a Nginx configuration file
        
        Args:
            config_path: Path to nginx.conf file
            
        Returns:
            Dictionary with validation results
        """
        self.issues = []
        self.warnings = []
        self.passes = []
        
        try:
            with open(config_path, 'r') as f:
                self.config_lines = f.readlines()
        except FileNotFoundError:
            return {
                "status": "error",
                "message": f"Configuration file not found: {config_path}",
                "critical_issues": 0,
                "warnings": 0,
                "passes": 0,
                "details": []
            }
        
        config_content = ''.join(self.config_lines)
        
        # Run all validators
        self._check_ssl_tls(config_content)
        self._check_headers(config_content)
        self._check_server_tokens(config_content)
        self._check_logging(config_content)
        self._check_timeouts(config_content)
        self._check_authentication(config_content)
        self._check_file_permissions(config_path)
        
        return self._generate_report()

    def _check_ssl_tls(self, config: str):
        """Check SSL/TLS configuration"""
        if 'ssl_protocols' not in config:
            self.issues.append({
                "severity": "critical",
                "check": "SSL/TLS Protocols",
                "issue": "ssl_protocols directive is missing",
                "recommendation": "Add 'ssl_protocols TLSv1.2 TLSv1.3;' to your nginx config",
                "cis_benchmark": "2.2.1"
            })
        else:
            if 'TLSv1.3' in config and 'TLSv1.2' in config:
                self.passes.append({
                    "check": "SSL/TLS Protocols",
                    "message": "Modern TLS versions (1.2+) are configured"
                })
            else:
                self.warnings.append({
                    "check": "SSL/TLS Protocols",
                    "issue": "Old TLS versions detected",
                    "recommendation": "Use only TLSv1.2 and TLSv1.3"
                })
        
        # Check cipher suites
        if 'ssl_ciphers' not in config:
            self.warnings.append({
                "check": "SSL Ciphers",
                "issue": "ssl_ciphers directive is missing (using default)",
                "recommendation": "Explicitly configure strong ciphers to ensure consistency"
            })
        
        # Check HSTS
        if 'add_header Strict-Transport-Security' not in config:
            self.issues.append({
                "severity": "high",
                "check": "HSTS",
                "issue": "Strict-Transport-Security header is missing",
                "recommendation": "Add 'add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;'",
                "cis_benchmark": "2.5.1"
            })
        else:
            self.passes.append({
                "check": "HSTS",
                "message": "HSTS header is configured"
            })

    def _check_headers(self, config: str):
        """Check security headers"""
        security_headers = {
            'X-Frame-Options': 'add_header X-Frame-Options "SAMEORIGIN"',
            'X-Content-Type-Options': 'add_header X-Content-Type-Options "nosniff"',
            'X-XSS-Protection': 'add_header X-XSS-Protection "1; mode=block"',
            'Referrer-Policy': 'add_header Referrer-Policy "strict-origin-when-cross-origin"',
        }
        
        found_headers = sum(1 for header in security_headers.keys() 
                           if f'add_header {header}' in config)
        
        if found_headers == 0:
            self.issues.append({
                "severity": "high",
                "check": "Security Headers",
                "issue": "Missing critical security headers",
                "recommendation": "Add security headers: X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy",
                "cis_benchmark": "2.5.2"
            })
        elif found_headers == len(security_headers):
            self.passes.append({
                "check": "Security Headers",
                "message": "All recommended security headers are configured"
            })
        else:
            self.warnings.append({
                "check": "Security Headers",
                "issue": f"Only {found_headers}/{len(security_headers)} security headers configured",
                "recommendation": "Configure all recommended security headers"
            })

    def _check_server_tokens(self, config: str):
        """Check if server tokens are disabled"""
        if 'server_tokens off' in config:
            self.passes.append({
                "check": "Server Tokens",
                "message": "Server tokens are disabled (version not exposed)"
            })
        else:
            self.warnings.append({
                "severity": "medium",
                "check": "Server Tokens",
                "issue": "Server tokens are not explicitly disabled",
                "recommendation": "Add 'server_tokens off;' to hide nginx version",
                "cis_benchmark": "2.2.2"
            })

    def _check_logging(self, config: str):
        """Check logging configuration"""
        if 'access_log' not in config:
            self.warnings.append({
                "check": "Access Logging",
                "issue": "Access logging is not configured",
                "recommendation": "Configure access_log for monitoring and auditing",
                "cis_benchmark": "2.4.1"
            })
        else:
            self.passes.append({
                "check": "Access Logging",
                "message": "Access logging is configured"
            })
        
        if 'error_log' not in config:
            self.warnings.append({
                "check": "Error Logging",
                "issue": "Error logging is not configured",
                "recommendation": "Configure error_log for error tracking"
            })
        else:
            self.passes.append({
                "check": "Error Logging",
                "message": "Error logging is configured"
            })

    def _check_timeouts(self, config: str):
        """Check timeout configurations"""
        timeouts = {
            'client_body_timeout': (5, 30),
            'client_header_timeout': (5, 30),
            'keepalive_timeout': (5, 75),
            'send_timeout': (5, 60),
        }
        
        configured_count = 0
        for timeout, (min_val, max_val) in timeouts.items():
            if timeout in config:
                configured_count += 1
        
        if configured_count == 0:
            self.warnings.append({
                "check": "Timeouts",
                "issue": "Timeout values are not explicitly configured",
                "recommendation": "Configure client_body_timeout, client_header_timeout, keepalive_timeout, send_timeout"
            })
        else:
            self.passes.append({
                "check": "Timeouts",
                "message": f"Timeout configuration: {configured_count}/{len(timeouts)} configured"
            })

    def _check_authentication(self, config: str):
        """Check authentication configuration"""
        if 'auth_basic' not in config and 'auth_request' not in config:
            self.warnings.append({
                "check": "Authentication",
                "issue": "No authentication mechanism configured",
                "recommendation": "Consider implementing auth_basic or auth_request for sensitive locations"
            })

    def _check_file_permissions(self, config_path: str):
        """Check file permissions"""
        import os
        import stat
        
        try:
            file_stat = os.stat(config_path)
            mode = file_stat.st_mode
            
            # Check if readable by world
            if mode & stat.S_IROTH:
                self.warnings.append({
                    "check": "File Permissions",
                    "issue": "Configuration file is world-readable",
                    "recommendation": "Restrict permissions: chmod 644 nginx.conf",
                    "cis_benchmark": "2.1.1"
                })
            else:
                self.passes.append({
                    "check": "File Permissions",
                    "message": "Configuration file permissions are appropriately restricted"
                })
        except Exception as e:
            self.warnings.append({
                "check": "File Permissions",
                "issue": f"Could not check file permissions: {str(e)}"
            })

    def _generate_report(self) -> Dict:
        """Generate validation report"""
        return {
            "status": "completed",
            "platform": "nginx",
            "critical_issues": len([i for i in self.issues if i.get("severity") == "critical"]),
            "high_issues": len([i for i in self.issues if i.get("severity") == "high"]),
            "medium_warnings": len([i for i in self.warnings if i.get("severity") == "medium"]),
            "warnings": len(self.warnings),
            "passes": len(self.passes),
            "issues": self.issues,
            "warnings_list": self.warnings,
            "passed_checks": self.passes,
        }
