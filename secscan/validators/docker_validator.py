"""
Docker Configuration Security Validator
Validates Dockerfile and docker-compose.yml against security best practices
"""

import re
from typing import List, Dict


class DockerValidator:
    """Validates Docker configurations for security issues"""

    def __init__(self):
        self.issues = []
        self.warnings = []
        self.passes = []

    def validate(self, config_path: str) -> Dict:
        """
        Validate a Dockerfile or docker-compose.yml file
        
        Args:
            config_path: Path to Dockerfile or docker-compose.yml
            
        Returns:
            Dictionary with validation results
        """
        self.issues = []
        self.warnings = []
        self.passes = []
        
        try:
            with open(config_path, 'r') as f:
                config_content = f.read()
        except FileNotFoundError:
            return {
                "status": "error",
                "message": f"Configuration file not found: {config_path}",
                "critical_issues": 0,
                "warnings": 0,
                "passes": 0,
                "details": []
            }
        
        # Determine file type
        if 'Dockerfile' in config_path:
            self._validate_dockerfile(config_content)
        elif 'docker-compose' in config_path:
            self._validate_docker_compose(config_content)
        else:
            # Try to detect by content
            if 'version:' in config_content and 'services:' in config_content:
                self._validate_docker_compose(config_content)
            else:
                self._validate_dockerfile(config_content)
        
        return self._generate_report()

    def _validate_dockerfile(self, content: str):
        """Validate Dockerfile security"""
        lines = content.split('\n')
        
        # Check for base image
        base_image_found = False
        for line in lines:
            if line.strip().startswith('FROM'):
                base_image_found = True
                self._check_base_image(line)
        
        if not base_image_found:
            self.issues.append({
                "severity": "critical",
                "check": "Base Image",
                "issue": "No FROM instruction found",
                "recommendation": "Specify a base image using FROM instruction",
                "cis_benchmark": "4.1"
            })
        
        # Check for USER instruction
        user_found = any('USER' in line and not line.strip().startswith('#') 
                        for line in lines)
        if not user_found:
            self.issues.append({
                "severity": "high",
                "check": "User Privileges",
                "issue": "No USER instruction found - container runs as root",
                "recommendation": "Add 'USER nonroot' or create a non-privileged user",
                "cis_benchmark": "4.2"
            })
        else:
            self.passes.append({
                "check": "User Privileges",
                "message": "Container runs with non-root user"
            })
        
        # Check for HEALTHCHECK
        healthcheck_found = any('HEALTHCHECK' in line and not line.strip().startswith('#') 
                               for line in lines)
        if not healthcheck_found:
            self.warnings.append({
                "check": "Health Check",
                "issue": "No HEALTHCHECK instruction found",
                "recommendation": "Add HEALTHCHECK for container health monitoring"
            })
        else:
            self.passes.append({
                "check": "Health Check",
                "message": "HEALTHCHECK is configured"
            })
        
        # Check for RUN with sudo
        for line in lines:
            if 'RUN' in line and 'sudo' in line:
                self.warnings.append({
                    "check": "Sudo Usage",
                    "issue": "Using sudo in RUN instruction",
                    "recommendation": "Avoid sudo in Docker - use USER instruction instead",
                    "line": line.strip()
                })
        
        # Check for secrets in ENV
        for line in lines:
            if 'ENV' in line and any(secret in line.upper() for secret in 
                                     ['PASSWORD', 'SECRET', 'TOKEN', 'KEY', 'APIKEY']):
                self.issues.append({
                    "severity": "critical",
                    "check": "Secrets",
                    "issue": "Sensitive data in ENV variable",
                    "recommendation": "Use Docker secrets or build args, never hardcode secrets",
                    "cis_benchmark": "4.9",
                    "line": line.strip()
                })
        
        # Check for apt-get without cleanup
        has_apt_get = any('apt-get' in line for line in lines)
        if has_apt_get:
            has_cleanup = any('apt-get clean' in line or 'rm -rf /var/lib/apt/lists' in line 
                            for line in lines)
            if not has_cleanup:
                self.warnings.append({
                    "check": "Image Size",
                    "issue": "apt-get used without cleanup",
                    "recommendation": "Use 'apt-get clean && rm -rf /var/lib/apt/lists/*' to reduce image size"
                })
            else:
                self.passes.append({
                    "check": "Image Size",
                    "message": "apt-get is properly cleaned up"
                })

    def _check_base_image(self, from_line: str):
        """Check base image for security issues"""
        # Extract image name
        match = re.search(r'FROM\s+(\S+)', from_line)
        if not match:
            return
        
        image = match.group(1)
        
        # Check for 'latest' tag
        if image.endswith(':latest') or ':' not in image:
            self.warnings.append({
                "severity": "medium",
                "check": "Base Image Tag",
                "issue": f"Using 'latest' tag or no specific version: {image}",
                "recommendation": "Use specific version tags for reproducibility and security",
                "cis_benchmark": "4.1"
            })
        else:
            self.passes.append({
                "check": "Base Image Tag",
                "message": f"Specific image version is specified: {image}"
            })
        
        # Check for suspicious images
        if 'alpine' in image:
            self.passes.append({
                "check": "Base Image Size",
                "message": f"Lightweight base image used: {image}"
            })
        elif 'ubuntu' in image or 'debian' in image:
            self.warnings.append({
                "check": "Base Image Size",
                "issue": f"Full OS base image used: {image}",
                "recommendation": "Consider using alpine or distroless images for smaller footprint"
            })

    def _validate_docker_compose(self, content: str):
        """Validate docker-compose.yml security"""
        
        # Check for privileged mode
        if 'privileged: true' in content:
            self.issues.append({
                "severity": "critical",
                "check": "Privileged Mode",
                "issue": "Container running in privileged mode",
                "recommendation": "Avoid privileged mode unless absolutely necessary",
                "cis_benchmark": "5.4"
            })
        else:
            self.passes.append({
                "check": "Privileged Mode",
                "message": "Container not running in privileged mode"
            })
        
        # Check for secrets
        if 'environment:' in content:
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if 'environment:' in line:
                    # Check next lines for hardcoded secrets
                    for j in range(i+1, min(i+10, len(lines))):
                        next_line = lines[j]
                        if not next_line.strip() or next_line[0] not in ' \t':
                            break
                        if any(secret in next_line.upper() for secret in 
                              ['PASSWORD', 'SECRET', 'TOKEN', 'KEY']):
                            self.issues.append({
                                "severity": "critical",
                                "check": "Hardcoded Secrets",
                                "issue": "Secrets exposed in environment variables",
                                "recommendation": "Use Docker secrets or .env files"
                            })
        
        # Check for network configuration
        if 'networks:' not in content:
            self.warnings.append({
                "check": "Network Isolation",
                "issue": "No custom network defined",
                "recommendation": "Define custom networks for service isolation"
            })
        else:
            self.passes.append({
                "check": "Network Isolation",
                "message": "Custom network is configured"
            })
        
        # Check for resource limits
        if 'mem_limit' not in content and 'memswap_limit' not in content:
            self.warnings.append({
                "check": "Resource Limits",
                "issue": "No memory limits defined",
                "recommendation": "Set mem_limit and memswap_limit for DoS prevention"
            })
        else:
            self.passes.append({
                "check": "Resource Limits",
                "message": "Memory limits are configured"
            })

    def _generate_report(self) -> Dict:
        """Generate validation report"""
        return {
            "status": "completed",
            "platform": "docker",
            "critical_issues": len([i for i in self.issues if i.get("severity") == "critical"]),
            "high_issues": len([i for i in self.issues if i.get("severity") == "high"]),
            "medium_warnings": len([w for w in self.warnings if w.get("severity") == "medium"]),
            "warnings": len(self.warnings),
            "passes": len(self.passes),
            "issues": self.issues,
            "warnings_list": self.warnings,
            "passed_checks": self.passes,
        }
