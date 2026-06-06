"""
Kubernetes Configuration Security Validator
Validates Kubernetes YAML manifests against security best practices.
"""

from typing import Dict, List

import yaml


class KubernetesValidator:
    """Validates Kubernetes manifests for security issues."""

    def __init__(self):
        self.issues = []
        self.warnings = []
        self.passes = []

    def validate(self, config_path: str) -> Dict:
        """
        Validate a Kubernetes YAML manifest.

        Args:
            config_path: Path to Kubernetes YAML file

        Returns:
            Dictionary with validation results
        """
        self.issues = []
        self.warnings = []
        self.passes = []

        try:
            with open(config_path, "r") as f:
                documents = list(yaml.safe_load_all(f))
        except FileNotFoundError:
            return {
                "status": "error",
                "message": f"Configuration file not found: {config_path}",
                "critical_issues": 0,
                "high_issues": 0,
                "medium_warnings": 0,
                "warnings": 0,
                "passes": 0,
                "issues": [],
                "warnings_list": [],
                "passed_checks": [],
            }
        except yaml.YAMLError as exc:
            return {
                "status": "error",
                "message": f"Invalid YAML file: {exc}",
                "critical_issues": 0,
                "high_issues": 0,
                "medium_warnings": 0,
                "warnings": 0,
                "passes": 0,
                "issues": [],
                "warnings_list": [],
                "passed_checks": [],
            }

        for document in documents:
            if not document:
                continue

            self._validate_document(document)

        return self._generate_report()

    def _validate_document(self, document: Dict):
        kind = document.get("kind", "Unknown")
        metadata = document.get("metadata", {})
        name = metadata.get("name", "unknown")

        pod_spec = self._extract_pod_spec(document)

        if not pod_spec:
            self.warnings.append({
                "check": "Pod Spec",
                "issue": f"No pod specification found in {kind}/{name}",
                "recommendation": "Validate Kubernetes workload resources such as Pod, Deployment, DaemonSet, StatefulSet, Job or CronJob.",
            })
            return

        self._check_host_namespace_usage(pod_spec, kind, name)

        containers = pod_spec.get("containers", [])
        init_containers = pod_spec.get("initContainers", [])

        all_containers = containers + init_containers

        if not all_containers:
            self.issues.append({
                "severity": "high",
                "check": "Containers",
                "issue": f"No containers defined in {kind}/{name}",
                "recommendation": "Define at least one container in the Kubernetes workload.",
            })
            return

        for container in all_containers:
            self._check_container_security(container, kind, name)

    def _extract_pod_spec(self, document: Dict):
        kind = document.get("kind")

        if kind == "Pod":
            return document.get("spec", {})

        if kind in ["Deployment", "DaemonSet", "StatefulSet", "ReplicaSet"]:
            return (
                document
                .get("spec", {})
                .get("template", {})
                .get("spec", {})
            )

        if kind == "Job":
            return (
                document
                .get("spec", {})
                .get("template", {})
                .get("spec", {})
            )

        if kind == "CronJob":
            return (
                document
                .get("spec", {})
                .get("jobTemplate", {})
                .get("spec", {})
                .get("template", {})
                .get("spec", {})
            )

        return None

    def _check_host_namespace_usage(self, pod_spec: Dict, kind: str, name: str):
        dangerous_fields = {
            "hostNetwork": "Host network namespace is enabled",
            "hostPID": "Host PID namespace is enabled",
            "hostIPC": "Host IPC namespace is enabled",
        }

        for field, issue in dangerous_fields.items():
            if pod_spec.get(field) is True:
                self.issues.append({
                    "severity": "critical",
                    "check": field,
                    "issue": f"{issue} in {kind}/{name}",
                    "recommendation": f"Avoid using {field}: true unless it is strictly required.",
                })
            else:
                self.passes.append({
                    "check": field,
                    "message": f"{field} is not enabled in {kind}/{name}",
                })

    def _check_container_security(self, container: Dict, kind: str, workload_name: str):
        container_name = container.get("name", "unknown")
        image = container.get("image", "")
        security_context = container.get("securityContext", {})

        if image.endswith(":latest") or ":" not in image:
            self.warnings.append({
                "severity": "medium",
                "check": "Image Tag",
                "issue": f"Container {container_name} in {kind}/{workload_name} uses an unpinned image tag: {image}",
                "recommendation": "Use a specific image version instead of latest or an implicit latest tag.",
            })
        else:
            self.passes.append({
                "check": "Image Tag",
                "message": f"Container {container_name} uses pinned image tag: {image}",
            })

        if security_context.get("privileged") is True:
            self.issues.append({
                "severity": "critical",
                "check": "Privileged Container",
                "issue": f"Container {container_name} in {kind}/{workload_name} runs in privileged mode",
                "recommendation": "Set securityContext.privileged to false or remove it.",
            })

        if security_context.get("allowPrivilegeEscalation") is not False:
            self.warnings.append({
                "severity": "medium",
                "check": "Privilege Escalation",
                "issue": f"Container {container_name} in {kind}/{workload_name} does not disable privilege escalation",
                "recommendation": "Set securityContext.allowPrivilegeEscalation: false.",
            })
        else:
            self.passes.append({
                "check": "Privilege Escalation",
                "message": f"Container {container_name} disables privilege escalation",
            })

        if security_context.get("runAsNonRoot") is not True:
            self.issues.append({
                "severity": "high",
                "check": "Run As Non Root",
                "issue": f"Container {container_name} in {kind}/{workload_name} is not explicitly configured to run as non-root",
                "recommendation": "Set securityContext.runAsNonRoot: true.",
            })
        else:
            self.passes.append({
                "check": "Run As Non Root",
                "message": f"Container {container_name} is configured to run as non-root",
            })

        if security_context.get("readOnlyRootFilesystem") is not True:
            self.warnings.append({
                "severity": "medium",
                "check": "Read Only Root Filesystem",
                "issue": f"Container {container_name} in {kind}/{workload_name} does not use a read-only root filesystem",
                "recommendation": "Set securityContext.readOnlyRootFilesystem: true where possible.",
            })
        else:
            self.passes.append({
                "check": "Read Only Root Filesystem",
                "message": f"Container {container_name} uses a read-only root filesystem",
            })

        resources = container.get("resources", {})
        limits = resources.get("limits", {})

        if not limits:
            self.warnings.append({
                "severity": "medium",
                "check": "Resource Limits",
                "issue": f"Container {container_name} in {kind}/{workload_name} has no resource limits",
                "recommendation": "Set CPU and memory limits to reduce DoS risk.",
            })
        else:
            self.passes.append({
                "check": "Resource Limits",
                "message": f"Container {container_name} has resource limits configured",
            })

        env_vars = container.get("env", [])
        for env in env_vars:
            env_name = env.get("name", "")
            if any(secret in env_name.upper() for secret in ["PASSWORD", "SECRET", "TOKEN", "KEY"]):
                self.issues.append({
                    "severity": "critical",
                    "check": "Hardcoded Secrets",
                    "issue": f"Possible secret exposed in environment variable {env_name} in container {container_name}",
                    "recommendation": "Use Kubernetes Secrets instead of hardcoded environment variables.",
                })

    def _generate_report(self) -> Dict:
        """Generate validation report."""
        return {
            "status": "completed",
            "platform": "kubernetes",
            "critical_issues": len([i for i in self.issues if i.get("severity") == "critical"]),
            "high_issues": len([i for i in self.issues if i.get("severity") == "high"]),
            "medium_warnings": len([w for w in self.warnings if w.get("severity") == "medium"]),
            "warnings": len(self.warnings),
            "passes": len(self.passes),
            "issues": self.issues,
            "warnings_list": self.warnings,
            "passed_checks": self.passes,
        }
