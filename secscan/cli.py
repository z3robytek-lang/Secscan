"""
Secscan CLI - Command Line Interface
"""

import json
from pathlib import Path

import click
from colorama import Fore, init
from tabulate import tabulate

from secscan.validators import NginxValidator, DockerValidator, KubernetesValidator


# Initialize colorama
init(autoreset=True)


@click.group()
def main():
    """
    Secscan - Security Configuration Validator

    Validate your infrastructure configurations against security best practices.
    """
    pass


@main.command()
@click.argument("config_path", type=click.Path(exists=True))
@click.option(
    "--format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
@click.option("--output", type=click.Path(), help="Output file path")
def nginx(config_path, format, output):
    """
    Validate Nginx configuration file.

    Example: secscan nginx /etc/nginx/nginx.conf
    """
    validator = NginxValidator()
    result = validator.validate(config_path)

    _display_results(result, format, output, "Nginx")


@main.command()
@click.argument("config_path", type=click.Path(exists=True))
@click.option(
    "--format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
@click.option("--output", type=click.Path(), help="Output file path")
def docker(config_path, format, output):
    """
    Validate Dockerfile or docker-compose.yml.

    Example: secscan docker Dockerfile
    Example: secscan docker docker-compose.yml
    """
    validator = DockerValidator()
    result = validator.validate(config_path)

    _display_results(result, format, output, "Docker")


@main.command()
@click.argument("config_path", type=click.Path(exists=True))
@click.option(
    "--format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
@click.option("--output", type=click.Path(), help="Output file path")
def k8s(config_path, format, output):
    """
    Validate Kubernetes YAML manifest.

    Example: secscan k8s deployment.yml
    """
    validator = KubernetesValidator()
    result = validator.validate(config_path)

    _display_results(result, format, output, "Kubernetes")


@main.command()
@click.argument(
    "directory",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    "--format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
def scan(directory, format):
    """
    Scan entire directory for configuration files.

    Example: secscan scan /etc/nginx/
    """
    nginx_files = list(Path(directory).glob("**/nginx.conf"))
    docker_files = list(Path(directory).glob("**/Dockerfile"))
    compose_files = list(Path(directory).glob("**/docker-compose.yml"))
    kubernetes_files = _find_kubernetes_files(directory)

    all_results = []

    click.echo(f"\n{Fore.CYAN}Scanning directory: {directory}")
    click.echo(
        f"Found {len(nginx_files)} Nginx, "
        f"{len(docker_files)} Dockerfile, "
        f"{len(compose_files)} docker-compose, "
        f"{len(kubernetes_files)} Kubernetes files\n"
    )

    for nginx_file in nginx_files:
        validator = NginxValidator()
        result = validator.validate(str(nginx_file))
        result["file"] = str(nginx_file)
        all_results.append(result)

    for docker_file in docker_files:
        validator = DockerValidator()
        result = validator.validate(str(docker_file))
        result["file"] = str(docker_file)
        all_results.append(result)

    for compose_file in compose_files:
        validator = DockerValidator()
        result = validator.validate(str(compose_file))
        result["file"] = str(compose_file)
        all_results.append(result)

    for kubernetes_file in kubernetes_files:
        validator = KubernetesValidator()
        result = validator.validate(str(kubernetes_file))
        result["file"] = str(kubernetes_file)
        all_results.append(result)

    if format == "json":
        click.echo(json.dumps(all_results, indent=2))
    else:
        _display_scan_summary(all_results)


@main.command()
def version():
    """Show version information."""
    from secscan import __version__

    click.echo(f"Secscan version {__version__}")


def _find_kubernetes_files(directory):
    """
    Find possible Kubernetes YAML files.

    This keeps the first implementation simple:
    it scans YAML/YML files and selects the ones that contain apiVersion and kind.
    """
    candidates = list(Path(directory).glob("**/*.yml"))
    candidates += list(Path(directory).glob("**/*.yaml"))

    kubernetes_files = []

    for file_path in candidates:
        try:
            content = file_path.read_text()
        except UnicodeDecodeError:
            continue

        if "apiVersion:" in content and "kind:" in content:
            kubernetes_files.append(file_path)

    return kubernetes_files


def _display_results(result: dict, format: str, output_path: str = None, platform: str = ""):
    """Display validation results."""

    if result["status"] == "error":
        click.echo(f"\n{Fore.RED}❌ Error: {result['message']}\n")
        return

    if format == "json":
        output_text = json.dumps(result, indent=2)
        if output_path:
            with open(output_path, "w") as f:
                f.write(output_text)
            click.echo(f"{Fore.GREEN}✓ Report saved to {output_path}")
        else:
            click.echo(output_text)
        return

    click.echo(f"\n{Fore.CYAN}{'=' * 60}")
    click.echo(f"{Fore.CYAN}{platform} Configuration Security Validation")
    click.echo(f"{Fore.CYAN}{'=' * 60}\n")

    click.echo(f"{Fore.RED}Critical Issues: {result['critical_issues']}")
    click.echo(f"{Fore.YELLOW}High Issues: {result['high_issues']}")
    click.echo(f"{Fore.YELLOW}Warnings: {result['warnings']}")
    click.echo(f"{Fore.GREEN}Passed Checks: {result['passes']}\n")

    if result["issues"]:
        click.echo(f"\n{Fore.RED}{'=' * 60}")
        click.echo(f"{Fore.RED}ISSUES")
        click.echo(f"{Fore.RED}{'=' * 60}")

        for issue in result["issues"]:
            severity_color = (
                Fore.RED if issue.get("severity") == "critical" else Fore.YELLOW
            )
            click.echo(
                f"\n{severity_color}[{issue.get('severity', 'ISSUE').upper()}] "
                f"{issue['check']}"
            )
            click.echo(f"{Fore.WHITE}  ❌ Issue: {issue['issue']}")
            click.echo(f"{Fore.WHITE}  💡 Recommendation: {issue['recommendation']}")

            if "cis_benchmark" in issue:
                click.echo(f"{Fore.WHITE}  📋 CIS Benchmark: {issue['cis_benchmark']}")

            if "line" in issue:
                click.echo(f"{Fore.WHITE}  📝 Line: {issue['line']}")

    if result["warnings_list"]:
        click.echo(f"\n{Fore.YELLOW}{'=' * 60}")
        click.echo(f"{Fore.YELLOW}WARNINGS")
        click.echo(f"{Fore.YELLOW}{'=' * 60}")

        for warning in result["warnings_list"]:
            click.echo(f"\n{Fore.YELLOW}⚠ {warning['check']}")
            click.echo(f"{Fore.WHITE}  Issue: {warning['issue']}")
            click.echo(f"{Fore.WHITE}  Recommendation: {warning['recommendation']}")

            if "cis_benchmark" in warning:
                click.echo(f"{Fore.WHITE}  📋 CIS Benchmark: {warning['cis_benchmark']}")

            if "line" in warning:
                click.echo(f"{Fore.WHITE}  📝 Line: {warning['line']}")

    if result["passed_checks"]:
        click.echo(f"\n{Fore.GREEN}{'=' * 60}")
        click.echo(f"{Fore.GREEN}PASSED CHECKS")
        click.echo(f"{Fore.GREEN}{'=' * 60}")

        for passed in result["passed_checks"]:
            click.echo(f"{Fore.GREEN}✓ {passed['check']}: {passed['message']}")

    click.echo(f"\n{Fore.CYAN}{'=' * 60}\n")


def _display_scan_summary(results: list):
    """Display scan summary for multiple files."""

    summary_data = []
    total_critical = 0
    total_high = 0
    total_warnings = 0
    total_passed = 0

    for result in results:
        total_critical += result["critical_issues"]
        total_high += result["high_issues"]
        total_warnings += result["warnings"]
        total_passed += result["passes"]

        summary_data.append(
            [
                result["file"],
                result["platform"],
                result["critical_issues"],
                result["high_issues"],
                result["warnings"],
                result["passes"],
            ]
        )

    click.echo(f"\n{Fore.CYAN}{'=' * 80}")
    click.echo(f"{Fore.CYAN}Security Scan Summary")
    click.echo(f"{Fore.CYAN}{'=' * 80}\n")

    click.echo(
        tabulate(
            summary_data,
            headers=["File", "Platform", "Critical", "High", "Warnings", "Passed"],
            tablefmt="grid",
        )
    )

    click.echo(f"\n{Fore.RED}Total Critical Issues: {total_critical}")
    click.echo(f"{Fore.YELLOW}Total High Issues: {total_high}")
    click.echo(f"{Fore.YELLOW}Total Warnings: {total_warnings}")
    click.echo(f"{Fore.GREEN}Total Passed: {total_passed}\n")


if __name__ == "__main__":
    main()
