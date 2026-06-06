from click.testing import CliRunner

from secscan.cli import main


def test_cli_version_command():
    runner = CliRunner()

    result = runner.invoke(main, ["version"])

    assert result.exit_code == 0
    assert "Secscan version" in result.output
def test_cli_k8s_command_detects_privileged_container(tmp_path):
    manifest = tmp_path / "deployment.yml"

    manifest.write_text("""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-nginx
spec:
  selector:
    matchLabels:
      app: insecure-nginx
  template:
    metadata:
      labels:
        app: insecure-nginx
    spec:
      containers:
        - name: nginx
          image: nginx:latest
          securityContext:
            privileged: true
""")

    runner = CliRunner()
    result = runner.invoke(main, ["k8s", str(manifest)])

    assert result.exit_code == 0
    assert "Privileged Container" in result.output
def test_scan_detects_compose_yaml_file(tmp_path):
    compose_file = tmp_path / "compose.yaml"

    compose_file.write_text("""
services:
  web:
    image: nginx:latest
""")

    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path)])

    assert result.exit_code == 0
    assert "1 docker-compose" in result.output
    assert "compose.yaml" in result.output
