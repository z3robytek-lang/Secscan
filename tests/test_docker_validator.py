from secscan.validators.docker_validator import DockerValidator


def test_docker_detects_latest_tag(tmp_path):
    dockerfile = tmp_path / "Dockerfile"

    dockerfile.write_text("""
    FROM nginx:latest
    COPY . /app
    """)

    validator = DockerValidator()
    results = validator.validate(str(dockerfile))

    assert any(
        item.get("check") == "Base Image Tag"
        for item in results["warnings_list"]
    )
