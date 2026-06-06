from secscan.validators.nginx_validator import NginxValidator


def test_nginx_detects_server_tokens_on(tmp_path):
    config_file = tmp_path / "nginx.conf"

    config_file.write_text("""
    http {
        server_tokens on;
    }
    """)

    validator = NginxValidator()
    results = validator.validate(str(config_file))

    assert any(
        item.get("check") == "Server Tokens"
        for item in results["warnings_list"]
    )
