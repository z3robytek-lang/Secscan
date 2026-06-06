from click.testing import CliRunner

from secscan.cli import main


def test_cli_version_command():
    runner = CliRunner()

    result = runner.invoke(main, ["version"])

    assert result.exit_code == 0
    assert "Secscan version" in result.output
