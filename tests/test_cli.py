from click.testing import CliRunner
import yaml
from mai.cli import cli


def test_no_command():
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['--config-file', 'mai.yaml'], catch_exceptions=False)

    assert 'No profile configured' in result.output

def test_cli():
    runner = CliRunner()

    data = {'myprofile': {}}

    with runner.isolated_filesystem():
        with open('mai.yaml', 'w') as fd:
            yaml.safe_dump(data, fd)
        result = runner.invoke(cli, ['--config-file', 'mai.yaml', 'list'], catch_exceptions=False)

    assert 'Name' in result.output
