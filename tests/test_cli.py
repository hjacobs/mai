from click.testing import CliRunner
from unittest.mock import MagicMock
import yaml
from mai.cli import cli, login_with_profile
import mai
import os
import aws_saml_login.saml
import time
import pytest

TEST_CONFIG = {'example-Administrator': {'saml_identity_provider_url': 'https://auth.example.com',
                                         'saml_role': ['arn:aws:iam::911:saml-provider/Shibboleth',
                                                       'arn:aws:iam::911:role/Shibboleth-Administrator',
                                                       'example'],
                                         'saml_user': 'foo.bar@example.com'},
               'example-User': {'saml_identity_provider_url': 'https://auth.example.com',
                                'saml_role': ['arn:aws:iam::911:saml-provider/Shibboleth',
                                              'arn:aws:iam::911:role/Shibboleth-User',
                                              'example'],
                                'saml_user': 'foo.bar@example.com'}}
SAML_RESPONSE_0_ROLES = ('''<xml xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Assertion>¬
            </Assertion></xml>''', [])
SAML_RESPONSE_1_ROLE = ('''<xml xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Assertion>¬
                           <Attribute FriendlyName="Role" Name="https://aws.amazon.com/SAML/Attributes/Role">¬
                           <AttributeValue>arn:aws:iam::911:saml-provider/Shibboleth,arn:aws:iam::911:role/Shibboleth-User</AttributeValue>¬
                           </Attribute>¬
                           </Assertion></xml>''',
                        [('arn:aws:iam::911:saml-provider/Shibboleth', 'arn:aws:iam::911:role/Shibboleth-User', None)])
SAML_RESPONSE_2_ROLES = ('''<xml xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Assertion>¬
                            <Attribute FriendlyName="Role" Name="https://aws.amazon.com/SAML/Attributes/Role">¬
                            <AttributeValue>arn:aws:iam::911:saml-provider/Shibboleth,arn:aws:iam::911:role/Shibboleth-User</AttributeValue>¬
                            </Attribute>¬
                            <Attribute FriendlyName="Role" Name="https://aws.amazon.com/SAML/Attributes/Role">¬
                            <AttributeValue>arn:aws:iam::911:saml-provider/Shibboleth,arn:aws:iam::911:role/Shibboleth-Administrator</AttributeValue>¬
                            </Attribute>¬
                            </Assertion></xml>''',
                         [('arn:aws:iam::911:saml-provider/Shibboleth',
                           'arn:aws:iam::911:role/Shibboleth-User',
                           'example'),
                          ('arn:aws:iam::911:saml-provider/Shibboleth',
                           'arn:aws:iam::911:role/Shibboleth-Administrator',
                           'example')])


def test_version():
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['--version'], catch_exceptions=False)

    assert 'Mai {}'.format(mai.__version__) in result.output


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
        result = runner.invoke(cli, ['--config-file', 'mai.yaml'], catch_exceptions=False)

    assert 'Usage: cli' in result.output
    assert 'Missing identity provider URL' in result.output


def test_cli_002():
    runner = CliRunner()

    data = {'myprofile': {'saml_identity_provider_url': 'https://auth.example.com'}}

    with runner.isolated_filesystem():
        with open('mai.yaml', 'w') as fd:
            yaml.safe_dump(data, fd)
        result = runner.invoke(cli, ['--config-file', 'mai.yaml'], catch_exceptions=False)

    assert 'Usage: cli' in result.output
    assert 'Missing SAML username' in result.output


def test_cli_global():
    runner = CliRunner()

    data = {'global': {'default_profile': 'myprofile'}, 'myprofile': {}}

    with runner.isolated_filesystem():
        with open('mai.yaml', 'w') as fd:
            yaml.safe_dump(data, fd)
        result = runner.invoke(cli, ['--config-file', 'mai.yaml'], catch_exceptions=False)

    assert 'Usage: cli' in result.output
    assert 'Missing identity provider URL' in result.output


def test_cli_list():
    runner = CliRunner()

    data = {'myprofile': {}}

    with runner.isolated_filesystem():
        with open('mai.yaml', 'w') as fd:
            yaml.safe_dump(data, fd)
        result = runner.invoke(cli, ['--config-file', 'mai.yaml', 'list'], catch_exceptions=False)

    assert 'Name' in result.output


def test_create_001_missing_argument():
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['--config-file', 'mai.yaml', 'create'], catch_exceptions=False)

    assert 'Usage: cli' in result.output
    assert 'Missing argument "profile-name"' in result.output


def test_create_002_one_role(monkeypatch):
    monkeypatch.setattr('keyring.get_password', MagicMock(return_value=''))
    monkeypatch.setattr('keyring.set_password', MagicMock(return_value=''))
    monkeypatch.setattr('mai.cli.authenticate', MagicMock(return_value=SAML_RESPONSE_1_ROLE))

    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['--config-file', 'mai.yaml', 'create', 'foobar'],
                               catch_exceptions=False, input='auth.example.com\nfoo.bar@example.com\n1234567\n')

        workingdir = os.getcwd()
        assert os.path.exists('mai.yaml')
        with open('mai.yaml') as fd:
            generated_config = yaml.safe_load(fd)

    assert generated_config['foobar']['saml_identity_provider_url'] == 'https://auth.example.com'
    assert generated_config['foobar']['saml_role'][1] == 'arn:aws:iam::911:role/Shibboleth-User'
    assert generated_config['foobar']['saml_user'] == 'foo.bar@example.com'
    assert 'Identity provider URL: auth.example.com' in result.output
    assert 'SAML username: foo.bar@example.com' in result.output
    assert 'Authenticating against https://auth.example.com.. OK' in result.output
    assert 'Storing new profile in {}.. OK'.format(os.path.join(workingdir, 'mai.yaml')) in result.output


def test_create_003_no_roles(monkeypatch):
    monkeypatch.setattr('keyring.get_password', MagicMock(return_value=''))
    monkeypatch.setattr('keyring.set_password', MagicMock(return_value=''))
    monkeypatch.setattr('mai.cli.authenticate', MagicMock(return_value=SAML_RESPONSE_0_ROLES))

    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['--config-file', 'mai.yaml', 'create', 'foobar'],
                               catch_exceptions=False, input='auth.example.com\nfoo.bar@example.com\n1234567\n')

    assert 'No roles found' in result.output
    assert result.exit_code == 1


def test_create_004_two_roles(monkeypatch):
    monkeypatch.setattr('keyring.get_password', MagicMock(return_value=''))
    monkeypatch.setattr('keyring.set_password', MagicMock(return_value=''))
    monkeypatch.setattr('mai.cli.authenticate', MagicMock(return_value=SAML_RESPONSE_2_ROLES))

    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['--config-file', 'mai.yaml', 'create', 'foobar'],
                               catch_exceptions=False, input='auth.example.com\nfoo.bar@example.com\n1234567\n1\n')

        workingdir = os.getcwd()
        assert os.path.exists('mai.yaml')
        with open('mai.yaml') as fd:
            generated_config = yaml.safe_load(fd)

    assert generated_config['foobar']['saml_identity_provider_url'] == 'https://auth.example.com'
    assert generated_config['foobar']['saml_role'][1] == 'arn:aws:iam::911:role/Shibboleth-Administrator'
    assert generated_config['foobar']['saml_user'] == 'foo.bar@example.com'
    assert 'Identity provider URL: auth.example.com' in result.output
    assert 'SAML username: foo.bar@example.com' in result.output
    assert 'Authenticating against https://auth.example.com.. OK' in result.output
    assert 'Storing new profile in {}.. OK'.format(os.path.join(workingdir, 'mai.yaml')) in result.output


def test_create_005_two_roles_options(monkeypatch):
    monkeypatch.setattr('keyring.get_password', MagicMock(return_value=''))
    monkeypatch.setattr('keyring.set_password', MagicMock(return_value=''))
    monkeypatch.setattr('mai.cli.authenticate', MagicMock(return_value=SAML_RESPONSE_2_ROLES))

    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['--config-file', 'mai.yaml',
                                     'create', 'foobar',
                                     '--url', 'auth.example.com',
                                     '--user', 'foo.bar@example.com'],
                               catch_exceptions=False, input='1234567\n1\n')

        workingdir = os.getcwd()
        assert os.path.exists('mai.yaml')
        with open('mai.yaml') as fd:
            generated_config = yaml.safe_load(fd)

    assert generated_config['foobar']['saml_identity_provider_url'] == 'https://auth.example.com'
    assert generated_config['foobar']['saml_role'][1] == 'arn:aws:iam::911:role/Shibboleth-Administrator'
    assert generated_config['foobar']['saml_user'] == 'foo.bar@example.com'
    assert 'Authenticating against https://auth.example.com.. OK' in result.output
    assert 'Storing new profile in {}.. OK'.format(os.path.join(workingdir, 'mai.yaml')) in result.output


def test_create_006_authentication_failed(monkeypatch):
    monkeypatch.setattr('keyring.get_password', MagicMock(return_value=''))
    monkeypatch.setattr('keyring.set_password', MagicMock(return_value=''))

    def my_authenticate_mock(url, user, saml_password):
        if saml_password == 'wrong':
            raise aws_saml_login.saml.AuthenticationFailed()
        else:
            return SAML_RESPONSE_2_ROLES

    monkeypatch.setattr('mai.cli.authenticate', my_authenticate_mock)

    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['--config-file', 'mai.yaml', 'create', 'foobar'],
                               catch_exceptions=False,
                               input='auth.example.com\nfoo.bar@example.com\nwrong\n1234567\n2\n')
        workingdir = os.getcwd()
        assert os.path.exists('mai.yaml')
        with open('mai.yaml') as fd:
            generated_config = yaml.safe_load(fd)

    assert generated_config['foobar']['saml_identity_provider_url'] == 'https://auth.example.com'
    assert generated_config['foobar']['saml_role'][1] == 'arn:aws:iam::911:role/Shibboleth-User'
    assert generated_config['foobar']['saml_user'] == 'foo.bar@example.com'
    assert 'Identity provider URL: auth.example.com' in result.output
    assert 'SAML username: foo.bar@example.com' in result.output
    assert 'Authenticating against https://auth.example.com.. Authentication Failed' in result.output
    assert 'Please check your username/password and try again.' in result.output
    assert 'Authenticating against https://auth.example.com.. OK' in result.output
    assert 'Storing new profile in {}.. OK'.format(os.path.join(workingdir, 'mai.yaml')) in result.output


def test_create_all_001(monkeypatch):
    monkeypatch.setattr('keyring.get_password', MagicMock(return_value=''))
    monkeypatch.setattr('keyring.set_password', MagicMock(return_value=''))
    monkeypatch.setattr('mai.cli.authenticate', MagicMock(return_value=SAML_RESPONSE_2_ROLES))

    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['--config-file', 'mai.yaml', 'create-all'],
                               catch_exceptions=False, input='auth.example.com\nfoo.bar@example.com\n123456\n')

        workingdir = os.getcwd()
        assert os.path.exists('mai.yaml')
        with open('mai.yaml') as fd:
            generated_config = yaml.safe_load(fd)

    assert generated_config['example-Administrator']['saml_identity_provider_url'] == 'https://auth.example.com'
    assert generated_config['example-Administrator']['saml_role'][1] == 'arn:aws:iam::911:role/Shibboleth-Administrator'
    assert generated_config['example-Administrator']['saml_user'] == 'foo.bar@example.com'
    assert generated_config['example-User']['saml_identity_provider_url'] == 'https://auth.example.com'
    assert generated_config['example-User']['saml_role'][1] == 'arn:aws:iam::911:role/Shibboleth-User'
    assert generated_config['example-User']['saml_user'] == 'foo.bar@example.com'
    assert 'Identity provider URL: auth.example.com' in result.output
    assert 'SAML username: foo.bar@example.com' in result.output
    assert 'Authenticating against https://auth.example.com.. OK' in result.output
    assert 'Storing new profile in {}.. OK'.format(os.path.join(workingdir, 'mai.yaml')) in result.output


def test_create_all_002_no_roles(monkeypatch):
    monkeypatch.setattr('keyring.get_password', MagicMock(return_value=''))
    monkeypatch.setattr('keyring.set_password', MagicMock(return_value=''))
    monkeypatch.setattr('mai.cli.authenticate', MagicMock(return_value=SAML_RESPONSE_0_ROLES))

    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['--config-file', 'mai.yaml', 'create-all'],
                               catch_exceptions=False, input='auth.example.com\nfoo.bar@example.com\n1234567\n')

    assert 'No roles found' in result.output
    assert result.exit_code == 1


def test_create_all_003_one_role(monkeypatch):
    monkeypatch.setattr('keyring.get_password', MagicMock(return_value=''))
    monkeypatch.setattr('keyring.set_password', MagicMock(return_value=''))
    monkeypatch.setattr('mai.cli.authenticate', MagicMock(return_value=SAML_RESPONSE_1_ROLE))

    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['--config-file', 'mai.yaml', 'create-all'],
                               catch_exceptions=False, input='auth.example.com\nfoo.bar@example.com\n123456\n')

        workingdir = os.getcwd()
        assert os.path.exists('mai.yaml')
        with open('mai.yaml') as fd:
            generated_config = yaml.safe_load(fd)
    assert generated_config['default-User']['saml_identity_provider_url'] == 'https://auth.example.com'
    assert generated_config['default-User']['saml_role'][1] == 'arn:aws:iam::911:role/Shibboleth-User'
    assert generated_config['default-User']['saml_user'] == 'foo.bar@example.com'
    assert 'Identity provider URL: auth.example.com' in result.output
    assert 'SAML username: foo.bar@example.com' in result.output
    assert 'Authenticating against https://auth.example.com.. OK' in result.output
    assert 'Storing new profile in {}.. OK'.format(os.path.join(workingdir, 'mai.yaml')) in result.output


def test_set_default_001(monkeypatch):
    data = TEST_CONFIG

    runner = CliRunner()

    with runner.isolated_filesystem():
        with open('mai.yaml', 'w') as fd:
            yaml.dump(data, fd)
        result = runner.invoke(cli, ['--config-file', 'mai.yaml', 'set-default', 'example-User'])

        workingdir = os.getcwd()
        assert os.path.exists('mai.yaml')
        with open('mai.yaml') as fd:
            generated_config = yaml.safe_load(fd)

    assert generated_config['global']['default_profile'] == 'example-User'
    assert 'Storing configuration in {}.. OK'.format(os.path.join(workingdir, 'mai.yaml')) in result.output


def test_set_default_002_unknown_profile(monkeypatch):
    data = TEST_CONFIG

    runner = CliRunner()

    with runner.isolated_filesystem():
        with open('mai.yaml', 'w') as fd:
            yaml.dump(data, fd)
        result = runner.invoke(cli, ['--config-file', 'mai.yaml', 'set-default', 'foobar-User'])

    assert 'Profile "foobar-User" does not exist' in result.output
    assert result.exit_code == 2


def test_delete_profile_001(monkeypatch):
    data = TEST_CONFIG

    runner = CliRunner()

    with runner.isolated_filesystem():
        with open('mai.yaml', 'w') as fd:
            yaml.dump(data, fd)
        result = runner.invoke(cli, ['--config-file', 'mai.yaml', 'delete', 'example-User'])

        workingdir = os.getcwd()
        assert os.path.exists('mai.yaml')
        with open('mai.yaml') as fd:
            generated_config = yaml.safe_load(fd)

    assert 'example-User' not in generated_config
    assert 'Deleting profile from {}.. OK'.format(os.path.join(workingdir, 'mai.yaml')) in result.output


def test_delete_profile_002_unknown_profile(monkeypatch):
    data = TEST_CONFIG

    runner = CliRunner()

    with runner.isolated_filesystem():
        with open('mai.yaml', 'w') as fd:
            yaml.dump(data, fd)
        result = runner.invoke(cli, ['--config-file', 'mai.yaml', 'delete', 'foobar-User'])

    assert 'Profile "foobar-User" does not exist' in result.output
    assert result.exit_code == 2


def test_login_001(monkeypatch):

    monkeypatch.setattr('keyring.get_password', MagicMock(return_value='123456'))
    monkeypatch.setattr('keyring.set_password', MagicMock(return_value=''))
    monkeypatch.setattr('mai.cli.authenticate', MagicMock(return_value=SAML_RESPONSE_2_ROLES))
    monkeypatch.setattr('mai.cli.assume_role', MagicMock(return_value=('KEYID', 'SECRET', 'SESSION_TOKEN')))
    monkeypatch.setattr('mai.cli.write_aws_credentials', MagicMock)

    class sleep_counter:
        count = 1

    sleep_backup = time.sleep

    def my_sleep(sec):
        if sec == 120:
            if sleep_counter.count > 3:
                raise KeyboardInterrupt
            sleep_counter.count += 1
            sleep_backup(0.1)
        else:
            sleep_backup(sec)
    monkeypatch.setattr('time.sleep', my_sleep)

    data = TEST_CONFIG

    runner = CliRunner()

    with runner.isolated_filesystem():
        with open('mai.yaml', 'w') as fd:
            yaml.dump(data, fd)
        result = runner.invoke(cli, ['--config-file', 'mai.yaml', 'login', 'example-User'],
                               catch_exceptions=False)

        assert 'Authenticating against https://auth.example.com.. OK' in result.output
        assert 'Assuming role AWS Account 911 (example): Shibboleth-User.. OK' in result.output
        assert 'Writing temporary AWS credentials.. OK' in result.output

        result = runner.invoke(cli, ['--config-file', 'mai.yaml', 'login', 'example-User'],
                               catch_exceptions=False)

        assert 'Authenticating against https://auth.example.com.. OK' in result.output
        assert 'Assuming role AWS Account 911 (example): Shibboleth-User.. OK' in result.output
        assert 'Writing temporary AWS credentials.. OK' in result.output

        result = runner.invoke(cli, ['--config-file', 'mai.yaml', 'login'],
                               catch_exceptions=False)

        assert 'Authenticating against https://auth.example.com.. OK' in result.output
        assert 'Assuming role AWS Account 911 (example): Shibboleth-User.. OK' in result.output
        assert 'Writing temporary AWS credentials.. OK' in result.output

        result = runner.invoke(cli, ['--config-file', 'mai.yaml', 'login', '--refresh'],
                               catch_exceptions=False)

        assert 'Authenticating against https://auth.example.com.. OK' in result.output
        assert 'Assuming role AWS Account 911 (example): Shibboleth-User.. OK' in result.output
        assert 'Writing temporary AWS credentials.. OK' in result.output
        assert 'Waiting 54 minutes before refreshing credentials.. . . . OK' in result.output

        sleep_counter.count = 1
        result = runner.invoke(cli, ['--config-file', 'mai.yaml', 'login', 'example-Administrator'],
                               catch_exceptions=False)

        assert 'Authenticating against https://auth.example.com.. OK' in result.output
        assert 'Assuming role AWS Account 911 (example): Shibboleth-Administrator.. OK' in result.output
        assert 'Writing temporary AWS credentials.. OK' in result.output

        result = runner.invoke(cli, ['--config-file', 'mai.yaml', 'login'],
                               catch_exceptions=False)

        assert 'Authenticating against https://auth.example.com.. OK' in result.output
        assert 'Assuming role AWS Account 911 (example): Shibboleth-Administrator.. OK' in result.output
        assert 'Writing temporary AWS credentials.. OK' in result.output

        result = runner.invoke(cli, ['--config-file', 'mai.yaml', 'login', '--refresh'],
                               catch_exceptions=False)

        assert 'Authenticating against https://auth.example.com.. OK' in result.output
        assert 'Assuming role AWS Account 911 (example): Shibboleth-Administrator.. OK' in result.output
        assert 'Writing temporary AWS credentials.. OK' in result.output
        assert 'Waiting 54 minutes before refreshing credentials.. . . . OK' in result.output


def test_login_002_unknown_profile(monkeypatch):
    data = TEST_CONFIG

    runner = CliRunner()

    with runner.isolated_filesystem():
        with open('mai.yaml', 'w') as fd:
            yaml.dump(data, fd)
        result = runner.invoke(cli, ['--config-file', 'mai.yaml', 'login', 'foobar-User'])

    assert 'Profile "foobar-User" does not exist' in result.output
    assert result.exit_code == 2


def test_assume_role_failed(monkeypatch):
    m_saml_login = MagicMock()
    m_saml_login.return_value = 'xml', []
    monkeypatch.setattr('mai.cli.saml_login', m_saml_login)

    m_assume_role = MagicMock()
    m_assume_role.side_effect = aws_saml_login.saml.AssumeRoleFailed('Test')
    monkeypatch.setattr('mai.cli.assume_role', m_assume_role)

    m_fatal_error = MagicMock()
    m_fatal_error.side_effect = SystemExit(1)
    monkeypatch.setattr('mai.cli.Action.fatal_error', m_fatal_error)

    config = {'saml_identity_provider_url': 'example.com',
              'saml_user': 'test_user',
              'saml_role': ('provider_arn',
                            'arn:aws:iam::911:saml-provider/Shibboleth',
                            'name')}
    with pytest.raises(SystemExit):
        login_with_profile(None, None, config, None)

    m_fatal_error.assert_called_once_with('Assuming role failed: Test')