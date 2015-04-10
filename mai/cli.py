import click
import os
import keyring
import yaml
import aws_saml_login.saml

from aws_saml_login import authenticate, assume_role, write_aws_credentials
from clickclick import Action, choice, error, AliasedGroup, info

CONFIG_DIR_PATH = click.get_app_dir('mai')
CONFIG_FILE_PATH = os.path.join(CONFIG_DIR_PATH, 'mai.yaml')

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(cls=AliasedGroup, invoke_without_command=True, context_settings=CONTEXT_SETTINGS)
@click.option('--config-file', '-c', help='Use alternative configuration file',
              default=CONFIG_FILE_PATH, metavar='PATH')
@click.pass_context
def cli(ctx, config_file):
    path = os.path.expanduser(config_file)
    data = {}
    if os.path.exists(path):
        with open(path, 'rb') as fd:
            data = yaml.safe_load(fd)
    ctx.obj = data

    if not ctx.invoked_subcommand:
        if not data:
            raise click.UsageError('No profile configured. Use "mai create .." to create a new profile.')
        profile = sorted(data.keys())[0]
        login_with_profile(profile, data.get(profile))


@cli.command('list')
@click.pass_obj
def list_profiles(obj):
    '''List profiles'''

    print(yaml.safe_dump(obj))


def get_role_label(role):
    """
    >>> get_role_label(('arn:aws:iam::123:saml-provider/Shibboleth',\
        'arn:aws:iam::123:role/Shibboleth-PowerUser', 'zalando-stups'))
    'AWS Account 123 (zalando-stups): Shibboleth-PowerUser'
    """
    provider_arn, role_arn, name = role
    number = role_arn.split(':')[4]
    return 'AWS Account {} ({}): {}'.format(number, name, role_arn.split('/')[-1])


@cli.command()
@click.argument('profile-name')
@click.option('--url', prompt='Identity provider URL')
@click.option('-U', '--user', envvar='SAML_USER', prompt='SAML username')
@click.pass_obj
def create(obj, profile_name, url, user):
    '''Create a new profile'''
    if not url:
        raise click.UsageError('Missing identity provider URL')

    if not user:
        raise click.UsageError('Missing SAML username')

    if not url.startswith('http'):
        url = 'https://{}'.format(url)

    saml_xml, roles = saml_login(user, url)

    if not roles:
        error('No roles found')

    if len(roles) == 1:
        role = roles[0]
    else:
        role = choice('Please select one role', [(r, get_role_label(r)) for r in sorted(roles)])

    data = {profile_name: {
        'saml_identity_provider_url': url,
        'saml_role': role,
        'saml_user': user
    }}

    path = os.path.expanduser(CONFIG_FILE_PATH)
    with Action('Storing new profile in {}..'.format(path)):
        os.makedirs(CONFIG_DIR_PATH, exist_ok=True)
        with open(path, 'w') as fd:
            yaml.safe_dump(data, fd)


def saml_login(user, url):
    ring_user = '{}@{}'.format(user, url)
    saml_password = keyring.get_password('mai', ring_user)

    saml_xml = None
    while not saml_xml:
        if not saml_password:
            saml_password = click.prompt('Please enter your SAML password', hide_input=True)

        with Action('Authenticating against {url}..', url=url) as act:
            try:
                saml_xml, roles = authenticate(url, user, saml_password)
            except aws_saml_login.saml.AuthenticationFailed:
                act.error('Authentication Failed')
                info('Please check your username/password and try again.')
                saml_password = None

    keyring.set_password('mai', ring_user, saml_password)
    return saml_xml, roles


def login_with_profile(profile, config):
    url = config.get('saml_identity_provider_url')
    user = config.get('saml_user')
    role = config.get('saml_role')

    if not url:
        raise click.UsageError('Missing identity provider URL')

    if not user:
        raise click.UsageError('Missing SAML username')

    saml_xml, roles = saml_login(user, url)

    with Action('Assuming role {role}..', role=get_role_label(role)):
        key_id, secret, session_token = assume_role(saml_xml, role[0], role[1])

    with Action('Writing temporary AWS credentials..'):
        write_aws_credentials('default', key_id, secret, session_token)


@cli.command()
@click.argument('profile', nargs=-1)
@click.pass_obj
def login(obj, profile):
    '''Login with given profile(s)'''

    for prof in profile:
        if prof not in obj:
            raise click.UsageError('Profile "{}" does not exist'.format(prof))

        login_with_profile(prof, obj[prof])


def main():
    cli()
