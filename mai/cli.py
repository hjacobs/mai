import click
import os
import keyring
import yaml
import aws_saml_login.saml
import time

import mai

from aws_saml_login import authenticate, assume_role, write_aws_credentials
from clickclick import Action, choice, error, AliasedGroup, info, print_table

CONFIG_DIR_PATH = click.get_app_dir('mai')
CONFIG_FILE_PATH = os.path.join(CONFIG_DIR_PATH, 'mai.yaml')

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo('Mai {}'.format(mai.__version__))
    ctx.exit()


@click.group(cls=AliasedGroup, invoke_without_command=True, context_settings=CONTEXT_SETTINGS)
@click.option('--config-file', '-c', help='Use alternative configuration file',
              default=CONFIG_FILE_PATH, metavar='PATH')
@click.option('-V', '--version', is_flag=True, callback=print_version, expose_value=False, is_eager=True,
              help='Print the current version number and exit.')
@click.pass_context
def cli(ctx, config_file):
    path = os.path.abspath(os.path.expanduser(config_file))
    data = {}
    if os.path.exists(path):
        with open(path, 'rb') as fd:
            data = yaml.safe_load(fd)
    ctx.obj = {'config': data,
               'config-file': path,
               'config-dir': os.path.dirname(path),
               'last-update-filename': os.path.join(os.path.dirname(path), 'last_update.yaml')}

    if not ctx.invoked_subcommand:
        if not data:
            raise click.UsageError('No profile configured. Use "mai create .." to create a new profile.')
        profile = None
        if 'global' in data:
            profile = data['global'].get('default_profile')
        if not profile:
            profile = sorted([k for k in data.keys() if k != 'global'])[0]
        login_with_profile(ctx.obj, profile, data.get(profile))


@cli.command('list')
@click.pass_obj
def list_profiles(obj):
    '''List profiles'''

    if obj['config']:
        rows = []
        for name, config in obj['config'].items():
            row = {
                'name': name,
                'role': get_role_label(config.get('saml_role')),
                'url': config.get('saml_identity_provider_url'),
                'user': config.get('saml_user')}
            rows.append(row)

        rows.sort(key=lambda r: r['name'])

        print_table(sorted(rows[0].keys()), rows)


def get_role_label(role):
    """
    >>> get_role_label(('arn:aws:iam::123:saml-provider/Shibboleth',\
        'arn:aws:iam::123:role/Shibboleth-PowerUser', 'zalando-stups'))
    'AWS Account 123 (zalando-stups): Shibboleth-PowerUser'
    """
    if not role:
        return ''
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
    if not url.startswith('http'):
        url = 'https://{}'.format(url)

    saml_xml, roles = saml_login(user, url)

    if not roles:
        error('No roles found')
        exit(1)

    if len(roles) == 1:
        role = roles[0]
    else:
        role = choice('Please select one role', [(r, get_role_label(r)) for r in sorted(roles)])

    data = obj['config']

    if not data:
        data = {}

    data[profile_name] = {
        'saml_identity_provider_url': url,
        'saml_role': role,
        'saml_user': user
    }

    path = obj['config-file']

    with Action('Storing new profile in {}..'.format(path)):
        os.makedirs(obj['config-dir'], exist_ok=True)
        with open(path, 'w') as fd:
            yaml.safe_dump(data, fd)


@cli.command('create-all')
@click.option('--url', prompt='Identity provider URL')
@click.option('-U', '--user', envvar='SAML_USER', prompt='SAML username')
@click.pass_obj
def create_all(obj, url, user):
    '''Create for all roles a new own profile'''
    if not url.startswith('http'):
        url = 'https://{}'.format(url)

    saml_xml, roles = saml_login(user, url)

    if not roles:
        error('No roles found')
        exit(1)

    data = obj['config']

    if not data:
        data = {}

    for r in sorted(roles):
        provider_arn, role_arn, name = r
        profile_name = '{}-{}'.format(name.split('-', maxsplit=1)[-1], role_arn.split('-', maxsplit=1)[-1])
        data[profile_name] = {
            'saml_identity_provider_url': url,
            'saml_role': r,
            'saml_user': user
        }

    path = obj['config-file']

    with Action('Storing new profile in {}..'.format(path)):
        os.makedirs(obj['config-dir'], exist_ok=True)
        with open(path, 'w') as fd:
            yaml.safe_dump(data, fd)


@cli.command('set-default')
@click.argument('profile-name')
@click.pass_obj
def set_default(obj, profile_name):
    '''Set default profile'''
    data = obj['config']

    if not data or profile_name not in data:
        raise click.UsageError('Profile "{}" does not exist'.format(profile_name))

    data['global'] = {
        'default_profile': profile_name
    }

    path = obj['config-file']

    with Action('Storing configuration in {}..'.format(path)):
        os.makedirs(obj['config-dir'], exist_ok=True)
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


def login_with_profile(obj, profile, config):
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
        with open(obj['last-update-filename'], 'w') as fd:
            yaml.safe_dump({'timestamp': time.time(), 'profile': profile}, fd)


@cli.command('delete')
@click.argument('profile-name')
@click.pass_obj
def delete(obj, profile_name):
    '''Delete profile'''

    path = obj['config-file']

    if not obj['config'] or profile_name not in obj['config']:
        raise click.UsageError('Profile "{}" does not exist'.format(profile_name))
    del obj['config'][profile_name]

    with Action('Deleting profile from {}..'.format(path)):
        os.makedirs(obj['config-dir'], exist_ok=True)
        with open(path, 'w') as fd:
            yaml.safe_dump(obj['config'], fd)


@cli.command()
@click.argument('profile', nargs=-1)
@click.option('-r', '--refresh', is_flag=True, help='Keep running and refresh access tokens automatically')
@click.pass_obj
def login(obj, profile, refresh):
    '''Login with given profile(s)'''

    repeat = True
    while repeat:
        last_update = get_last_update(obj)
        if 'profile' in last_update and last_update['profile'] and not profile:
            profile = [last_update['profile']]
        for prof in profile:
            if prof not in obj['config']:
                raise click.UsageError('Profile "{}" does not exist'.format(prof))

            login_with_profile(obj, prof, obj['config'][prof])
        if refresh:
            last_update = get_last_update(obj)
            wait_time = 3600 * 0.9
            with Action('Waiting {} minutes before refreshing credentials..'
                        .format(round(((last_update['timestamp']+wait_time)-time.time()) / 60))) as act:
                while time.time() < last_update['timestamp'] + wait_time:
                    try:
                        time.sleep(120)
                    except KeyboardInterrupt:
                        # do not show "EXCEPTION OCCURRED" for CTRL+C
                        repeat = False
                        break
                    act.progress()
        else:
            repeat = False


def get_last_update(obj):
    try:
        with open(obj['last-update-filename'], 'rb') as fd:
            last_update = yaml.safe_load(fd)
    except:
        last_update = {'timestamp': 0}
    return last_update


def main():
    cli()
