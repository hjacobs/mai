import click
import os
import keyring
import yaml
import aws_saml_login.saml
import requests
import time
import stups_cli.config
import zign.api

import mai

from aws_saml_login import authenticate, assume_role, write_aws_credentials
from clickclick import Action, choice, error, AliasedGroup, info, print_table, OutputFormat
from requests.exceptions import RequestException

CONFIG_DIR_PATH = click.get_app_dir('mai')
CONFIG_FILE_PATH = os.path.join(CONFIG_DIR_PATH, 'mai.yaml')

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo('Mai {}'.format(mai.__version__))
    ctx.exit()


output_option = click.option('-o', '--output', type=click.Choice(['text', 'json', 'tsv']), default='text',
                             help='Use alternative output format')


@click.group(cls=AliasedGroup, invoke_without_command=True, context_settings=CONTEXT_SETTINGS)
@click.option('--config-file', '-c', help='Use alternative configuration file',
              default=CONFIG_FILE_PATH, metavar='PATH')
@click.option('-V', '--version', is_flag=True, callback=print_version, expose_value=False, is_eager=True,
              help='Print the current version number and exit.')
@click.option('--awsprofile', help='Profilename in ~/.aws/credentials', default='default', show_default=True)
@click.pass_context
def cli(ctx, config_file, awsprofile):
    path = os.path.abspath(os.path.expanduser(config_file))
    data = {}
    if os.path.exists(path):
        with open(path, 'rb') as fd:
            data = yaml.safe_load(fd)

    zign_config = stups_cli.config.load_config('zign')

    ctx.obj = {'config': data,
               'config-file': path,
               'config-dir': os.path.dirname(path),
               'last-update-filename': os.path.join(os.path.dirname(path), 'last_update.yaml'),
               'user': zign_config['user']}

    if 'global' not in data or 'service_url' not in data['global']:
        write_service_url(data, path)

    if not ctx.invoked_subcommand:
        if not data:
            raise click.UsageError('No profile configured. Use "mai create .." to create a new profile.')
        profile = None
        if 'global' in data:
            profile = data['global'].get('default_profile')
        if not profile:
            profile = sorted([k for k in data.keys() if k != 'global'])[0]
        login_with_profile(ctx.obj, profile, data.get(profile), awsprofile)


def write_service_url(data, path):
    '''Prompts for the Credential Service URL and writes in local configuration'''

    # Keep trying until successful connection
    while True:
        service_url = click.prompt('Enter credentials service URL')
        if not service_url.startswith('http'):
            service_url = 'https://{}'.format(service_url)
        try:
            r = requests.get(service_url + '/swagger.json')
            if r.status_code == 200:
               break
            else:
               click.secho('ERROR: no response from credentials service', fg='red', bold=True)
        except RequestException as e:
            click.secho('ERROR: connection error or timed out', fg='red', bold=True)

    if 'global' not in data:
        data['global'] = dict()
    data['global']['service_url'] = service_url

    with Action('Storing new credentials service URL in {}..'.format(path)):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as fd:
            yaml.safe_dump(data, fd)


@cli.command('list')
@output_option
@click.pass_obj
def list_profiles(obj, output):
    '''List profiles'''

    role_list = get_profiles(obj['user'])

    rows = []
    for item in role_list:
        row = {
            'name': item['name'],
            'id': item['id'],
            'role': item['role'],
        }
        rows.append(row)
    rows.sort(key=lambda r: r['name'])
    with OutputFormat(output):
        print_table(sorted(rows[0].keys()), rows)


def get_profiles(user):
    '''Returns the AWS profiles for the specified user'''

    # TODO MUST be changed to the Credential Service URL 
    service_url = 'https://teams.auth.zalando.com/api/accounts/aws?member={}&role=any'.format(user)

    token = get_zign_token(user)
    r = requests.get(service_url, headers={'Authorization': 'Bearer {}'.format(token.get('access_token'))})

    return r.json()


def get_zign_token(user):
    try:
        return zign.api.get_named_token(['uid'], 'employees', 'mai', user, None, prompt=True)
    except zign.api.ServerError as e:
        raise click.ClickException('Unable to get token from zign')


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


def login_with_profile(obj, profile, config, awsprofile):
    url = config.get('saml_identity_provider_url')
    user = config.get('saml_user')
    role = config.get('saml_role')

    if not url:
        raise click.UsageError('Missing identity provider URL')

    if not user:
        raise click.UsageError('Missing SAML username')

    saml_xml, roles = saml_login(user, url)

    with Action('Assuming role {role}..', role=get_role_label(role)) as action:
        try:
            key_id, secret, session_token = assume_role(saml_xml,
                                                        role[0], role[1])
        except aws_saml_login.saml.AssumeRoleFailed as e:
            action.fatal_error(str(e))

    with Action('Writing temporary AWS credentials..'):
        write_aws_credentials(awsprofile, key_id, secret, session_token)
        with open(obj['last-update-filename'], 'w') as fd:
            yaml.safe_dump({'timestamp': time.time(), 'profile': profile}, fd)


@cli.command()
@click.argument('account')
@click.argument('role')
@click.option('-r', '--refresh', is_flag=True, help='Keep running and refresh access tokens automatically')
@click.option('--awsprofile', help='Profilename in ~/.aws/credentials', default='default', show_default=True)
@click.pass_obj
def login(obj, profile, refresh, awsprofile):
    '''Login to AWS with given ACCOUNT and ROLE'''

    repeat = True
    while repeat:
        last_update = get_last_update(obj)
        if 'profile' in last_update and last_update['profile'] and not profile:
            profile = [last_update['profile']]
        for prof in profile:
            if prof not in obj['config']:
                raise click.UsageError('Profile "{}" does not exist'.format(prof))

            login_with_profile(obj, prof, obj['config'][prof], awsprofile)
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


@cli.command()
@click.argument('profile', nargs=-1)
@click.option('--awsprofile', help='Profilename in ~/.aws/credentials', default='default', show_default=True)
@click.pass_context
def require(context, profile, awsprofile):
    '''Login if necessary'''

    last_update = get_last_update(context.obj)
    time_remaining = last_update['timestamp'] + 3600 * 0.9 - time.time()
    if time_remaining < 0 or (profile and profile[0] != last_update['profile']):
        context.invoke(login, profile=profile, refresh=False, awsprofile=awsprofile)


def get_last_update(obj):
    try:
        with open(obj['last-update-filename'], 'rb') as fd:
            last_update = yaml.safe_load(fd)
    except:
        last_update = {'timestamp': 0}
    return last_update


def main():
    cli()
