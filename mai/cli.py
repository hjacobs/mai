import click
import configparser
import json
import os
import requests
import stups_cli.config
import time
import yaml
import zign.api

import mai

from clickclick import Action, choice, error, AliasedGroup, info, print_table, OutputFormat
from requests.exceptions import RequestException

AWS_CREDENTIALS_PATH = '~/.aws/credentials'
CONFIG_DIR_PATH = click.get_app_dir('mai')
CONFIG_FILE_PATH = os.path.join(CONFIG_DIR_PATH, 'mai.yaml')

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

CREDENTIALS_RESOURCE = '/aws-accounts/{}/roles/{}/credentials'


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

    if 'service_url' not in data:
        write_service_url(data, path)

    if not ctx.invoked_subcommand:
        account, role = None, None
        if 'default_account' in data:
            account = data['default_account']
            role = data['default_role']

        if not account:
            raise click.UsageError('No default profile configured. Use "mai set-default..." to set a default profile.')
        ctx.invoke(login, account=account, role=role)


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

    data['service_url'] = service_url

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
    role_list.sort(key=lambda r: r['name'])
    with OutputFormat(output):
        print_table(sorted(role_list[0].keys()), role_list)


def get_profiles(user):
    '''Returns the AWS profiles for the specified user'''

    # TODO MUST be changed to the Credential Service URL 
    service_url = 'https://teams.auth.zalando.com/api/accounts/aws?member={}&role=any'.format(user)

    token = get_zign_token(user)
    r = requests.get(service_url, headers={'Authorization': 'Bearer {}'.format(token.get('access_token'))})

    return [ { 'name': item['name'], 'role': item['role'], 'id': item['id'] } for item in r.json() ]


def get_zign_token(user):
    try:
        return zign.api.get_named_token(['uid'], 'employees', 'mai', user, None, prompt=True)
    except zign.api.ServerError as e:
        raise click.ClickException('Unable to get token from zign')


@cli.command('set-default')
@click.argument('account')
@click.argument('role')
@click.pass_obj
def set_default(obj, account, role):
    '''Set default AWS account and role'''

    role_list = get_profiles(obj['user'])

    if (account, role) not in [ (item['name'], item['role']) for item in role_list ]:
        raise click.UsageError('Profile "{} {}" does not exist'.format(account, role))

    obj['config']['default_account'] = account
    obj['config']['default_role'] = role
        
    with Action('Storing configuration in {}..'.format(obj['config-file'])):
        os.makedirs(obj['config-dir'], exist_ok=True)
        with open(obj['config-file'], 'w') as fd:
            yaml.safe_dump(obj['config'], fd)


def get_aws_credentials(user, account, role, service_url):
    '''Requests AWS Temporary Credentials from the provided Credential Service URL'''

    profiles = get_profiles(user)

    id = None
    for item in profiles:
        if item['name'] == account and item['role'] == role:
            id = item['id']

    if not id:
        raise click.UsageError('Profile "{} {}" does not exist'.format(account, role))

    credentials_url = service_url + CREDENTIALS_RESOURCE.format(id, role)

    token = get_zign_token(user)
    r = requests.get(credentials_url, headers={'Authorization': 'Bearer {}'.format(token.get('access_token'))})

    return r.json()


@cli.command()
@click.argument('account')
@click.argument('role')
@click.option('-r', '--refresh', is_flag=True, help='Keep running and refresh access tokens automatically')
@click.option('--awsprofile', help='Profilename in ~/.aws/credentials', default='default', show_default=True)
@click.pass_obj
def login(obj, account, role, refresh, awsprofile):
    '''Login to AWS with given account and role'''

    repeat = True
    while repeat:
        last_update = get_last_update(obj)
        if 'account' in last_update and last_update['account'] and (not account or not role):
            account, role = last_update['account'], last_update['role']

        creds = get_aws_credentials(obj['user'], account, role, obj['config']['service_url'])
        with Action('Writing temporary AWS credentials for {} {}..'.format(account, role)):
            write_aws_credentials(awsprofile, creds['access_key_id'], creds['secret_access_key'], creds['session_token'])
            with open(obj['last-update-filename'], 'w') as fd:
                yaml.safe_dump({'timestamp': time.time(), 'account': account, 'role': role}, fd)

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


def write_aws_credentials(profile, key_id, secret, session_token=None):
    credentials_path = os.path.expanduser(AWS_CREDENTIALS_PATH)
    os.makedirs(os.path.dirname(credentials_path), exist_ok=True)
    config = configparser.ConfigParser()
    if os.path.exists(credentials_path):
        config.read(credentials_path)

    config[profile] = {}
    config[profile]['aws_access_key_id'] = key_id
    config[profile]['aws_secret_access_key'] = secret
    if session_token:
        # apparently the different AWS SDKs either use "session_token" or "security_token", so set both
        config[profile]['aws_session_token'] = session_token
        config[profile]['aws_security_token'] = session_token

    with open(credentials_path, 'w') as fd:
        config.write(fd)


def main():
    cli()
