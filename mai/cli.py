import click
import keyring

from aws_saml_login import authenticate, assume_role, write_aws_credentials
from clickclick import Action, choice, error


@click.command()
@click.option('--url')
@click.option('-U', '--user', envvar='SAML_USER')
def cli(url, user):
    if not url:
        raise click.UsageError('Missing identity provider URL')

    if not user:
        raise click.UsageError('Missing SAML username')

    saml_password = keyring.get_password('mai', user)
    if not saml_password:
        saml_password = click.prompt('Please enter your SAML password', hide_input=True)

    with Action('Authenticating against {url}..', url=url):
        saml_xml, roles = authenticate(url, user, saml_password)

    keyring.set_password('mai', user, saml_password)

    if not roles:
        error('No roles found')

    if len(roles) == 1:
        role = roles[0]
    else:
        role = choice('Please select one role', [(r, str(r)) for r in sorted(roles)])

    with Action('Assuming role {role}..', role=role):
        key_id, secret, session_token = assume_role(saml_xml, role[0], role[1])

    with Action('Writing temporary AWS credentials..'):
        write_aws_credentials('default', key_id, secret, session_token)


def main():
    cli()
