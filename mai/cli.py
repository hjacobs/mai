import click
import keyring

from aws_saml_login import authenticate, assume_role, write_aws_credentials


@click.command()
@click.option('--url')
@click.option('-U', '--user', envvar='SAML_USER')
def cli(url, user):
    saml_password = keyring.get_password('mai', user)
    if not saml_password:
        saml_password = click.prompt('Please enter your SAML password', hide_input=True)

    saml_xml, roles = authenticate(url, user, saml_password)
    keyring.set_password('mai', user, saml_password)

    role = roles[0]
    key_id, secret, session_token = assume_role(saml_xml, role[0], role[1])
    write_aws_credentials('default', key_id, secret, session_token)


def main():
    cli()
