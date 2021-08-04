import time

import click
import os
import sys
from loguru import logger

from spysecli import Printer, APIClient, InputParser
from spyse import SearchQuery, QueryParam, DomainSearchParams, IPSearchParams, Operators, Account

client: APIClient
printer: Printer
parser: InputParser
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


def do(func):
    try:
        for line in sys.stdin:
            func(line.strip())
    except BaseException as e:
        logger.error(e)


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option('--api_token', help='Personal API token')
@click.option('--output_format', help='Output format',
              type=click.Choice([Printer.FORMAT_PLAIN, Printer.FORMAT_JSON]), default=Printer.FORMAT_JSON)
def cli(api_token, output_format):
    if not api_token and os.getenv("SPYSE_API_TOKEN"):
        api_token = os.getenv("SPYSE_API_TOKEN")
    elif not api_token and not os.getenv("SPYSE_API_TOKEN"):
        logger.error("Spyse API Token must be specified.\n"
                     "Set flag: spysecli --api_token=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx task\n"
                     "or set env variable: export SPYSE_API_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
        raise click.Abort()

    global client, printer, parser
    client = APIClient(api_token)
    printer = Printer(output_format)
    parser = InputParser()

    def f(account: Account):
        logger.info(f'API requests: {account.api_requests_remaining}/{account.api_requests_limit}')

    client.fetch_account(f)
    pass


@cli.command(short_help='Find subdomains of a target domain')
def subdomains():
    def f(d: str):
        q = SearchQuery()
        q.append_param(QueryParam(DomainSearchParams.name, Operators.ends_with, "." + parser.extract_domain_name(d)))
        client.fetch_domains(q, printer.domain)

    do(f)


@cli.command(short_help='Find domains hosted on IPv4 host')
def reverse_ip():
    def f(s: str):
        net = parser.ipv4_to_network(s)
        q = SearchQuery()

        if "/" in s:
            for address in net:
                q.append_param(QueryParam(DomainSearchParams.dns_a, Operators.equals, str(address)))
        else:
            q.append_param(QueryParam(DomainSearchParams.dns_a, Operators.equals, s))

        client.fetch_domains(q, printer.domain)

    do(f)


@cli.command(short_help='Get detailed information about a domain')
def domain():
    def f(s: str):
        client.fetch_domain(parser.extract_domain_name(s), printer.domain)

    do(f)


@cli.command(short_help='Get detailed information about an IP')
def ip():
    def f(s: str):
        parser.ipv4_to_network(s)
        client.fetch_ip(s, printer.ip)

    do(f)


@cli.command(name="as", short_help="Get detailed information about an Autonomous System")
def autonomous_system():
    def f(s: str):
        client.fetch_autonomous_system(parser.extract_autonomous_sustem(s), printer.autonomous_system)

    do(f)


@cli.command(short_help="Get a list of sources in which an email was seen.")
def email():
    def f(s: str):
        client.fetch_email(parser.extract_email(s), printer.email)

    do(f)


@cli.command(short_help='Shows which domains are using given name server')
def reverse_ns():
    def f(s: str):
        q = SearchQuery()
        q.append_param(QueryParam(DomainSearchParams.dns_ns, Operators.equals, parser.extract_domain_name(s)))
        client.fetch_domains(q, printer.domain)

    do(f)


@cli.command(short_help='Shows which domains are using given mail server')
def reverse_mx():
    def f(s: str):
        q = SearchQuery()
        q.append_param(QueryParam(DomainSearchParams.dns_mx, Operators.equals, parser.extract_domain_name(s)))
        client.fetch_domains(q, printer.domain)

    do(f)


@cli.command(short_help='Shows which IPv4 hosts are using given PTR record')
def reverse_ptr():
    def f(s: str):
        q = SearchQuery()
        q.append_param(QueryParam(IPSearchParams.ptr, Operators.equals, parser.extract_domain_name(s)))

        client.fetch_ips(q, printer.ip)

    do(f)


@cli.command(short_help="Find all domains sharing the same AdSense ID")
def reverse_adsense():
    def f(s: str):
        q = SearchQuery()
        q.append_param(QueryParam(DomainSearchParams.http_extract_tracker_adsense_id, Operators.equals,
                                  parser.extract_adsense_id(s)))

        client.fetch_domains(q, printer.domain)

    do(f)


@cli.command(short_help="Find all domains sharing the same iTunes app ID")
def reverse_itunes():
    def f(s: str):
        q = SearchQuery()
        q.append_param(QueryParam(DomainSearchParams.http_extract_tracker_apple_itunes_app, Operators.equals,
                                  parser.extract_itunes_id(s)))

        client.fetch_domains(q, printer.domain)

    do(f)


@cli.command(short_help='Returns a list of domains that matched the search query.')
def search_domains():
    def f(s: str):
        q = parser.extract_search_query(s)
        client.fetch_domains(q, printer.domain)

    do(f)


@cli.command(short_help='Returns a list of IPv4 hosts that matched the search query.')
def search_ip():
    def f(s: str):
        q = parser.extract_search_query(s)
        client.fetch_ips(q, printer.ip)

    do(f)


@cli.command(short_help="Find all domains sharing the same Google Play app ID")
def reverse_google_play():
    def f(s: str):
        q = SearchQuery()
        q.append_param(QueryParam(DomainSearchParams.http_extract_tracker_google_play_app, Operators.equals,
                                  parser.extract_google_play(s)))

        client.fetch_domains(q, printer.domain)

    do(f)


@cli.command(short_help="Find all domains sharing the same Google Analytics ID")
def reverse_google_analytics():
    def f(s: str):
        q = SearchQuery()
        q.append_param(
            QueryParam(DomainSearchParams.http_extract_tracker_google_analytics_key, Operators.equals,
                       parser.extract_google_analytics(s)))
        client.fetch_domains(q, printer.domain)

    do(f)


@cli.command(short_help="Find all domains sharing the same Google site verification code")
def reverse_google_site_verification():
    def f(s: str):
        q = SearchQuery()
        q.append_param(
            QueryParam(DomainSearchParams.http_extract_tracker_google_site_verification, Operators.equals,
                       parser.extract_google_site_verification(s)))
        client.fetch_domains(q, printer.domain)

    do(f)


@cli.command(short_help="Get historical DNS A records")
def history_dns_a():
    def f(s: str):
        client.fetch_dns_history(parser.extract_domain_name(s), "A", printer.dns_history)

    do(f)


@cli.command(short_help="Get historical DNS AAAA records")
def history_dns_aaaa():
    def f(s: str):
        client.fetch_dns_history(parser.extract_domain_name(s), "AAAA", printer.dns_history)

    do(f)


@cli.command(short_help="Get historical DNS CNAME records")
def history_dns_cname():
    def f(s: str):
        client.fetch_dns_history(parser.extract_domain_name(s), "CNAME", printer.dns_history)

    do(f)


@cli.command(short_help="Get historical DNS TXT records")
def history_dns_txt():
    def f(s: str):
        client.fetch_dns_history(parser.extract_domain_name(s), "TXT", printer.dns_history)

    do(f)


@cli.command(short_help="Get historical DNS MX records")
def history_dns_mx():
    def f(s: str):
        client.fetch_dns_history(parser.extract_domain_name(s), "MX", printer.dns_history)

    do(f)


@cli.command(short_help="Get historical DNS NS records")
def history_dns_ns():
    def f(s: str):
        client.fetch_dns_history(parser.extract_domain_name(s), "NS", printer.dns_history)

    do(f)


@cli.command(short_help="Get historical WHOIS records")
def history_whois():
    def f(s: str):
        client.fetch_whois_history(s, printer.whois_history)

    do(f)


@cli.command(short_help="Find all websites mentioning the same email address on the homepage")
def reverse_email():
    def f(s: str):
        q = SearchQuery()
        q.append_param(QueryParam(DomainSearchParams.http_extract_email, Operators.equals, parser.extract_email(s)))
        client.fetch_domains(q, printer.domain)

    do(f)


@cli.result_callback()
def process_result(result, **kwargs):
    time.sleep(0.1)
    sys.stdout.flush()
    logger.info(f'Spent {client.requests_done} API requests')


if __name__ == '__main__':
    cli()
