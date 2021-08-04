import requests
from typing import List, Optional

from .models import AS, Domain, IP, CVE, Account, Certificate, Email, DNSHistoricalRecord, WHOISHistoricalRecord
from .response import Response
from .search_query import SearchQuery


class DomainsSearchResults:
    def __init__(self, results: List[Domain], total_items: int = None, search_id: str = None):
        self.total_items: Optional[int] = total_items
        self.search_id: Optional[str] = search_id
        self.results: List[Domain] = results


class AutonomousSystemsSearchResults:
    def __init__(self, results: List[AS], total_items: int = None, search_id: str = None):
        self.total_items: Optional[int] = total_items
        self.search_id: Optional[str] = search_id
        self.results: List[AS] = results


class IPSearchResults:
    def __init__(self, results: List[IP], total_items: int = None, search_id: str = None):
        self.total_items: Optional[int] = total_items
        self.search_id: Optional[str] = search_id
        self.results: List[IP] = results


class CertificatesSearchResults:
    def __init__(self, results: List[Certificate], total_items: int = None, search_id: str = None):
        self.total_items: Optional[int] = total_items
        self.search_id: Optional[str] = search_id
        self.results: List[Certificate] = results


class CVESearchResults:
    def __init__(self, results: List[CVE], total_items: int = None, search_id: str = None):
        self.total_items: Optional[int] = total_items
        self.search_id: Optional[str] = search_id
        self.results: List[CVE] = results


class EmailsSearchResults:
    def __init__(self, results: List[Email], total_items: int = None, search_id: str = None):
        self.total_items: Optional[int] = total_items
        self.search_id: Optional[str] = search_id
        self.results: List[Email] = results


class HistoricalDNSSearchResults:
    def __init__(self, results: List[DNSHistoricalRecord], total_items: int = None, search_id: str = None):
        self.total_items: Optional[int] = total_items
        self.search_id: Optional[str] = search_id
        self.results: List[DNSHistoricalRecord] = results


class HistoricalWHOISSearchResults:
    def __init__(self, results: List[WHOISHistoricalRecord], total_items: int = None, search_id: str = None):
        self.total_items: Optional[int] = total_items
        self.search_id: Optional[str] = search_id
        self.results: List[WHOISHistoricalRecord] = results


class Client:
    DEFAULT_BASE_URL = 'https://api.spyse.com/v4/data'
    MAX_LIMIT = 100
    SEARCH_RESULTS_LIMIT = 10000

    def __init__(self, api_token, base_url=DEFAULT_BASE_URL):
        self.session = requests.Session()
        self.session.headers.update({'Authorization': 'Bearer ' + api_token})
        self.session.headers.update({'User-Agent': 'spyse-python'})
        self.base_url = base_url

    def __get(self, endpoint: str) -> Response:
        return Response.from_dict(self.session.get(endpoint).json())

    def __search(self, endpoint, query: SearchQuery, limit: int = MAX_LIMIT, offset: int = 0) -> Response:
        return Response.from_dict(self.session.post(endpoint,
                                                    json={"search_params": query.get(), "limit": limit,
                                                          "offset": offset}).json())

    def __scroll(self, endpoint, query: SearchQuery, search_id: Optional[str] = None) -> Response:
        if search_id:
            body = {"search_params": query.get(), "search_id": search_id}
        else:
            body = {"search_params": query.get()}

        return Response.from_dict(self.session.post(endpoint, json=body).json())

    def set_user_agent(self, s: str):
        self.session.headers.update({'User-Agent': s})

    def get_quotas(self) -> Optional[Account]:
        """Returns details about your account quotas."""
        response = self.__get('{}/account/quota'.format(self.base_url))
        response.check_errors()

        return Account.from_dict(response.data.items[0]) if len(response.data.items) > 0 else None

    def get_autonomous_system_details(self, asn: int) -> Optional[AS]:
        """Returns details about an autonomous system by AS number."""
        response = self.__get('{}/as/{}'.format(self.base_url, asn))
        response.check_errors()

        return AS.from_dict(response.data.items[0]) if len(response.data.items) > 0 else None

    def count_autonomous_systems(self, query: SearchQuery) -> int:
        """Returns the precise number of search results that matched the search query."""
        response = self.__search('{}/as/search/count'.format(self.base_url), query)
        response.check_errors()

        return response.data.total_items

    def search_autonomous_systems(self, query: SearchQuery, limit: int = MAX_LIMIT,
                                  offset: int = 0) -> AutonomousSystemsSearchResults:
        """
        Returns a list of autonomous systems that matched the search query.
        Allows getting only the first 10,000 results.
        """

        response = self.__search('{}/as/search'.format(self.base_url), query, limit, offset)
        response.check_errors()

        as_list = list()
        for r in response.data.items:
            as_list.append(AS.from_dict(r))

        return AutonomousSystemsSearchResults(as_list, response.data.total_items)

    def scroll_autonomous_systems(self, query: SearchQuery, scroll_id: str = None) -> AutonomousSystemsSearchResults:
        """
        Returns a list of autonomous systems that matched the search query.
        Allows getting all the results but requires a Spyse Pro subscription
        """
        response = self.__scroll('{}/as/scroll/search'.format(self.base_url), query, scroll_id)
        response.check_errors()

        as_list = list()
        for r in response.data.items:
            as_list.append(AS.from_dict(r))

        return AutonomousSystemsSearchResults(as_list, search_id=response.data.search_id)

    def get_domain_details(self, domain_name: str) -> Optional[Domain]:
        """Returns details about domain"""
        response = self.__get('{}/domain/{}'.format(self.base_url, domain_name))
        response.check_errors()

        return Domain.from_dict(response.data.items[0]) if len(response.data.items) > 0 else None

    def search_domains(self, query: SearchQuery, limit: int = MAX_LIMIT, offset: int = 0) -> DomainsSearchResults:
        """
        Returns a list of domains that matched the search query.
        Allows getting only the first 10,000 results.
        """
        response = self.__search('{}/domain/search'.format(self.base_url), query, limit, offset)
        response.check_errors()

        domains = list()
        for r in response.data.items:
            domains.append(Domain.from_dict(r))

        return DomainsSearchResults(domains, response.data.total_items)

    def count_domains(self, query: SearchQuery):
        """Returns the precise number of search results that matched the search query."""
        response = self.__search('{}/domain/search/count'.format(self.base_url), query)
        response.check_errors()

        return response.data.total_items

    def scroll_domains(self, query: SearchQuery, scroll_id: str = None) -> DomainsSearchResults:
        """
        Returns a list of domains that matched the search query.
        Allows getting all the results but requires a Spyse Pro subscription
        """
        response = self.__scroll('{}/domain/scroll/search'.format(self.base_url), query, scroll_id)
        response.check_errors()

        domains = list()
        for r in response.data.items:
            domains.append(Domain.from_dict(r))

        return DomainsSearchResults(domains, search_id=response.data.search_id)

    def get_ip_details(self, ip: str) -> Optional[IP]:
        """Returns details about IP"""
        response = self.__get('{}/ip/{}'.format(self.base_url, ip))
        response.check_errors()

        return IP.from_dict(response.data.items[0]) if len(response.data.items) > 0 else None

    def search_ip(self, query: SearchQuery, limit: int = MAX_LIMIT, offset: int = 0) -> IPSearchResults:
        """
        Returns a list of IPv4 hosts that matched the search query.
        Allows getting only the first 10,000 results.
        """
        response = self.__search('{}/ip/search'.format(self.base_url), query, limit, offset)
        response.check_errors()

        ips = list()
        for r in response.data.items:
            ips.append(IP.from_dict(r))

        return IPSearchResults(ips, response.data.total_items)

    def count_ip(self, query: SearchQuery) -> int:
        """Returns the precise number of search results that matched the search query."""
        response = self.__search('{}/ip/search/count'.format(self.base_url), query)
        response.check_errors()

        return response.data.total_items

    def scroll_ip(self, query: SearchQuery, scroll_id: str = None) -> IPSearchResults:
        """
        Returns a list of IPv4 hosts that matched the search query.
        Allows getting all the results but requires a Spyse Pro subscription
        """
        response = self.__scroll('{}/ip/scroll/search'.format(self.base_url), query, scroll_id)
        response.check_errors()

        ips = list()
        for r in response.data.items:
            ips.append(IP.from_dict(r))

        return IPSearchResults(ips, search_id=response.data.search_id)

    def get_certificate_details(self, fingerprint_sha256: str) -> Optional[Certificate]:
        """Returns details about SSL/TLS certificate"""
        response = self.__get('{}/certificate/{}'.format(self.base_url, fingerprint_sha256))
        response.check_errors()

        return Certificate.from_dict(response.data.items[0]) if len(response.data.items) > 0 else None

    def search_certificate(self, query: SearchQuery, limit: int = MAX_LIMIT,
                           offset: int = 0) -> CertificatesSearchResults:
        """
        Returns a list of SSL/TLS certificate hosts that matched the search query.
        Allows getting only the first 10,000 results.
        """
        response = self.__search('{}/certificate/search'.format(self.base_url), query, limit, offset)
        response.check_errors()

        certs = list()
        for r in response.data.items:
            certs.append(Certificate.from_dict(r))

        return CertificatesSearchResults(certs, response.data.total_items)

    def count_certificate(self, query: SearchQuery) -> int:
        """Returns the precise number of search results that matched the search query."""
        response = self.__search('{}/certificate/search/count'.format(self.base_url), query)
        response.check_errors()

        return response.data.total_items

    def scroll_certificate(self, query: SearchQuery, scroll_id: str = None) -> CertificatesSearchResults:
        """
        Returns a list of SSL/TLS certificates that matched the search query.
        Allows getting all the results but requires a Spyse Pro subscription
        """
        response = self.__scroll('{}/certificate/scroll/search'.format(self.base_url), query, scroll_id)
        response.check_errors()

        certs = list()
        for r in response.data.items:
            certs.append(Certificate.from_dict(r))

        return CertificatesSearchResults(certs, search_id=response.data.search_id)

    def get_cve_details(self, cve_id: str) -> Optional[CVE]:
        """Returns details about CVE"""
        response = self.__get('{}/cve/{}'.format(self.base_url, cve_id))
        response.check_errors()

        return CVE.from_dict(response.data.items[0]) if len(response.data.items) > 0 else None

    def search_cve(self, query: SearchQuery, limit: int = MAX_LIMIT, offset: int = 0) -> CVESearchResults:
        """
        Returns a list of CVE that matched the search query.
        Allows getting only the first 10,000 results.
        """
        response = self.__search('{}/cve/search'.format(self.base_url), query, limit, offset)
        response.check_errors()

        cve_list = list()
        for r in response.data.items:
            cve_list.append(CVE.from_dict(r))

        return CVESearchResults(cve_list, response.data.total_items)

    def count_cve(self, query: SearchQuery) -> int:
        """Returns the precise number of search results that matched the search query."""
        response = self.__search('{}/cve/search/count'.format(self.base_url), query)
        response.check_errors()

        return response.data.total_items

    def scroll_cve(self, query: SearchQuery, scroll_id: str = None) -> CVESearchResults:
        """
        Returns a list of CVEs that matched the search query.
        Allows getting all the results but requires a Spyse Pro subscription
        """
        response = self.__scroll('{}/cve/scroll/search'.format(self.base_url), query, scroll_id)
        response.check_errors()

        cve_list = list()
        for r in response.data.items:
            cve_list.append(CVE.from_dict(r))

        return CVESearchResults(cve_list, search_id=response.data.search_id)

    def get_email_details(self, email: str) -> Optional[Email]:
        """Returns details about email"""
        response = self.__get('{}/email/{}'.format(self.base_url, email))
        response.check_errors()

        return Email.from_dict(response.data.items[0]) if len(response.data.items) > 0 else None

    def search_emails(self, query: SearchQuery, limit: int = MAX_LIMIT, offset: int = 0) -> EmailsSearchResults:
        """
        Returns a list of emails that matched the search query.
        Allows getting only the first 10,000 results.
        """
        response = self.__search('{}/email/search'.format(self.base_url), query, limit, offset)
        response.check_errors()

        emails = list()
        for r in response.data.items:
            emails.append(Email.from_dict(r))

        return EmailsSearchResults(emails, response.data.total_items)

    def count_emails(self, query: SearchQuery) -> int:
        """Returns the precise number of search results that matched the search query."""
        response = self.__search('{}/cve/email/count'.format(self.base_url), query)
        response.check_errors()

        return response.data.total_items

    def scroll_emails(self, query: SearchQuery, scroll_id: str = None) -> EmailsSearchResults:
        """
        Returns a list of emails that matched the search query.
        Allows getting all the results but requires a Spyse Pro subscription
        """
        response = self.__scroll('{}/email/scroll/search'.format(self.base_url), query, scroll_id)
        response.check_errors()

        emails = list()
        for r in response.data.items:
            emails.append(Email.from_dict(r))

        return EmailsSearchResults(emails, search_id=response.data.search_id)

    def search_historical_dns(self, dns_type, domain_name: str, limit: int = MAX_LIMIT, offset: int = 0) \
            -> HistoricalDNSSearchResults:
        """
        Returns the historical DNS records about the given domain name.
        """
        response = self.__get(f'{self.base_url}/history/dns/{dns_type}/{domain_name}?limit={limit}&offset={offset}')
        response.check_errors()

        records = list()
        for r in response.data.items:
            records.append(DNSHistoricalRecord.from_dict(r))

        return HistoricalDNSSearchResults(records, response.data.total_items)

    def search_historical_whois(self, domain_name: str, limit: int = MAX_LIMIT, offset: int = 0) \
            -> HistoricalWHOISSearchResults:
        """
        Returns the historical WHOIS records for the given domain name.
        """
        response = self.__get(f'{self.base_url}/history/domain-whois/{domain_name}?limit={limit}&offset={offset}')
        response.check_errors()

        records = list()
        for r in response.data.items:
            records.append(WHOISHistoricalRecord.from_dict(r))

        return HistoricalWHOISSearchResults(records, response.data.total_items)
