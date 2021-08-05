import sys
from spyse import Client, SearchQuery


class APIClient:
    MAX_SEARCH_OFFSET = 9900
    MAX_LIMIT = 100

    def __init__(self, api_token: str):
        self.client = Client(api_token)
        self.client.set_user_agent("spysecli")
        self.requests_done = 0

    def fetch_domain(self, domain_name: str, callback_f):
        self.requests_done += 1
        callback_f(self.client.get_domain_details(domain_name))

    def fetch_ip(self, ip: str, callback_f):
        self.requests_done += 1
        callback_f(self.client.get_ip_details(ip))

    def fetch_account(self, callback_f):
        callback_f(self.client.get_quotas())

    def fetch_email(self, email: str, callback_f):
        self.requests_done += 1
        callback_f(self.client.get_email_details(email))

    def fetch_autonomous_system(self, asn: int, callback_f):
        self.requests_done += 1
        callback_f(self.client.get_autonomous_system_details(asn))

    def fetch_domains(self, q: SearchQuery, callback_f, limit=None):
        self.__fetch(q, self.client.count_domains, self.client.search_domains, self.client.scroll_domains,
                     callback_f, limit)

    def fetch_ips(self, q: SearchQuery, callback_f, limit=None):
        self.__fetch(q, self.client.count_ip, self.client.search_ip, self.client.scroll_ip, callback_f, limit)

    def fetch_dns_history(self, domain: str, dns_type: str, callback_f):
        self.__fetch_historical_dns(domain, dns_type, callback_f)

    def fetch_whois_history(self, domain: str, callback_f):
        self.__fetch_historical_whois(domain, callback_f)


    def __fetch(self, q: SearchQuery, count_func, search_func, scroll_func, print_func, limit=None):
        total = count_func(q)
        self.requests_done += 1
        if total == 0:
            return
        if total > self.client.SEARCH_RESULTS_LIMIT and self.client.get_quotas().is_scroll_search_enabled:
            self.__scroll(scroll_func, q, print_func, limit)
        else:
            self.__search(search_func, q, print_func, limit)

    def __scroll(self, scroll_func, q: SearchQuery, print_func, limit):
        scroll_id = None
        n_fetched_results = 0
        while True:

            scroll_results = scroll_func(q, scroll_id)
            self.requests_done += 1

            scroll_id = scroll_results.search_id
            for r in scroll_results.results:
                print_func(r)
            sys.stdout.flush()

            n_fetched_results += len(scroll_results.results)
            if n_fetched_results == scroll_results.total_items:
                break

            if limit and n_fetched_results >= limit:
                break

    def __search(self, scroll_func, q: SearchQuery, print_func, limit):
        n_fetched_results = 0
        offset = 0
        while True:
            search_results = scroll_func(q, self.client.MAX_LIMIT, offset)
            self.requests_done += 1

            for r in search_results.results:
                print_func(r)

            n_fetched_results += len(search_results.results)
            if n_fetched_results == search_results.total_items:
                break

            if limit and n_fetched_results >= limit:
                break
            offset += self.client.MAX_LIMIT
            sys.stdout.flush()

    def __fetch_historical_dns(self, domain: str, dns_type: str, callback_f, limit=None):
        n_fetched_results = 0
        offset = 0
        while True:
            search_results = self.client.search_historical_dns(dns_type, domain, self.client.MAX_LIMIT, offset)
            self.requests_done += 1

            for r in search_results.results:
                callback_f(r)

            n_fetched_results += len(search_results.results)
            if n_fetched_results == search_results.total_items:
                break

            if limit and n_fetched_results >= limit:
                break
            offset += self.client.MAX_LIMIT
            sys.stdout.flush()

    def __fetch_historical_whois(self, domain: str, callback_f, limit=None):
        n_fetched_results = 0
        offset = 0
        while True:
            search_results = self.client.search_historical_whois(domain, self.client.MAX_LIMIT, offset)
            self.requests_done += 1

            for r in search_results.results:
                callback_f(r)

            n_fetched_results += len(search_results.results)
            if n_fetched_results == search_results.total_items:
                break

            if limit and n_fetched_results >= limit:
                break
            offset += self.client.MAX_LIMIT
            sys.stdout.flush()