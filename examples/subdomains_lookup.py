from spyse import Client, DomainSearchParams, Operators, SearchQuery, QueryParam
import os
import json
import sys


def scroll(c: Client, q: SearchQuery, limit=None):
    scroll_id = None
    n_fetched_results = 0
    while True:
        scroll_results = c.scroll_domains(q, scroll_id)

        scroll_id = scroll_results.search_id
        for r in scroll_results.results:
            print(json.dumps(r, default=lambda o: o.__dict__, sort_keys=True, indent=4))
        sys.stdout.flush()

        n_fetched_results += len(scroll_results.results)
        if n_fetched_results == scroll_results.total_items:
            break

        if limit and n_fetched_results >= limit:
            break


def search(c: Client, q: SearchQuery, limit=None):
    n_fetched_results = 0
    offset = 0
    while True:
        search_results = c.search_domains(q, client.MAX_LIMIT, offset)

        for r in search_results.results:
            print(json.dumps(r, default=lambda o: o.__dict__, sort_keys=True, indent=4))

        n_fetched_results += len(search_results.results)
        if n_fetched_results == search_results.total_items:
            break

        if limit and n_fetched_results >= limit:
            break
        offset += c.MAX_LIMIT
        sys.stdout.flush()


# Init client
api_token = os.getenv("SPYSE_API_TOKEN")
client = Client(api_token)

# Prepare search query
q = SearchQuery()
domain = "att.com"
q.append_param(QueryParam(DomainSearchParams.name, Operators.ends_with, "." + domain))

# Get total subdomains number
total = client.count_domains(q)
# print(f"Subdomains total: {total}")
# The search method allows to obtain up to 10 000 results
# we should use the Scroll method to fetch all results
# Note: The Scroll method is available only for Pro users
# check: https://spyse.com/pricing
if total > client.SEARCH_RESULTS_LIMIT and client.get_quotas().is_scroll_search_enabled:
    scroll(client, q)
else:
    search(client, q)
