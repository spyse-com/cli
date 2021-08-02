from spyse import Client, DomainSearchParams, Operators, SearchQuery, QueryParam
import os
import json
import sys


# Init client
api_token = os.getenv("SPYSE_API_TOKEN")
client = Client(api_token)


# Prepare search query
q = SearchQuery()
domain = "att.com"
q.append_param(QueryParam(DomainSearchParams.name, Operators.ends_with, "." + domain))

# Get total subdomains number
total = client.count_domains(q)
print(f"Subdomains total: {total}")


# The search method allows to obtain up to 10 000 results
# we should use the Scroll method to fetch all results
# Note: The Scroll method is available only for Pro users
# check: https://spyse.com/pricing
if total > client.SEARCH_RESULTS_LIMIT and client.get_quotas().is_scroll_search_enabled:
    print("Do scroll request")
    scroll_id = None
    subdomains_left = total
    while subdomains_left > 0:
        scroll_results = client.scroll_domains(q, search_id)
        search_id = scroll_results.search_id
        for r in scroll_results.results:
            print(json.dumps(r, default=lambda o: o.__dict__, sort_keys=True, indent=4))
        sys.stdout.flush()
        subdomains_left -= client.MAX_LIMIT
else:
    print("Do search request")
    offset = 0
    subdomains = []
    while offset <= total - client.MAX_LIMIT or offset == 0:
        for r in client.search_domains(q, client.MAX_LIMIT, offset).results:
            print(json.dumps(r, default=lambda o: o.__dict__, sort_keys=True, indent=4))
        offset += client.MAX_LIMIT
        sys.stdout.flush()
