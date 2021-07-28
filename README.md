# Python wrapper for Spyse API

The official wrapper for [spyse.com](https://spyse.com/) API, written in Python, aimed to help developers build their
integrations with Spyse.

[Spyse](https://spyse.com/) is the most complete Internet assets search engine for every cybersecurity
professional.

Examples of data Spyse delivers:

* List of 300+ most popular open ports found on 3.5 Billion publicly accessible IPv4 hosts.
* Technologies used on 300+ most popular open ports and IP addresses and domains using a particular technology.
* Security score for each IP host and website, calculated based on the found vulnerabilities.
* List of websites hosted on each IPv4 host.
* DNS and WHOIS records of the domain names.
* SSL certificates provided by the website hosts.
* Structured content of the website homepages.
* Abuse reports associated with IPv4 hosts.
* Organizations and industries associated with the domain names.
* Email addresses found during the Internet scanning, associated with a domain name.

More information about the data Spyse collects is available on the [Our data](https://spyse.com/our-data) page.

Spyse provides an API accessible via **token-based authentication**.
API tokens are **available only for registered users** on their [account page](https://spyse.com/user).

For more information about the API, please check the [API Reference](https://spyse-dev.readme.io/reference/quick-start).

## Installation

```bash
pip3 install spyse
```

## Updating

```bash
pip3 install --no-cache-dir spyse.py
```


## Quick start
```python
from spyse import Client

client = Client("your-api-token-here")

d = client.get_domain_details('tesla.com')

print(f"Domain details:")
print(f"Website title: {d.http_extract.title}")
print(f"Alexa rank: {d.alexa.rank}")
print(f"Certificate subject org: {d.cert_summary.subject.organization}")
print(f"Certificate issuer org: {d.cert_summary.issuer.organization}")
print(f"Updated at: {d.updated_at}")
print(f"DNS Records: {d.dns_records}")
print(f"Technologies: {d.technologies}")
print(f"Vulnerabilities: {d.cve_list}")
print(f"Trackers: {d.trackers}")
# ...

```

## Examples

- [Check your API quotas](./examples/get_account_quotas.py)
- [Subdomains lookup ('Search', 'Scroll', 'Count' methods demo)](./examples/subdomains_lookup.py)
- [Domain lookup](./examples/domain_lookup.py)


Note: You need to export access_token to run any example:
```bash
export SPYSE_API_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

## How to search
Using Spyse you can search for any Internet assets by their digital fingerprints. To do that, you need to form a specific search query and pass it to 'search', 'scroll', or 'count' methods.

Each search query can contain multiple search params. Each search param consists of name, operator, and value. 

Check API docs to find out all existing combinations. Here is an example for domains search: https://spyse-dev.readme.io/reference/domains#domain_search
You may also be interested in our GUI for building and testing queries before jumping to code: https://spyse.com/advanced-search/domain

Example search request to find subdomains of att.com:
```python
from spyse import Client, SearchQuery, QueryParam, DomainSearchParams, Operators

# Prepare query
q = SearchQuery()
domain = "att.com"

# Add param to search for att.com subdomains
q.append_param(QueryParam(DomainSearchParams.name, Operators.ends_with, '.' + domain))

# Add param to search only for alive subdomains
q.append_param(QueryParam(DomainSearchParams.http_extract_status_code, Operators.equals, 200))

# Add param to remove subdomains seen as PTR records
q.append_param(QueryParam(DomainSearchParams.is_ptr, Operators.equals, False))

# Next, you can use the query to run search, count or scroll methods
c = Client("your-api-token-here")
total_count = c.count_domains(q)
search_results = c.search_domains(q)
scroll_results = c.scroll_domains(q).results
```

Example search request to find any alive IPv4 hosts in US, with open port 22 and running nginx:
```python
from spyse import Client, SearchQuery, QueryParam, IPSearchParams, Operators

# Prepare query
q = SearchQuery()

# Add param to search for IPv4 hosts located in US
q.append_param(QueryParam(IPSearchParams.geo_country_iso_code, Operators.equals, 'US'))

# Add param to search only for hosts with open 22 port
q.append_param(QueryParam(IPSearchParams.open_port, Operators.equals, 22))

# Add param to search only for hosts with nginx
q.append_param(QueryParam(IPSearchParams.port_technology_name, Operators.contains, "nginx"))

# Next, you can use the query to run search, count or scroll methods
c = Client("your-api-token-here")
total_count = c.count_domains(q)
search_results = c.search_domains(q)
scroll_results = c.scroll_domains(q).results
```

## Scroll vs Search
While a 'search' request allows to paginate over the first 10'000 results, the 'scroll search' can be used for deep pagination over a larger number of results (or even all results) in much the same way as you would use a cursor on a traditional database. 

In order to use scrolling, the initial search response will return a 'search_id' data field which should be specified in the subsequent requests in order to iterate over the rest of results.

### Limitations
The scroll is available only for customers with 'Pro' subscription.

Example code to check if the scroll is available for your account
```python
from spyse import Client
c = Client("your-api-token-here")

if c.get_quotas().is_scroll_search_enabled:
    print("Scroll is available")
else:
    print("Scroll is NOT available")
```


## Development

### Installation
```bash
git clone https://github.com/spyse-com/spyse-python
pip install -e .
```


Run tests:
```bash
cd tests
python client_test.py
```

## License

Distributed under the MIT License. See [LICENSE](./LICENSE.md) for more information.

## Troubleshooting and contacts

For any proposals and questions, please write at:

- Email: [contact@spyse.com](contact@spyse.com)
- Discord: [channel](https://discord.gg/XqaUP8c)
- Twitter: [@scanpatch](https://twitter.com/scanpatch), [@MrMristov](https://twitter.com/MrMristov)
