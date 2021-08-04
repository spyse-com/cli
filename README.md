# Spyse CLI

The official command-line client for [spyse.com](https://spyse.com/).
> **_NOTE:_**  This tool is currently in the early stage beta and shouldn't be used in production.
> 
> Your feedback and suggestions are highly appreciated.
## Supported Features

Targeted recon:

- [Get Domain details](#get-domain-details)
- [Get IPv4 host details](#get-ipv4-host-details)
- [Get Autonomous System details](#get-autonomous-system-details)
- [Get Email details](#get-email-details)

Gather associated targets:

- [Subdomains lookup](#subdomains-lookup)
- [Reverse IP lookup](#reverse-ip-lookup)
- [Reverse NS lookup](#reverse-ns-lookup)
- [Reverse MX lookup](#reverse-mx-lookup)
- [Reverse PTR lookup](#reverse-ptr-lookup)
- [Reverse AdSense ID lookup](#reverse-adsense-id-lookup)
- [Reverse iTunes ID lookup](#reverse-itunes-id--lookup)
- [Reverse Google Play ID lookup](#reverse-google-play-id-lookup)
- [Reverse Google Analytics ID lookup](#reverse-google-analytics-id-lookup)
- [Reverse Google Site Verification ID lookup](#reverse-google-site-verification-id-lookup)
- [Reverse Email lookup](#reverse-email-lookup)
  
Gather historical records

- [Get historical DNS A records](#historical-dns-a-records)
- [Get historical DNS AAAA records](#historical-dns-aaaa-records)
- [Get historical DNS CNAME records](#historical-dns-cnmae-records)
- [Get historical DNS TXT records](#historical-dns-txt-records)
- [Get historical DNS MX records](#historical-dns-mx-records)
- [Get historical DNS NS records](#historical-dns-ns-records)
- [Get historical WHOIS records](#historical-whois-records)
  

Custom Internet-wide assets search:
- [Custom search for domains](#custom-search-for-domains)
- [Custom search for IPv4 hosts](#custom-search-for-ipv4-hosts)


## Installation
> **_NOTE:_**  Spyse API token is required to use this tool.
> 
> API tokens are **available only for registered users** on their [account page](https://spyse.com/user).   
> For more information about the API, please check the [API Reference](https://spyse-dev.readme.io/reference/quick-start).


### Using Docker:
```shell
docker build -t spysecli .
echo "tesla.com" | docker run --interactive spysecli --api_token=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx subdomains
```

### Using pip
```bash
pip3 install spysecli
spysecli --api_token=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -h 

# API token also can be read from environment
export SPYSE_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
spysecli -h
```

## Using as a library
This repository is about CLI only. If you want to integrate spyse.com into your application, you should check out our SDKs.

Official:
- [SDK for Python](https://github.com/spyse-com/spyse-python)
- [SDK for Golang](https://github.com/spyse-com/go-spyse)

Community:
- [SDK for Ruby](https://github.com/ninoseki/spysex)

## Using the client

Targeted recon:

### Get Domain details
Get DNS records, SSL/TLS certificate, structured HTTP response, technologies, potential vulnerabilities, and other details about domain by its name.
```shell
# Command example:
echo "tesla.com" | spysecli domain

# Examples of valid input lines:
domain.com
https://example.com
https://example.com/path
```

### Get IPv4 host details
Get Open ports, autonomous system number/organization, ISP, technologies, ip reputation and abuse reports, structured HTTP response, potential vulnerabilities, and other details about IP address.
```shell
# Command example:
echo "8.8.8.8" | spysecli ip

# Examples of valid input lines:
8.8.8.8
8.8.8.0/24
```

### Get Autonomous System details
Get associated organization, IPv4 prefixes, IPv6 prefixes, and other details about autonomous system.
```shell
# Command example:
echo "AS15169" | spysecli as

# Examples of valid input lines:
AS15169
as15169
15169
```

### Get Email details
Get a list of sources in which an email was seen.

```shell
# Command example:
echo "test@domain.com" | spysecli email

# Examples of valid input lines:
test@domain.com
```

Gather associated targets:

### Subdomains lookup
Find subdomains of a target domain
```shell
# Command example:
echo "tesla.com" | spysecli subdomains

# Examples of valid input lines:
domain.com
https://example.com
https://example.com/path
```

### Reverse IP lookup
Find domains hosted on IPv4 host
```shell
# Command example:
echo "8.8.8.8" | spysecli reverse-ip

# Examples of valid input lines:
8.8.8.8
8.8.8.0/24
```

### Reverse NS lookup
Shows which domains are using given name server

```shell
# Command example:
echo "ns1.google.com" | spysecli reverse-ns

# Examples of valid input lines:
ns1.domain.com
```

### Reverse MX lookup
Shows which domains are using given mail server

```shell
# Command example:
echo "mx.google.com" | spysecli reverse-mx

# Examples of valid input lines:
mx.google.com
```

### Reverse PTR lookup
Shows which IPv4 hosts are using given PTR record

```shell
# Command example:
echo "google.com" | spyse reverse-ptr

# Examples of valid input lines:
domain.com
```

### Reverse AdSense ID lookup
Find all domains sharing the same AdSense ID

```shell
# Command example:
echo "1234567891234567" | spyse reverse-adsense

# Examples of valid input lines:
pub-1234567891234567
1234567891234567
```

### Reverse iTunes ID lookup
Find all domains sharing the same iTunes app ID

```shell
# Command example:
echo "1188352635" | spyse reverse-itunes

# Examples of valid input lines:
1188352635
```

### Reverse Google Play ID lookup
Find all domains sharing the same Google Play app ID

```shell
# Command example:
echo "google.com" | spyse reverse-google-play

# Examples of valid input lines:
domain.com
```

### Reverse Google Analytics ID lookup
Find all domains sharing the same Google Analytics ID

```shell
# Command example:
echo "UA-12345-12" | spyse reverse-google-analytics

# Examples of valid input lines:
UA-12345-12
```

### Reverse Google Site Verification ID lookup
Find all domains sharing the same Google site verification code

```shell
# Command example:
echo "rXOxyZounnZasA8Z7oaD3c14JdjS9aKSWvsR1EbUSIQ" | spyse reverse-google-site-verification

# Examples of valid input lines:
rXOxyZounnZasA8Z7oaD3c14JdjS9aKSWvsR1EbUSIQ
```

### Reverse Email lookup
Find all websites mentioning the same email address on the homepage

```shell
# Command example:
echo "test@domain.com" | spyse reverse-email

# Examples of valid input lines:
test@domain.com
```

Gather historical records

### Get historical DNS A records
Get historical DNS A records
```shell
# Command example:
echo "google.com" | spyse history-dns-a

# Examples of valid input lines:
domain.com
```

### Get historical DNS AAAA records
Get historical DNS AAAA records
```shell
# Command example:
echo "google.com" | spyse history-dns-aaaa

# Examples of valid input lines:
domain.com
```

### Get historical DNS CNAME records
Get historical DNS CNAME records
```shell
# Command example:
echo "google.com" | spyse history-dns-cname

# Examples of valid input lines:
domain.com
```

### Get historical DNS TXT records
Get historical DNS TXT records
```shell
# Command example:
echo "google.com" | spyse history-dns-txt

# Examples of valid input lines:
domain.com
```

### Get historical DNS MX records
Get historical DNS MX records
```shell
# Command example:
echo "google.com" | spyse history-dns-mx

# Examples of valid input lines:
domain.com
```

### Get historical DNS NS records
Get historical DNS NS records
```shell
# Command example:
echo "google.com" | spyse history-dns-ns

# Examples of valid input lines:
domain.com
```

### Get historical WHOIS records
Get historical DNS WHOIS records
```shell
# Command example:
echo "google.com" | spyse history-whois

# Examples of valid input lines:
domain.com
```

### Custom search for domains
Returns a list of domains that matched the search query.

Use [API docs](https://spyse-dev.readme.io/reference/domains#domain_search) and [Spyse Advanced Search](https://spyse.com/advanced-search/domain)
 to craft your own request.
```shell
# Command example:
echo '{"search_params":[{"name":{"operator":"ends","value":".spyse.com"}}]}' | spysecli search-domains
```

### Custom search for IPv4 hosts
Returns a list of IPv4 hosts that matched the search query.

Use [API docs](https://spyse-dev.readme.io/reference/ips#ip_search) and [Spyse Advanced Search](https://spyse.com/advanced-search/ip)
 to craft your own request.
```shell
# Command example:
echo '{"search_params":[{"open_port":{"operator":"eq","value":"200"}}]}' | spysecli search-domains
```




## Planned features
- [ ] CVE lookup
- [ ] CIDR lookup
- [ ] Emails lookup
