from spyse import Client
import os

# Init client
api_token = os.getenv("SPYSE_API_TOKEN")
client = Client(api_token)

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