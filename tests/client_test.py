import unittest
import responses

from spyse import Client


class TestSpyse(unittest.TestCase):
    def setUp(self) -> None:
        self.client = Client("test-key")

    @responses.activate
    def test_get_quotas(self):
        f = open("./data/quotas.json")
        fixture = f.read()
        f.close()

        responses.add(**{
            'method': responses.GET,
            'url': 'https://api.spyse.com/v4/data/account/quota',
            'body': fixture,
            'status': 200,
            'content_type': 'application/json',
        })

        quotas = self.client.get_quotas()

        self.assertEqual(quotas.start_at, "2021-07-22T00:00:00Z")
        self.assertEqual(quotas.end_at, "2021-08-22T00:00:00Z")
        self.assertEqual(quotas.api_requests_remaining, 49895)
        self.assertEqual(quotas.api_requests_limit, 50000)
        self.assertEqual(quotas.downloads_limit_remaining, 50)
        self.assertEqual(quotas.downloads_limit, 50)
        self.assertEqual(quotas.is_scroll_search_enabled, True)
        self.assertEqual(quotas.search_params_limit, 10)

    @responses.activate
    def test_get_certificate(self):
        f = open("data/certificate_details.json")
        fixture = f.read()
        f.close()

        responses.add(**{
            'method': responses.GET,
            'url': 'https://api.spyse.com/v4/data/certificate/some-hash',
            'body': fixture,
            'status': 200,
            'content_type': 'application/json',
        })

        final = self.client.get_certificate_details("some-hash")

        self.assertEqual(final.updated_at, "2020-06-23T07:29:15.155941969Z")
        self.assertEqual(final.validation, None)
        self.assertEqual(final.parsed.fingerprint_sha256,
                         "5c157070be587becb7856643c9be75ab31726a0328a88377b0093c908a53abf5")
        self.assertEqual(final.parsed.issuer.email_address[0], "team@3amteam.com")
        self.assertEqual(final.parsed.subject_key_info.ecdsa_public_key.b, "")
        self.assertEqual(final.parsed.subject_key_info.fingerprint_sha256,
                         "bea1371c7524254c267a3f0226b59d8cbf66293f8501d26ab862cf8a865118e0")
        self.assertEqual(final.parsed.validity.end, "9999-12-31T23:59:59Z")

    @responses.activate
    def test_get_cve(self):
        f = open("data/cve_details.json")
        fixture = f.read()
        f.close()

        responses.add(**{
            'method': responses.GET,
            'url': 'https://api.spyse.com/v4/data/cve/some-cve-id',
            'body': fixture,
            'status': 200,
            'content_type': 'application/json',
        })

        final = self.client.get_cve_details("some-cve-id")

        self.assertEqual(final.id, "CVE-2004-2343")
        self.assertEqual(final.references.reference_data[0].tags[0], "Vendor Advisory")
        self.assertEqual(final.description.description_data[0].lang, "en")
        self.assertEqual(final.impact.baseMetricV2.cvssV2.baseScore, 7.2)
        self.assertEqual(final.conditions[0].cpe_prefix, "cpe:2.3:a:apache:http_server")
        self.assertEqual(final.problemtype.problemtype_data[0].description[0].value, "NVD-CWE-Other")
        self.assertEqual(final.publishedDate, "2004-12-31T05:00:00Z")
        self.assertEqual(final.lastModifiedDate, "2017-07-11T01:31:00Z")

    @responses.activate
    def test_history_dns(self):
        f = open("./data/dns_history.json")
        fixture = f.read()
        f.close()

        responses.add(**{
            'method': responses.GET,
            'url': 'https://api.spyse.com/v4/data/history/dns/A/google.com',
            'body': fixture,
            'status': 200,
            'content_type': 'application/json',
        })

        final = self.client.search_historical_dns("A", "google.com")

        self.assertEqual(final.results[0].value, "13.170.7.0")
        self.assertEqual(final.results[0].first_seen, "2020-12-18")
        self.assertEqual(final.results[0].last_seen, "2020-12-18")

    @responses.activate
    def test_history_whois(self):
        f = open("./data/whois_history.json")
        fixture = f.read()
        f.close()

        responses.add(**{
            'method': responses.GET,
            'url': 'https://api.spyse.com/v4/data/history/domain-whois/google.com',
            'body': fixture,
            'status': 200,
            'content_type': 'application/json',
        })

        final = self.client.search_historical_whois("google.com")

        self.assertEqual(final.results[0].registrar.created_date, "2013-12-16T19:33:28Z")
        self.assertEqual(final.results[0].registrar.emails, "abuse@namecheap.com")
        self.assertEqual(final.results[0].tech.city, "")
        self.assertEqual(final.results[0].updated_at, None)
        self.assertEqual(final.results[0].created_at, "2021-03-16T23:00:00+02:00")

    @responses.activate
    def test_get_domain(self):
        f = open("data/domain_details.json")
        fixture = f.read()
        f.close()

        responses.add(**{
            'method': responses.GET,
            'url': 'https://api.spyse.com/v4/data/domain/google.com',
            'body': fixture,
            'status': 200,
            'content_type': 'application/json',
        })

        final = self.client.get_domain_details("google.com")

        self.assertEqual(final.alexa.rank, 45948)
        self.assertEqual(final.cert_summary.fingerprint_sha256, "39b1d164f63d6044e92b4b72ff054a6ad0e9584968b132a9e1fcd90b4b45d449")
        self.assertEqual(final.cert_summary.issuer.country, "US")
        self.assertEqual(final.dns_records.A[0], "69.172.200.235")
        self.assertEqual(final.dns_records.SOA.email, "jposch.testcentral.com")
        self.assertEqual(final.dns_records.TXT[0], "google-site-verification=kW9t2V_S7WjOX57zq0tP8Ae_WJhRwUcZoqpdEkvuXJk")
        self.assertEqual(final.http_extract.http_status_code, 200)
        self.assertEqual(final.http_extract.http_status_code, 200)
        self.assertEqual(final.http_extract.http_headers[0].name, "Server")
        self.assertEqual(final.whois_parsed.admin.email, "fy4gz7f67tr@networksolutionsprivateregistration.com")
        self.assertEqual(final.security_score.score, 100)
        self.assertEqual(final.organizations[0].crunchbase.name, "Spyse")
        self.assertEqual(final.organizations[0].crunchbase.categories[0], "Big Data")
        self.assertEqual(final.organizations[0].crunchbase.is_primary, True)
        self.assertEqual(final.technologies[0].name, "Nginx")
        self.assertEqual(final.trackers.adsense_id, "")

    @responses.activate
    def test_get_as(self):
        f = open("data/as_details.json")
        fixture = f.read()
        f.close()

        responses.add(**{
            'method': responses.GET,
            'url': 'https://api.spyse.com/v4/data/as/15169',
            'body': fixture,
            'status': 200,
            'content_type': 'application/json',
        })

        final = self.client.get_autonomous_system_details(15169)

        self.assertEqual(final.asn, 1)
        self.assertEqual(final.as_org, "LVLT-1")
        self.assertEqual(final.ipv4_prefixes[0].cidr, "4.34.12.0/23")
        self.assertEqual(final.ipv4_prefixes[0].isp, "Level 3 Communications")
        self.assertEqual(final.ipv6_prefixes, None)

    @responses.activate
    def test_get_email(self):
        f = open("data/email_details.json")
        fixture = f.read()
        f.close()

        responses.add(**{
            'method': responses.GET,
            'url': 'https://api.spyse.com/v4/data/email/example@spyse.com',
            'body': fixture,
            'status': 200,
            'content_type': 'application/json',
        })

        final = self.client.get_email_details("example@spyse.com")

        self.assertEqual(final.email, "test@gmail.com")
        self.assertEqual(final.sources[0].target, "www.satyavathywomensclinic.com")
        self.assertEqual(final.sources[0].type, "site")
        self.assertEqual(final.sources[0].last_seen, "2020-10-02T15:10:52.484411677Z")
        self.assertEqual(final.updated_at, "2020-11-21T11:18:16.775330284Z")

    @responses.activate
    def test_get_ip(self):
        f = open("data/ip_details.json")
        fixture = f.read()
        f.close()

        responses.add(**{
            'method': responses.GET,
            'url': 'https://api.spyse.com/v4/data/ip/8.8.8.8',
            'body': fixture,
            'status': 200,
            'content_type': 'application/json',
        })

        final = self.client.get_ip_details("8.8.8.8")

        self.assertEqual(final.ip, "8.8.8.8")
        self.assertEqual(final.cve_list[0].id, "CVE-2017-15906")
        self.assertEqual(final.cve_list[0].ports[0], 22)
        self.assertEqual(final.cve_list[0].technology, "OpenSSH")
        self.assertEqual(final.geo_info.location.lon, -97.822)
        self.assertEqual(final.geo_info.location.lat, 37.751)
        self.assertEqual(final.isp_info.as_num, 15169)
        self.assertEqual(final.isp_info.updated_at, None)
        self.assertEqual(final.ptr_record.value, "dns.google")
        self.assertEqual(final.ptr_record.updated_at, None)
        self.assertEqual(final.ports[0].http_extract.final_redirect_url.full_uri, "https://dns.google/")
        self.assertEqual(final.ports[0].port, 443)
        self.assertEqual(final.technologies[0].port, 22)
        self.assertEqual(final.technologies[0].name, "OpenSSH")
        self.assertEqual(final.technologies[0].version, "7.4")
        self.assertEqual(final.abuses.reports[0].categories[0].id, 18)
        self.assertEqual(final.abuses.reports[0].categories[0].name, "Brute-Force")


if __name__ == '__main__':
    unittest.main()
