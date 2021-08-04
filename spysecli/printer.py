from spyse import Domain, IP, CVE, AS, Certificate, HistoricalDNSSearchResults, Email, HistoricalWHOISSearchResults
import json


class Printer:
    FORMAT_JSON = 'json'
    FORMAT_PLAIN = 'plain'

    def __init__(self, f: str):
        self.format: str = f

    def domain(self, d: Domain):
        if self.format == self.FORMAT_JSON:
            print(json.dumps(d, default=lambda o: o.__dict__, sort_keys=True))
        elif self.format == self.FORMAT_PLAIN:
            print(d.name)

    def ip(self, ip: IP):
        if self.format == self.FORMAT_JSON:
            print(json.dumps(ip, default=lambda o: o.__dict__, sort_keys=True))
        elif self.format == self.FORMAT_PLAIN:
            print(ip.ip)

    def cve(self, cve: CVE):
        if self.format == self.FORMAT_JSON:
            print(json.dumps(cve, default=lambda o: o.__dict__, sort_keys=True))
        elif self.format == self.FORMAT_PLAIN:
            print(cve.id)

    def autonomous_system(self, system: AS):
        if self.format == self.FORMAT_JSON:
            print(json.dumps(system, default=lambda o: o.__dict__, sort_keys=True))
        elif self.format == self.FORMAT_PLAIN:
            print(system.asn)

    def certificate(self, cert: Certificate):
        if self.format == self.FORMAT_JSON:
            print(json.dumps(cert, default=lambda o: o.__dict__, sort_keys=True))
        elif self.format == self.FORMAT_PLAIN:
            print(cert.fingerprint_sha256)

    def dns_history(self, dns_history_record: HistoricalDNSSearchResults):
        if self.format == self.FORMAT_JSON:
            print(json.dumps(dns_history_record, default=lambda o: o.__dict__, sort_keys=True))
        elif self.format == self.FORMAT_PLAIN:
            for dns_value in dns_history_record.results:
                print(dns_value.value)

    def whois_history(self, whois_history_record: HistoricalWHOISSearchResults):
        if self.format == self.FORMAT_JSON:
            print(json.dumps(whois_history_record, default=lambda o: o.__dict__, sort_keys=True))
        elif self.format == self.FORMAT_PLAIN:
            for whois_value in whois_history_record.results:
                print(whois_value.registrant.name)

    def email(self, email_record: Email):
        if self.format == self.FORMAT_JSON:
            print(json.dumps(email_record, default=lambda o: o.__dict__, sort_keys=True))
        elif self.format == self.FORMAT_PLAIN:
            print(email_record.email)
