import ipaddress
import validators
import json
from spyse import SearchQuery


class InputParser:
    def extract_autonomous_sustem(self, s: str) -> int:
        return int(s.lower().replace("asn", "").replace("as", ""))

    def is_cidr(self, s):
        try:
            ipaddress.IPv4Network(s)
            return True
        except ValueError:
            return False

    def ipv4_to_network(self, s: str):
        try:
            return ipaddress.IPv4Network(s)
        except ValueError:
            raise ValueError(f'"{s}" is not a valid IP notation')

    def extract_adsense_id(self, s: str):
        adsense_split = s.split("-")
        if len(adsense_split) > 1:
            return adsense_split[len(adsense_split) - 1]
        else:
            return adsense_split[0]

    def extract_itunes_id(self, s: str):
        itunes_split = s.split("=")
        if len(itunes_split) > 1:
            return itunes_split[len(itunes_split) - 1]
        else:
            return itunes_split[0]

    def extract_google_play(self, s: str):
        google_play_split = s.split("=")
        if len(google_play_split) > 1:
            return google_play_split[len(google_play_split) - 1]
        else:
            return google_play_split[0]

    def extract_google_analytics(self, s: str):
        return s

    def extract_google_site_verification(self, s: str):
        return s

    def extract_email(self, s: str) -> str:
        return s

    def extract_domain_name(self, s: str) -> str:
        if not validators.domain(s):
            raise ValueError(f'"{s}" is not a valid domain name')

        return s.replace("https://", "").replace("http://", "").split("/")[0]

    def extract_search_query(self, s: str):
        try:
            q = SearchQuery()
            q.query = json.loads(s).get("search_params")
        except:
            raise ValueError(f'"{s}" is not a valid search query')
