from dataclasses import dataclass
from typing import List, Dict

@dataclass
class QueryParam:
    def __init__(self, name: str, operator: str, value: str):
        self.name: str = name
        self.operator: str = operator
        self.value: str = value


@dataclass
class SearchQuery:
    def __init__(self):
        self.query: List[Dict[str, Dict[str, str]]] = []

    def append_param(self, param: QueryParam):
        """Adds given param to the search query"""
        self.query.append({param.name: {"operator": param.operator, "value": param.value}})

    def append_group_param(self, params: List[QueryParam]):
        """Adds group param to the search query"""
        options: Dict[str, Dict[str, str]] = dict()
        for p in params:
            options[p.name] = {"operator": p.operator, "value": p.value}

        self.query.append(options)

    def get(self):
        return self.query


class ASSearchParams:
    ip: str = "ip"
    asn: str = "asn"
    domain: str = "domain"
    organization: str = "as_org"


class CertificateSearchParams:
    issued_for_domain: str = "issued_for_domain"
    issued_for_ip: str = "issued_for_ip"
    issuer_country: str = "issuer_country"
    issuer_org: str = "issuer_org"
    issuer_common_name: str = "issuer_common_name"
    issuer_email: str = "issuer_email"
    subject_country: str = "subject_country"
    subject_org: str = "issued_for_domain"
    subject_common_name: str = "subject_common_name"
    subject_email: str = "subject_email"
    fingerprint_md5: str = "fingerprint_md5"
    fingerprint_sha1: str = "fingerprint_sha1"
    fingerprint_sha256: str = "fingerprint_sha256"
    validity_end: str = "validity_end"
    validity_start: str = "validity_start"
    is_trusted: str = "is_trusted"


class CVESearchParams:
    id: str = "id"
    cpe: str = "cpe"
    score_cvss2: str = "score_cvss2"
    score_cvss3: str = "score_cvss3"
    severity_cvss2: str = "severity_cvss2"
    severity_cvss3: str = "severity_cvss3"
    published_at: str = "published_at"
    modified_at: str = "modified_at"


class DomainSearchParams:
    name: str = "name"
    http_extract_tracker_adsense_id: str = "http_extract_tracker_adsense_id"
    alexa_rank: str = "alexa_rank"
    dns_a: str = "dns_a"
    dns_aaaa: str = "dns_aaaa"
    dns_ns: str = "dns_ns"
    dns_mx: str = "dns_mx"
    dns_txt: str = "dns_txt"
    dns_caa: str = "dns_caa"
    dns_cname: str = "dns_cname"
    dns_spf_raw: str = "dns_spf_raw"
    dns_spf_version: str = "dns_spf_version"
    dns_spf_errors_target: str = "dns_spf_errors_target"
    dns_spf_modifiers_name: str = "dns_spf_modifiers_name"
    dns_spf_mechanisms_name: str = "dns_spf_mechanisms_name"
    dns_spf_modifiers_value: str = "dns_spf_modifiers_value"
    dns_spf_mechanisms_value: str = "dns_spf_mechanisms_value"
    dns_spf_errors_description: str = "dns_spf_errors_description"
    dns_spf_mechanisms_qualifier: str = "dns_spf_mechanisms_qualifier"
    http_extract_title: str = "http_extract_title"
    http_extract_email: str = "http_extract_email"
    http_extract_robots: str = "http_extract_robots"
    http_extract_styles: str = "http_extract_styles"
    http_extract_scripts: str = "http_extract_scripts"
    http_extract_meta_name: str = "http_extract_meta_name"
    http_extract_link_host: str = "http_extract_link_host"
    http_extract_meta_value: str = "http_extract_meta_value"
    http_extract_favicon_uri: str = "http_extract_favicon_uri"
    http_extract_status_code: str = "http_extract_status_code"
    http_extract_favicon_sha256: str = "http_extract_favicon_sha256"
    http_extract_headers_name: str = "http_extract_headers_name"
    http_extract_description: str = "http_extract_description"
    http_extract_headers_value: str = "http_extract_headers_value"
    http_extract_link_url: str = "http_extract_link_url"
    http_extract_final_redirect_url: str = "http_extract_final_redirect_url"
    cve_id: str = "cve_id"
    cve_severity: str = "cve_severity"
    technology_name: str = "technology_name"
    technology_version: str = "technology_version"
    certificate_sha256: str = "certificate_sha256"
    certificate_version: str = "certificate_version"
    whois_registrar_whois_server: str = "whois_registrar_whois_server"
    whois_registrant_org: str = "whois_registrant_org"
    whois_registrar_name: str = "whois_registrar_name"
    whois_registrant_name: str = "whois_registrant_name"
    whois_registrar_email: str = "whois_registrar_email"
    whois_registrant_phone: str = "whois_registrant_phone"
    whois_registrant_email: str = "whois_registrant_email"
    without_suffix: str = "without_suffix"
    http_extract_tracker_google_analytics_key: str = "http_extract_tracker_google_analytics_key"
    http_extract_tracker_google_play_app: str = "http_extract_tracker_google_play_app"
    http_extract_tracker_apple_itunes_app: str = "http_extract_tracker_apple_itunes_app"
    http_extract_tracker_google_site_verification: str = "http_extract_tracker_google_site_verification"
    certificate_issuer_org: str = "certificate_issuer_org"
    certificate_issuer_cname: str = "certificate_issuer_cname"
    certificate_issuer_email: str = "certificate_issuer_email"
    certificate_issuer_organizational_unit: str = "certificate_issuer_organizational_unit"
    certificate_issuer_country: str = "certificate_issuer_country"
    certificate_issuer_state: str = "certificate_issuer_state"
    certificate_issuer_locality: str = "certificate_issuer_locality"
    certificate_subject_org: str = "certificate_subject_org"
    certificate_subject_cname: str = "certificate_subject_cname"
    certificate_subject_email: str = "certificate_subject_email"
    certificate_subject_organizational_unit: str = "certificate_subject_organizational_unit"
    certificate_subject_country: str = "certificate_subject_country"
    certificate_subject_state: str = "certificate_subject_state"
    certificate_subject_locality: str = "certificate_subject_locality"
    certificate_subject_serial_number: str = "certificate_subject_serial_number"
    certificate_validity_end: str = "certificate_validity_end"
    geo_country_iso_code: str = "geo_country_iso_code"
    geo_country: str = "geo_country"
    geo_city: str = "geo_city"
    as_num: str = "as_num"
    organization_industry: str = "organization_industry"
    organization_email: str = "organization_email"
    organization_name: str = "organization_name"
    organization_legal_name: str = "organization_legal_name"
    isp: str = "isp"
    as_org: str = "as_org"
    is_ptr: str = "is_ptr"
    is_mx: str = "is_mx"
    is_ns: str = "is_ns"
    is_subdomain: str = "is_subdomain"
    is_cname: str = "is_cname"


class IPSearchParams:
    cidr: str = "cidr"
    isp: str = "isp"
    ptr: str = "ptr"
    as_org: str = "as_org"
    as_num: str = "as_num"
    geo_city: str = "geo_city"
    geo_country: str = "geo_country"
    geo_country_iso_code: str = "geo_country_iso_code"
    technology_cpe: str = "technology_cpe"
    port_technology_name: str = "port_technology_name"
    port_technology_version: str = "port_technology_version"
    open_port: str = "open_port"
    port_cve_id: str = "port_cve_id"
    port_banner: str = "port_banner"
    port_service: str = "port_service"
    http_extract_description: str = "http_extract_description"
    http_extract_title: str = "http_extract_title"
    http_extract_email: str = "http_extract_email"
    http_extract_robots: str = "http_extract_robots"
    http_extract_styles: str = "http_extract_styles"
    http_extract_scripts: str = "http_extract_scripts"
    http_extract_tracker_adsense_id: str = "http_extract_tracker_adsense_id"
    http_extract_meta_name: str = "http_extract_meta_name"
    http_extract_meta_value: str = "http_extract_meta_value"
    http_extract_link_host: str = "http_extract_link_host"
    http_extract_status_code: str = "http_extract_status_code"
    http_extract_favicon_sha256: str = "http_extract_favicon_sha256"
    http_extract_headers_name: str = "http_extract_headers_name"
    http_extract_headers_value: str = "http_extract_headers_value"
    http_extract_link_url: str = "http_extract_link_url"
    http_extract_final_redirect_url: str = "http_extract_final_redirect_url"
    http_extract_tracker_google_analytics_key: str = "http_extract_tracker_google_analytics_key"
    http_extract_tracker_google_play_app: str = "http_extract_tracker_google_play_app"
    http_extract_tracker_apple_itunes_app: str = "http_extract_tracker_apple_itunes_app"
    http_extract_tracker_google_site_verification: str = "http_extract_tracker_google_site_verification"
    abuses_reports_num: str = "abuses_reports_num"
    abuses_reports_comment: str = "abuses_reports_comment"
    abuses_confidence_score: str = "abuses_confidence_score"
    abuses_category_name: str = "abuses_category_name"
    abuses_is_whitelist_strong: str = "abuses_is_whitelist_strong"
    abuses_is_whitelist_weak: str = "abuses_is_whitelist_weak"
    security_score: str = "security_score"


class Operators:
    equals: str = "eq"
    contains: str = "contains"
    starts_with: str = "starts"
    ends_with: str = "ends"
    greater_or_equal_to: str = "gte"
    less_or_equal_to: str = "lte"
    exists: str = "exists"
    not_exists: str = "not_exists"
