from typing import List, Optional
from dataclasses_json import dataclass_json
from dataclasses import dataclass


@dataclass_json
@dataclass
class Account:
    start_at: Optional[str] = None
    end_at: Optional[str] = None
    api_requests_remaining: Optional[int] = None
    api_requests_limit: Optional[int] = None
    downloads_limit_remaining: Optional[int] = None
    downloads_limit: Optional[int] = None
    is_scroll_search_enabled: Optional[bool] = None
    search_params_limit: Optional[int] = 10


@dataclass_json
@dataclass
class Prefix:
    cidr: Optional[str] = None
    isp: Optional[str] = None


@dataclass_json
@dataclass
class AS:
    asn: Optional[int] = None
    as_org: Optional[str] = None
    ipv4_prefixes: Optional[List[Prefix]] = None
    ipv6_prefixes: Optional[List[Prefix]] = None


@dataclass_json
@dataclass
class CrunchBase:
    name: Optional[str] = None
    legal_name: Optional[str] = None
    homepage_url: Optional[str] = None
    description: Optional[str] = None
    short_description: Optional[str] = None
    address: Optional[str] = None
    categories: Optional[List[str]] = None
    founded_on: Optional[str] = None
    closed_on: Optional[str] = None
    contact_email: Optional[str] = None
    image_url: Optional[str] = None
    num_employees_enum: Optional[str] = None
    operating_status: Optional[str] = None
    phone_number: Optional[str] = None
    revenue_range: Optional[str] = None
    status: Optional[str] = None
    country_code: Optional[str] = None
    state_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    postal_code: Optional[str] = None
    cb_url: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    is_primary: Optional[bool] = None


@dataclass_json
@dataclass
class Organization:
    crunchbase: Optional[CrunchBase] = None


@dataclass_json
@dataclass
class AlexaInfo:
    rank: Optional[int] = None
    updated_at: Optional[str] = None


@dataclass_json
@dataclass
class DomainCertIssuerDN:
    country: Optional[str] = None
    common_name: Optional[str] = None
    locality: Optional[str] = None
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    province: Optional[str] = None
    emailAddress: Optional[str] = None


@dataclass_json
@dataclass
class DomainCertSubjectDN:
    country: Optional[str] = None
    common_name: Optional[str] = None
    locality: Optional[str] = None
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    province: Optional[str] = None
    businessCategory: Optional[str] = None
    emailAddress: Optional[str] = None
    jurisdictionCountry: Optional[str] = None
    jurisdictionStateOrProvince: Optional[str] = None
    postalCode: Optional[str] = None
    serialNumber: Optional[str] = None
    street: Optional[str] = None


@dataclass_json
@dataclass
class CertSummary:
    fingerprint_sha256: Optional[str] = None
    issuer: DomainCertIssuerDN = None
    issuer_dn: Optional[str] = None
    subject: DomainCertSubjectDN = None
    subject_dn: Optional[str] = None
    tls_version: Optional[str] = None
    validity_end: Optional[str] = None


@dataclass_json
@dataclass
class CVEInfo:
    id: Optional[str] = None
    base_score_cvss2: Optional[float] = None


@dataclass_json
@dataclass
class DNSSOARecord:
    email: Optional[str] = None
    expire: Optional[int] = None
    min_ttl: Optional[int] = None
    ns: Optional[str] = None
    refresh: Optional[int] = None
    retry: Optional[int] = None
    serial: Optional[int] = None


@dataclass_json
@dataclass
class Mechanisms:
    name: Optional[str] = None
    qualifier: Optional[str] = None
    value: Optional[str] = None


@dataclass_json
@dataclass
class Modifiers:
    name: Optional[str] = None
    value: Optional[str] = None


@dataclass_json
@dataclass
class ValidationError:
    description: Optional[str] = None
    target: Optional[str] = None


@dataclass_json
@dataclass
class SPF:
    mechanisms: Optional[List[Mechanisms]] = None
    modifiers: Optional[List[Modifiers]] = None
    raw: Optional[str] = None
    validation_errors: Optional[List[ValidationError]] = None
    version: Optional[str] = None


@dataclass_json
@dataclass
class DNSRecords:
    A: Optional[List[str]] = None
    AAAA: Optional[List[str]] = None
    CAA: Optional[List[str]] = None
    CNAME: Optional[List[str]] = None
    MX: Optional[List[str]] = None
    NS: Optional[List[str]] = None
    SOA: Optional[DNSSOARecord] = None
    TXT: Optional[List[str]] = None
    SPF: Optional[List[SPF]] = None
    updated_at: Optional[str] = None


@dataclass_json
@dataclass
class ExtractCookie:
    domain: Optional[str] = None
    expire: Optional[str] = None
    http_only: Optional[bool] = None
    key: Optional[str] = None
    max_age: Optional[int] = None
    path: Optional[str] = None
    security: Optional[bool] = None
    value: Optional[str] = None


@dataclass_json
@dataclass
class URIParts:
    full_uri: Optional[str] = None
    host: Optional[str] = None
    path: Optional[str] = None


@dataclass_json
@dataclass
class HTTPHeaders:
    name: Optional[str] = None
    value: Optional[str] = None


@dataclass_json
@dataclass
class HyperlinkAttributes:
    URI: Optional[str] = None


@dataclass_json
@dataclass
class Hyperlink:
    anchor: Optional[str] = None
    attributes: Optional[HyperlinkAttributes] = None


@dataclass_json
@dataclass
class MetaTag:
    name: Optional[str] = None
    value: Optional[str] = None


@dataclass_json
@dataclass
class WHOIS:
    city: Optional[str] = None
    country: Optional[str] = None
    email: Optional[str] = None
    fax: Optional[str] = None
    fax_ext: Optional[str] = None
    id: Optional[str] = None
    name: Optional[str] = None
    organization: Optional[str] = None
    phone: Optional[str] = None
    phone_ext: Optional[str] = None
    postal_code: Optional[str] = None
    province: Optional[str] = None
    street: Optional[str] = None
    street_ext: Optional[str] = None


@dataclass_json
@dataclass
class WHOISRegistrar:
    created_date: Optional[str] = None
    domain_dnssec: Optional[str] = None
    domain_id: Optional[str] = None
    domain_name: Optional[str] = None
    domain_status: Optional[str] = None
    emails: Optional[str] = None
    expiration_date: Optional[str] = None
    name_servers: Optional[str] = None
    referral_url: Optional[str] = None
    registrar_id: Optional[str] = None
    registrar_name: Optional[str] = None
    updated_date: Optional[str] = None
    whois_server: Optional[str] = None


@dataclass_json
@dataclass
class WHOISParsedData:
    admin: Optional[WHOIS] = None
    registrant: Optional[WHOIS] = None
    registrar: Optional[WHOISRegistrar] = None
    tech: Optional[WHOIS] = None
    updated_at: Optional[Optional[str]] = None


@dataclass_json
@dataclass
class ExtractData:
    cookies: Optional[List[ExtractCookie]] = None
    description: Optional[str] = None
    emails: Optional[List[str]] = None
    final_redirect_url: Optional[URIParts] = None
    extracted_at: Optional[str] = None
    favicon_sha256: Optional[str] = None
    http_headers: Optional[List[HTTPHeaders]] = None
    http_status_code: Optional[int] = None
    links: Optional[List[Hyperlink]] = None
    meta_tags: Optional[List[MetaTag]] = None
    robots_txt: Optional[str] = None
    scripts: Optional[List[str]] = None
    styles: Optional[List[str]] = None
    title: Optional[str] = None


@dataclass_json
@dataclass
class CertParsedExtensionsAuthorityInfoAccess:
    issuer_urls: Optional[List[str]] = None
    ocsp_urls: Optional[List[str]] = None


@dataclass_json
@dataclass
class CertParsedExtensionsBasicConstraints:
    is_ca: Optional[bool] = None
    max_path_len: Optional[bool] = None


@dataclass_json
@dataclass
class NoticeReference:
    notice_numbers: Optional[int] = None
    organization: Optional[str] = None


@dataclass_json
@dataclass
class ExtensionsCertPoliciesUserNotice:
    explicit_text: Optional[str] = None
    notice_reference: Optional[NoticeReference] = None


@dataclass_json
@dataclass
class CertParsedExtensionsCertPolicies:
    cps: Optional[List[str]] = None
    id: Optional[str] = None
    user_notice: Optional[List[ExtensionsCertPoliciesUserNotice]] = None


@dataclass_json
@dataclass
class CertParsedExtensionsExtendedKeyUsage:
    any: Optional[bool] = None
    apple_ichat_encryption: Optional[bool] = None
    apple_ichat_signing: Optional[bool] = None
    apple_system_identity: Optional[bool] = None
    client_auth: Optional[bool] = None
    code_signing: Optional[bool] = None
    dvcs: Optional[bool] = None
    eap_over_lan: Optional[bool] = None
    eap_over_ppp: Optional[bool] = None
    email_protection: Optional[bool] = None
    ipsec_end_system: Optional[bool] = None
    ipsec_intermediate_system_usage: Optional[bool] = None
    ipsec_tunnel: Optional[bool] = None
    ipsec_user: Optional[bool] = None
    microsoft_ca_exchange: Optional[bool] = None
    microsoft_cert_trust_list_signing: Optional[bool] = None
    microsoft_document_signing: Optional[bool] = None
    microsoft_drm: Optional[bool] = None
    microsoft_efs_recovery: Optional[bool] = None
    microsoft_embedded_nt_crypto: Optional[bool] = None
    microsoft_encrypted_file_system: Optional[bool] = None
    microsoft_enrollment_agent: Optional[bool] = None
    microsoft_kernel_mode_code_signing: Optional[bool] = None
    microsoft_key_recovery_21: Optional[bool] = None
    microsoft_key_recovery_3: Optional[bool] = None
    microsoft_lifetime_signing: Optional[bool] = None
    microsoft_nt5_crypto: Optional[bool] = None
    microsoft_oem_whql_crypto: Optional[bool] = None
    microsoft_qualified_subordinate: Optional[bool] = None
    microsoft_root_list_signer: Optional[bool] = None
    microsoft_server_gated_crypto: Optional[bool] = None
    microsoft_smartcard_logon: Optional[bool] = None
    microsoft_system_health: Optional[bool] = None
    microsoft_timestamp_signing: Optional[bool] = None
    microsoft_whql_crypto: Optional[bool] = None
    sbgp_cert_aa_service_auth: Optional[bool] = None
    server_auth: Optional[bool] = None
    time_stamping: Optional[bool] = None


@dataclass_json
@dataclass
class CertIssuerAltNameDirectoryNames:
    common_name: Optional[str] = None
    country: Optional[str] = None
    domain_component: Optional[str] = None
    locality: Optional[str] = None
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    serial_number: Optional[str] = None
    street_address: Optional[str] = None


@dataclass_json
@dataclass
class CertAltNameOtherNames:
    id: Optional[str] = None
    value: Optional[str] = None


@dataclass_json
@dataclass
class CertIssuerAltName:
    directory_names: Optional[List[CertIssuerAltNameDirectoryNames]] = None
    dns_names: Optional[List[str]] = None
    email_addresses: Optional[List[str]] = None
    ip_addresses: Optional[List[str]] = None
    other_names: Optional[List[CertAltNameOtherNames]] = None
    registered_ids: Optional[List[str]] = None
    uniform_resource_identifiers: Optional[List[str]] = None


@dataclass_json
@dataclass
class CertParsedExtensionsKeyUsage:
    certificate_sign: Optional[bool] = None
    content_commitment: Optional[bool] = None
    crl_sign: Optional[bool] = None
    data_encipherment: Optional[bool] = None
    decipher_only: Optional[bool] = None
    digital_signature: Optional[bool] = None
    encipher_only: Optional[bool] = None
    key_agreement: Optional[bool] = None
    key_encipherment: Optional[bool] = None
    value: Optional[bool] = None


@dataclass_json
@dataclass
class CertParsedExtensionsNameConstraints:
    critical: Optional[bool] = None
    permitted_email_addresses: Optional[List[str]] = None
    permitted_names: Optional[List[str]] = None


@dataclass_json
@dataclass
class SignedCertificateTimestamps:
    log_id: Optional[str] = None
    signature: Optional[str] = None
    timestamp: Optional[int] = None
    version: Optional[int] = None


@dataclass_json
@dataclass
class CertSubjectAltNameDirectoryNames:
    common_name: Optional[str] = None
    country: Optional[str] = None
    domain_component: Optional[str] = None
    email_address: Optional[str] = None
    locality: Optional[str] = None
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    province: Optional[str] = None
    serial_number: Optional[str] = None
    surname: Optional[str] = None


@dataclass_json
@dataclass
class CertParsedExtensionsSubjectAltName:
    directory_names: Optional[List[CertSubjectAltNameDirectoryNames]] = None
    dns_names: Optional[List[str]] = None
    email_addresses: Optional[List[str]] = None
    ip_addresses: Optional[List[str]] = None
    other_names: Optional[List[CertAltNameOtherNames]] = None
    registered_ids: Optional[List[str]] = None
    uniform_resource_identifiers: Optional[List[str]] = None


@dataclass_json
@dataclass
class CertParsedIssuer:
    common_name: Optional[List[str]] = None
    country: Optional[List[str]] = None
    domain_component: Optional[List[str]] = None
    email_address: Optional[List[str]] = None
    given_name: Optional[List[str]] = None
    jurisdiction_country: Optional[List[str]] = None
    jurisdiction_locality: Optional[List[str]] = None
    jurisdiction_province: Optional[List[str]] = None
    locality: Optional[List[str]] = None
    organization: Optional[List[str]] = None
    organizational_unit: Optional[List[str]] = None
    postal_code: Optional[List[str]] = None
    province: Optional[List[str]] = None
    serial_number: Optional[List[str]] = None
    street_address: Optional[List[str]] = None
    surname: Optional[List[str]] = None


@dataclass_json
@dataclass
class CertParsedSignatureAlgorithm:
    name: Optional[str] = None
    oid: Optional[str] = None


@dataclass_json
@dataclass
class CertParsedSignature:
    self_signed: Optional[bool] = None
    signature_algorithm: Optional[CertParsedSignatureAlgorithm] = None
    valid: Optional[bool] = None
    value: Optional[str] = None


@dataclass_json
@dataclass
class CertParsedSubject:
    common_name: Optional[List[str]] = None
    country: Optional[List[str]] = None
    domain_component: Optional[List[str]] = None
    email_address: Optional[List[str]] = None
    given_name: Optional[List[str]] = None
    jurisdiction_country: Optional[List[str]] = None
    jurisdiction_locality: Optional[List[str]] = None
    jurisdiction_province: Optional[List[str]] = None
    locality: Optional[List[str]] = None
    organization: Optional[List[str]] = None
    organizational_unit: Optional[List[str]] = None
    postal_code: Optional[List[str]] = None
    province: Optional[List[str]] = None
    serial_number: Optional[List[str]] = None
    street_address: Optional[List[str]] = None
    surname: Optional[List[str]] = None


@dataclass_json
@dataclass
class EcdsaPublicKey:
    b: Optional[str] = None
    curve: Optional[str] = None
    gx: Optional[str] = None
    gy: Optional[str] = None
    length: Optional[int] = None
    n: Optional[str] = None
    p: Optional[str] = None
    pub: Optional[str] = None
    x: Optional[str] = None
    y: Optional[str] = None


@dataclass_json
@dataclass
class KeyAlgorithm:
    name: Optional[str] = None


@dataclass_json
@dataclass
class RSAPublicKey:
    exponent: Optional[int] = None
    length: Optional[int] = None
    modulus: Optional[str] = None


@dataclass_json
@dataclass
class CertParsedSubjectKeyInfo:
    ecdsa_public_key: Optional[EcdsaPublicKey] = None
    fingerprint_sha256: Optional[str] = None
    key_algorithm: Optional[KeyAlgorithm] = None
    rsa_public_key: Optional[RSAPublicKey] = None


@dataclass_json
@dataclass
class CertParsedValidity:
    status: Optional[str] = None
    end: Optional[str] = None
    length: Optional[int] = None
    start: Optional[str] = None


@dataclass_json
@dataclass
class Validation:
    reason: Optional[str] = None
    is_valid: Optional[bool] = None


@dataclass_json
@dataclass
class CertParsedExtensions:
    authority_info_access: Optional[CertParsedExtensionsAuthorityInfoAccess] = None
    authority_key_id: Optional[str] = None
    basic_constraints: Optional[CertParsedExtensionsBasicConstraints] = None
    certificate_policies: Optional[List[CertParsedExtensionsCertPolicies]] = None
    crl_distribution_points: Optional[List[str]] = None
    extended_key_usage: Optional[CertParsedExtensionsExtendedKeyUsage] = None
    issuer_alt_name: Optional[CertIssuerAltName] = None
    key_usage: Optional[CertParsedExtensionsKeyUsage] = None
    name_constraints: Optional[List[CertParsedExtensionsNameConstraints]] = None
    signed_certificate_timestamps: Optional[List[SignedCertificateTimestamps]] = None
    subject_alt_name: Optional[CertParsedExtensionsSubjectAltName] = None
    subject_key_id: Optional[str] = None


@dataclass_json
@dataclass
class CertParsed:
    extensions: Optional[CertParsedExtensions] = None
    fingerprint_md5: Optional[str] = None
    fingerprint_sha1: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    issuer: Optional[CertParsedIssuer] = None
    issuer_dn: Optional[str] = None
    names: Optional[List[str]] = None
    redacted: Optional[bool] = None
    serial_number: Optional[str] = None
    signature: Optional[CertParsedSignature] = None
    signature_algorithm: Optional[CertParsedSignatureAlgorithm] = None
    spki_subject_fingerprint: Optional[str] = None
    subject: Optional[CertParsedSubject] = None
    subject_dn: Optional[str] = None
    subject_key_info: Optional[CertParsedSubjectKeyInfo] = None
    tbs_fingerprint: Optional[str] = None
    tbs_noct_fingerprint: Optional[str] = None
    validation_level: Optional[str] = None
    validity: Optional[CertParsedValidity] = None
    version: Optional[int] = None


@dataclass_json
@dataclass
class Certificate:
    parsed: Optional[CertParsed] = None
    raw: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    validation: Optional[Validation] = None
    updated_at: Optional[str] = None


@dataclass_json
@dataclass
class ReferencesData:
    url: Optional[str] = None
    name: Optional[str] = None
    refsource: Optional[str] = None
    tags: Optional[List[str]] = None


@dataclass_json
@dataclass
class References:
    reference_data: Optional[List[ReferencesData]] = None


@dataclass_json
@dataclass
class DescriptionData:
    lang: Optional[str] = None
    value: Optional[str] = None


@dataclass_json
@dataclass
class Descriptions:
    description_data: Optional[List[DescriptionData]] = None


@dataclass_json
@dataclass
class BaseMetricCVSSV2:
    version: Optional[str] = None
    vectorString: Optional[str] = None
    accessVector: Optional[str] = None
    accessComplexity: Optional[str] = None
    authentication: Optional[str] = None
    confidentialityImpact: Optional[str] = None
    integrityImpact: Optional[str] = None
    availabilityImpact: Optional[str] = None
    baseScore: Optional[float] = None


@dataclass_json
@dataclass
class BaseMetricV2:
    cvssV2: Optional[BaseMetricCVSSV2] = None
    severity: Optional[str] = None
    exploitabilityScore: Optional[float] = None
    impactScore: Optional[float] = None
    acInsufInfo: Optional[bool] = None
    obtainAllPrivilege: Optional[bool] = None
    obtainUserPrivilege: Optional[bool] = None
    obtainOtherPrivilege: Optional[bool] = None
    userInteractionRequired: Optional[bool] = None


@dataclass_json
@dataclass
class BaseMetricCVSSV3:
    attackComplexity: Optional[str] = None
    attackVector: Optional[str] = None
    availabilityImpact: Optional[str] = None
    baseScore: Optional[float] = None
    baseSeverity: Optional[str] = None
    confidentialityImpact: Optional[str] = None
    integrityImpact: Optional[str] = None
    privilegesRequired: Optional[str] = None
    scope: Optional[str] = None
    userInteraction: Optional[str] = None
    vectorString: Optional[str] = None
    version: Optional[str] = None


@dataclass_json
@dataclass
class BaseMetricV3:
    cvssV3: Optional[str] = None
    exploitabilityScore: Optional[float] = None
    impactScore: Optional[float] = None


@dataclass_json
@dataclass
class Impact:
    baseMetricV2: Optional[BaseMetricV2] = None
    baseMetricV3: Optional[BaseMetricV3] = None


@dataclass_json
@dataclass
class Conditions:
    application: Optional[str] = None
    cpe_prefix: Optional[str] = None
    hardware: Optional[str] = None
    operation_system: Optional[str] = None
    version_end_excluding: Optional[str] = None
    version_end_excluding_representation: Optional[int] = None
    version_end_including: Optional[str] = None
    version_end_including_representation: Optional[int] = None
    version_start_excluding: Optional[str] = None
    version_start_excluding_representation: Optional[int] = None
    version_start_including: Optional[str] = None
    version_start_including_representation: Optional[int] = None


@dataclass_json
@dataclass
class ProblemTypeData:
    description: Optional[List[DescriptionData]] = None


@dataclass_json
@dataclass
class ProblemType:
    problemtype_data: Optional[List[ProblemTypeData]] = None


@dataclass_json
@dataclass
class CVE:
    id: Optional[str] = None
    references: Optional[References] = None
    description: Optional[Descriptions] = None
    impact: Optional[Impact] = None
    conditions: Optional[List[Conditions]] = None
    problemtype: Optional[ProblemType] = None
    publishedDate: Optional[str] = None
    lastModifiedDate: Optional[str] = None


@dataclass_json
@dataclass
class Sources:
    target: Optional[str] = None
    type: Optional[str] = None
    last_seen: Optional[str] = None


@dataclass_json
@dataclass
class Email:
    email: Optional[str] = None
    sources: List[Sources] = None
    updated_at: Optional[str] = None


@dataclass_json
@dataclass
class DNSHistoricalRecord:
    value: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


@dataclass_json
@dataclass
class WHOISHistoricalRecord:
    admin: Optional[WHOIS] = None
    registrant: Optional[WHOIS] = None
    registrar: Optional[WHOISRegistrar] = None
    tech: Optional[WHOIS] = None
    updated_at: Optional[str] = None
    created_at: Optional[str] = None


@dataclass_json
@dataclass
class IPCVE:
    id: Optional[str] = None
    base_score_cvss2: Optional[bool] = None
    ports: Optional[List[int]] = None
    technology: Optional[str] = None


@dataclass_json
@dataclass
class GeoPoint:
    lat: Optional[bool] = None
    lon: Optional[bool] = None


@dataclass_json
@dataclass
class LocationData:
    city_name: Optional[str] = None
    country: Optional[str] = None
    country_iso_code: Optional[str] = None
    location: Optional[GeoPoint] = None


@dataclass_json
@dataclass
class Score:
    score: Optional[int] = None


@dataclass_json
@dataclass
class ReportCategory:
    id: Optional[int] = None
    name: Optional[str] = None
    description: Optional[str] = None


@dataclass_json
@dataclass
class Report:
    categories: Optional[List[ReportCategory]] = None
    comment: Optional[str] = None
    reportedAt: Optional[str] = None


@dataclass_json
@dataclass
class Abuse:
    reports_num: Optional[int] = None
    score: Optional[int] = None
    reports:  Optional[List[Report]] = None


@dataclass_json
@dataclass
class ISPInfo:
    as_num: Optional[int] = None
    as_org: Optional[str] = None
    isp: Optional[str] = None
    updated_at: Optional[str] = None


@dataclass_json
@dataclass
class GeoData:
    ip: Optional[str] = None
    as_num: Optional[int] = None
    as_org: Optional[str] = None
    isp: Optional[str] = None
    location_data: Optional[LocationData] = None


@dataclass_json
@dataclass
class SeverityDetails:
    HIGH: Optional[int] = None
    MEDIUM: Optional[int] = None
    LOW: Optional[int] = None

@dataclass_json
@dataclass
class PtrRecord:
    value: Optional[str] = None
    updated_at: Optional[str] = None


@dataclass_json
@dataclass
class Trackers:
    adsense_id: Optional[str] = None
    apple_itunes_app: Optional[str] = None
    google_play_app: Optional[str] = None
    google_analytics_key: Optional[str] = None
    google_site_verification: Optional[str] = None


@dataclass_json
@dataclass
class PortExtract:
    cookies: Optional[List[ExtractCookie]] = None
    description: Optional[str] = None
    emails: Optional[List[str]] = None
    final_redirect_url: Optional[URIParts] = None
    extracted_at: Optional[str] = None
    favicon_sha256: Optional[str] = None
    http_headers: Optional[List[HTTPHeaders]] = None
    http_status_code: Optional[int] = None
    links: Optional[List[Hyperlink]] = None
    meta_tags: Optional[List[MetaTag]] = None
    robots_txt: Optional[str] = None
    scripts: Optional[List[str]] = None
    styles: Optional[List[str]] = None
    title: Optional[str] = None


@dataclass_json
@dataclass
class Technology:
    port: Optional[int] = None
    name: Optional[str] = None
    version: Optional[str] = None


@dataclass_json
@dataclass
class Port:
    banner: Optional[str] = None
    http_extract: Optional[PortExtract] = None
    port: Optional[int] = None
    technology: Optional[List[Technology]] = None
    masscan_service_name: Optional[str] = None
    updated_at: Optional[str] = None
    trackers: Optional[Trackers] = None


@dataclass_json
@dataclass
class IP:
    cve_list: Optional[List[IPCVE]] = None
    ip: Optional[str] = None
    geo_info: Optional[LocationData] = None
    isp_info: Optional[ISPInfo] = None
    ptr_record: Optional[PtrRecord] = None
    ports: Optional[List[Port]] = None
    security_score: Optional[Score] = None
    updated_at: Optional[str] = None
    cidr: Optional[str] = None
    technologies: Optional[List[Technology]] = None
    abuses: Optional[Abuse] = None


@dataclass_json
@dataclass
class IPInfo:
    score: Optional[Score] = None
    severity_details: Optional[SeverityDetails] = None
    cve_list: Optional[List[IPCVE]] = None
    osh: Optional[int] = None
    geo_data: Optional[List[GeoData]] = None


@dataclass_json
@dataclass
class Domain:
    alexa: Optional[AlexaInfo] = None
    cert_summary: Optional[CertSummary] = None
    dns_records: Optional[DNSRecords] = None
    hosts_enrichment: Optional[List[GeoData]] = None
    http_extract: Optional[ExtractData] = None
    is_CNAME: Optional[bool] = None
    is_MX: Optional[bool] = None
    is_NS: Optional[bool] = None
    is_PTR: Optional[bool] = None
    is_subdomain: Optional[bool] = None
    name: Optional[str] = None
    name_without_suffix: Optional[str] = None
    updated_at: Optional[str] = None
    whois_parsed: Optional[WHOISParsedData] = None
    screenshot_url: Optional[str] = None
    security_score: Optional[Score] = None
    cve_list: Optional[List[CVEInfo]] = None
    technologies: Optional[List[Technology]] = None
    trackers: Optional[Trackers] = None
    organizations: Optional[List[Organization]] = None
