#include "completion_definitions.h"
#include "logger.h"
#include <cctype>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

std::shared_ptr<CompletionItem> CompletionItem::root = std::make_shared<CompletionItem>();

void CompletionItem::initialize_tree() {
    // Google types not (or partially) implemented
    // Graph Entity not implemented
    // Is there a way to shorten this ?
    // Can it be done at compile time ?

    std::shared_ptr<CompletionItem> noun = std::make_shared<CompletionItem>();

    std::shared_ptr<CompletionItem> keyValuePair = std::make_shared<CompletionItem>();
    keyValuePair->addChild("key");
    keyValuePair->addChild("value");

    std::shared_ptr<CompletionItem> protobufStruct = std::make_shared<CompletionItem>();
    protobufStruct->addChild(keyValuePair, "fields");

    std::shared_ptr<CompletionItem> SSLCertificate_CertSignature = std::make_shared<CompletionItem>();
    SSLCertificate_CertSignature->addChild("signature");
    SSLCertificate_CertSignature->addChild("signature_algorithm");

    std::shared_ptr<CompletionItem> SSLCertificate_EC = std::make_shared<CompletionItem>();
    SSLCertificate_EC->addChild("oid");
    SSLCertificate_EC->addChild("pub");

    std::shared_ptr<CompletionItem> SSLCertificate_AuthorityKeyId = std::make_shared<CompletionItem>();
    SSLCertificate_AuthorityKeyId->addChild("keyid");
    SSLCertificate_AuthorityKeyId->addChild("serial_number");

    std::shared_ptr<CompletionItem> SSLCertificate_Extension = std::make_shared<CompletionItem>();
    SSLCertificate_Extension->addChild(SSLCertificate_AuthorityKeyId, "authority_key_id");
    SSLCertificate_Extension->addChild("ca");
    SSLCertificate_Extension->addChild("ca_info_access");
    SSLCertificate_Extension->addChild("cert_template_name_dc");
    SSLCertificate_Extension->addChild("certificate_policies");
    SSLCertificate_Extension->addChild("crl_distribution_points");
    SSLCertificate_Extension->addChild("extended_key_usage");
    SSLCertificate_Extension->addChild("key_usage");
    SSLCertificate_Extension->addChild("netscape_cert_comment");
    SSLCertificate_Extension->addChild("netscape_certificate");
    SSLCertificate_Extension->addChild("old_authority_key_id");
    SSLCertificate_Extension->addChild("pe_logotype");
    SSLCertificate_Extension->addChild("subject_alternative_name");
    SSLCertificate_Extension->addChild("subject_key_id");

    std::shared_ptr<CompletionItem> SSLCertificate_Subject = std::make_shared<CompletionItem>();
    SSLCertificate_Subject->addChild("common_name");
    SSLCertificate_Subject->addChild("country_name");
    SSLCertificate_Subject->addChild("locality");
    SSLCertificate_Subject->addChild("organization");
    SSLCertificate_Subject->addChild("organizational_unit");
    SSLCertificate_Subject->addChild("state_or_province_name");

    std::shared_ptr<CompletionItem> SSLCertificate_Validity = std::make_shared<CompletionItem>();
    SSLCertificate_Validity->addChild("expiry_time");
    SSLCertificate_Validity->addChild("issue_time");

    std::shared_ptr<CompletionItem> SSLCertificate = std::make_shared<CompletionItem>();
    SSLCertificate->addChild(protobufStruct, "cert_extensions");
    SSLCertificate->addChild(SSLCertificate_CertSignature, "cert_signature");
    SSLCertificate->addChild(SSLCertificate_EC, "ec");
    SSLCertificate->addChild(SSLCertificate_Extension, "extension");
    SSLCertificate->addChild("first_seen_time");
    SSLCertificate->addChild(SSLCertificate_Subject, "issuer");
    SSLCertificate->addChild("serial_number");
    SSLCertificate->addChild("signature_algorithm");
    SSLCertificate->addChild("size");
    SSLCertificate->addChild(SSLCertificate_Subject, "subject");
    SSLCertificate->addChild("thumbprint");
    SSLCertificate->addChild("thumbprint_sha256");
    SSLCertificate->addChild(SSLCertificate_Validity, "validity");
    SSLCertificate->addChild("version");

    std::shared_ptr<CompletionItem> location = std::make_shared<CompletionItem>();
    location->addChild("city");
    location->addChild("country_or_region");
    location->addChild("desk_name");
    location->addChild("floor_name");
    location->addChild("name");
    location->addChild("region_coordinates");
    location->addChild("region_latitude");
    location->addChild("region_longitude");
    location->addChild("state");

    std::shared_ptr<CompletionItem> dhcp_option = std::make_shared<CompletionItem>();
    dhcp_option->addChild("code");
    dhcp_option->addChild("data");

    std::shared_ptr<CompletionItem> dhcp = std::make_shared<CompletionItem>();
    dhcp->addChild("chaddr");
    dhcp->addChild("ciaddr");
    dhcp->addChild("client_hostname");
    dhcp->addChild("client_identifier");
    dhcp->addChild("file");
    dhcp->addChild("flags");
    dhcp->addChild("giaddr");
    dhcp->addChild("hlen");
    dhcp->addChild("hops");
    dhcp->addChild("htype");
    dhcp->addChild("lease_time_seconds");
    dhcp->addChild("opcode");
    dhcp->addChild(dhcp_option, "options");
    dhcp->addChild("requested_address");
    dhcp->addChild("seconds");
    dhcp->addChild("siaddr");
    dhcp->addChild("sname");
    dhcp->addChild("transaction_id");
    dhcp->addChild("type");
    dhcp->addChild("yiaddr");

    std::shared_ptr<CompletionItem> prevalence = std::make_shared<CompletionItem>();
    prevalence->addChild("day_count");
    prevalence->addChild("day_max");
    prevalence->addChild("day_max_sub_domains");
    prevalence->addChild("rolling_max");
    prevalence->addChild("rolling_max_sub_domains");

    std::shared_ptr<CompletionItem> dns_ResourceRecord = std::make_shared<CompletionItem>();
    dns_ResourceRecord->addChild("binary_data");
    dns_ResourceRecord->addChild("class");
    dns_ResourceRecord->addChild("data");
    dns_ResourceRecord->addChild("name");
    dns_ResourceRecord->addChild("ttl");
    dns_ResourceRecord->addChild("type");

    std::shared_ptr<CompletionItem> dns_Question = std::make_shared<CompletionItem>();
    dns_Question->addChild("class");
    dns_Question->addChild("name");
    dns_Question->addChild(prevalence, "prevalence");
    dns_Question->addChild("type");

    std::shared_ptr<CompletionItem> dns = std::make_shared<CompletionItem>();
    dns->addChild(dns_ResourceRecord, "additional");
    dns->addChild(dns_ResourceRecord, "answers");
    dns->addChild("authoritative");
    dns->addChild(dns_ResourceRecord, "authority");
    dns->addChild("id");
    dns->addChild("opcode");
    dns->addChild(dns_Question, "questions");
    dns->addChild("recursion_available");
    dns->addChild("recursion_desired");
    dns->addChild("response");
    dns->addChild("response_code");
    dns->addChild("truncated");

    std::shared_ptr<CompletionItem> email = std::make_shared<CompletionItem>();
    email->addChild("bcc");
    email->addChild("bounce_address");
    email->addChild("cc");
    email->addChild("from");
    email->addChild("mail_id");
    email->addChild("reply_to");
    email->addChild("subject");
    email->addChild("to");

    std::shared_ptr<CompletionItem> ftp = std::make_shared<CompletionItem>();
    ftp->addChild("command");

    std::shared_ptr<CompletionItem> http = std::make_shared<CompletionItem>();
    http->addChild("method");
    http->addChild("parsed_user_agent");
    http->addChild("referral_url");
    http->addChild("response_code");
    http->addChild("user_agent");

    std::shared_ptr<CompletionItem> certificate = std::make_shared<CompletionItem>();
    certificate->addChild("issuer");
    certificate->addChild("md5");
    certificate->addChild("not_after");
    certificate->addChild("not_before");
    certificate->addChild("serial");
    certificate->addChild("sha1");
    certificate->addChild("sha256");
    certificate->addChild("subject");
    certificate->addChild("version");

    std::shared_ptr<CompletionItem> tls_server = std::make_shared<CompletionItem>();
    tls_server->addChild("certificate");
    tls_server->addChild("ja3s");

    std::shared_ptr<CompletionItem> tls_client = std::make_shared<CompletionItem>();
    tls_client->addChild(certificate, "certificate");
    tls_client->addChild("ja3");
    tls_client->addChild("server_name");
    tls_client->addChild("supported_ciphers");

    std::shared_ptr<CompletionItem> tls = std::make_shared<CompletionItem>();
    tls->addChild("cipher");
    tls->addChild(tls_client, "client");
    tls->addChild("curve");
    tls->addChild("established");
    tls->addChild("next_protocol");
    tls->addChild("resumed");
    tls->addChild(tls_server, "server");
    tls->addChild("version");
    tls->addChild("version_protocol");

    std::shared_ptr<CompletionItem> network = std::make_shared<CompletionItem>();
    network->addChild("application_protocol");
    network->addChild("application_protocol_version");
    network->addChild("asn");
    network->addChild("carrier_name");
    network->addChild("community_id");
    network->addChild(dhcp, "dhcp");
    network->addChild("direction");
    network->addChild(dns, "dns");
    network->addChild("dns_domain");
    network->addChild(email, "email");
    network->addChild(ftp, "ftp");
    network->addChild(http, "http");
    network->addChild("ip_protocol");
    network->addChild("ip_subnet_range");
    network->addChild("organization_name");
    network->addChild("parent_session_id");
    network->addChild("received_bytes");
    network->addChild("received_packets");
    network->addChild("sent_bytes");
    network->addChild("sent_packets");
    network->addChild("session_duration");
    network->addChild("session_id");
    network->addChild("smtp");
    network->addChild(tls, "tls");

    std::shared_ptr<CompletionItem> artifact = std::make_shared<CompletionItem>();
    artifact->addChild("as_owner");
    artifact->addChild("asn");
    artifact->addChild("first_seen_time");
    artifact->addChild("ip");
    artifact->addChild("jarm");
    artifact->addChild(SSLCertificate, "last_http_certificate");
    artifact->addChild("last_https_certificate_date");
    artifact->addChild("last_seen_time");
    artifact->addChild(location, "location");
    artifact->addChild(network, "network");
    artifact->addChild(prevalence, "prevalence");
    artifact->addChild("regional_internet_registry");
    artifact->addChild("tags");
    artifact->addChild("whois");
    artifact->addChild("whois_date");

    std::shared_ptr<CompletionItem> resource = std::make_shared<CompletionItem>();
    std::shared_ptr<CompletionItem> cloud = std::make_shared<CompletionItem>();
    cloud->addChild("availability_zone");
    cloud->addChild("environment");
    cloud->addChild(resource, "project");
    cloud->addChild(resource, "vpc");

    std::shared_ptr<CompletionItem> label = std::make_shared<CompletionItem>();
    label->addChild("key");
    label->addChild("rbac_enabled");
    label->addChild("value");

    std::shared_ptr<CompletionItem> permission = std::make_shared<CompletionItem>();
    permission->addChild("description");
    permission->addChild("name");
    permission->addChild("type");

    std::shared_ptr<CompletionItem> role = std::make_shared<CompletionItem>();
    role->addChild("description");
    role->addChild("name");
    role->addChild("type");

    std::shared_ptr<CompletionItem> attribute = std::make_shared<CompletionItem>();
    attribute->addChild(cloud, "cloud");
    attribute->addChild("creation_time");
    attribute->addChild(label, "labels");
    attribute->addChild("last_update_time");
    attribute->addChild(permission, "permissions");
    attribute->addChild(role, "roles");

    // Definition is above
    //std::shared_ptr<CompletionItem> resource = std::make_shared<CompletionItem>();
    resource->addChild(attribute, "attribute");
    resource->addChild("id");
    resource->addChild("name");
    resource->addChild("parent");
    resource->addChild("product_object_id");
    resource->addChild("resource_subtype");
    resource->addChild("resource_type");
    resource->addChild("type");

    std::shared_ptr<CompletionItem> hardware = std::make_shared<CompletionItem>();
    hardware->addChild("cpu_clock_speed");
    hardware->addChild("cpu_max_clock_speed");
    hardware->addChild("cpu_model");
    hardware->addChild("cpu_number_cores");
    hardware->addChild("cpu_platform");
    hardware->addChild("manufacturer");
    hardware->addChild("model");
    hardware->addChild("ram");
    hardware->addChild("serial_number");

    std::shared_ptr<CompletionItem> platformSoftware = std::make_shared<CompletionItem>();
    platformSoftware->addChild("platform");
    platformSoftware->addChild("platform_patch_level");
    platformSoftware->addChild("platform_version");

    std::shared_ptr<CompletionItem> software = std::make_shared<CompletionItem>();
    software->addChild("description");
    software->addChild("name");
    software->addChild(permission, "permissions");
    software->addChild("vendor_name");
    software->addChild("version");

    std::shared_ptr<CompletionItem> vulnerability = std::make_shared<CompletionItem>();
    vulnerability->addChild(noun, "about");
    vulnerability->addChild("cve_description");
    vulnerability->addChild("cve_id");
    vulnerability->addChild("cvss_base_score");
    vulnerability->addChild("cvss_vector");
    vulnerability->addChild("cvss_version");
    vulnerability->addChild("description");
    vulnerability->addChild("first_found");
    vulnerability->addChild("last_found");
    vulnerability->addChild("name");
    vulnerability->addChild("scan_end_time");
    vulnerability->addChild("scan_start_time");
    vulnerability->addChild("severity");
    vulnerability->addChild("severity_details");
    vulnerability->addChild("vendor");
    vulnerability->addChild("vendor_knowledge_base_article_id");
    vulnerability->addChild("vendor_vulnerability_id");

    std::shared_ptr<CompletionItem> asset = std::make_shared<CompletionItem>();
    asset->addChild("asset_id");
    asset->addChild(attribute, "attribute");
    asset->addChild("category");
    asset->addChild("creation_time");
    asset->addChild("deployment_status");
    asset->addChild("first_discover_time");
    asset->addChild("first_seen_time");
    asset->addChild(hardware, "hardware");
    asset->addChild("hostname");
    asset->addChild("ip");
    asset->addChild(label, "labels");
    asset->addChild("last_boot_time");
    asset->addChild("last_discover_time");
    asset->addChild(location, "location");
    asset->addChild("mac");
    asset->addChild("nat_ip");
    asset->addChild("network_domain");
    asset->addChild(platformSoftware, "platform_software");
    asset->addChild("product_object_id");
    asset->addChild(software, "software");
    asset->addChild("system_last_update_time");
    asset->addChild("type");
    asset->addChild(vulnerability, "vulnerabilities");

    std::shared_ptr<CompletionItem> timeOff = std::make_shared<CompletionItem>();
    timeOff->addChild("description");
    timeOff->addChild("interval");

    std::shared_ptr<CompletionItem> user = std::make_shared<CompletionItem>();
    user->addChild("account_expiration_time");
    user->addChild("account_lockout_time");
    user->addChild("account_type");
    user->addChild(attribute, "attribute");
    user->addChild("company_name");
    user->addChild("department");
    user->addChild("email_addresses");
    user->addChild("employee_id");
    user->addChild("first_name");
    user->addChild("first_seen_time");
    user->addChild("group_identifiers");
    user->addChild("groupid");
    user->addChild("hire_date");
    user->addChild("last_bad_password_attempt_time");
    user->addChild("last_login_time");
    user->addChild("last_name");
    user->addChild("last_password_change_time");
    user->addChild(user, "managers");
    user->addChild("middle_name");
    user->addChild(location, "office_address");
    user->addChild("password_expiration_time");
    user->addChild(location, "personal_address");
    user->addChild("phone_numbers");
    user->addChild("product_object_id");
    user->addChild("role_description");
    user->addChild("role_name");
    user->addChild("termination_date");
    user->addChild(timeOff, "time_off");
    user->addChild("title");
    user->addChild("user_authentication_status");
    user->addChild("user_display_name");
    user->addChild("user_role");
    user->addChild("userid");
    user->addChild("windows_sid");

    std::shared_ptr<CompletionItem> favicon = std::make_shared<CompletionItem>();
    favicon->addChild(user, "dhash");
    favicon->addChild(user, "raw_md5");

    std::shared_ptr<CompletionItem> dnsRecord = std::make_shared<CompletionItem>();
    dnsRecord->addChild(user, "expire");
    dnsRecord->addChild(user, "minimum");
    dnsRecord->addChild(user, "priority");
    dnsRecord->addChild(user, "refresh");
    dnsRecord->addChild(user, "retry");
    dnsRecord->addChild(user, "rname");
    dnsRecord->addChild(user, "serial");
    dnsRecord->addChild(user, "ttl");
    dnsRecord->addChild(user, "type");
    dnsRecord->addChild(user, "value");

    std::shared_ptr<CompletionItem> popularityRank = std::make_shared<CompletionItem>();
    popularityRank->addChild(user, "giver");
    popularityRank->addChild(user, "ingestion_time");
    popularityRank->addChild(user, "rank");

    std::shared_ptr<CompletionItem> domain = std::make_shared<CompletionItem>();
    domain->addChild(user, "admin");
    domain->addChild("audit_update_time");
    domain->addChild(user, "billing");
    domain->addChild("categories");
    domain->addChild("contact_email");
    domain->addChild("creation_time");
    domain->addChild("expiration_time");
    domain->addChild(favicon, "favicon");
    domain->addChild("first_seen_time");
    domain->addChild("iana_registrar_id");
    domain->addChild("jarm");
    domain->addChild(dnsRecord, "last_dns_records");
    domain->addChild("last_dns_records_time");
    domain->addChild(SSLCertificate, "last_https_certificate");
    domain->addChild("last_https_certificate_time");
    domain->addChild("last_seen_time");
    domain->addChild("name");
    domain->addChild("name_server");
    domain->addChild(popularityRank, "popularity_ranks");
    domain->addChild(prevalence, "prevalence");
    domain->addChild("private_registration");
    domain->addChild(user, "registrant");
    domain->addChild("registrar");
    domain->addChild("registry_data_raw_text");
    domain->addChild("status");
    domain->addChild("tags");
    domain->addChild(user, "tech");
    domain->addChild("update_time");
    domain->addChild("whois_record_raw_text");
    domain->addChild("whois_server");
    domain->addChild("whois_time");
    domain->addChild(user, "zone");

    std::shared_ptr<CompletionItem> pdfInfo = std::make_shared<CompletionItem>();
    pdfInfo->addChild("acroform");
    pdfInfo->addChild("autoaction");
    pdfInfo->addChild("embedded_file");
    pdfInfo->addChild("encrypted");
    pdfInfo->addChild("endobj_count");
    pdfInfo->addChild("endstream_count");
    pdfInfo->addChild("flash");
    pdfInfo->addChild("header");
    pdfInfo->addChild("javascript");
    pdfInfo->addChild("jbig2_compression");
    pdfInfo->addChild("js");
    pdfInfo->addChild("launch_action_count");
    pdfInfo->addChild("obj_count");
    pdfInfo->addChild("object_stream_count");
    pdfInfo->addChild("openaction");
    pdfInfo->addChild("page_count");
    pdfInfo->addChild("startxref");
    pdfInfo->addChild("stream_count");
    pdfInfo->addChild("suspicious_colors");
    pdfInfo->addChild("trailer");
    pdfInfo->addChild("xfa");
    pdfInfo->addChild("xref");

    std::shared_ptr<CompletionItem> signerInfo = std::make_shared<CompletionItem>();
    signerInfo->addChild("cert_issuer");
    signerInfo->addChild("name");
    signerInfo->addChild("status");
    signerInfo->addChild("valid_usage");

    std::shared_ptr<CompletionItem> x509 = std::make_shared<CompletionItem>();
    x509->addChild("algorithm");
    x509->addChild("cert_issuer");
    x509->addChild("name");
    x509->addChild("serial_number");
    x509->addChild("thumbprint");

    std::shared_ptr<CompletionItem> fileMetadataSignatureInfo = std::make_shared<CompletionItem>();
    fileMetadataSignatureInfo->addChild("signer");
    fileMetadataSignatureInfo->addChild(signerInfo, "signers");
    fileMetadataSignatureInfo->addChild("verification_message");
    fileMetadataSignatureInfo->addChild("verified");
    fileMetadataSignatureInfo->addChild(x509, "x509");

    std::shared_ptr<CompletionItem> fileMetadataPE = std::make_shared<CompletionItem>();
    fileMetadataPE->addChild("compilation_exiftool_time");
    fileMetadataPE->addChild("compilation_time");
    fileMetadataPE->addChild("entry_point");
    fileMetadataPE->addChild("entry_point_exiftool");
    fileMetadataPE->addChild("imphash");
    fileMetadataPE->addChild("imports");
    fileMetadataPE->addChild("resource");
    fileMetadataPE->addChild("resources_language_count");
    fileMetadataPE->addChild(label, "resources_language_count_str");
    fileMetadataPE->addChild("resources_type_count");
    fileMetadataPE->addChild(label, "resources_type_count_str");
    fileMetadataPE->addChild("section");
    fileMetadataPE->addChild(signerInfo, "signature_info");

    std::shared_ptr<CompletionItem> analyticsMetadata = std::make_shared<CompletionItem>();
    analyticsMetadata->addChild("analytic");

    std::shared_ptr<CompletionItem> securityResult_associationAlias = std::make_shared<CompletionItem>();
    securityResult_associationAlias->addChild("company");
    securityResult_associationAlias->addChild("name");

    std::shared_ptr<CompletionItem> securityResult_association = std::make_shared<CompletionItem>();
    securityResult_association->addChild(securityResult_associationAlias, "alias");
    securityResult_association->addChild(securityResult_association, "associated_actors");
    securityResult_association->addChild("country_code");
    securityResult_association->addChild("description");
    securityResult_association->addChild("first_reference_time");
    securityResult_association->addChild("id");
    securityResult_association->addChild("industries_affected");
    securityResult_association->addChild("last_reference_time");
    securityResult_association->addChild("name");
    securityResult_association->addChild(location, "region_code");
    securityResult_association->addChild("role");
    securityResult_association->addChild("source_country");
    securityResult_association->addChild(location, "sponsor_region");
    securityResult_association->addChild("tags");
    securityResult_association->addChild(location, "targeted_regions");
    securityResult_association->addChild("type");

    std::shared_ptr<CompletionItem> attackDetails_tactic = std::make_shared<CompletionItem>();
    attackDetails_tactic->addChild("id");
    attackDetails_tactic->addChild("name");

    std::shared_ptr<CompletionItem> attackDetails_technique = std::make_shared<CompletionItem>();
    attackDetails_technique->addChild("id");
    attackDetails_technique->addChild("name");
    attackDetails_technique->addChild("subtechnique_id");
    attackDetails_technique->addChild("subtechnique_name");

    std::shared_ptr<CompletionItem> attackDetails = std::make_shared<CompletionItem>();
    attackDetails->addChild(attackDetails_tactic, "tactics");
    attackDetails->addChild(attackDetails_technique, "techniques");
    attackDetails->addChild("version");

    std::shared_ptr<CompletionItem> securityResult_IoCStats = std::make_shared<CompletionItem>();
    securityResult_IoCStats->addChild("benign_count");
    securityResult_IoCStats->addChild("first_level_source");
    securityResult_IoCStats->addChild("ioc_stats_type");
    securityResult_IoCStats->addChild("malicious_count");
    securityResult_IoCStats->addChild("quality");
    securityResult_IoCStats->addChild("response_count");
    securityResult_IoCStats->addChild("second_level_source");
    securityResult_IoCStats->addChild("source_count");

    std::shared_ptr<CompletionItem> securityResult_verdictInfo = std::make_shared<CompletionItem>();
    securityResult_verdictInfo->addChild("benign_count");
    securityResult_verdictInfo->addChild("category_details");
    securityResult_verdictInfo->addChild("confidence_score");
    securityResult_verdictInfo->addChild("global_customer_count");
    securityResult_verdictInfo->addChild("global_hits_count");
    securityResult_verdictInfo->addChild(securityResult_IoCStats, "ioc_stats");
    securityResult_verdictInfo->addChild("malicious_count");
    securityResult_verdictInfo->addChild("neighbour_influence");
    securityResult_verdictInfo->addChild("pwn");
    securityResult_verdictInfo->addChild("pwn_first_tagged_time");
    securityResult_verdictInfo->addChild("response_count");
    securityResult_verdictInfo->addChild("source_count");
    securityResult_verdictInfo->addChild("source_provider");
    securityResult_verdictInfo->addChild("verdict_response");
    securityResult_verdictInfo->addChild("verdict_time");
    securityResult_verdictInfo->addChild("verdict_type");

    std::shared_ptr<CompletionItem> securityResult = std::make_shared<CompletionItem>();
    securityResult->addChild(noun, "about");
    securityResult->addChild("action");
    securityResult->addChild("action_details");
    securityResult->addChild("alert_state");
    securityResult->addChild(analyticsMetadata, "analytics_metadata");
    securityResult->addChild(securityResult_association, "associations");
    securityResult->addChild(attackDetails, "attack_details");
    securityResult->addChild("campaigns");
    securityResult->addChild("category");
    securityResult->addChild("category_details");
    securityResult->addChild("confidence");
    securityResult->addChild("confidence_details");
    securityResult->addChild("confidence_score");
    securityResult->addChild("description");
    securityResult->addChild(label, "detection_fields");
    securityResult->addChild("first_discovered_time");
    securityResult->addChild("last_discovered_time");
    securityResult->addChild("last_updated_time");
    securityResult->addChild(label, "outcomes");
    securityResult->addChild("priority");
    securityResult->addChild("priority_details");
    securityResult->addChild("risk_score");
    securityResult->addChild("rule_author");
    securityResult->addChild("rule_id");
    securityResult->addChild(label, "rule_labels");
    securityResult->addChild("rule_name");
    securityResult->addChild("rule_set");
    securityResult->addChild("rule_set_display_name");
    securityResult->addChild("rule_type");
    securityResult->addChild("rule_version");
    securityResult->addChild("ruleset_category_display_name");
    securityResult->addChild("severity");
    securityResult->addChild("severity_details");
    securityResult->addChild("summary");
    securityResult->addChild("threat_feed_name");
    securityResult->addChild("threat_id");
    securityResult->addChild("threat_id_namespace");
    securityResult->addChild("threat_name");
    securityResult->addChild("threat_status");
    securityResult->addChild("threat_verdict");
    securityResult->addChild("url_back_to_product");
    securityResult->addChild("verdict");
    securityResult->addChild(securityResult_verdictInfo, "verdict_info");

    std::shared_ptr<CompletionItem> fileMetadataCodesign = std::make_shared<CompletionItem>();
    fileMetadataCodesign->addChild("compilation_time");
    fileMetadataCodesign->addChild("format");
    fileMetadataCodesign->addChild("id");

    std::shared_ptr<CompletionItem> signatureInfo = std::make_shared<CompletionItem>();
    signatureInfo->addChild(fileMetadataCodesign, "codesign");
    signatureInfo->addChild(fileMetadataSignatureInfo, "sigcheck");

    std::shared_ptr<CompletionItem> file = std::make_shared<CompletionItem>();
    file->addChild("ahash");
    file->addChild("authentihash");
    file->addChild("capabilities_tags");
    file->addChild("embedded_domains");
    file->addChild("embedded_ips");
    file->addChild("embedded_urls");
    file->addChild("exif_info");
    file->addChild("file_metadata");
    file->addChild("file_type");
    file->addChild("first_seen_time");
    file->addChild("first_submission_time");
    file->addChild("full_path");
    file->addChild("last_analysis_time");
    file->addChild("last_modification_time");
    file->addChild("last_seen_time");
    file->addChild("last_submission_time");
    file->addChild(favicon, "main_icon");
    file->addChild("md5");
    file->addChild("mime_type");
    file->addChild("names");
    file->addChild(pdfInfo, "pdf_info");
    file->addChild(fileMetadataPE, "pe_file");
    file->addChild(prevalence, "prevalence");
    file->addChild(securityResult, "security_result");
    file->addChild("sha1");
    file->addChild("sha256");
    file->addChild(signatureInfo, "signature_info");
    file->addChild("size");
    file->addChild("ssdeep");
    file->addChild("stat_dev");
    file->addChild("stat_flags");
    file->addChild("stat_inode");
    file->addChild("stat_mode");
    file->addChild("stat_nlink");
    file->addChild("tags");
    file->addChild("vhash");

    std::shared_ptr<CompletionItem> group = std::make_shared<CompletionItem>();
    group->addChild(attribute, "attribute");
    group->addChild("creation_time");
    group->addChild("email_addresses");
    group->addChild("group_display_name");
    group->addChild("product_object_id");
    group->addChild("windows_sid");

    std::shared_ptr<CompletionItem> securityResult_analystVerdict = std::make_shared<CompletionItem>();
    securityResult_analystVerdict->addChild("confidence_score");
    securityResult_analystVerdict->addChild("verdict_response");
    securityResult_analystVerdict->addChild("verdict_time");

    std::shared_ptr<CompletionItem> securityResult_source = std::make_shared<CompletionItem>();
    securityResult_source->addChild("benign_count");
    securityResult_source->addChild("malicious_count");
    securityResult_source->addChild("name");
    securityResult_source->addChild("quality");
    securityResult_source->addChild("response_count");
    securityResult_source->addChild("source_count");
    securityResult_source->addChild(securityResult_source, "threat_intelligence_sources");

    std::shared_ptr<CompletionItem> securityResult_providerMLVerdict = std::make_shared<CompletionItem>();
    securityResult_providerMLVerdict->addChild("benign_count");
    securityResult_providerMLVerdict->addChild("confidence_score");
    securityResult_providerMLVerdict->addChild("malicious_count");
    securityResult_providerMLVerdict->addChild(securityResult_source, "mandiant_sources");
    securityResult_providerMLVerdict->addChild("source_provider");
    securityResult_providerMLVerdict->addChild(securityResult_source, "third_party_sources");

    std::shared_ptr<CompletionItem> securityResult_verdict = std::make_shared<CompletionItem>();
    securityResult_verdict->addChild(securityResult_analystVerdict, "analyst_verdict");
    securityResult_verdict->addChild("neighbour_influence");
    securityResult_verdict->addChild("response_count");
    securityResult_verdict->addChild("source_count");
    securityResult_verdict->addChild(securityResult_providerMLVerdict, "verdict");

    std::shared_ptr<CompletionItem> investigation = std::make_shared<CompletionItem>();
    investigation->addChild("comments");
    investigation->addChild("priority");
    investigation->addChild("reason");
    investigation->addChild("reputation");
    investigation->addChild("risk_score");
    investigation->addChild("root_cause");
    investigation->addChild("severity_score");
    investigation->addChild("status");
    investigation->addChild(securityResult_verdict, "verdict");

    std::shared_ptr<CompletionItem> process = std::make_shared<CompletionItem>();
    process->addChild("access_mask");
    process->addChild("command_line");
    process->addChild("command_line_history");
    process->addChild(file, "file");
    process->addChild("integrity_level_rid");
    process->addChild("parent_pid");
    process->addChild(process, "parent_process");
    process->addChild("pid");
    process->addChild("product_specific_parent_process_id");
    process->addChild("product_specific_process_id");
    process->addChild("token_elevation_type");

    std::shared_ptr<CompletionItem> registry = std::make_shared<CompletionItem>();
    registry->addChild("registry_key");
    registry->addChild("registry_value_data");
    registry->addChild("registry_value_name");

    std::shared_ptr<CompletionItem> tracker = std::make_shared<CompletionItem>();
    tracker->addChild("id");
    tracker->addChild("timestamp");
    tracker->addChild("tracker");
    tracker->addChild("url");

    std::shared_ptr<CompletionItem> url = std::make_shared<CompletionItem>();
    url->addChild("categories");
    url->addChild(favicon, "favicon");
    url->addChild(protobufStruct, "html_meta");
    url->addChild("last_final_url");
    url->addChild("last_http_response_code");
    url->addChild("last_http_response_content_length");
    url->addChild("last_http_response_content_sha256");
    url->addChild(protobufStruct, "last_http_response_cookies");
    url->addChild(protobufStruct, "last_http_response_headers");
    url->addChild("tags");
    url->addChild("title");
    url->addChild(tracker, "trackers");
    url->addChild("url");

    // Definition is above
    // std::shared_ptr<CompletionItem> noun = std::make_shared<CompletionItem>();
    noun->addChild("administrative_domain");
    noun->addChild("application");
    noun->addChild(artifact, "artifact");
    noun->addChild(asset, "asset");
    noun->addChild("asset_id");
    noun->addChild(cloud, "cloud");
    noun->addChild(domain, "domain");
    noun->addChild("email");
    noun->addChild(file, "file");
    noun->addChild(group, "group");
    noun->addChild("hostname");
    noun->addChild(investigation, "investigation");
    noun->addChild("ip");
    noun->addChild(artifact, "ip_geo_artifact");
    noun->addChild(location, "ip_location");
    noun->addChild(label, "labels");
    noun->addChild(location, "location");
    noun->addChild("mac");
    noun->addChild("namespace");
    noun->addChild("nat_ip");
    noun->addChild("nat_port");
    noun->addChild(network, "network");
    noun->addChild("object_reference");
    noun->addChild("platform");
    noun->addChild("platform_patch_level");
    noun->addChild("platform_version");
    noun->addChild("port");
    noun->addChild(process, "process");
    noun->addChild(process, "process_ancestors");
    noun->addChild(registry, "registry");
    noun->addChild(resource, "resource");
    noun->addChild(resource, "resource_ancestors");
    noun->addChild(securityResult, "security_result");
    noun->addChild("url");
    noun->addChild(url, "url_metadata");
    noun->addChild(user, "user");
    noun->addChild(user, "user_management_chain");

    std::shared_ptr<CompletionItem> authentication = std::make_shared<CompletionItem>();
    authentication->addChild("auth_details");
    authentication->addChild("mechanism");
    authentication->addChild("type");

    std::shared_ptr<CompletionItem> vulnerabilities = std::make_shared<CompletionItem>();
    vulnerabilities->addChild(vulnerability, "vulnerabilities");

    std::shared_ptr<CompletionItem> extensions = std::make_shared<CompletionItem>();
    extensions->addChild(authentication, "auth");
    extensions->addChild(vulnerabilities, "vulns");

    std::shared_ptr<CompletionItem> tags = std::make_shared<CompletionItem>();
    tags->addChild("data_tap_config_name");
    tags->addChild("tenant_id");
    
    std::shared_ptr<CompletionItem> metadata = std::make_shared<CompletionItem>();
    metadata->addChild("base_labels");
    metadata->addChild("collected_timestamp");
    metadata->addChild("description");
    metadata->addChild("enrichment_labels");
    metadata->addChild("enrichment_state");
    metadata->addChild("event_timestamp");
    metadata->addChild("event_type");
    metadata->addChild("id");
    metadata->addChild("ingested_timestamp");
    metadata->addChild(label, "ingestion_labels");
    metadata->addChild("log_type");
    metadata->addChild("product_deployment_id");
    metadata->addChild("product_event_type");
    metadata->addChild("product_log_id");
    metadata->addChild("product_name");
    metadata->addChild("product_version");
    metadata->addChild(tags, "tags");
    metadata->addChild("url_back_to_product");
    metadata->addChild("vendor_name");

    root->addChild(noun, "about");
    root->addChild(protobufStruct, "additional");
    root->addChild(extensions, "extensions");
    root->addChild(noun, "intermediary");
    root->addChild(metadata, "metadata");
    root->addChild(network, "network");
    root->addChild(noun, "observer");
    root->addChild(noun, "principal");
    root->addChild(securityResult, "security_result");
    root->addChild(noun, "src");
    root->addChild(noun, "target");
}


bool operator==(const CompletionItemProperties& lhs, const CompletionItemProperties& rhs) {
        return lhs.label == rhs.label;
}


void CompletionItem::addChild(const std::string& label) {
    children[CompletionItemProperties(label)] = nullptr;
}

void CompletionItem::addChild(const CompletionItemProperties& property) {
    children[property] = nullptr;
}

void CompletionItem::addChild(std::shared_ptr<CompletionItem> ptr, const std::string& label) {
    children[CompletionItemProperties(label)] = ptr;
}

void CompletionItem::addChild(std::shared_ptr<CompletionItem> ptr, const CompletionItemProperties& property) {
    children[property] = ptr;
}

const std::string& CompletionItemProperties::getLabel() const {return label;}
const std::optional<json> CompletionItemProperties::getLabelDetails() const {return labelDetails;}
const std::optional<json> CompletionItemProperties::getKind() const {return kind;}
const std::optional<json> CompletionItemProperties::getTags() const {return tags;}
const std::optional<json> CompletionItemProperties::getDetail() const {return detail;}
const std::optional<json> CompletionItemProperties::getDocumentation() const {return documentation;}
const std::optional<json> CompletionItemProperties::getPreselect() const {return preselect;}
const std::optional<json> CompletionItemProperties::getSortText() const {return sortText;}
const std::optional<json> CompletionItemProperties::getFilterText() const {return filterText;}
const std::optional<json> CompletionItemProperties::getInsertText() const {return insertText;}
const std::optional<json> CompletionItemProperties::getInsertTextFormat() const {return insertTextFormat;}
const std::optional<json> CompletionItemProperties::getInsertTextMode() const {return insertTextMode;}
const std::optional<json> CompletionItemProperties::getTextEdit() const {return textEdit;}
const std::optional<json> CompletionItemProperties::getTextEditText() const {return textEditText;}
const std::optional<json> CompletionItemProperties::getAdditionalTextEdits() const {return additionalTextEdits;}
const std::optional<json> CompletionItemProperties::getCommitCharacters() const {return commitCharacters;}
const std::optional<json> CompletionItemProperties::getCommand() const {return command;}
const std::optional<json> CompletionItemProperties::getData() const {return data;}


template <class T>
void add_if_present(json& j, std::string name, const std::optional<T>& opt) {
    if (opt.has_value())
        j[name]=opt.value();
}

void to_json(json& j, const CompletionItemProperties& i) {
    j = json{ {"label", i.getLabel()}};
    add_if_present(j, "labelDetails", i.getLabelDetails());
    add_if_present(j, "kind", i.getKind());
    add_if_present(j, "tags", i.getTags());
    add_if_present(j, "detail", i.getDetail());
    add_if_present(j, "documentation", i.getDocumentation());
    add_if_present(j, "preselect", i.getPreselect());
    add_if_present(j, "sortText", i.getSortText());
    add_if_present(j, "filterText", i.getFilterText());
    add_if_present(j, "insertText", i.getInsertText());
    add_if_present(j, "insertTextFormat", i.getInsertTextFormat());
    add_if_present(j, "insertTextMode", i.getInsertTextMode());
    add_if_present(j, "textEdit", i.getTextEdit());
    add_if_present(j, "textEditText", i.getTextEditText());
    add_if_present(j, "additionalTextEdits", i.getAdditionalTextEdits());
    add_if_present(j, "commitCharacters", i.getCommitCharacters());
    add_if_present(j, "command", i.getCommand());
    add_if_present(j, "data", i.getData());
}


void to_json(json& j, const completion_list& p) {
    j = json{
        {"isIncomplete", p.isIncomplete},
        {"items", p.items}
    };
    add_if_present(j, "itemDefaults", p.itemDefaults);
}


const std::shared_ptr<CompletionItem> CompletionItem::getChildByName(std::string name) const {
    for (const auto& pair : children) {
        if (pair.first == name)
            return pair.second;
    }
    return nullptr;
}

std::string getCurrentExpression(const std::string& line, size_t pos) {
    if (pos >= line.size()) {
        return "";
    }

    // Find the start
    size_t start = pos;
    while (start > 0 && line[start - 1] != ' ' && line[start - 1] != '=' && line[start - 1] != '(') {
        --start;
    }

    // Find the end
    size_t end = pos;
    while (end < line.size() && line[end] != ' ' && line[end] != '=' && line[end] != ')') {
        ++end;
    }

    return line.substr(start, end - start);
}


bool isEndDelim(char lastDelim, char c) {
    switch (lastDelim) {
    case '`':
    case '/':
    case '\"':
    case '\'':
        return lastDelim == c;
    case '[':
        return c == ']';
    default:
        return true;
    }
}

bool isStartDelim(char c) {
    return c == '[' || c == ']' || c == '`' || c == '\'' || c == '/' || c == '\"';
}

const std::vector<CompletionItemProperties> CompletionItem::getCompletionList(const std::string& line, int pos) {
    std::string expression = getCurrentExpression(line, pos);

    std::stringstream ss;
    std::shared_ptr<CompletionItem> current = nullptr;

    size_t len = expression.length();
    bool ignore = false;
    char last_delim;
    for (size_t i = 0; i < len; ++i) {
        if (ignore && isEndDelim(last_delim, expression[i])) { // End of ignore zone
            ignore = false;
            continue;
        }
        if (ignore)
            continue;

        if (isStartDelim(expression[i])) { // Start of ignore zone
            ignore = true;
            last_delim = expression[i];
            continue;
        }

        if (expression[i] == '.') { // noun delimiter
            std::string noun = ss.str();
            print_error(noun);
            if (current == nullptr) {
                if (noun.empty() || noun[0] != '$') // Syntaxe error
                    break;
                current = root; // Initialize root with event name like '$my_event'
            } else {
                current = current->getChildByName(noun);
                if (current == nullptr) // Not found
                  break;
            }

            ss.str("");
            ss.clear();
        } else {
            ss << expression[i];
        }

    }

    std::vector<CompletionItemProperties> res;
    if (current == nullptr)
        return res;

    for (const auto& pair : current->children) {
        res.push_back(pair.first);
    }
    return res;
}
