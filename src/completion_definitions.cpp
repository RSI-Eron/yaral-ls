#include "completion_definitions.h"
#include "logger.h"
#include <cctype>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#define VAR_NAME(var) #var

std::shared_ptr<CompletionItem> CompletionItem::root = std::make_shared<CompletionItem>();

void CompletionItem::initialize_tree() {
    // Google types not (or partially) implemented
    // Graph Entity not implemented
    // Is there a way to shorten this ?
    // Can it be done at compile time ?

    std::shared_ptr<CompletionItem> noun = std::make_shared<CompletionItem>();

    std::shared_ptr<CompletionItem> keyValuePair = std::make_shared<CompletionItem>();
    keyValuePair->addChild("key");
    keyValuePair->addChild("value", "value");

    std::shared_ptr<CompletionItem> protobuf_Struct = std::make_shared<CompletionItem>();
    protobuf_Struct->addChild(keyValuePair, "fields", "map<string, Value>");

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
    SSLCertificate_Extension->addChild(SSLCertificate_AuthorityKeyId, "authority_key_id", VAR_NAME(SSLCertificate_AuthorityKeyId));
    SSLCertificate_Extension->addChild("ca", "bool");
    SSLCertificate_Extension->addChild("ca_info_access");
    SSLCertificate_Extension->addChild("cert_template_name_dc");
    SSLCertificate_Extension->addChild("certificate_policies");
    SSLCertificate_Extension->addChild("crl_distribution_points");
    SSLCertificate_Extension->addChild("extended_key_usage");
    SSLCertificate_Extension->addChild("key_usage");
    SSLCertificate_Extension->addChild("netscape_cert_comment");
    SSLCertificate_Extension->addChild("netscape_certificate", "bool");
    SSLCertificate_Extension->addChild("old_authority_key_id", "bool");
    SSLCertificate_Extension->addChild("pe_logotype", "bool");
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
    SSLCertificate_Validity->addChild("expiry_time", "protobuf.Timestamp");
    SSLCertificate_Validity->addChild("issue_time", "protobuf.Timestamp");

    std::shared_ptr<CompletionItem> SSLCertificate = std::make_shared<CompletionItem>();
    SSLCertificate->addChild(protobuf_Struct, "cert_extensions", VAR_NAME(protobuf_Struct));
    SSLCertificate->addChild(SSLCertificate_CertSignature, "cert_signature", VAR_NAME(SSLCertificate_CertSignature));
    SSLCertificate->addChild(SSLCertificate_EC, "ec", VAR_NAME(SSLCertificate_EC));
    SSLCertificate->addChild(SSLCertificate_Extension, "extension", VAR_NAME(SSLCertificate_Extension));
    SSLCertificate->addChild("first_seen_time", "protobuf.Timestamp");
    SSLCertificate->addChild(SSLCertificate_Subject, "issuer", VAR_NAME(SSLCertificate_Subject));
    SSLCertificate->addChild("serial_number");
    SSLCertificate->addChild("signature_algorithm");
    SSLCertificate->addChild("size", "int64");
    SSLCertificate->addChild(SSLCertificate_Subject, "subject", VAR_NAME(SSLCertificate_Subject));
    SSLCertificate->addChild("thumbprint");
    SSLCertificate->addChild("thumbprint_sha256");
    SSLCertificate->addChild(SSLCertificate_Validity, "validity", VAR_NAME(SSLCertificate_Validity));
    SSLCertificate->addChild("version");

    std::shared_ptr<CompletionItem> location = std::make_shared<CompletionItem>();
    location->addChild("city");
    location->addChild("country_or_region");
    location->addChild("desk_name");
    location->addChild("floor_name");
    location->addChild("name");
    location->addChild("region_coordinates", "type.LatLng");
    location->addChild("region_latitude", "float");
    location->addChild("region_longitude", "float");
    location->addChild("state");

    std::shared_ptr<CompletionItem> dhcp_option = std::make_shared<CompletionItem>();
    dhcp_option->addChild("code", "uint32");
    dhcp_option->addChild("data", "bytes");

    std::shared_ptr<CompletionItem> dhcp = std::make_shared<CompletionItem>();
    dhcp->addChild("chaddr");
    dhcp->addChild("ciaddr");
    dhcp->addChild("client_hostname");
    dhcp->addChild("client_identifier", "bytes");
    dhcp->addChild("file");
    dhcp->addChild("flags", "uint32");
    dhcp->addChild("giaddr");
    dhcp->addChild("hlen", "uint32");
    dhcp->addChild("hops", "uint32");
    dhcp->addChild("htype", "uint32");
    dhcp->addChild("lease_time_seconds", "uint32");
    dhcp->addChild(CompletionItemProperties("opcode", "Dhcp.OpCode", completionItemKind::Enum));
    dhcp->addChild(dhcp_option, "options", VAR_NAME(dhcp_option));
    dhcp->addChild("requested_address");
    dhcp->addChild("seconds", "uint32");
    dhcp->addChild("siaddr");
    dhcp->addChild("sname");
    dhcp->addChild("transaction_id", "uint32");
    dhcp->addChild(CompletionItemProperties("type", "Dhcp.MessageType", completionItemKind::Enum));
    dhcp->addChild("yiaddr");

    std::shared_ptr<CompletionItem> prevalence = std::make_shared<CompletionItem>();
    prevalence->addChild("day_count", "int32");
    prevalence->addChild("day_max", "int32");
    prevalence->addChild("day_max_sub_domains", "int32");
    prevalence->addChild("rolling_max", "int32");
    prevalence->addChild("rolling_max_sub_domains", "int32");

    std::shared_ptr<CompletionItem> dns_ResourceRecord = std::make_shared<CompletionItem>();
    dns_ResourceRecord->addChild("binary_data", "bytes");
    dns_ResourceRecord->addChild("class", "uint32");
    dns_ResourceRecord->addChild("data");
    dns_ResourceRecord->addChild("name");
    dns_ResourceRecord->addChild("ttl", "uint32");
    dns_ResourceRecord->addChild("type", "uint32");

    std::shared_ptr<CompletionItem> dns_Question = std::make_shared<CompletionItem>();
    dns_Question->addChild("class", "uint32");
    dns_Question->addChild("name");
    dns_Question->addChild(prevalence, "prevalence", VAR_NAME(prevalence));
    dns_Question->addChild("type", "uint32");

    std::shared_ptr<CompletionItem> dns = std::make_shared<CompletionItem>();
    dns->addChild(dns_ResourceRecord, "additional", VAR_NAME(dns_ResourceRecord));
    dns->addChild(dns_ResourceRecord, "answers", VAR_NAME(dns_ResourceRecord));
    dns->addChild("authoritative", "bool");
    dns->addChild(dns_ResourceRecord, "authority", VAR_NAME(dns_ResourceRecord));
    dns->addChild("id", "uint32");
    dns->addChild("opcode", "uint32");
    dns->addChild(dns_Question, "questions", VAR_NAME(dns_Question));
    dns->addChild("recursion_available", "bool");
    dns->addChild("recursion_desired", "bool");
    dns->addChild("response", "bool");
    dns->addChild("response_code", "uint32");
    dns->addChild("truncated", "bool");

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
    http->addChild("response_code", "int32");
    http->addChild("user_agent");

    std::shared_ptr<CompletionItem> certificate = std::make_shared<CompletionItem>();
    certificate->addChild("issuer");
    certificate->addChild("md5");
    certificate->addChild("not_after", "protobuf.Timestamp");
    certificate->addChild("not_before", "protobuf.Timestamp");
    certificate->addChild("serial");
    certificate->addChild("sha1");
    certificate->addChild("sha256");
    certificate->addChild("subject");
    certificate->addChild("version");

    std::shared_ptr<CompletionItem> tls_server = std::make_shared<CompletionItem>();
    tls_server->addChild("certificate");
    tls_server->addChild("ja3s");

    std::shared_ptr<CompletionItem> tls_client = std::make_shared<CompletionItem>();
    tls_client->addChild(certificate, "certificate", VAR_NAME(certificate));
    tls_client->addChild("ja3");
    tls_client->addChild("server_name");
    tls_client->addChild("supported_ciphers");

    std::shared_ptr<CompletionItem> tls = std::make_shared<CompletionItem>();
    tls->addChild("cipher");
    tls->addChild(tls_client, "client", VAR_NAME(tls_client));
    tls->addChild("curve");
    tls->addChild("established", "bool");
    tls->addChild("next_protocol");
    tls->addChild("resumed", "bool");
    tls->addChild(tls_server, "server", VAR_NAME(tls_server));
    tls->addChild("version");
    tls->addChild("version_protocol");

    std::shared_ptr<CompletionItem> Smtp = std::make_shared<CompletionItem>();
    Smtp->addChild("helo");
    Smtp->addChild("is_tls", "bool");
    Smtp->addChild("is_webmail", "bool");
    Smtp->addChild("mail_from");
    Smtp->addChild("message_path");
    Smtp->addChild("rcpt_to");
    Smtp->addChild("server_response");

    std::shared_ptr<CompletionItem> network = std::make_shared<CompletionItem>();
    network->addChild(CompletionItemProperties("application_protocol", "Network.ApplicationProtocol", completionItemKind::Enum));
    network->addChild("application_protocol_version");
    network->addChild("asn");
    network->addChild("carrier_name");
    network->addChild("community_id");
    network->addChild(dhcp, "dhcp", VAR_NAME(dhcp));
    network->addChild(CompletionItemProperties("direction", "Network.Direction", completionItemKind::Enum));
    network->addChild(dns, "dns", VAR_NAME(dns));
    network->addChild("dns_domain");
    network->addChild(email, "email", VAR_NAME(email));
    network->addChild(ftp, "ftp", VAR_NAME(ftp));
    network->addChild(http, "http", VAR_NAME(http));
    network->addChild(CompletionItemProperties("ip_protocol", "Network.IpPortocol", completionItemKind::Enum));
    network->addChild("ip_subnet_range");
    network->addChild("organization_name");
    network->addChild("parent_session_id");
    network->addChild("received_bytes", "uint64");
    network->addChild("received_packets", "int64");
    network->addChild("sent_bytes", "uint64");
    network->addChild("sent_packets", "int64");
    network->addChild("session_duration", "int64");
    network->addChild("session_id");
    network->addChild(Smtp, "smtp", VAR_NAME(Smtp));
    network->addChild(tls, "tls", VAR_NAME(tls));

    std::shared_ptr<CompletionItem> artifact = std::make_shared<CompletionItem>();
    artifact->addChild("as_owner");
    artifact->addChild("asn", "int64");
    artifact->addChild("first_seen_time", "protobuf.Timestamp");
    artifact->addChild("ip");
    artifact->addChild("jarm");
    artifact->addChild(SSLCertificate, "last_http_certificate", VAR_NAME(SSLCertificate));
    artifact->addChild("last_https_certificate_date", "protobuf.Timestamp");
    artifact->addChild("last_seen_time", "protobuf.Timestamp");
    artifact->addChild(location, "location", VAR_NAME(location));
    artifact->addChild(network, "network", VAR_NAME(network));
    artifact->addChild(prevalence, "prevalence", VAR_NAME(prevalence));
    artifact->addChild("regional_internet_registry");
    artifact->addChild("tags");
    artifact->addChild("whois");
    artifact->addChild("whois_date", "protobuf.Timestamp");

    std::shared_ptr<CompletionItem> resource = std::make_shared<CompletionItem>();
    std::shared_ptr<CompletionItem> cloud = std::make_shared<CompletionItem>();
    cloud->addChild("availability_zone");
    cloud->addChild(CompletionItemProperties("environment", "Cloud.CloudEnvironment", completionItemKind::Enum));
    cloud->addChild(resource, "project", VAR_NAME(resource));
    cloud->addChild(resource, "vpc", VAR_NAME(resource));

    std::shared_ptr<CompletionItem> label = std::make_shared<CompletionItem>();
    label->addChild("key");
    label->addChild("rbac_enabled", "bool");
    label->addChild("value");

    std::shared_ptr<CompletionItem> permission = std::make_shared<CompletionItem>();
    permission->addChild("description");
    permission->addChild("name");
    permission->addChild(CompletionItemProperties("type", "Permission.PermissionType", completionItemKind::Enum));

    std::shared_ptr<CompletionItem> role = std::make_shared<CompletionItem>();
    role->addChild("description");
    role->addChild("name");
    role->addChild("type", "Role.Type");

    std::shared_ptr<CompletionItem> attribute = std::make_shared<CompletionItem>();
    attribute->addChild(cloud, "cloud", VAR_NAME(cloud));
    attribute->addChild("creation_time", "protobuf.Timestamp");
    attribute->addChild(label, "labels", VAR_NAME(label));
    attribute->addChild("last_update_time", "protobuf.Timestamp");
    attribute->addChild(permission, "permissions", VAR_NAME(permission));
    attribute->addChild(role, "roles", VAR_NAME(role));

    // Definition is above
    //std::shared_ptr<CompletionItem> resource = std::make_shared<CompletionItem>();
    resource->addChild(attribute, "attribute", VAR_NAME(attribute));
    resource->addChild("id");
    resource->addChild("name");
    resource->addChild("parent");
    resource->addChild("product_object_id");
    resource->addChild("resource_subtype");
    resource->addChild(CompletionItemProperties("resource_type", "Resource.ResourceType", completionItemKind::Enum));
    resource->addChild("type");

    std::shared_ptr<CompletionItem> hardware = std::make_shared<CompletionItem>();
    hardware->addChild("cpu_clock_speed", "uint64");
    hardware->addChild("cpu_max_clock_speed", "uint64");
    hardware->addChild("cpu_model");
    hardware->addChild("cpu_number_cores", "uint64");
    hardware->addChild("cpu_platform");
    hardware->addChild("manufacturer");
    hardware->addChild("model");
    hardware->addChild("ram", "uint64");
    hardware->addChild("serial_number");

    std::shared_ptr<CompletionItem> platformSoftware = std::make_shared<CompletionItem>();
    platformSoftware->addChild(CompletionItemProperties("platform", "Noun.Platform", completionItemKind::Enum));
    platformSoftware->addChild("platform_patch_level");
    platformSoftware->addChild("platform_version");

    std::shared_ptr<CompletionItem> software = std::make_shared<CompletionItem>();
    software->addChild("description");
    software->addChild("name");
    software->addChild(permission, "permissions", VAR_NAME(permission));
    software->addChild("vendor_name");
    software->addChild("version");

    std::shared_ptr<CompletionItem> vulnerability = std::make_shared<CompletionItem>();
    vulnerability->addChild(noun, "about", VAR_NAME(noun));
    vulnerability->addChild("cve_description");
    vulnerability->addChild("cve_id");
    vulnerability->addChild("cvss_base_score", "float");
    vulnerability->addChild("cvss_vector");
    vulnerability->addChild("cvss_version");
    vulnerability->addChild("description");
    vulnerability->addChild("first_found", "protobuf.Timestamp");
    vulnerability->addChild("last_found", "protobuf.Timestamp");
    vulnerability->addChild("name");
    vulnerability->addChild("scan_end_time", "protobuf.Timestamp");
    vulnerability->addChild("scan_start_time", "protobuf.Timestamp");
    vulnerability->addChild(CompletionItemProperties("severity", "Vulnerability.Severity", completionItemKind::Enum));
    vulnerability->addChild("severity_details");
    vulnerability->addChild("vendor");
    vulnerability->addChild("vendor_knowledge_base_article_id");
    vulnerability->addChild("vendor_vulnerability_id");

    std::shared_ptr<CompletionItem> asset = std::make_shared<CompletionItem>();
    asset->addChild("asset_id");
    asset->addChild(attribute, "attribute", VAR_NAME(attribute));
    asset->addChild("category");
    asset->addChild("creation_time", "protobuf.Timestamp");
    asset->addChild(CompletionItemProperties("deployment_status", "Asset.DeploymentStatus", completionItemKind::Enum));
    asset->addChild("first_discover_time", "protobuf.Timestamp");
    asset->addChild("first_seen_time", "protobuf.Timestamp");
    asset->addChild(hardware, "hardware", VAR_NAME(hardware));
    asset->addChild("hostname");
    asset->addChild("ip");
    asset->addChild(label, "labels", VAR_NAME(label));
    asset->addChild("last_boot_time", "protobuf.Timestamp");
    asset->addChild("last_discover_time", "protobuf.Timestamp");
    asset->addChild(location, "location", VAR_NAME(location));
    asset->addChild("mac");
    asset->addChild("nat_ip");
    asset->addChild("network_domain");
    asset->addChild(platformSoftware, "platform_software", VAR_NAME(platformSoftware));
    asset->addChild("product_object_id");
    asset->addChild(software, "software", VAR_NAME(software));
    asset->addChild("system_last_update_time", "protobuf.Timestamp");
    asset->addChild(CompletionItemProperties("type", "Asset.AssetType", completionItemKind::Enum));
    asset->addChild(vulnerability, "vulnerabilities", VAR_NAME(vulnerability));

    std::shared_ptr<CompletionItem> timeOff = std::make_shared<CompletionItem>();
    timeOff->addChild("description");
    timeOff->addChild("interval", "type.Interval");

    std::shared_ptr<CompletionItem> user = std::make_shared<CompletionItem>();
    user->addChild("account_expiration_time", "protobuf.Timestamp");
    user->addChild("account_lockout_time", "protobuf.Timestamp");
    user->addChild(CompletionItemProperties("account_type", "User.AccountType", completionItemKind::Enum));
    user->addChild(attribute, "attribute", VAR_NAME(attribute));
    user->addChild("company_name");
    user->addChild("department");
    user->addChild("email_addresses");
    user->addChild("employee_id");
    user->addChild("first_name");
    user->addChild("first_seen_time", "protobuf.Timestamp");
    user->addChild("group_identifiers");
    user->addChild("groupid");
    user->addChild("hire_date", "protobuf.Timestamp");
    user->addChild("last_bad_password_attempt_time", "protobuf.Timestamp");
    user->addChild("last_login_time", "protobuf.Timestamp");
    user->addChild("last_name");
    user->addChild("last_password_change_time", "protobuf.Timestamp");
    user->addChild(user, "managers", VAR_NAME(user));
    user->addChild("middle_name");
    user->addChild(location, "office_address", VAR_NAME(location));
    user->addChild("password_expiration_time", "protobuf.Timestamp");
    user->addChild(location, "personal_address", VAR_NAME(location));
    user->addChild("phone_numbers");
    user->addChild("product_object_id");
    user->addChild("role_description");
    user->addChild("role_name");
    user->addChild("termination_date", "protobuf.Timestamp");
    user->addChild(timeOff, "time_off", VAR_NAME(timeOff));
    user->addChild("title");
    user->addChild(CompletionItemProperties("user_authentication_status", "Authentication.AuthenticationStatus", completionItemKind::Enum));
    user->addChild("user_display_name");
    user->addChild(CompletionItemProperties("user_role", "User.Role", completionItemKind::Enum));
    user->addChild("userid");
    user->addChild("windows_sid");

    std::shared_ptr<CompletionItem> favicon = std::make_shared<CompletionItem>();
    favicon->addChild("dhash");
    favicon->addChild("raw_md5");

    std::shared_ptr<CompletionItem> dnsRecord = std::make_shared<CompletionItem>();
    dnsRecord->addChild("expire", "int64");
    dnsRecord->addChild("minimum", "int64");
    dnsRecord->addChild("priority", "int64");
    dnsRecord->addChild("refresh", "int64");
    dnsRecord->addChild("retry", "int64");
    dnsRecord->addChild("rname");
    dnsRecord->addChild("serial", "int64");
    dnsRecord->addChild("ttl", "int64");
    dnsRecord->addChild("type");
    dnsRecord->addChild("value");

    std::shared_ptr<CompletionItem> popularityRank = std::make_shared<CompletionItem>();
    popularityRank->addChild("giver");
    popularityRank->addChild("ingestion_time", "protobuf.Timestamp");
    popularityRank->addChild("rank", "int64");

    std::shared_ptr<CompletionItem> domain = std::make_shared<CompletionItem>();
    domain->addChild(user, "admin", VAR_NAME(user));
    domain->addChild("audit_update_time", "protobuf.Timestamp");
    domain->addChild(user, "billing", VAR_NAME(user));
    domain->addChild("categories");
    domain->addChild("contact_email");
    domain->addChild("creation_time", "protobuf.Timestamp");
    domain->addChild("expiration_time", "protobuf.Timestamp");
    domain->addChild(favicon, "favicon", VAR_NAME(favicon));
    domain->addChild("first_seen_time", "protobuf.Timestamp");
    domain->addChild("iana_registrar_id", "int64");
    domain->addChild("jarm");
    domain->addChild(dnsRecord, "last_dns_records", VAR_NAME(dnsRecord));
    domain->addChild("last_dns_records_time", "protobuf.Timestamp");
    domain->addChild(SSLCertificate, "last_https_certificate", VAR_NAME(SSLCertificate));
    domain->addChild("last_https_certificate_time", "protobuf.Timestamp");
    domain->addChild("last_seen_time", "protobuf.Timestamp");
    domain->addChild("name");
    domain->addChild("name_server");
    domain->addChild(popularityRank, "popularity_ranks", VAR_NAME(popularityRank));
    domain->addChild(prevalence, "prevalence", VAR_NAME(prevalence));
    domain->addChild("private_registration", "bool");
    domain->addChild(user, "registrant", VAR_NAME(user));
    domain->addChild("registrar");
    domain->addChild("registry_data_raw_text", "bytes");
    domain->addChild("status");
    domain->addChild("tags");
    domain->addChild(user, "tech", VAR_NAME(user));
    domain->addChild("update_time", "protobuf.Timestamp");
    domain->addChild("whois_record_raw_text", "bytes");
    domain->addChild("whois_server");
    domain->addChild("whois_time", "protobuf.Timestamp");
    domain->addChild(user, "zone", VAR_NAME(user));

    std::shared_ptr<CompletionItem> pdfInfo = std::make_shared<CompletionItem>();
    pdfInfo->addChild("acroform", "int64");
    pdfInfo->addChild("autoaction", "int64");
    pdfInfo->addChild("embedded_file", "int64");
    pdfInfo->addChild("encrypted", "int64");
    pdfInfo->addChild("endobj_count", "int64");
    pdfInfo->addChild("endstream_count", "int64");
    pdfInfo->addChild("flash", "int64");
    pdfInfo->addChild("header");
    pdfInfo->addChild("javascript", "int64");
    pdfInfo->addChild("jbig2_compression", "int64");
    pdfInfo->addChild("js", "int64");
    pdfInfo->addChild("launch_action_count", "int64");
    pdfInfo->addChild("obj_count", "int64");
    pdfInfo->addChild("object_stream_count", "int64");
    pdfInfo->addChild("openaction", "int64");
    pdfInfo->addChild("page_count", "int64");
    pdfInfo->addChild("startxref", "int64");
    pdfInfo->addChild("stream_count", "int64");
    pdfInfo->addChild("suspicious_colors", "int64");
    pdfInfo->addChild("trailer", "int64");
    pdfInfo->addChild("xfa", "int64");
    pdfInfo->addChild("xref", "int64");

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
    fileMetadataSignatureInfo->addChild(signerInfo, "signers", VAR_NAME(signerInfo));
    fileMetadataSignatureInfo->addChild("verification_message");
    fileMetadataSignatureInfo->addChild("verified", "bool");
    fileMetadataSignatureInfo->addChild(x509, "x509", VAR_NAME(x509));

    std::shared_ptr<CompletionItem> fileMetadataPE = std::make_shared<CompletionItem>();
    fileMetadataPE->addChild("compilation_exiftool_time", "protobuf.Timestamp");
    fileMetadataPE->addChild("compilation_time", "protobuf.Timestamp");
    fileMetadataPE->addChild("entry_point", "int64");
    fileMetadataPE->addChild("entry_point_exiftool", "int64");
    fileMetadataPE->addChild("imphash");
    fileMetadataPE->addChild("imports", "FileMetadataImports");
    fileMetadataPE->addChild("resource", "FileMetadataPeResourceInfo");
    fileMetadataPE->addChild("resources_language_count", "StringToInt64MapEntry");
    fileMetadataPE->addChild(label, "resources_language_count_str", VAR_NAME(label));
    fileMetadataPE->addChild("resources_type_count", "StringToInt64MapEntry");
    fileMetadataPE->addChild(label, "resources_type_count_str", VAR_NAME(label));
    fileMetadataPE->addChild("section", "FileMetadataSection");
    fileMetadataPE->addChild(signerInfo, "signature_info", VAR_NAME(signerInfo));

    std::shared_ptr<CompletionItem> analyticsMetadata = std::make_shared<CompletionItem>();
    analyticsMetadata->addChild("analytic");

    std::shared_ptr<CompletionItem> securityResult_associationAlias = std::make_shared<CompletionItem>();
    securityResult_associationAlias->addChild("company");
    securityResult_associationAlias->addChild("name");

    std::shared_ptr<CompletionItem> securityResult_association = std::make_shared<CompletionItem>();
    securityResult_association->addChild(securityResult_associationAlias, "alias", VAR_NAME(securityResult_associationAlias));
    securityResult_association->addChild(securityResult_association, "associated_actors", VAR_NAME(securityResult_association));
    securityResult_association->addChild("country_code");
    securityResult_association->addChild("description");
    securityResult_association->addChild("first_reference_time", "protobuf.Timestamp");
    securityResult_association->addChild("id");
    securityResult_association->addChild("industries_affected");
    securityResult_association->addChild("last_reference_time", "protobuf.Timestamp");
    securityResult_association->addChild("name");
    securityResult_association->addChild(location, "region_code", VAR_NAME(location));
    securityResult_association->addChild("role");
    securityResult_association->addChild("source_country");
    securityResult_association->addChild(location, "sponsor_region", VAR_NAME(location));
    securityResult_association->addChild("tags");
    securityResult_association->addChild(location, "targeted_regions", VAR_NAME(location));
    securityResult_association->addChild(CompletionItemProperties("type", "SecurityResult.Association.AssociationType", completionItemKind::Enum));

    std::shared_ptr<CompletionItem> attackDetails_tactic = std::make_shared<CompletionItem>();
    attackDetails_tactic->addChild("id");
    attackDetails_tactic->addChild("name");

    std::shared_ptr<CompletionItem> attackDetails_technique = std::make_shared<CompletionItem>();
    attackDetails_technique->addChild("id");
    attackDetails_technique->addChild("name");
    attackDetails_technique->addChild("subtechnique_id");
    attackDetails_technique->addChild("subtechnique_name");

    std::shared_ptr<CompletionItem> attackDetails = std::make_shared<CompletionItem>();
    attackDetails->addChild(attackDetails_tactic, "tactics", VAR_NAME(attackDetails_tactic));
    attackDetails->addChild(attackDetails_technique, "techniques", VAR_NAME(attackDetails_technique));
    attackDetails->addChild("version");

    std::shared_ptr<CompletionItem> securityResult_IoCStats = std::make_shared<CompletionItem>();
    securityResult_IoCStats->addChild("benign_count", "int32");
    securityResult_IoCStats->addChild("first_level_source");
    securityResult_IoCStats->addChild(CompletionItemProperties("ioc_stats_type", "SecurityResult.IoCStatsType", completionItemKind::Enum));
    securityResult_IoCStats->addChild("malicious_count", "int32");
    securityResult_IoCStats->addChild(CompletionItemProperties("quality", "SecurityResult.ProductConfidence", completionItemKind::Enum));
    securityResult_IoCStats->addChild("response_count", "int32");
    securityResult_IoCStats->addChild("second_level_source");
    securityResult_IoCStats->addChild("source_count", "int32");

    std::shared_ptr<CompletionItem> securityResult_verdictInfo = std::make_shared<CompletionItem>();
    securityResult_verdictInfo->addChild("benign_count", "int32");
    securityResult_verdictInfo->addChild("category_details");
    securityResult_verdictInfo->addChild("confidence_score", "int32");
    securityResult_verdictInfo->addChild("global_customer_count", "int32");
    securityResult_verdictInfo->addChild("global_hits_count", "int32");
    securityResult_verdictInfo->addChild(securityResult_IoCStats, "ioc_stats", VAR_NAME(securityResult_IoCStats));
    securityResult_verdictInfo->addChild("malicious_count", "int32");
    securityResult_verdictInfo->addChild("neighbour_influence");
    securityResult_verdictInfo->addChild("pwn", "bool");
    securityResult_verdictInfo->addChild("pwn_first_tagged_time", "protobuf.Timestamp");
    securityResult_verdictInfo->addChild("response_count", "int32");
    securityResult_verdictInfo->addChild("source_count", "int32");
    securityResult_verdictInfo->addChild("source_provider");
    securityResult_verdictInfo->addChild(CompletionItemProperties("verdict_response", "SecurityResult.VerdictResponse", completionItemKind::Enum));
    securityResult_verdictInfo->addChild("verdict_time", "protobuf.Timestamp");
    securityResult_verdictInfo->addChild(CompletionItemProperties("verdict_type", "SecurityResult.VerdictType", completionItemKind::Enum));

    std::shared_ptr<CompletionItem> securityResult = std::make_shared<CompletionItem>();
    securityResult->addChild(noun, "about", VAR_NAME(noun));
    securityResult->addChild(CompletionItemProperties("action", "SecurityResult.Action", completionItemKind::Enum));
    securityResult->addChild("action_details");
    securityResult->addChild(CompletionItemProperties("alert_state", "SecurityResult.AlertState", completionItemKind::Enum));
    securityResult->addChild(analyticsMetadata, "analytics_metadata", VAR_NAME(analyticsMetadata));
    securityResult->addChild(securityResult_association, "associations", VAR_NAME(securityResult_association));
    securityResult->addChild(attackDetails, "attack_details", VAR_NAME(attackDetails));
    securityResult->addChild("campaigns");
    securityResult->addChild(CompletionItemProperties("category", "SecurityResult.SecurityCategory", completionItemKind::Enum));
    securityResult->addChild("category_details");
    securityResult->addChild(CompletionItemProperties("confidence", "SecurityResult.ProductConfidence", completionItemKind::Enum));
    securityResult->addChild("confidence_details");
    securityResult->addChild("confidence_score", "float");
    securityResult->addChild("description");
    securityResult->addChild(label, "detection_fields", VAR_NAME(label));
    securityResult->addChild("first_discovered_time", "protobuf.Timestamp");
    securityResult->addChild("last_discovered_time", "protobuf.Timestamp");
    securityResult->addChild("last_updated_time", "protobuf.Timestamp");
    securityResult->addChild(label, "outcomes", VAR_NAME(label));
    securityResult->addChild(CompletionItemProperties("priority", "SecurityResult.ProductPriority", completionItemKind::Enum));
    securityResult->addChild("priority_details");
    securityResult->addChild("risk_score", "float");
    securityResult->addChild("rule_author");
    securityResult->addChild("rule_id");
    securityResult->addChild(label, "rule_labels", VAR_NAME(label));
    securityResult->addChild("rule_name");
    securityResult->addChild("rule_set");
    securityResult->addChild("rule_set_display_name");
    securityResult->addChild("rule_type");
    securityResult->addChild("rule_version");
    securityResult->addChild("ruleset_category_display_name");
    securityResult->addChild(CompletionItemProperties("severity", "SecurityResult.ProductSeverity", completionItemKind::Enum));
    securityResult->addChild("severity_details");
    securityResult->addChild("summary");
    securityResult->addChild("threat_feed_name");
    securityResult->addChild("threat_id");
    securityResult->addChild("threat_id_namespace", "Id.Namespace");
    securityResult->addChild("threat_name");
    securityResult->addChild(CompletionItemProperties("threat_status", "SecurityResult.ThreatStatus", completionItemKind::Enum));
    securityResult->addChild(CompletionItemProperties("threat_verdict", "ThreatVerdict", completionItemKind::Enum));
    securityResult->addChild("url_back_to_product");
    securityResult->addChild(CompletionItemProperties("verdict", "SecurityResult.Verdict", completionItemKind::Enum));
    securityResult->addChild(securityResult_verdictInfo, "verdict_info", VAR_NAME(securityResult_verdictInfo));

    std::shared_ptr<CompletionItem> fileMetadataCodesign = std::make_shared<CompletionItem>();
    fileMetadataCodesign->addChild("compilation_time", "protobuf.Timestamp");
    fileMetadataCodesign->addChild("format");
    fileMetadataCodesign->addChild("id");

    std::shared_ptr<CompletionItem> signatureInfo = std::make_shared<CompletionItem>();
    signatureInfo->addChild(fileMetadataCodesign, "codesign", VAR_NAME(fileMetadataCodesign));
    signatureInfo->addChild(fileMetadataSignatureInfo, "sigcheck", VAR_NAME(fileMetadataSignatureInfo));

    std::shared_ptr<CompletionItem> file = std::make_shared<CompletionItem>();
    file->addChild("ahash");
    file->addChild("authentihash");
    file->addChild("capabilities_tags");
    file->addChild("embedded_domains");
    file->addChild("embedded_ips");
    file->addChild("embedded_urls");
    file->addChild("exif_info", "ExifInfo");
    file->addChild("file_metadata", "FileMetadata");
    file->addChild(CompletionItemProperties("file_type", "File.FileType", completionItemKind::Enum));
    file->addChild("first_seen_time", "protobuf.Timestamp");
    file->addChild("first_submission_time", "protobuf.Timestamp");
    file->addChild("full_path");
    file->addChild("last_analysis_time", "protobuf.Timestamp");
    file->addChild("last_modification_time", "protobuf.Timestamp");
    file->addChild("last_seen_time", "protobuf.Timestamp");
    file->addChild("last_submission_time", "protobuf.Timestamp");
    file->addChild(favicon, "main_icon", VAR_NAME(favicon));
    file->addChild("md5");
    file->addChild("mime_type");
    file->addChild("names");
    file->addChild(pdfInfo, "pdf_info", VAR_NAME(pdfInfo));
    file->addChild(fileMetadataPE, "pe_file", VAR_NAME(fileMetadataPE));
    file->addChild(prevalence, "prevalence", VAR_NAME(prevalence));
    file->addChild(securityResult, "security_result", VAR_NAME(securityResult));
    file->addChild("sha1");
    file->addChild("sha256");
    file->addChild(signatureInfo, "signature_info", VAR_NAME(signatureInfo));
    file->addChild("size", "uint64");
    file->addChild("ssdeep");
    file->addChild("stat_dev", "uint64");
    file->addChild("stat_flags", "uint32");
    file->addChild("stat_inode", "uint64");
    file->addChild("stat_mode", "uint64");
    file->addChild("stat_nlink", "uint64");
    file->addChild("tags");
    file->addChild("vhash");

    std::shared_ptr<CompletionItem> group = std::make_shared<CompletionItem>();
    group->addChild(attribute, "attribute", VAR_NAME(attribute));
    group->addChild("creation_time", "protobuf.Timestamp");
    group->addChild("email_addresses");
    group->addChild("group_display_name");
    group->addChild("product_object_id");
    group->addChild("windows_sid");

    std::shared_ptr<CompletionItem> securityResult_analystVerdict = std::make_shared<CompletionItem>();
    securityResult_analystVerdict->addChild("confidence_score", "int32");
    securityResult_analystVerdict->addChild(CompletionItemProperties("verdict_response", "SecurityResult.VerdictResponse", completionItemKind::Enum));
    securityResult_analystVerdict->addChild("verdict_time", "protobuf.Timestamp");

    std::shared_ptr<CompletionItem> securityResult_source = std::make_shared<CompletionItem>();
    securityResult_source->addChild("benign_count", "int32");
    securityResult_source->addChild("malicious_count", "int32");
    securityResult_source->addChild("name");
    securityResult_source->addChild(CompletionItemProperties("quality", "SecurityResult.ProductConfidence", completionItemKind::Enum));
    securityResult_source->addChild("response_count", "int32");
    securityResult_source->addChild("source_count", "int32");
    securityResult_source->addChild(securityResult_source, "threat_intelligence_sources", VAR_NAME(securityResult_source));

    std::shared_ptr<CompletionItem> securityResult_providerMLVerdict = std::make_shared<CompletionItem>();
    securityResult_providerMLVerdict->addChild("benign_count", "int32");
    securityResult_providerMLVerdict->addChild("confidence_score", "int32");
    securityResult_providerMLVerdict->addChild("malicious_count", "int32");
    securityResult_providerMLVerdict->addChild(securityResult_source, "mandiant_sources", VAR_NAME(securityResult_source));
    securityResult_providerMLVerdict->addChild("source_provider");
    securityResult_providerMLVerdict->addChild(securityResult_source, "third_party_sources", VAR_NAME(securityResult_source));

    std::shared_ptr<CompletionItem> securityResult_verdict = std::make_shared<CompletionItem>();
    securityResult_verdict->addChild(securityResult_analystVerdict, "analyst_verdict", VAR_NAME(securityResult_analystVerdict));
    securityResult_verdict->addChild("neighbour_influence");
    securityResult_verdict->addChild("response_count", "int32");
    securityResult_verdict->addChild("source_count", "int32");
    securityResult_verdict->addChild(securityResult_providerMLVerdict, "verdict", VAR_NAME(securityResult_providerMLVerdict));

    std::shared_ptr<CompletionItem> investigation = std::make_shared<CompletionItem>();
    investigation->addChild("comments");
    investigation->addChild("priority", "Priority");
    investigation->addChild("reason", "Reason");
    investigation->addChild("reputation", "Reputation");
    investigation->addChild("risk_score", "uint32");
    investigation->addChild("root_cause");
    investigation->addChild("severity_score", "uint32");
    investigation->addChild("status", "Status");
    investigation->addChild(securityResult_verdict, "verdict", VAR_NAME(securityResult_verdict));

    std::shared_ptr<CompletionItem> process = std::make_shared<CompletionItem>();
    process->addChild("access_mask", "uint64");
    process->addChild("command_line");
    process->addChild("command_line_history");
    process->addChild(file, "file", VAR_NAME(file));
    process->addChild("integrity_level_rid", "uint64");
    process->addChild("parent_pid");
    process->addChild(process, "parent_process", VAR_NAME(process));
    process->addChild("pid");
    process->addChild("product_specific_parent_process_id");
    process->addChild("product_specific_process_id");
    process->addChild(CompletionItemProperties("token_elevation_type", "Process.TokenElevationType", completionItemKind::Enum));

    std::shared_ptr<CompletionItem> registry = std::make_shared<CompletionItem>();
    registry->addChild("registry_key");
    registry->addChild("registry_value_data");
    registry->addChild("registry_value_name");

    std::shared_ptr<CompletionItem> tracker = std::make_shared<CompletionItem>();
    tracker->addChild("id");
    tracker->addChild("timestamp", "protobuf.Timestamp");
    tracker->addChild("tracker");
    tracker->addChild("url");

    std::shared_ptr<CompletionItem> url = std::make_shared<CompletionItem>();
    url->addChild("categories");
    url->addChild(favicon, "favicon", VAR_NAME(favicon));
    url->addChild(protobuf_Struct, "html_meta", VAR_NAME(protobuf_Struct));
    url->addChild("last_final_url");
    url->addChild("last_http_response_code", "int32");
    url->addChild("last_http_response_content_length", "int64");
    url->addChild("last_http_response_content_sha256");
    url->addChild(protobuf_Struct, "last_http_response_cookies", VAR_NAME(protobuf_Struct));
    url->addChild(protobuf_Struct, "last_http_response_headers", VAR_NAME(protobuf_Struct));
    url->addChild("tags");
    url->addChild("title");
    url->addChild(tracker, "trackers", VAR_NAME(tracker));
    url->addChild("url");

    // Definition is above
    // std::shared_ptr<CompletionItem> noun = std::make_shared<CompletionItem>();
    noun->addChild("administrative_domain");
    noun->addChild("application");
    noun->addChild(artifact, "artifact", VAR_NAME(artifact));
    noun->addChild(asset, "asset", VAR_NAME(asset));
    noun->addChild("asset_id");
    noun->addChild(cloud, "cloud", VAR_NAME(cloud));
    noun->addChild(domain, "domain", VAR_NAME(domain));
    noun->addChild("email");
    noun->addChild(file, "file", VAR_NAME(file));
    noun->addChild(group, "group", VAR_NAME(group));
    noun->addChild("hostname");
    noun->addChild(investigation, "investigation", VAR_NAME(investigation));
    noun->addChild("ip");
    noun->addChild(artifact, "ip_geo_artifact", VAR_NAME(artifact));
    noun->addChild(location, "ip_location", VAR_NAME(location));
    noun->addChild(label, "labels", VAR_NAME(label));
    noun->addChild(location, "location", VAR_NAME(location));
    noun->addChild("mac");
    noun->addChild("namespace");
    noun->addChild("nat_ip");
    noun->addChild("nat_port", "int32");
    noun->addChild(network, "network", VAR_NAME(network));
    noun->addChild("object_reference");
    noun->addChild("platform");
    noun->addChild("platform_patch_level");
    noun->addChild("platform_version");
    noun->addChild("port", "int32");
    noun->addChild(process, "process", VAR_NAME(process));
    noun->addChild(process, "process_ancestors", VAR_NAME(process));
    noun->addChild(registry, "registry", VAR_NAME(registry));
    noun->addChild(resource, "resource", VAR_NAME(resource));
    noun->addChild(resource, "resource_ancestors", VAR_NAME(resource));
    noun->addChild(securityResult, "security_result", VAR_NAME(securityResult));
    noun->addChild("url");
    noun->addChild(url, "url_metadata", VAR_NAME(url));
    noun->addChild(user, "user", VAR_NAME(user));
    noun->addChild(user, "user_management_chain", VAR_NAME(user));

    std::shared_ptr<CompletionItem> authentication = std::make_shared<CompletionItem>();
    authentication->addChild("auth_details");
    authentication->addChild(CompletionItemProperties("mechanism", "Authentication.Mechanism", completionItemKind::Enum));
    authentication->addChild(CompletionItemProperties("type", "Authentication.AuthType", completionItemKind::Enum));

    std::shared_ptr<CompletionItem> vulnerabilities = std::make_shared<CompletionItem>();
    vulnerabilities->addChild(vulnerability, "vulnerabilities", VAR_NAME(vulnerability));

    std::shared_ptr<CompletionItem> extensions = std::make_shared<CompletionItem>();
    extensions->addChild(authentication, "auth", VAR_NAME(authentication));
    extensions->addChild(vulnerabilities, "vulns", VAR_NAME(vulnerabilities));

    std::shared_ptr<CompletionItem> tags = std::make_shared<CompletionItem>();
    tags->addChild("data_tap_config_name");
    tags->addChild("tenant_id", "bytes");
    
    std::shared_ptr<CompletionItem> metadata = std::make_shared<CompletionItem>();
    metadata->addChild("base_labels", "DataAccessLabels");
    metadata->addChild("collected_timestamp", "protobuf.Timestamp");
    metadata->addChild("description");
    metadata->addChild("enrichment_labels", "DataAccessLabels");
    metadata->addChild(CompletionItemProperties("enrichment_state", "Metadata.EnrichmentState", completionItemKind::Enum));
    metadata->addChild("event_timestamp", "protobuf.Timestamp");
    metadata->addChild(CompletionItemProperties("event_type", "Metadata.EventType", completionItemKind::Enum));
    metadata->addChild("id", "bytes");
    metadata->addChild("ingested_timestamp", "protobuf.Timestamp");
    metadata->addChild(label, "ingestion_labels", VAR_NAME(label));
    metadata->addChild("log_type");
    metadata->addChild("product_deployment_id");
    metadata->addChild("product_event_type");
    metadata->addChild("product_log_id");
    metadata->addChild("product_name");
    metadata->addChild("product_version");
    metadata->addChild(tags, "tags", VAR_NAME(tags));
    metadata->addChild("url_back_to_product");
    metadata->addChild("vendor_name");

    root->addChild(noun, "about", VAR_NAME(noun));
    root->addChild(protobuf_Struct, "additional", VAR_NAME(protobuf_Struct));
    root->addChild(extensions, "extensions", VAR_NAME(extensions));
    root->addChild(noun, "intermediary", VAR_NAME(noun));
    root->addChild(metadata, "metadata", VAR_NAME(metadata));
    root->addChild(network, "network", VAR_NAME(network));
    root->addChild(noun, "observer", VAR_NAME(noun));
    root->addChild(noun, "principal", VAR_NAME(noun));
    root->addChild(securityResult, "security_result", VAR_NAME(securityResult));
    root->addChild(noun, "src", VAR_NAME(noun));
    root->addChild(noun, "target", VAR_NAME(noun));
}


bool operator==(const CompletionItemProperties& lhs, const CompletionItemProperties& rhs) {
        return lhs.label == rhs.label;
}


void CompletionItem::addChild(const std::string& label, std::string type) {
    std::replace(type.begin(), type.end(), '_', '.');
    children[CompletionItemProperties(label, type)] = nullptr;
}

void CompletionItem::addChild(const CompletionItemProperties& property) {
    children[property] = nullptr;
}

void CompletionItem::addChild(std::shared_ptr<CompletionItem> ptr, const std::string& label, std::string type) {
    std::replace(type.begin(), type.end(), '_', '.');
    children[CompletionItemProperties(label, type, completionItemKind::Method)] = ptr;
}

void CompletionItem::addChild(std::shared_ptr<CompletionItem> ptr, const CompletionItemProperties& property) {
    children[property] = ptr;
}

const std::string& CompletionItemProperties::getLabel() const {return label;}
const std::optional<json> CompletionItemProperties::getLabelDetails() const {return labelDetails;}
const std::optional<json> CompletionItemProperties::getKind() const {return kind;}
const std::optional<json> CompletionItemProperties::getTags() const {return tags;}
const std::optional<json> CompletionItemProperties::getDetail() const {return detail;}
const std::optional<json> CompletionItemProperties::getDeprecated() const {return deprecated;}
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
    add_if_present(j, "deprecated", i.getDeprecated());
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
        if (pair.first.getLabel() == name)
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
