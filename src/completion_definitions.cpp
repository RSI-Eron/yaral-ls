#include "completion_definitions.h"
#include "logger.h"
#include <cctype>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

completion_item completion_item::root("root");

void completion_item::initialize_tree() {
    // Google types not implemented
    // Is there a way to shorten this ?
    // Can it be done at compile time ?

    completion_item SSLCertificate_CertSignature("SSLCertificate_CertSignature");
    SSLCertificate_CertSignature.add_child("signature");
    SSLCertificate_CertSignature.add_child("signature_algorithm");

    completion_item SSLCertificate_EC("SSLCertificate_EC");
    SSLCertificate_EC.add_child("oid");
    SSLCertificate_EC.add_child("pub");

    completion_item SSLCertificate_AuthorityKeyId("SSLCertificate_AuthorityKeyId");
    SSLCertificate_AuthorityKeyId.add_child("keyid");
    SSLCertificate_AuthorityKeyId.add_child("serial_number");

    completion_item SSLCertificate_Extension("SSLCertificate_Extension");
    SSLCertificate_Extension.add_child(&SSLCertificate_AuthorityKeyId, "authority_key_id");
    SSLCertificate_Extension.add_child("ca");
    SSLCertificate_Extension.add_child("ca_info_access");
    SSLCertificate_Extension.add_child("cert_template_name_dc");
    SSLCertificate_Extension.add_child("certificate_policies");
    SSLCertificate_Extension.add_child("crl_distribution_points");
    SSLCertificate_Extension.add_child("extended_key_usage");
    SSLCertificate_Extension.add_child("key_usage");
    SSLCertificate_Extension.add_child("netscape_cert_comment");
    SSLCertificate_Extension.add_child("netscape_certificate");
    SSLCertificate_Extension.add_child("old_authority_key_id");
    SSLCertificate_Extension.add_child("pe_logotype");
    SSLCertificate_Extension.add_child("subject_alternative_name");
    SSLCertificate_Extension.add_child("subject_key_id");

    completion_item SSLCertificate_Subject("SSLCertificate_Subject");
    SSLCertificate_Subject.add_child("common_name");
    SSLCertificate_Subject.add_child("country_name");
    SSLCertificate_Subject.add_child("locality");
    SSLCertificate_Subject.add_child("organization");
    SSLCertificate_Subject.add_child("organizational_unit");
    SSLCertificate_Subject.add_child("state_or_province_name");

    completion_item SSLCertificate_Validity("SSLCertificate_Validity");
    SSLCertificate_Validity.add_child("expiry_time");
    SSLCertificate_Validity.add_child("issue_time");

    completion_item SSLCertificate("SSLCertificate");
    SSLCertificate.add_child("cert_extensions");
    SSLCertificate.add_child(&SSLCertificate_CertSignature, "cert_signature");
    SSLCertificate.add_child(&SSLCertificate_EC, "ec");
    SSLCertificate.add_child(&SSLCertificate_Extension, "extension");
    SSLCertificate.add_child("first_seen_time");
    SSLCertificate.add_child(&SSLCertificate_Subject, "issuer");
    SSLCertificate.add_child("serial_number");
    SSLCertificate.add_child("signature_algorithm");
    SSLCertificate.add_child("size");
    SSLCertificate.add_child(&SSLCertificate_Subject, "subject");
    SSLCertificate.add_child("thumbprint");
    SSLCertificate.add_child("thumbprint_sha256");
    SSLCertificate.add_child(&SSLCertificate_Validity, "validity");
    SSLCertificate.add_child("version");

    completion_item location("location");
    location.add_child("city");
    location.add_child("country_or_region");
    location.add_child("desk_name");
    location.add_child("floor_name");
    location.add_child("name");
    location.add_child("region_coordinates");
    location.add_child("region_latitude");
    location.add_child("region_longitude");
    location.add_child("state");

    completion_item dhcp_option("dhcp_option");
    dhcp_option.add_child("code");
    dhcp_option.add_child("data");

    completion_item dhcp("dhcp");
    dhcp.add_child("chaddr");
    dhcp.add_child("ciaddr");
    dhcp.add_child("client_hostname");
    dhcp.add_child("client_identifier");
    dhcp.add_child("file");
    dhcp.add_child("flags");
    dhcp.add_child("giaddr");
    dhcp.add_child("hlen");
    dhcp.add_child("hops");
    dhcp.add_child("htype");
    dhcp.add_child("lease_time_seconds");
    dhcp.add_child("opcode");
    dhcp.add_child(&dhcp_option, "options");
    dhcp.add_child("requested_address");
    dhcp.add_child("seconds");
    dhcp.add_child("siaddr");
    dhcp.add_child("sname");
    dhcp.add_child("transaction_id");
    dhcp.add_child("type");
    dhcp.add_child("yiaddr");

    completion_item prevalence("prevalence");
    prevalence.add_child("day_count");
    prevalence.add_child("day_max");
    prevalence.add_child("day_max_sub_domains");
    prevalence.add_child("rolling_max");
    prevalence.add_child("rolling_max_sub_domains");

    completion_item dns_ResourceRecord("dns_ResourceRecord");
    dns_ResourceRecord.add_child("binary_data");
    dns_ResourceRecord.add_child("class");
    dns_ResourceRecord.add_child("data");
    dns_ResourceRecord.add_child("name");
    dns_ResourceRecord.add_child("ttl");
    dns_ResourceRecord.add_child("type");

    completion_item dns_Question("dns_Question");
    dns_Question.add_child("class");
    dns_Question.add_child("name");
    dns_Question.add_child(&prevalence, "prevalence");
    dns_Question.add_child("type");

    completion_item dns("dns");
    dns.add_child(&dns_ResourceRecord, "additional");
    dns.add_child(&dns_ResourceRecord, "answers");
    dns.add_child("authoritative");
    dns.add_child(&dns_ResourceRecord, "authority");
    dns.add_child("id");
    dns.add_child("opcode");
    dns.add_child(&dns_Question, "questions");
    dns.add_child("recursion_available");
    dns.add_child("recursion_desired");
    dns.add_child("response");
    dns.add_child("response_code");
    dns.add_child("truncated");

    completion_item email("email");
    email.add_child("bcc");
    email.add_child("bounce_address");
    email.add_child("cc");
    email.add_child("from");
    email.add_child("mail_id");
    email.add_child("reply_to");
    email.add_child("subject");
    email.add_child("to");

    completion_item ftp("ftp");
    ftp.add_child("command");

    completion_item http("http");
    http.add_child("method");
    http.add_child("parsed_user_agent");
    http.add_child("referral_url");
    http.add_child("response_code");
    http.add_child("user_agent");

    completion_item certificate("certificate");
    certificate.add_child("issuer");
    certificate.add_child("md5");
    certificate.add_child("not_after");
    certificate.add_child("not_before");
    certificate.add_child("serial");
    certificate.add_child("sha1");
    certificate.add_child("sha256");
    certificate.add_child("subject");
    certificate.add_child("version");

    completion_item tls_server("tls_server");
    tls_server.add_child("certificate");
    tls_server.add_child("ja3s");

    completion_item tls_client("tls_client");
    tls_client.add_child(&certificate, "certificate");
    tls_client.add_child("ja3");
    tls_client.add_child("server_name");
    tls_client.add_child("supported_ciphers");

    completion_item tls("tls");
    tls.add_child("cipher");
    tls.add_child(&tls_client, "client");
    tls.add_child("curve");
    tls.add_child("established");
    tls.add_child("next_protocol");
    tls.add_child("resumed");
    tls.add_child(&tls_server, "server");
    tls.add_child("version");
    tls.add_child("version_protocol");

    completion_item network("network");
    network.add_child("application_protocol");
    network.add_child("application_protocol_version");
    network.add_child("asn");
    network.add_child("carrier_name");
    network.add_child("community_id");
    network.add_child(&dhcp, "dhcp");
    network.add_child("direction");
    network.add_child(&dns, "dns");
    network.add_child("dns_domain");
    network.add_child(&email, "email");
    network.add_child(&ftp, "ftp");
    network.add_child(&http, "http");
    network.add_child("ip_protocol");
    network.add_child("ip_subnet_range");
    network.add_child("organization_name");
    network.add_child("parent_session_id");
    network.add_child("received_bytes");
    network.add_child("received_packets");
    network.add_child("sent_bytes");
    network.add_child("sent_packets");
    network.add_child("session_duration");
    network.add_child("session_id");
    network.add_child("smtp");
    network.add_child(&tls, "tls");

    completion_item artifact("artifact");
    artifact.add_child("as_owner");
    artifact.add_child("asn");
    artifact.add_child("first_seen_time");
    artifact.add_child("ip");
    artifact.add_child("jarm");
    artifact.add_child(&SSLCertificate, "last_http_certificate");
    artifact.add_child("last_https_certificate_date");
    artifact.add_child("last_seen_time");
    artifact.add_child(&location, "location");
    artifact.add_child(&network, "network");
    artifact.add_child(&prevalence, "prevalence");
    artifact.add_child("regional_internet_registry");
    artifact.add_child("tags");
    artifact.add_child("whois");
    artifact.add_child("whois_date");

    completion_item resource_circular("resource_circular");
    resource_circular.add_child("id");
    resource_circular.add_child("name");
    resource_circular.add_child("parent");
    resource_circular.add_child("product_object_id");
    resource_circular.add_child("resource_subtype");
    resource_circular.add_child("resource_type");
    resource_circular.add_child("type");

    completion_item cloud("cloud");
    cloud.add_child("availability_zone");
    cloud.add_child("environment");
    cloud.add_child(&resource_circular, "project");
    cloud.add_child(&resource_circular, "vpc");

    completion_item label("label");
    label.add_child("key");
    label.add_child("rbac_enabled");
    label.add_child("value");

    completion_item permission("permission");
    permission.add_child("description");
    permission.add_child("name");
    permission.add_child("type");

    completion_item role("role");
    role.add_child("description");
    role.add_child("name");
    role.add_child("type");

    completion_item attribute("attribute");
    attribute.add_child(&cloud, "cloud");
    attribute.add_child("creation_time");
    attribute.add_child(&label, "labels");
    attribute.add_child("last_update_time");
    attribute.add_child(&permission, "permissions");
    attribute.add_child(&role, "roles");

    completion_item resource("resource");
    resource.add_child(&attribute, "attribute");
    resource.add_child("id");
    resource.add_child("name");
    resource.add_child("parent");
    resource.add_child("product_object_id");
    resource.add_child("resource_subtype");
    resource.add_child("resource_type");
    resource.add_child("type");

    completion_item hardware("hardware");
    hardware.add_child("cpu_clock_speed");
    hardware.add_child("cpu_max_clock_speed");
    hardware.add_child("cpu_model");
    hardware.add_child("cpu_number_cores");
    hardware.add_child("cpu_platform");
    hardware.add_child("manufacturer");
    hardware.add_child("model");
    hardware.add_child("ram");
    hardware.add_child("serial_number");

    completion_item platformSoftware("platformSoftware");
    platformSoftware.add_child("platform");
    platformSoftware.add_child("platform_patch_level");
    platformSoftware.add_child("platform_version");

    completion_item software("software");
    software.add_child("description");
    software.add_child("name");
    software.add_child(&permission, "permissions");
    software.add_child("vendor_name");
    software.add_child("version");

    completion_item vulnerability("vulnerability");
    //vulnerability.add_child(&noun_circular, "about");
    vulnerability.add_child("cve_description");
    vulnerability.add_child("cve_id");
    vulnerability.add_child("cvss_base_score");
    vulnerability.add_child("cvss_vector");
    vulnerability.add_child("cvss_version");
    vulnerability.add_child("description");
    vulnerability.add_child("first_found");
    vulnerability.add_child("last_found");
    vulnerability.add_child("name");
    vulnerability.add_child("scan_end_time");
    vulnerability.add_child("scan_start_time");
    vulnerability.add_child("severity");
    vulnerability.add_child("severity_details");
    vulnerability.add_child("vendor");
    vulnerability.add_child("vendor_knowledge_base_article_id");
    vulnerability.add_child("vendor_vulnerability_id");

    completion_item asset("asset");
    asset.add_child("asset_id");
    asset.add_child(&attribute, "attribute");
    asset.add_child("category");
    asset.add_child("creation_time");
    asset.add_child("deployment_status");
    asset.add_child("first_discover_time");
    asset.add_child("first_seen_time");
    asset.add_child(&hardware, "hardware");
    asset.add_child("hostname");
    asset.add_child("ip");
    asset.add_child(&label, "labels");
    asset.add_child("last_boot_time");
    asset.add_child("last_discover_time");
    asset.add_child(&location, "location");
    asset.add_child("mac");
    asset.add_child("nat_ip");
    asset.add_child("network_domain");
    asset.add_child(&platformSoftware, "platform_software");
    asset.add_child("product_object_id");
    asset.add_child(&software, "software");
    asset.add_child("system_last_update_time");
    asset.add_child("type");
    asset.add_child(&vulnerability, "vulnerabilities");

    completion_item timeOff("timeOff");
    timeOff.add_child("description");
    timeOff.add_child("interval");

    completion_item user("user");
    user.add_child("account_expiration_time");
    user.add_child("account_lockout_time");
    user.add_child("account_type");
    user.add_child(&attribute, "attribute");
    user.add_child("company_name");
    user.add_child("department");
    user.add_child("email_addresses");
    user.add_child("employee_id");
    user.add_child("first_name");
    user.add_child("first_seen_time");
    user.add_child("group_identifiers");
    user.add_child("groupid");
    user.add_child("hire_date");
    user.add_child("last_bad_password_attempt_time");
    user.add_child("last_login_time");
    user.add_child("last_name");
    user.add_child("last_password_change_time");
    user.add_child("middle_name");
    user.add_child(&location, "office_address");
    user.add_child("password_expiration_time");
    user.add_child(&location, "personal_address");
    user.add_child("phone_numbers");
    user.add_child("product_object_id");
    user.add_child("role_description");
    user.add_child("role_name");
    user.add_child("termination_date");
    user.add_child(&timeOff, "time_off");
    user.add_child("title");
    user.add_child("user_authentication_status");
    user.add_child("user_display_name");
    user.add_child("user_role");
    user.add_child("userid");
    user.add_child("windows_sid");
    user.add_child(&user, "managers");

    completion_item domain("domain");
    domain.add_child("admin");
    domain.add_child("audit_update_time");
    domain.add_child("billing");
    domain.add_child("categories");
    domain.add_child("contact_email");
    domain.add_child("creation_time");
    domain.add_child("expiration_time");
    domain.add_child("favicon");
    domain.add_child("first_seen_time");
    domain.add_child("iana_registrar_id");
    domain.add_child("jarm");
    domain.add_child("last_dns_records");
    domain.add_child("last_dns_records_time");
    domain.add_child("last_https_certificate");
    domain.add_child("last_https_certificate_time");
    domain.add_child("last_seen_time");
    domain.add_child("name");
    domain.add_child("name_server");
    domain.add_child("popularity_ranks");
    domain.add_child("prevalence");
    domain.add_child("private_registration");
    domain.add_child("registrant");
    domain.add_child("registrar");
    domain.add_child("registry_data_raw_text");
    domain.add_child("status");
    domain.add_child("tags");
    domain.add_child("tech");
    domain.add_child("update_time");
    domain.add_child("whois_record_raw_text");
    domain.add_child("whois_server");
    domain.add_child("whois_time");
    domain.add_child("zone");

    completion_item noun("noun");
    noun.add_child("administrative_domain");
    noun.add_child("application");
    noun.add_child(&artifact, "artifact");
    noun.add_child(&asset, "asset");
    noun.add_child("asset_id");
    noun.add_child(&cloud, "cloud");
    noun.add_child("domain");
    noun.add_child("email");
    noun.add_child("file");
    noun.add_child("group");
    noun.add_child("hostname");
    noun.add_child("investigation");
    noun.add_child("ip");
    noun.add_child("ip_geo_artifact");
    noun.add_child("ip_location");
    noun.add_child("labels");
    noun.add_child("location");
    noun.add_child("mac");
    noun.add_child("namespace");
    noun.add_child("nat_ip");
    noun.add_child("nat_port");
    noun.add_child("network");
    noun.add_child("object_reference");
    noun.add_child("platform");
    noun.add_child("platform_patch_level");
    noun.add_child("platform_version");
    noun.add_child("port");
    noun.add_child("process");
    noun.add_child("process_ancestors");
    noun.add_child("registry");
    noun.add_child("resource");
    noun.add_child("resource_ancestors");
    noun.add_child("security_result");
    noun.add_child("url");
    noun.add_child("url_metadata");
    noun.add_child("user");
    noun.add_child("user_management_chain");

    root.add_child(&noun, "about");
    root.add_child(&noun, "intermediary");
    root.add_child(&noun, "observer");
    root.add_child(&noun, "principal");
    root.add_child(&noun, "src");
    root.add_child(&noun, "target");
}

void completion_item::add_child(completion_item *k, std::string new_label) {
    children.push_back(completion_item(*k, new_label));
}

void completion_item::add_child(std::string new_label) {
    children.push_back(completion_item(new_label));
}

const std::string completion_item::getLabel() const {
    return label;
}


const std::optional<json> completion_item::getLabelDetails() const {
    return labelDetails;
}


const std::optional<json> completion_item::getKind() const {
    return kind;
}


const std::optional<json> completion_item::getTags() const {
    return tags;
}


const std::optional<json> completion_item::getDetail() const {
    return detail;
}


const std::optional<json> completion_item::getDocumentation() const {
    return documentation;
}


const std::optional<json> completion_item::getPreselect() const {
    return preselect;
}


const std::optional<json> completion_item::getSortText() const {
    return sortText;
}


const std::optional<json> completion_item::getFilterText() const {
    return filterText;
}


const std::optional<json> completion_item::getInsertText() const {
    return insertText;
}


const std::optional<json> completion_item::getInsertTextFormat() const {
    return insertTextFormat;
}


const std::optional<json> completion_item::getInsertTextMode() const {
    return insertTextMode;
}


const std::optional<json> completion_item::getTextEdit() const {
    return textEdit;
}


const std::optional<json> completion_item::getTextEditText() const {
    return textEditText;
}


const std::optional<json> completion_item::getAdditionalTextEdits() const {
    return additionalTextEdits;
}


const std::optional<json> completion_item::getCommitCharacters() const {
    return commitCharacters;
}


const std::optional<json> completion_item::getCommand() const {
    return command;
}


const std::optional<json> completion_item::getData() const {
    return data;
}


template <class T>
void add_if_present(json& j, std::string name, const std::optional<T>& opt) {
    if (opt.has_value())
        j[name]=opt.value();
}

void to_json(json& j, const completion_item& i) {
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


const completion_item* completion_item::getChildByName(std::string name) const {
    for (const auto& item : children) {
        if (item.label == name)
            return &item;
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

std::vector<completion_item> completion_item::get_completion_list(const std::string& line, int pos) {
    std::string expression = getCurrentExpression(line, pos);

    std::stringstream ss;
    const completion_item* current = nullptr;

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
                current = &root; // Initialize root with event name like '$my_event'
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



    if (current == nullptr)
        return std::vector<completion_item>();
    return current->children;
}
