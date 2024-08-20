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
    // Google types not implemented
    // Is there a way to shorten this ?
    // Can it be done at compile time ?


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
    SSLCertificate->addChild("cert_extensions");
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

    std::shared_ptr<CompletionItem> resource_circular = std::make_shared<CompletionItem>();
    resource_circular->addChild("id");
    resource_circular->addChild("name");
    resource_circular->addChild("parent");
    resource_circular->addChild("product_object_id");
    resource_circular->addChild("resource_subtype");
    resource_circular->addChild("resource_type");
    resource_circular->addChild("type");

    std::shared_ptr<CompletionItem> cloud = std::make_shared<CompletionItem>();
    cloud->addChild("availability_zone");
    cloud->addChild("environment");
    cloud->addChild(resource_circular, "project");
    cloud->addChild(resource_circular, "vpc");

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

    std::shared_ptr<CompletionItem> resource = std::make_shared<CompletionItem>();
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
    //vulnerability->addChild(noun_circular, "about");
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
    user->addChild(user, "managers");

    std::shared_ptr<CompletionItem> domain = std::make_shared<CompletionItem>();
    domain->addChild("admin");
    domain->addChild("audit_update_time");
    domain->addChild("billing");
    domain->addChild("categories");
    domain->addChild("contact_email");
    domain->addChild("creation_time");
    domain->addChild("expiration_time");
    domain->addChild("favicon");
    domain->addChild("first_seen_time");
    domain->addChild("iana_registrar_id");
    domain->addChild("jarm");
    domain->addChild("last_dns_records");
    domain->addChild("last_dns_records_time");
    domain->addChild("last_https_certificate");
    domain->addChild("last_https_certificate_time");
    domain->addChild("last_seen_time");
    domain->addChild("name");
    domain->addChild("name_server");
    domain->addChild("popularity_ranks");
    domain->addChild("prevalence");
    domain->addChild("private_registration");
    domain->addChild("registrant");
    domain->addChild("registrar");
    domain->addChild("registry_data_raw_text");
    domain->addChild("status");
    domain->addChild("tags");
    domain->addChild("tech");
    domain->addChild("update_time");
    domain->addChild("whois_record_raw_text");
    domain->addChild("whois_server");
    domain->addChild("whois_time");
    domain->addChild("zone");

    std::shared_ptr<CompletionItem> noun = std::make_shared<CompletionItem>();
    noun->addChild("administrative_domain");
    noun->addChild("application");
    noun->addChild(artifact, "artifact");
    noun->addChild(asset, "asset");
    noun->addChild("asset_id");
    noun->addChild(cloud, "cloud");
    noun->addChild("domain");
    noun->addChild("email");
    noun->addChild("file");
    noun->addChild("group");
    noun->addChild("hostname");
    noun->addChild("investigation");
    noun->addChild("ip");
    noun->addChild("ip_geo_artifact");
    noun->addChild("ip_location");
    noun->addChild("labels");
    noun->addChild("location");
    noun->addChild("mac");
    noun->addChild("namespace");
    noun->addChild("nat_ip");
    noun->addChild("nat_port");
    noun->addChild("network");
    noun->addChild("object_reference");
    noun->addChild("platform");
    noun->addChild("platform_patch_level");
    noun->addChild("platform_version");
    noun->addChild("port");
    noun->addChild("process");
    noun->addChild("process_ancestors");
    noun->addChild("registry");
    noun->addChild("resource");
    noun->addChild("resource_ancestors");
    noun->addChild("security_result");
    noun->addChild("url");
    noun->addChild("url_metadata");
    noun->addChild("user");
    noun->addChild("user_management_chain");

    root->addChild(noun, "about");
    root->addChild(noun, "intermediary");
    root->addChild(noun, "observer");
    root->addChild(noun, "principal");
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
