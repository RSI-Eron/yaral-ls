#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <variant>
#include "completion_definitions.h"
#include "document.h"
#include "forger.h"
#include "rpc.h"
#include "logger.h"


RPCHandler& RPCHandler::getInstance() {
    static RPCHandler singleton;
    return singleton;
}

void RPCHandler::sendResponse(const rpc_response& response) {
    json j = response;

    // Build the payload
    std::stringstream ss;
    std::string body = j.dump();
    ss << "Content-Length: " << body.length() << "\r\n";
    if (response.header.contentType != "")
        ss << "Content-Type: " << response.header.contentType << "\r\n";
    ss << "\r\n";
    ss << body;
    std::cout << ss.str();
    log_rpc_message(response);
}

void RPCHandler::initializeResult(const rpc_request& initialize_request) {
    rpc_response response;
    response.id = initialize_request.id;
    response.is_id_string = initialize_request.is_id_string;

    std::vector<std::string> trigger_chars;
    trigger_chars.push_back(".");
    static json completion_capabilities {
        {"triggerCharacters", trigger_chars},
    };

    static json server_capabilities{
        {"textDocumentSync", 2}, // Incremental, only changes are sent to server. Not the full document (1).
        {"completionProvider", completion_capabilities},
//        {"documentFormattingProvider"}
//        {"diagnosticProvider"}
    };
    static json server_info{
        {"name", SERVER_NAME},
        {"version", SERVER_VERSION}
    };

    response.result = {
        {"capabilities", server_capabilities},
        {"serverInfo", server_info}
    };


    sendResponse(response);
}

void RPCHandler::shutdown(const rpc_request& ignored) {
    (void)ignored;
    return; // TODO
}

void RPCHandler::didOpen(const rpc_request& request) {
    documents.emplace_back(request);
}

void RPCHandler::didChange(const rpc_request& request) {
    json param(request.params.value());
    Document* doc = Document::findByUri(documents, param["textDocument"]["uri"]);
    for (auto& change : param["contentChanges"]) {
        doc->modifyContent(
            change["range"]["start"]["line"],
            change["range"]["start"]["character"],
            change["range"]["end"]["line"],
            change["range"]["end"]["character"],
            change["text"]);
    }
}

void RPCHandler::didClose(const rpc_request& request) {
    removeDocumentByUri(request.params.value()["textDocument"]["uri"]);
}

void RPCHandler::completion(const rpc_request& request) {
    json param(request.params.value());
    const std::string line = Document::findByUri(
        documents,
        param["textDocument"]["uri"])->getLine(param["position"]["line"]);

    std::vector<completion_item> item_list = completion_item::get_completion_list(line, (int)param["position"]["character"] - 1);

    completion_list list = {
        .isIncomplete = false,
        .itemDefaults = std::optional<completion_item>(), // Not used for now
        .items = item_list,
    };

    json test {item_list};

    rpc_response response;
    response.id = request.id;
    response.is_id_string = request.is_id_string;
    response.result = list;

    // print_request(request);
    // print_response(response);

    sendResponse(response);
}

void RPCHandler::ignore(const rpc_request& request) {
    (void) request;
    return;
}

void RPCHandler::removeDocumentByUri(const std::string& uri) {
    auto it = std::remove_if(documents.begin(), documents.end(),
        [&uri](const Document &doc) { return doc == uri; });

    // Erase the 'removed' elements from the vector
    documents.erase(it);
}


void RPCHandler::handleRequest(const rpc_request& request) {
    MemberFunctionPointer func = findRequestFunction(request.method);
    if (func) {
        (this->*func)(request); // Call the member function
    } else {
        print_error("No matching function for request: " + request.method);
        print_request(request);
    }
}

void RPCHandler::handleNotification(const rpc_request& request) {
    MemberFunctionPointer func = findNotificationFunction(request.method);
    if (func) {
        (this->*func)(request); // Call the member function
    } else {
        print_request(request);
    }
}


void RPCHandler::listen() {
    rpc_request request;
    std::string headers_string;
    char current, prev = '\0';
    // Get headers
    bool isLastSequenceDelmiter = false;
    while (std::cin.get(current)) {
        headers_string += current;
        if (prev == '\r' && current == '\n') {
            if (isLastSequenceDelmiter)
                break;
            else
                isLastSequenceDelmiter = true;
        } else if (current != '\r') {
            isLastSequenceDelmiter = false;
        }
        prev = current;
    }
    parse_header(headers_string, &request);

    // Get body
    std::string body_string;
    for (int i = 0; i < request.header.contentLength && std::cin.get(current) ; ++i) {
        body_string += current;
    }

    parse_request_body(body_string, &request);
    log_rpc_message(request); // Log before handling

    if (std::holds_alternative<std::string>(request.id) && std::get<std::string>(request.id).empty())
        handleNotification(request);
    else
        handleRequest(request);
}
