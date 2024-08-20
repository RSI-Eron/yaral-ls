#include "forger.h"
#include <sstream>
#include <string>

#include <iostream>

void parse_header(const std::string& raw, rpc_message* msg) {
    std::istringstream raw_stream(raw);
    std::string line;

    while (std::getline(raw_stream, line)) {
        // Remove the carriage return character if it exists
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        // Check for the end of the headers section
        if (line.empty()) {
            break;
        }

        // Find the position of the colon
        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string header_name = line.substr(0, colon_pos);
            int offset = 1 + ( line.at(colon_pos+1) == ' ' ? 1 : 0);
            std::string header_value = line.substr(colon_pos + offset); // Skip the colon and the space after it

            if (header_name == "Content-Length") {
                try {
                    msg->header.contentLength = std::stoi(header_value);
                } catch (const std::invalid_argument &e) {
                    std::cerr << "Invalid argument: " << e.what() << std::endl;
                } catch (const std::out_of_range &e) {
                    std::cerr << "Out of range: " << e.what() << std::endl;
                }
            } else if (header_name == "Content-Type") {
                msg->header.contentType = header_value;
            }
        }
    }
}

void parse_request_body(const std::string& body, rpc_request* request) {
    json j = json::parse(body);
    request->json_rpc = j["jsonrpc"];
    request->params = j["params"];
    request->method = j["method"];
    if (j.contains("id")) { // Request
        request->id = (int)j["id"];
    } else { // Notification
        request->id = "";
    }
}

static std::string getStringFromVariant(const std::variant<std::string, int>& var) {
    return std::visit([](auto&& arg) -> std::string {
        if constexpr (std::is_same_v<std::decay_t<decltype(arg)>, std::string>) {
            return arg;
        } else {
            return std::to_string(arg);
        }
    }, var);
}


void to_json(json& j, const rpc_response& response) {
    j = json{
        {"id", getStringFromVariant(response.id)},
        {"jsonrpc", response.json_rpc}, // should always be "2.0"
    };

    if (response.result)
        j["result"] = response.result.value();

    if (response.error) {
        json error_json{
            {"code", response.error.value().code},
            {"message", response.error.value().message}
        };
        if (response.error.value().data)
            error_json["data"] = response.error.value().data.value();
        j["error"] = error_json;
    }
}
