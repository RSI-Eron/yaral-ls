#ifndef RPC_H_
#define RPC_H_

#include <iostream>
#include <vector>
#include "forger.h"
#include "document.h"


class RPCHandler {
private:
    rpc_header current_header;
    std::vector<Document> documents;
private:
    RPCHandler() {};
    RPCHandler(const RPCHandler&) = delete;
    RPCHandler& operator=(const RPCHandler) = delete;

public:
    static RPCHandler& getInstance();
    void listen();

private:
    void removeDocumentByUri(const std::string&);
    void sendResponse(const rpc_response&);
    void initializeResult(const rpc_request&);
    void shutdown(const rpc_request&);
    void handleRequest(const rpc_request&);
    void handleNotification(const rpc_request&);
    void completion(const rpc_request&);
    void didOpen(const rpc_request&);
    void didChange(const rpc_request&);
    void didClose(const rpc_request&);
    void ignore(const rpc_request&);

    // Function pointer type for member functions
    using MemberFunctionPointer = void (RPCHandler::*)(const rpc_request&);

    static constexpr std::array<std::pair<std::string_view, MemberFunctionPointer>, 3> requestMap = {{
        {"initialize", &RPCHandler::initializeResult},
        {"shutdown", &RPCHandler::shutdown},
        {"textDocument/completion", &RPCHandler::completion},
    }};

    // Compile-time lookup function
    static constexpr MemberFunctionPointer findRequestFunction(std::string_view method) {
        for (const auto& pair : requestMap) {
            if (pair.first == method) {
                return pair.second;
            }
        }
        return nullptr;
    }

    static constexpr std::array<std::pair<std::string_view, MemberFunctionPointer>, 4> notificationMap = {{
        {"textDocument/didOpen", &RPCHandler::didOpen},
        {"textDocument/didChange", &RPCHandler::didChange},
        {"textDocument/didClose", &RPCHandler::didClose},
        {"initialized", &RPCHandler::ignore}
    }};

    // Compile-time lookup function
    static constexpr MemberFunctionPointer findNotificationFunction(std::string_view method) {
        for (const auto& pair : notificationMap) {
            if (pair.first == method) {
                return pair.second;
            }
        }
        return nullptr;
    }

};

#endif // RPC_H_
