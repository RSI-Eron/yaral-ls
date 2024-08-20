#ifndef FORGER_H_
#define FORGER_H_

#include "json.hpp"
#include <optional>
#include <sstream>
#include <vector>
#include <variant>

using json = nlohmann::json;

enum rpc_error_code {
    // Defined by JSON-RPC
    PARSE_ERROR = -32700,
    INVALID_REQUEST = -32600,
    METHOD_NOT_FOUND = -32601,
    INVALID_PARAMS = -32602,
    INTERNAL_ERROR = -32603,

    /**
     * This is the start range of JSON-RPC reserved error codes.
     * It doesn't denote a real error code. No LSP error codes should
     * be defined between the start and end range. For backwards
     * compatibility the `ServerNotInitialized` and the `UnknownErrorCode`
     * are left in the range.
     *
     * @since 3.16.0
     */
    jsonrpcReservedErrorRangeStart = -32099,
    ServerNotInitialized = -32002,
    UnknownErrorCode = -32001,
    jsonrpcReservedErrorRangeEnd = -32000,

    /**
     * This is the start range of LSP reserved error codes.
     * It doesn't denote a real error code.
     *
     * @since 3.16.0
     */
    lspReservedErrorRangeStart = -32899,

    /**
     * A request failed but it was syntactically correct, e.g the
     * method name was known and the parameters were valid. The error
     * message should contain human readable information about why
     * the request failed.
     *
     * @since 3.17.0
     */
    RequestFailed = -32803,

    /**
     * The server cancelled the request. This error code should
     * only be used for requests that explicitly support being
     * server cancellable.
     *
     * @since 3.17.0
     */
    ServerCancelled = -32802,

    /**
     * The server detected that the content of a document got
     * modified outside normal conditions. A server should
     * NOT send this error code if it detects a content change
     * in it unprocessed messages. The result even computed
     * on an older state might still be useful for the client.
     *
     * If a client decides that a result is not of any use anymore
     * the client should cancel the request.
     */
    ContentModified = -32801,

    /**
     * The client has canceled a request and a server has detected
     * the cancel.
     */
    RequestCancelled = -32800,

    /**
     * This is the end range of LSP reserved error codes.
     * It doesn't denote a real error code.
     *
     * @since 3.16.0
     */
    lspReservedErrorRangeEnd = -32800,
};

struct rpc_header {
    int contentLength;
    std::string contentType = "application\vscode-jsonrpc; charset=utf-8";
};

struct rpc_message {
    std::variant<std::string, int> id;
    bool is_id_string;
    std::string json_rpc = "2.0";
    rpc_header header;
};

struct rpc_request : public rpc_message { // Notifications are also mapped here
    std::string method;
    std::optional<json> params;
};

struct rpc_response_error {
    rpc_error_code code;
    std::string message;
    std::optional<json> data;
};

struct rpc_response : public rpc_message {
    std::optional<json> result;
    std::optional<rpc_response_error> error;
};

void to_json(json& j, const rpc_response& response);
void parse_header(const std::string&, rpc_message*);
void parse_request_body(const std::string&, rpc_request*);
rpc_request parse_response();

#endif // FORGER_H_
