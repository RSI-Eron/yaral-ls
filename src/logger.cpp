#include "logger.h"
#include "forger.h"
#include <chrono>
#include <iomanip>
#include <variant>

void print_footprint() {
  std::cerr << "Author : " << AUTHOR << "\n"
            << "Version : " << SERVER_VERSION << std::endl;
}

static std::variant<std::string, int> last_id = 0;
static std::string last_method = "";

struct make_string_functor {
  std::string operator()(const std::string &x) const { return x; }
  std::string operator()(int x) const { return std::to_string(x); }
};

void print_headers(const rpc_header &header) {
  std::cerr << "> Content-Length : " << header.contentLength << "\n"
            << "> Content-Type : " << header.contentType << "\n";
}

void print_request(const rpc_request &request, bool only_body) {
  if (!only_body) {
    std::cerr << "> Content-Length : " << request.header.contentLength << "\n"
              << "> Content-Type : " << request.header.contentType << "\n"
              << "> jsonrpc: " << request.json_rpc << "\n"
              << "> method: " << request.method << "\n"
              << "> id : " << std::visit(make_string_functor(), request.id) << "\n";
  }
  std::cerr << "> params: " << (request.params ? request.params.value() : "N/A") << "\n";
}


void print_response(const rpc_response &response, bool only_body) {
  if (!only_body) {
    std::cerr << "> Content-Length : " << response.header.contentLength << "\n"
              << "> Content-Type : " << response.header.contentType << "\n"
              << "> jsonrpc: " << response.json_rpc << "\n"
              << "> id : " << std::visit(make_string_functor(), response.id) << "\n";
  }
  std::cerr << "> result: " << (response.result ? response.result.value() : "N/A") << "\n";
}

void print_error(const std::string &message) {
  std::cerr << "[" << ERROR_TAG << "] " << message << std::endl;
}

std::string getSystemClockTime() {
  auto now = std::chrono::system_clock::now();
  std::time_t now_time_t = std::chrono::system_clock::to_time_t(now);
  std::tm local_tm = *std::localtime(&now_time_t);
  std::ostringstream oss;
  oss << std::put_time(&local_tm, "%H:%M:%S");
  return oss.str();
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

void log_rpc_message(const rpc_request& request) {
  if (!(std::holds_alternative<std::string>(request.id) && std::get<std::string>(request.id).empty())) {
      std::cerr << "[" << getSystemClockTime() << "] --> " << request.method << "(" << getStringFromVariant(request.id) << ")"<< std::endl;
    last_id = request.id;
    last_method = request.method;
  } else {
      std::cerr << "[" << getSystemClockTime() << "] --> " << request.method << std::endl;
  }
}



void log_rpc_message(const rpc_response& response) {
  if (std::holds_alternative<std::string>(response.id) && std::get<std::string>(response.id).empty()) {
    std::cerr << "[" << getSystemClockTime() << "] <-- " << "Unknown response ?" << std::endl;
    print_error("Unexpected reponse sent by this server. Check code.");
  } else {
    std::cerr << "[" << getSystemClockTime() << "] <-- " << last_method << "(" << getStringFromVariant(response.id) << ")" << std::endl;
  }
}
