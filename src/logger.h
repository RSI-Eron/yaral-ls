#ifndef LOGGER_H_
#define LOGGER_H_

#include "forger.h"
#include <iostream>
#include <string>
#include "Meta.h"

#define ERROR_TAG "ERROR"

void print_footprint();
void print_error(const std::string&);
void print_headers(const rpc_header&);
void print_request(const rpc_request&, bool only_body = true);
void print_response(const rpc_response&, bool only_body = true);
void log_rpc_message(const rpc_request&);
void log_rpc_message(const rpc_response&);

#endif // LOGGER_H_
