#include <fstream>
#include <iostream>
#include <string>

#include "completion_definitions.h"
#include "forger.h"
#include "json.hpp"
#include "Meta.h"
#include "rpc.h"
#include "logger.h"

int main(/*int argc, char *argv[]*/) {
  print_footprint();

  completion_item::initialize_tree();

  while (true) {
    RPCHandler::getInstance().listen();
  }

  return 0;
}
