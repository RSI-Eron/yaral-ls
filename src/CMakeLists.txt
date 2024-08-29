cmake_minimum_required(VERSION 3.14)

project(yaral-ls LANGUAGES CXX VERSION 1.1)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)


set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(yaral-ls
  yaral-ls.cpp
  rpc.cpp
  forger.cpp
  json.hpp
  logger.cpp
  document.cpp
  completion_definitions.cpp
)

set(AUTHOR "Heron")
set(SERVER_NAME "YARAL-LS")

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/Meta.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/Meta.h
)
target_include_directories(yaral-ls PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_compile_options(yaral-ls PRIVATE -Wall -Wextra -Wpedantic -Werror)
