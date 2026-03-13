cmake_minimum_required(VERSION 3.10)
project(ndpiBenchmarkMark3 C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_options(-Wall -Wextra -Wno-unused-parameter)
add_definitions(-D_GNU_SOURCE)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_C_FLAGS_RELEASE "-O3")
set(CMAKE_C_FLAGS_DEBUG "-g -O0")

if(NOT DEFINED NDPI_PREFIX)
  set(NDPI_PREFIX "$ENV{HOME}/ndpi-install")
endif()

set(NDPI_INCLUDE_DIR "${NDPI_PREFIX}/include/ndpi")
set(NDPI_LIB_DIR "${NDPI_PREFIX}/lib")

if(NOT EXISTS "${NDPI_INCLUDE_DIR}/ndpi_api.h")
  message(FATAL_ERROR
    "nDPI not found at: ${NDPI_PREFIX}\n"
    "Expected header: ${NDPI_INCLUDE_DIR}/ndpi_api.h\n"
    "Please install nDPI or specify correct path:\n"
    "  cmake -DNDPI_PREFIX=/path/to/ndpi-install ..")
endif()

set(CMAKE_BUILD_RPATH "${NDPI_LIB_DIR}")
set(CMAKE_INSTALL_RPATH "${NDPI_LIB_DIR}")

find_library(PCAP_LIB pcap REQUIRED)
find_package(Threads REQUIRED)

set(NDPI_BENCHMARK_SOURCES
  src/main.c
  src/benchmark_common.c
  src/packet_parser.c
  src/flow_table.c
  src/rss_table.c
  src/worker.c
  src/reader.c
)

add_executable(ndpiBenchmarkMark3
  ${NDPI_BENCHMARK_SOURCES}
)

target_include_directories(ndpiBenchmarkMark3 PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
  ${NDPI_INCLUDE_DIR}
)

target_link_directories(ndpiBenchmarkMark3 PRIVATE
  ${NDPI_LIB_DIR}
)

target_link_libraries(ndpiBenchmarkMark3 PRIVATE
  ndpi
  ${PCAP_LIB}
  Threads::Threads
  m
)

message(STATUS "")
message(STATUS "=== ndpiBenchmarkMark3 ===")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "nDPI: ${NDPI_PREFIX}")
message(STATUS "==========================")
message(STATUS "")
