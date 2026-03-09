cmake_minimum_required(VERSION 3.13)

project(ndpiBenchmark C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Default nDPI install prefix (override with -DNDPI_PREFIX=...)
set(NDPI_PREFIX "/home/zync/ndpi-install" CACHE PATH "Prefix where libndpi is installed")

add_executable(ndpiBenchmark
  src/main.c
  src/benchmark_util.c
  src/packet_parser.c
  src/flow_table.c
)

target_compile_options(ndpiBenchmark PRIVATE
  -O3
  -g
  -Wall
  -Wextra
  -Wpedantic
  -Wno-unused-parameter
)

target_compile_definitions(ndpiBenchmark PRIVATE _GNU_SOURCE)


target_include_directories(ndpiBenchmark PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

find_package(Threads REQUIRED)
find_package(PkgConfig QUIET)

if(PkgConfig_FOUND)
  pkg_check_modules(PCAP QUIET libpcap)
endif()

if(PCAP_FOUND)
  target_include_directories(ndpiBenchmark PRIVATE ${PCAP_INCLUDE_DIRS})
  target_link_directories(ndpiBenchmark PRIVATE ${PCAP_LIBRARY_DIRS})
  target_link_libraries(ndpiBenchmark PRIVATE ${PCAP_LIBRARIES})
else()
  target_link_libraries(ndpiBenchmark PRIVATE pcap)
endif()

# nDPI headers and lib from NDPI_PREFIX
if(EXISTS "${NDPI_PREFIX}/include/ndpi_api.h")
  target_include_directories(ndpiBenchmark PRIVATE "${NDPI_PREFIX}/include")
elseif(EXISTS "${NDPI_PREFIX}/include/ndpi/ndpi_api.h")
  target_include_directories(ndpiBenchmark PRIVATE "${NDPI_PREFIX}/include/ndpi")
else()
  message(FATAL_ERROR "ndpi_api.h not found under ${NDPI_PREFIX}/include")
endif()

target_link_directories(ndpiBenchmark PRIVATE "${NDPI_PREFIX}/lib")
target_link_libraries(ndpiBenchmark PRIVATE ndpi Threads::Threads)
