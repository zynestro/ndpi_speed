cmake_minimum_required(VERSION 3.10)
project(ndpiBenchmarkMark5 C)

# mark5 构建配置说明：
# - 目标是生成首包签名画像版本 ndpiBenchmarkMark5
# - 依赖 nDPI / libpcap / pthread
# - 使用 NDPI_PREFIX 指定 nDPI 安装根目录

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

# nDPI 头文件与库目录
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
get_filename_component(NDPI_SPEED_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
set(NDPI_SPEED_OUTPUT_DIR "${NDPI_SPEED_ROOT}/output")

find_library(PCAP_LIB pcap REQUIRED)
find_package(Threads REQUIRED)

set(NDPI_BENCHMARK_SOURCES
  # 程序入口 + 单线程主循环 + 统计输出
  src/main.c
  # 报文标准化/解析/flow key
  src/packet_parser.c
  # flow 状态表
  src/flow_table.c
)

add_executable(ndpiBenchmarkMark5
  ${NDPI_BENCHMARK_SOURCES}
)

add_executable(ndpiBenchmarkMark5Prefix4
  ${NDPI_BENCHMARK_SOURCES}
)

target_include_directories(ndpiBenchmarkMark5 PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
  ${NDPI_INCLUDE_DIR}
)
target_compile_definitions(ndpiBenchmarkMark5 PRIVATE
  NDPI_SPEED_OUTPUT_DIR="${NDPI_SPEED_OUTPUT_DIR}"
)

target_include_directories(ndpiBenchmarkMark5Prefix4 PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
  ${NDPI_INCLUDE_DIR}
)
target_compile_definitions(ndpiBenchmarkMark5Prefix4 PRIVATE
  NDPI_SPEED_OUTPUT_DIR="${NDPI_SPEED_OUTPUT_DIR}"
)

target_link_directories(ndpiBenchmarkMark5 PRIVATE
  ${NDPI_LIB_DIR}
)

target_link_directories(ndpiBenchmarkMark5Prefix4 PRIVATE
  ${NDPI_LIB_DIR}
)

target_link_libraries(ndpiBenchmarkMark5 PRIVATE
  ndpi
  ${PCAP_LIB}
  Threads::Threads
  m
)

target_link_libraries(ndpiBenchmarkMark5Prefix4 PRIVATE
  ndpi
  ${PCAP_LIB}
  Threads::Threads
  m
)

message(STATUS "")
message(STATUS "=== ndpiBenchmarkMark5 ===")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "nDPI: ${NDPI_PREFIX}")
message(STATUS "==========================")
message(STATUS "")
