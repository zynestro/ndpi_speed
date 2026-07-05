cmake_minimum_required(VERSION 3.10)
project(ndpiBenchmarkMark9 C)

# mark9 构建配置：
# - 基于 mark7，新增 proto-level lookup table (v2)
# - 依赖 nDPI / libpcap / pthread

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

find_library(PCAP_LIB pcap REQUIRED)
find_package(Threads REQUIRED)

set(NDPI_BENCHMARK_SOURCES
  # 入口与汇总输出
  src/main.c
  # 调度配置与策略
  src/cost_table.c
  src/dispatch.c
  src/oracle_table.c
  # 公共工具（样本打印、绑核等）
  src/benchmark_common.c
  # 报文标准化/解析/flow key
  src/packet_parser.c
  # flow 状态表
  src/flow_table.c
  # 软件 RSS（flow -> worker）
  src/rss_table.c
  # worker 线程逻辑
  src/worker.c
  # reader + dispatcher 控制逻辑
  src/reader.c
)

function(configure_mark9_target target_name)
  target_include_directories(${target_name} PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${NDPI_INCLUDE_DIR}
  )

  target_compile_definitions(${target_name} PRIVATE
    NDPI_BENCHMARK_BATCH=1
    QUEUE_PACKET_DATA_SIZE=2048
    QUEUE_PACKET_USE_REF=1
  )

  target_link_directories(${target_name} PRIVATE
    ${NDPI_LIB_DIR}
  )

  target_link_libraries(${target_name} PRIVATE
    ndpi
    ${PCAP_LIB}
    Threads::Threads
    m
  )
endfunction()

add_executable(ndpiBenchmarkMark9
  ${NDPI_BENCHMARK_SOURCES}
)
configure_mark9_target(ndpiBenchmarkMark9)

message(STATUS "")
message(STATUS "=== ndpiBenchmarkMark9 ===")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "nDPI: ${NDPI_PREFIX}")
message(STATUS "==========================")
message(STATUS "")
