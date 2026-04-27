cmake_minimum_required(VERSION 3.10)
project(ndpiBenchmarkMark6 C)

# mark3 构建配置说明：
# - 目标是生成多 worker + 多 dispatcher 的 benchmark 可执行文件
# - 依赖 nDPI / libpcap / pthread
# - 通过 NDPI_PREFIX 指定 nDPI 安装位置（默认 $HOME/ndpi-install）

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

function(configure_mark6_target target_name)
  target_include_directories(${target_name} PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${NDPI_INCLUDE_DIR}
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

add_executable(ndpiBenchmarkMark6
  ${NDPI_BENCHMARK_SOURCES}
)
configure_mark6_target(ndpiBenchmarkMark6)

add_executable(ndpiBenchmarkMark6Hash
  ${NDPI_BENCHMARK_SOURCES}
)
target_compile_definitions(ndpiBenchmarkMark6Hash PRIVATE MARK6_DISPATCH_HASH_ONLY=1)
configure_mark6_target(ndpiBenchmarkMark6Hash)

message(STATUS "")
message(STATUS "=== ndpiBenchmarkMark6 ===")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "nDPI: ${NDPI_PREFIX}")
message(STATUS "==========================")
message(STATUS "")
