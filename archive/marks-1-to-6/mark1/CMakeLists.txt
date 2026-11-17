cmake_minimum_required(VERSION 3.10)
project(ndpiBenchmark C)

# ============================================
# 基本设置
# ============================================
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_options(-Wall -Wextra -Wno-unused-parameter)
add_definitions(-D_GNU_SOURCE)

# 编译模式
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_C_FLAGS_RELEASE "-O3")
set(CMAKE_C_FLAGS_DEBUG "-g -O0")

# ============================================
# nDPI 配置
# ============================================
# 默认路径，可通过 cmake -DNDPI_PREFIX=/other/path .. 覆盖
if(NOT DEFINED NDPI_PREFIX)
    set(NDPI_PREFIX "$ENV{HOME}/ndpi-install")
endif()

set(NDPI_INCLUDE_DIR "${NDPI_PREFIX}/include/ndpi")
set(NDPI_LIB_DIR "${NDPI_PREFIX}/lib")

# 检查路径是否存在
if(NOT EXISTS "${NDPI_INCLUDE_DIR}/ndpi_api.h")
    message(FATAL_ERROR 
        "nDPI not found at: ${NDPI_PREFIX}\n"
        "Expected header: ${NDPI_INCLUDE_DIR}/ndpi_api.h\n"
        "Please install nDPI or specify correct path:\n"
        "  cmake -DNDPI_PREFIX=/path/to/ndpi-install ..")
endif()

# 运行时库路径（避免 LD_LIBRARY_PATH）
set(CMAKE_BUILD_RPATH "${NDPI_LIB_DIR}")
set(CMAKE_INSTALL_RPATH "${NDPI_LIB_DIR}")

# ============================================
# 系统依赖
# ============================================
find_library(PCAP_LIB pcap REQUIRED)
find_package(Threads REQUIRED)

# ============================================
# 构建目标
# ============================================
set(NDPI_BENCHMARK_SOURCES
    src/main.c
    src/benchmark_common.c
    src/packet_parser.c
    src/flow_table.c
    src/rss_table.c
    src/worker.c
    src/reader.c
)

add_executable(ndpiBenchmark
    ${NDPI_BENCHMARK_SOURCES}
)

target_include_directories(ndpiBenchmark PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${NDPI_INCLUDE_DIR}
)

target_link_directories(ndpiBenchmark PRIVATE
    ${NDPI_LIB_DIR}
)

target_link_libraries(ndpiBenchmark PRIVATE
    ndpi
    ${PCAP_LIB}
    Threads::Threads
    m
)

# Classified-flow variant (aggressive: pin protocol after first detection)
add_executable(ndpiBenchmarkClassified
    ${NDPI_BENCHMARK_SOURCES}
)

target_compile_definitions(ndpiBenchmarkClassified PRIVATE
    NDPI_BENCHMARK_CLASSIFIED
)

target_include_directories(ndpiBenchmarkClassified PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${NDPI_INCLUDE_DIR}
)

target_link_directories(ndpiBenchmarkClassified PRIVATE
    ${NDPI_LIB_DIR}
)

target_link_libraries(ndpiBenchmarkClassified PRIVATE
    ndpi
    ${PCAP_LIB}
    Threads::Threads
    m
)

# Batch-enqueue reader variant (streaming)
add_executable(ndpiBenchmarkBatch
    ${NDPI_BENCHMARK_SOURCES}
)

target_compile_definitions(ndpiBenchmarkBatch PRIVATE
    NDPI_BENCHMARK_BATCH
)

target_include_directories(ndpiBenchmarkBatch PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${NDPI_INCLUDE_DIR}
)

target_link_directories(ndpiBenchmarkBatch PRIVATE
    ${NDPI_LIB_DIR}
)

target_link_libraries(ndpiBenchmarkBatch PRIVATE
    ndpi
    ${PCAP_LIB}
    Threads::Threads
    m
)

# Memory-buffered reader variant
add_executable(ndpiBenchmarkMem
    ${NDPI_BENCHMARK_SOURCES}
)

target_compile_definitions(ndpiBenchmarkMem PRIVATE
    NDPI_BENCHMARK_MEMREADER
)

target_include_directories(ndpiBenchmarkMem PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${NDPI_INCLUDE_DIR}
)

target_link_directories(ndpiBenchmarkMem PRIVATE
    ${NDPI_LIB_DIR}
)

target_link_libraries(ndpiBenchmarkMem PRIVATE
    ndpi
    ${PCAP_LIB}
    Threads::Threads
    m
)

# Single-hash RSS variant (new flow -> h1 % N directly)
add_executable(ndpiBenchmarkSingleHash
    ${NDPI_BENCHMARK_SOURCES}
)

target_compile_definitions(ndpiBenchmarkSingleHash PRIVATE
    NDPI_BENCHMARK_SINGLEHASH
)

target_include_directories(ndpiBenchmarkSingleHash PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${NDPI_INCLUDE_DIR}
)

target_link_directories(ndpiBenchmarkSingleHash PRIVATE
    ${NDPI_LIB_DIR}
)

target_link_libraries(ndpiBenchmarkSingleHash PRIVATE
    ndpi
    ${PCAP_LIB}
    Threads::Threads
    m
)

# Aggressive load-balance RSS variant (multi-candidate + global fallback)
add_executable(ndpiBenchmarkAggLB
    ${NDPI_BENCHMARK_SOURCES}
)

target_compile_definitions(ndpiBenchmarkAggLB PRIVATE
    NDPI_BENCHMARK_AGGRESSIVE_LB
)

target_include_directories(ndpiBenchmarkAggLB PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${NDPI_INCLUDE_DIR}
)

target_link_directories(ndpiBenchmarkAggLB PRIVATE
    ${NDPI_LIB_DIR}
)

target_link_libraries(ndpiBenchmarkAggLB PRIVATE
    ndpi
    ${PCAP_LIB}
    Threads::Threads
    m
)

# ============================================
# 打印配置
# ============================================
message(STATUS "")
message(STATUS "=== ndpiBenchmark ===")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "nDPI: ${NDPI_PREFIX}")
message(STATUS "=====================")
message(STATUS "")
