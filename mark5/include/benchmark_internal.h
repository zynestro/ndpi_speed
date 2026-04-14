#ifndef BENCHMARK_INTERNAL_H
#define BENCHMARK_INTERNAL_H

/*
 * benchmark_internal.h（mark4）
 *
 * mark4 是单线程实现，模块关系比 mark3 简化：
 * - main 直接调用 parser + flow_table + nDPI
 * - 不涉及 reader/worker 队列与 RSS 调度
 *
 * 本头文件用于汇总内部实现依赖的系统头与公共类型声明。
 */

#include "ndpi_benchmark.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#endif
