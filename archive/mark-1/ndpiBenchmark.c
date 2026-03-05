/*
 * ndpiBenchmark.c
 *
 * High-performance nDPI throughput benchmark tool
 * Optimizations:
 * 1. Pre-load entire PCAP into memory
 * 2. Multi-threaded processing with CPU affinity
 * 3. Flow-based packet distribution (avoid lock contention)
 * 4. Flow randomization to avoid cache cheating
 * 5. Timestamp jittering to avoid flow table pollution
 */

#include "ndpiBenchmark.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#ifdef __linux__
#include <sched.h>
#endif

/* External variables from ndpiReader */
u_int8_t enable_doh_dot_detection = 0;
char *_protoFilePath = NULL;
u_int8_t verbose = 0;
u_int8_t human_readeable_string_len = 0;  /* Disable payload analysis for performance */
u_int8_t max_num_udp_dissected_pkts = 24;
u_int8_t max_num_tcp_dissected_pkts = 80;
u_int8_t enable_flow_stats = 0;
u_int8_t enable_payload_analyzer = 0;
char *addr_dump_path = NULL;
int monitoring_enabled = 0;
FILE *fingerprint_fp = NULL;
int malloc_size_stats = 0;

/* Flow detection counters */
static volatile uint32_t total_flows_completed = 0;
static volatile uint32_t flows_with_protocol = 0;

/* Forward declarations */
static void configure_ndpi(struct ndpi_detection_module_struct *ndpi_struct);
static void usage(void);
static benchmark_config_t parse_args(int argc, char **argv);
static void flow_detection_callback(struct ndpi_workflow *workflow, 
                                   struct ndpi_flow_info *flow, 
                                   void *userdata);

/* *********************************************** */

/* Flow detection callback to verify nDPI is working */
static void flow_detection_callback(struct ndpi_workflow *workflow, 
                                   struct ndpi_flow_info *flow, 
                                   void *userdata) {
    static pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;
    static uint32_t printed_count = 0;
    char buf1[64];
    (void)userdata;  /* Unused */
    
    __sync_fetch_and_add(&total_flows_completed, 1);
    
    /* Check if protocol was detected */
    if (flow->detected_protocol.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN ||
        flow->detected_protocol.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN) {
        __sync_fetch_and_add(&flows_with_protocol, 1);
    }
    
    /* Print first 10 flows for verification (thread-safe) */
    pthread_mutex_lock(&print_mutex);
    if (printed_count < 10) {
        printed_count++;
        
        printf("[Flow Detection #%u]\n", printed_count);
        printf("  Protocol: %s\n", 
               ndpi_protocol2name(workflow->ndpi_struct, flow->detected_protocol.proto, 
                                buf1, sizeof(buf1)));
        printf("  Confidence: %s\n", ndpi_confidence_get_name(flow->confidence));
        printf("  Packets: %u (c->s: %u, s->c: %u)\n",
               flow->src2dst_packets + flow->dst2src_packets,
               flow->src2dst_packets, flow->dst2src_packets);
        printf("  Bytes: %lu (c->s: %lu, s->c: %lu)\n",
               flow->src2dst_bytes + flow->dst2src_bytes,
               flow->src2dst_bytes, flow->dst2src_bytes);
        
        /* Print master protocol if different */
        if (flow->detected_protocol.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN &&
            flow->detected_protocol.proto.master_protocol != flow->detected_protocol.proto.app_protocol) {
            printf("  Master Protocol: %s\n",
                   ndpi_get_proto_name(workflow->ndpi_struct, 
                                      flow->detected_protocol.proto.master_protocol));
        }
        
        printf("\n");
    }
    pthread_mutex_unlock(&print_mutex);
}

/* *********************************************** */

int main(int argc, char **argv) {
    benchmark_config_t config = parse_args(argc, argv);
    
    printf("========================================\n");
    printf("nDPI High-Performance Benchmark Tool\n");
    printf("========================================\n\n");
    
    /* Step 1: Load PCAP into memory */
    printf("[1/5] Loading PCAP into memory...\n");
    packet_pool_t *pool = load_pcap_to_memory(config.pcap_file);
    if (!pool) {
        fprintf(stderr, "Error: Failed to load PCAP file\n");
        return 1;
    }
    printf("      Loaded %u packets (%.2f MB)\n", 
           pool->num_packets, pool->total_bytes / 1024.0 / 1024.0);
    
    /* Step 2: Initialize global nDPI context */
    printf("[2/5] Initializing nDPI...\n");
    struct ndpi_global_context *g_ctx = ndpi_global_init();
    if (!g_ctx) {
        fprintf(stderr, "Error: Failed to initialize global context\n");
        free_packet_pool(pool);
        return 1;
    }
    
    /* Step 3: Create worker threads */
    printf("[3/5] Creating %u worker thread(s)...\n", config.num_workers);
    worker_context_t *workers = calloc(config.num_workers, sizeof(worker_context_t));
    if (!workers) {
        fprintf(stderr, "Error: Failed to allocate workers\n");
        free_packet_pool(pool);
        return 1;
    }
    
    /* Initialize workers */
    for (uint32_t i = 0; i < config.num_workers; i++) {
        workers[i].worker_id = i;
        workers[i].cpu_core = config.core_list ? config.core_list[i] : i;
        workers[i].pool = pool;
        workers[i].num_loops = config.num_loops;
        workers[i].flow_randomization = config.flow_randomization;
        workers[i].timestamp_jitter = config.timestamp_jitter;
        workers[i].g_ctx = g_ctx;
    }
    
    /* Step 4: Distribute packets to workers by flow */
    printf("[4/5] Distributing packets to workers (by flow hash)...\n");
    assign_packets_to_workers(pool, workers, config.num_workers);
    
    uint32_t min_pkts = workers[0].num_packets;
    uint32_t max_pkts = workers[0].num_packets;
    for (uint32_t i = 1; i < config.num_workers; i++) {
        if (workers[i].num_packets < min_pkts) min_pkts = workers[i].num_packets;
        if (workers[i].num_packets > max_pkts) max_pkts = workers[i].num_packets;
    }
    printf("      Packets per worker: min=%u, max=%u (%.1f%% variance)\n",
           min_pkts, max_pkts, (max_pkts - min_pkts) * 100.0 / min_pkts);
    
    /* Step 5: Run benchmark */
    printf("[5/5] Starting benchmark...\n");
    printf("      Loops: %u\n", config.num_loops);
    printf("      Flow randomization: %s\n", config.flow_randomization ? "ON" : "OFF");
    printf("      Timestamp jitter: %s\n", config.timestamp_jitter ? "ON" : "OFF");
    printf("\n");
    printf("----------------------------------------\n");
    printf("Protocol Detection Samples (first 10 flows):\n");
    printf("----------------------------------------\n");
    
    /* Reset verification counters */
    total_flows_completed = 0;
    flows_with_protocol = 0;
    
    struct timeval tv_start, tv_end;
    gettimeofday(&tv_start, NULL);
    uint64_t cycles_start = rdtsc();
    
    /* Launch worker threads */
    for (uint32_t i = 0; i < config.num_workers; i++) {
        if (pthread_create(&workers[i].thread, NULL, worker_thread, &workers[i]) != 0) {
            fprintf(stderr, "Error: Failed to create thread %u\n", i);
            exit(1);
        }
    }
    
    /* Wait for completion */
    for (uint32_t i = 0; i < config.num_workers; i++) {
        pthread_join(workers[i].thread, NULL);
    }
    
    uint64_t cycles_end = rdtsc();
    gettimeofday(&tv_end, NULL);
    
    double elapsed = (tv_end.tv_sec - tv_start.tv_sec) + 
                    (tv_end.tv_usec - tv_start.tv_usec) / 1000000.0;
    
    /* Print results */
    print_benchmark_results(workers, config.num_workers, 
                          cycles_end - cycles_start, elapsed);
    
    /* Cleanup */
    for (uint32_t i = 0; i < config.num_workers; i++) {
        cleanup_worker(&workers[i]);
    }
    free(workers);
    free_packet_pool(pool);
    ndpi_global_deinit(g_ctx);
    if (config.core_list) free(config.core_list);
    
    return 0;
}

/* *********************************************** */

void* worker_thread(void *arg) {
    worker_context_t *worker = (worker_context_t*)arg;
    
    /* Set CPU affinity */
#ifdef __linux__
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(worker->cpu_core, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
#endif
    
    /* Initialize workflow */
    init_worker_workflow(worker);
    
    /* Performance counters */
    worker->packets_processed = 0;
    worker->bytes_processed = 0;
    worker->cycles_start = rdtsc();
    
    /* Process packets in loops */
    for (uint32_t loop = 0; loop < worker->num_loops; loop++) {
        for (uint32_t i = 0; i < worker->num_packets; i++) {
            uint32_t pkt_idx = worker->packet_indices[i];
            mem_packet_t *pkt = worker->pool->packets[pkt_idx];
            
            /* Apply randomization if enabled */
            if (worker->flow_randomization) {
                randomize_packet_tuple(pkt, loop, worker->worker_id);
            }
            if (worker->timestamp_jitter) {
                adjust_packet_timestamp(pkt, loop);
            }
            
            /* Prefetch next packet */
            if (i + PREFETCH_OFFSET < worker->num_packets) {
                uint32_t next_idx = worker->packet_indices[i + PREFETCH_OFFSET];
                __builtin_prefetch(worker->pool->packets[next_idx], 0, 3);
            }
            
            /* Process packet */
            struct pcap_pkthdr header;
            header.ts.tv_sec = pkt->timestamp_us / 1000000;
            header.ts.tv_usec = pkt->timestamp_us % 1000000;
            header.caplen = pkt->caplen;
            header.len = pkt->wirelen;
            
            struct ndpi_flow_info *flow = NULL;
            ndpi_risk flow_risk = 0;
            ndpi_workflow_process_packet(worker->workflow, &header, pkt->data, 
                                        &flow_risk, &flow);
            
            worker->packets_processed++;
            worker->bytes_processed += pkt->caplen;
        }
    }
    
    worker->cycles_end = rdtsc();
    worker->flows_detected = worker->workflow->num_allocated_flows;
    
    return NULL;
}

/* *********************************************** */

void init_worker_workflow(worker_context_t *worker) {
    struct ndpi_workflow_prefs prefs;
    memset(&prefs, 0, sizeof(prefs));
    
    prefs.decode_tunnels = 1;
    prefs.num_roots = NUM_ROOTS;
    prefs.max_ndpi_flows = MAX_NDPI_FLOWS;
    prefs.quiet_mode = 1;
    prefs.ignore_vlanid = 0;
    
    /* Create a dummy pcap handle for datalink type (we don't actually use it for reading) */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *dummy_pcap = pcap_open_dead(DLT_EN10MB, 65535);
    if (!dummy_pcap) {
        fprintf(stderr, "Error: Failed to create dummy pcap handle\n");
        exit(1);
    }
    
    worker->workflow = ndpi_workflow_init(&prefs, dummy_pcap, 1, 
                                         ndpi_serialization_format_unknown,
                                         worker->g_ctx);
    
    if (!worker->workflow) {
        fprintf(stderr, "Error: Failed to initialize workflow for worker %u\n", 
                worker->worker_id);
        exit(1);
    }
    
    configure_ndpi(worker->workflow->ndpi_struct);
    
    /* Register flow completion callback for verification */
    ndpi_workflow_set_flow_callback(worker->workflow, flow_detection_callback, worker);
    
    int ret = ndpi_finalize_initialization(worker->workflow->ndpi_struct);
    if (ret != 0) {
        fprintf(stderr, "Error: ndpi_finalize_initialization failed: %d\n", ret);
        exit(1);
    }
}

/* *********************************************** */

void cleanup_worker(worker_context_t *worker) {
    if (worker->workflow) {
        ndpi_workflow_free(worker->workflow);
        worker->workflow = NULL;
    }
    if (worker->packet_indices) {
        free(worker->packet_indices);
        worker->packet_indices = NULL;
    }
}

/* *********************************************** */

static void configure_ndpi(struct ndpi_detection_module_struct *ndpi_struct) {
    /* Basic configuration - can be extended with protocol files */
    ndpi_set_config(ndpi_struct, NULL, "tcp_ack_payload_heuristic", "enable");
    
    if (_protoFilePath != NULL) {
        ndpi_load_protocols_file(ndpi_struct, _protoFilePath);
    }
}

/* *********************************************** */

void print_benchmark_results(worker_context_t *workers, uint32_t num_workers,
                            uint64_t total_cycles, double elapsed_sec) {
    printf("\n========================================\n");
    printf("Benchmark Results\n");
    printf("========================================\n\n");
    
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    uint64_t total_flows = 0;
    
    for (uint32_t i = 0; i < num_workers; i++) {
        total_packets += workers[i].packets_processed;
        total_bytes += workers[i].bytes_processed;
        total_flows += workers[i].flows_detected;
    }
    
    printf("Total Statistics:\n");
    printf("  Elapsed time:    %.3f seconds\n", elapsed_sec);
    printf("  Total packets:   %lu\n", total_packets);
    printf("  Total bytes:     %lu (%.2f MB)\n", 
           total_bytes, total_bytes / 1024.0 / 1024.0);
    printf("  Unique flows:    %lu\n", total_flows);
    printf("\n");
    
    double pps = total_packets / elapsed_sec;
    double mpps = pps / 1000000.0;
    double avg_pkt_size = (double)total_bytes / total_packets;
    double gbps = (total_bytes * 8.0) / elapsed_sec / 1e9;
    
    printf("Throughput:\n");
    printf("  Packets/sec:     %.0f (%.3f Mpps)\n", pps, mpps);
    printf("  Bits/sec:        %.2f Gbps\n", gbps);
    printf("  Avg packet size: %.0f bytes\n", avg_pkt_size);
    printf("  Avg time/packet: %.2f ns\n", elapsed_sec * 1e9 / total_packets);
    printf("\n");
    
    /* Protocol detection verification */
    printf("Protocol Detection Verification:\n");
    printf("  Flows completed:      %u\n", total_flows_completed);
    printf("  Flows with protocol:  %u (%.1f%%)\n", 
           flows_with_protocol,
           total_flows_completed > 0 ? (flows_with_protocol * 100.0 / total_flows_completed) : 0.0);
    if (flows_with_protocol > 0) {
        printf("  ✓ nDPI is actively detecting protocols!\n");
    } else {
        printf("  ✗ WARNING: No protocols detected!\n");
    }
    printf("\n");
    
    if (num_workers > 1) {
        printf("Per-Worker Statistics:\n");
        for (uint32_t i = 0; i < num_workers; i++) {
            double worker_pps = workers[i].packets_processed / elapsed_sec;
            double worker_gbps = (workers[i].bytes_processed * 8.0) / elapsed_sec / 1e9;
            printf("  Worker %2u [Core %2u]: %.2f Mpps, %.2f Gbps, %lu flows\n",
                   i, workers[i].cpu_core,
                   worker_pps / 1e6, worker_gbps, workers[i].flows_detected);
        }
        printf("\n");
        
        double scaling = (pps / num_workers) / (workers[0].packets_processed / elapsed_sec);
        printf("Scaling Efficiency: %.1f%%\n", scaling * 100);
        printf("\n");
    }
    
    printf("========================================\n");
}

/* *********************************************** */

static void usage(void) {
    printf("ndpiBenchmark - High-performance nDPI throughput benchmark\n\n");
    printf("Usage: ndpiBenchmark -i <pcap> [options]\n\n");
    printf("Required:\n");
    printf("  -i <file>          PCAP file to process\n\n");
    printf("Options:\n");
    printf("  -n <num>           Number of worker threads (default: 1)\n");
    printf("  -l <num>           Number of loops (default: 1)\n");
    printf("  -c <list>          CPU core list (e.g., 0,1,2,3)\n");
    printf("  -r                 Enable flow randomization (avoid cache cheating)\n");
    printf("  -t                 Enable timestamp jitter (avoid flow pollution)\n");
    printf("  -p <file>          Protocol configuration file\n");
    printf("  -q                 Quiet mode\n");
    printf("  -h                 Show this help\n\n");
    printf("Example:\n");
    printf("  ndpiBenchmark -i test.pcap -n 4 -l 1000 -r -t\n\n");
}

/* *********************************************** */

static benchmark_config_t parse_args(int argc, char **argv) {
    benchmark_config_t config;
    memset(&config, 0, sizeof(config));
    
    config.num_workers = 1;
    config.num_loops = 1;
    config.flow_randomization = 0;
    config.timestamp_jitter = 0;
    config.quiet_mode = 0;
    config.core_list = NULL;
    
    int opt;
    while ((opt = getopt(argc, argv, "i:n:l:c:p:rtqh")) != -1) {
        switch (opt) {
            case 'i':
                config.pcap_file = optarg;
                break;
            case 'n':
                config.num_workers = atoi(optarg);
                if (config.num_workers < 1 || config.num_workers > MAX_WORKERS) {
                    fprintf(stderr, "Error: Invalid number of workers (1-%d)\n", MAX_WORKERS);
                    exit(1);
                }
                break;
            case 'l':
                config.num_loops = atoi(optarg);
                if (config.num_loops < 1) {
                    fprintf(stderr, "Error: Invalid number of loops\n");
                    exit(1);
                }
                break;
            case 'c':
                config.core_list = malloc(config.num_workers * sizeof(uint32_t));
                char *token = strtok(optarg, ",");
                uint32_t idx = 0;
                while (token && idx < config.num_workers) {
                    config.core_list[idx++] = atoi(token);
                    token = strtok(NULL, ",");
                }
                break;
            case 'r':
                config.flow_randomization = 1;
                break;
            case 't':
                config.timestamp_jitter = 1;
                break;
            case 'p':
                _protoFilePath = optarg;
                break;
            case 'q':
                config.quiet_mode = 1;
                verbose = 0;
                break;
            case 'h':
                usage();
                exit(0);
            default:
                usage();
                exit(1);
        }
    }
    
    if (!config.pcap_file) {
        fprintf(stderr, "Error: PCAP file required (-i)\n\n");
        usage();
        exit(1);
    }
    
    return config;
}
