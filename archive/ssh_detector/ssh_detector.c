/**
 * SSH流量识别器 - 完整示例
 * 
 * 功能：读取pcap文件，识别其中的SSH流量
 * 
 * 编译：gcc -o ssh_detector ssh_detector.c -lpcap
 * 运行：./ssh_detector test.pcap
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

/*============================================================================
 * 第一部分：DFA状态机定义
 *============================================================================*/

// DFA状态定义
typedef enum {
    STATE_START = 0,    // 起始状态
    STATE_S1    = 1,    // 匹配了 'S'
    STATE_S2    = 2,    // 匹配了 'SS'
    STATE_H     = 3,    // 匹配了 'SSH'
    STATE_ACCEPT = 4,   // 匹配了 'SSH-'，接受状态
    STATE_COUNT = 5
} DFAState;

// 状态转移表
// transitions[当前状态][输入字符] = 下一个状态
static int transitions[STATE_COUNT][256];

// 初始化DFA状态转移表
void init_dfa() {
    // 默认所有转移都回到起始状态
    for (int i = 0; i < STATE_COUNT; i++) {
        for (int j = 0; j < 256; j++) {
            transitions[i][j] = STATE_START;
        }
    }
    
    // 定义有效的状态转移
    // 状态0 + 'S' -> 状态1
    transitions[STATE_START]['S'] = STATE_S1;
    
    // 状态1 + 'S' -> 状态2
    transitions[STATE_S1]['S'] = STATE_S2;
    
    // 状态2 + 'H' -> 状态3
    transitions[STATE_S2]['H'] = STATE_H;
    
    // 状态3 + '-' -> 状态4 (接受状态)
    transitions[STATE_H]['-'] = STATE_ACCEPT;
    
    // 接受状态保持在接受状态
    for (int j = 0; j < 256; j++) {
        transitions[STATE_ACCEPT][j] = STATE_ACCEPT;
    }
    
    printf("[DFA] 状态机初始化完成\n");
    printf("[DFA] 匹配模式: \"SSH-\"\n");
    printf("[DFA] 状态数: %d\n\n", STATE_COUNT);
}

// 使用DFA匹配数据
// 返回: 1=匹配成功(是SSH), 0=未匹配
int dfa_match(const uint8_t *data, int len) {
    DFAState state = STATE_START;
    
    for (int i = 0; i < len; i++) {
        // 状态转移
        state = transitions[state][data[i]];
        
        // 到达接受状态，匹配成功
        if (state == STATE_ACCEPT) {
            return 1;
        }
    }
    
    return 0;
}

/*============================================================================
 * 第二部分：数据包解析
 *============================================================================*/

// 以太网头部 (14字节)
struct ethernet_header {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ether_type;
};

#define ETHER_TYPE_IP 0x0800

// 统计信息
typedef struct {
    int total_packets;
    int ip_packets;
    int tcp_packets;
    int ssh_packets;
    int ssh_by_port;      // 仅通过端口识别
    int ssh_by_payload;   // 通过payload识别
} Stats;

// 处理单个数据包
void process_packet(const uint8_t *packet, int len, Stats *stats) {
    stats->total_packets++;
    
    // 1. 解析以太网头部
    if (len < sizeof(struct ethernet_header)) {
        return;
    }
    struct ethernet_header *eth = (struct ethernet_header *)packet;
    
    // 检查是否是IP包
    if (ntohs(eth->ether_type) != ETHER_TYPE_IP) {
        return;
    }
    stats->ip_packets++;
    
    // 2. 解析IP头部
    const uint8_t *ip_packet = packet + sizeof(struct ethernet_header);
    int ip_len = len - sizeof(struct ethernet_header);
    
    if (ip_len < sizeof(struct iphdr)) {
        return;
    }
    struct iphdr *ip = (struct iphdr *)ip_packet;
    
    // 只处理TCP
    if (ip->protocol != IPPROTO_TCP) {
        return;
    }
    stats->tcp_packets++;
    
    // 3. 解析TCP头部
    int ip_header_len = ip->ihl * 4;
    const uint8_t *tcp_packet = ip_packet + ip_header_len;
    int tcp_len = ip_len - ip_header_len;
    
    if (tcp_len < sizeof(struct tcphdr)) {
        return;
    }
    struct tcphdr *tcp = (struct tcphdr *)tcp_packet;
    
    uint16_t src_port = ntohs(tcp->source);
    uint16_t dst_port = ntohs(tcp->dest);
    
    // 4. 获取Payload
    int tcp_header_len = tcp->doff * 4;
    const uint8_t *payload = tcp_packet + tcp_header_len;
    int payload_len = tcp_len - tcp_header_len;
    
    // 5. SSH识别
    int is_ssh = 0;
    int method = 0;  // 1=端口, 2=payload
    
    // 方法1: 端口号识别 (简单但不可靠)
    if (src_port == 22 || dst_port == 22) {
        is_ssh = 1;
        method = 1;
        stats->ssh_by_port++;
    }
    
    // 方法2: Payload DFA匹配 (更可靠)
    if (payload_len > 0 && dfa_match(payload, payload_len)) {
        is_ssh = 1;
        method = 2;
        stats->ssh_by_payload++;
    }
    
    if (is_ssh) {
        stats->ssh_packets++;
        
        // 打印详细信息
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));
        
        printf("[SSH检测] %s:%d -> %s:%d", src_ip, src_port, dst_ip, dst_port);
        printf(" | 方法: %s", method == 2 ? "Payload匹配" : "端口识别");
        
        // 如果是payload匹配，显示SSH版本
        if (method == 2 && payload_len > 4) {
            printf(" | 版本: ");
            // 打印SSH版本字符串 (到换行为止)
            for (int i = 0; i < payload_len && i < 50; i++) {
                if (payload[i] == '\r' || payload[i] == '\n') break;
                printf("%c", payload[i]);
            }
        }
        printf("\n");
    }
}

/*============================================================================
 * 第三部分：主函数
 *============================================================================*/

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("用法: %s <pcap文件>\n", argv[0]);
        printf("示例: %s capture.pcap\n", argv[0]);
        return 1;
    }
    
    const char *pcap_file = argv[1];
    
    printf("==============================================\n");
    printf("         SSH流量识别器 - DFA示例\n");
    printf("==============================================\n\n");
    
    // 初始化DFA
    init_dfa();
    
    // 打开pcap文件
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "无法打开文件 %s: %s\n", pcap_file, errbuf);
        return 1;
    }
    
    printf("[INFO] 正在分析文件: %s\n\n", pcap_file);
    printf("----------------------------------------------\n");
    
    // 处理数据包
    Stats stats = {0};
    struct pcap_pkthdr *header;
    const uint8_t *packet;
    int ret;
    
    while ((ret = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (ret == 0) continue;  // 超时
        process_packet(packet, header->caplen, &stats);
    }
    
    // 输出统计
    printf("----------------------------------------------\n\n");
    printf("==============================================\n");
    printf("                 统计结果\n");
    printf("==============================================\n");
    printf("总数据包:        %d\n", stats.total_packets);
    printf("IP数据包:        %d\n", stats.ip_packets);
    printf("TCP数据包:       %d\n", stats.tcp_packets);
    printf("SSH数据包:       %d\n", stats.ssh_packets);
    printf("  - 端口识别:    %d\n", stats.ssh_by_port);
    printf("  - Payload识别: %d\n", stats.ssh_by_payload);
    printf("==============================================\n");
    
    pcap_close(handle);
    return 0;
}
