#!/usr/bin/env python3
"""
Generate a larger, more realistic PCAP for nDPI throughput tests.
Includes multiple protocols, bidirectional flows, and variable packet sizes.

Supports target size (e.g., hundreds of MB) with streaming writes.
"""

import sys
import os
import math
import argparse

try:
    from scapy.all import Ether, IP, TCP, UDP, Raw, PcapWriter
except ImportError:
    print("Error: scapy is required")
    print("Install: pip3 install scapy")
    sys.exit(1)

def parse_args():
    parser = argparse.ArgumentParser(description="Generate a realistic PCAP (supports target size)")
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output PCAP file path (default: /home/zync/WORKSPACE/ndpi_speed/seed_150b.pcap)"
    )
    parser.add_argument(
        "--output-dir",
        default="/home/zync/WORKSPACE/ndpi_speed/input",
        help="Output directory (default: /home/zync/WORKSPACE/ndpi_speed)"
    )
    parser.add_argument(
        "--flows",
        type=int,
        default=500,
        help="Number of flows (default: 500). Ignored if target size is set."
    )
    parser.add_argument(
        "--pkts-per-flow",
        type=int,
        default=20,
        help="Packets per flow (default: 20). For TCP, each packet has a response."
    )
    parser.add_argument(
        "--payload-size",
        type=int,
        default=1400,
        help="Base payload size (default: 1400). Used as max for size profile."
    )
    parser.add_argument(
        "--target-mb",
        type=float,
        default=150,
        help="Target PCAP size (MB). When set, flow count is ignored."
    )
    parser.add_argument(
        "--target-bytes",
        type=int,
        default=None,
        help="Target PCAP size (bytes). Higher priority than --target-mb."
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=1,
        help="Random seed (default: 1)"
    )
    parser.add_argument(
        "--jitter-ms",
        type=float,
        default=0.2,
        help="Timestamp jitter in ms (default: 0.2)"
    )
    parser.add_argument(
        "--size-profile",
        choices=["mtu", "mixed", "small"],
        default="mixed",
        help="Packet size profile (default: mixed)"
    )
    parser.add_argument(
        "--plaintext-only",
        action="store_true",
        help="Generate only plaintext-like protocols (HTTP/SSH)"
    )
    parser.add_argument(
        "--sync-write",
        action="store_true",
        help="Enable sync writes (safer but much slower). Default: disabled for speed"
    )
    return parser.parse_args()


args = parse_args()

OUTPUT_DIR = args.output_dir
OUTPUT_FILE = args.output or os.path.join(OUTPUT_DIR, "seed_1500b.pcap")
RANDOM_SEED = args.seed

# 确保输出目录存在
os.makedirs(OUTPUT_DIR, exist_ok=True)

import random
random.seed(RANDOM_SEED)

print("========================================")
print("Generate realistic test PCAP")
print("========================================")
print()

flow_id = 0
SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "02:00:00:00:00:02"

# 配置参数
NUM_FLOWS = args.flows
PKTS_PER_FLOW = args.pkts_per_flow
PAYLOAD_SIZE = args.payload_size
JITTER_MS = args.jitter_ms
SIZE_PROFILE = args.size_profile

print("Config:")
print(f"  flows: {NUM_FLOWS}")
print(f"  pkts/flow: {PKTS_PER_FLOW}")
print(f"  max payload: {PAYLOAD_SIZE} bytes")
print(f"  size profile: {SIZE_PROFILE}")
print(f"  jitter: {JITTER_MS} ms")
print(f"  plaintext only: {args.plaintext_only}")
print(f"  sync write: {args.sync_write}")
print()

# 定义协议模板
protocols = [
    {
        'name': 'HTTP',
        'weight': 30,
        'sport': 80,
        'transport': 'tcp',
        'request': b'GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\nAccept: */*\r\n\r\n',
        'response': b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nhello, world'
    },
    # {
    #     'name': 'HTTPS',
    #     'weight': 40,
    #     'sport': 443,
    #     'transport': 'tcp',
    #     'request': b'\x16\x03\x01\x02\x00',
    #     'response': b'\x16\x03\x03\x02\x00'
    # },
    {
        'name': 'DNS',
        'weight': 10,
        'sport': 53,
        'transport': 'udp',
        'request': b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00',
        'response': b'\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
    },
    {
        'name': 'SSH',
        'weight': 10,
        'sport': 22,
        'transport': 'tcp',
        'request': b'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4\r\n',
        'response': b'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n'
    },
    {
        'name': 'MySQL',
        'weight': 10,
        'sport': 3306,
        'transport': 'tcp',
        'request': b'\x03\x00\x00\x01\x00',
        'response': b'\x0a\x35\x2e\x37\x2e\x33\x30'
    },
]

if args.plaintext_only:
    protocols = [p for p in protocols if p["name"] in ("HTTP", "SSH")]
    if not protocols:
        print("Error: plaintext protocol set is empty")
        sys.exit(1)

def build_payload(proto_payload, payload_size):
    if payload_size <= 0:
        return b""
    base_payload = proto_payload * (payload_size // len(proto_payload) + 1)
    return base_payload[:payload_size]


def choose_payload_size():
    if SIZE_PROFILE == "mtu":
        return random.randint(max(200, PAYLOAD_SIZE - 200), PAYLOAD_SIZE)
    if SIZE_PROFILE == "small":
        return random.randint(60, min(400, PAYLOAD_SIZE))
    # mixed
    roll = random.random()
    if roll < 0.6:
        return random.randint(max(200, PAYLOAD_SIZE - 300), PAYLOAD_SIZE)
    if roll < 0.9:
        return random.randint(200, 800)
    return random.randint(60, 200)


def build_tcp_packet(src_ip, dst_ip, src_port, dst_port, flags, seq, ack, payload):
    return Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=src_ip, dst=dst_ip) / TCP(
        sport=src_port,
        dport=dst_port,
        flags=flags,
        seq=seq,
        ack=ack
    ) / Raw(load=payload)


def build_udp_packet(src_ip, dst_ip, src_port, dst_port, payload):
    return Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=src_ip, dst=dst_ip) / UDP(
        sport=src_port,
        dport=dst_port
    ) / Raw(load=payload)


def estimate_packet_size():
    payload = build_payload(protocols[0]['request'], PAYLOAD_SIZE)
    pkt = build_tcp_packet("192.168.0.1", "10.0.0.1", 12345, 80, 'PA', 1, 1, payload)
    return len(bytes(pkt))


target_bytes = None
if args.target_bytes is not None:
    target_bytes = args.target_bytes
elif args.target_mb is not None:
    target_bytes = int(args.target_mb * 1024 * 1024)

if target_bytes is not None:
    est_pkt_size = estimate_packet_size()
    total_packets = max(1, math.ceil(target_bytes / est_pkt_size))
    NUM_FLOWS = max(1, math.ceil(total_packets / PKTS_PER_FLOW))
    print(f"Target size: {target_bytes} bytes")
    print(f"Estimated packet size: {est_pkt_size} bytes")
    print(f"Estimated total packets: {total_packets}")
    print(f"Estimated flows: {NUM_FLOWS}")
    print()

print(f"  total packets (est): {NUM_FLOWS * PKTS_PER_FLOW}")
print()

# 预计算权重
total_weight = sum(p['weight'] for p in protocols)
weighted_protocols = []
for proto in protocols:
    weighted_protocols.append((proto, proto['weight'] / total_weight))

def choose_protocol():
    r = random.random()
    acc = 0.0
    for proto, w in weighted_protocols:
        acc += w
        if r <= acc:
            return proto
    return weighted_protocols[-1][0]

print("Protocols:")
for proto, w in weighted_protocols:
    print(f"  {proto['name']:10s}: {w*100:5.1f}%")
print()

# 生成数据包
print("Generating packets...")
timestamp = 1000000.0
total_packets_written = 0
total_bytes_written = 0

writer = PcapWriter(OUTPUT_FILE, sync=args.sync_write)

def write_packet(pkt):
    global timestamp, total_packets_written, total_bytes_written
    pkt.time = timestamp
    interval = 0.001 + (random.random() - 0.5) * (JITTER_MS / 1000.0)
    if interval < 0:
        interval = 0.0
    timestamp += interval
    writer.write(pkt)
    total_packets_written += 1
    total_bytes_written += len(bytes(pkt))


def write_tcp_flow(src_ip, dst_ip, src_port, dst_port, proto):
    seq_c = random.randint(1, 1_000_000)
    seq_s = random.randint(1, 1_000_000)
    # SYN
    write_packet(build_tcp_packet(src_ip, dst_ip, src_port, dst_port, 'S', seq_c, 0, b""))
    # SYN-ACK
    write_packet(build_tcp_packet(dst_ip, src_ip, dst_port, src_port, 'SA', seq_s, seq_c + 1, b""))
    # ACK
    write_packet(build_tcp_packet(src_ip, dst_ip, src_port, dst_port, 'A', seq_c + 1, seq_s + 1, b""))

    seq_c += 1
    seq_s += 1

    for _ in range(PKTS_PER_FLOW):
        req_size = choose_payload_size()
        resp_size = choose_payload_size()
        req_payload = build_payload(proto['request'], req_size)
        resp_payload = build_payload(proto['response'], resp_size)
        write_packet(build_tcp_packet(src_ip, dst_ip, src_port, dst_port, 'PA', seq_c, seq_s, req_payload))
        seq_c += len(req_payload)
        write_packet(build_tcp_packet(dst_ip, src_ip, dst_port, src_port, 'PA', seq_s, seq_c, resp_payload))
        seq_s += len(resp_payload)

    # FIN close
    write_packet(build_tcp_packet(src_ip, dst_ip, src_port, dst_port, 'FA', seq_c, seq_s, b""))
    write_packet(build_tcp_packet(dst_ip, src_ip, dst_port, src_port, 'FA', seq_s, seq_c + 1, b""))


def write_udp_flow(src_ip, dst_ip, src_port, dst_port, proto):
    for _ in range(PKTS_PER_FLOW):
        req_size = choose_payload_size()
        resp_size = choose_payload_size()
        req_payload = build_payload(proto['request'], req_size)
        resp_payload = build_payload(proto['response'], resp_size)
        write_packet(build_udp_packet(src_ip, dst_ip, src_port, dst_port, req_payload))
        write_packet(build_udp_packet(dst_ip, src_ip, dst_port, src_port, resp_payload))


def should_stop():
    return target_bytes is not None and total_bytes_written >= target_bytes

while True:
    if target_bytes is not None and should_stop():
        break
    if target_bytes is None and flow_id >= NUM_FLOWS:
        break

    proto = choose_protocol()
    src_ip = f"192.168.{(flow_id // 256) % 256}.{flow_id % 256}"
    dst_ip = f"10.0.{(flow_id // 256) % 256}.{flow_id % 256}"
    src_port = 10000 + (flow_id % 50000)
    dst_port = proto['sport']

    if proto['transport'] == 'tcp':
        write_tcp_flow(src_ip, dst_ip, src_port, dst_port, proto)
    else:
        write_udp_flow(src_ip, dst_ip, src_port, dst_port, proto)

    flow_id += 1

writer.close()

print(f"Generated packets: {total_packets_written}")
print()

# 验证文件
file_size = os.path.getsize(OUTPUT_FILE)
file_size_mb = file_size / 1024 / 1024

print()
print("========================================")
print("Done")
print("========================================")
print(f"File: {OUTPUT_FILE}")
print(f"Size: {file_size_mb:.2f} MB")
print(f"Packets: {total_packets_written}")
print(f"Flows: {flow_id}")
print()
