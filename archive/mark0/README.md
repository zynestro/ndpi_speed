# ndpiBenchmark (Standalone)

This is a **standalone** version of the `ndpiBenchmark` tool you shared.

Key difference vs the original:
- **No dependency on `nDPI/example/reader_util.*` or `ndpi_workflow_*`**.
- It links **only** against the public **libndpi** API + libpcap + pthread.

This lets you keep the benchmark as a third-party app, in its own repo/tree,
while nDPI stays a separate dependency.

## Directory layout

```
ndpi-benchmark-standalone/
  include/
    ndpi_benchmark.h
    packet_parser.h
    flow_table.h
  src/
    main.c
    benchmark_util.c      # from your original project, kept mostly intact
    packet_parser.c       # Ethernet/VLAN/IPv4/IPv6 parser
    flow_table.c          # per-thread flow table
  Makefile
  README.md
```

## Build nDPI separately

You can build nDPI in its own directory/prefix, then build this app against it.

Example (nDPI from source):

```bash
git clone https://github.com/ntop/nDPI.git
cd nDPI
./autogen.sh
./configure --prefix=$HOME/ndpi-install --with-only-libndpi
make -j
make install
```

Notes:
- `--with-only-libndpi` builds the library without the example tools.
- You may need `libpcap-dev` / `libpcap-devel` installed.

## Build this standalone benchmark

### Preferred: pkg-config (if `libndpi.pc` is installed)

```bash
cd ndpi-benchmark-standalone
make
```

### Fallback: point to nDPI install prefix

```bash
make NDPI_PREFIX=$HOME/ndpi-install
```

### Fallback: point directly to an nDPI build tree

```bash
make NDPI_SRC=/path/to/nDPI
```

## Run

If you installed nDPI into a non-system prefix, ensure the runtime linker can
find `libndpi.so`:

```bash
export LD_LIBRARY_PATH=$HOME/ndpi-install/lib:$LD_LIBRARY_PATH
./ndpiBenchmark -i /path/to/trace.pcap -n 4 -l 1000 -r -t -c 0,1,2,3
```

Options:
- `-i <pcap>`: input pcap
- `-n <num>`: workers
- `-l <num>`: loops
- `-c <list>`: pin workers to CPU cores
- `-r`: randomize flow tuple per loop (avoid cache cheating)
- `-t`: timestamp jitter + flow cleanup between loops when `-r` is enabled
- `-p <file>`: load nDPI protocol configuration file
- `-q`: quiet

## How it works

Per worker thread:
- Maintain a **private** flow table (no locks)
- For each packet:
  1) Parse Ethernet/VLAN + IP + TCP/UDP
  2) Lookup / create a canonical bidirectional flow key
  3) Call `ndpi_detection_process_packet()` on the flow state

When `-r -t` is enabled:
- Each loop mutates the 5-tuple so the packets look like new flows
- We clear the flow table between loops to avoid unbounded growth

