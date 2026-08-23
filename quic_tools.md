# QUIC Verification and Benchmarking Tools

This document lists the recommended tools for verifying, testing interoperability, and benchmarking QUIC implementations.

## Verification & Interoperability

* **[QUIC Interop Runner](https://github.com)**: The official automated framework used by the IETF community to test cross-implementation compatibility and protocol correctness across clients and servers.
* **[QUICTester](https://github.com)**: A learning-based, blackbox noncompliance checker designed to find edge-case protocol violations and logical bugs in QUIC servers.
* **[qlog](https://github.com)**: The standardized, JSON-based logging schema designed specifically for structured tracing of QUIC and HTTP/3 protocol events.
* **[qvis](https://github.com)**: A visual analysis suite built to ingest `qlog` files and generate sequence diagrams, packet flows, and congestion control timelines.

## Benchmarking & Network Simulation

* **[QUIC Network Simulator (QNS)](https://github.com)**: An ns-3 and Docker-based simulation framework used to test how implementations handle real-world bottlenecks, jitter, and packet loss.
* **[picoquic](https://github.com)**: A lightweight QUIC implementation that includes `quicperf`, a built-in benchmarking tool used to drive concurrent streams and measure raw throughput limits.
* **[Linux tc-netem](https://man7.org)**: The native Linux Network Emulation kernel module used to manually inject deterministic delay, jitter, and packet loss on local test interfaces.

