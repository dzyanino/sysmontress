# sysmontress

A simple C program that stresses the system or collects its info and exposes
everything through REST API endpoints.

Uses `libmicrohttpd` for the HTTP server and `jansson` for JSON.

Made for a school project to stress K8s pods.

<sub><sup>(and it was half assed with AI so don't expect too much)</sup></sub>

## Installation

```bash
make
```

## Usage

```sh
./sysmontress
```

Starts the server on `http://0.0.0.0:8080`.

## Endpoints

### `GET /api/health`

Returns the health status of the server and its data sources.

The HTTP status is `200 OK` when all checks pass, or `503 Service Unavailable`
when any subsystem is unavailable.

```json
{
  "status": "ok",
  "timestamp_iso": "2025-05-16T12:00:00Z",
  "uptime_seconds": 3600,
  "checks": {
    "proc_stat": "ok",
    "proc_meminfo": "ok",
    "proc_net_dev": "ok"
  }
}
```

`status` is either `"ok"` or `"degraded"`. Each entry in `checks` is either
`"ok"` or `"unavailable"`.

---

### `GET /api/sysinfo`

Returns a snapshot of the current system state.

```json
{
  "timestamp_iso": "2025-05-16T12:00:00Z",
  "hostname": "my-host",
  "uptime_seconds": 3600,

  "cpu_count": 4,
  "cpu_usage_percent": 12.5,
  "load_avg": {
    "1m": 0.45,
    "5m": 0.30,
    "15m": 0.20
  },

  "total_ram_mb": 16000,
  "used_ram_mb": 8400,
  "ram_usage_percent": 52.5,

  "network_interface": "eth0",
  "network_rx_bytes": 123456,
  "network_rx_mb": 0.12,
  "network_tx_bytes": 654321,
  "network_tx_mb": 0.62
}
```

---

### `GET /api/stress/compute`

Runs a CPU/memory stress test using `stress-ng` and returns its output along
with timing and CPU impact metrics.

| Parameter  | Default | Min | Max  | Description         |
|------------|---------|-----|------|---------------------|
| `duration` | `5`     | `1` | `60` | Duration in seconds |
| `cpu`      | `1`     | `1` | `16` | CPU worker threads  |
| `vm`       | `0`     | `0` | `8`  | VM/malloc workers   |
| `vm_bytes` | `128`   | `16`| `512`| MB per VM worker    |

```sh
GET /api/stress/compute?duration=10&cpu=2&vm=1&vm_bytes=256
```

```json
{
  "timestamp_iso": "2025-05-16T12:00:00Z",
  "type": "compute",
  "command": "stress-ng --cpu 2 --vm 1 --vm-bytes 256M --timeout 10s --metrics-brief 2>&1",
  "duration_s": 10,
  "elapsed_ms": 10043,
  "cpu_workers": 2,
  "vm_workers": 1,
  "vm_bytes_mb": 256,
  "exit_code": 0,
  "cpu_snapshot": {
    "cpu_usage_percent_before": 5.2,
    "cpu_usage_percent_after": 98.7
  },
  "output": "stress-ng: info: ..."
}
```

`elapsed_ms` is the actual wall-clock duration measured by the server.
`cpu_snapshot` shows CPU load just before and just after the run so you can
see the real impact of the stress test.

---

### `GET /api/stress/ping`

Minimal endpoint for benchmarking request-handling overhead.

```json
{
  "status": "pong",
  "seq": 42,
  "timestamp_ms": 1234567890123,
  "timestamp_iso": "2025-05-16T12:00:00Z",
  "uptime_seconds": 3600
}
```

`seq` increments by one on every call for the lifetime of the process. A gap
in the sequence means a response was lost, which makes this endpoint useful
for automated latency and reliability loops without needing to compare
timestamps.
