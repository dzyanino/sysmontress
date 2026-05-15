# sysmontress

This is just a simple C program that will stress the system or get its info and
return it through RESTApi endpoints

It uses `libmicrohttpd` for the HTTP server and `jansson` for JSON

This program was made for our school project to stress K8s pods

<sub><sup>(and it was half assed with AI so don't expect too much)</sup></sub>

## Installation

To build the program, just run

```bash
make
```

## Usage

```sh
./sysmontress
```

Starts the server on port `8080`.

## Endpoints

### `GET /api/health`

Returns a basic health check.

```json
{ "status": "ok" }
```

---

### `GET /api/sysinfo`

Returns current system information.

```json
{
  "hostname": "my-host",
  "cpu_usage_percent": 12.5,
  "total_ram_mb": 16000,
  "used_ram_mb": 8400,
  "network_interface": "eth0",
  "network_rx_bytes": 123456,
  "network_tx_bytes": 654321
}
```

---

### `GET /api/stress/compute`

Runs a CPU/memory stress test using `stress-ng` and returns its output.

| Parameter  | Default | Min | Max | Description          |
|------------|---------|-----|-----|----------------------|
| `duration` | `5`     | `1` | `60`| Duration in seconds  |
| `cpu`      | `1`     | `1` | `16`| CPU worker threads   |
| `vm`       | `0`     | `0` | `8` | VM/malloc workers    |
| `vm_bytes` | `128`   | `16`| `512`| MB per VM worker   |

```sh
GET /stress/compute?duration=10&cpu=2&vm=1&vm_bytes=256
```

---

### `GET /api/stress/ping`

Returns a monotonic timestamp. Useful for benchmarking request handling overhead.

```json
{ "status": "pong", "timestamp_ms": 1234567890 }
```
