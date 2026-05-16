#include <ifaddrs.h>
#include <jansson.h>
#include <microhttpd.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PORT 8080
#define BUF_SIZE 1024

/*
 * Data model
 * */

typedef struct {
  double cpu_usage;
  unsigned long total_ram;
  unsigned long used_ram;
  char hostname[256];
  char iface[64];
  unsigned long long received_bytes;
  unsigned long long transmitted_bytes;
} SystemInfo;

/*
 * Collectors
 * */

void get_hostname(char *buffer, size_t size) {
  if (gethostname(buffer, size) != 0)
    strncpy(buffer, "unknown", size);
}

void get_ram_usage(unsigned long *total, unsigned long *used) {
  *total = *used = 0;

  FILE *fp = fopen("/proc/meminfo", "r");
  if (!fp)
    return;

  unsigned long mem_total = 0, mem_available = 0;
  char key[64];
  unsigned long value;

  while (fscanf(fp, "%63s %lu kB", key, &value) == 2) {
    if (strcmp(key, "MemTotal:") == 0)
      mem_total = value;
    else if (strcmp(key, "MemAvailable:") == 0)
      mem_available = value;

    if (mem_total && mem_available)
      break;
  }

  fclose(fp);

  *total = mem_total * 1024;
  *used = (mem_total - mem_available) * 1024;
}

void get_cpu_usage(double *cpu) {
  *cpu = -1.0;

  static unsigned long long previous_total = 0, previous_idle = 0;
  unsigned long long user, nice, system, idle, iowait, irq, softirq, steal,
      guest, guest_nice;
  unsigned long long total;

  FILE *fp = fopen("/proc/stat", "r");
  if (!fp)
    return;

  if (fscanf(fp, "cpu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu", &user,
             &nice, &system, &idle, &iowait, &irq, &softirq, &steal, &guest,
             &guest_nice) != 10) {
    fclose(fp);
    return;
  }

  fclose(fp);

  total = user + nice + system + idle + iowait + irq + softirq + steal + guest +
          guest_nice;

  if (previous_total == 0) {
    previous_total = total;
    previous_idle = idle;
    usleep(200000);
    return get_cpu_usage(cpu);
  }

  unsigned long long diff_total = total - previous_total;
  unsigned long long diff_idle = idle - previous_idle;

  previous_total = total;
  previous_idle = idle;

  *cpu = (diff_total == 0)
             ? 0.0
             : (double)(diff_total - diff_idle) * 100.0 / diff_total;
}

void get_network_stats(const char *iface, unsigned long long *received,
                       unsigned long long *transmitted) {
  *received = *transmitted = 0;

  FILE *fp = fopen("/proc/net/dev", "r");
  if (!fp)
    return;

  char line[BUF_SIZE];
  while (fgets(line, sizeof(line), fp)) {
    if (!strstr(line, iface))
      continue;

    char *colon = strchr(line, ':');
    if (!colon)
      continue;

    sscanf(colon + 1,
           "%llu %*u %*u %*u %*u %*u %*u %*u "
           "%llu",
           received, transmitted);
    break;
  }

  fclose(fp);
}

/* Returns the number of logical CPUs online, or -1 on error. */
static int get_cpu_count(void) { return (int)sysconf(_SC_NPROCESSORS_ONLN); }

/* Fills load[3] with 1-, 5-, 15-minute load averages. Returns 0 on success. */
static int get_load_avg(double load[3]) {
  return getloadavg(load, 3) == 3 ? 0 : -1;
}

/*
 * Returns the system uptime in seconds by reading /proc/uptime.
 * Falls back to sysinfo(2) if the file is unavailable.
 * */
static long get_uptime_seconds(void) {
  FILE *fp = fopen("/proc/uptime", "r");
  if (fp) {
    double up = 0.0;
    fscanf(fp, "%lf", &up);
    fclose(fp);
    return (long)up;
  }

  struct sysinfo si;
  return (sysinfo(&si) == 0) ? (long)si.uptime : -1L;
}

/* Writes an ISO-8601 UTC timestamp (e.g. "2025-05-16T12:34:56Z") into buf. */
static void iso_timestamp(char *buf, size_t size) {
  time_t now = time(NULL);
  struct tm gm;
  gmtime_r(&now, &gm);
  strftime(buf, size, "%Y-%m-%dT%H:%M:%SZ", &gm);
}

/*
 * Interface detection
 * */

static int detect_iface_ifaddrs(char *out, size_t size) {
  struct ifaddrs *ifaddr, *ifa;
  if (getifaddrs(&ifaddr) == -1)
    return -1;

  int found = 0;
  for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr)
      continue;
    if (ifa->ifa_addr->sa_family != AF_INET)
      continue;
    if (ifa->ifa_flags & IFF_LOOPBACK)
      continue;
    if (!(ifa->ifa_flags & IFF_UP))
      continue;

    strncpy(out, ifa->ifa_name, size - 1);
    out[size - 1] = '\0';
    found = 1;
    break;
  }

  freeifaddrs(ifaddr);
  return found ? 0 : -1;
}

static int detect_iface_proc(char *out, size_t size) {
  FILE *fp = fopen("/proc/net/dev", "r");
  if (!fp)
    return -1;

  char line[BUF_SIZE];
  int lineno = 0, found = 0;

  while (fgets(line, sizeof(line), fp)) {
    if (++lineno <= 2)
      continue;

    char name[64];
    char *colon = strchr(line, ':');
    if (!colon)
      continue;

    *colon = '\0';
    if (sscanf(line, " %63s", name) != 1)
      continue;

    if (strcmp(name, "lo") == 0)
      continue;

    strncpy(out, name, size - 1);
    out[size - 1] = '\0';
    found = 1;
    break;
  }

  fclose(fp);
  return found ? 0 : -1;
}

static void detect_interface(char *out, size_t size) {
  if (detect_iface_ifaddrs(out, size) == 0)
    return;
  if (detect_iface_proc(out, size) == 0)
    return;
  strncpy(out, "unknown", size);
}

/*
 * JSON builder
 * */

/*
 * /api/sysinfo
 *   timestamp_iso      ISO-8601 UTC collection time
 *   uptime_seconds     seconds since last boot
 *   cpu_count          logical CPUs online
 *   cpu_usage_percent  0-100 float
 *   load_avg           { "1m", "5m", "15m" }
 *   total_ram_mb / used_ram_mb / ram_usage_percent
 *   network_interface  detected iface name
 *   network_rx_bytes / network_rx_mb
 *   network_tx_bytes / network_tx_mb
 * */
static char *build_json(const SystemInfo *info) {
  char ts[32];
  iso_timestamp(ts, sizeof(ts));

  long uptime = get_uptime_seconds();
  int cpu_count = get_cpu_count();
  double load[3] = {-1.0, -1.0, -1.0};
  get_load_avg(load);

  double ram_pct = (info->total_ram > 0)
                       ? (double)info->used_ram * 100.0 / info->total_ram
                       : 0.0;

  json_t *load_obj = json_object();
  json_object_set_new(load_obj, "1m", json_real(load[0]));
  json_object_set_new(load_obj, "5m", json_real(load[1]));
  json_object_set_new(load_obj, "15m", json_real(load[2]));

  json_t *root = json_object();

  /* meta */
  json_object_set_new(root, "timestamp_iso", json_string(ts));
  json_object_set_new(root, "hostname", json_string(info->hostname));
  json_object_set_new(root, "uptime_seconds", json_integer(uptime));

  /* cpu */
  json_object_set_new(root, "cpu_count", json_integer(cpu_count));
  json_object_set_new(root, "cpu_usage_percent", json_real(info->cpu_usage));
  json_object_set_new(root, "load_avg", load_obj);

  /* ram */
  json_t *total_mb =
      json_integer((json_int_t)(info->total_ram / (1024 * 1024)));
  json_t *used_mb = json_integer((json_int_t)(info->used_ram / (1024 * 1024)));
  json_object_set_new(root, "total_ram_mb", total_mb);
  json_object_set_new(root, "used_ram_mb", used_mb);
  json_object_set_new(root, "ram_usage_percent", json_real(ram_pct));

  /* network */
  json_object_set_new(root, "network_interface", json_string(info->iface));
  json_object_set_new(root, "network_rx_bytes",
                      json_integer((json_int_t)info->received_bytes));
  json_object_set_new(
      root, "network_rx_mb",
      json_real((double)info->received_bytes / (1024.0 * 1024.0)));
  json_object_set_new(root, "network_tx_bytes",
                      json_integer((json_int_t)info->transmitted_bytes));
  json_object_set_new(
      root, "network_tx_mb",
      json_real((double)info->transmitted_bytes / (1024.0 * 1024.0)));

  char *out = json_dumps(root, JSON_INDENT(2));
  json_decref(root);
  return out;
}

/*
 * HTTP helpers
 * */

static enum MHD_Result send_response(struct MHD_Connection *conn,
                                     unsigned int status,
                                     const char *content_type, char *body,
                                     int must_free) {
  struct MHD_Response *resp = MHD_create_response_from_buffer(
      strlen(body), body,
      must_free ? MHD_RESPMEM_MUST_FREE : MHD_RESPMEM_PERSISTENT);

  MHD_add_response_header(resp, "Content-Type", content_type);
  MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");

  enum MHD_Result ret = MHD_queue_response(conn, status, resp);
  MHD_destroy_response(resp);
  return ret;
}

static enum MHD_Result send_error(struct MHD_Connection *conn,
                                  unsigned int status, const char *message) {
  char ts[32];
  iso_timestamp(ts, sizeof(ts));

  json_t *err = json_object();
  json_object_set_new(err, "error", json_integer(status));
  json_object_set_new(err, "message", json_string(message));
  json_object_set_new(err, "timestamp_iso", json_string(ts));

  char *body = json_dumps(err, 0);
  json_decref(err);

  return send_response(conn, status, "application/json", body, 1);
}

/*
 * ENDPOINTS handlers
 * */

/*
 * GET /api/stress/compute
 *
 * Query params (all optional):
 *   duration  seconds to run        (default: 5,   max: 60 )
 *   cpu       CPU worker threads    (default: 1,   max: 16 )
 *   vm        VM/malloc workers     (default: 0,   max: 8  )
 *   vm_bytes  MB per VM worker      (default: 128, max: 512)
 * */
static enum MHD_Result handle_stress_compute(struct MHD_Connection *conn) {
  const char *qs;
  int duration = 5, cpu_workers = 1, vm_workers = 0, vm_bytes = 128;

#define QS_INT(key, var, lo, hi)                                               \
  qs = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, key);          \
  if (qs) {                                                                    \
    int v = atoi(qs);                                                          \
    var = v<(lo) ? (lo) : v>(hi) ? (hi) : v;                                   \
  }

  QS_INT("duration", duration, 1, 60)
  QS_INT("cpu", cpu_workers, 1, 16)
  QS_INT("vm", vm_workers, 0, 8)
  QS_INT("vm_bytes", vm_bytes, 16, 512)
#undef QS_INT

  char command[512];
  if (vm_workers > 0)
    snprintf(command, sizeof(command),
             "stress-ng --cpu %d --vm %d --vm-bytes %dM "
             "--timeout %ds --metrics-brief 2>&1",
             cpu_workers, vm_workers, vm_bytes, duration);
  else
    snprintf(command, sizeof(command),
             "stress-ng --cpu %d --timeout %ds --metrics-brief 2>&1",
             cpu_workers, duration);

  /* cpu snapshot before the run */
  double cpu_before = -1.0;
  get_cpu_usage(&cpu_before);

  /* wall-clock start */
  struct timespec t0, t1;
  clock_gettime(CLOCK_MONOTONIC, &t0);

  FILE *fp = popen(command, "r");
  if (!fp)
    return send_error(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                      "Failed to launch stress-ng");

  char output[4096] = {0};
  size_t pos = 0, chunk;
  while (pos < sizeof(output) - 1 &&
         (chunk = fread(output + pos, 1, sizeof(output) - 1 - pos, fp)) > 0)
    pos += chunk;

  int exit_status = pclose(fp);

  /* wall-clock end + cpu snapshot after */
  clock_gettime(CLOCK_MONOTONIC, &t1);
  long elapsed_ms =
      (t1.tv_sec - t0.tv_sec) * 1000L + (t1.tv_nsec - t0.tv_nsec) / 1000000L;

  double cpu_after = -1.0;
  get_cpu_usage(&cpu_after);

  char ts[32];
  iso_timestamp(ts, sizeof(ts));

  json_t *root = json_object();
  json_object_set_new(root, "timestamp_iso", json_string(ts));
  json_object_set_new(root, "type", json_string("compute"));
  json_object_set_new(root, "command", json_string(command));
  json_object_set_new(root, "duration_s", json_integer(duration));
  json_object_set_new(root, "elapsed_ms", json_integer(elapsed_ms));
  json_object_set_new(root, "cpu_workers", json_integer(cpu_workers));
  json_object_set_new(root, "vm_workers", json_integer(vm_workers));
  json_object_set_new(root, "vm_bytes_mb", json_integer(vm_bytes));
  json_object_set_new(root, "exit_code",
                      json_integer(WEXITSTATUS(exit_status)));

  /* before / after cpu snapshots */
  json_t *snap = json_object();
  json_object_set_new(snap, "cpu_usage_percent_before", json_real(cpu_before));
  json_object_set_new(snap, "cpu_usage_percent_after", json_real(cpu_after));
  json_object_set_new(root, "cpu_snapshot", snap);

  json_object_set_new(root, "output", json_string(output));

  char *body = json_dumps(root, JSON_INDENT(2));
  json_decref(root);

  return send_response(conn, MHD_HTTP_OK, "application/json", body, 1);
}

/*
 * GET /api/stress/ping
 * */
static enum MHD_Result handle_stress_ping(struct MHD_Connection *conn) {
  static long seq = 0;

  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  long timestamp_ms = ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;

  char iso[32];
  iso_timestamp(iso, sizeof(iso));

  long uptime = get_uptime_seconds();

  json_t *root = json_object();
  json_object_set_new(root, "status", json_string("pong"));
  json_object_set_new(root, "seq", json_integer(++seq));
  json_object_set_new(root, "timestamp_ms", json_integer(timestamp_ms));
  json_object_set_new(root, "timestamp_iso", json_string(iso));
  json_object_set_new(root, "uptime_seconds", json_integer(uptime));

  char *body = json_dumps(root, 0);
  json_decref(root);

  return send_response(conn, MHD_HTTP_OK, "application/json", body, 1);
}

/*
 * GET /api/health
 * */
static enum MHD_Result handle_health(struct MHD_Connection *conn) {
  char ts[32];
  iso_timestamp(ts, sizeof(ts));

  long uptime = get_uptime_seconds();

  /* subsystem probes */
  int proc_stat_ok = (access("/proc/stat", R_OK) == 0);
  int proc_mem_ok = (access("/proc/meminfo", R_OK) == 0);
  int proc_net_ok = (access("/proc/net/dev", R_OK) == 0);

  const char *overall =
      (proc_stat_ok && proc_mem_ok && proc_net_ok) ? "ok" : "degraded";

  json_t *checks = json_object();
  json_object_set_new(checks, "proc_stat",
                      json_string(proc_stat_ok ? "ok" : "unavailable"));
  json_object_set_new(checks, "proc_meminfo",
                      json_string(proc_mem_ok ? "ok" : "unavailable"));
  json_object_set_new(checks, "proc_net_dev",
                      json_string(proc_net_ok ? "ok" : "unavailable"));

  json_t *root = json_object();
  json_object_set_new(root, "status", json_string(overall));
  json_object_set_new(root, "timestamp_iso", json_string(ts));
  json_object_set_new(root, "uptime_seconds", json_integer(uptime));
  json_object_set_new(root, "checks", checks);

  char *body = json_dumps(root, JSON_INDENT(2));
  json_decref(root);

  unsigned int http_status =
      strcmp(overall, "ok") == 0 ? MHD_HTTP_OK : MHD_HTTP_SERVICE_UNAVAILABLE;

  return send_response(conn, http_status, "application/json", body, 1);
}

/*
 * Requests dispacther
 * */

static enum MHD_Result
handle_request(void *cls, struct MHD_Connection *conn, const char *url,
               const char *method, const char *version, const char *upload_data,
               size_t *upload_data_size, void **con_cls) {
  (void)cls;
  (void)version;
  (void)upload_data;
  (void)upload_data_size;
  (void)con_cls;

  if (strcmp(method, "GET") != 0)
    return send_error(conn, MHD_HTTP_METHOD_NOT_ALLOWED,
                      "Only GET is supported");

  if (strcmp(url, "/api/sysinfo") == 0) {
    SystemInfo info = {0};

    detect_interface(info.iface, sizeof(info.iface));
    get_hostname(info.hostname, sizeof(info.hostname));
    get_ram_usage(&info.total_ram, &info.used_ram);
    get_cpu_usage(&info.cpu_usage);
    get_network_stats(info.iface, &info.received_bytes,
                      &info.transmitted_bytes);

    char *body = build_json(&info);
    return send_response(conn, MHD_HTTP_OK, "application/json", body, 1);
  }

  if (strcmp(url, "/api/health") == 0)
    return handle_health(conn);

  if (strcmp(url, "/api/stress/compute") == 0)
    return handle_stress_compute(conn);

  if (strcmp(url, "/api/stress/ping") == 0)
    return handle_stress_ping(conn);

  return send_error(conn, MHD_HTTP_NOT_FOUND, "Unknown endpoint");
}

/*
 * Entry point
 * */

int main(void) {
  struct MHD_Daemon *daemon =
      MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, PORT, NULL, NULL,
                       &handle_request, NULL, MHD_OPTION_END);

  if (!daemon) {
    fprintf(stderr, "Failed to start HTTP daemon on port %d\n", PORT);
    return EXIT_FAILURE;
  }

  char iface[64];
  detect_interface(iface, sizeof(iface));

  printf("sysinfo-api listening on http://0.0.0.0:%d\n", PORT);
  printf("  Detected interface : %s\n", iface);
  printf("  GET /api/sysinfo\n");
  printf("  GET /api/health\n");
  printf("  GET /api/stress/compute[?duration=5&cpu=2&vm=1&vm_bytes=128]\n");
  printf("  GET /api/stress/ping\n");

  pause();
  MHD_stop_daemon(daemon);
  return EXIT_SUCCESS;
}
