#include <ifaddrs.h>
#include <jansson.h>
#include <microhttpd.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysinfo.h>
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
  struct sysinfo si;
  if (sysinfo(&si) == 0) {
    *total = si.totalram * si.mem_unit;
    *used = *total - (si.freeram * si.mem_unit);
  } else {
    *total = *used = 0;
  }
}

void get_cpu_usage(double *cpu) {
  *cpu = -1.0;

  static unsigned long long previous_total = 0, previous_idle = 0;
  unsigned long long user, nice, system, idle, iowait, irq, softirq, steal,
      guest, guest_nice, total;

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
    /* first call: seed, sleep, retry */
    previous_total = total;
    previous_idle = idle;
    usleep(200000);

    return get_cpu_usage(cpu);
  }

  unsigned long long dt = total - previous_total;
  unsigned long long di = idle - previous_idle;
  previous_total = total;
  previous_idle = idle;

  *cpu = (dt == 0) ? 0.0 : (double)(dt - di) * 100.0 / dt;
}

void get_network_stats(const char *iface, unsigned long long *rx,
                       unsigned long long *tx) {
  *rx = *tx = 0;

  FILE *fp = fopen("/proc/net/dev", "r");
  if (!fp)
    return;

  char line[BUF_SIZE];
  while (fgets(line, sizeof(line), fp)) {
    if (!strstr(line, iface))
      continue;

    /* skip past the colon after the interface name */
    char *colon = strchr(line, ':');
    if (!colon)
      continue;

    sscanf(colon + 1,
           "%llu %*u %*u %*u %*u %*u %*u %*u "
           "%llu",
           rx, tx);
    break;
  }

  fclose(fp);
}

/*
 * Interface detection that picks
 * the first non-loopback, UP+RUNNING AF_INET interface
 * and falls back to scanning /proc/net/dev if getifaddrs fails
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

    /* skip loopback */
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
 * json builder
 * */
static char *build_json(const SystemInfo *info) {
  json_t *root = json_object();

  json_object_set_new(root, "hostname", json_string(info->hostname));
  json_object_set_new(root, "cpu_usage_percent", json_real(info->cpu_usage));
  json_object_set_new(
      root, "total_ram_mb",
      json_integer((json_int_t)(info->total_ram / (1024 * 1024))));
  json_object_set_new(
      root, "used_ram_mb",
      json_integer((json_int_t)(info->used_ram / (1024 * 1024))));
  json_object_set_new(root, "network_interface", json_string(info->iface));
  json_object_set_new(root, "network_rx_bytes",
                      json_integer((json_int_t)info->received_bytes));
  json_object_set_new(root, "network_tx_bytes",
                      json_integer((json_int_t)info->transmitted_bytes));

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

  json_t *err = json_object();
  json_object_set_new(err, "error", json_integer(status));
  json_object_set_new(err, "message", json_string(message));
  char *body = json_dumps(err, 0);
  json_decref(err);
  return send_response(conn, status, "application/json", body, 1);
}

/*
 * Request handler
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

  /* onlyGET */
  if (strcmp(method, "GET") != 0)
    return send_error(conn, MHD_HTTP_METHOD_NOT_ALLOWED,
                      "Only GET is supported");

  /* GET /api/sysinfo */
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

  /* GET /health */
  if (strcmp(url, "/health") == 0) {
    char *body = strdup("{\"status\":\"ok\"}");
    return send_response(conn, MHD_HTTP_OK, "application/json", body, 1);
  }

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

  /* detect interface once at startup */
  char iface[64];
  detect_interface(iface, sizeof(iface));

  printf("sysinfo-api listening on http://0.0.0.0:%d\n", PORT);
  printf("  Detected interface : %s\n", iface);
  printf("  GET /api/sysinfo   — full system info\n");
  printf("  GET /health        — liveness probe\n");
  printf("Press ENTER to stop.\n\n");

  getchar();

  MHD_stop_daemon(daemon);

  return EXIT_SUCCESS;
}
