#ifndef NANODNS_H
#define NANODNS_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>

#define APP_NAME "PS-NanoDNS"
#define APP_VERSION "1.2"
#define APP_COPYRIGHT "(c) drakmor modified by macleod"

#define DATA_DIR "/data/nanodns"
#define CONFIG_PATH DATA_DIR "/nanodns.ini"
#define DEFAULT_LOG_PATH DATA_DIR "/nanodns.log"

#define MAX_DNS_PACKET 4096
#define MAX_UPSTREAMS 8
#define MAX_RULES 64
#define MAX_EXCEPTIONS 64
#define MAX_DOMAIN_LEN 256
#define MAX_LOG_PATH 256

#define DNS_PORT 53
#define DEFAULT_WEB_PORT 8080
#define DEFAULT_TIMEOUT_MS 1500
#define OVERRIDE_TTL 60

typedef struct {
  struct in_addr addr;
  char text[INET_ADDRSTRLEN];
} upstream_t;

typedef struct {
  char mask[MAX_DOMAIN_LEN];
  struct in_addr addr;
  char text[INET_ADDRSTRLEN];
} override_rule_t;

typedef struct {
  char mask[MAX_DOMAIN_LEN];
} exception_rule_t;

typedef struct {
  upstream_t upstreams[MAX_UPSTREAMS];
  size_t upstream_count;
  override_rule_t rules[MAX_RULES];
  size_t rule_count;
  exception_rule_t exceptions[MAX_EXCEPTIONS];
  size_t exception_count;
  int timeout_ms;
  int debug_enabled;
  int web_port;
  char log_path[MAX_LOG_PATH];
} app_config_t;

extern volatile sig_atomic_t g_running;
extern int g_debug_enabled;

// === utils.c (Utilities and Logging) ===
int logger_init(const app_config_t *cfg);
void logger_fini(void);
void log_printf(const char *fmt, ...);
void log_errno(const char *what);
void normalize_domain(const char *input, char *output, size_t output_size);

// === cfg.c (Configuration and Rule Matching) ===
int ensure_runtime_dir_exists(const char *path);
int ensure_default_config_exists(const char *path);
int load_config(const char *path, app_config_t *cfg);
void config_set_defaults(app_config_t *cfg);
void config_apply_builtin_upstreams(app_config_t *cfg);
int config_apply_builtin_overrides(app_config_t *cfg);
void config_apply_builtin_exceptions(app_config_t *cfg);

// API for Adding/Deleting Rules and Upstreams
int config_add_upstream(app_config_t *cfg, const char *ip);
int config_add_rule(app_config_t *cfg, const char *mask, const char *ip);
int config_del_rule(app_config_t *cfg, const char *mask);
void config_add_exception(app_config_t *cfg, const char *mask);
int config_del_exception(app_config_t *cfg, const char *mask);
int config_save_all(const app_config_t *cfg);

const override_rule_t *find_matching_rule(const app_config_t *cfg, const char *domain);
int has_matching_exception(const app_config_t *cfg, const char *domain);

// === Module Entry Points ===
void dns_process_request(int server_fd, const app_config_t *cfg);
void web_process_request(int listen_fd, app_config_t *cfg);

#endif // NANODNS_H

