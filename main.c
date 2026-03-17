#include "nanodns.h"
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <signal.h>

#ifdef PS4_HOST
#include <ps4/kernel.h>
#else
#include <ps5/kernel.h>
#endif

#define PRIVILEGED_AUTHID 0x4801000000000013L

volatile sig_atomic_t g_running = 1;
static int g_libnet_mem_id = -1;

int sceNetInit(void);
int sceNetPoolCreate(const char *name, int size, int flags);
int sceNetPoolDestroy(int memid);
int sceNetTerm(void);

static void on_signal(int signo) {
  (void)signo;
  g_running = 0;
}

// === Network and System Environment Initialization ===
static int elevate_privileges(void) {
  pid_t pid = getpid();
  if(kernel_set_ucred_authid(pid, PRIVILEGED_AUTHID) != 0) return -1;
  return 0;
}

static int net_init(void) {
  if(sceNetInit() != 0) return -1;
  g_libnet_mem_id = sceNetPoolCreate("nanodns", 64 * 1024, 0);
  if(g_libnet_mem_id < 0) { sceNetTerm(); return -1; }
  return 0;
}

static void net_fini(void) {
  if(g_libnet_mem_id >= 0) sceNetPoolDestroy(g_libnet_mem_id);
  sceNetTerm();
}

static int setup_udp_socket(int port) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in addr;
  int reuse = 1;
  if(fd < 0) return -1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { close(fd); return -1; }
  return fd;
}

static int setup_tcp_socket(int port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr;
  int reuse = 1;
  if(fd < 0) return -1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, 5) != 0) {
    close(fd); return -1;
  }
  return fd;
}

// === Main Program ===
int main(void) {
  app_config_t cfg;
  int dns_fd = -1, web_fd = -1;
  struct pollfd pfds[2];

  (void)syscall(SYS_thr_set_name, -1, "nanodns.elf");
  
  // Use sigaction instead of signal to avoid SA_RESTART
  // This ensures blocking calls (like poll, recv) are interrupted on exit
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_signal;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGQUIT, &sa, NULL);

  // Initialize configuration
  ensure_runtime_dir_exists(DATA_DIR);
  ensure_default_config_exists(CONFIG_PATH);

  if(load_config(CONFIG_PATH, &cfg) != 0) {
    config_set_defaults(&cfg);
    config_apply_builtin_upstreams(&cfg);
    (void)config_apply_builtin_overrides(&cfg);
    config_apply_builtin_exceptions(&cfg);
  }

  // Initialize logger
  logger_init(&cfg);

  if(elevate_privileges() != 0) {
    log_errno("kernel_set_ucred_authid failed");
    logger_fini();
    return EXIT_FAILURE;
  }

  if(net_init() != 0) {
    log_errno("net init failed");
    logger_fini();
    return 1;
  }

  dns_fd = setup_udp_socket(DNS_PORT);
  web_fd = setup_tcp_socket(cfg.web_port);

  if(dns_fd < 0 || web_fd < 0) {
    log_errno("socket init failed");
    if(dns_fd >= 0) close(dns_fd);
    if(web_fd >= 0) close(web_fd);
    net_fini();
    logger_fini();
    return 1;
  }

  log_printf("[nanodns] Started DNS on :%d, Web on :%d\n", DNS_PORT, cfg.web_port);

  pfds[0].fd = dns_fd; pfds[0].events = POLLIN;
  pfds[1].fd = web_fd; pfds[1].events = POLLIN;

  while(g_running) {
    if(poll(pfds, 2, 1000) <= 0) continue;
    
    if(pfds[0].revents & POLLIN) {
      dns_process_request(dns_fd, &cfg);
    }
    if(pfds[1].revents & POLLIN) {
      web_process_request(web_fd, &cfg);
    }
  }

  log_printf("[nanodns] shutting down\n");
  close(dns_fd);
  close(web_fd);
  net_fini();
  logger_fini();
  return 0;
}

