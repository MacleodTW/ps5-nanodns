#include "nanodns.h"
#include <ctype.h>
#include <errno.h>
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

static const char *k_default_config =
    "# " APP_NAME " configuration auto-generated\n"
    "#\n"
    "[general]\n"
    "log=" DEFAULT_LOG_PATH "\n"
    "debug=0\n"
    "web_port=8080\n"
    "\n"
    "[upstream]\n"
    "server=8.8.8.8\n"
    "timeout_ms=1500\n"
    "\n"
    "[overrides]\n"
    // Playstation
    "*playstation*=0.0.0.0\n"
    "*sonyentertainmentnetwork*=0.0.0.0\n"
    "*ribob01*=0.0.0.0\n"
    "*akamai*=0.0.0.0\n"
    // Youtube
    "*youtube*=0.0.0.0\n"
    "*ggpht*=0.0.0.0\n"
    "*googlevideo*=0.0.0.0\n"
    "*yt.be*=0.0.0.0\n"
    "*ytimg.com*=0.0.0.0\n"
    "*yt3.googleusercontent.com*=0.0.0.0\n"
    "\n"
    "[exceptions]\n"
    "feature.api.playstation.com\n"
    "*.stun.playstation.net\n"
    "stun.*.playstation.net\n"
    "ena.net.playstation.net\n"
    "post.net.playstation.net\n"
    "gst.prod.dl.playstation.net\n";

static char *ltrim(char *s) {
  while(*s && isspace((unsigned char)*s)) ++s;
  return s;
}

static void rtrim(char *s) {
  size_t len = strlen(s);
  while(len > 0 && isspace((unsigned char)s[len - 1])) s[--len] = '\0';
}

static char *trim(char *s) {
  s = ltrim(s);
  rtrim(s);
  return s;
}

static void strip_inline_comment(char *s) {
  char *hash = strchr(s, '#');
  char *semi = strchr(s, ';');
  char *cut = NULL;
  if(hash && semi) cut = hash < semi ? hash : semi;
  else if(hash) cut = hash;
  else if(semi) cut = semi;
  if(cut) {
    *cut = '\0';
    rtrim(s);
  }
}

void config_set_defaults(app_config_t *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  cfg->timeout_ms = DEFAULT_TIMEOUT_MS;
  cfg->web_port = DEFAULT_WEB_PORT;
  cfg->debug_enabled = 0;
  snprintf(cfg->log_path, sizeof(cfg->log_path), "%s", DEFAULT_LOG_PATH);
}

int config_add_upstream(app_config_t *cfg, const char *ip) {
  upstream_t *upstream;
  if(cfg->upstream_count >= MAX_UPSTREAMS) return -1;
  upstream = &cfg->upstreams[cfg->upstream_count];
  if(inet_pton(AF_INET, ip, &upstream->addr) != 1) return -1;
  snprintf(upstream->text, sizeof(upstream->text), "%s", ip);
  ++cfg->upstream_count;
  return 0;
}

int config_add_rule(app_config_t *cfg, const char *mask, const char *ip) {
  override_rule_t *rule;
  if(cfg->rule_count >= MAX_RULES) return -1;
  rule = &cfg->rules[cfg->rule_count];
  if(inet_pton(AF_INET, ip, &rule->addr) != 1) return -1;
  snprintf(rule->mask, sizeof(rule->mask), "%s", mask);
  normalize_domain(rule->mask, rule->mask, sizeof(rule->mask));
  snprintf(rule->text, sizeof(rule->text), "%s", ip);
  ++cfg->rule_count;
  return 0;
}

int config_del_rule(app_config_t *cfg, const char *mask) {
  char normalized[MAX_DOMAIN_LEN];
  normalize_domain(mask, normalized, sizeof(normalized));
  for (size_t i = 0; i < cfg->rule_count; i++) {
    if (strcmp(cfg->rules[i].mask, normalized) == 0) {
      for (size_t j = i; j < cfg->rule_count - 1; j++) {
        cfg->rules[j] = cfg->rules[j + 1];
      }
      cfg->rule_count--;
      return 0;
    }
  }
  return -1;
}

void config_add_exception(app_config_t *cfg, const char *mask) {
  exception_rule_t *rule;
  if(cfg->exception_count >= MAX_EXCEPTIONS) return;
  rule = &cfg->exceptions[cfg->exception_count];
  snprintf(rule->mask, sizeof(rule->mask), "%s", mask);
  normalize_domain(rule->mask, rule->mask, sizeof(rule->mask));
  ++cfg->exception_count;
}

int config_del_exception(app_config_t *cfg, const char *mask) {
  char normalized[MAX_DOMAIN_LEN];
  normalize_domain(mask, normalized, sizeof(normalized));
  for (size_t i = 0; i < cfg->exception_count; i++) {
    if (strcmp(cfg->exceptions[i].mask, normalized) == 0) {
      for (size_t j = i; j < cfg->exception_count - 1; j++) {
        cfg->exceptions[j] = cfg->exceptions[j + 1];
      }
      cfg->exception_count--;
      return 0;
    }
  }
  return -1;
}

void config_apply_builtin_exceptions(app_config_t *cfg) {
  cfg->exception_count = 0;
  config_add_exception(cfg, "feature.api.playstation.com");
  config_add_exception(cfg, "*.stun.playstation.net");
  config_add_exception(cfg, "stun.*.playstation.net");
  config_add_exception(cfg, "ena.net.playstation.net");
  config_add_exception(cfg, "post.net.playstation.net");
  config_add_exception(cfg, "gst.prod.dl.playstation.net");
}

void config_apply_builtin_upstreams(app_config_t *cfg) {
  cfg->upstream_count = 0;
  (void)config_add_upstream(cfg, "8.8.8.8");
}

int config_apply_builtin_overrides(app_config_t *cfg) {
  cfg->rule_count = 0;
  // Playstation
  if(config_add_rule(cfg, "*playstation*", "0.0.0.0") != 0) return -1;
  if(config_add_rule(cfg, "*sonyentertainmentnetwork*", "0.0.0.0") != 0) return -1;
  if(config_add_rule(cfg, "*ribob01*", "0.0.0.0") != 0) return -1;
  if(config_add_rule(cfg, "*akamai*", "0.0.0.0") != 0) return -1;
  // Youtube
  if(config_add_rule(cfg, "*youtube*", "0.0.0.0") != 0) return -1;
  if(config_add_rule(cfg, "*ggpht*", "0.0.0.0") != 0) return -1;
  if(config_add_rule(cfg, "*googlevideo*", "0.0.0.0") != 0) return -1;
  if(config_add_rule(cfg, "*yt.be*", "0.0.0.0") != 0) return -1;
  if(config_add_rule(cfg, "*ytimg.com*", "0.0.0.0") != 0) return -1;
  if(config_add_rule(cfg, "*yt3.googleusercontent.com*", "0.0.0.0") != 0) return -1;
  return 0;
}

int ensure_runtime_dir_exists(const char *path) {
  struct stat st;
  if(stat(path, &st) == 0) {
    if(S_ISDIR(st.st_mode)) return 0;
    errno = ENOTDIR;
    return -1;
  }
  if(mkdir(path, 0777) != 0) return -1;
  return 1;
}

int ensure_default_config_exists(const char *path) {
  struct stat st;
  FILE *fp;
  if(stat(path, &st) == 0) return 0;
  fp = fopen(path, "w");
  if(fp == NULL) return -1;
  if(fputs(k_default_config, fp) == EOF) {
    fclose(fp);
    errno = EIO;
    return -1;
  }
  if(fclose(fp) != 0) return -1;
  return 1;
}

int load_config(const char *path, app_config_t *cfg) {
  enum { SECTION_NONE = 0, SECTION_GENERAL, SECTION_UPSTREAM, SECTION_OVERRIDES, SECTION_EXCEPTIONS } section = SECTION_NONE;
  FILE *fp;
  char line[512];
  bool replace_upstreams = false;

  config_set_defaults(cfg);
  config_apply_builtin_upstreams(cfg);

  fp = fopen(path, "r");
  if(fp == NULL) return -1;

  cfg->rule_count = 0;
  cfg->exception_count = 0;

  while(fgets(line, sizeof(line), fp) != NULL) {
    char *s = trim(line);
    if(*s == '\0' || *s == '#' || *s == ';') continue;

    if(*s == '[') {
      char *end = strchr(s, ']');
      if(end == NULL) continue;
      *end = '\0';
      s = trim(s + 1);

      if(!strcasecmp(s, "general") || !strcasecmp(s, "settings")) section = SECTION_GENERAL;
      else if(!strcasecmp(s, "upstream") || !strcasecmp(s, "upstreams")) section = SECTION_UPSTREAM;
      else if(!strcasecmp(s, "override") || !strcasecmp(s, "overrides")) section = SECTION_OVERRIDES;
      else if(!strcasecmp(s, "exception") || !strcasecmp(s, "exceptions")) section = SECTION_EXCEPTIONS;
      else section = SECTION_NONE;
      continue;
    }

    strip_inline_comment(s);
    if(*s == '\0') continue;

    if(section == SECTION_EXCEPTIONS) {
      char *eq = strchr(s, '=');
      if(eq != NULL) *eq = '\0';
      char *key = trim(s);
      if(*key != '\0') config_add_exception(cfg, key);
      continue;
    }

    char *eq = strchr(s, '=');
    if(eq == NULL) continue;

    *eq = '\0';
    char *key = trim(s);
    char *value = trim(eq + 1);

    if(*key == '\0' || *value == '\0') continue;

    if(section == SECTION_GENERAL || (section == SECTION_NONE && (!strcasecmp(key, "log") || !strcasecmp(key, "debug") || !strcasecmp(key, "web_port")))) {
      if(!strcasecmp(key, "log")) snprintf(cfg->log_path, sizeof(cfg->log_path), "%s", value);
      else if(!strcasecmp(key, "debug")) cfg->debug_enabled = atoi(value) != 0 ? 1 : 0;
      else if(!strcasecmp(key, "web_port")) cfg->web_port = atoi(value);
    } else if(section == SECTION_UPSTREAM) {
      if(!strcasecmp(key, "server") || !strcasecmp(key, "dns")) {
        if(!replace_upstreams) {
          cfg->upstream_count = 0;
          replace_upstreams = true;
        }
        (void)config_add_upstream(cfg, value);
      } else if(!strcasecmp(key, "timeout_ms")) {
        cfg->timeout_ms = atoi(value);
        if(cfg->timeout_ms <= 0) cfg->timeout_ms = DEFAULT_TIMEOUT_MS;
      }
    } else if(section == SECTION_OVERRIDES) {
      (void)config_add_rule(cfg, key, value);
    }
  }

  fclose(fp);
  if(cfg->upstream_count == 0) config_apply_builtin_upstreams(cfg);
  if(cfg->web_port <= 0 || cfg->web_port > 65535) cfg->web_port = DEFAULT_WEB_PORT;

  return 0;
}

int config_save_all(const app_config_t *cfg) {
  FILE *fp = fopen(CONFIG_PATH, "w");
  if (fp == NULL) {
    log_errno("Failed to open config for writing");
    return -1;
  }

  fprintf(fp, "# %s configuration auto-generated by Web UI\n\n", APP_NAME);
  
  fprintf(fp, "[general]\n");
  fprintf(fp, "log=%s\n", cfg->log_path);
  fprintf(fp, "debug=%d\n", cfg->debug_enabled);
  fprintf(fp, "web_port=%d\n\n", cfg->web_port);

  fprintf(fp, "[upstream]\n");
  for (size_t i = 0; i < cfg->upstream_count; i++) {
    fprintf(fp, "server=%s\n", cfg->upstreams[i].text);
  }
  fprintf(fp, "timeout_ms=%d\n\n", cfg->timeout_ms);

  fprintf(fp, "[overrides]\n");
  for (size_t i = 0; i < cfg->rule_count; i++) {
    fprintf(fp, "%s=%s\n", cfg->rules[i].mask, cfg->rules[i].text);
  }
  fprintf(fp, "\n");

  fprintf(fp, "[exceptions]\n");
  for (size_t i = 0; i < cfg->exception_count; i++) {
    fprintf(fp, "%s\n", cfg->exceptions[i].mask);
  }

  fclose(fp);
  log_printf("[nanodns] Configuration saved to %s\n", CONFIG_PATH);
  return 0;
}

const override_rule_t *find_matching_rule(const app_config_t *cfg, const char *domain) {
  for(size_t i = 0; i < cfg->rule_count; ++i) {
    if(fnmatch(cfg->rules[i].mask, domain, FNM_CASEFOLD) == 0) return &cfg->rules[i];
  }
  return NULL;
}

int has_matching_exception(const app_config_t *cfg, const char *domain) {
  for(size_t i = 0; i < cfg->exception_count; ++i) {
    if(fnmatch(cfg->exceptions[i].mask, domain, FNM_CASEFOLD) == 0) return 1;
  }
  return 0;
}

