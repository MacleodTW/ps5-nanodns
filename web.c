#include "nanodns.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

// URL Decoder
static void url_decode(char *dst, const char *src) {
  char a, b;
  while (*src) {
    if ((*src == '%') && ((a = src[1]) && (b = src[2])) && (isxdigit(a) && isxdigit(b))) {
      if (a >= 'a') a -= 'a'-'A';
      else if (a >= 'A') a -= ('A' - 10);
      else a -= '0';
      if (b >= 'a') b -= 'a'-'A';
      else if (b >= 'A') b -= ('A' - 10);
      else b -= '0';
      *dst++ = 16 * a + b;
      src += 3;
    } else if (*src == '+') {
      *dst++ = ' ';
      src++;
    } else {
      *dst++ = *src++;
    }
  }
  *dst = '\0';
}

void web_process_request(int listen_fd, app_config_t *cfg) {
  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);
  int client_fd;
  char buf[2048];
  ssize_t nread;

  client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
  if (client_fd < 0) return;

  // Add: Set receive timeout to 2 seconds
  // Prevents the thread from hanging indefinitely if a client connects but sends no data
  struct timeval tv;
  tv.tv_sec = 2;
  tv.tv_usec = 0;
  setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  nread = recv(client_fd, buf, sizeof(buf) - 1, 0);
  if (nread <= 0) {
    close(client_fd);
    return;
  }
  buf[nread] = '\0';

  bool redirect = false;

  // Handle POST requests
  if (strncmp(buf, "POST ", 5) == 0) {
    char *body = strstr(buf, "\r\n\r\n");
    if (body) {
      body += 4;
      
      // Handle updating general settings (Debug, Timeout, Web Port, Upstreams)
      if (strncmp(buf, "POST /update_settings", 21) == 0) {
        char *dbg_str = strstr(body, "debug=");
        char *to_str = strstr(body, "timeout=");
        char *wp_str = strstr(body, "web_port=");
        char *u1_str = strstr(body, "upstream1=");
        char *u2_str = strstr(body, "upstream2=");
        char *u3_str = strstr(body, "upstream3=");

        if (dbg_str) {
          int dbg = 0;
          sscanf(dbg_str, "debug=%d", &dbg);
          cfg->debug_enabled = dbg;
          g_debug_enabled = dbg; // Apply to logger immediately
        }
        if (to_str) {
          int to = 1500;
          sscanf(to_str, "timeout=%d", &to);
          if (to > 0) cfg->timeout_ms = to;
        }
        if (wp_str) {
          int wp = DEFAULT_WEB_PORT;
          sscanf(wp_str, "web_port=%d", &wp);
          if (wp > 0 && wp <= 65535) cfg->web_port = wp;
        }

        // Reconfigure Upstreams
        cfg->upstream_count = 0;
        char ip_buf[256], decoded[256];

        if (u1_str && sscanf(u1_str, "upstream1=%255[^& \r\n]", ip_buf) == 1) {
          url_decode(decoded, ip_buf);
          if (decoded[0]) config_add_upstream(cfg, decoded);
        }
        if (u2_str && sscanf(u2_str, "upstream2=%255[^& \r\n]", ip_buf) == 1) {
          url_decode(decoded, ip_buf);
          if (decoded[0]) config_add_upstream(cfg, decoded);
        }
        if (u3_str && sscanf(u3_str, "upstream3=%255[^& \r\n]", ip_buf) == 1) {
          url_decode(decoded, ip_buf);
          if (decoded[0]) config_add_upstream(cfg, decoded);
        }

        // Failsafe: If all cleared, apply default 8.8.8.8
        if (cfg->upstream_count == 0) {
          config_apply_builtin_upstreams(cfg);
        }

        config_save_all(cfg);
        redirect = true;
      }
      else if (strncmp(buf, "POST /add_override", 18) == 0) {
        char *mask_str = strstr(body, "mask=");
        char *ip_str = strstr(body, "ip=");
        if (mask_str && ip_str) {
          char mask[256] = {0}, ip[256] = {0}, decoded_mask[256] = {0}, decoded_ip[256] = {0};
          sscanf(mask_str, "mask=%255[^&]", mask);
          sscanf(ip_str, "ip=%255[^& \r\n]", ip);
          url_decode(decoded_mask, mask);
          url_decode(decoded_ip, ip);
          if (config_add_rule(cfg, decoded_mask, decoded_ip) == 0) {
            config_save_all(cfg);
          }
        }
        redirect = true;
      }
      else if (strncmp(buf, "POST /del_override", 18) == 0) {
        char *mask_str = strstr(body, "mask=");
        if (mask_str) {
          char mask[256] = {0}, decoded_mask[256] = {0};
          sscanf(mask_str, "mask=%255[^& \r\n]", mask);
          url_decode(decoded_mask, mask);
          if (config_del_rule(cfg, decoded_mask) == 0) {
            config_save_all(cfg);
          }
        }
        redirect = true;
      }
      else if (strncmp(buf, "POST /add_exception", 19) == 0) {
        char *mask_str = strstr(body, "mask=");
        if (mask_str) {
          char mask[256] = {0}, decoded_mask[256] = {0};
          sscanf(mask_str, "mask=%255[^& \r\n]", mask);
          url_decode(decoded_mask, mask);
          config_add_exception(cfg, decoded_mask);
          config_save_all(cfg);
        }
        redirect = true;
      }
      else if (strncmp(buf, "POST /del_exception", 19) == 0) {
        char *mask_str = strstr(body, "mask=");
        if (mask_str) {
          char mask[256] = {0}, decoded_mask[256] = {0};
          sscanf(mask_str, "mask=%255[^& \r\n]", mask);
          url_decode(decoded_mask, mask);
          if (config_del_exception(cfg, decoded_mask) == 0) {
            config_save_all(cfg);
          }
        }
        redirect = true;
      }
    }
  }

  // Redirect after handling POST
  if (redirect) {
    const char *resp = "HTTP/1.1 303 See Other\r\nLocation: /\r\n\r\n";
    send(client_fd, resp, strlen(resp), 0);
  }
  // Render GET webpage
  else {
    char *html = malloc(32768);
    if (html) {
      int offset = snprintf(html, 32768,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Connection: close\r\n\r\n"
        "<html><head><title>NanoDNS Dashboard</title>"
        "<style>"
        "body{font-family:Arial,sans-serif;margin:20px;background:#f4f4f9;color:#333;}"
        "h1,h2{color:#0056b3;} table{width:100%%;border-collapse:collapse;margin-bottom:20px;background:#fff;}"
        "th,td{padding:10px;border:1px solid #ddd;text-align:left;}"
        "th{background:#0056b3;color:#fff;} input[type=text],input[type=number],select{padding:8px;width:250px;border:1px solid #ccc;}"
        "input[type=submit]{padding:8px 20px;background:#28a745;color:#fff;border:none;cursor:pointer;border-radius:3px;}"
        ".btn-del{background:#dc3545;padding:5px 10px;}"
        ".form-box{background:#fff;padding:15px;border:1px solid #ddd;margin-bottom:30px;}"
        "label{display:inline-block;width:120px;font-weight:bold;margin-bottom:10px;}"
        "</style></head><body>"
        "<h1>NanoDNS Dashboard (%s v%s)</h1>", APP_NAME, APP_VERSION);

      // Render General Settings section
      offset += snprintf(html + offset, 32768 - offset,
        "<div class='form-box'><h2>General Settings</h2>"
        "<form action='/update_settings' method='POST' onsubmit=\"return confirm('Are you sure you want to save these settings?\\n(Changing the Web Port requires a restart to take effect)');\">"
        "<label>Debug Log:</label> <select name='debug'>"
        "<option value='0' %s>Disabled</option>"
        "<option value='1' %s>Enabled</option>"
        "</select><br>"
        "<label>Web Port:</label> <input type='number' name='web_port' value='%d' min='1' max='65535' required><br>"
        "<label>Timeout (ms):</label> <input type='number' name='timeout' value='%d' min='100' max='10000' required><br><br>"
        "<h3>Upstream Servers</h3>"
        "<label>Server 1:</label> <input type='text' name='upstream1' value='%s' placeholder='e.g. 8.8.8.8'><br>"
        "<label>Server 2:</label> <input type='text' name='upstream2' value='%s' placeholder='Optional'><br>"
        "<label>Server 3:</label> <input type='text' name='upstream3' value='%s' placeholder='Optional'><br><br>"
        "<input type='submit' value='Save Settings'></form></div>",
        cfg->debug_enabled ? "" : "selected",
        cfg->debug_enabled ? "selected" : "",
        cfg->web_port,
        cfg->timeout_ms,
        cfg->upstream_count > 0 ? cfg->upstreams[0].text : "",
        cfg->upstream_count > 1 ? cfg->upstreams[1].text : "",
        cfg->upstream_count > 2 ? cfg->upstreams[2].text : ""
      );

      // Render Overrides section
      offset += snprintf(html + offset, 32768 - offset, "<h2>Overrides (%zu / %d)</h2><table><tr><th>Domain Mask</th><th>Target IP</th><th width='80'>Action</th></tr>", cfg->rule_count, MAX_RULES);
      for (size_t i = 0; i < cfg->rule_count; i++) {
        offset += snprintf(html + offset, 32768 - offset, 
          "<tr><td>%s</td><td>%s</td>"
          "<td><form action='/del_override' method='POST' style='margin:0;' onsubmit=\"return confirm('Are you sure you want to delete this rule?');\">"
          "<input type='hidden' name='mask' value='%s'>"
          "<input type='submit' class='btn-del' value='Delete'></form></td></tr>", 
          cfg->rules[i].mask, cfg->rules[i].text, cfg->rules[i].mask);
      }
      offset += snprintf(html + offset, 32768 - offset, "</table>");

      offset += snprintf(html + offset, 32768 - offset,
        "<div class='form-box'>"
        "<form action='/add_override' method='POST' onsubmit=\"return confirm('Are you sure you want to add this rule?');\">"
        "<b>Add Override: </b>"
        "<input type='text' name='mask' placeholder='e.g., *.playstation.com' required> "
        "<input type='text' name='ip' placeholder='e.g., 0.0.0.0' required> "
        "<input type='submit' value='Add Rule'></form></div>");

      // Render Exceptions section
      offset += snprintf(html + offset, 32768 - offset, "<h2>Exceptions (%zu / %d)</h2><table><tr><th>Domain Mask</th><th width='80'>Action</th></tr>", cfg->exception_count, MAX_EXCEPTIONS);
      for (size_t i = 0; i < cfg->exception_count; i++) {
        offset += snprintf(html + offset, 32768 - offset, 
          "<tr><td>%s</td>"
          "<td><form action='/del_exception' method='POST' style='margin:0;' onsubmit=\"return confirm('Are you sure you want to delete this exception?');\">"
          "<input type='hidden' name='mask' value='%s'>"
          "<input type='submit' class='btn-del' value='Delete'></form></td></tr>", 
          cfg->exceptions[i].mask, cfg->exceptions[i].mask);
      }
      offset += snprintf(html + offset, 32768 - offset, "</table>");

      offset += snprintf(html + offset, 32768 - offset,
        "<div class='form-box'>"
        "<form action='/add_exception' method='POST' onsubmit=\"return confirm('Are you sure you want to add this exception?');\">"
        "<b>Add Exception: </b>"
        "<input type='text' name='mask' placeholder='e.g., feature.api.playstation.com' required> "
        "<input type='submit' value='Add Rule'></form></div>");

      snprintf(html + offset, 32768 - offset, "</body></html>");

      send(client_fd, html, strlen(html), 0);
      free(html);
    }
  }

  close(client_fd);
}

