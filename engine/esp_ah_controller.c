#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#include <errno.h>
#include <syslog.h>

#define LOG_FILE "/var/log/naval-ipsec.log"
#define CONFIG_FILE "/etc/ipsec.conf"
#define SECRETS_FILE "/etc/ipsec.secrets"
#define MAX_RETRIES 3
#define HEALTH_CHECK_INTERVAL 5
#define TUNNEL_TIMEOUT 30
#define MAX_FAILED_ATTEMPTS 5

// Security event types
typedef enum {
    EVENT_TUNNEL_UP,
    EVENT_TUNNEL_DOWN,
    EVENT_AUTH_FAILURE,
    EVENT_RESTART_ATTEMPT,
    EVENT_INTRUSION_DETECTED,
    EVENT_KEY_ROTATION,
    EVENT_SYSTEM_ERROR
} SecurityEventType;

// Global state tracking
typedef struct {
    int tunnel_status;
    int failed_attempts;
    time_t last_success;
    time_t last_check;
    int restart_count;
    int intrusion_alerts;
} SystemState;

SystemState sys_state = {0, 0, 0, 0, 0, 0};
volatile sig_atomic_t keep_running = 1;

// ============================================
// LOGGING & AUDIT SYSTEM
// ============================================

void init_logging() {
    openlog("NAVAL-ESP", LOG_PID | LOG_CONS, LOG_DAEMON);
    FILE *log = fopen(LOG_FILE, "a");
    if (log) {
        fprintf(log, "\n=== Naval IPsec Controller Started ===\n");
        fclose(log);
    }
}

void log_security_event(SecurityEventType type, const char *message) {
    FILE *log = fopen(LOG_FILE, "a");
    if (!log) {
        syslog(LOG_ERR, "Failed to open log file: %s", strerror(errno));
        return;
    }

    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    const char *event_type_str;
    int priority;

    switch(type) {
        case EVENT_TUNNEL_UP:
            event_type_str = "TUNNEL_UP";
            priority = LOG_INFO;
            break;
        case EVENT_TUNNEL_DOWN:
            event_type_str = "TUNNEL_DOWN";
            priority = LOG_WARNING;
            break;
        case EVENT_AUTH_FAILURE:
            event_type_str = "AUTH_FAILURE";
            priority = LOG_ERR;
            break;
        case EVENT_INTRUSION_DETECTED:
            event_type_str = "INTRUSION";
            priority = LOG_ALERT;
            break;
        case EVENT_KEY_ROTATION:
            event_type_str = "KEY_ROTATION";
            priority = LOG_NOTICE;
            break;
        default:
            event_type_str = "UNKNOWN";
            priority = LOG_INFO;
    }

    fprintf(log, "[%s] [%s] %s\n", timestamp, event_type_str, message);
    fclose(log);
    
    syslog(priority, "[%s] %s", event_type_str, message);
}

// ============================================
// CONFIGURATION VALIDATION
// ============================================

int validate_config_security() {
    struct stat st;
    
    // Check if config files exist
    if (stat(CONFIG_FILE, &st) != 0) {
        log_security_event(EVENT_SYSTEM_ERROR, "Config file missing");
        return 0;
    }
    
    // Check file permissions (must be 600 or stricter)
    if (stat(SECRETS_FILE, &st) == 0) {
        if (st.st_mode & (S_IRWXG | S_IRWXO)) {
            log_security_event(EVENT_SYSTEM_ERROR, 
                "CRITICAL: Secrets file has unsafe permissions");
            return 0;
        }
    }
    
    // Validate PSK strength
    FILE *secrets = fopen(SECRETS_FILE, "r");
    if (secrets) {
        char line[256];
        while (fgets(line, sizeof(line), secrets)) {
            if (strstr(line, "PSK")) {
                char *psk = strstr(line, "\"");
                if (psk) {
                    psk++;
                    char *end = strstr(psk, "\"");
                    if (end) {
                        int psk_len = end - psk;
                        if (psk_len < 16) {
                            log_security_event(EVENT_SYSTEM_ERROR, 
                                "CRITICAL: PSK too weak (< 16 chars)");
                            fclose(secrets);
                            return 0;
                        }
                    }
                }
            }
        }
        fclose(secrets);
    }
    
    return 1;
}

// ============================================
// INTRUSION DETECTION SYSTEM
// ============================================

void check_intrusion_indicators() {
    char cmd[256];
    FILE *fp;
    char buffer[512];
    int suspicious_activity = 0;
    
    // Check for failed authentication attempts
    snprintf(cmd, sizeof(cmd), 
        "grep -c 'authentication failed' /var/log/syslog 2>/dev/null || echo 0");
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            int failed_auth = atoi(buffer);
            if (failed_auth > MAX_FAILED_ATTEMPTS) {
                suspicious_activity = 1;
                sys_state.intrusion_alerts++;
                log_security_event(EVENT_INTRUSION_DETECTED, 
                    "Multiple authentication failures detected");
            }
        }
        pclose(fp);
    }
    
    // Check for unusual tunnel flapping
    if (sys_state.restart_count > 10) {
        suspicious_activity = 1;
        log_security_event(EVENT_INTRUSION_DETECTED, 
            "Tunnel instability detected - possible DoS attack");
    }
    
    // Check for ESP packet anomalies
    snprintf(cmd, sizeof(cmd), 
        "timeout 2 tcpdump -i any -c 100 esp 2>/dev/null | wc -l");
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            int packet_count = atoi(buffer);
            if (packet_count == 0 && sys_state.tunnel_status == 1) {
                suspicious_activity = 1;
                log_security_event(EVENT_INTRUSION_DETECTED, 
                    "No ESP packets detected despite active tunnel");
            }
        }
        pclose(fp);
    }
    
    if (suspicious_activity) {
        printf("[!] SECURITY ALERT: Intrusion indicators detected!\n");
        printf("[!] Total alerts: %d\n", sys_state.intrusion_alerts);
    }
}

// ============================================
// SECURE TUNNEL MANAGEMENT
// ============================================

int secure_system_call(const char *command) {
    int status = system(command);
    
    if (status == -1) {
        log_security_event(EVENT_SYSTEM_ERROR, "Failed to execute command");
        return -1;
    }
    
    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        if (exit_code != 0) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Command failed with exit code: %d", exit_code);
            log_security_event(EVENT_SYSTEM_ERROR, msg);
            return -1;
        }
    }
    
    return 0;
}

int start_ipsec_service() {
    printf("[*] Starting IPsec service...\n");
    log_security_event(EVENT_RESTART_ATTEMPT, "Initiating IPsec restart");
    
    if (secure_system_call("ipsec stop > /dev/null 2>&1") != 0) {
        return -1;
    }
    
    sleep(2);
    
    if (secure_system_call("ipsec start > /dev/null 2>&1") != 0) {
        return -1;
    }
    
    sleep(3);
    sys_state.restart_count++;
    return 0;
}

int establish_esp_tunnel() {
    printf("[*] Establishing ESP tunnel...\n");
    
    for (int i = 0; i < MAX_RETRIES; i++) {
        if (secure_system_call("ipsec up naval-esp > /dev/null 2>&1") == 0) {
            sys_state.failed_attempts = 0;
            sys_state.last_success = time(NULL);
            log_security_event(EVENT_TUNNEL_UP, "ESP tunnel established successfully");
            return 0;
        }
        
        sys_state.failed_attempts++;
        printf("[!] Attempt %d failed. Retrying...\n", i + 1);
        sleep(2);
    }
    
    log_security_event(EVENT_AUTH_FAILURE, "Failed to establish ESP tunnel after retries");
    return -1;
}

int check_tunnel_status() {
    FILE *fp = popen("ipsec status naval-esp 2>/dev/null | grep -c 'INSTALLED'", "r");
    if (!fp) {
        return 0;
    }
    
    char buffer[32];
    int installed = 0;
    
    if (fgets(buffer, sizeof(buffer), fp)) {
        installed = atoi(buffer);
    }
    
    pclose(fp);
    return installed > 0;
}

void verify_esp_encryption() {
    printf("[*] Verifying ESP encryption...\n");
    
    FILE *fp = popen("timeout 3 tcpdump -i any -c 5 esp 2>/dev/null | head -1", "r");
    if (fp) {
        char buffer[256];
        if (fgets(buffer, sizeof(buffer), fp)) {
            if (strstr(buffer, "ESP")) {
                printf("[✓] ESP packets detected - Encryption ACTIVE\n");
                log_security_event(EVENT_TUNNEL_UP, "ESP encryption verified");
            } else {
                printf("[!] WARNING: No ESP packets found\n");
                log_security_event(EVENT_SYSTEM_ERROR, "ESP encryption not verified");
            }
        }
        pclose(fp);
    }
}

// ============================================
// HEALTH MONITORING
// ============================================

void monitor_tunnel_health() {
    sys_state.last_check = time(NULL);
    
    int status = check_tunnel_status();
    
    if (status) {
        if (!sys_state.tunnel_status) {
            printf("[✓] Tunnel UP\n");
            sys_state.tunnel_status = 1;
            verify_esp_encryption();
        }
        
        // Check if tunnel has been up for a while
        if (difftime(time(NULL), sys_state.last_success) > TUNNEL_TIMEOUT) {
            verify_esp_encryption();
            sys_state.last_success = time(NULL);
        }
    } else {
        if (sys_state.tunnel_status) {
            printf("[!] Tunnel DOWN - Recovering...\n");
            log_security_event(EVENT_TUNNEL_DOWN, "Tunnel failure detected");
            sys_state.tunnel_status = 0;
        }
        
        // Auto-recovery
        if (start_ipsec_service() == 0) {
            sleep(2);
            establish_esp_tunnel();
        }
    }
    
    // Run intrusion detection every 5 checks
    static int check_counter = 0;
    if (++check_counter >= 5) {
        check_intrusion_indicators();
        check_counter = 0;
    }
}

// ============================================
// STATUS DISPLAY
// ============================================

void display_status() {
    printf("\n╔════════════════════════════════════════════╗\n");
    printf("║   NAVAL IPsec ESP SECURITY CONTROLLER    ║\n");
    printf("╚════════════════════════════════════════════╝\n");
    printf("  Status: %s\n", sys_state.tunnel_status ? "🟢 SECURE" : "🔴 OFFLINE");
    printf("  Failed Attempts: %d\n", sys_state.failed_attempts);
    printf("  Restarts: %d\n", sys_state.restart_count);
    printf("  Intrusion Alerts: %d\n", sys_state.intrusion_alerts);
    
    time_t now = time(NULL);
    if (sys_state.last_success > 0) {
        printf("  Last Success: %.0f seconds ago\n", 
            difftime(now, sys_state.last_success));
    }
    printf("════════════════════════════════════════════\n\n");
}

// ============================================
// SIGNAL HANDLING
// ============================================

void signal_handler(int signum) {
    keep_running = 0;
    log_security_event(EVENT_SYSTEM_ERROR, "Received shutdown signal");
}

// ============================================
// MAIN CONTROLLER
// ============================================

int main() {
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  NAVAL IPsec ESP/AH SECURITY CONTROLLER     ║\n");
    printf("║  Multi-Layer Defence System v2.0             ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");
    
    // Check if running as root
    if (geteuid() != 0) {
        fprintf(stderr, "[✗] ERROR: Must run as root (use sudo)\n");
        return 1;
    }
    
    // Initialize logging
    init_logging();
    log_security_event(EVENT_TUNNEL_UP, "Controller initialized");
    
    // Validate security configuration
    printf("[*] Validating security configuration...\n");
    if (!validate_config_security()) {
        fprintf(stderr, "[✗] Security validation FAILED\n");
        fprintf(stderr, "[!] Fix configuration issues before proceeding\n");
        return 1;
    }
    printf("[✓] Security validation passed\n\n");
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initial startup
    if (start_ipsec_service() != 0) {
        fprintf(stderr, "[✗] Failed to start IPsec service\n");
        return 1;
    }
    
    sleep(2);
    
    if (establish_esp_tunnel() != 0) {
        fprintf(stderr, "[✗] Failed to establish ESP tunnel\n");
        return 1;
    }
    
    printf("\n[✓] System initialized successfully\n");
    printf("[*] Starting continuous monitoring...\n\n");
    
    // Main monitoring loop
    while (keep_running) {
        monitor_tunnel_health();
        display_status();
        sleep(HEALTH_CHECK_INTERVAL);
    }
    
    // Cleanup
    printf("\n[*] Shutting down gracefully...\n");
    log_security_event(EVENT_SYSTEM_ERROR, "Controller shutdown");
    closelog();
    
    return 0;
}