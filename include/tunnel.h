#pragma once
#ifndef WS_CLIENT_H
#define WS_CLIENT_H

#include "esp_log.h"
#include "esp_err.h"
#include <stdbool.h>

#define MAX_HTTP_REQUEST_SIZE (CONFIG_HTTPD_MAX_REQ_HDR_LEN + CONFIG_HTTPD_MAX_URI_LEN + 128)
#define TUNNEL_DEFAULT_RX_BUFFER_SIZE MAX_HTTP_REQUEST_SIZE
#define TUNNEL_DEFAULT_TX_BUFFER_SIZE 4096
#define TUNNEL_BUFFER_MIN_SIZE 256

#define LOCAL_SELECT_TIMEOUT_MKS 50000
#define TUNNEL_SELECT_TIMEOUT_MKS 100000
#define TUNNEL_SELECT_TLS_TIMEOUT_MKS 150000
#define TUNNEL_LATENCY_MS 150
#define MAX_EAGAIN_ATTEMPTS 30
// todo remove, only for local test
// #define TEST_CERT 1

// WebSocket opcodes
typedef enum
{
    WS_OPCODE_CONTINUATION = 0x00,
    WS_OPCODE_TEXT = 0x01,
    WS_OPCODE_BINARY = 0x02,
    WS_OPCODE_CLOSE = 0x08,
    WS_OPCODE_PING = 0x09,
    WS_OPCODE_PONG = 0x0a,
    WS_OPCODE_FIN = 0x80,
    WS_OPCODE_NONE = 0x100
} ws_opcode_t;

// Connection states
typedef enum
{
    WS_STATE_DISCONNECTED,
    // WS_STATE_CONNECTING,
    WS_STATE_CONNECTED,
    WS_STATE_CLOSING,
    WS_STATE_ERROR // Not used?
} ws_state_t;

typedef enum
{
    TUNNEL_STATE_DISCONNECTED,
    TUNNEL_STATE_AUTHENTICATING,
    TUNNEL_STATE_AUTHENTICATED,
    TUNNEL_STATE_RUNNING,
    TUNNEL_STATE_SUSPEND,
} tunnel_state_t;

typedef enum
{
    TUNNEL_RX_MARKER_EMPTY = 0x00,
    TUNNEL_RX_MARKER_START = 0x01,
    TUNNEL_RX_MARKER_CONTINUATION = 0x02,
    TUNNEL_RX_MARKER_END = 0x80,
    TUNNEL_RX_MARKER_EOF = 0x10,
    TUNNEL_RX_MARKER_ERROR = 0xff,
} tunnel_rx_marker_t;

typedef struct
{
    tunnel_state_t tunnel_state;
    uint8_t *suspend_command;
    size_t suspend_command_len;
    uint8_t *eof_marker;
    size_t eof_marker_len;
    uint8_t is_primary;
} tunnel_info_t;

// typedef int tunnel_tx_func_t(char *data, size_t len, tunnel_rx_marker_t *marker);
typedef int tunnel_rx_func_t(const char *data, size_t len);

typedef struct
{
    const char *provider_URI; // WebSocket provider URI (e.g., wss://device-tunnel.top:3333)
    const char *domain;       // Client domain
    const char *secret;       // Your account secret
    const char *name;         // Any valid device name for routing

    const char *client_cert; // Client certificate for mutual TLS (optional)
    const char *client_key;  // Client key for mutual TLS (optional)

    int32_t reconnect_timeout_ms; // Reconnect timeout in milliseconds (0 to disable)

    size_t rx_buffer_size; // Receive buffer size
    size_t tx_buffer_size; // Transmit buffer size

    tunnel_rx_func_t *rx_func; // Manula function for receiving data (used if local server proxy is disabled)
    // tunnel_tx_func_t *tx_func; // Manula function for sending data (used if local server proxy is disabled)

    uint16_t local_port; // 0 - disabled local server proxy (you need to provide custom tunnel_tx_func and tunnel_rx_func)
    uint8_t auto_eof;    // 0 - auto send EOF markers in responses
    uint8_t is_public;   // 0 - private, 1 - public
    uint8_t non_block;   // Socket mode (0 = blocking, 1 = non-blocking)
    uint8_t wifi_watch;  // 0 - disabled, 1 - enabled
    uint8_t priority;    // Task priority
    uint16_t stack_size; // Task stack size
} tunnel_config_t;

#define TUNNEL_DEFAULT_CONFIG()                          \
    {                                                    \
        .provider_URI = "wss://device-tunnel.top:3333",  \
        .domain = NULL,                                  \
        .secret = NULL,                                  \
        .name = "ESP-32",                                \
        .client_cert = NULL,                             \
        .client_key = NULL,                              \
        .reconnect_timeout_ms = 30000,                   \
        .rx_buffer_size = MAX_HTTP_REQUEST_SIZE,         \
        .tx_buffer_size = TUNNEL_DEFAULT_TX_BUFFER_SIZE, \
        .rx_func = NULL,                                 \
        .local_port = 80,                                \
        .auto_eof = 1,                                   \
        .is_public = 0,                                  \
        .non_block = 1,                                  \
        .wifi_watch = 1,                                 \
        .priority = tskIDLE_PRIORITY + 6,                \
        .stack_size = 1024 * 6,                          \
    }

#ifdef __cplusplus
extern "C"
{
#endif

    esp_err_t tunnel_init(tunnel_config_t *_config);
    void tunnel_get_info(tunnel_info_t *out_info);
    void tunnel_destroy(void);
    esp_err_t local_client_init();

    // void send_ping(void);
    void send_login_request(void);
    void send_start_request(void);
    void send_pause_request(void);

    esp_err_t ws_connect();
    esp_err_t ws_send_text(char *text);
    void send_internal_error(const char *error_msg);
    esp_err_t send_eof();
    esp_err_t ws_send_frame(uint8_t *data, size_t len, ws_opcode_t opcode, bool fin);
    // esp_err_t ws_client_send_binary(void *data, size_t len, bool fin);

#ifdef TEST_CERT
    static const char *test_cert = "-----BEGIN CERTIFICATE-----\n"
                                   "MIIFTTCCAzWgAwIBAgIRAIEbJZNMRe313pPFbPDf1AQwDQYJKoZIhvcNAQELBQAw\n"
                                   "ZjELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1\n"
                                   "cml0eSBSZXNlYXJjaCBHcm91cDEiMCAGA1UEAxMZKFNUQUdJTkcpIFByZXRlbmQg\n"
                                   "UGVhciBYMTAeFw0yNDAzMTMwMDAwMDBaFw0yNzAzMTIyMzU5NTlaMFoxCzAJBgNV\n"
                                   "BAYTAlVTMSAwHgYDVQQKExcoU1RBR0lORykgTGV0J3MgRW5jcnlwdDEpMCcGA1UE\n"
                                   "AxMgKFNUQUdJTkcpIENvdW50ZXJmZWl0IENhc2hldyBSMTAwggEiMA0GCSqGSIb3\n"
                                   "DQEBAQUAA4IBDwAwggEKAoIBAQCa8zRfthw5T4/n9kt2iuNxb4zt78rR3ZygeZvp\n"
                                   "GGx8nMdU7jqCLeOqkuqhKBvBV823fvA0bYg3JaCiFsyB6Idry8eVZLFJp3BtBZFX\n"
                                   "pbAb7+QCYLAZrUl5rX3G9VoTG/x4Q8a9pN57CI34bmJlKaaefSLoeeAOArk8fcV3\n"
                                   "/MkTQHWG+heh9ex0ogr3kDQQOSm+dI14hz75eHuiV26kory+tDDBN1re76Qf8RRt\n"
                                   "NxnngYZFrbJ9IOovFJa28weGOVXekOL4JJ7/VdFMMceXQze8M+0qnkaaj+HNRYQx\n"
                                   "z0N1geD3clT/xrme3gL0y5xAKjX6eq4dXdJuau0h90VFTc3DAgMBAAGjggEAMIH9\n"
                                   "MA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEw\n"
                                   "EgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUpFJG6lioj2jYt7GQ0UpCSo9r\n"
                                   "KHEwHwYDVR0jBBgwFoAUtfNl8v6wCpIf+zx980SgrGMlwxQwNgYIKwYBBQUHAQEE\n"
                                   "KjAoMCYGCCsGAQUFBzAChhpodHRwOi8vc3RnLXgxLmkubGVuY3Iub3JnLzATBgNV\n"
                                   "HSAEDDAKMAgGBmeBDAECATArBgNVHR8EJDAiMCCgHqAchhpodHRwOi8vc3RnLXgx\n"
                                   "LmMubGVuY3Iub3JnLzANBgkqhkiG9w0BAQsFAAOCAgEAHhpGt8p6QJk8fnM0zOS5\n"
                                   "AEUultcQP/20NSCdBpIxAfownd+ylUzH2s1prl8T9rhKzTm4xZ+NBqPEDAd/1p5e\n"
                                   "1PYqR8bNnKJcTAAkjBYvKo5br0ng6GUkCQTqJ3atbAvx2bghdfrULF6+u+f4o288\n"
                                   "Jo6o1kN2Jf1mTXTKi2GRJ5JerChn0dls28Mzx8QS3mWfFFSu+QuGwtxLty7ySzWE\n"
                                   "TH+lNMa8U6MbtSvoWf8OYzNUZ7Bih6JKnuo4ueG7zRir2go8ygNdZoWHhmk84c35\n"
                                   "ABH8dKX+fKNDK6xzeygtbguJN2/D1n72RQK8w7gXjT7ptphEoxmxe+ZSQ1XEoKUv\n"
                                   "I/Xy2D8F/5+b4Uxg8xSNev/N+E9F/env3Pp7zQJt/L4dhnUMoqqbAOifOE8l/CdN\n"
                                   "QHKv1OJkNYiaJ+xfx+Z9wUw4zRvjuD23EK42GjCfsK0JNuHb98LAmDBF+Xfq+PlH\n"
                                   "OGZTLlmnM72Jmjvi5IJ/uo5pM2QbmauUMle4tZwq11ipRs0BggZY0fHFK/7AxXj/\n"
                                   "j3PQZAbnLSo/9x/YUK6aR1NGZYBScfwFCfbEMNuXB1KJJvn/eQP7TbVSrqsrsHpk\n"
                                   "AAzAHvDkhUpctdN8Bfjjylj4p9D0zGpqz7RMd4EKnC+K6waARt3+cY05nzq7uF34\n"
                                   "4eamtcAi8f6h3h9vQlcWOAg=\n"
                                   "-----END CERTIFICATE-----\n";
#endif

#ifdef __cplusplus
}
#endif
#endif