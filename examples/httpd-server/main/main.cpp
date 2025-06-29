#include "esp_app_desc.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_http_server.h"
#include "nvs_flash.h"
#include "tunnel.h"

static const char *TAG = "example";

#define WIFI_SSID "YOUR_WIFI_SSID"
#define WIFI_PASSWORD "YOUR_WIFI_PASSWORD"
#define MANUAL_EOF 0

#if MANUAL_EOF
static void send_eof(httpd_req_t *req)
{
    tunnel_info_t tunnel;
    tunnel_get_info(&tunnel);
    if (tunnel.eof_marker)
        httpd_send(req, (char *)tunnel.eof_marker, tunnel.eof_marker_len);
}
#endif

static esp_err_t hello_html_get_handler(httpd_req_t *req)
{
    extern const unsigned char hello_html_start[] asm("_binary_hello_world_html_start");
    extern const unsigned char hello_html_end[] asm("_binary_hello_world_html_end");
    const size_t hello_html_size = (hello_html_end - hello_html_start);
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, (const char *)hello_html_start, hello_html_size);
#if MANUAL_EOF
    send_eof(req);
#endif
    return ESP_OK;
}
static esp_err_t favicon_get_handler(httpd_req_t *req)
{
    extern const unsigned char favicon_ico_start[] asm("_binary_favicon_ico_start");
    extern const unsigned char favicon_ico_end[] asm("_binary_favicon_ico_end");
    const size_t favicon_ico_size = (favicon_ico_end - favicon_ico_start);
    httpd_resp_set_type(req, "image/x-icon");
    httpd_resp_send(req, (const char *)favicon_ico_start, favicon_ico_size);
#if MANUAL_EOF
    send_eof(req);
#endif
    return ESP_OK;
}

static void event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
        esp_wifi_connect();
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)
        ESP_LOGI(TAG, "WiFi connect fail");
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
        ESP_LOGI(TAG, "WiFi connected, waiting for tunnel connection");
}

void setup(void)
{
    const esp_app_desc_t *desc = esp_app_get_description();

    ESP_LOGI(TAG, "Starting example %s", desc->project_name);

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_t *netif = esp_netif_create_default_wifi_sta();
    if (netif == NULL)
    {
        ESP_LOGE(TAG, "Failed to create default WiFi STA interface");
        return;
    }

    // Setup tunnel
    tunnel_config_t tunnel = TUNNEL_DEFAULT_CONFIG();
    tunnel.domain = "xxl-test.sytes.net";                                               // can be set in config
    tunnel.secret = "6lHPnL4BkTznVtn0n9eg0JrEdFjymHQQ1NqhHxW17tpofUH4qpbadH8eNej572ry"; // can be set in config
    tunnel.name = desc->project_name;                                                   // name of yuor device
    tunnel.is_public = 1;                                                               // webserver can be accessed by anyone
#if MANUAL_EOF
    tunnel.auto_eof = 0; // automatically send EOF marker, for the lazy but works slowly
#endif
    ESP_ERROR_CHECK(tunnel_init(&tunnel));

    // Setup WiFi
    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, &instance_got_ip));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASSWORD,
        }};
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    // Setup webserver
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    ESP_ERROR_CHECK(httpd_start(&server, &config));

    httpd_uri_t favicon_uri = {
        .uri = "/favicon.ico",
        .method = HTTP_GET,
        .handler = favicon_get_handler,
    };
    httpd_register_uri_handler(server, &favicon_uri);
    httpd_uri_t hello_uri = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = hello_html_get_handler,
    };
    // add handler for current device if is not a primary
    char uri[128];
    snprintf(uri, sizeof(uri), "/%s", desc->project_name);
    httpd_register_uri_handler(server, &hello_uri);
    httpd_uri_t device_uri = {
        .uri = uri,
        .method = HTTP_GET,
        .handler = hello_html_get_handler};
    httpd_register_uri_handler(server, &device_uri);

    ESP_LOGI(TAG, "Server started");
}

#ifdef __cplusplus
extern "C"
{
#endif

    void app_main(void)
    {
        setup();
        vTaskDelete(NULL);
    }

#ifdef __cplusplus
}
#endif