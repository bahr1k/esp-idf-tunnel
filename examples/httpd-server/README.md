# esp-idf-tunnel

**esp-idf-tunnel** is an ESP-IDF component that allows your ESP32 to establish an outbound, secure WebSocket tunnel to a remote service, enabling HTTPS access to your device from anywhere without port forwarding or a static IP. You can register any domain (including free subdomains from providers like No-IP or ClouDNS) or use your own custom domain and configure it in one place.

## Features

- 📡 Remote HTTPS access to ESP32 behind NAT/firewalls  
- 🔐 Secure WebSocket-based tunneling  
- 🌍 No port forwarding or public IP required  
- ⚙️ Easy integration via `idf_component.yml` (or as a standalone clone)  
- 🔧 All tunnel parameters (domain, secret, etc.) can be set in the config  

## How It Works

1. **ESP32** opens a persistent WebSocket connection to a tunnel service endpoint (hosted under your domain).  
2. The **tunnel service** accepts incoming HTTPS requests for your domain and forwards them over the WebSocket to your ESP32.  
3. ESP32 handles each request locally (for example, serving pages, reading sensors, toggling GPIOs) and returns a response back through the tunnel.  

## Quick Start

### 1. Pick/Register a Domain
- You can use **any** domain or subdomain.  
- If you need a free subdomain, try services like **No-IP** or **ClouDNS**.  
- Add your domain to the https://device-tunnel.top/ service.

### 2. Add the Component to Your ESP-IDF Project

**Option A: Git-based dependency**  
In your project's top-level `idf_component.yml`, add:
```yaml
dependencies:
  esp-idf-tunnel:
    git: https://github.com/bahr1k/esp-idf-tunnel
    version: "v0.3.2"
```

**Option B: Clone directly into components/**
```bash
cd <your-esp-idf-project>
mkdir -p components
cd components
git clone https://github.com/bahr1k/esp-idf-tunnel.git esp-idf-tunnel
cd esp-idf-tunnel
git checkout v0.3.2
```

### 3. Configure the Tunnel 

**Option A: In Code**  
Inside your application code (e.g., in `app_main()`), you only need to set up one struct—all other defaults come from `TUNNEL_DEFAULT_CONFIG()`:
```c
#include "tunnel.h"
// … (Wi-Fi setup, HTTP server init, etc.) …

// Setup tunnel
tunnel_config_t tunnel = TUNNEL_DEFAULT_CONFIG();
tunnel.domain = "myesp.mydomain.com";  // set your domain
tunnel.secret = "my_secret";           // set your tunnel service key here
tunnel.name   = desc->project_name;    // typically your project or device name

ESP_ERROR_CHECK(tunnel_init(&tunnel)); // run tunnel task
```

**Option B: In Menu Config**
- Find the Web Tunnel section in `idf.py menuconfig`
- Set your domain and secret options
- These values will automatically be applied to `TUNNEL_DEFAULT_CONFIG()`

## Accessing Multiple Devices Under One Domain

If you host multiple ESP32 devices behind the same tunnel service, you can route by path. For example:
- Device A uses `domain = "mygroup.example.com"`, `name = "deviceA"`
- Device B uses the same domain, `name = "deviceB"`

Then clients can access:
```
https://mygroup.example.com/deviceA/...
https://mygroup.example.com/deviceB/...
```

The tunnel service will route based on the name prefix. By default, it will route to the device that is set as primary on the service.

## Requirements

- ESP-IDF 5.0 or higher
- Internet access (STA mode) for your ESP32
- A registered domain (or subdomain) pointing to a compatible tunnel service

## Configuration Reference

The `tunnel_config_t` structure provides the following configuration options:

```c
typedef struct {
    const char *domain;           // Your tunnel domain (required)
    const char *secret;           // Tunnel service authentication key (required)
    const char *name;             // Device name for routing (optional)
    const char *client_cert;      // Client certificate for mutual TLS (optional)
    const char *client_key;       // Client private key for mutual TLS (optional)
    int32_t reconnect_timeout_ms; // Reconnect timeout in milliseconds (0 to disable auto-reconnect)
    size_t rx_buffer_size;        // WebSocket receive buffer size in bytes
    size_t tx_buffer_size;        // WebSocket transmit buffer size in bytes
    tunnel_rx_func_t *rx_func;    // Custom function for receiving data (used when local server proxy is disabled)
    tunnel_tx_func_t *tx_func;    // Custom function for sending data (used when local server proxy is disabled)
    uint16_t local_port;          // Local HTTP server port (0 = disabled, requires custom rx/tx functions)
    uint8_t auto_eof;             // Automatically send EOF markers in responses (1 = enabled, 0 = disabled)
    uint8_t is_public;            // Access control (0 = private with service authorization, 1 = public access)
    uint8_t non_block;            // WebSocket mode (0 = blocking, 1 = non-blocking)
} tunnel_config_t;
```

### Configuration Details

**Required Parameters:**
- `domain`: The domain name that will route to your ESP32
- `secret`: Authentication key provided by your tunnel service

**Optional Parameters:**
- `name`: Device identifier for multi-device routing under one domain
- `client_cert`/`client_key`: For mutual TLS authentication with the tunnel service
- `reconnect_timeout_ms`: How long to wait before attempting reconnection (default: auto-reconnect enabled)
- `rx_buffer_size`/`tx_buffer_size`: WebSocket buffer sizes for performance tuning
- `local_port`: Port of your local HTTP server (set to 0 for custom handling)
- `auto_eof`: Controls automatic EOF marker insertion in HTTP responses
- `is_public`: Whether the tunnel requires service-level authorization
- `non_block`: Socket blocking behavior

**Custom Functions:**
When `local_port` is set to 0, you must provide custom `rx_func` and `tx_func` implementations to handle incoming requests and outgoing responses manually.

## License

MIT

## Contributing / Feedback

If you find a bug, have a feature request, or want to contribute, please file an issue or submit a PR on the GitHub repo.
