#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_netif.h"
#include "esp_crt_bundle.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_http_client.h"
#include "cJSON.h"
#include "driver/gpio.h"
#include "esp_sntp.h"
#include <time.h>
#include <sys/time.h>
#include "esp_http_server.h"
#include <ctype.h>
#include "esp_timer.h"

#define LED_GPIO GPIO_NUM_2
#define WIFI_RETRY_MAX 10
#define AUTH_RETRY_MAX 5

#define DEFAULT_AP_SSID "ESP32_Setup"
#define DEFAULT_AP_PASS "12345678"
#define WIFI_SSID_MAX_LEN 32
#define WIFI_PASS_MAX_LEN 64
#define USER_MAX_LEN 32
#define PASS_MAX_LEN 64

static char auth_token[512] = {0};
static const char *TAG = "ESP32_SSL";

static char wifi_ssid[WIFI_SSID_MAX_LEN] = {0};
static char wifi_pass[WIFI_PASS_MAX_LEN] = {0};
static char api_user[USER_MAX_LEN] = {0};
static char api_pass[PASS_MAX_LEN] = {0};
static char auth_url[1024] = {0};
static char switch_url[1024] = {0};
static char switch_name[32] = {0};

extern const uint8_t server_cert_pem_start[] asm("_binary_cert_pem_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_cert_pem_end");

// Global buffer to store the response body
static char response_buffer[1024];
static int response_index = 0;

static EventGroupHandle_t wifi_event_group;
const int WIFI_CONNECTED_BIT = BIT0;
static int retry_num = 0;

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif


void esp_sntp_init(void);
void start_wifi_ap();
httpd_handle_t start_webserver(void);
//erase nvs
//#include "nvs_flash.h"
//#include "esp_wifi.h"

void clear_wifi_credentials() {
    nvs_flash_init();
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("storage", NVS_READWRITE, &nvs_handle);
    if (err == ESP_OK) {
        nvs_erase_all(nvs_handle);  // Wipe all keys in "wifi_config"
        nvs_commit(nvs_handle);
        nvs_close(nvs_handle);
    }

    // Optionally clear WiFi stack config
    esp_wifi_restore();
}

//
// Function to create a new switch via POST request
// HTTP event handler to capture server responses
esp_err_t http_event_handler_2(esp_http_client_event_t *evt) {
        
    switch (evt->event_id) {
        
        case HTTP_EVENT_ON_DATA:
            if (evt->data_len > 0) {
                strncpy(response_buffer, (char *)evt->data, evt->data_len);
                response_buffer[evt->data_len] = '\0';  // Ensure null termination
                ESP_LOGI(TAG, "Create Switches Response: %s", response_buffer);
            }
            break;
	    case HTTP_EVENT_ON_FINISH:
		ESP_LOGI(TAG, "Full Create switch Response: %s", response_buffer);
            break;
            default:
    		break;	    
	
    }
    return ESP_OK;
}
void create_switch() {
    ESP_LOGI(TAG, "Creating a switch...");
        //ESP_LOGE(TAG, "auth token in create_switch (): %s", auth_token);
    // Configure HTTP client
    char auth_header[600];
    snprintf(auth_header, sizeof(auth_header), "Bearer %s", auth_token);
    esp_http_client_config_t config = {
        .url = switch_url,
        .event_handler = http_event_handler_2,
        .method = HTTP_METHOD_POST,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };
	esp_http_client_handle_t client = esp_http_client_init(&config);
	//esp_http_client_set_header(client, "Content-Type", "application/json");

	char post_data[256]; // Buffer for JSON payload
	snprintf(post_data, sizeof(post_data), "{\"name\": \"%s\", \"state\": \"false\"}", switch_name);
	esp_http_client_set_post_field(client, post_data, strlen(post_data));


    esp_http_client_set_header(client, "Authorization", auth_header);
    esp_http_client_set_header(client, "Content-Type", "application/json");

    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {
        int status_code = esp_http_client_get_status_code(client);
        char response[300];
        esp_http_client_read_response(client, response, sizeof(response));

        if (status_code == 200 && strstr(response, "[]")) {
            ESP_LOGW(TAG, "No switch found. Creating new one...");

            // Set method to POST and update request
            esp_http_client_set_method(client, HTTP_METHOD_POST);
            char post_data[200];
            //static const char *switch_name = "switch_1";
            //snprintf(post_data, sizeof(post_data), "{\"name\": \"%s\", \"state\": false}",switch_name);
            esp_http_client_set_post_field(client, post_data, strlen(post_data));

            // Perform the request
            esp_err_t err2 = esp_http_client_perform(client);

            if (err2 == ESP_OK) {
                ESP_LOGI(TAG, "Switch created successfully!");
        	//fetch_switch_state();//
            } else {
                ESP_LOGE(TAG, "Failed to create switch: %s", esp_err_to_name(err2));
            }
        }
    } else {
        ESP_LOGE(TAG, "Failed to fetch switches: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
}

// ********** NVS Storage for JWT **********
/*
void save_token_to_nvs(const char *token) {
    nvs_handle_t nvs_handle;
    ESP_ERROR_CHECK(nvs_open("storage", NVS_READWRITE, &nvs_handle));
    ESP_ERROR_CHECK(nvs_set_str(nvs_handle, "auth_token", token));
    ESP_ERROR_CHECK(nvs_commit(nvs_handle));
    nvs_close(nvs_handle);
}

void load_token_from_nvs() {
    nvs_handle_t nvs_handle;
    ESP_ERROR_CHECK(nvs_open("storage", NVS_READONLY, &nvs_handle));
    size_t token_len = sizeof(auth_token);
    //nvs_get_str(nvs_handle,"auth_token",auth_token,&token_len);
    //ESP_LOGI(TAG, "Loaded JWT Token from NVS: %s", auth_token);
    
    if (nvs_get_str(nvs_handle, "auth_token", auth_token, &token_len) == ESP_OK) {
        ESP_LOGI(TAG, "Loaded JWT Token from NVS: %s", auth_token);
    }
    
    nvs_close(nvs_handle);
}
*/
//wifi eventhandler
static void event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (retry_num < WIFI_RETRY_MAX) {
            retry_num++;
            ESP_LOGW("WIFI", "Retrying connection... Attempt %d/%d", retry_num, WIFI_RETRY_MAX);
            esp_wifi_connect();
        } else {
            ESP_LOGE("WIFI", "Wi-Fi connection failed! Restarting ESP32...");
            esp_restart();
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
	ESP_LOGI("WIFI", "SSID: %s, Password Length: %d", wifi_ssid, strlen(wifi_pass));
        ESP_LOGI("WIFI", "Connected! IP Address: " IPSTR, IP2STR(&event->ip_info.ip));
        retry_num = 0;
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

// ********** Initialize Wi-Fi **********

void wifi_init() {
    ESP_LOGI(TAG, "Initializing Wi-Fi...");
    wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, NULL));

    wifi_config_t wifi_config = {};  // Zero out the structure

    // Copy stored Wi-Fi credentials
    strncpy((char *)wifi_config.sta.ssid, wifi_ssid, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char *)wifi_config.sta.password, wifi_pass, sizeof(wifi_config.sta.password) - 1);

    // Set authentication mode based on password presence
    wifi_config.sta.threshold.authmode = (strlen(wifi_pass) == 0) ? WIFI_AUTH_OPEN : WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
 
    ESP_LOGI(TAG, "Wi-Fi setup complete. Waiting for connection...");
    ESP_LOGI("WIFI", "SSID: %s, Password Length: %d", wifi_ssid, strlen(wifi_pass));
    xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY);
}

//auth eventhandler 
esp_err_t _http_event_handler(esp_http_client_event_t *evt) {
   
    switch (evt->event_id) {
        case HTTP_EVENT_ON_DATA:
            if (response_index + evt->data_len < sizeof(response_buffer)) {
                memcpy(response_buffer + response_index, evt->data, evt->data_len);
                response_index += evt->data_len;
                response_buffer[response_index] = '\0';  // Null-terminate the response
            }
            break;

        case HTTP_EVENT_ON_FINISH:
            ESP_LOGI(TAG, "Full Auth Response: %s", response_buffer);
            cJSON *json = cJSON_Parse(response_buffer);
            if (json) {
                cJSON *access = cJSON_GetObjectItem(json, "access");
                if (cJSON_IsString(access)) {
                    strncpy(auth_token, access->valuestring, sizeof(auth_token) - 1);
                    ESP_LOGI(TAG, "saving Auth Token: %s", auth_token);
		    //save_token_to_nvs(auth_token);  // Save token to NVS
                } else {
                    //ESP_LOGE(TAG, "Error: Access token not found in response");
                }
                cJSON_Delete(json);

            } else {
                //ESP_LOGE(TAG, "Error: Failed to parse JSON");
            }
            response_index = 0;  // Reset buffer index for next request
            break;

        default:
            break;
    }
    return ESP_OK;
}

//get auth token

void get_auth_token() {
    esp_http_client_config_t config = {
        .url = auth_url,
        .event_handler = _http_event_handler,
        .method = HTTP_METHOD_POST,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 10000,  // Increase timeout to 10 seconds
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_http_client_set_header(client, "Content-Type", "application/json");

    char post_data[256]; // Buffer for JSON payload
    snprintf(post_data, sizeof(post_data), "{\"username\": \"%s\", \"password\": \"%s\"}", api_user, api_pass);
    esp_http_client_set_post_field(client, post_data, strlen(post_data));

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Authentication succesful ...");
    } else {
        ESP_LOGI(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
    }
    
    esp_http_client_cleanup(client);
}

// HTTP event handler to collect response data
esp_err_t _http_event_handler_1(esp_http_client_event_t *evt) {
    switch (evt->event_id) {
        case HTTP_EVENT_ON_DATA:
            // Append the received data to the response buffer
            if (response_index + evt->data_len < sizeof(response_buffer)) {
                memcpy(response_buffer + response_index, evt->data, evt->data_len);
                response_index += evt->data_len;
                response_buffer[response_index] = '\0';  // Null-terminate the buffer
            }
            break;

        case HTTP_EVENT_ON_FINISH:
            // Log the full response
            ESP_LOGI(TAG, "Full Response: %s", response_buffer);
        // Parse the JSON response
        cJSON *json = cJSON_Parse(response_buffer);
	//
		//Create new if not found working
	
        if (cJSON_IsArray(json) && cJSON_GetArraySize(json) == 0) {
            ESP_LOGW(TAG, "No switches found. Creating a new one...");
            create_switch();
	    }
	//
        if (json) {
            // Check if the response is an array
            if (cJSON_IsArray(json)) {
                // Get the first object in the array
		// how to get id ?
                cJSON *first_item = cJSON_GetArrayItem(json, 0);
		//get id before state
		//if 
                if (first_item) {
                    // Extract the "state" field
                    cJSON *state = cJSON_GetObjectItem(first_item, "state");
                    if (cJSON_IsBool(state)) {
                        bool switch_state = cJSON_IsTrue(state);
                        gpio_set_level(LED_GPIO, switch_state);
                        ESP_LOGI(TAG, "Switch state: %d, LED: %s", switch_state, switch_state ? "ON" : "OFF");

                    }
		   }
	    }
	}
            break;

        default:
            break;
    }
    return ESP_OK;
}

void fetch_switch_state() {
    char auth_header[600];
    snprintf(auth_header, sizeof(auth_header), "Bearer %s", auth_token);

    esp_http_client_config_t config = {
        .url = switch_url,
        .event_handler = _http_event_handler_1,
        .method = HTTP_METHOD_GET,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };

    // Initialize the response buffer
    memset(response_buffer, 0, sizeof(response_buffer));
    response_index = 0;

    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_http_client_set_header(client, "Authorization", auth_header);
    esp_http_client_set_header(client, "Content-Type", "application/json");

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
                ESP_LOGI(TAG, "switch OK");
		//
		//BOOT button to AP
		//
    } else {
        ESP_LOGI(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
	//reboot
         esp_restart();
	
    }
  
    esp_http_client_cleanup(client);
}

// Task to continuously fetch switch state
void switch_task(void *pvParameters) {
    while (1) {
    fetch_switch_state();
    }
}
/*
void switch_task(void *pvParameters) {
    
	while (1) {
    		uint32_t val;
    		if (xTaskNotifyWait(0x00, 0x00, &val, pdMS_TO_TICKS(10 * 1000))) {
        		ESP_LOGI(TAG, "BOOT button pressed - entering AP mode");

        		esp_wifi_stop();
        		esp_wifi_deinit();
        		start_wifi_ap();
        		start_webserver();
    }

    // your regular loop logic here...
    fetch_switch_state();
  }
}
*/ 

// Stored Configurations

// Function to save config to NVS
void save_config_to_nvs(const char *api_user, const char *api_pass,const char *wifi_ssid,const char *wifi_pass,const char *auth_url,const char *switch_url,const char *switch_name) {
//void save_config_to_nvs() {
   nvs_handle_t nvs_handle;
   if (nvs_open("storage", NVS_READWRITE, &nvs_handle) == ESP_OK) {
        nvs_set_str(nvs_handle, "wifi_ssid", wifi_ssid);
        nvs_set_str(nvs_handle, "wifi_pass", wifi_pass);
        nvs_set_str(nvs_handle, "api_user", api_user);
        nvs_set_str(nvs_handle, "api_pass", api_pass);
        nvs_set_str(nvs_handle, "auth_url", auth_url);
        nvs_set_str(nvs_handle, "switch_url", switch_url);
	nvs_set_str(nvs_handle, "switch_name", switch_name);
        nvs_commit(nvs_handle);
        nvs_close(nvs_handle);
    }
}

// Function to load config from NVS
void load_config_from_nvs() {
    nvs_handle_t nvs_handle;
    size_t len;
    if (nvs_open("storage", NVS_READONLY, &nvs_handle) == ESP_OK) {
        len = sizeof(wifi_ssid); nvs_get_str(nvs_handle, "wifi_ssid", wifi_ssid, &len);
        len = sizeof(wifi_pass); nvs_get_str(nvs_handle, "wifi_pass", wifi_pass, &len);
        len = sizeof(api_user); nvs_get_str(nvs_handle, "api_user", api_user, &len);
        len = sizeof(api_pass); nvs_get_str(nvs_handle, "api_pass", api_pass, &len);
        len = sizeof(auth_url); nvs_get_str(nvs_handle, "auth_url", auth_url, &len);
        len = sizeof(switch_url); nvs_get_str(nvs_handle, "switch_url", switch_url, &len);
	len = sizeof(switch_name); nvs_get_str(nvs_handle, "switch_name", switch_name, &len);
        nvs_close(nvs_handle);
    }
}

// Function to wait for time synchronization
void obtain_time(void) {
    ESP_LOGI(TAG, "Initializing SNTP...");

    // Configure NTP
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    //sntp_setoperatingmode();
    esp_sntp_setservername(0, "pool.ntp.org"); // Set NTP server
    esp_sntp_init();

    // Wait until time is set
    time_t now = 0;
    struct tm timeinfo = { 0 };
    int retry = 0;
    const int max_retries = 10;

    while (timeinfo.tm_year < (2024 - 1900) && ++retry < max_retries) {
        ESP_LOGI(TAG, "Waiting for system time to be set... (%d/%d)", retry, max_retries);
        vTaskDelay(2000 / portTICK_PERIOD_MS); // Wait 2 seconds
        time(&now);
        localtime_r(&now, &timeinfo);
    }

    if (retry == max_retries) {
        ESP_LOGE(TAG, "Failed to get NTP time!");
    } else {
        ESP_LOGI(TAG, "Time synchronized: %s", asctime(&timeinfo));
    }
}


// Function to verify system time before SSL request
void verify_time() {
    time_t now;
    struct tm timeinfo;
    time(&now);
    localtime_r(&now, &timeinfo);

    if (timeinfo.tm_year < (2024 - 1900)) {
        ESP_LOGW(TAG, "Time not set! Syncing with NTP...");
        obtain_time();
    } else {
        ESP_LOGI(TAG, "System time is valid: %s", asctime(&timeinfo));
    }
}

//http interface to get the configuration
//
//start wifi AP

#define AP_SSID "ESP32_Setup"
#define AP_PASS "12345678"

void start_wifi_ap() {
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    wifi_config_t wifi_config = {
        .ap = {
            .ssid = AP_SSID,
            .ssid_len = strlen(AP_SSID),
            .password = AP_PASS,
            .max_connection = 4,
            .authmode = WIFI_AUTH_WPA_WPA2_PSK
        },
    };

    if (strlen(AP_PASS) == 0) {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_set_config(WIFI_IF_AP, &wifi_config);
    esp_wifi_start();

    ESP_LOGI("WiFi", "Started Wi-Fi AP: %s", AP_SSID);
}

//
//

// --- Move these outside any other function ---
static int from_hex(char c) {
    return isdigit((unsigned char)c) ? c - '0' : tolower((unsigned char)c) - 'a' + 10;
}

void url_decode(char *str) {
    char *p = str;
    while (*str) {
        if (*str == '%') {
            if (str[1] && str[2]) {
                *p++ = (char)(from_hex(str[1]) << 4 | from_hex(str[2]));
                str += 3;
            }
        } else if (*str == '+') {
            *p++ = ' ';
            str++;
        } else {
            *p++ = *str++;
        }
    }
    *p = '\0';
}

//get
static esp_err_t setup_page_get_handler(httpd_req_t *req) {

const char *html = 
"<html><body>"
"<!DOCTYPE html>"
"<html lang='en'>"
"<head>"
  "<meta charset='UTF-8'>"
  "<title>ESP32 Setup</title>"
  "<style>"
    "body {"
      "font-family: sans-serif;"
      "display: flex;"
      "justify-content: center;"
      "align-items: center;"
      "height: 100vh;"
      "background: #f4f4f4;"
    "}"
    "form {"
      "background: white;"
      "padding: 2rem;"
      "border-radius: 8px;"
      "box-shadow: 0 4px 10px rgba(0,0,0,0.1);"
      "width: 300px;"
    "}"
    "input {"
      "width: 100%;"
      "margin: 0.5rem 0;"
      "padding: 0.5rem;"
    "}"
    "button {"
      "padding: 0.5rem;"
      "width: 100%;"
      "background: #007bff;"
      "color: white;"
      "border: none;"
      "border-radius: 4px;"
    "}"
  "</style>"
"</head>"
"<body>"
  "<form method='POST' action='/setup'>"
    "<h2>Device Setup</h2>"
    "<input type='text' name='api_user' placeholder='api_user' required/>"
    "<input type='password' name='api_pass' placeholder='api_pass' required/>"
    "<input type='text' name='wifi_ssid' placeholder='wifi ssid' required />"
    "<input type='password' name='wifi_pass' placeholder='wifi Password' required />"
    "<input type='text' name='auth_url' placeholder='auth url' required />"
    "<input type='text' name='switch_url' placeholder='switch url' />"
    "<input type='text' name='switch_name' placeholder='switch name' />"
    "<button type='submit'>Save & Connect</button>"
  "</form>"
"</body>"
"</html>";
    
    httpd_resp_send(req, html, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

//post
esp_err_t setup_page_post_handler(httpd_req_t *req) {
    char buf[256];
    int ret = httpd_req_recv(req, buf, MIN(req->content_len, sizeof(buf)-1));
    if (ret <= 0) {
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    // Decode the URL-encoded form data
   
    url_decode(buf);  
    //retrive  
    httpd_query_key_value(buf, "api_pass", api_pass, sizeof(api_pass));
    httpd_query_key_value(buf, "api_user", api_user, sizeof(api_user));
    httpd_query_key_value(buf, "api_pass", api_pass, sizeof(api_pass));
    httpd_query_key_value(buf, "wifi_ssid", wifi_ssid, sizeof(wifi_ssid));
    httpd_query_key_value(buf, "wifi_pass", wifi_pass, sizeof(wifi_pass));
    httpd_query_key_value(buf, "auth_url", auth_url, sizeof(auth_url));
    httpd_query_key_value(buf, "switch_url", switch_url, sizeof(switch_url));
    httpd_query_key_value(buf, "switch_name", switch_name, sizeof(switch_name));
    //verify
   
    //save to nvs
    save_config_to_nvs(api_user, api_pass,wifi_ssid,wifi_pass,auth_url,switch_url,switch_name);
    
    httpd_resp_send(req, "Settings saved successfully...", HTTPD_RESP_USE_STRLEN);
    ESP_LOGI(TAG, "Settings saved successfully...");
    
    vTaskDelay(1000 / portTICK_PERIOD_MS);
    esp_restart();
   
    return ESP_OK;
}

//server

httpd_handle_t start_webserver(void) {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();

    httpd_handle_t server = NULL;
    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_uri_t setup_get_uri = {
            .uri       = "/setup",
            .method    = HTTP_GET,
            .handler   = setup_page_get_handler,
            .user_ctx  = NULL
        };
        httpd_register_uri_handler(server, &setup_get_uri);

        httpd_uri_t setup_post_uri = {
            .uri       = "/setup",
            .method    = HTTP_POST,
            .handler   = setup_page_post_handler,
            .user_ctx  = NULL
        };
        httpd_register_uri_handler(server, &setup_post_uri);
    }

    return server;
}

//http interface to get config
//BOOT (GPIO0) – this one is perfect for use as a manual AP reset trigger!
//GPIO0 is the BOOT button, which:
//Is a regular GPIO (when not used for flashing)
//Has a pull-up resistor by default
//Is already debounced by hardware
//Step 1: Define BOOT pin and ISR
//reset button task
/*
#define RESET_BUTTON_GPIO 0
#define RESET_BUTTON_DEBOUNCE_MS 50
#define RESET_BUTTON_HOLD_TIME_MS 2000

void reset_button_task(void *pvParameter)
{
    gpio_config_t btn_config = {
        .pin_bit_mask = 1ULL << RESET_BUTTON_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };
    gpio_config(&btn_config);

    bool btn_pressed = false;
    int64_t press_start = 0;

    while (1) {
        int level = gpio_get_level(RESET_BUTTON_GPIO);

        if (level == 0 && !btn_pressed) {
            // Button just pressed
            btn_pressed = true;
            press_start = esp_timer_get_time() / 1000; // in ms
        } else if (level == 1 && btn_pressed) {
            // Button released
            int64_t press_duration = (esp_timer_get_time() / 1000) - press_start;
            btn_pressed = false;

            if (press_duration >= RESET_BUTTON_HOLD_TIME_MS) {
                ESP_LOGW("RESET_BTN", "Long press detected. Starting fallback AP...");

                esp_wifi_stop();
                esp_wifi_deinit();
		start_wifi_ap();
		start_webserver();
 clear_wifi_credentials();
                //AP mode config logic here
            } else {
                ESP_LOGI("RESET_BTN", "Short press ignored");
            }
        }

        vTaskDelay(pdMS_TO_TICKS(RESET_BUTTON_DEBOUNCE_MS));
    }
}
*/
#define BUTTON_GPIO GPIO_NUM_0  // Boot button on ESP32 DevKit V4

void button_task(void *pvParameters) {
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << BUTTON_GPIO),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,  // Pull-up needed for BOOT button
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };
    gpio_config(&io_conf);

    int button_pressed = 0;
    int64_t press_start = 0;

    while (1) {
        int level = gpio_get_level(BUTTON_GPIO);
        if (level == 0 && !button_pressed) {
            button_pressed = 1;
            press_start = esp_timer_get_time() / 1000; // ms
            printf("Button pressed!\n");
        } else if (level == 1 && button_pressed) {
            button_pressed = 0;
            int64_t press_duration = (esp_timer_get_time() / 1000) - press_start;
            printf("Button released. Duration: %lld ms\n", press_duration);
            clear_wifi_credentials();
                esp_wifi_stop();
                esp_wifi_deinit();
            esp_restart();
		//start_wifi_ap();
		//start_webserver();
        }

        vTaskDelay(pdMS_TO_TICKS(50));  // debounce
    }
}

//
//main

void app_main(void) {
   nvs_flash_init();
   load_config_from_nvs();
   
    ESP_LOGI(TAG,"api_user : %s",api_user);
    ESP_LOGI(TAG,"api_pass : %s",api_pass);
    ESP_LOGI(TAG,"wifi_ssid : %s",wifi_ssid);
    ESP_LOGI(TAG,"widi_pass : %s",wifi_pass);
    ESP_LOGI(TAG,"auth_url : %s",auth_url);
    ESP_LOGI(TAG,"switch_url : %s",switch_url);
    ESP_LOGI(TAG,"switch_name : %s",switch_name);
    //clear_wifi_credentials();//
    //ESP_LOGI(TAG,"old config cleared...");
    //if (strlen(api_user) == 0 && strlen(api_pass) == 0 && strlen(wifi_ssid) == 0 && strlen(wifi_pass) == 0 && strlen(auth_url) == 0 && strlen(switch_url) == 0 && strlen(switch_name) == 0) {
    if (strlen(api_user) == 0 || strlen(api_pass) == 0 || strlen(wifi_ssid) == 0 || strlen(wifi_pass) == 0 || strlen(auth_url) == 0 || strlen(switch_url) == 0 || strlen(switch_name) == 0) {
        start_wifi_ap();
        start_webserver();
    
    } else {

        wifi_init();  // Connect to stored Wi-Fi

	verify_time();
	get_auth_token();
        gpio_set_direction(LED_GPIO, GPIO_MODE_OUTPUT);
        xTaskCreate(&switch_task, "switch_task", 8192, NULL, 5, NULL);
	//xTaskCreate(reset_button_task, "reset_button_task", 2048, NULL, 5, NULL);
	xTaskCreate(button_task, "button_task", 2048, NULL, 5, NULL);
        }
}


