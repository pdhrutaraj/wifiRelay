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

void esp_sntp_init(void);
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
                cJSON *first_item = cJSON_GetArrayItem(json, 0);
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

// HTTP Server Handler for Configuration Page
/*
esp_err_t config_handler(httpd_req_t *req) {
    char buf[512];
    int ret = httpd_req_recv(req, buf, sizeof(buf));
    if (ret > 0) {
        buf[ret] = '\0';
        sscanf(buf, "api_user=%63s&api_pass=%63s&wifi_ssid=%63s&wifi_pass=%63s&auth_url=%127s&switch_url=%127s", 
               api_user, api_pass, wifi_ssid, wifi_pass, auth_url, switch_url);
        save_config_to_nvs();
        httpd_resp_send(req, "Saved! Rebooting...", HTTPD_RESP_USE_STRLEN);
        vTaskDelay(pdMS_TO_TICKS(2000));
        esp_restart();
    }
    return ESP_OK;
}
*/

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
//main

void app_main(void) {
    nvs_flash_init();

    save_config_to_nvs("admin", "admin","Redmi Note 11S","Patientpay2015","https://eapi-vijn.onrender.com/api/token/","https://eapi-vijn.onrender.com/api/switches","switch_1");
    load_config_from_nvs();
    gpio_set_direction(LED_GPIO, GPIO_MODE_OUTPUT);
    wifi_init();
    //load_token_from_nvs();
    // Verify system time and sync if needed
    verify_time();
    get_auth_token();
    //if (strlen(auth_token) == 0) get_auth_token();
    
    xTaskCreate(&switch_task, "switch_task", 8192, NULL, 5, NULL);
   }


