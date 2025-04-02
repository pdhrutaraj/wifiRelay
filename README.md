🌟 How it Works
First boot (or if no credentials are stored)
ESP32 starts as an Access Point (AP)
Serves a Web Form at 192.168.4.1 for user input
User enters Wi-Fi & API credentials
ESP32 stores them in NVS (non-volatile storage)
Reboots and connects to Wi-Fi
If Wi-Fi fails
Starts AP mode again for reconfiguration
🔥 Usage
Flash the firmware to ESP32
Connect to "ESP32_Setup" Wi-Fi (Password: 12345678)
Go to http://192.168.4.1 in a browser
Enter Wi-Fi & API credentials and click "Save"
ESP32 reboots and connects to Wi-Fi & API
🚀 Now, ESP32 dynamically connects to Wi-Fi & API based on user input!
