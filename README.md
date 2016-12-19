# WIFI STATION MONITOR

------

This will listen for all nearby WIFI station (client) *802.11 probe requests* and record in SQLite database  the MAC address of the client, the network for which it is probing and a timestamp.   

Usually the 802.11 probe requests method is used by WIFI clients to identify  all available access points (AP) that have the same SSID so they can roam. This is also known as active scanning. 

One use example can be identifying all clients connected to AP or just identifying nearby clients and getting a list of the SSIDs that they are probing for. 

This scan is completely passive and nothing is transmitted by the monitor.  It does not require to be connected to any network either. A WIFI adapter with a driver  that supports promiscuous mode is needed. The network adapter should be also configured with a valid WIFI channel. Any channel will work as the probes are usually  broadcasted to all channels. 

The code uses the python SCAPY library to filter 802.11 probe requests (Dot11ProbeReq) out of all captured network traffic. It also requires a  SQLite database:

```
CREATE TABLE "hosts" (
	`hostmac`	TEXT,
	`ssid`	TEXT,
	`date`	TEXT NOT NULL
);
```
