__author__ = 'nkapashikov'
from scapy.all import *
import sqlite3

readHostSql = 'SELECT hostmac || ssid FROM hosts'
newHostSql = 'INSERT INTO hosts(hostmac,ssid,date) VALUES(?, ?, ?)'
updateHostSql = 'UPDATE hosts set date=? WHERE hostmac==? AND ssid==?'
exludedmacsFile = '/opt/exlude.txt'

# A function to read the excluded hosts. Those hosts will not be recorded in the host list file.

def dbConnect():
    global cursor
    global connection
    connection = sqlite3.connect('/opt/myCode/scapy.sqlite3')
    connection.row_factory = lambda cursor, row: row[0]
    cursor = connection.cursor()
    connection.text_factory = str

def readExcHosts(filename):
    global exludedmacs
    exfile = open(filename)
    exludedmacs = open(filename).read().splitlines()
    exfile.close()

# A function to read the current hosts stored in the file and them in a list. 
# This is also used as a very simple cache in memory. The list is seareched first before trying
# to insert in the database.

def readHosts():
    global currentHostListCache
    dbConnect()
    currentHostListCache = cursor.execute(readHostSql).fetchall()
    print('\n'.join('{}: {}'.format(*k) for k in enumerate(currentHostListCache)))
    connection.close()

# A fucntion to update the last seen time of host that is already in the currentHosList.

def updateLastTimeHostList(date, mac, ssid):
    dbConnect()
    cursor.execute(updateHostSql, (date, mac, ssid))
    connection.commit()
    connection.close()

# A function to write a host in currentHostList.

def writeNewHost(mac, ssid, date):
    dbConnect()
    cursor.execute(newHostSql, (mac, ssid, date))
    connection.commit()
    connection.close()

# Main logic

def findHosts(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        if pkt.addr2 not in exludedmacs and str(pkt.addr2) + str(pkt.info) not in currentHostListCache and pkt.info:
            writeNewHost(pkt.addr2, str(pkt.info), int(time.time()))
            readHosts()
        elif pkt.addr2 not in exludedmacs and str(pkt.addr2) + str(pkt.info) in currentHostListCache and pkt.info:
            updateLastTimeHostList(int(time.time()), pkt.addr2, str(pkt.info))

# Place the correct wlan interface below. 
			
def main():
    sniff(iface='wlx00xxxxxxxxxx', filter='', store=0, prn=findHosts)

if __name__=="__main__":
    readExcHosts(exludedmacsFile)
    readHosts()
    main()