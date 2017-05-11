import argparse, time, sys, os, subprocess

class snmpRecon(object):
    def __init__(self):
        self.parseArgs()
        self.paramStrings=['1.3.6.1.2.1.25.1.6.0', '1.3.6.1.2.1.25.4.2.1.2', '1.3.6.1.2.1.25.4.2.1.4', '1.3.6.1.2.1.25.2.3.1.4', '1.3.6.1.2.1.25.6.3.1.2', '1.3.6.1.4.1.77.1.2.25', '1.3.6.1.2.1.6.13.1.3']
        self.communityList="wordlists/community.txt"
        self.nmapScripts(self.host, self.port)
        self.onesixtyoneScan(self.host, self.port)
        self.snmpEnum(self.host, self.port)

    def parseArgs(self):
        parser = argparse.ArgumentParser(prog='snmpEnumerator', add_help=True)
        parser.add_argument('host', help='host to scan')    
        parser.add_argument('port', help='port to scan')
        args = parser.parse_args()
        self.host=args.host
        self.port=args.port

    def nmapScripts(self, ip_address, port):
        print "INFO: Performing nmap snmp script scan for " + ip_address + ":" + port
        nmapSCAN = "nmap -sV -Pn -vv -p %s --script=snmp* -oN pillageResults/%s_snmp.nmap %s" % (port, ip_address, ip_address)
        subprocess.check_output(nmapSCAN, shell=True)

    def onesixtyoneScan(self,ip_address,port):
        print "INFO: Performing OneSixtyOne snmp scan for " + ip_address + ":" + port
        oneSixtyOneSCAN="onesixtyone -c %s %s >> pillageResults/%s_161snmp.txt" % (self.communityList, ip_address, ip_address)
        subprocess.check_output(oneSixtyOneSCAN, shell=True)

    def snmpEnum (self, ip_address, port):
        print "INFO: Performing snmpwalk scan for " + ip_address + ":" + port
        for param in self.paramStrings:
            try:
                snmpWalkSCAN="snmpwalk -c public -v1 %s %s >> pillageResults/%s_snmpwalk.txt;" % (ip_address, param, ip_address)
                subprocess.check_output(snmpWalkSCAN, shell=True)
            except:
                pass

        print "INFO: Performing snmpcheck scan for " + ip_address + ":" + port
        try:
            snmpCheckSCAN="snmpcheck -t %s >> pillageResults/%s_snmpcheck.txt;" % (ip_address, ip_address)
            subprocess.check_output(snmpCheckSCAN, shell=True)
        except:
            pass
if __name__ == "__main__":
    snmp = snmpRecon()


