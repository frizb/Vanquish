import argparse, time, sys, os, subprocess

class dnsRecon(object):
    def __init__(self):
        self.parseArgs()
        self.zoneTransfer(self.host, self.port)

    def parseArgs(self):
        parser = argparse.ArgumentParser(prog='dnsEnumerator', add_help=True)
        parser.add_argument('host', help='host to scan')    
        parser.add_argument('port', help='port to scan')
        args = parser.parse_args()
        self.host=args.host
        self.port=args.port

    def zoneTransfer(self, ip_address, port):
        hostnameCmd = "nmblookup -A %s | grep '<00>' | grep -v '<GROUP>' | cut -d' ' -f1" % (ip_address)# grab the hostname         
        hostname = subprocess.check_output(hostnameCmd, shell=True).strip()
        print "INFO: Attempting Domain Transfer on " + ip_address
        ztCmd = "dig @%s.thinc.local thinc.local -axfr >> pillageResults/%s_dnsZT.txt" % (hostname, ip_address)
        try:
            ztresults = subprocess.check_output(ztCmd, shell=True)
            if "failed" in ztresults:
                print "INFO: Zone Transfer failed for " + ip_address
            else:
                print "[*] Zone Transfer successful for " + ip_address
        except:
            print "Error: Zone Transfer failed for " + ip_address

if __name__ == "__main__":
    dns = dnsRecon()
