import argparse, time, sys, os, subprocess

class rdpRecon(object):
    def __init__(self):
        self.parseArgs()
        self.nmapScripts(self.host,self.port)
        #self.bruteforce(self.host, self.port, self.userList, self.passList)

    def parseArgs(self):
        parser = argparse.ArgumentParser(prog='rdpEnumerator', add_help=True)
        parser.add_argument('host', help='host to scan')    
        parser.add_argument('port', help='port to scan')
        parser.add_argument('userList', help='users to use in bruteforce')
        parser.add_argument('passList', help='passwords to use in bruteforce')
        args = parser.parse_args()
        self.host=args.host
        self.port=args.port
        self.userList=args.userList
        self.passList=args.passList
        
    def nmapScripts(self, ip_address, port):
        print "INFO: Performing nmap rdp script scan for " + ip_address + ":" + port
        nmapSCAN = "nmap -sV -Pn -vv -p %s --script=rdp* -oN pillageResults/%s_rdp.nmap %s" % (port, ip_address, ip_address)
        subprocess.check_output(nmapSCAN, shell=True)

    def bruteforce(self, ip_address, port, userList, passList):
        print "INFO: Performing ncrack rdp scan against " + ip_address + ":" + port
        ncrackCmd = "ncrack -U %s -P %s -f -oN pillageResults/%s_rdpNcrack.txt %s:%s" % (userList, passList, ip_address, ip_address, port)
        try:
            results = subprocess.check_output(ncrackCmd, shell=True)
            resultarr = results.split("\n")
            foundString="%s %s/tcp rdp:" % (ip_address, port)
            for result in resultarr:
                if foundString in result:
                    print "[*] Valid rdp credentials found: " + result 
        except:
            print "INFO: No valid rdp credentials found"

if __name__ == "__main__":
    rdp = rdpRecon()
