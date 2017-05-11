import argparse, time, sys, os, subprocess

class ftpRecon(object):
    def __init__(self):
        self.parseArgs()
        self.nmapScripts(self.host, self.port)
        #self.bruteforce(self.host, self.port, self.userList, self.passList)

    def parseArgs(self):
	parser = argparse.ArgumentParser(prog='ftpEnumerator', add_help=True)
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
        print "INFO: Performing nmap FTP script scan for " + ip_address + ":" + port
        FTPSCAN = "nmap -sV -Pn -vv -p %s --script=ftp* -oN 'pillageResults/%s_ftp.nmap' %s" % (port, ip_address, ip_address)
        results = subprocess.check_output(FTPSCAN, shell=True)

    def bruteforce(self, ip_address, port, userList, passList):
        print "INFO: Performing hydra ftp scan against " + ip_address 
        hydraCmd = "hydra -L %s -P %s -f -o pillageResults/%s_ftphydra.txt -u %s -s %s ftp" % (userList, passList, ip_address, ip_address, port)
        try:
            results = subprocess.check_output(hydraCmd, shell=True)
            resultarr = results.split("\n")
            for result in resultarr:
                if "login:" in result:
                    print "[*] Valid ftp credentials found: " + result 
        except:
            print "INFO: No valid ftp credentials found"

if __name__ == "__main__":
    ftp = ftpRecon()
