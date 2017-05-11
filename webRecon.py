import argparse, time, sys, os, subprocess
# TODO integrate KEWL

class webRecon(object):
    def __init__(self):
        self.parseArgs()
        self.site = "%s://%s:%s" % (self.protocol, self.host, self.port)

        self.nmapScripts(self.host, self.port)
        self.vulnScan(self.host, self.port)
        self.goBuster(self.host, self.port)
        #self.dirBust(self.host, self.port)

    def parseArgs(self):
        parser = argparse.ArgumentParser(prog='webEnumerator', add_help=True)
        parser.add_argument('host', help='host to scan')
        parser.add_argument('port', help='port to scan')
        parser.add_argument('protocol', help='web protocol')
        parser.add_argument('userList', help='users to use in bruteforce')
        parser.add_argument('passList', help='passwords to use in bruteforce')
        args = parser.parse_args()
        self.host = args.host
        self.port = args.port
        self.protocol = args.protocol
        self.userList = args.userList
        self.passList = args.passList

    def nmapScripts(self, ip_address, port):
        print "INFO: Performing nmap web script scan for " + ip_address + ":" + port
        webSCAN = "nmap -sV -Pn -vv -p %s --script='(http* or ssl*) and not (broadcast or dos or external or http-slowloris* or fuzzer)' -oN pillageResults/%s_%s_%s.nmap %s" % (
        port, ip_address, self.protocol, port, ip_address)
        print webSCAN
        subprocess.check_output(webSCAN, shell=True)


    def goBuster(self, ip_address, port):
        found = []
        folders = ["/usr/share/dirb/wordlists", "/usr/share/dirb/wordlists/vulns"]
        print "INFO: Starting gobuster scan for %s:%s " % (ip_address, port)

        allFiles = []
        #for folder in folders:
        #    for filename in os.listdir(folder):
        #        allFiles.append(folder + '/' + filename)
        #allFiles.append("/usr/share/wordlists/dirb/directory-list-2.3-medium.txt")
        allFiles.append("/usr/share/wordlists/dirb/common.txt")
        #gobuster - w / usr / share / wordlists / dirb / common.txt - u $ip
        for filename in allFiles:
            GOBUSTERSCAN = "gobuster -u %s -w %s -t 50 -U username -P password >> pillageResults/%s_gobuster_%s.txt" % (self.site, filename, ip_address, port)
            print GOBUSTERSCAN
            try:
                results = subprocess.check_output(GOBUSTERSCAN, shell=True)
                resultarr = results.split("\n")
                for line in resultarr:
                    if "/" in line:
                        if line not in found:
                            found.append(line)
            except:
                pass

        try:
            if found[0] != "":
                print "[*] GoBuster found the following items..."
                for item in found:
                    print "   " + item
        except:
            print "INFO: No items found during GoBuster scan of " + ip_address


    def dirBust(self, ip_address, port):
        found = []
        folders = ["/usr/share/dirb/wordlists", "/usr/share/dirb/wordlists/vulns"]
        print "INFO: Starting dirb scan for %s:%s " % (ip_address, port)

        allFiles = []
        for folder in folders:
            for filename in os.listdir(folder):
                allFiles.append(folder + '/' + filename)
        # allFiles.append("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")

        for filename in allFiles:
            DIRBSCAN = "dirb %s %s -S -w  >> pillageResults/%s_dirb_%s.txt" % (self.site, filename, ip_address, port)
            print DIRBSCAN
            try:
                results = subprocess.check_output(DIRBSCAN, shell=True)
                resultarr = results.split("\n")
                for line in resultarr:
                    if "+" in line:
                        if line not in found:
                            found.append(line)
            except:
                pass

        try:
            if found[0] != "":
                print "[*] Dirb found the following items..."
                for item in found:
                    print "   " + item
        except:
            print "INFO: No items found during dirb scan of " + ip_address


    def vulnScan(self, ip_address, port):
        print "INFO: Performing Nikto Scan on " + ip_address + ":" + port
        niktoScan = "nikto -nointeractive -host %s -p %s >> pillageResults/%s_%snikto_%s.txt -C all" % (
        ip_address, port, ip_address, self.protocol, port)
        print niktoScan
        subprocess.check_output(niktoScan, shell=True)


if __name__ == "__main__":
    web = webRecon()
