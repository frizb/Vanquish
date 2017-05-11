import argparse, time, sys, os, subprocess
#TODO: More testing!
class mySqlRecon(object):
    def __init__(self):
        self.parseArgs()
        self.nmapScripts(self.host, self.port)
        #self.bruteforce(self.host, self.port, self.userList, self.passList)
       
    def parseArgs(self):
        parser = argparse.ArgumentParser(prog='mySqlEnumerator', add_help=True)
        parser.add_argument('host', help='host to scan')    
        parser.add_argument('port', help='port to scan')
        parser.add_argument('userList', help='users to use in bruteforce')
        parser.add_argument('passList', help='passwords to use in bruteforce')
        args = parser.parse_args()
        self.host=args.host
        self.port=args.port
        self.userList=args.userList
        self.passList=args.passList
        self.username=None
        self.password=None
        
    def bruteforce(self, ip_address, port, userList, passList):
        print "INFO: Performing hydra mySql scan against " + ip_address 
        hydraCmd = "hydra -L %s -P %s -f -e n -o pillageResults/%s_mySqlhydra.txt -u %s -s %s mySql" % (userList, passList, ip_address, ip_address, port)
        creds={}
        try:
            results = subprocess.check_output(hydraCmd, shell=True)
            resultarr = results.split("\n")
            for result in resultarr:
                if "login:" in result:
                    print "[*] Valid mySql credentials found: " + result
                    resultList=result.split()
                    self.username=resultList[4]
                    if resultList[6]:
                        self.password=resultList[6]
                    else:
                        self.password=''
                    
        except:
            print "INFO: No valid mySql credentials found"

    def nmapScripts(self, ip_address, port):
        print "INFO: Performing nmap mySql script scan for " + ip_address + ":" + port
        mySqlSCAN = "nmap -vv -sV -sC -Pn -p %s --script=mysql* -oN 'pillageResults/%s_mySql.nmap' %s" % (port, ip_address, ip_address)
        results = subprocess.check_output(mySqlSCAN, shell=True)

if __name__ == "__main__":
    mySql = mySqlRecon()
