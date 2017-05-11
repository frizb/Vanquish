import argparse, time, sys, os, subprocess
#TODO: More testing!
class msSqlRecon(object):
    def __init__(self):
        self.parseArgs()
        #self.bruteforce(self.host, self.port, self.userList, self.passList)
        self.nmapScripts(self.host, self.port)

    def parseArgs(self):
        parser = argparse.ArgumentParser(prog='msSqlEnumerator', add_help=True)
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
        print "INFO: Performing hydra msSql scan against " + ip_address 
        hydraCmd = "hydra -L %s -P %s -f -e n -o pillageResults/%s_msSqlhydra.txt -u %s -s %s mssql" % (userList, passList, ip_address, ip_address, port)
        creds={}
        try:
            results = subprocess.check_output(hydraCmd, shell=True)
            resultarr = results.split("\n")
            for result in resultarr:
                if "login:" in result:
                    print "[*] Valid msSql credentials found: " + result
                    resultList=result.split()
                    self.username=resultList[4]
                    if resultList[6]:
                        self.password=resultList[6]
                    else:
                        self.password=''
                    
        except:
            print "INFO: No valid msSql credentials found"

    def nmapScripts(self, ip_address, port):
        print "INFO: Performing nmap msSql script scan for " + ip_address + ":" + port
        msSqlSCAN = "nmap -vv -sV -Pn -p %s --script=ms-sql* -oN 'pillageResults/%s_msSql.nmap' %s" % (port, ip_address, ip_address)
        results = subprocess.check_output(msSqlSCAN, shell=True)
        
        if self.username:
            msSqlSCAN2 = "nmap -vv -sV -Pn -p %s --script=ms-sql-config,ms-sql-dump-hashes,ms-sql-hasdbaccess,ms-sql-tables --script-args mssql.username=%s,mssql.password=%s -oN 'pillageResults/%s_msSql2.nmap' %s" % (port, self.username, self.password, ip_address, ip_address)
            #has xp-cmdshell
            results = subprocess.check_output(msSqlSCAN2, shell=True)
            

if __name__ == "__main__":
    msSql = msSqlRecon()
