import argparse, time, sys, os, subprocess, socket

class smtpRecon(object):
    def __init__(self):
        self.parseArgs()
        self.dirPath = "pillageResults"
        self.nmapScripts(self.host, self.port)
        self.enumUsers(self.host, self.port)

    def parseArgs(self):
        parser = argparse.ArgumentParser(prog='smtpEnumerator', add_help=True)
        parser.add_argument('host', help='host to scan')    
        parser.add_argument('port', help='port to scan')
        parser.add_argument('userList', help='users to use in bruteforce')
        parser.add_argument('passList', help='passwords to use in bruteforce')
        args = parser.parse_args()
        self.host=args.host
        self.port=args.port
        self.userList=self.parseFile(args.userList)
        self.passList=args.passList

    def nmapScripts(self, ip_address, port):
        print "INFO: Performing nmap smtp script scan for " + ip_address + ":" + port
        #Nmap also has psExec
        nmapSCAN = "nmap -sV -Pn -vv -p %s --script=smtp* -oN pillageResults/%s_smtp.nmap %s" % (port, ip_address, ip_address)
        subprocess.check_output(nmapSCAN, shell=True)
   
    def enumUsers(self, ip_address, port):
        print "INFO: Performing brute force user enum for " + ip_address + ":" + port
        result=""
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect=s.connect((ip_address,int(port)))
        banner=s.recv(1024)
        result+=banner +"\n"
        for user in self.userList:
            s.send('VRFY ' + user + '\r\n') # VRFY a user
            response=s.recv(1024)
            if "250 " in response[:4]:
                result+=response
        s.close()
        filepath="{}/{}_smtpEnum.txt".format(self.dirPath,str(ip_address))
        self.recordResults(filepath,result)

    def recordResults(self, filepath, results):
        with open(filepath, "a") as myfile:
            myfile.write(results)

    def parseFile(self, inputfile):
        try:
            with open(inputfile) as f:
                allEntries=[]
                for line in f:
                    if line[0]=='#':
                        pass
                    else:
                        if len(line.split())==1:
                            allEntries.append(line.strip())
                        else:
                            raise
            return allEntries
        except:
            print "Invalid file formatting!"
            sys.exit()

if __name__ == "__main__":
    smtp = smtpRecon()
