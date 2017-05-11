import argparse, time, sys, os, subprocess

class smbRecon(object):
    def __init__(self):
        self.parseArgs()
        self.nmapScripts(self.host, self.port)
        self.nbtScan(self.host, self.port)
        self.smbEnum(self.host, self.port)

    def parseArgs(self):
        parser = argparse.ArgumentParser(prog='smbEnumerator', add_help=True)
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
        print "INFO: Performing nmap smb script scan for " + ip_address + ":" + port
        #Nmap also has psExec
        nmapSCAN = "nmap -sV -Pn -vv -p %s --script='(smb*) and not (brute or broadcast or dos or external or fuzzer)' --script-args=unsafe=1 -oN pillageResults/%s_smb.nmap %s" % (port, ip_address, ip_address)
        subprocess.check_output(nmapSCAN, shell=True)

    def nbtScan(self, ip_address, port):
        print "INFO: Performing ntbscan for " + ip_address + ":" + port
        nbtSCAN = "nbtscan -r -v -h %s >> pillageResults/%s_smbNbt.txt" % (ip_address, ip_address)
        subprocess.check_output(nbtSCAN, shell=True)

    def smbEnum (self, ip_address, port):
        print "INFO: Performing enum4Linux scan for " + ip_address + ":" + port
        try:
            enumSCAN = "enum4linux -a -M -v %s >> pillageResults/%s_smbEnum.txt" % (ip_address, ip_address)
            subprocess.check_output(enumSCAN, shell=True)
        except:
            print "ERROR: enum4Linux scan FAILED for " + ip_address + ":" + port

if __name__ == "__main__":
    smb = smbRecon()
