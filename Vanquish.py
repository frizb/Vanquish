#!/usr/bin/python
import argparse, time, sys, os, random
import subprocess, multiprocessing

#TODO
# Starts Fast moves to Through
# 1. NMAP Scan
# 2. Service Enumeration Scan
# 3. Word list creation 1st pass
#       Banner Grab
#       HTTP Enum
#       Spider site
#       HTTP Download all assets
#       Image Scan - Meta / Steg / OCR
#       Create Site Map txt file for all assets
#       Create Wordlist version1

# 4. Service Enumeration with Word List
# 5. Bruteforcing with word list
# 6. Mutation of word list service enumeration
# 7. Bruteforcing with mutation

class Pillage(object):

    def __init__(self, directoryName="pillageResults", userList="wordlists/users.txt", passList="wordlists/mutatedMega.txt"):
        self.banner()
        self.parseArgs()
        self.userList=userList
        self.passList=passList
        self.createDir(directoryName)
        self.pillageHosts()

    def parseArgs(self):
        parser = argparse.ArgumentParser(prog='Analyzes a group of hosts and enumerates interesting info', add_help=True)
        parser.add_argument('hostfile', help='host range to scan')    
        args = parser.parse_args()
        self.hosts=self.analyzeHostfile(args.hostfile)

    def addProcess(self, method, arguments):
        p = multiprocessing.Process(target=method, args=(arguments,))
        p.start()

    def sshEnum(self, args):
        host = args[0]
        port = args[1]
        print "INFO: Detected SSH on " + host + ":" + port
        script = "python sshRecon.py {} {} {} {}".format(host, port, self.userList, self.passList)
        subprocess.call(script, shell=True)

    def ftpEnum(self, args):
        host = args[0]
        port = args[1]
        print "INFO: Detected FTP on " + host + ":" + port
        script = "python ftpRecon.py {} {} {} {}".format(host, port, self.userList, self.passList)
        subprocess.call(script, shell=True)

        # Http and Https are the same but just change filename

    def httpEnum(self, args):
        host = args[0]
        port = args[1]
        protocol = args[2]
        print "INFO: Detected webapp on " + host + ":" + port
        script = "python webRecon.py {} {} {} {} {}".format(host, port, protocol, self.userList, self.passList)
        subprocess.call(script, shell=True)

    def dnsEnum(self, args):
        host = args[0]
        port = args[1]
        print "INFO: Detected DNS on " + host + ":" + port
        script = "python dnsRecon.py {} {}".format(host, port)
        subprocess.call(script, shell=True)

    def msSqlEnum(self, args):
        host = args[0]
        port = args[1]
        print "INFO: Detected MS-SQL on " + host + ":" + port
        script = "python msSqlRecon.py {} {} {} {}".format(host, port, self.userList, self.passList)
        subprocess.call(script, shell=True)

    def snmpEnum(self, host, port, args):
        host = args[0]
        port = args[1]
        print "INFO: Detected snmp on " + host + ":" + port
        script = "python snmpRecon.py {} {}".format(host, port)
        subprocess.call(script, shell=True)

    def smtpEnum(self, args):

        host=args[0]
        port=args[1]
        print "INFO: Detected smtp on " + host + ":" + port
        script = "python smtpRecon.py {} {} {} {}".format(host, port, self.userList, self.passList)
        subprocess.call(script, shell=True)

    def smbEnum(self, args):
        host=args[0]
        port=args[1]
        print "INFO: Detected smb on " + host + ":" + port
        script = "python smbRecon.py {} {} {} {}".format(host, port, self.userList, self.passList)
        subprocess.call(script, shell=True)

    def rdpEnum(self, args):
        host=args[0]
        port=args[1]
        print "INFO: Detected rdp on " + host + ":" + port
        script = "python rdpRecon.py {} {} {} {}".format(host, port, self.userList, self.passList)
        subprocess.call(script, shell=True)

    def pillageHosts(self):
        for host in self.hosts:
            tcpServices, udpServices = self.scanHost(host)
            for service in tcpServices:
                port=service[0].split('/')[0]
                serv=service[2]

                if serv == 'ssh':
                    self.addProcess(self.sshEnum, [host, port])
                elif serv == 'ftp':
                    self.addProcess(self.ftpEnum, [host, port])
                elif serv == 'dns':
                    self.addProcess(self.dnsEnum, [host, port])
                elif 'https' in serv or 'http' in serv:
                    protocol = 'http'
                    if 'ssl' in serv or 'https' in serv:
                        protocol = 'http'
                    self.addProcess(self.httpEnum, [host, port, protocol])
                elif serv == 'msSql' or serv == 'ms-sql-s' or serv == 'ms-sql':
                    self.addProcess(self.msSqlEnum, [host, port])
                elif serv == 'smtp':
                    self.addProcess(self.smtpEnum, [host, port])
                elif serv == 'snmp':
                    self.addProcess(self.snmpEnum, [host, port])
                elif serv == 'smb':
                    self.addProcess(self.smbEnum, [host, port])
                elif serv == 'rdp' or serv == ' microsoft-rdp' or serv == 'ms-wbt-server' or serv == 'ms-term-serv':
                    self.addProcess(self.rdpEnum, [host, port])
                else:
                    print "INFO: no module found for %s" % (serv)

            print "INFO: TCP/UDP Nmap scans completed for " + host 

            #Iterate through UDP

    def scanHost(self, host):
        print "INFO: Running general TCP/UDP nmap scans for " + host
        fullPath="{}/{}".format(self.dirPath,str(host))
        TCPSCAN = "nmap -vv -Pn -A -sC -sV -T4 -p- -oN '%s.nmap' -oX '%s.xml' %s"  % (fullPath, fullPath, host)
        print TCPSCAN
        results = subprocess.check_output(TCPSCAN, shell=True)

        # None of the modules support UDP at this time, so I am omitting the scan and results.
        #UDPSCAN = "nmap -vv -Pn -A -sC -sV -sU -T 4 --top-ports 500 -oN '%sU.nmap' -oX '%sU.xml' %s" % (fullPath, fullPath, host)
        udpresults= []#subprocess.check_output(UDPSCAN, shell=True)
        return self.getInterestingTCP(host, results), self.getInterestingUDP(host, udpresults)

    def getInterestingTCP(self, host, results):
        tcpServices=[]
        for line in iter(results.splitlines()):
            words=line.split()
            try:
                if words and words[1] == "open" and "/tcp" in words[0]:
                    tcpServices.append(words)
            except:
                #weird formatting...
                continue
        return tcpServices

    #Could implement
    def getInterestingUDP(self,host, results):
        return []

    def recordResults(self, host, results):
        filepath="{}/{}Results.txt".format(self.dirPath,str(host))
        with open(filepath, "a") as myfile:
            myfile.write(results)

    def analyzeHostfile(self, hostfile):
        try:
            with open(hostfile) as f:
                allHosts=[]
                for line in f:
                    if line[0]=='#':
                        pass
                    else:
                        if len(line.split())==1:
                            allHosts.append(line.strip())
                        else:
                            raise
            return allHosts
        except:
            print "Invalid host file formatting!"
            sys.exit()

    def createDir(self, directory):
        self.dirPath=directory
        if not os.path.exists(directory):
            os.makedirs(directory)

    def banner(self):
        banner_numbers = [1,2,3]
        banners = {
            1 : self.banner_flame,
            2 : self.banner_doom,
            3 : self.banner_block
        }
        secure_random = random.SystemRandom()
        banners[secure_random.choice(banner_numbers)]()


    def banner_flame(self):
        print '                  )             (   (       )  '
        print '         (     ( /(   (         )\ ))\ ) ( /(  '
        print ' (   (   )\    )\())( )\     ( (()/(()/( )\()) '
        print ' )\  )((((_)( ((_)\ )((_)    )\ /(_))(_)|(_)\  '
        print '((_)((_)\ _ )\ _((_|(_)_  _ ((_|_))(_))  _((_) '
        print '\ \ / /(_)_\(_) \| |/ _ \| | | |_ _/ __|| || | '
        print ' \ V /  / _ \ | .` | (_) | |_| || |\__ \| __ | '
        print '  \_/  /_/ \_\|_|\_|\__\_\\\\___/|___|___/|_||_| '

    def banner_doom(self):
        print ' __      __     _   _  ____  _    _ _____  _____ _    _ '
        print ' \ \    / /\   | \ | |/ __ \| |  | |_   _|/ ____| |  | |'
        print '  \ \  / /  \  |  \| | |  | | |  | | | | | (___ | |__| |'
        print '   \ \/ / /\ \ | . ` | |  | | |  | | | |  \___ \|  __  |'
        print '    \  / ____ \| |\  | |__| | |__| |_| |_ ____) | |  | |'
        print '     \/_/    \_\_| \_|\___\_\\\\____/|_____|_____/|_|  |_|'

    def banner_block(self):
        print ' __   ___   _  _  ___  _   _ ___ ___ _  _ '
        print ' \ \ / /_\ | \| |/ _ \| | | |_ _/ __| || |'
        print '  \ V / _ \| .` | (_) | |_| || |\__ \ __ |'
        print '   \_/_/ \_\_|\_|\__\_\\\\___/|___|___/_||_|'


if __name__ == "__main__":
    pillager = Pillage()
