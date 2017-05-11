#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Vanquish
# Root2Boot automation platform designed to systematically enumernate and exploit using the law of diminishing returns
#

# Starts Fast moves to Through
# 1. NMAP Scan / Mascan
# 2. Service Enumeration Scan
# 3. Word list creation 1st pass
#       Banner Grab
#       HTTP Enum
#       Spider site
#       HTTP Download all assets
#       Image Scan - Meta / Steg / OCR
#       Create Site Map txt file for all assets
#       Create Wordlist version1
#
# 4. Service Enumeration with Word List
# 5. Bruteforcing with word list
# 6. Mutation of word list service enumeration
# 7. Bruteforcing with mutation
#
# Copyright (c) 2017, Austin Scott
#
# Contact information:
# Austin Scott
#


"""
Main application logic and automation functions
"""

__version__ = '0.1'
__lastupdated__ = 'May 8, 2017'

###
# Imports
###
import os
import sys
import time
import re
import ConfigParser
import argparse
import random
import subprocess
import multiprocessing


class logger:
    DEBUG = False;
    VERBOSE = False;

    @staticmethod
    def debug(msg):
        if logger.DEBUG == True:
            print(msg)

    @staticmethod
    def verbose(msg):
        if logger.VERBOSE == True:
            print(msg)

class Vanquish:
    def __init__(self, argv):
        self.banner()
        print("Vanquish Version: " + __version__ + " Updated: " + __lastupdated__)
        print("  Use the -h parameter for help.")
        self.parser = argparse.ArgumentParser(
            description='Root2Boot automation platform designed to systematically enumernate and exploit using the law of diminishing returns.')
        self.parser.add_argument("-outputFolder", metavar='folder', type=str, nargs=1, default="output",
                            help='output folder path (default: %(default)s)')
        self.parser.add_argument("-configFile", metavar='file', type=str, nargs=1, default="config.ini",
                            help='configuration ini file (default: %(default)s)')
        self.parser.add_argument("-attackPlanFile", metavar='file', type=str, nargs=1, default="attackplan.ini",
                            help='attack plan ini file (default: %(default)s)')
        self.parser.add_argument("-hostFile", metavar='file', type=argparse.FileType("r"), nargs=1, default="hosts.txt",
                            help='list of hosts to attack (default: %(default)s)')
        self.parser.add_argument("-resume", action='store_true', help='resume a previous session')
        self.parser.add_argument("-range", metavar='IPs', type=str, nargs="+", default="",
                                 help='a range to scan ex: 10.10.10.0/24')
        self.args = self.parser.parse_args()
        self.hosts = self.args.hostFile.readlines() #List of hosts

        # load config
        self.config = ConfigParser.ConfigParser()
        self.config.read(self.args.configFile)
        logger.VERBOSE = self.config.getboolean("System","Verbose")
        logger.DEBUG = self.config.getboolean("System", "Debug")
        # load attack plan
        self.plan = ConfigParser.ConfigParser()
        self.plan.read(self.args.attackPlanFile)

    def scan_hosts(self):
        logger.debug("scan_hosts()")
        for host in self.hosts:
            tcp_services, udp_services = self.scanHost(host)
            for service in tcp_services:
                port = service[0].split('/')[0]
                serv = service[2]

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

    def scanHost(self, host):
        logger.debug("INFO: Running general TCP/UDP nmap scans for " + host)
        output = "{}/{}".format(self.args.outputFolder, str(host))
        nmap = self.prepare_command("Nmap",{'output':output,'target':host})
        logger.debug( nmap )
        results = subprocess.check_output(nmap, shell=True)

        return self.getInterestingTCP(host, results), self.getInterestingUDP(host, results)

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

    def prepare_command(self, command, keyvalues):
        command = self.config.get(command,"command")
        logger.verbose("command: "+ command)
        for k in keyvalues.iterkeys():
            logger.verbose("    key: " + k)
            command = command.replace("<"+k+">", keyvalues[k])
        return command

    def banner(self):
        banner_numbers = [1, 2, 3]
        banners = {
            1: self.banner_flame,
            2: self.banner_doom,
            3: self.banner_block
        }
        secure_random = random.SystemRandom()
        banners[secure_random.choice(banner_numbers)]()

    @staticmethod
    def banner_flame():
        print '                  )             (   (       )  '
        print '         (     ( /(   (         )\ ))\ ) ( /(  '
        print ' (   (   )\    )\())( )\     ( (()/(()/( )\()) '
        print ' )\  )((((_)( ((_)\ )((_)    )\ /(_))(_)|(_)\  '
        print '((_)((_)\ _ )\ _((_|(_)_  _ ((_|_))(_))  _((_) '
        print '\ \ / /(_)_\(_) \| |/ _ \| | | |_ _/ __|| || | '
        print ' \ V /  / _ \ | .` | (_) | |_| || |\__ \| __ | '
        print '  \_/  /_/ \_\|_|\_|\__\_\\\\___/|___|___/|_||_| '

    @staticmethod
    def banner_doom():
        print ' __      __     _   _  ____  _    _ _____  _____ _    _ '
        print ' \ \    / /\   | \ | |/ __ \| |  | |_   _|/ ____| |  | |'
        print '  \ \  / /  \  |  \| | |  | | |  | | | | | (___ | |__| |'
        print '   \ \/ / /\ \ | . ` | |  | | |  | | | |  \___ \|  __  |'
        print '    \  / ____ \| |\  | |__| | |__| |_| |_ ____) | |  | |'
        print '     \/_/    \_\_| \_|\___\_\\\\____/|_____|_____/|_|  |_|'

    @staticmethod
    def banner_block():
        print ' __   ___   _  _  ___  _   _ ___ ___ _  _ '
        print ' \ \ / /_\ | \| |/ _ \| | | |_ _/ __| || |'
        print '  \ V / _ \| .` | (_) | |_| || |\__ \ __ |'
        print '   \_/_/ \_\_|\_|\__\_\\\\___/|___|___/_||_|'

    ##################################################################################
    # Entry point for command-line execution
    ##################################################################################

    def main(self):
        #sys.stderr = open("errorlog.txt", 'w')
        print("Using configuration file: " + str(self.args.configFile))
        print("Using attack plan file: " + str(self.args.attackPlanFile))
        logger.debug("DEBUG MODE ENABLED!")
        logger.verbose("VERBOSE MODE ENABLED!")

        # Check folder for existing output
        if not os.path.exists(self.args.outputFolder):
            os.makedirs(self.args.outputFolder)

        # Resume
        if self.args.resume:
            logger.verbose("Resume!")
            #open xml
        logger.verbose("Hosts:"+str(self.hosts))

        #### -- REMOVE ME!
        exit()

        if len(self.hosts) > 0:
            self.scan_hosts()
        else:
            self.massScanHosts()

        logger.verbose("Goodbye!")
        return 0


def main(argv=None):
    vanquish = Vanquish(argv if argv else sys.argv[1:])
    return vanquish.main()


if __name__ == "__main__":
    sys.exit(main())