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

__version__ = '0.6'
__lastupdated__ = 'June 11, 2017'

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
from pprint import pformat
import subprocess
from subprocess import call
import multiprocessing
import xml.etree.ElementTree as ET
from multiprocessing.dummy import Pool as ThreadPool

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
        self.parser.add_argument("-outputFolder", metavar='folder', type=str, default= "."+os.path.sep+"output",
                            help='output folder path (default: %(default)s)')
        self.parser.add_argument("-configFile", metavar='file', type=str, default="config.ini",
                            help='configuration ini file (default: %(default)s)')
        self.parser.add_argument("-attackPlanFile", metavar='file', type=str,  default="attackplan.ini",
                            help='attack plan ini file (default: %(default)s)')
        self.parser.add_argument("-hostFile", metavar='file', type=argparse.FileType("r"), default="hosts.txt",
                            help='list of hosts to attack (default: %(default)s)')
        self.parser.add_argument("-domain", metavar='domain', type=str, default="thinc.local",
                            help='domain to use in DNS enumeration (default: %(default)s)')
        self.parser.add_argument("-reportFile", metavar='report', type=str, default="report.txt",
                            help='filename used for the report (default: %(default)s)')
        self.parser.add_argument("-resume", action='store_true', help='resume a previous session')
        self.parser.add_argument("-range", metavar='IPs', type=str, nargs="+", default="",
                                 help='a range to scan ex: 10.10.10.0/24')
        self.parser.add_argument("-threadPool", metavar='threads', type=int,  default="16",
                            help='Thread Pool Size (default: %(default)s)')
        self.parser.add_argument("-verbose", action='store_true', help='display verbose details during the scan')
        self.parser.add_argument("-debug", action='store_true', help='display debug details during the scan')
        self.args = self.parser.parse_args()
        #self.hosts = self.args.hostFile.readlines() # List of hosts
        self.hosts = self.args.hostFile

        # load config
        self.config = ConfigParser.ConfigParser()
        self.config.read(self.args.configFile)

        logger.VERBOSE = ( self.config.getboolean("System","Verbose") or self.args.verbose)
        logger.DEBUG = (self.config.getboolean("System", "Debug") or self.args.debug)

        # load attack plan
        self.plan = ConfigParser.ConfigParser()
        self.plan.read(self.args.attackPlanFile)

        #Master NMAP Data Structure Dict
        self.nmap_dict = {}

        #current enumeration phase command que
        self.phase_commands = []

    # Enumerate a phase
    # phases are defined in attackplan.ini
    # enumerate will create a que of all the commands to run in a phase
    # then it will create a progress bar and execute a specified number of threads at the same time
    # until all the threads are finished then the results are parsed by another function
    def enumerate(self,phase_name):
        logger.debug("Enumerate - "+ phase_name)
        for host in self.nmap_dict:
            logger.debug("enumerate() - Host: " + host)
            for service in self.nmap_dict[host]['ports']:
                logger.debug("\tenumerate() - Service: " + str(service))
                # Look for any known server ports from config file
                for known_service, ports in self.config.items('Service Ports'):
                    if service['name'].find(known_service) <> -1 or service['portid'] in ports.split(','):
                        logger.debug("\t\tenumerate() - Ports Match: " + ports)
                        logger.debug("\t\tenumerate() - Known Service: " + known_service)
                        logger.debug("\t\tenumerate() - Service Port: " + service['portid'])
                        logger.debug("\t\tenumerate() - Service: " + service['name'])
                        if (self.plan.has_option(phase_name,known_service)):
                            for command in self.plan.get(phase_name,known_service).split(','):
                                command_keys = {
                                    'output': self.get_scan_path(host, service['name'], command),
                                    'target': host,
                                    'domain': self.args.domain,
                                    'service': service['name'],
                                    'port':service['portid']
                                }
                                self.phase_commands.append(self.prepare_command(command,command_keys))
                        else:
                            logger.debug("\tenumerate() - NO command section found for phase: " + phase_name + " service name: "+known_service )

    def get_scan_path(self, host, service, command):
        service_path = os.path.join(self.args.outputFolder, service)
        # Check folder for existing service
        if not os.path.exists(service_path):
            os.makedirs(service_path)
        return os.path.join(service_path, command+"_" + host.strip().replace(".", "_") + ".xml")

    def scan_hosts(self, hosts):
        pool = ThreadPool(self.args.threadPool)
        results = pool.map(self.execute_command, hosts)
        pool.close()
        pool.join()
        print results

    def execute_command(self,host):
        nmap = self.prepare_command("Nmap", {'output': self.get_scan_path(host, "Nmap"), 'target': host.strip()})
        logger.debug("scan_hosts() - " + "Nmap" + " Command: " + nmap)
        stream = os.popen(nmap)

    def prepare_command(self, command, keyvalues):
        command = self.config.get(command, "command")
        logger.verbose("command: " + command)
        for k in keyvalues.iterkeys():
            logger.verbose("    key: " + k)
            command = command.replace("<" + k + ">", keyvalues[k])
        return command

    def parse_nmap_xml(self, hosts, command):
        # NMAP XML Magic Elements
        port_attribs_to_read = ['protocol', 'portid']
        service_attribs_to_read = ['name', 'product', 'version', 'hostname', 'extrainfo']
        state_attribs_to_read = ['state']
        xml_nmap_elements = {'service': service_attribs_to_read, 'state': state_attribs_to_read}
        searchAddress = {'path': 'address', 'el': 'addr'}
        searchPorts = {'path': 'ports', 'el': 'portid'}
        nmap_host_element = 'host'
        nmap_port_element = 'port'
        logger.debug("XML HOSTS " + str(hosts))
        for host in hosts:
            # Read a list of addresses and ports
            nmap_file = self.get_scan_path(host,"Nmap",command)
            if not os.path.isfile(nmap_file):
                logger.debug("ERROR NMAP XML PARSE: file not found:" + nmap_file)
                continue
            logger.debug("XML PARSE: " + nmap_file)
            tree = ET.parse(nmap_file)
            root = tree.getroot()
            for i in root.iter(nmap_host_element):
                e = i.find(searchAddress['path'])
                find_ports = i.find(searchPorts['path'])
                if find_ports is not None:
                    logger.verbose("NMAP XML PARSE: - Found Address " + e.get(searchAddress['el']))
                    addr = e.get(searchAddress['el'])
                    self.nmap_dict[addr] = {}
                    #self.nmap_dict[addr]['ip'] = host.strip()
                    portarray = []
                    for port in find_ports.iter(nmap_port_element):
                        element_dict = {}
                        self.xml_to_dict(port_attribs_to_read, port, element_dict)
                        for xml_element in xml_nmap_elements:
                            for attribute in port.iter(xml_element):
                                if attribute is not None:
                                    self.xml_to_dict(service_attribs_to_read, attribute, element_dict)
                                    if attribute.get('hostname', '') is not '':
                                        self.nmap_dict[addr]['hostname'] = attribute.get('hostname', '')

                        portarray.append(element_dict)
                    self.nmap_dict[addr]['ports'] = portarray
        logger.verbose("NMAP XML PARSE: - Finished NMAP Dict Creation:\n " + str(self.nmap_dict))

    def xml_to_dict(self, list_to_read, xml_elements, dict):
        for element in list_to_read:
            dict[element] = xml_elements.get(element, '')
        return dict

    def write_report_file(self, data):
        report_path = os.path.join(self.args.outputFolder, self.args.reportFile)
        f = open(report_path, 'w')
        f.write(pformat(data, indent=4, width=1))
        f.close()

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

        # Inital NMAP Port Scan
        self.hosts = self.hosts.readlines()
        #self.scan_hosts(self.hosts)
        self.write_report_file(self.nmap_dict)
        self.parse_nmap_xml(self.hosts, "Nmap")
        self.write_report_file(self.nmap_dict)
        self.enumerate("Information Gathering")
        self.write_report_file(self.nmap_dict)

        print str(self.phase_commands)

        logger.verbose("Goodbye!")
        return 0


def main(argv=None):
    vanquish = Vanquish(argv if argv else sys.argv[1:])
    return vanquish.main()


if __name__ == "__main__":
    sys.exit(main())