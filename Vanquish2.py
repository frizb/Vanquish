#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Vanquish
# Root2Boot automation platform designed to systematically enumernate and exploit using the law of diminishing returns
#
# TODO: Import data into MSF database and generate pretty table reports of servers and ports
# TODO: Append the exact command that is used to the output text files for easy refernce in documentation
# TODO: Create a suggest only mode that dumps a list of commands to try rather than running anything
# TODO: Fix TCP / UDP / Multi Nmap scan merging - When multiple scans have the same port info,we get duplicate entries
# TODO: Do not enum closed or filtered ports
# Starts Fast moves to Through
# 1. NMAP Scan
# 2. Service Enumeration Scan
#
# TODO:
# 3. Word list creation 1st pass
#       Banner Grabx
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
#


"""
Main application logic and automation functions
"""

__version__ = '0.8'
__lastupdated__ = 'June 17, 2017'
__nmap_folder__ = 'Nmap'

###
# Imports
###
import fnmatch
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
import threading
import xml.etree.ElementTree as ET
from multiprocessing.dummy import Pool as ThreadPool


# PROGRESS BAR - Thank you! clint.textui.progress
BAR_TEMPLATE = '%s[%s%s] %i/%i - %s\r'
DOTS_CHAR = '.'
BAR_FILLED_CHAR = '#'
BAR_EMPTY_CHAR = ' '
ETA_INTERVAL = 1
ETA_SMA_WINDOW = 9
STREAM = sys.stderr
class Bar(object):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.done()
        return False  # we're not suppressing exceptions

    def __init__(self, label='', width=32, hide=None, empty_char=BAR_EMPTY_CHAR,
                 filled_char=BAR_FILLED_CHAR, expected_size=None, every=1):
        self.label = label
        self.width = width
        self.hide = hide
        # Only show bar in terminals by default (better for piping, logging etc.)
        if hide is None:
            try:
                self.hide = not STREAM.isatty()
            except AttributeError:  # output does not support isatty()
                self.hide = True
        self.empty_char =    empty_char
        self.filled_char =   filled_char
        self.expected_size = expected_size
        self.every =         every
        self.start =         time.time()
        self.ittimes =       []
        self.eta =           0
        self.etadelta =      time.time()
        self.etadisp =       self.format_time(self.eta)
        self.last_progress = 0
        if (self.expected_size):
            self.show(0)

    def show(self, progress, count=None):
        if count is not None:
            self.expected_size = count
        if self.expected_size is None:
            raise Exception("expected_size not initialized")
        self.last_progress = progress
        if (time.time() - self.etadelta) > ETA_INTERVAL:
            self.etadelta = time.time()
            self.ittimes = \
                self.ittimes[-ETA_SMA_WINDOW:] + \
                    [-(self.start - time.time()) / (progress+1)]
            self.eta = \
                sum(self.ittimes) / float(len(self.ittimes)) * \
                (self.expected_size - progress)
            self.etadisp = self.format_time(self.eta)
        x = int(self.width * progress / self.expected_size)
        if not self.hide:
            if ((progress % self.every) == 0 or      # True every "every" updates
                (progress == self.expected_size)):   # And when we're done
                STREAM.write(BAR_TEMPLATE % (
                    self.label, self.filled_char * x,
                    self.empty_char * (self.width - x), progress,
                    self.expected_size, self.etadisp))
                STREAM.flush()

    def done(self):
        self.elapsed = time.time() - self.start
        elapsed_disp = self.format_time(self.elapsed)
        if not self.hide:
            # Print completed bar with elapsed time
            STREAM.write(BAR_TEMPLATE % (
                self.label, self.filled_char * self.width,
                self.empty_char * 0, self.last_progress,
                self.expected_size, elapsed_disp))
            STREAM.write('\n')
            STREAM.flush()

    def format_time(self, seconds):
        return time.strftime('%H:%M:%S', time.gmtime(seconds))


def bar(it, label='', width=32, hide=None, empty_char=BAR_EMPTY_CHAR,
        filled_char=BAR_FILLED_CHAR, expected_size=8, every=1):
    with Bar(label=label, width=width, hide=hide, empty_char=BAR_EMPTY_CHAR,
             filled_char=BAR_FILLED_CHAR, expected_size=expected_size, every=every) \
            as bar:
        for i, item in enumerate(it):
            yield item
            bar.show(i + 1)
class logger:
    DEBUG = False;
    VERBOSE = False;

    @staticmethod
    def debug(msg):
        if logger.DEBUG == True:
            print("[!] "+msg)

    @staticmethod
    def verbose(msg):
        if logger.VERBOSE == True:
            print("[*] "+msg)

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
        self.parser.add_argument("-noResume", action='store_true', help='do not resume a previous session')
        self.parser.add_argument("-range", metavar='IPs', type=str, nargs="+", default="",
                                 help='a range to scan ex: 10.10.10.0/24')
        self.parser.add_argument("-threadPool", metavar='threads', type=int,  default="8",
                            help='Thread Pool Size (default: %(default)s)')
        self.parser.add_argument("-verbose", action='store_true', help='display verbose details during the scan')
        self.parser.add_argument("-debug", action='store_true', help='display debug details during the scan')
        self.args = self.parser.parse_args()
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

    # Scan the hosts using Nmap
    # Create a thread pool and run multiple nmap sessions in parallel
    def upfront_scan_hosts(self, hosts, command_label):
        logger.verbose("scan_hosts() - command label : " + command_label )
        pool = ThreadPool(self.args.threadPool)
        self.phase_commands = []
        nmap_path = os.path.join(self.args.outputFolder, __nmap_folder__)
        # Check folder for existing service
        if not os.path.exists(nmap_path):
            os.makedirs(nmap_path)
        for host in hosts:
            command_keys = {
                'output': os.path.join(nmap_path, command_label.replace(" ","_")+"_"+host.strip().replace(".", "_") ),
                'target': host.strip()}
            command = self.prepare_command( command_label ,command_keys )
            base, filename = os.path.split(command_keys['output']) # Resume file already exists
            if not self.args.noResume and self.find_files(base, filename + ".*").__len__() > 0:
                logger.verbose("scan_hosts() - RESUME - output file already exists: "
                               + command_keys['output'])
            else:
                self.phase_commands.append(command)
                logger.debug("scan_hosts() - command : " + command)

        #results = pool.map(self.execute_scan, self.phase_commands)
        for _ in bar(pool.imap_unordered(self.execute_scan, self.phase_commands), expected_size=len(self.phase_commands)):
            pass
        pool.close()
        pool.join()

    def execute_scan(self, command):
        logger.debug("execute_scan() - " + command)
        stream = os.popen(command)
        logger.debug("execute_scan() - COMPLETED! - " + command)

    # Parse Nmap XML - Reads all the Nmap xml files in the Nmap folder
    def parse_nmap_xml(self):
        print "[+] Reading Nmap XML Output Files..."
        port_attribs_to_read = ['protocol', 'portid']
        service_attribs_to_read = ['name', 'product', 'version', 'hostname', 'extrainfo']
        state_attribs_to_read = ['state']
        xml_nmap_elements = {'service': service_attribs_to_read, 'state': state_attribs_to_read}
        searchAddress = {'path': 'address', 'el': 'addr'}
        searchPorts = {'path': 'ports', 'el': 'portid'}
        nmap_output_path = os.path.join(self.args.outputFolder, __nmap_folder__)
        for nmap_file in os.listdir(nmap_output_path):
            if nmap_file.endswith(".xml"):
                nmap_file_path = os.path.join(nmap_output_path, nmap_file)
                logger.debug("XML PARSE: " + nmap_file_path)
                try:
                    tree = ET.parse(nmap_file_path)
                except:
                    logger.debug("XML PARSE: Error Parsing : "+nmap_file_path )
                    continue
                root = tree.getroot()
                for i in root.iter('host'):
                    e = i.find(searchAddress['path'])
                    find_ports = i.find(searchPorts['path'])
                    if find_ports is not None:
                        logger.verbose("NMAP XML PARSE: - Found Address " + e.get(searchAddress['el']))
                        addr = e.get(searchAddress['el'])
                        if self.nmap_dict.get(addr,None) is None: self.nmap_dict[addr] = {}
                        port_dict = []
                        for port in find_ports.iter('port'):
                            element_dict = {}
                            self.xml_to_dict(port_attribs_to_read, port, element_dict)
                            for xml_element in xml_nmap_elements:
                                for attribute in port.iter(xml_element):
                                    if attribute is not None:
                                        self.xml_to_dict(service_attribs_to_read, attribute, element_dict)
                                        logger.verbose("NMAP XML PARSE: Port: " + element_dict['portid'])
                                        if attribute.get('hostname', '') is not '':
                                            self.nmap_dict[addr]['hostname'] = attribute.get('hostname', '')
                                        if self.nmap_dict[addr].get("ports", '') is not '' and filter(
                                                lambda dict_ports: dict_ports['portid'] == element_dict['portid'],
                                                self.nmap_dict[addr]['ports']).__len__() == 0:
                                                    logger.verbose("NMAP XML PARSE: Port already Exsits: "+element_dict['portid'] )
                                        else:
                                            logger.verbose("NMAP XML PARSE: Append: " + element_dict['portid'])
                                            port_dict.append(element_dict)
                        if self.nmap_dict[addr].get('ports', None) is None:
                            logger.verbose("NMAP XML PARSE: NEW MAP")
                            self.nmap_dict[addr]['ports'] = port_dict
                        else:
                            logger.verbose("NMAP XML PARSE: MAP MERGE")
                            self.nmap_dict[addr]['ports'] = self.nmap_dict[addr]['ports'] + port_dict
            logger.verbose("NMAP XML PARSE: - Finished NMAP Dict Creation:\n " + str(self.nmap_dict))

    # find exploits from exploit db and copy them to service folder
    # TODO: Copy results to service folders - update nmap_dict with other web app etc products and versions...
    def exploit_search(self):
        logger.debug("exploit_search()")
        # Check nmap_dict
        self.phase_commands = []
        for host in self.nmap_dict:
            for service in self.nmap_dict[host]['ports']:
                if service.get('product', '') is not '' and service.get('version','') is not '':
                    version_digits = ' '.join(str(x) for x in re.findall(r'\d+',service.get('version','')))
                    stream = os.popen('searchsploit --json '+service.get('product', '')+" "+version_digits)
                    json_results = stream.read()
                    stream.close()
                    print json_results

    # Enumerate a phase
    # phases are defined in attackplan.ini
    # enumerate will create a que of all the commands to run in a phase
    # then it will create a progress bar and execute a specified number of threads at the same time
    # until all the threads are finished then the results are parsed by another function
    def enumerate(self,phase_name):
        logger.debug("Enumerate - "+ phase_name)
        self.phase_commands = []
        for host in self.nmap_dict:
            logger.debug("enumerate() - Host: " + host)
            for service in self.nmap_dict[host]['ports']:
                logger.debug("\tenumerate() - port_number: " + str(service))
                for known_service, ports in self.config.items('Service Ports'):
                    if service['name'].find(known_service) <> -1 or service['portid'] in ports.split(','):
                        if (self.plan.has_option(phase_name,known_service)):
                            for command in self.plan.get(phase_name,known_service).split(','):
                                if command is not '':
                                    command_keys = {
                                        'output': self.get_enumeration_path(host, service['name'],service['portid'], command),
                                        'target': host,
                                        'domain': self.args.domain,
                                        'service': service['name'],
                                        'port':service['portid']
                                    }
                                    base, filename = os.path.split(command_keys['output']) # Resume file already exists
                                    if not self.args.noResume and self.find_files(base,filename+".*").__len__()>0:
                                        logger.verbose("enumerate() - RESUME - output file already exists: "
                                                       + command_keys['output'])
                                    else:
                                        self.phase_commands.append(self.prepare_command(command,command_keys))
                                        logger.verbose("enumerate() - command : " + command)
                        else:
                            logger.debug("\tenumerate() - NO command section found for phase: " + phase_name +
                                         " service name: "+known_service )
        pool = ThreadPool(self.args.threadPool)
        #results = pool.map(self.execute_enumeration, self.phase_commands)
        for _ in bar(pool.imap_unordered(self.execute_enumeration, self.phase_commands), expected_size=len(self.phase_commands)):
            pass
        pool.close()
        pool.join()

    def execute_enumeration(self,enumerate_command):
        logger.debug("execute_enumeration() - " + enumerate_command)
        stream = os.popen(enumerate_command)
        logger.debug("execute_enumeration() - COMPLETED! - " + enumerate_command)

    def get_enumeration_path(self, host, service, port, command):
        ip_path = os.path.join(self.args.outputFolder, host.strip().replace(".","_"))
        if not os.path.exists(ip_path): os.makedirs(ip_path)
        service_path = os.path.join(ip_path, service)
        if not os.path.exists(service_path): os.makedirs(service_path)
        return os.path.join(service_path, command.replace(" ","_")+"_"+str(port))

    def prepare_command(self, command, keyvalues):
        command = self.config.get(command, "command")
        logger.debug("prepare_command() command: " + command)
        for k in keyvalues.iterkeys():
            logger.debug("    prepare_command() key: " + k)
            command = command.replace("<" + k + ">", keyvalues[k])
        return command

    def xml_to_dict(self, list_to_read, xml_elements, dict):
        for element in list_to_read:
            value = xml_elements.get(element, '')
            if element is "name" and self.config.has_option("Service Labels",value):
                    dict[element] = self.config.get("Service Labels",value)
            else:
                dict[element] = value
        return dict

    def write_report_file(self, data):
        report_path = os.path.join(self.args.outputFolder, self.args.reportFile)
        f = open(report_path, 'w')
        f.write(pformat(data, indent=4, width=1))
        f.close()

    def find_files(self,base, pattern):
        return [n for n in fnmatch.filter(os.listdir(base), pattern) if
                os.path.isfile(os.path.join(base, n))]

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
        print '\n                  )             (   (       )  '
        print '         (     ( /(   (         )\ ))\ ) ( /(  '
        print ' (   (   )\    )\())( )\     ( (()/(()/( )\()) '
        print ' )\  )((((_)( ((_)\ )((_)    )\ /(_))(_)|(_)\  '
        print '((_)((_)\ _ )\ _((_|(_)_  _ ((_|_))(_))  _((_) '
        print '\ \ / /(_)_\(_) \| |/ _ \| | | |_ _/ __|| || | '
        print ' \ V /  / _ \ | .` | (_) | |_| || |\__ \| __ | '
        print '  \_/  /_/ \_\|_|\_|\__\_\\\\___/|___|___/|_||_| '
        print ' Built for speed!'

    @staticmethod
    def banner_doom():
        print '\n __      __     _   _  ____  _    _ _____  _____ _    _ '
        print ' \ \    / /\   | \ | |/ __ \| |  | |_   _|/ ____| |  | |'
        print '  \ \  / /  \  |  \| | |  | | |  | | | | | (___ | |__| |'
        print '   \ \/ / /\ \ | . ` | |  | | |  | | | |  \___ \|  __  |'
        print '    \  / ____ \| |\  | |__| | |__| |_| |_ ____) | |  | |'
        print '     \/_/    \_\_| \_|\___\_\\\\____/|_____|_____/|_|  |_|'
        print ' The faster you hack ... the more you can hack'

    @staticmethod
    def banner_block():
        print '\n __   ___   _  _  ___  _   _ ___ ___ _  _ '
        print ' \ \ / /_\ | \| |/ _ \| | | |_ _/ __| || |'
        print '  \ V / _ \| .` | (_) | |_| || |\__ \ __ |'
        print '   \_/_/ \_\_|\_|\__\_\\\\___/|___|___/_||_|'
        print ' Faster than a one-legged man in a butt kicking contest'

    ##################################################################################
    # Entry point for command-line execution
    ##################################################################################

    def main(self):
        start_time = time.time()
        #sys.stderr = open("errorlog.txt", 'w')
        print("[+] Configuration file: " + str(self.args.configFile))
        print("[+] Attack plan file:   " + str(self.args.attackPlanFile))
        print("[+] Output Path:        " + str(self.args.outputFolder))
        print("[+] Host File:          " + str(self.args.hostFile.name))
        logger.debug("DEBUG MODE ENABLED!")
        logger.verbose("VERBOSE MODE ENABLED!")

        # Check folder for existing output
        if not os.path.exists(self.args.outputFolder):
            os.makedirs(self.args.outputFolder)
        elif not self.args.noResume:
            print "[+] Resuming previous session"

        self.hosts = self.hosts.readlines()
        logger.verbose("Hosts:"+str(self.hosts))

        # Start up front NMAP port scans
        print "[+] Starting upfront Nmap Scan..."
        for scan_command in self.plan.get("Scans Start", "Order").split(","):
            print "[+] Starting Scan Type: " + scan_command
            self.upfront_scan_hosts(self.hosts, scan_command)

        print "[+] Starting background Nmap Scan..."
        # Start background Nmap port scans ... these will take time and will run concurrently with enumeration
        #for scan_command in self.plan.get("Scans Start", "Order").split(","):
        #    self.upfront_scan_hosts(self.hosts, scan_command)
        #thread = threading.Thread(target=self.background_scan_hosts, args=())
        #thread.daemon = True                            # Daemonize thread
        #thread.start()                                  # Start the execution
        #TODO background thread with long term comprehensive scan - restart enumeration it has finished -
        # ensure resume is turned on

        # Begin Enumeration Phases
        print "[+] Starting enumeration..."
        for phase in self.plan.get("Enumeration Plan","Order").split(","):
            self.parse_nmap_xml()
            self.write_report_file(self.nmap_dict)
            # print "[+] Starting upfront Nmap Scan..."
            # TODO Search for exploits
            #self.exploit_search()
            print "[+] Starting Phase: " + phase
            self.enumerate(phase)


        print "[+] Elapsed Time: " + time.strftime('%H:%M:%S', time.gmtime(time.time() - start_time))
        logger.verbose("Goodbye!")
        return 0


def main(argv=None):
    vanquish = Vanquish(argv if argv else sys.argv[1:])
    return vanquish.main()

if __name__ == "__main__":
    sys.exit(main())