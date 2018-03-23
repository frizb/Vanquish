#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Vanquish
# Root2Boot automation platform designed to systematically enumernate and exploit using the law of diminishing returns
# DONE: Automate DNS Name lookup NMap XML generation upon discovering a DNS server
# DONE: remove upfront_scan_hosts funciton and merge with enumerate function
# DONE: Import data into MSF database and generate pretty table reports of servers and ports
# DONE: Combine scanning and information gathering loops
# DONE: Create custom password word list from CEWL URL Findings, Users, domains, groups, ComputerName
# DONE: Installer script and setup

# TODO: Seclist directory enumeration orchestation / Seclist user enumeration / Seclist brute forcing
# TODO: Add some FILTERED port results back in if they prodivde enumeration value (MongoDB)
# TODO: Attack plans config associated with one or more Config files - simplify - only specify an attack plan and a target
# TODO: Load findings from files here for merging - dont overwrite user added findings...
# TODO: SMB Hydra is running twice - 139 and 445 - 445 is the only service that returns results - STOP hydra from running 139
# TODO: Pipe any SMB credentials found back into Enum4Linux
# TODO: Command to parse credential findings from Hydra and parse them into ../credentals.txt
# TODO: The findings list can also leverage a regular expression to extract a substring from each line of a findings file
# TODO: remove exploit search function and merge with enumerate function
# TODO: getting false positives from Nikto - Nmap0
# -0.Shell Shock Script against specific folder paths
# nmap 10.11.1.71 -p 80 \
#  --script=http-shellshock \
#  --script-args uri=/cgi-bin/test.cgi --script-args uri=/cgi-bin/admin.cgi
# TODO: Exploit Apache Mod CGI - cp /usr/share/exploitdb/platforms/linux/remote/34900.py ./Documents/EXploitz/Apache_Mod_CGI.py
# TODO: shell shock exploit curl -H 'User-Agent: () { :; }; echo "CVE-2014-6271 vulnerable" bash -c id' http://10.11.1.71/cgi-bin/admin.cgi
# TODO: Append the exact command that is used to the output text files for easy refernce in documentation
# TODO: Create a suggest only mode that dumps a list of commands to try rather than running anything
# TODO: Add color and -color -colour flags to disable it

# TODO: Finish exploitation dynamic replacements from user credentials list
# TODO: More to be done with HTTP enumeration and service identification / exploit searches
# TODO: Move HTTP_NMAP_WEB_SCAN
# TODO: Add config file findings replacers to run on findings after initial results to clean up data for further enumeration (ex. user credentials, and whatweb service findings)
# TODO: hash / bas64 finder / flag post process searching
# TODO: Nmap http enum - include?  or is this redundant at this point?
# TODO: Add Metasploit style summary table with number of services, commands, phases etc.
# 1. NMAP Scan
# 2. Service Enumeration Scan
# 3. Finds relavant exploits and copies to a subfolder
# 3. Word list creation 1st pass
#       Banner Grabx
#       HTTP Enum
#       TODO: Spider site
#       TODO: HTTP Download all assets
#       TODO: Image Scan - Meta / Steg / OCRd
#       TODO: Grab screen shots of pages found
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
from parser import ParserError

__version__ = '0.29'
__lastupdated__ = 'March 18, 2018'
__nmap_folder__ = 'Nmap'
__findings_label__ = 'findings'
__accounce_label__ = 'announce'
__password_list_label__ = 'passwordlist'
__urlshttp_list_label__ = 'urlshttp'
__urlshttps_list_label__ = 'urlshttps'
__findings_label_dynamic__ = 'Findings'
__findings_label_list_dynamic__ = 'FindingsList'

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
import operator
from pprint import pformat
from pprint import pprint
from shutil import copyfile
import json
import xml.etree.ElementTree as ET
from multiprocessing.dummy import Pool as ThreadPool
from subprocess import Popen, PIPE, STDOUT
from datetime import datetime

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
        self.empty_char = empty_char
        self.filled_char = filled_char
        self.expected_size = expected_size
        self.every = every
        self.start = time.time()
        self.ittimes = []
        self.eta = 0
        self.etadelta = time.time()
        self.etadisp = self.format_time(self.eta)
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
                [-(self.start - time.time()) / (progress + 1)]
            self.eta = \
                sum(self.ittimes) / float(len(self.ittimes)) * \
                (self.expected_size - progress)
            self.etadisp = self.format_time(self.eta)
        x = int(self.width * progress / self.expected_size)
        if not self.hide:
            if ((progress % self.every) == 0 or  # True every "every" updates
                    (progress == self.expected_size)):  # And when we're done
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


class Logger:
    DEBUG = False
    VERBOSE = False
    DEBUG_FILE = None
    VERBOSE_FILE = None

    @staticmethod
    def debug(msg):
        if Logger.DEBUG_FILE is not None:
            Logger.DEBUG_FILE.write(msg + '\n')
        elif Logger.DEBUG == True:
            print("[!] " + msg)

    @staticmethod
    def verbose(msg):
        if Logger.VERBOSE_FILE is not None:
            Logger.VERBOSE_FILE.write(msg + '\n')
        elif Logger.VERBOSE == True:
            print("[*] " + msg)


class Color:

    ENABLE_COLOR = True

    @staticmethod
    def redback():
        if Color.ENABLE_COLOR:
            return "\033[0m\033[37m\033[41m"
	else: return ""

    @staticmethod
    def black():
        if Color.ENABLE_COLOR:
            return '\033[0;30m'
	else: return ""

    @staticmethod
    def red():
        if Color.ENABLE_COLOR:
            return '\033[0;31m'
	else: return ""

    @staticmethod
    def green():
        if Color.ENABLE_COLOR:
            return '\033[0;32m'
	else: return ""

    @staticmethod
    def yellow():
        if Color.ENABLE_COLOR:
            return '\033[0;33m'
	else: return ""

    @staticmethod
    def blue():
        if Color.ENABLE_COLOR:
            return '\033[0;34m'
	else: return ""

    @staticmethod
    def magenta():
        if Color.ENABLE_COLOR:
            return '\033[0;35m'
	else: return ""

    @staticmethod
    def cyan():
        if Color.ENABLE_COLOR:
            return '\033[0;36m'
	else: return ""

    @staticmethod
    def grey():
        if Color.ENABLE_COLOR:
            return '\033[0;37m'
	else: return ""

    @staticmethod
    def white():
        if Color.ENABLE_COLOR:
            return '\033[0;38m'
	else: return ""

    @staticmethod
    def reset():
        if Color.ENABLE_COLOR:
            return '\033[0;39m'
	else: return ""

class Vanquish:
    def __init__(self, argv):
        self.banner()
        print(Color.green()+"Vanquish Version: " + __version__ + " Updated: " + __lastupdated__ +Color.reset())
        self.parser = argparse.ArgumentParser(
            description='Vanquish is Kali Linux based Enumeration Orchestrator.')
        self.parser.add_argument("-install", action='store_true',
                                 help='Install Vanquish and it\'s requirements')
        self.parser.add_argument("-outputFolder", metavar='folder', type=str, default="",
                                 help='output folder path (default: name of the host file))')
        self.parser.add_argument("-configFile", metavar='file', type=str, default="config.ini",
                                 help='configuration ini file (default: %(default)s)')
        self.parser.add_argument("-attackPlanFile", metavar='file', type=str, default="attackplan.ini",
                                 help='attack plan ini file (default: %(default)s)')
        self.parser.add_argument("-hostFile", metavar='file', type=argparse.FileType("r"), default="hosts.txt",
                                 help='list of hosts to attack (default: %(default)s)')
        self.parser.add_argument("-workspace", metavar='workspace', type=str, default="",
                                 help='Metasploit workspace to import data into (default: is the host filename)')
        self.parser.add_argument("-domain", metavar='domain', type=str, default="megacorpone.com",
                                 help='Domain to be used in DNS enumeration (default: %(default)s)')
        self.parser.add_argument("-dnsServer", metavar='dnsServer', type=str, default="",
                                 help='DNS server option to use with Nmap DNS enumeration. Reveals the host names of'
                                      ' each server (default: %(default)s)')
        self.parser.add_argument("-proxy", metavar='proxy', type=str, default="",
                                 help='Proxy server option to use with scanning tools that support proxies. Should be '
                                      ' in the format of ip:port (default: %(default)s)')
        self.parser.add_argument("-reportFile", metavar='report', type=str, default="report.txt",
                                 help='filename used for the report (default: %(default)s)')
        self.parser.add_argument("-noResume", action='store_true', help='do not resume a previous session')
        self.parser.add_argument("-noColor", action='store_true', help='do not display color')
        self.parser.add_argument("-threadPool", metavar='threads', type=int, default="8",
                                 help='Thread Pool Size (default: %(default)s)')
        self.parser.add_argument("-phase", metavar='phase', type=str, default='', help='only execute a specific phase')
        self.parser.add_argument("-noExploitSearch", action='store_true', help='disable searchspolit exploit searching')
        self.parser.add_argument("-benchmarking", action='store_true',
                                 help='enable bench mark reporting on the execution time of commands(exports '
                                      'to benchmark.csv)')
        self.parser.add_argument("-logging", action='store_true', help='enable verbose and debug data logging to files')
        self.parser.add_argument("-verbose", action='store_true', help='display verbose details during the scan')
        self.parser.add_argument("-debug", action='store_true', help='display debug details during the scan')

        self.args = self.parser.parse_args()
        self.hosts = self.args.hostFile

        # Installation Setup
        if self.args.install:
            self.args.configFile = "install.ini"
            self.args.attackPlanFile = "installplan.ini"

        # load config
        self.config = ConfigParser.ConfigParser()
        self.config.read(self.args.configFile)

        Logger.VERBOSE = (self.config.getboolean("System", "Verbose") or self.args.verbose)
        Logger.DEBUG = (self.config.getboolean("System", "Debug") or self.args.debug)

        # Default output location
        if self.args.outputFolder == "":
            self.args.outputFolder = "." + os.path.sep + str(self.args.hostFile.name).split(".")[0]

	    # Nmap scan output folder
        self.nmap_path = os.path.join(self.args.outputFolder, __nmap_folder__)

        # Check folder for existing output and nmap folders
        if not os.path.exists(self.args.outputFolder):
            os.makedirs(self.args.outputFolder)
        elif not self.args.noResume:
            print Color.yellow()+"[*]"+Color.reset()+" Resuming previous session"

        if not os.path.exists(self.nmap_path):
                os.makedirs(self.nmap_path)

        if self.args.noColor:
            Color.ENABLE_COLOR = False;

        # Metasploit workspace name - the workspace name is the name of the host file minus it's extension
        if self.args.workspace == "":
            self.workspace = str(self.args.hostFile.name).split(".")[0]
        else:
            self.workspace = self.args.workspace

        # load attack plan
        self.plan = ConfigParser.ConfigParser()
        self.plan.read(self.args.attackPlanFile)

        self.nmap_dns_server = ""
        if self.args.dnsServer != "":
            self.nmap_dns_server = " --dns-server "+self.args.dnsServer

        self.proxy_server = ""
        if self.args.proxy != "":
            self.proxy_server = " --proxy "+self.args.proxy

        # Master NMAP Data Structure Dict
        self.nmap_dict = {}

        # current enumeration phase command que
        self.phase_commands = []

        # announced vulnerabilities - Prevent findings from being reported multiple times
        self.announced = {}
        # calculate risk scores as we enumerate
        self.risk_score = {}
        # track that these commands are only run once per phase
        self.run_once = {}

        # Current Thread Pool command contents
        self.thread_pool_commands = []
        self.thread_pool_errors = []

        # Lists discovered during enumeration
        self.findings = {'users': [], 'urls': [], 'groups': [], 'passwords': [], 'vulnerabilities': []}

        # write errors to error log rather than display them on screen
        self.command_error_log = open("commanderrorlog.txt", 'w')
        self.active_commands = "activecommands.txt"
        if self.args.logging:
            self.debug_log = open("debuglog.txt", 'w')
            self.verbose_log = open("verboselog.txt", 'w')
            Logger.DEBUG_FILE = self.debug_log
            Logger.VERBOSE_FILE = self.verbose_log

        if self.args.benchmarking:
            self.benchmarking_csv = open("benchmark.csv", 'w')
            self.benchmarking_csv.write("TIME,COMMAND\n")
        #sys.stderr = self.command_error_log
        self.devnull = open(os.devnull, 'w')

        
    # Parse Nmap XML - Reads all the Nmap xml files in the Nmap folder
    def parse_nmap_xml(self):
        Logger.verbose("[+] Reading Nmap XML Output Files...")
        port_attribs_to_read = ['protocol', 'portid']
        service_attribs_to_read = ['name', 'product', 'version', 'extrainfo', 'method', 'tunnel']
        state_attribs_to_read = ['state', 'reason']
        xml_nmap_elements = {'service': service_attribs_to_read, 'state': state_attribs_to_read}
        search_address = {'path': 'address', 'el': 'addr'}
        search_ports = {'path': 'ports', 'el': 'portid'}
        nmap_output_path = os.path.join(self.args.outputFolder, __nmap_folder__)
        for nmap_file in os.listdir(nmap_output_path):
            if nmap_file.endswith(".xml"):
                nmap_file_path = os.path.join(nmap_output_path, nmap_file)
                Logger.debug("XML PARSE: " + nmap_file_path)
                try:
                    tree = ET.parse(nmap_file_path)
                except:
                    Logger.debug("XML PARSE: Error Parsing : " + nmap_file_path)
                    continue
                root = tree.getroot()
                for i in root.iter('host'):
                    e = i.find(search_address['path'])
                    find_ports = i.find(search_ports['path'])
                    if find_ports is not None:
                        addr = e.get(search_address['el'])
                        if self.nmap_dict.get(addr, None) is None: self.nmap_dict[addr] = {}
                        port_dict = []
                        for port in find_ports.iter('port'):
                            element_dict = {}
                            attribute_dict = {}
                            self.xml_to_dict(port_attribs_to_read, port, element_dict)
                            for xml_element in xml_nmap_elements:
                                for attribute in port.iter(xml_element):
                                    if attribute is not None:
                                        self.xml_to_dict(xml_nmap_elements[xml_element], attribute, attribute_dict)
                                        element_dict = self.merge_two_dicts(element_dict, attribute_dict)
                                        if attribute.get('hostname', '') is not '':
                                            self.nmap_dict[addr]['hostname'] = attribute.get('hostname', '')
                                        if attribute.get('tunnel', '') == 'ssl' and attribute.get('name', '') == 'http':
                                            element_dict['name'] = 'https'
                                        # If we have encountered an unknown service set the name to unknown so we can still enum
                                        if attribute.get('name', None) is None:
                                            for attrib_name in service_attribs_to_read:
                                                element_dict[attrib_name] = ''
                                            element_dict['name'] = 'unknown'
                            # Check to see if this port already exists
                            port_was_merged = False
                            if self.nmap_dict[addr].get('ports', None) is not None:
                                for pos, port in enumerate(self.nmap_dict[addr]['ports']):
                                    if port['portid'] == element_dict['portid']:
                                        port_was_merged = True
                                        for element in service_attribs_to_read:
                                            if len(element_dict[element]) > 0: self.nmap_dict[addr]['ports'][pos][element] = element_dict[element]
                            if port_was_merged is False:
                                port_dict.append(element_dict)
                        if self.nmap_dict[addr].get('ports', None) is None:
                            self.nmap_dict[addr]['ports'] = port_dict
                        else:
                            self.nmap_dict[addr]['ports'] = self.nmap_dict[addr]['ports'] + port_dict
            Logger.debug("NMAP XML PARSE: - Finished NMAP Dict Creation:\n " + str(self.nmap_dict))

    @staticmethod
    def merge_two_dicts(x, y):
        z = x.copy()
        z.update(y)
        return z

    # find exploits from exploit db and copy them to service folder
    # TODO: Copy results to service folders - update nmap_dict with other web app etc products and versions...
    def exploit_search(self, command_label):
        if self.args.noExploitSearch: return False
        Logger.debug("exploit_search()")
        for host in self.nmap_dict:
            for service in self.nmap_dict[host]['ports']:
                if service.get('product', '') is not '' and service.get('version', '') is not '':
                    version_digits = ' '.join(str(x) for x in re.findall(r'\d+', service.get('version', '')))
                    command_keys = {
                        'output': self.get_enumeration_path(host, service['name'], service['portid'], command_label),
                        'target': service.get('product', '')}
                    base, filename = os.path.split(command_keys['output'])  # Resume file already exists
                    if not self.args.noResume and self.find_files(base, filename + ".*").__len__() > 0:
                        Logger.debug("exploit_search() -Exploit Search file already exists: "
                                     + command_keys['output'])
                    else:
                        self.execute_command(self.prepare_command(command_label, command_keys))
                        with open(command_keys['output'] + ".json") as data_file:
                            try:
                                data = json.load(data_file)
                            except:
                                continue
                            if len(data['RESULTS']) == 0:
                                os.remove(command_keys['output'] + ".json")
                            else:  # copy exploits to exploit folder
                                exploits_path = os.path.join(base, "exploits")
                                if not os.path.exists(exploits_path): os.makedirs(exploits_path)
                                for exploit in data['RESULTS']:
                                    exploit_base, exploit_filename = os.path.split(exploit['Path'])
                                    copyfile(exploit['Path'], os.path.join(exploits_path, exploit_filename))

    # Enumerate a phase
    # phases are defined in attackplan.ini
    # enumerate will create a que of all the commands to run in a phase
    # then it will create a progress bar and execute a specified number of threads at the same time
    # until all the threads are finished then the results are parsed by another function
    def enumerate(self, phase_name):
        Logger.debug("Enumerate - " + phase_name)
        self.phase_commands = []
        self.thread_pool_errors = []
        for host in self.nmap_dict:
            Logger.debug("enumerate() - Host: " + host)
            host_ports = [d['portid'] for d in self.nmap_dict[host]['ports'] if 'portid' in d]
            if self.plan.has_option(phase_name, 'always'):
                self.nmap_dict[host]['ports'].append(
                    {'state': 'open', 'name': 'always', 'portid': '0', 'product': 'Vanquish Added Always Service'})
            if self.plan.has_option(phase_name, 'run once'):
                if self.run_once.get(phase_name) is None:
                    self.run_once[phase_name] = host
                    self.nmap_dict[host]['ports'].append(
                        {'state': 'open', 'name': 'run once', 'portid': '-1', 'product': 'Vanquish Added Run Once Service'})
            for service in self.nmap_dict[host]['ports']:
                Logger.debug("\tenumerate() - port_number: " + str(service))
                for known_service, ports in self.config.items('Service Ports'):
                    if not ('closed' in service['state'] or 'filtered' in service['state']) \
                            and (service['name'].find(known_service) <> -1 or service['portid'] in ports.split(',')):
                        if self.plan.has_option(phase_name, known_service):
                            for command_label in self.plan.get(phase_name, known_service).split(','):
                                if command_label is not '':
                                    command_keys = {
                                        'output': self.get_enumeration_path(host, service['name'], service['portid'],
                                                                            command_label),
                                        'output folder': self.args.outputFolder,
				 	'output nmap': os.path.join(self.nmap_path,command_label.replace(" ", "_") + "_" + host.replace(".", "_")),
                                        'target': host,
                                        'domain': self.args.domain,
                                        'service': service['name'],
                                        'port': service['portid'],
                                        'host ports comma': ",".join(host_ports),
                                        'host ports space': " ".join(host_ports),
                                        'host file': self.args.hostFile.name,
                                        'nmap dns server': self.nmap_dns_server,
                                        'nmap proxy server': self.proxy_server,
                                        'proxy server': self.args.proxy,
                                        'workspace': self.workspace,
                                    }
                                    base, filename = os.path.split(command_keys['output'])  # Resume file already exists
                                    if not self.args.noResume and self.find_files(base, filename + ".*").__len__() > 0:
                                        Logger.debug("enumerate() - RESUME - output file already exists: "
                                                     + command_keys['output'])
                                    else:
                                        command = self.prepare_command(command_label, command_keys)
                                        # TODO: Check for dictionary tags / list tags / findings lists
                                        do_not_append = False
                                        if "<"+__findings_label_dynamic__+" " in command:
                                            findings_path = os.path.join(self.args.outputFolder,host.replace(".","_"))
                                            findings_files = self.find_files(findings_path, "*.txt")
                                            for findings_file in findings_files:
                                                replacement = "<"+__findings_label_dynamic__+ " " +str(findings_file).replace(".txt","")+">"
                                                if replacement in command:
                                                    findings_file_path = os.path.join(findings_path,findings_file)
                                                    command = command.replace(replacement, findings_file_path)
                                        # Still have a findings tag in the command?  do not add it to the list -
                                        if "<" + __findings_label_dynamic__ + " " in command:
                                            do_not_append = True
                                            Logger.debug("enumerate() - Did not append command that still contained findings label" + command )
                                        # Findings Lists
                                        if "<" + __findings_label_list_dynamic__ + " " in command:
                                            findings_path = os.path.join(self.args.outputFolder, host.replace(".", "_"))
                                            findings_files = self.find_files(findings_path, "*.txt")
                                            for findings_file in findings_files:
                                                replacement = "<" + __findings_label_list_dynamic__ + " " + str(
                                                    findings_file).replace(".txt", "") + ">"
                                                #TODO Delimited Findings ? REGEX Delim
                                                #delim = "<" + __findings_label_dynamic__ + " " + str(findings_file).replace(".txt", "") + " .+>"
                                                if replacement in command:
                                                    findings_file_path = os.path.join(findings_path, findings_file)
                                                    with open(findings_file_path) as f:
                                                        content = [x.strip() for x in f.readlines()]
                                                        for line in content:
                                                            new_command = command
                                                            new_command = new_command.replace(replacement, line)
                                                            self.phase_commands.append(new_command)
                                        # Lists
                                        for section in self.config.sections():
                                            if "List" in section:
                                                if command.find(
                                                                        "<" + section + ">") <> -1:  # include entire list from section
                                                    do_not_append = True
                                                    for item in self.config.items(section):
                                                        new_command = command
                                                        new_command = new_command.replace("<" + section + ">", item[1])
                                                        self.phase_commands.append(new_command)
                                                else:
                                                    for item in self.config.items(section):
                                                        command = command.replace("<" + item[0] + ">", item[1])
                                        if not do_not_append and "<"+__findings_label_dynamic__ not in command:
                                            self.phase_commands.append(command)
                                            Logger.debug("enumerate() - added command : " + command_label)
                                        else:
                                            Logger.debug("enumerate() - skipped command : " + command_label)
                        else:
                            Logger.debug("\tenumerate() - NO command section found for phase: " + phase_name +
                                         " service name: " + known_service)
        self.phase_commands = self.remove_duplicates(self.phase_commands)
        pool = ThreadPool(self.args.threadPool)
        for _ in bar(pool.imap_unordered(self.execute_command, self.phase_commands),
                     expected_size=len(self.phase_commands)):
            pass
        pool.close()
        pool.join()

    @staticmethod
    def remove_duplicates(list_with_duplicates):
        return list(set(list_with_duplicates))

    def execute_command(self, command):
        Logger.verbose("root@kali:/# " + command)
        Logger.debug("execute_command() - Starting: - " + command)
        command_start_time = time.time()
        with open(self.active_commands, 'w') as active_command_report_file:
            active_command_report_file.write("Last Update: " + str(datetime.now()) + "\n")
            active_command_report_file.write(pformat(self.thread_pool_commands, indent=4, width=1))
        self.thread_pool_commands.append(command)
        process = Popen(command, shell=True, stdin=PIPE, stderr=self.command_error_log, stdout=self.devnull)
        process.stdin.close()
        # FIXME: Process wait is causing the application to hang in some fringe cases - need to find a better way
        if process.wait() != 0:
            Logger.debug("execute_command() - ERRORS EXECUTING:  - " + command)
            self.thread_pool_errors.append(command)
        Logger.debug("execute_command() - COMPLETED! - " + command)
        self.thread_pool_commands.remove(command)
        if self.args.benchmarking:
            with open(self.active_commands, 'w') as active_command_report_file:
                active_command_report_file.write("Last Update: "+ str(datetime.now())+"\n")
                active_command_report_file.write(pformat(self.thread_pool_commands, indent=4, width=1))
            self.benchmarking_csv.write(
                time.strftime('%H:%M:%S', time.gmtime(time.time() - command_start_time)) + "," + command.replace(",",
                                                                                                                 " ") + "\n")

    def enumerate_plan(self, plan):
        for phase in self.plan.get(plan, "Order").split(","):
            print Color.green()+"[+]"+Color.reset()+" Starting Phase: " + phase
            Logger.verbose("[+] Starting Phase: " + phase)
            try:
                if self.args.phase == phase or self.args.phase == '': self.enumerate(phase)
            except KeyboardInterrupt:
                Logger.debug("[X] Keyboard Interrupt Detected... exiting phase:: " + phase)
                Logger.debug("[X] Thread Pool at Interrupt: \n" + pformat(self.thread_pool_commands))
                print Color.red()+"[X]"+Color.reset()+" Keyboard Interrupt Detected... exiting phase: " + phase
                print Color.red()+"[X]"+Color.reset()+" Thread Pool at Interrupt:"
                pprint(self.thread_pool_commands)
                continue
            except ValueError as err:
                bar(self.phase_commands, expected_size=len(self.phase_commands))
                if len(self.thread_pool_errors) > 0:
                    Logger.debug("[X] Phase completed but encountered the following errors:  \n"
                                 + pformat(self.thread_pool_errors) + pformat(self.thread_pool_commands))
                    print Color.red()+"[X]"+Color.reset()+" Phase completed but encountered the following errors: \n" \
                          + pformat(self.thread_pool_errors) + pformat(self.thread_pool_commands)
                continue
	    self.parse_nmap_xml()
	    self.write_report_file(self.nmap_dict, self.args.outputFolder, self.args.reportFile)
            Logger.verbose("[+] Finding's Post Processing...")
            self.findings_post_processing()


    def findings_post_processing(self):
        for current_host in self.hosts:
            host_path = os.path.join(self.args.outputFolder, current_host.replace(".", "_"))
            files_to_process = [os.path.join(dp, f) for dp, dn, fn in os.walk(os.path.expanduser(host_path))
                                for f in fn]
            self.findings = {'users': [], 'urls': [], 'groups': [], 'passwords': [], 'vulnerabilities': []}
            # TODO: Load findings from files here for merging - dont overwrite user added findings...

            for file in files_to_process:
                base, filename = os.path.split(file)
                if base.endswith(__nmap_folder__): continue
                file_segments = filename.split("_")
                file_segments.pop()
                config_command_name = " ".join(file_segments)
                if self.config.has_section(config_command_name):
                    for item in self.config.items(config_command_name):
                        if __findings_label__ in item[0]:
                            list_type = str(item[0]).split(" ")[1]
                            list_type = ''.join([i for i in list_type if not i.isdigit()]) # remove digits in item name
                            if self.findings.get(list_type) is None: self.findings[list_type] = []
                            regex = re.compile(item[1])
                            # First try line by line
                            wholefile = ""
                            with open(file) as f:
                                for line in f:
                                    wholefile += line
                                    match = regex.match(line)
                                    if match is not None:
                                        self.findings[list_type].append(match.group(1))
                                        announcement = current_host + ":  \t" + match.group(1);
                                        if __accounce_label__ in item[0] and self.announced.get(announcement) != 1:
                                            self.announced[announcement] = 1
                                            print Color.redback() + "[!] " + announcement + \
                                                  " " + re.sub(__findings_label__ + " " + __accounce_label__+ "\d*","",str(item[0])) \
                                                  + Color.reset()

                            # Next try multiline search mode
                            matches = re.search(item[1], wholefile, re.MULTILINE)
                            if matches and matches.group(1) is not None:
                                self.findings[list_type].append(matches.group(1))
                                announcement = current_host + ":  \t" + matches.group(1);
                                if __accounce_label__ in item[0] and self.announced.get(announcement) != 1:
                                    self.announced[announcement] = 1
                                    print Color.redback() + "[!] " +  announcement +\
                                          " " + re.sub(__findings_label__ + " " + __accounce_label__+ "\d*","",str(item[0])) +\
                                          Color.reset()
            # Remove duplicates and output results to findings files
            for findings_list in self.findings:
                self.findings[findings_list] = self.remove_duplicates(self.findings[findings_list])
                self.findings[findings_list].sort()
                if len(self.findings[findings_list]) > 0:
                    with open(os.path.join(host_path, findings_list + ".txt"), 'w') as findings_file:
                        findings_file.write("\n".join(self.findings[findings_list]))
            # Calculate Risk Score
            risk_score = 0
            for findings_list in self.findings:
                risk_score += len(self.findings.get(findings_list, [])) * 1
            if len(self.findings.get(__accounce_label__, [])) > 0:
                risk_score += 1000
            risk_score -= len(self.findings.get(__password_list_label__,[]))
            risk_score -= len(self.findings.get(__urlshttp_list_label__, []))
            risk_score -= len(self.findings.get(__urlshttps_list_label__, []))
            if len(self.findings.get(__urlshttp_list_label__, [])) > 20:
                risk_score += 20
            else:
                risk_score += len(self.findings.get(__urlshttp_list_label__, []))
            if len(self.findings.get(__urlshttps_list_label__, [])) > 20:
                risk_score += 20
            else:
                risk_score += len(self.findings.get(__urlshttps_list_label__, []))
            self.risk_score[current_host] = risk_score

    def get_enumeration_path(self, host, service, port, command):
        ip_path = os.path.join(self.args.outputFolder, host.replace(".", "_"))
        if not os.path.exists(ip_path): os.makedirs(ip_path)
        service_path = os.path.join(ip_path, service)
        if not os.path.exists(service_path): os.makedirs(service_path)
        return os.path.join(service_path, command.replace(" ", "_") + "_" + str(port))

    def prepare_command(self, command, keyvalues):
        command = self.config.get(command, "command")
        Logger.debug("prepare_command() command: " + command)
        for k in keyvalues.iterkeys():
            Logger.debug("    prepare_command() key: " + k)
            command = command.replace("<" + k + ">", keyvalues[k])
        return command

    def xml_to_dict(self, list_to_read, xml_elements, dict):
        for element in list_to_read:
            value = xml_elements.get(element, '')
            if element is "name" and self.config.has_option("Service Labels", value):
                dict[element] = self.config.get("Service Labels", value)
            else:
                dict[element] = value
        return dict

    def write_report_file(self, data, folder, file):
        report_path = os.path.join(folder,file)
        f = open(report_path, 'w')
        f.write(pformat(data, indent=4, width=1))
        f.close()

    def write_csv_report_file(self, data, header, folder, file):
        report_path = os.path.join(folder,file)
        f = open(report_path, 'w')
        f.write(header)
        for item in data:
            f.write(str(item[0])+","+str(item[1])+"\n")
        f.close()

    def find_files(self, base, pattern):
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
        print Color.red()+'\n' \
              '                  )             (   (       )  '
        print '         (     ( /(   (         )\ ))\ ) ( /(  '
        print ' (   (   )\    )\())( )\     ( (()/(()/( )\()) '
        print ' )\  )((((_)( ((_)\ )((_)    )\ /(_))(_)|(_)\  '
        print '((_)((_)\ _ )\ _((_|(_)_  _ ((_|_))(_))  _((_) '
        print '\ \ / /(_)_\(_) \| |/ _ \| | | |_ _/ __|| || | '
        print ' \ V /  / _ \ | .` | (_) | |_| || |\__ \| __ | '
        print '  \_/  /_/ \_\|_|\_|\__\_\\\\___/|___|___/|_||_| '
        print 'Get to shell.'+Color.reset()

    @staticmethod
    def banner_doom():
        print Color.yellow()+'\n ' \
               '__      __     _   _  ____  _    _ _____  _____ _    _ '
        print ' \ \    / /\   | \ | |/ __ \| |  | |_   _|/ ____| |  | |'
        print '  \ \  / /  \  |  \| | |  | | |  | | | | | (___ | |__| |'
        print '   \ \/ / /\ \ | . ` | |  | | |  | | | |  \___ \|  __  |'
        print '    \  / ____ \| |\  | |__| | |__| |_| |_ ____) | |  | |'
        print '     \/_/    \_\_| \_|\___\_\\\\____/|_____|_____/|_|  |_|'
        print 'Set your Mertilizers on "deep fat fry".'+Color.reset()

    @staticmethod
    def banner_block():
        print Color.magenta()+'' \
            '\n __   ___   _  _  ___  _   _ ___ ___ _  _ '
        print ' \ \ / /_\ | \| |/ _ \| | | |_ _/ __| || |'
        print '  \ V / _ \| .` | (_) | |_| || |\__ \ __ |'
        print '   \_/_/ \_\_|\_|\__\_\\\\___/|___|___/_||_|'
        print 'Faster than a one-legged man in a butt kicking contest.'+Color.reset()

    ##################################################################################
    # Entry point for command-line execution
    ##################################################################################

    @property
    def main(self):
        start_time = time.time()
        print Color.cyan()
        print("Configuration file: " + str(self.args.configFile))
        print("Attack plan file:   " + str(self.args.attackPlanFile))
        print("Output Path:        " + str(self.args.outputFolder))
        print("Host File:          " + str(self.args.hostFile.name))
        print Color.reset()
        Logger.debug("DEBUG MODE ENABLED!")
        Logger.verbose("VERBOSE MODE ENABLED!")

        self.hosts = self.hosts.read().splitlines()
        Logger.verbose("Hosts:" + str(self.hosts))
        for host in self.hosts:
            self.nmap_dict[host] = { "ports": [] };

        for scan_phase in self.plan.get("Nmap Scans", "Order").split(","):
            if scan_phase is not '': self.enumerate_plan(scan_phase)
            self.enumerate_plan("Enumeration Plan")

        # Begin Post Enumeration Phases
        print Color.grey()+"[+]"+Color.reset()+" Starting post enumeration..."
        self.enumerate_plan("Post Enumeration Plan")

        try:
            print Color.grey()+"[+]"+Color.reset()+" Searching for matching exploits..."
            self.exploit_search("SearchSploit JSON")
        except:
            bar(self.phase_commands, expected_size=len(self.phase_commands))

        # Generate Reports
        sorted_x = sorted(self.risk_score.items(), key=operator.itemgetter(1))
        self.write_csv_report_file(sorted_x, "Host,Risk Score\n", self.args.outputFolder, "riskscores.csv")

        print Color.grey()+"[+]"+Color.reset()+" Elapsed Time: " + time.strftime('%H:%M:%S', time.gmtime(time.time() - start_time))
        Logger.verbose("Goodbye!")
        self.command_error_log.close()
        if self.args.logging:
            self.debug_log.close()
            self.verbose_log.close()

        if self.args.benchmarking:
            self.benchmarking_csv.close()
        return 0



def main(argv=None):
    vanquish = Vanquish(argv if argv else sys.argv[1:])
    return vanquish.main


if __name__ == "__main__":
    sys.exit(main())
