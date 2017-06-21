# Vanquish
Multithreaded Kali Linux scanning and enumeration automation platform.
Designed to systematically enumerate and exploit using the law of diminishing returns.
Includes :
  * Nmap Scanning
  * GoBuster
  * Nikto
  * SSH
  * mySQL
  * MSSql
  * RDP
  * SMB
  * SMTP
  * SNMP
  * SSH
  * FTP
  * DNS
  * Web
 
Vanquish Version: 0.9 Updated: June 18, 2017

  Use the -h parameter for help.
  
usage: Vanquish2.py [-h] [-outputFolder folder] [-configFile file]

                    [-attackPlanFile file] [-hostFile file] [-domain domain]
                    
                    [-reportFile report] [-noResume] [-threadPool threads]
                    
                    [-phase phase] [-noExploitSearch] [-logging] [-verbose]
                    
                    [-debug]
                    


Root2Boot automation platform designed to systematically enumernate and

exploit using the law of diminishing returns.


optional arguments:

  -h, --help            show this help message and exit
  
  -outputFolder folder  output folder path (default: ./output)
  
  -configFile file      configuration ini file (default: config.ini)
  
  -attackPlanFile file  attack plan ini file (default: attackplan.ini)
  
  -hostFile file        list of hosts to attack (default: hosts.txt)
  
  -domain domain        domain to use in DNS enumeration (default: thinc.local)
  
  -reportFile report    filename used for the report (default: report.txt)
  
  -noResume             do not resume a previous session
  
  -threadPool threads   Thread Pool Size (default: 8)
  
  -phase phase          only execute a specific phase
  
  -noExploitSearch      disable searchspolit exploit searching
  
  -logging              enable verbose and debug data logging to files
  
  -verbose              display verbose details during the scan
  
  -debug                display debug details during the scan
  
