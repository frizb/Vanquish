# Vanquish – Get to Shell

<p align="center">
  <img src="https://raw.githubusercontent.com/frizb/Vanquish/master/Vanquish.png" title="Vanquish - Kali Linux Enumeration Orchestrator"/>
</p>

Vanquish is a Kali Linux based Enumeration Orchestrator built in Python.  Vanquish leverages the opensource enumeration tools on Kali to perform multiple active information gathering phases. The results of each phase are fed into the next phase to identify vulnerabilities that could be leveraged for a remote shell.  

[![asciicast](https://asciinema.org/a/AoAay13XL1qJuy35jt45FCIzp.png)](https://asciinema.org/a/AoAay13XL1qJuy35jt45FCIzp)

## Vanquish Features
So what is so special about Vanquish compared to other enumeration scripts?

1.	**Multi-threaded** – Runs multiple commands and scans multiple hosts simultaneously.
2.	**Configurable** – All commands are configured in a separate .ini file for ease of adjustment
3.	**Multiphase** – Optimized to run the fastest enumeration commands first in order to get actionable results as quickly as possible.
4.	**Intelligent** – Feeds the findings from one phase into the next in order to uncover deeper vulnerabilities.
5.	**Modular** – New attack plans and commands configurations can be easily built for fit for purpose enumeration orchestration.

## Getting Started

Vanquish can be installed on Kali Linux using the following commands:

    git clone https://github.com/frizb/Vanquish
    cd Vanquish
    python Vanquish2.py -install
    vanquish --help

[![asciicast](https://asciinema.org/a/87e2AIjr9ZVF6RM8B9ObDNcEX.png)](https://asciinema.org/a/87e2AIjr9ZVF6RM8B9ObDNcEX)

Once Vanquish is installed you can scan hosts by leveraging the best of breed Kali Linux tools:

    echo 192.168.126.133 >> test.txt
    vanquish -hostFile test.txt -logging
    echo review the results!
    cd test
    cd 192_168_126_133
    ls -la

## What Kali Tools does Vanquish leverage?
| NMap | Hydra | Nikto | Metasploit |
| Gobuster | Dirb | Exploitdb | Nbtscan |
| Ntpq | Enum4linux | Smbclient | Rpcclient |
| Onesixtyone | Sslscan | Sslyze | Snmpwalk |
| Ident-user-enum | Smtp-user-enum | Snmp-check | Cisco-torch |
| Dnsrecon | Dig | Whatweb | Wafw00f |
| Wpscan | Cewl  | Curl | Mysql | Nmblookup | Searchsploit |
| Nbtscan-unixwiz | Xprobe2 | Blindelephant | Showmount |

## Running Vanquish

- **CTRL + C**

    CTRL + C to exit an enumeration phase and skip to the next phase (helpful if a command is taking too long)
    Vanquish will skip running a command again if it sees that the output files already exist.
    If you want to re-execute a command, delete the output files (.txt,.xml,.nmap etc.) and run Vanquish again.

- **CTRL + Z**

    CTRL + Z to exit Vanquish.
    
- **Resume Mode**

    Vanquish will skip running a command again if it sees that the output files already exist.

- **Re-run an enumeration command**

    If you want to re-execute a command, delete the output files (.txt,.xml,.nmap etc.) and run Vanquish again.

## Commandline Arguments
<pre>
Command Line Arguments
usage: vanquish [-h] [-install] [-outputFolder folder] [-configFile file]
                [-attackPlanFile file] [-hostFile file] [-workspace workspace]
                [-domain domain] [-dnsServer dnsServer] [-proxy proxy]
                [-reportFile report] [-noResume] [-noColor]
                [-threadPool threads] [-phase phase] [-noExploitSearch]
                [-benchmarking] [-logging] [-verbose] [-debug]

Vanquish is Kali Linux based Enumeration Orchestrator.

optional arguments:
  -h, --help            show this help message and exit
  -install              Install Vanquish and it's requirements
  -outputFolder folder  output folder path (default: name of the host file))
  -configFile file      configuration ini file (default: config.ini)
  -attackPlanFile file  attack plan ini file (default: attackplan.ini)
  -hostFile file        list of hosts to attack (default: hosts.txt)
  -workspace workspace  Metasploit workspace to import data into (default: is
                        the host filename)
  -domain domain        Domain to be used in DNS enumeration (default:
                        megacorpone.com)
  -dnsServer dnsServer  DNS server option to use with Nmap DNS enumeration.
                        Reveals the host names of each server (default: )
  -proxy proxy          Proxy server option to use with scanning tools that
                        support proxies. Should be in the format of ip:port
                        (default: )
  -reportFile report    filename used for the report (default: report.txt)
  -noResume             do not resume a previous session
  -noColor              do not display color
  -threadPool threads   Thread Pool Size (default: 8)
  -phase phase          only execute a specific phase
  -noExploitSearch      disable searchspolit exploit searching
  -benchmarking         enable bench mark reporting on the execution time of
                        commands(exports to benchmark.csv)
  -logging              enable verbose and debug data logging to files
  -verbose              display verbose details during the scan
  -debug                display debug details during the scan
</pre>

## Custom Attack Plans

**GoBuster Max**

GoBuster Max is an attack plan that will run all the web application content detection dictionaries against your targets.

    Vanquish -hostFile test.txt -attackPlanFile ./attackplans/gobuster-max.ini -logging
    
[![asciicast](https://asciinema.org/a/U6TvUgVUhLDI4zRKjLpEaY3Ps.png)](https://asciinema.org/a/U6TvUgVUhLDI4zRKjLpEaY3Ps)

**Hydra Credentials Scanner**

We users love to reuse our passwords across multiple systems. As you explore a network and harvest usernames and passwords, its probably a good idea to check where else those username and passwords are also used.  This attack plan will do exactly that for a single host or across an entire network. Attack plans will also leverage what has been learned about a network from previous scans and will automatically use the discovered services as part of the credential testing.

This attack will use a list of known credentials for a network and test them against all hosts and services that have been discovered.
Store the credentials in a file in the root of your scan path and name it: credentials.txt

Ex. File containing host list: /root/Documents/Vanquish/myhosts.txt
    
    /root/Documents/Vanquish/myhosts/credentials.txt

Store each known credential in username:password format in the text file
Ex. credentials.txt

    elvis:Password!
    jamesdean:rockyou
    justin:12345678

Note: this attack plan does NOT create the >> <output>.txt file so it can be run again and again without havingto delete the output files.  This allows new credentials to be added to the list and the network to be rescanned frequently.

    python Vanquish2.py -hostFile hostlist.txt -attackPlanFile ./attackplans/credentials.ini
    
**Hydra Usernames and Passwords List Scanner**

This attack will use a list of known usernames and a list of known passwords for a network and test them against all hosts and services that have been discovered.

Store the usernames in a file in the root of your scan path and name it: usernames.txt
Ex. File containing host list: /root/Documents/Vanquish/myhosts.txt

    /root/Documents/Vanquish/myhosts/usernames.txt
    
Store the passwords in a file in the root of your scan path and name it: passwords.txt
Ex. File containing host list: /root/Documents/Vanquish/myhosts.txt
    
    /root/Documents/Vanquish/myhosts/passwords.txt
    
Store each username or password on a new line of the text file
Ex. usernames.txt

    elvis
    jamesdean
    justin

Passwords are stored in a similar manner in the passwords.txt file.

Note: this attack plan does NOT create the >> <output>.txt file so it can be run again and again without having to delete the output files.  This allows new credentials to be added to the list and the network to be rescanned frequently.

    python Vanquish2.py -hostFile hostlist.txt -attackPlanFile ./attackplans/usernamespasswords.ini
