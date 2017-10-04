# Vanquish – Get to Shell
Vanquish is Kali Linux based Enumeration Orchestrator.  Vanquish leverages the opensource enumeration tools on Kali to perform multiple active information gathering phases. The results of each phase are fed into the next phase to identify vulnerabilities that could be leveraged for a remote shell.  

## Vanquish Features
So what is so special about Vanquish compared to other enumeration scripts?
  1.	Multi-threaded and scans multiple hosts at once.
  2.	Configurable – all commands are configured in a separate .ini file for ease of adjustment
  3.	Multiphase – Optimized to run the fastest enumeration commands first in order to get actionable results as quickly as possible.
  4.	Intelligent - Feeds the findings from one phase into the next in order to uncover deeper vulnerabilities.

## Getting Started

Vanquish can be installed on Kali Linux using the following commands:

    git clone https://github.com/frizb/Vanquish
    cd Vanquish
    python Vanquish2.py -install
    vanquish --help

<script type="text/javascript" src="https://asciinema.org/a/87e2AIjr9ZVF6RM8B9ObDNcEX.js" id="asciicast-87e2AIjr9ZVF6RM8B9ObDNcEX" async></script>
