"""
This module is responsible for interaction with the nmap tool.
"""
import nmap

def scan(ip):
    targets = []
    range = ip[:-3] + "0-255"
    nm = nmap.PortScanner()
    nm.scan(hosts=range, arguments="-O -n -p445,139")
    hosts = nm.all_hosts()
    for host in hosts:
    	if 'osmatch' in nm[host]:
			host_obj = { 'ip': host, 'osfamily': "", 'osgen': []}
    		for os in nm[host]['osmatch']:
    			for c in os['osclass']:
    				if c['osfamily'] == "Windows":
    					if len(host_obj['osfamily']) == 0:
    						host_obj['osfamily'] = c['osfamily']
    					host_obj['osgen'].append(c['osgen'])
    		if host_obj['osfamily'] == "Windows":
    			targets.append(host_obj)

    return targets

def get_hosts():
    hosts = scan('10.202.208.230')
    print(hosts)

get_hosts()
