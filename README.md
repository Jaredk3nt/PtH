# Pass the Hash -- Ethical Hacking Final Project

PtH functions through three main steps: Discovery, Intrusion, and Collection.

#### Discovery

In the discovery phase the program uses a python library for Nmap to scan a given network (currently based on a 24-bit mask of a target machines IP) for possible vulnerable hosts. PtH runs the equivalent of nmap 123.456.789.0-255 -n -O -p445 to search for any hosts on the network with port 445 open. We can then filter the returned list by the OS details and mark any Windows machine as a possible target.

#### Intrusion

Based on the list of Windows machines gathered from the discovery step the program will then begin to attempt to break into an initial machine using the EternalBlue exploit against Windows 7. For this we used the Metasploit RPC server and interacted with it through a python library called pymetasploit. This rpc server allowed us to script metasploit jobs instead of having to use system-calls on the command line itself.

#### Collection

Once a machine has been accessed using EternalBlue we can use the meterpreter shell to dump the windows hashes. With this set of initial hashes we can begin our iterative attack on the rest of the machines on the network. We iterate over each remaining windows machine, attempting to pass each hash on our running list of hashes against them using the PSexec SMB exploit. If we successfully gain access to one of these machines we use meterpreter to dump the hashes from the box and add any new credentials to the hash list. This process repeats until we have iterated over every machine in the target list. Once complete PtH will output its findings to ‘pth.out’, which contains each IP accessed and the hashes that were dumped from it.
