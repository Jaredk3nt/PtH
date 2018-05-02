x-terminal-emulator -e msfrpcd -P password -n -f -a 127.0.0.1
read -p 'Your local IP: ' localipvar
read -p 'Target IP: ' targetipvar
sudo python2.7 pth.py -l $localipvar -t $targetipvar
