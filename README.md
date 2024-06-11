#start exegol like this

CTF=klendathu.vl; [ -d /home/kali/ctf/$CTF ] && echo "/home/kali/ctf/$CTF already exists. Exiting." && exit 1 || mkdir -p /home/kali/ctf/$CTF && cd /home/kali/ctf/$CTF && sudo exegol start $CTF nightly -fs -cwd -s zsh --vpn /home/kali/ctf/vulnlab.ovpn
