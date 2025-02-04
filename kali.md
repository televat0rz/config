##
sudo apt install xrdp xfce4 xfce4-goodies -y
sudo systemctl enable xrdp
sudo systemctl start xrdp

sudo apt install kali-tools-top10 alacritty apt-transport-https binwalk default-mysql-client default-mysql-client-core docker.io dos2unix enum4linux evil-winrm feroxbuster gdb ghidra golang-go hashcat hashcat-utils jq kali-wallpapers-2020.4 krb5-user libcap-dev libfuse-dev ligolo-ng lolcat mariadb-client mongodb mongodb-clients mongo-tools nbtscan neo4j nikto nmap node-bcrypt-pbkdf node-js-beautify npm ntpdate nuclei onesixtyone oscanner pipx proxychains4 redis-tools rlwrap seclists shelldap sliver smbclient smbmap snmp snmpcheck sqlmap sslscan wfuzz whatweb wireshark wkhtmltopdf xclip

sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker kali
sudo reboot now


# pipx
pipx install exegol
pipx install ngrok
pipx install 'git+https://github.com/Tib3rius/AutoRecon'
pipx install 'git+https://github.com/Pennyw0rth/NetExec'
pipx install 'git+https://github.com/calebstewart/pwncat'
pipx install 'git+https://github.com/blacklanternsecurity/badsecrets'
pipx install 'git+https://github.com/blacklanternsecurity/bbot'
pipx install 'git+https://github.com/Mazars-Tech/AD_Miner'
pipx upgrade-all

# go
go install github.com/fffaraz/fakessh@latest

# docker permissions fix to avoid root
sudo setfacl -R -d -m u:kali:rwx /home/kali/ctf/



# update all repos in dir
┌──(root㉿kali)-[/opt]
└─# find . -maxdepth 3 -name .git -type d | rev | cut -c 6- | rev | xargs -I {} git -C {} pull

# clone all .repos | GIT_SSL_NO_VERIFY=true if ssl errors
┌──(root㉿kali)-[/opt]
└─# cat /opt/.repos | xargs -I% git clone https://github.com/%

# maintain /opt/.repos packages
┌──(root㉿kali)-[/opt]
└─# cat /opt/.repos
0xsp-SRD/mortar
61106960/adPEAS
carlospolop/Auto_Wordlists
CiscoCXSecurity/linikatz
f-bader/TokenTacticsV2
GeisericII/Winpacket
gh0x0st/Get-ReverseShell
icyguider/Nimcrypt2
icyguider/UAC-BOF-Bonanza
ihebski/DefaultCreds-cheat-sheet
ItsMerkz/Python-Exe-Decompiler
ivan-sincek/php-reverse-shell
jonaslejon/malicious-pdf
jvdsn/crypto-attacks
kimci86/bkcrack
klezVirus/inceptor
lkarlslund/ldapnomnom
ly4k/PwnKit
nccgroup/featherduster
NHAS/reverse_ssh
optiv/ScareCrow
qtc-de/remote-method-guesser
S3cur3Th1sSh1t/PowerSharpPack
secretsquirrel/SigThief
sevagas/macro_pack
sighook/pixload
silentsignal/rsa_sign2n
synacktiv/php_filter_chain_generator
t3l3machus/hoaxshell
TheWover/donut
# bchecks
emadshanab/BChecks-Collection
nullfuzz-pentest/bchecks-templates /opt/BChecks/bchecks-templates
cyberK9/BChecksFTW /opt/BChecks/BChecksFTW
IAmRoot0/BCheck-Rules /opt/BChecks/BCheck-Rules
0xm4v3rick/Burp-BChecks /opt/BChecks/Burp-BChecks
PortSwigger/BChecks /opt/BChecks/PortSwigger
NetSPIWillD/BChecks /opt/BChecks/NetSPIWillD
lisandre-com/BChecks /opt/BChecks/lisandre-com
beishanxueyuan/BChecks /opt/BChecks/beishanxueyuan
buggysolid/bchecks /opt/BChecks/buggysolid
MrW0l05zyn/bchecks /opt/BChecks/MrW0l05zyn


##################################################################################################
##################################################################################################
# old
3v4Si0N/HTTP-revshell
AlmondOffSec/PassTheCert
ambionics/phpggc
antonioCoco/RemotePotato0
arthaud/git-dumper
attackdebris/kerberos_enum_userlists
cobbr/SharpSploit
CravateRouge/bloodyAD
danielbohannon/Invoke-Obfuscation
Dec0ne/KrbRelayUp
Dhayalanb/windows-php-reverse-shell
dirkjanm/krbrelayx
dirkjanm/PKINITtools
epinna/weevely3
evilmog/ntlmv1-multi
Flangvik/SharpCollection
franc-pentest/ldeep
Ganapati/RsaCtfTool
Greenwolf/ntlm_theft
Hacking-the-Cloud/hackingthe.cloud
internetwache/GitTools
itm4n/PrivescCheck
JacobEbben/Bloodhound_Summary
jordanpotti/AWSBucketDump
Kevin-Robertson/Powermad
matterpreter/OffensiveCSharp
micahvandeusen/gMSADumper
noraj/flask-session-cookie-manager
optiv/Go365
p0dalirius/Coercer
p0dalirius/ldapconsole
p0dalirius/LDAPmonitor
PShlyundin/ldap_shell
quentinhardy/msdat
Ridter/noPac
ropnop/kerbrute
ShutdownRepo/pywhisker
ShutdownRepo/targetedKerberoast
skelsec/pypykatz
spipm/Depix
stealthcopter/deepce
synacktiv/ntdissector
t3l3machus/Villain
tarunkant/Gopherus
the-useless-one/pywerview
Tib3rius/AutoRecon
ticarpi/jwt_tool
topotam/PetitPotam
tothi/rbcd-attack
urbanadventurer/username-anarchy
vladko312/SSTImap
wireghoul/graudit
##################################################################################################
##################################################################################################



# ligolo-ng
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up

# vscode
/usr/bin/curl -L 'https://code.visualstudio.com/sha/download?build=stable&os=linux-deb-x64' -o /home/kali/Downloads/vscode.deb; /usr/bin/chmod +x /home/kali/Downloads/vscode.deb; /usr/bin/apt install /home/kali/Downloads/vscode.deb

# container_toolkit
/usr/bin/curl -fsSL https://github.com/cdk-team/CDK/releases/latest/download/cdk_linux_amd64 -o /opt/cdk_linux_amd64; /usr/bin/chmod +x /opt/cdk_linux_amd64

# remote-method-guesser
/usr/bin/curl -fsSL https://github.com/qtc-de/remote-method-guesser/releases/download/v4.4.1/rmg-4.4.1-jar-with-dependencies.jar -o /opt/rmg-4.4.1-jar-with-dependencies.jar; /usr/bin/chmod +x /opt/rmg-4.4.1-jar-with-dependencies.jar

# recaf
/usr/bin/curl -fsSL https://github.com/Col-E/Recaf/releases/download/2.21.13/recaf-2.21.13-J8-jar-with-dependencies.jar -o /opt/recaf-2.21.13-J8-jar-with-dependencies.jar;/usr/bin/chmod +x /opt/recaf-2.21.13-J8-jar-with-dependencies.jar

# websocat
/usr/bin/curl -fsSL https://github.com/vi/websocat/releases/latest/download/websocat_max.x86_64-unknown-linux-musl -o /opt/websocat_max.x86_64-unknown-linux-musl; /usr/bin/chmod +x /opt/websocat_max.x86_64-unknown-linux-musl

# wordlists
/usr/bin/mkdir /opt/wordlists; /usr/bin/curl -fsSL https://raw.githubusercontent.com/televat0rs/wordlists/main/command_injection.txt -o /opt/wordlists/command_injection.txt; /usr/bin/curl -fsSL https://raw.githubusercontent.com/televat0rs/wordlists/main/last-names.txt -o /opt/wordlists/last-names.txt


### old ###


# peass
/usr/bin/curl -fsSL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /opt/linpeas.sh;/usr/bin/chmod +x /opt/linpeas.sh & /usr/bin/curl -fsSL https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe -o /opt/winPEASany.exe;/usr/bin/chmod +x /opt/winPEASany.exe

# pspy
/usr/bin/curl -fsSL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /opt/pspy64; /usr/bin/chmod +x /opt/pspy64 & /usr/bin/curl -fsSL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32 -o /opt/pspy32; /usr/bin/chmod +x /opt/pspy32

# kerbrute
/usr/bin/curl -fsSL https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 -o /opt/kerbrute_linux_amd64; /usr/bin/chmod +x /opt/kerbrute_linux_amd64

# ysoserial
/usr/bin/curl -fsSL https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar -o /opt/ysoserial-all.jar; /usr/bin/chmod +x /opt/ysoserial-all.jar

# deobfuscator
/usr/bin/curl -fsSL https://github.com/java-deobfuscator/deobfuscator/releases/latest/download/deobfuscator.jar -o /opt/deobfuscator.jar; /usr/bin/chmod +x /opt/deobfuscator.jar

# static-binaries
/usr/bin/curl -fsSL https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap -o /opt/static-nmap; /usr/bin/chmod +x /opt/static-nmap & /usr/bin/curl -fsSL https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/ncat -o /opt/static-ncat; /usr/bin/chmod +x /opt/static-ncat & /usr/bin/curl -fsSL https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/strings -o /opt/static-strings; /usr/bin/chmod +x /opt/static-strings & /usr/bin/curl -fsSL https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/p0f -o /opt/static-p0f; /usr/bin/chmod +x /opt/static-p0f & /usr/bin/curl -fsSL https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/python2.7 -o /opt/static-python2.7; /usr/bin/chmod +x /opt/static-python2.7

# chisel
/usr/bin/curl -fsSL https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz -o /opt/chisel_1.9.1_linux_amd64.gz;wait;/usr/bin/gunzip /opt/chisel_1.9.1_linux_amd64.gz;wait;/usr/bin/chmod +x /opt/chisel_1.9.1_linux_amd64;/usr/bin/rm /opt/chisel_1.9.1_linux_amd64.gz && /usr/bin/curl -fsSL https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_windows_amd64.gz -o /opt/chisel_1.9.1_windows_amd64.gz;wait;/usr/bin/gunzip /opt/chisel_1.9.1_windows_amd64.gz;wait;/usr/bin/chmod +x /opt/chisel_1.9.1_windows_amd64;/usr/bin/mv /opt/chisel_1.9.1_windows_amd64 /opt/chisel_1.9.1_windows_amd64.exe;/usr/bin/rm /opt/chisel_1.9.1_windows_amd64.gz

# grpcurl
/usr/bin/curl -fsSL https://github.com/fullstorydev/grpcurl/releases/download/v1.8.7/grpcurl_1.8.7_linux_x86_64.tar.gz -o /opt/grpcurl_1.8.7_linux_x86_64.tar.gz;/usr/bin/tar -zxvf /opt/grpcurl_1.8.7_linux_x86_64.tar.gz grpcurl;/usr/bin/rm /opt/grpcurl_1.8.7_linux_x86_64.tar.gz;/usr/bin/chown root:root /opt/grpcurl

# mssql_shell.py
/usr/bin/curl -fsSL https://gist.githubusercontent.com/s0j0hn/ba2163e3f094b419c1d4480ae5dc9a66/raw/32de33226e0ddf728f72c511d4424ec333ad242f/mandros3.py -o /opt/mssql_shell.py;/usr/bin/chmod +x /opt/mssql_shell.py

# namemash.py
/usr/bin/curl -fsSL https://gist.githubusercontent.com/superkojiman/11076951/raw/74f3de7740acb197ecfa8340d07d3926a95e5d46/namemash.py -o /opt/namemash.py;/usr/bin/chmod +x /opt/namemash.py

# ngrok
/usr/bin/curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo /usr/bin/tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null && echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo /usr/bin/tee /etc/apt/sources.list.d/ngrok.list && sudo /usr/bin/apt update && sudo /usr/bin/apt install ngrok; ngrok config add-authtoken 2TGyTuBsVo6lUgdGE8PLX21z0Zn_6dS81WNnnjVHKTq5dNeJA

# gef
/usr/bin/bash -c "$(/usr/bin/curl -fsSL https://gef.blah.cat/sh)"

# mitm6 #2023.3 python3-* preferred over pip
#[[ -d /opt/mitm6 ]] && /usr/bin/rm -rf /opt/mitm6 || /usr/bin/git clone https://github.com/dirkjanm/mitm6 /opt/mitm6; /usr/bin/git clone https://github.com/dirkjanm/mitm6 /opt/mitm6; /usr/bin/pip /opt/mitm6/install -r requirements.txt; /usr/bin/python /opt/mitm6/setup.py install

######

# bloodhound
[[ -d /opt/BloodHound-linux-x64 ]] && /usr/bin/rm -rf /opt/BloodHound-linux-x64 || /usr/bin/curl -fsSL https://github.com/BloodHoundAD/BloodHound/releases/latest/download/BloodHound-linux-x64.zip -o /opt/BloodHound-linux-x64.zip;/usr/bin/unzip /opt/BloodHound-linux-x64.zip;/usr/bin/rm /opt/BloodHound-linux-x64.zip

# powersploit
[[ -d /opt/PowerSploit-3.0.0 ]] && /usr/bin/rm -rf /opt/PowerSploit-3.0.0 || /usr/bin/curl -fsSL https://github.com/PowerShellMafia/PowerSploit/archive/refs/tags/v3.0.0.zip -o /opt/v3.0.0.zip; /usr/bin/unzip /opt/v3.0.0.zip;/usr/bin/rm /opt/v3.0.0.zip

# runascs
[[ /opt/RunasCs*.exe ]] && /usr/bin/rm /opt/RunasCs*.exe || /usr/bin/curl -fsSL https://github.com/antonioCoco/RunasCs/releases/latest/download/RunasCs.zip -o /opt/RunasCs.zip; /usr/bin/unzip /opt/RunasCs.zip; /usr/bin/rm /opt/RunasCs.zip;/usr/bin/chmod +x /opt/RunasCs*.exe

# nc.exe
[[ /opt/nc*.exe ]] && /usr/bin/rm /opt/nc*.exe || /usr/bin/curl -fsSL https://eternallybored.org/misc/netcat/netcat-win32-1.12.zip -o /opt/netcat-win32-1.12.zip; /usr/bin/unzip /opt/netcat-win32-1.12.zip nc.exe;/usr/bin/unzip /opt/netcat-win32-1.12.zip nc64.exe; /usr/bin/rm /opt/netcat-win32-1.12.zip;/usr/bin/chmod +x /opt/nc*.exe

# binaryninja
[[ -d /opt/binaryninja ]] && /usr/bin/rm -rf /opt/binaryninja || /usr/bin/curl -fsSL https://cdn.binary.ninja/installers/binaryninja_free_linux.zip -o /opt/binaryninja.zip; /usr/bin/unzip /opt/binaryninja.zip;/usr/bin/rm /opt/binaryninja.zip

# /etc/samba/smb.conf
if [ $(/usr/bin/cat /etc/samba/smb.conf | /usr/bin/grep -i -c "client min protocol = LANMAN" ) -ne 1 ]; then echo -e "\n /etc/samba/smb.conf is not default - quitting"; /usr/bin/cat /etc/samba/smb.conf; else /usr/bin/sed 's/client min protocol = LANMAN1/client min protocol = CORE\n   client max protocol = SMB3\n''/' -i /etc/samba/smb.conf; fi

# /etc/default/grub
if [ $(/usr/bin/cat /etc/default/grub | /usr/bin/grep -i -c "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"" ) -ne 1 ]; then echo -e "\n /etc/default/grub is not default - quitting"; /usr/bin/cat /etc/default/grub; else /usr/bin/sed 's/GRUB_CMDLINE_LINUX_DEFAULT="quiet"/GRUB_CMDLINE_LINUX_DEFAULT="quiet mitigations=off"/' -i /etc/default/grub; /usr/sbin/update-grub; fi

# /home/kali/.config/qterminal.org/qterminal.ini # open2panes # fixedSize=@Size(2060 1405)
if [ $(/usr/bin/cat /home/kali/.config/qterminal.org/qterminal.ini | /usr/bin/grep -i -c "MenuVisible=true") -ne 1 ]; then echo -e "\n /home/kali/.config/qterminal.org/qterminal.ini is not default - quitting"; else /usr/bin/cp /home/kali/.config/qterminal.org/qterminal.ini /home/kali/.config/qterminal.org/qterminal.ini.bak & /usr/bin/sed -e 's/BookmarksVisible=true/BookmarksVisible=false/' -e 's/Borderless=false/Borderless=true/' -e 's/MenuVisible=true/MenuVisible=false/' -e 's/UseCWD=false/UseCWD=true/' -e 's/showTerminalSizeHint=true/showTerminalSizeHint=false/' -e 's/ShowCloseTabButton=true/ShowCloseTabButton=false/' -i /home/kali/.config/qterminal.org/qterminal.ini;fi

# /etc/proxychains4.conf # 2024.1 added space before tab ' 	'
if [ $(/usr/bin/cat /etc/proxychains4.conf | /usr/bin/grep -i -c "socks4 	127.0.0.1 9050") -ne 1 ]; then echo -e "\n /etc/proxychains4.conf is not default - quitting"; else /usr/bin/sed 's/socks4 	127.0.0.1 9050/#socks4 	127.0.0.1 9050/' -i /etc/proxychains4.conf & echo -en 'socks5 	127.0.0.1 1080' >> /etc/proxychains4.conf;fi

# /etc/ldap/ldap.conf
echo TLS_REQCERT	never | tee -a /etc/ldap/ldap.conf

# vulners:api
vulners:key

# ghidra
https://raw.githubusercontent.com/evyatar9/GptHidra/main/GptHidra.py

/usr/bin/mkdir /opt/wordlists; /usr/bin/curl -fsSL https://raw.githubusercontent.com/televat0rs/wordlists/main/command_injection.txt -o /opt/wordlists/command_injection.txt; /usr/bin/curl -fsSL https://raw.githubusercontent.com/televat0rs/wordlists/main/last-names.txt -o /opt/wordlists/last-names.txt

https://github.com/mooncat-greenpy/Ghidra_GolangAnalyzerExtension



# xhost for root
echo '#!/bin/bash\nxhost +SI:localuser:root' | tee /etc/profile.d/xhost.sh > /dev/null && chmod +x /etc/profile.d/xhost.sh

# post apt update xfce hang fix
sudo apt install -y linux-headers-$(uname -r)








for $ctf in $(ls ctf folder) do
cp $ctf/$ctf.md /home/kali/Necronomicon/ctf/
&
tar -czf $ctf.tar.gz $ctf





# burp
{{install}}
/usr/bin/curl 'https://portswigger-cdn.net/burp/releases/download?product=pro&version=2024.2.1.3&type=Linux' -o /home/kali/Downloads/burpsuite_pro_linux_v2024_new.sh; /usr/bin/chmod +x /home/kali/Downloads/burpsuite_pro_linux_v2024_new.sh; /usr/bin/sudo -u root cat /home/kali/Downloads/burpsuite_pro_linux_v2024_new.sh | /bin/bash
{{scope}}
10.0.0.0-10.255.255.255
172.16.0.0-172.31.255.255
192.168.0.0-192.168.255.255
100.64.0.0-100.127.255.255
(^|^[^:]+:\/\/|[^\.]+\.)htb.*
(^|^[^:]+:\/\/|[^\.]+\.)web-security-academy.*
(^|^[^:]+:\/\/|[^\.]+\.)vl.*
#
(^|^[^:]+:\/\/|[^\.]+\.)google.*
(^|^[^:]+:\/\/|[^\.]+\.)cloudflare.*
(^|^[^:]+:\/\/|[^\.]+\.)gstatic.*
(^|^[^:]+:\/\/|[^\.]+\.)vulners.*
(^|^[^:]+:\/\/|[^\.]+\.)darkreader.*
(^|^[^:]+:\/\/|[^\.]+\.)github.*
(^|^[^:]+:\/\/|[^\.]+\.)stripe.*
(^|^[^:]+:\/\/|[^\.]+\.)doubleclick.*
(^|^[^:]+:\/\/|[^\.]+\.)wappalyzer.*
{{ram}}
/usr/bin/java -jar -Xmx16G /usr/local/BurpSuitePro/burpsuite_pro.jar
{{jython}}
/usr/bin/curl https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.3/jython-standalone-2.7.3.jar -o /home/kali/Downloads/jython-standalone-2.7.3.jar
{{extensions}}
403 Bypasser, Active Scan++, Additional Scanner Checks, Backslash Powered Scanner, HTTP Request Smuggler, J2EEScan, Java Deserialization Scanner, JS Miner, JWT Editor, NoSQLi Scanner, Param Miner, Retire.js, SAML Raider, Server-Side Prototype Pollution Scanner, Software Version Reporter, Software Vulnerability Scanner, Turbo Intruder, Upload Scanner
{{bchecks}}
/usr/bin/find /opt/BChecks -type f -exec /usr/bin/chmod 644 -- {} +; /usr/bin/find /opt/BChecks -name '*.bcheck' -exec /usr/bin/mv -t /home/kali/.BurpSuite/bchecks {} +; /usr/bin/find /home/kali/.BurpSuite/bchecks -name '*.bcheck' -exec chown kali:kali {} +
/usr/bin/find /opt/BChecks -type f | /usr/bin/grep -v '.bcheck\|git\|LICENSE\|\.md'
/usr/bin/find /opt/BChecks -type f | /usr/bin/grep -v '.bcheck\|git\|LICENSE\|\.md\|\.' | while read -r v; do broke=$(basename "$v"); fixed="${broke}.bcheck"; /usr/bin/mv "$v" "/home/kali/.BurpSuite/bchecks/${fixed}"; /usr/bin/find /home/kali/.BurpSuite/bchecks -name '*.bcheck' -exec chown kali:kali {} +; done



### /home/AMBERJACK/7yn5ehjphp
/usr/bin/find /opt/BChecks -type f -exec /usr/bin/chmod 644 -- {} +; /usr/bin/find /opt/BChecks -name '*.bcheck' -exec /usr/bin/mv -t /home/AMBERJACK/7yn5ehjphp/.BurpSuite/bchecks {} +; /usr/bin/find /home/AMBERJACK/7yn5ehjphp/.BurpSuite/bchecks -name '*.bcheck' -exec chown 7yn5ehjphp:7yn5ehjphp {} +
/usr/bin/find /opt/BChecks -type f | /usr/bin/grep -v '.bcheck\|git\|LICENSE\|\.md'
/usr/bin/find /opt/BChecks -type f | /usr/bin/grep -v '.bcheck\|git\|LICENSE\|\.md\|\.' | while read -r v; do broke=$(basename "$v"); fixed="${broke}.bcheck"; /usr/bin/mv "$v" "/home/AMBERJACK/7yn5ehjphp/.BurpSuite/bchecks/${fixed}"; /usr/bin/find /home/AMBERJACK/7yn5ehjphp/.BurpSuite/bchecks -name '*.bcheck' -exec chown 7yn5ehjphp:7yn5ehjphp {} +; done

######################################################################
.    ,'    ,--'   ,'    `;-.     / \      `. o  ,--.      `.   /
 `.-'    ,'      '`-.,  /       /   `.      `--'  o `.      \ /     `-
   `.   /       /  '-..,       ;    ,-`.          ,---`.,.---'
     \ /     `-;.    ,'    ,--'   ,'    `;-.     / \      `. o  ,--.
'`.---'          `.-'    ,'      '`-.,  /       /   `.      `--'  o `.
   `. o  ,--.      `.   /       /  '-..,       ;    ,-`.          ,---
     `--'  o `.      \ /     `-;.    ,'    ,--'   ,'    `;-.     / \
.          ,---`'`.---'          `.-'    ,'      '`-.,  /       /   `.
 `;-.     / \      `. o  ,--.      `.   /       /  '-..,       ;    ,-
 /       /   `.      `--'  o `.      \ /     `-;.    ,'    ,--'   ,'
,       ;    ,-`.          ,---`.,.---'          `.-'    ,'      '`-.,
    ,--'   ,'    `;-.     / \      `. o  ,--.      `.   /       /  '-.
  ,'      '`-.,  /       /   `.      `--'  o `.      \ /     `-;.    ,
 /       /  '-..,       ;    ,-`.          ,---`'`.---'          `.-'
/     `-;.    ,'    ,--'   ,'    `;-.     / \      `. o  ,--.      `.
          `.-'    ,'      '`-.,  /       /   `.      `--'  o `.      \
  ,--.      `.   /       /  '-..,       ;    ,-`.          ,---`'`.---
-'  o `.      \ /     `-;.    ,'    ,--'   ,'    `;-.     / \      `.
    ,---`'`.---'          `.-'    ,'      '`-.,  /       /   `.      `
   / \      `. o  ,--.      `.   /       /  '-..,       ;    ,-`.
  /   `.      `--'  o `.      \ /     `-;.    ,'    ,--'   ,'    `;-.
 ;    ,-`.          ,---`'`.---'          `.-'    ,'      '`-.,  /
'   ,'    `;-.     / \      `. o  ,--.      `.   / -hrr- /  '-..,
   '`-.,  /       /   `.      `--'  o `.      \ /     `-;.    ,'    ,-
######################################################################
