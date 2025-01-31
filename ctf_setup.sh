#!/bin/bash

# check if the necessary environment variables are set
if [ -z "$TARGET" ] || [ -z "$ATTACKER_IP" ] || [ -z "$DOMAIN" ]; then
  echo "Please set the necessary environment variables before running the script:"
  echo "export TARGET=<IP>; export DOMAIN=\$(echo \$HOSTNAME | sed 's/^exegol-//'); export ATTACKER_IP=\$(ip addr show tun0 | grep 'inet ' | awk '{print \$2}' | cut -d/ -f1); /opt/my-resources/bin/ctf.sh"
  exit 1
fi

# append TARGET and DOMAIN to /etc/hosts
echo -e "$TARGET\t$DOMAIN" | tee -a /etc/hosts "/workspace/${DOMAIN}.md"

# replace IP
sed -i "s/VPN_IP/${ATTACKER_IP}/g" "/workspace/${DOMAIN}.md"

# group ownership kali
chgrp -R kali /workspace

# set group permissions
chmod -R g+rwX /workspace

# SGID on /workspace
chmod g+s /workspace

# fix groups for rvm|kali
groupmod -g 1002 rvm && groupmod -g 1000 kali

# fix permissions
chown -R root:kali /workspace

# tmux
tmux new-session -d -s "m" -x- -y-

# config
tmux rename-window -t "m:0" "config"
sleep 1
tmux split-window -h -l 127 -t "m:config.0"
sleep 1
tmux split-window -v -l 60 -t "m:config.0"
sleep 1
tmux split-window -v -l 60 -t "m:config.2"
sleep 1
tmux send-keys -t "m:config.0" "cd /opt/resources && http-server 6789" C-m
tmux send-keys -t "m:config.1" "cd /opt/resources && l /opt/resources/windows && l /opt/resources/linux" C-m
tmux send-keys -t "m:config.2" "sudo -u kali /home/kali/BurpSuitePro/BurpSuitePro --config-file=/home/kali/.BurpSuite/ProjectConfigPro.json --user-config-file=/home/kali/.BurpSuite/UserConfigPro.json --project-file=/home/kali/$HOSTNAME.burp" C-m
tmux send-keys -t "m:config.3" "tail /etc/hosts" C-m
tmux send-keys -t "m:config.3" "vi /etc/hosts"

# recon
tmux new-window -n recon
sleep 1
tmux split-window -h -l 76 -t "m:recon.0"
sleep 1
tmux send-keys -t "m:recon.0" "autorecon --only-scans-dir --no-port-dirs --dirbuster.threads 99 --dirbuster.wordlist /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt --subdomain-enum.threads 99 --subdomain-enum.wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --vhost-enum.threads 99 --vhost-enum.wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -vvv $DOMAIN" C-m
sleep 1
tmux send-keys -t "m:recon.1" "tree -h /workspace/results"

# main
tmux new-window
sleep 1
tmux split-window -h -l 115 -t "m:2.0"
sleep 1
tmux split-window -v -l 6 -t "m:2.0"
sleep 1
tmux split-window -v -l 6 -t "m:2.2"
sleep 1
tmux send-keys -t "m:2.0" "export HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=http://127.0.0.1:8080 http_proxy=http://127.0.0.1:8080 https_proxy=http://127.0.0.1:8080" C-m
tmux send-keys -t "m:2.1" "rlwrap nc -lvnp 1337" C-m
tmux send-keys -t "m:2.2" "export HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=http://127.0.0.1:8080 http_proxy=http://127.0.0.1:8080 https_proxy=http://127.0.0.1:8080" C-m
tmux send-keys -t "m:2.3" "http-put-server 80" C-m

# select recon
tmux select-window -t "m:recon"
tmux select-pane -t "m:recon.1"

# attach to tmux
tmux attach-session -t "m"
