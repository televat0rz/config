#!/bin/bash

# Get the tun0 IP address and export as ATTACKER_IP
tun0_ipv4=$(ip addr show tun0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
export ATTACKER_IP=$tun0_ipv4

# Extract DOMAIN from HOSTNAME and export
name=$(echo $HOSTNAME | sed 's/^exegol-//')
export DOMAIN=$name

# Setup 'config' to host resources and kali
tmux rename-window -t 0 'config'

tmux split-window -h -t 'config'.0 && tmux resize-pane -R 22
tmux split-window -v -t 'config'.0 && tmux resize-pane -U 16
tmux split-window -v -t 'config'.2 && tmux resize-pane -U 16

tmux send-keys -t 'config'.0 'cd /opt/resources && http-server 6789' C-m
tmux send-keys -t 'config'.1 'cd /opt/resources && l /opt/resources/windows && l /opt/resources/linux' C-m
tmux send-keys -t 'config'.2 "sudo -u kali /home/kali/BurpSuitePro/BurpSuitePro --config-file=/home/kali/.BurpSuite/ProjectConfigPro.json --user-config-file=/home/kali/.BurpSuite/UserConfigPro.json --project-file=/home/kali/$HOSTNAME.burp" C-m
tmux send-keys -t 'config'.3 'tail /etc/hosts' C-m
tmux send-keys -t 'config'.3 'vi /etc/hosts'

# Setup 'recon' for scans
tmux new-window -n 'recon'

tmux split-window -h -t 'recon'.0 && tmux resize-pane -R 36
tmux split-window -v -t 'recon'.1 && tmux resize-pane -U 16

tmux send-keys -t 'recon'.0 'autorecon --only-scans-dir --no-port-dirs --dirbuster.threads 50 --dirbuster.wordlist /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt --subdomain-enum.threads 70 --subdomain-enum.wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --vhost-enum.threads 70 --vhost-enum.wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --wpscan.api-token L5X3jBnXfGxdN7Y2OCClOcr95VWCILg5pvDumLTG7IM -vvv $TARGET'
tmux send-keys -t 'recon'.1 'export TARGET= ATTACKER_IP='$tun0_ipv4' DOMAIN='$name'; echo -e "$TARGET\t$DOMAIN" | sudo tee -a /etc/hosts'
tmux send-keys -t 'recon'.2 'cd results/*/scans'

# Create another window
tmux new-window
tmux split-window -h -t ':2.0' && tmux resize-pane -R 24
tmux split-window -v -t ':2.1' && tmux resize-pane -U 16

tmux send-keys -t ':2.1' 'http-server 80' C-m

# Select 'recon' pane to paste your machine IP
tmux select-window -t 'recon'
tmux select-pane -t 'recon'.1
