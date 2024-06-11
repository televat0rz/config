#!/bin/bash

# Check if the necessary environment variables are set
if [ -z "$TARGET" ] || [ -z "$ATTACKER_IP" ] || [ -z "$DOMAIN" ]; then
  echo "Please set the necessary environment variables before running the script:"
  echo "export DOMAIN=$(echo \$HOSTNAME | sed 's/^exegol-//'); export ATTACKER_IP=\$(ip addr show tun0 | grep 'inet ' | awk '{print \$2}' | cut -d/ -f1); export TARGET=<IP>; /opt/my-resources/bin/ctf.sh"
  exit 1
fi

# Automatically append TARGET and DOMAIN to /etc/hosts
echo -e "$TARGET\t$DOMAIN" | sudo tee -a /etc/hosts

# Start a new tmux session with the environment variables
tmux new-session -d -s 0
sleep 1

# Create the 'config' window and setup panes
tmux rename-window -t 0:0 'config'
tmux split-window -h -t 0:config.0 && tmux resize-pane -R 22
tmux split-window -v -t 0:config.0 && tmux resize-pane -U 16
tmux split-window -v -t 0:config.2 && tmux resize-pane -U 16
sleep 2
tmux send-keys -t 0:config.0 "cd /opt/resources && http-server 6789" C-m
sleep 1
tmux send-keys -t 0:config.1 "cd /opt/resources && l /opt/resources/windows && l /opt/resources/linux" C-m
sleep 1
tmux send-keys -t 0:config.2 "sudo -u kali /home/kali/BurpSuitePro/BurpSuitePro --config-file=/home/kali/.BurpSuite/ProjectConfigPro.json --user-config-file=/home/kali/.BurpSuite/UserConfigPro.json --project-file=/home/kali/$HOSTNAME.burp" C-m
sleep 1
tmux send-keys -t 0:config.3 "tail /etc/hosts" C-m
tmux send-keys -t 0:config.3 "vi /etc/hosts"

# Create and setup 'recon' window panes
tmux new-window -n recon
sleep 1
tmux split-window -h -t 0:recon.0 && tmux resize-pane -R 42
sleep 2
tmux send-keys -t 0:recon.0 "autorecon --only-scans-dir --no-port-dirs --dirbuster.threads 50 --dirbuster.wordlist /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt --subdomain-enum.threads 70 --subdomain-enum.wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --vhost-enum.threads 70 --vhost-enum.wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -vvv $TARGET" C-m
sleep 1
tmux send-keys -t 0:recon.1 "cd results/*/scans;tree -h"

# Create another unnamed window and split the pane horizontally
tmux new-window
sleep 1
tmux split-window -h -t 0:2.0 && tmux resize-pane -R 24
tmux split-window -v -t 0:2.0 && tmux resize-pane -D 32
tmux split-window -v -t 0:2.1 && tmux resize-pane -U 26
sleep 2
tmux send-keys -t 0:2.1 'pwncat-cs -p 1337' C-m
tmux send-keys -t 0:2.2 'http-server 80' C-m

# Select the final pane for the cursor in 'recon'
tmux select-window -t 0:recon
tmux select-pane -t 0:recon.1

# Attach to the tmux session
tmux attach-session -t 0
