#!/bin/bash

# Exit if any command in this script fails
set -e
# Record the last executed command
trap 'last_command=$current_command; current_command=$BASH_COMMAND' DEBUG
# Echo an error message before exiting
trap 'echo "\"${last_command}\" returned exit code $?." >&2' EXIT

if [ "$#" -ne 3 ]; then
    echo "Usage: ./bootstrap_node.sh <key_name> <github_repo_url> <github_repo_name>"
    exit 1
fi

KEY_NAME="$1"
REPO_URL="$2"
REPO_NAME="$3"

FUNC="install"

# Backup limits.conf
LIMITS="/etc/security/limits.conf"
[ ! -f "$LIMITS".bak ] && sudo cp "$LIMITS" "$LIMITS".bak

# Overwrite default file limits. Essential for large networks (200+).
printf "* soft     nproc          65535 \n\
* hard     nproc          65535 \n\
* soft     nofile         65535 \n\
* hard     nofile         65535 \n\
root soft     nproc          65535 \n\
root hard     nproc          65535 \n\
root soft     nofile         65535 \n\
root hard     nofile         65535\n" | sudo tee "$LIMITS" >/dev/null

sudo sysctl -w fs.nr_open=65535
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_tw_reuse=1
sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 33554432"
sudo sysctl -w net.ipv4.tcp_wmem="4096 65535 33554432"

# TODO: Unsure if these are necessary.
echo "ulimit -n 65535" >> /home/ubuntu/.bashrc
echo "ulimit -n 65535" >> /home/ubuntu/.profile

# Generate the public key corresponding to the GitHub deploy key.
ssh-keygen -y -f /home/ubuntu/"$KEY_NAME" > /home/ubuntu/"$KEY_NAME".pub
# Move the previously-copied deploy key to its proper location and set it 
# as the default for GitHub.
mv /home/ubuntu/"$KEY_NAME"* /home/ubuntu/.ssh
echo -e \
    "Host github.com\n  HostName github.com\n  IdentityFile ~/.ssh/$KEY_NAME" \
    > /home/ubuntu/.ssh/config
eval $(ssh-agent)
ssh-add /home/ubuntu/.ssh/"$KEY_NAME"

# Update the distro
sudo apt-get update
sudo apt-get -y upgrade
sudo apt-get -y autoremove

# The following dependencies prevent the error: [error: linker `cc` not found].
sudo apt-get -y install build-essential
sudo apt-get -y install cmake

# Install rust (non-interactive).
curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME"/.cargo/env
rustup default stable

# This is missing from the Rocksdb installer (needed for Rocksdb).
sudo apt-get install -y clang

cd /home/ubuntu

# Clone the repo.
if ! [ -d "$REPO_NAME" ]; then
    # git init prevents "kex_exchange_identification: read: Connection reset by peer",
    # which otherwise occurs sometimes. Cause unknown.
    (git init; GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no" git clone "$REPO_URL")
fi

# Cleanup ssh-agent
kill "$SSH_AGENT_PID"

echo "$FUNC complete"
