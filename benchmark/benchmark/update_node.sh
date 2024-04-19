#!/bin/bash

# Exit if any command in this script fails
set -e
# Record the last executed command
trap 'last_command=$current_command; current_command=$BASH_COMMAND' DEBUG
# Echo an error message before exiting
trap 'echo "\"${last_command}\" returned exit code $?." >&2' EXIT

if [ "$#" -ne 3 ]; then
    echo "Usage: ./update_node.sh <key_name> <github_repo_name> <repo_branch_name>"
    exit 1
fi

KEY_NAME="$1"
REPO_NAME="$2"
BRANCH_NAME="$3"

FUNC="update"

eval $(ssh-agent)
ssh-add /home/ubuntu/.ssh/"$KEY_NAME"
cd /home/ubuntu/"$REPO_NAME" 
git fetch -f
git checkout -f "$BRANCH_NAME"
git pull -f

source "$HOME"/.cargo/env
cd /home/ubuntu/"$REPO_NAME"/node
cargo build --quiet --release --features benchmark

cd /home/ubuntu
rm -f node
rm -f benchmark_client
ln -s ./"$REPO_NAME"/target/release/node . 
ln -s ./"$REPO_NAME"/target/release/benchmark_client .

kill "$SSH_AGENT_PID"

echo "$FUNC complete"
