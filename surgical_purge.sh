#!/bin/bash
# ----------------------------------------------------------------
# THE TREVINO DOCTRINE: SURGICAL FILE PURGE (PEACOCK REPO)
# ----------------------------------------------------------------

echo -e "\033[1;33m[*] Starting surgical removal of prompts/googleapikeys.txt...\033[0m"

# 1. Install the nuke tool
sudo apt update && sudo apt install -y git-filter-repo

# 2. The Purge
# This command goes through the WHOLE history and removes ONLY that file.
# Your other files and work are safe.
git filter-repo --path prompts/googleapikeys.txt --invert-paths --force

# 3. Re-link to GitHub (filter-repo drops the remote for safety)
REMOTE_URL=$(gh repo view --json url -q .url)
git remote add origin $REMOTE_URL

# 4. The Force Push
# This is what clears the 'History' tab on GitHub.
echo -e "\033[1;31m[!] Finalizing purge on GitHub... Overwriting the leaked history.\033[0m"
git push origin --force --all

echo -e "\n\033[1;92m🎯 PURGE COMPLETE: The file and its history are vanished. 🎯\033[0m"
