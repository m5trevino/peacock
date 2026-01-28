#!/bin/bash
# 1. Clear the redline (Add everything)
git add .

# 2. Force the remote to match your local history EXACTLY
echo -e "\033[1;33m[*] Forcing local MASTER to GitHub...\033[0m"
git push origin master --force

# 3. Hijack the MAIN branch (where GitHub UI looks)
# This makes 'main' an exact clone of your 'master' work
echo -e "\033[1;33m[*] Mirroring to MAIN for the GitHub UI...\033[0m"
git checkout -B main
git merge master
git push origin main --force

# 4. Return to master and lock the tracking
git checkout master
git branch --set-upstream-to=origin/master master

echo -e "\033[1;92m🎯 OPERATION COMPLETE: GitHub is now a mirror of your local reality. 🎯\033[0m"
