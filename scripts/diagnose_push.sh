#!/usr/bin/env bash
# Minimal push diagnostic script — run from repo root: ./scripts/diagnose_push.sh
LOG="diagnose.log"
echo "=== push diagnostic: $(date) ===" > "$LOG"

# Ensure we are in a git repo
if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "Not a git repository. Run this script from the repo root." | tee -a "$LOG"
  exit 1
fi

echo "--- git status ---" | tee -a "$LOG"
git status -b --porcelain | tee -a "$LOG"

echo "--- remote -v ---" | tee -a "$LOG"
git remote -v | tee -a "$LOG"

echo "--- current branch ---" | tee -a "$LOG"
git rev-parse --abbrev-ref HEAD | tee -a "$LOG"

echo "--- upstream (if any) ---" | tee -a "$LOG"
git rev-parse --abbrev-ref --symbolic-full-name @{u} 2>> "$LOG" || echo "no upstream configured" | tee -a "$LOG"

echo "--- last commit ---" | tee -a "$LOG"
git log -1 --stat --pretty=oneline | tee -a "$LOG"

echo "--- unpushed commits (local vs remote) ---" | tee -a "$LOG"
git cherry -v | tee -a "$LOG"

echo "--- object database / size info ---" | tee -a "$LOG"
git count-objects -vH | tee -a "$LOG"

echo "--- remote URL inspection ---" | tee -a "$LOG"
origin_url="$(git config --get remote.origin.url || echo '')"
echo "origin: $origin_url" | tee -a "$LOG"
if [[ "$origin_url" == http* ]]; then
  echo "Remote uses HTTPS: ensure you are using a Personal Access Token (PAT) if your account has 2FA, and check credential helper." | tee -a "$LOG"
elif [[ "$origin_url" == git@* || "$origin_url" == ssh* ]]; then
  echo "Remote uses SSH: ensure your SSH key is added to the ssh-agent and uploaded to GitHub." | tee -a "$LOG"
else
  echo "Unable to determine remote protocol." | tee -a "$LOG"
fi

echo "--- pre-push hook check ---" | tee -a "$LOG"
if [ -x .git/hooks/pre-push ]; then
  echo "pre-push hook exists and is executable. It may block pushes." | tee -a "$LOG"
else
  echo "no executable pre-push hook detected" | tee -a "$LOG"
fi

echo
echo "SUMMARY / next steps (short):"
echo " - Run: git remote -v   (check URL scheme)"
echo " - If HTTPS + 2FA: use PAT or credential helper"
echo " - If SSH: run ssh -T git@github.com and ensure key is loaded (ssh-agent)"
echo " - Check for large files (>100MB) — GitHub blocks pushes with such files"
echo " - If 'no upstream configured' run: git push -u origin $(git rev-parse --abbrev-ref HEAD)"
echo
echo "Full diagnostic written to: $LOG"
echo "Please paste the exact 'git push' error and the contents of $LOG if you want further help."
