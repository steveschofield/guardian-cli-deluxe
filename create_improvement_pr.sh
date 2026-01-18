#!/usr/bin/env bash
# Helper script to create a Pull Request for Guardian improvements

set -euo pipefail

echo "=========================================="
echo "Creating Improvement Branch & PR"
echo "=========================================="
echo ""

# Check if we're in a git repo
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo "ERROR: Not a git repository"
    exit 1
fi

# Create a new branch
BRANCH_NAME="improvements/fix-tool-failures-$(date +%Y%m%d)"
echo "Creating branch: $BRANCH_NAME"

git checkout -b "$BRANCH_NAME"

# Stage changes
git add setup.sh
echo "Staged: setup.sh"

# Commit
git commit -m "fix: Add Docker/ZAP, Kiterunner, and Retire.js fixes

- Add install_docker_and_zap() to verify Docker and pull ZAP image
- Add install_kiterunner_wordlists() to download required wordlists
- Add install_retire() to fix retire.js installation issues
- Add verify_installation() framework for tool verification

Fixes:
- ZAP scans now work (Docker integration)
- Kiterunner no longer fails with missing wordlist
- Retire.js properly installed and verified

Based on comprehensive analysis of tool failures in reports."

echo ""
echo "Committed changes to branch: $BRANCH_NAME"
echo ""
echo "Next steps:"
echo ""
echo "1. Push the branch:"
echo "   git push origin $BRANCH_NAME"
echo ""
echo "2. Create Pull Request on GitHub:"
echo "   gh pr create --title 'Fix tool installation failures' --body 'Fixes ZAP, Kiterunner, and Retire.js installation issues'"
echo ""
echo "   Or visit GitHub and create PR manually"
echo ""
