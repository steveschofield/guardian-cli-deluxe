#!/usr/bin/env bash
# Guardian Setup.sh - Quick Fixes
# Fixes immediate issues found during setup

set -euo pipefail

GUARDIAN_DIR="${1:-$(pwd)}"
BACKUP_SUFFIX="_prefixes_$(date +%Y%m%d_%H%M%S)"

echo "=========================================="
echo "Guardian Setup.sh Quick Fixes"
echo "=========================================="
echo ""

if [[ ! -f "${GUARDIAN_DIR}/setup.sh" ]]; then
    echo "ERROR: setup.sh not found in: ${GUARDIAN_DIR}"
    exit 1
fi

echo "Creating backup..."
cp "${GUARDIAN_DIR}/setup.sh" "${GUARDIAN_DIR}/setup.sh${BACKUP_SUFFIX}"
echo "✓ Backup: setup.sh${BACKUP_SUFFIX}"
echo ""

# Fix 1: Dalfox binary name issue
echo "Fix 1: Correcting dalfox binary extraction..."

if grep -q "install_github_release_and_link.*dalfox" "${GUARDIAN_DIR}/setup.sh"; then
    # The issue is that dalfox tar contains 'dalfox_version' not 'dalfox'
    # Need to fix the install_github_release_and_link function or add special handling
    
    # Find the dalfox installation line
    if grep -q "install_github_release_and_link.*hahwul/dalfox" "${GUARDIAN_DIR}/setup.sh"; then
        echo "  Found dalfox installation - needs manual fix"
        echo "  Issue: tar contains 'dalfox_2.9.2' not 'dalfox'"
        echo ""
        echo "  Recommended fix: Use go install instead"
        
        # Add a fix function after install_github_release_and_link
        cat >> "${GUARDIAN_DIR}/setup.sh" << 'DALFOX_FIX'

# Fix for dalfox - use go install instead of binary download
install_dalfox_fixed() {
    echo "Installing dalfox..."
    
    if command -v dalfox >/dev/null 2>&1; then
        echo "✓ dalfox already installed"
        return 0
    fi
    
    if command -v go >/dev/null 2>&1; then
        echo "Installing via go install..."
        if go install github.com/hahwul/dalfox/v2@latest; then
            # Link into venv
            local go_bin="${GOPATH:-$HOME/go}/bin"
            if [[ -x "${go_bin}/dalfox" ]]; then
                link_into_venv "${go_bin}/dalfox" "dalfox"
                echo "✓ dalfox installed"
                return 0
            fi
        fi
    fi
    
    echo "WARN: Failed to install dalfox" >&2
    echo "Manual install: go install github.com/hahwul/dalfox/v2@latest" >&2
    return 1
}
DALFOX_FIX

        echo "✓ Added install_dalfox_fixed() function"
        
        # Now replace the call
        sed -i.bak 's/install_github_release_and_link.*dalfox.*/install_dalfox_fixed/g' "${GUARDIAN_DIR}/setup.sh"
        echo "✓ Updated dalfox installation call"
    fi
fi

echo ""

# Fix 2: Commix directory already exists
echo "Fix 2: Fixing commix installation (directory conflict)..."

# Find commix installation
if grep -q "git clone.*commix" "${GUARDIAN_DIR}/setup.sh"; then
    # Add check before cloning
    sed -i.bak 's|git clone https://github.com/commixproject/commix.git|if [[ ! -d "${TOOLS_DIR}/vendor/commix" ]] \&\& git clone https://github.com/commixproject/commix.git|g' "${GUARDIAN_DIR}/setup.sh"
    echo "✓ Added directory check for commix"
else
    echo "  No commix installation found - might be OK"
fi

echo ""

# Fix 3: Add general git clone safety
echo "Fix 3: Adding safe git clone function..."

cat >> "${GUARDIAN_DIR}/setup.sh" << 'SAFE_CLONE'

# Safe git clone that handles existing directories
safe_git_clone() {
    local repo_url="$1"
    local target_dir="$2"
    local repo_name=$(basename "$target_dir")
    
    if [[ -d "$target_dir" ]]; then
        echo "Directory already exists: $target_dir"
        
        # Check if it's a git repo
        if [[ -d "${target_dir}/.git" ]]; then
            echo "Updating existing repo..."
            (cd "$target_dir" && git pull) || echo "WARN: Failed to update $repo_name"
        else
            echo "Removing non-git directory and cloning fresh..."
            rm -rf "$target_dir"
            git clone "$repo_url" "$target_dir"
        fi
    else
        git clone "$repo_url" "$target_dir"
    fi
}
SAFE_CLONE

echo "✓ Added safe_git_clone() function"
echo ""

# Fix 4: Fix binary extraction issues
echo "Fix 4: Improving binary extraction..."

cat >> "${GUARDIAN_DIR}/setup.sh" << 'EXTRACT_FIX'

# Enhanced extraction that handles various archive formats
extract_binary_from_archive() {
    local archive="$1"
    local expected_binary="$2"
    local extract_dir="$3"
    
    mkdir -p "$extract_dir"
    
    # Extract archive
    if [[ "$archive" == *.tar.gz ]] || [[ "$archive" == *.tgz ]]; then
        tar -xzf "$archive" -C "$extract_dir"
    elif [[ "$archive" == *.tar ]]; then
        tar -xf "$archive" -C "$extract_dir"
    elif [[ "$archive" == *.zip ]]; then
        unzip -q "$archive" -d "$extract_dir"
    else
        echo "ERROR: Unknown archive format: $archive" >&2
        return 1
    fi
    
    # Find the binary (might have version suffix)
    local found_binary=""
    
    # Try exact match first
    if [[ -f "${extract_dir}/${expected_binary}" ]]; then
        found_binary="${extract_dir}/${expected_binary}"
    else
        # Try with version suffix (e.g., dalfox_2.9.2)
        found_binary=$(find "$extract_dir" -name "${expected_binary}*" -type f -executable | head -n 1)
    fi
    
    if [[ -n "$found_binary" ]]; then
        echo "Found binary: $found_binary"
        # Move to expected location if different
        if [[ "$found_binary" != "${extract_dir}/${expected_binary}" ]]; then
            mv "$found_binary" "${extract_dir}/${expected_binary}"
        fi
        chmod +x "${extract_dir}/${expected_binary}"
        return 0
    else
        echo "ERROR: Binary '$expected_binary' not found in archive" >&2
        echo "Archive contents:" >&2
        ls -la "$extract_dir" >&2
        return 1
    fi
}
EXTRACT_FIX

echo "✓ Added extract_binary_from_archive() function"
echo ""

# Create a summary script
cat > "${GUARDIAN_DIR}/SETUP_FIXES_APPLIED.md" << 'SUMMARY'
# Setup.sh Fixes Applied

## Issues Fixed

### 1. Dalfox Installation
**Problem:** Binary download extracts to 'dalfox_2.9.2' not 'dalfox'  
**Fix:** Added `install_dalfox_fixed()` that uses `go install` instead

### 2. Commix Directory Conflict
**Problem:** `git clone` fails when directory already exists  
**Fix:** Added directory check before cloning

### 3. General Git Clone Safety
**Fix:** Added `safe_git_clone()` function that:
- Checks if directory exists
- Updates existing repos instead of failing
- Removes corrupted directories and re-clones

### 4. Binary Extraction Issues
**Fix:** Added `extract_binary_from_archive()` that:
- Handles version-suffixed binaries
- Searches for binary with wildcards
- Renames to expected name

## Usage

### For Fresh Install
Just run setup.sh as normal:
```bash
./setup.sh
```

### To Fix Existing Issues

#### Clean Commix Directory
```bash
rm -rf tools/vendor/commix
./setup.sh
```

#### Force Reinstall Dalfox
```bash
go install github.com/hahwul/dalfox/v2@latest
```

## Rollback

If needed:
```bash
cp setup.sh_prefixes_* setup.sh
```

## Testing

Test specific tools:
```bash
# Test dalfox
dalfox version

# Test commix
python tools/vendor/commix/commix.py --version
```
SUMMARY

echo "✓ Created SETUP_FIXES_APPLIED.md"
echo ""

echo "=========================================="
echo "Fixes Complete!"
echo "=========================================="
echo ""
echo "Applied fixes:"
echo "  ✓ Dalfox installation (use go install)"
echo "  ✓ Commix directory check"
echo "  ✓ Safe git clone function"
echo "  ✓ Binary extraction improvements"
echo ""
echo "To apply fixes, run setup again:"
echo "  cd ${GUARDIAN_DIR}"
echo "  ./setup.sh"
echo ""
echo "If you still have issues:"
echo ""
echo "Clean slate for problematic tools:"
echo "  rm -rf tools/vendor/commix"
echo "  rm -rf tools/.bin/dalfox"
echo "  ./setup.sh"
echo ""