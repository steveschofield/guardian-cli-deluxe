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
