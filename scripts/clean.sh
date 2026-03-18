#!/bin/bash

# Azure Guest Attestation SDK - Clean Script
# Removes build artifacts and verifies .gitignore is working

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

# Command line options
DRY_RUN=false
VERBOSE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--dry-run] [--verbose]"
            echo "  --dry-run   Show what would be cleaned without deleting"
            echo "  --verbose   Show detailed output"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo -e "${GREEN}Azure Guest Attestation SDK - Clean Script${NC}"

# Get project root (directory containing this script)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Define patterns to clean
declare -a CLEAN_PATTERNS=(
    # Rust build artifacts
    "target"
    "Cargo.lock"
    
    # Native libraries (stray copies outside target/)
    "*.dll"
    "*.so"
    "*.dylib" 
    "*.pdb"
    
    # Logs and temp files
    "*.log"
    "*.tmp"
    "*.temp"
)

items_found=0
items_removed=0

clean_build_artifacts() {
    echo -e "\n${CYAN}=== Cleaning Build Artifacts ===${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "${YELLOW}🔍 DRY RUN MODE - No files will be deleted${NC}"
    fi
    
    cd "$PROJECT_ROOT"
    
    for pattern in "${CLEAN_PATTERNS[@]}"; do
        if [[ "$VERBOSE" == "true" ]]; then
            echo -e "${GRAY}Checking pattern: $pattern${NC}"
        fi
        
        # Use find to locate files/directories matching the pattern
        while IFS= read -r -d '' item; do
            # Make path relative to project root
            rel_path="${item#$PROJECT_ROOT/}"
            
            if [[ -n "$rel_path" ]]; then
                ((items_found++))
                echo -e "${YELLOW}Found: $rel_path${NC}"
                
                if [[ "$DRY_RUN" == "false" ]]; then
                    rm -rf "$item"
                    echo -e "  ${GREEN}✓ Removed${NC}"
                    ((items_removed++))
                else
                    echo -e "  ${CYAN}🔍 Would remove (dry run)${NC}"
                fi
            fi
        done < <(find "$PROJECT_ROOT" -name "$pattern" -print0 2>/dev/null || true)
    done
}

test_gitignore() {
    echo -e "\n${CYAN}=== Testing .gitignore ===${NC}"
    
    cd "$PROJECT_ROOT"
    
    # Check if we're in a git repository
    if ! git rev-parse --git-dir >/dev/null 2>&1; then
        echo -e "${RED}❌ Not in a git repository${NC}"
        return
    fi
    
    # Check git status for untracked files that should be ignored
    untracked_files=$(git status --porcelain=v1 | grep '^??' | cut -c4- || true)
    
    problem_files=()
    while IFS= read -r file; do
        if [[ -n "$file" ]]; then
            # Check if this looks like a build artifact
            if [[ "$file" =~ \.(dll|so|dylib|pdb|pyc|pyo)$ ]] || 
               [[ "$file" =~ (target|build|dist|__pycache__)/ ]] ||
               [[ "$file" =~ \.egg-info/ ]]; then
                problem_files+=("$file")
            fi
        fi
    done <<< "$untracked_files"
    
    if [[ ${#problem_files[@]} -eq 0 ]]; then
        echo -e "${GREEN}✅ .gitignore is working correctly - no build artifacts in git status${NC}"
    else
        echo -e "${YELLOW}⚠️  Found untracked build artifacts that should be ignored:${NC}"
        for file in "${problem_files[@]}"; do
            echo -e "  ${RED}- $file${NC}"
        done
        echo -e "${YELLOW}Consider updating .gitignore to ignore these patterns${NC}"
    fi
}

# Main execution
clean_build_artifacts

echo -e "\n${CYAN}=== Clean Summary ===${NC}"
echo -e "${YELLOW}Items found: $items_found${NC}"

if [[ "$DRY_RUN" == "true" ]]; then
    echo -e "${CYAN}Items that would be removed: $items_found${NC}"
    echo -e "${GRAY}Run without --dry-run to actually clean files${NC}"
else
    echo -e "${GREEN}Items removed: $items_removed${NC}"
fi

# Test .gitignore
test_gitignore

echo -e "\n${GREEN}✅ Clean operation complete!${NC}"