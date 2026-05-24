#!/bin/bash
#
# sync-to-local.sh - Sync VAPT Security plugin to Local by Flywheel
#
# Usage: ./sync-to-local.sh [site-name]
# Example: ./sync-to-local.sh vaptsecure
#

set -e

PLUGIN_NAME="VAPTSecurityFull-QWenCoder"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}VAPT Security - Local Sync Tool${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

show_usage() {
    echo -e "${YELLOW}Usage: $0 <site-name>${NC}"
    echo ""
    echo "Examples:"
    echo "  $0 vaptsecure              # Sync to vaptsecure site"
    echo ""
    echo "Note: If your T: drive is not mounted in WSL:"
    echo "  Run: sudo mount -t drvfs T: /mnt/t"
    echo ""
    
    if [ -d "/mnt/t" ]; then
        echo -e "${BLUE}Sites on T: drive:${NC}"
        find /mnt/t -type d -name "Local Sites" 2>/dev/null | while read dir; do
            ls -1 "$dir" 2>/dev/null | sed "s/^/  - /"
        done
    else
        echo -e "${YELLOW}T: drive not mounted at /mnt/t${NC}"
    fi
    echo ""
    exit 1
}

if [ -z "$1" ]; then
    show_usage
fi

SITE_NAME="$1"
TARGET_DIR=""

# Try different path variations (handle both $ and ~ in path)
PATHS=(
    "/mnt/t/\$/Local925 Sites/$SITE_NAME/app/public/wp-content/plugins/$PLUGIN_NAME"
    "/mnt/t/~/Local925 Sites/$SITE_NAME/app/public/wp-content/plugins/$PLUGIN_NAME"
    "/mnt/t/-/Local925 Sites/$SITE_NAME/app/public/wp-content/plugins/$PLUGIN_NAME"
)

echo -e "${BLUE}Looking for: ${GREEN}$SITE_NAME${NC}"

for path in "${PATHS[@]}"; do
    parent=$(dirname "$path")
    if [ -d "$parent" ]; then
        TARGET_DIR="$path"
        break
    fi
done

if [ -z "$TARGET_DIR" ]; then
    echo -e "${RED}✗ Site not found${NC}"
    echo ""
    echo "Please run this command first to mount your T: drive:"
    echo -e "  ${BLUE}sudo mount -t drvfs T: /mnt/t${NC}"
    echo ""
    echo "Then run this script again."
    echo ""
    echo "Alternative: Copy files manually from:"
    echo "  $SOURCE_DIR"
    echo "  to:"
    echo "  T:\\~\\Local925 Sites\\$SITE_NAME\\app\\public\\wp-content\\plugins\\$PLUGIN_NAME"
    exit 1
fi

echo -e "${GREEN}✓ Target: ${NC}$TARGET_DIR"
echo ""

# Create directory if needed
mkdir -p "$TARGET_DIR"

# Check if rsync is available
if ! command -v rsync &> /dev/null; then
    echo -e "${YELLOW}rsync not found, using cp instead...${NC}"
    cp -r "$SOURCE_DIR"/* "$TARGET_DIR/"
else
    echo -e "${BLUE}Syncing files...${NC}"
    rsync -av --delete \
        --exclude='.git' \
        --exclude='node_modules' \
        --exclude='*.log' \
        --exclude='.env*' \
        --exclude='tests/' \
        --exclude='.github/' \
        "$SOURCE_DIR/" "$TARGET_DIR/"
fi

echo ""
echo -e "${GREEN}✓ Sync complete!${NC}"
echo ""
echo "Visit: http://$SITE_NAME.local/wp-admin"
echo "Plugin folder: $TARGET_DIR"
