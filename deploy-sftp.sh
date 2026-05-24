#!/bin/bash
#
# deploy-sftp.sh - Deploy VAPT Security plugin to remote server via SFTP
#
# Usage: ./deploy-sftp.sh [config-file]
# Example: ./deploy-sftp.sh sftp-config.txt
#

set -e

# Configuration
PLUGIN_NAME="vapt-security"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}VAPT Security - SFTP Deploy Tool${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check if config file provided
if [ -z "$1" ]; then
    echo -e "${YELLOW}Usage: $0 <sftp-config-file>${NC}"
    echo ""
    echo "Create a config file with the following format:"
    echo "----------------------------------------"
    echo "HOST=your-server.com"
    echo "PORT=22"
    echo "USER=your-username"
    echo "PASS=your-password"
    echo "# or use key authentication:"
    echo "# KEY=/path/to/private/key"
    echo "REMOTE_PATH=/var/www/html/wp-content/plugins"
    echo "# REMOTE_PATH=/home/username/public_html/wp-content/plugins  # cPanel"
    echo "----------------------------------------"
    echo ""
    echo "Example config files:"
    if [ -f "$SOURCE_DIR/sftp-config-sample.txt" ]; then
        echo "  - sftp-config-sample.txt (sample)"
    fi
    echo ""
    echo -e "${YELLOW}Security Tip: Set permissions to 600 on your config file:${NC}"
    echo "  chmod 600 your-config-file.txt"
    echo ""
    exit 1
fi

CONFIG_FILE="$1"

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}Error: Config file '$CONFIG_FILE' not found${NC}"
    exit 1
fi

# Load configuration
echo -e "${BLUE}Loading configuration from: $CONFIG_FILE${NC}"
source "$CONFIG_FILE"

# Validate required variables
if [ -z "$HOST" ] || [ -z "$USER" ] || [ -z "$REMOTE_PATH" ]; then
    echo -e "${RED}Error: Missing required configuration variables${NC}"
    echo "Required: HOST, USER, REMOTE_PATH"
    exit 1
fi

# Set default port if not specified
PORT=${PORT:-22}

# Build remote path
REMOTE_PLUGIN_PATH="$REMOTE_PATH/$PLUGIN_NAME"

echo ""
echo -e "${GREEN}Deployment Configuration:${NC}"
echo "  Host: $HOST:$PORT"
echo "  User: $USER"
echo "  Remote Path: $REMOTE_PLUGIN_PATH"
echo ""

# Check authentication method
if [ -n "$KEY" ] && [ -f "$KEY" ]; then
    echo -e "${BLUE}Using SSH key authentication${NC}"
    SSH_OPTS="-i $KEY -o StrictHostKeyChecking=no -o BatchMode=yes"
elif [ -n "$PASS" ]; then
    echo -e "${BLUE}Using password authentication${NC}"
    SSH_OPTS="-o StrictHostKeyChecking=no"
    # Create SSH password file for lftp/sftp
    echo "set sftp:connect-program \"ssh -a -x -o StrictHostKeyChecking=no\"" > /tmp/lftp_cmds_$$.txt
else
    echo -e "${RED}Error: No valid authentication method found${NC}"
    echo "Provide either KEY (path to private key) or PASS (password) in config"
    exit 1
fi

echo ""
echo -e "${YELLOW}Preparing deployment package...${NC}"

# Create temporary directory for deployment
DEPLOY_DIR=$(mktemp -d)
trap "rm -rf $DEPLOY_DIR" EXIT

# Copy files to deploy directory (excluding unnecessary files)
rsync -av \
    --exclude='.git' \
    --exclude='.agent' \
    --exclude='DevDocs' \
    --exclude='ReqDocs' \
    --exclude='graphify-out' \
    --exclude='releases' \
    --exclude='tests' \
    --exclude='*.zip' \
    --exclude='.gitignore' \
    --exclude='test-*.php' \
    --exclude='prompt.txt' \
    --exclude='sync-to-local.sh' \
    --exclude='deploy-sftp.sh' \
    --exclude='sftp-config*.txt' \
    --exclude='.DS_Store' \
    "$SOURCE_DIR/" "$DEPLOY_DIR/"

echo -e "${GREEN}✓ Package prepared${NC}"
echo ""

# Deploy using lftp (more reliable than sftp for batch operations)
if command -v lftp &> /dev/null; then
    echo -e "${YELLOW}Deploying via lftp...${NC}"
    
    if [ -n "$KEY" ] && [ -f "$KEY" ]; then
        lftp -c "
            set sftp:connect-program 'ssh -i $KEY -x -o StrictHostKeyChecking=no';
            open sftp://$USER@$HOST:$PORT;
            cd $REMOTE_PATH;
            mirror --reverse --delete --verbose --exclude='.git*' --exclude='*.zip' $DEPLOY_DIR $PLUGIN_NAME;
            bye;
        "
    else
        # Password authentication with lftp
        lftp -c "
            open -u $USER,$PASS sftp://$HOST:$PORT;
            set sftp:connect-program 'ssh -x -o StrictHostKeyChecking=no';
            cd $REMOTE_PATH;
            mirror --reverse --delete --verbose --exclude='.git*' --exclude='*.zip' $DEPLOY_DIR $PLUGIN_NAME;
            bye;
        "
    fi
    
else
    # Fallback to rsync over SSH
    echo -e "${YELLOW}lftp not found, deploying via rsync over SSH...${NC}"
    
    if [ -n "$KEY" ] && [ -f "$KEY" ]; then
        rsync -avz -e "ssh -i $KEY -o StrictHostKeyChecking=no" \
            --delete \
            "$DEPLOY_DIR/" \
            "$USER@$HOST:$REMOTE_PLUGIN_PATH/"
    else
        # For password auth, we need sshpass
        if command -v sshpass &> /dev/null; then
            sshpass -p "$PASS" rsync -avz -e "ssh -o StrictHostKeyChecking=no" \
                --delete \
                "$DEPLOY_DIR/" \
                "$USER@$HOST:$REMOTE_PLUGIN_PATH/"
        else
            echo -e "${RED}Error: Neither lftp nor sshpass available for password authentication${NC}"
            echo "Install lftp: sudo apt-get install lftp"
            echo "Or install sshpass: sudo apt-get install sshpass"
            echo "Or use SSH key authentication (recommended)"
            exit 1
        fi
    fi
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✓ Deployment Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Plugin deployed to: $USER@$HOST:$REMOTE_PLUGIN_PATH"
echo ""
echo "Next steps:"
echo "1. Log into your WordPress admin panel"
echo "2. Go to Plugins page"
echo "3. If plugin was active, deactivate and reactivate it"
echo "4. Test the updated functionality"
echo ""
echo -e "${YELLOW}Tip: Check the plugin version in WP Admin → VAPT Security${NC}"
