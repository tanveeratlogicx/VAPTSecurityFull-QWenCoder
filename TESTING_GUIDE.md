# Testing & Deployment Guide

This guide explains how to test your VAPT Security plugin changes before deploying to production.

## Quick Start

You have **two main options** for testing:

### Option 1: Sync to Local by Flywheel (Recommended for Development)
### Option 2: Deploy to Remote Server via SFTP (For Staging/Production Testing)

---

## Option 1: Local Testing with Local by Flywheel

### Prerequisites
- Local by Flywheel installed on your system
- WSL (Ubuntu) accessible on Windows, or native Linux
- At least one WordPress site created in Local

### Setup Steps

1. **Make the sync script executable** (already done):
   ```bash
   chmod +x sync-to-local.sh
   ```

2. **Find your Local site name**:
   ```bash
   ./sync-to-local.sh
   ```
   This will list all available Local sites.

3. **Sync to your Local site**:
   ```bash
   ./sync-to-local.sh your-site-name
   ```
   
   Example:
   ```bash
   ./sync-to-local.sh mytestsite
   ```

### What It Does
- Automatically detects your Local by Flywheel installation
- Syncs only necessary plugin files (excludes .git, tests, docs, etc.)
- Preserves existing plugin data and settings
- Uses `rsync` for fast, incremental updates

### After Syncing
1. Open Local by Flywheel
2. Start your test site
3. Click "WP Admin" to open WordPress dashboard
4. Go to **Plugins → Installed Plugins**
5. Activate "VAPT Security" if not already active
6. Test your changes!

### Pro Tips
- Run the sync command anytime you make changes
- The script uses `--delete` flag, so removed files will be cleaned up
- Plugin settings are preserved (stored in database, not files)

---

## Option 2: Remote Deployment via SFTP

### Prerequisites
- SSH/SFTP access to your remote server
- Either:
  - `lftp` installed (`sudo apt-get install lftp`), OR
  - `sshpass` installed (`sudo apt-get install sshpass`) for password auth
- WordPress installed on remote server

### Setup Steps

1. **Create your SFTP configuration**:
   ```bash
   cp sftp-config-sample.txt sftp-config.txt
   ```

2. **Edit the config file** with your server details:
   ```bash
   nano sftp-config.txt
   ```
   
   Fill in:
   - `HOST` - Your server domain or IP
   - `USER` - SSH username
   - `PASS` or `KEY` - Password or SSH key path
   - `REMOTE_PATH` - Path to wp-content/plugins

3. **Secure the config file**:
   ```bash
   chmod 600 sftp-config.txt
   ```

4. **Deploy to remote server**:
   ```bash
   ./deploy-sftp.sh sftp-config.txt
   ```

### What It Does
- Creates a clean deployment package (excludes dev files)
- Connects via SFTP securely
- Uploads only changed files (incremental deployment)
- Supports both password and SSH key authentication

### Authentication Methods

#### SSH Key (Recommended)
```bash
# In sftp-config.txt:
KEY=/home/username/.ssh/id_rsa
# Comment out PASS line
```

#### Password Authentication
```bash
# In sftp-config.txt:
PASS=your-password
# Comment out KEY line
```

### After Deployment
1. Log into your WordPress admin panel
2. Go to **Plugins** page
3. If plugin was active, deactivate and reactivate it
4. Check **VAPT Security** menu for version number
5. Test functionality thoroughly

### Pro Tips
- Always test on a staging server first
- Use SSH keys instead of passwords for better security
- Keep a backup before deploying to production
- The script shows detailed progress during deployment

---

## Alternative: Manual ZIP Package

If you prefer manual deployment:

1. **Create a clean ZIP package**:
   ```bash
   mkdir -p /tmp/vapt-security
   rsync -av \
     --exclude='.git' \
     --exclude='.agent' \
     --exclude='DevDocs' \
     --exclude='tests' \
     --exclude='*.zip' \
     --exclude='*.sh' \
     --exclude='sftp-config*.txt' \
     ./ /tmp/vapt-security/
   
   cd /tmp && zip -r vapt-security-deploy.zip vapt-security/
   ```

2. **Download the ZIP** from `/tmp/vapt-security-deploy.zip`

3. **Upload manually** via:
   - WordPress Admin → Plugins → Add New → Upload Plugin
   - Or extract directly on server via SSH

---

## Workflow Recommendations

### Daily Development
```bash
# Make code changes
# Then sync to local:
./sync-to-local.sh mytestsite

# Test in Local by Flywheel browser
# Repeat as needed
```

### Pre-Release Testing
```bash
# Deploy to staging server
./deploy-sftp.sh staging-config.txt

# Test on staging WordPress
# Fix any issues
# Sync back to workspace if needed
```

### Production Deployment
```bash
# After staging approval
./deploy-sftp.sh production-config.txt

# Monitor logs and functionality
# Keep rollback plan ready
```

---

## Troubleshooting

### sync-to-local.sh Issues

**"Could not find Local site"**
- Check site name is exact (case-sensitive)
- Ensure Local by Flywheel has finished creating the site
- If on Windows, run from WSL (Ubuntu), not PowerShell

**Permission denied**
- Make sure script is executable: `chmod +x sync-to-local.sh`
- Check WSL can access Windows directories

### deploy-sftp.sh Issues

**"lftp not found"**
- Install: `sudo apt-get install lftp`
- Or use SSH key with rsync fallback

**"sshpass not found"**
- Install: `sudo apt-get install sshpass`
- Or switch to SSH key authentication (recommended)

**Connection refused**
- Verify server hostname and port
- Check firewall allows SSH (port 22)
- Confirm SSH service is running on server

**Authentication failed**
- Double-check username/password
- For SSH keys, ensure public key is in `~/.ssh/authorized_keys` on server
- Check key permissions: `chmod 600 ~/.ssh/id_rsa`

---

## Best Practices

1. **Always test locally first** before remote deployment
2. **Use version control** - commit before deploying
3. **Keep configs secure** - never commit sftp-config.txt to Git
4. **Test on staging** before production
5. **Backup databases** before major updates
6. **Check PHP error logs** after deployment
7. **Verify plugin version** in WP Admin after deploy

---

## Quick Reference

| Task | Command |
|------|---------|
| List Local sites | `./sync-to-local.sh` |
| Sync to Local | `./sync-to-local.sh sitename` |
| Deploy to Remote | `./deploy-sftp.sh config.txt` |
| Secure config file | `chmod 600 sftp-config.txt` |
| Install lftp | `sudo apt-get install lftp` |
| Install sshpass | `sudo apt-get install sshpass` |

---

## Need Help?

- Check plugin logs: WP Admin → VAPT Security → Logs
- Enable debug mode in `vapt-config.php`
- Review `CHANGELOG.md` for recent changes
- Consult `DOCUMENTATION.md` for feature details
