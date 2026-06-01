# VAPT Security Plugin - Deployment & Testing Guide

This guide explains how to test and deploy the VAPT Security plugin using your Local by Flywheel setup and production server.

## Quick Start

### 1. Sync to Local WordPress (Testing)

Run the sync script from WSL:

```bash
cd /path/to/your/plugin/repo
./sync-to-local.sh
```

**Default behavior:**
- Automatically syncs to your `vaptsecure` Local site
- Uses the path: `T:\~\Local925 Sites\vaptsecure\app\public\wp-content\plugins\VAPTSecurityFull-QWenCoder`

**Custom site name:**
```bash
./sync-to-local.sh my-other-site
```

### 2. Deploy to Production Server

Configure your SFTP credentials:

```bash
cp sftp-config-sample.txt sftp-config.txt
```

Edit `sftp-config.txt` with your server details:
```
HOST=your-server.com
PORT=22
USER=your-username
PASSWORD=your-password-or-use-key
REMOTE_PATH=/var/www/html/wp-content/plugins/VAPTSecurityFull-QWenCoder
```

Then deploy:
```bash
./deploy-sftp.sh sftp-config.txt
```

## How It Works

### Local Sync (`sync-to-local.sh`)

The script:
1. Detects your Local by Flywheel installation on Windows via WSL
2. Copies plugin files from Git repo to Local's plugins directory
3. Excludes development files (.git, tests, docs, etc.)
4. Preserves your plugin settings (doesn't delete wp-config or database)

**Path mapping:**
- Windows: `T:\~\Local925 Sites\vaptsecure\...`
- WSL: `/mnt/t/$/Local925 Sites/vaptsecure/...`

### Production Deploy (`deploy-sftp.sh`)

The script:
1. Connects to your server via SFTP (secure FTP)
2. Uploads only necessary plugin files
3. Excludes development and temporary files
4. Keeps your production settings intact

## Prerequisites

### For Local Sync:
- ✅ Local by Flywheel installed
- ✅ WSL (Windows Subsystem for Linux) with Ubuntu
- ✅ T: drive mounted in WSL (usually automatic)
- ✅ Site created in Local named `vaptsecure` (or customize)

### For SFTP Deploy:
- ✅ SFTP access to production server
- ✅ Server credentials (host, username, password/key)
- ✅ Write permissions to WordPress plugins directory

## Verify T: Drive Mount in WSL

Before running the sync script, verify your T: drive is accessible:

```bash
# From WSL terminal
ls /mnt/t
```

You should see your `~\Local925 Sites` folder listed. If not:
1. Open Windows PowerShell as Administrator
2. Run: `wsl --shutdown`
3. Restart WSL and try again

## Testing Workflow

1. **Make changes** in your Git repo (`/workspace`)
2. **Sync to Local**: `./sync-to-local.sh`
3. **Test locally** in browser: `http://vaptsecure.local/wp-admin`
4. **Verify functionality** in WP Admin → Plugins → VAPTSecurityFull-QWenCoder
5. **Deploy to production**: `./deploy-sftp.sh sftp-config.txt`
6. **Test on production** server

## Troubleshooting

### "Could not find Local site" error

**Check 1:** Verify T: drive is mounted
```bash
ls /mnt/t
```

**Check 2:** Verify site exists
```bash
ls "/mnt/t/\$/Local925 Sites/"
```

**Check 3:** Manually create plugin directory if needed
```bash
mkdir -p "/mnt/t/\$/Local925 Sites/vaptsecure/app/public/wp-content/plugins/VAPTSecurityFull-QWenCoder"
```

### SFTP Connection Failed

**Check 1:** Verify credentials in `sftp-config.txt`
**Check 2:** Test connection manually:
```bash
sftp -P 22 your-username@your-server.com
```
**Check 3:** Ensure firewall allows SFTP (port 22)

### Plugin Not Appearing in WP Admin

1. Deactivate and reactivate the plugin
2. Clear WordPress cache
3. Check file permissions on server:
   ```bash
   chmod 755 wp-content/plugins/VAPTSecurityFull-QWenCoder
   chmod 644 wp-content/plugins/VAPTSecurityFull-QWenCoder/*.php
   ```

## File Exclusions

Both scripts exclude these files/folders from sync/deploy:
- `.git/` - Version control
- `.agent/` - Development tools
- `DevDocs/`, `ReqDocs/` - Documentation
- `tests/` - Test files
- `*.zip` - Release packages
- `sync-to-local.sh`, `deploy-sftp.sh` - Scripts themselves
- Other development artifacts

## Alternative: Manual ZIP Upload

If you prefer manual deployment:

```bash
# Create release ZIP
cd /workspace
zip -r vapt-security-latest.zip \
    *.php \
    assets/ \
    includes/ \
    templates/ \
    languages/ \
    -x "*.git*" -x "tests/*" -x "*.zip" -x "DevDocs/*" -x "ReqDocs/*"
```

Then upload `vapt-security-latest.zip` via:
- WP Admin → Plugins → Add New → Upload Plugin
- Or extract on server via SSH

## Support

For issues with:
- **Local by Flywheel**: Check [Local's documentation](https://localwp.com/help-docs/)
- **WSL mounting**: See [Microsoft WSL docs](https://docs.microsoft.com/en-us/windows/wsl/filesystems)
- **SFTP issues**: Contact your hosting provider
- **Plugin bugs**: Check plugin documentation or open GitHub issue

---

**Last Updated:** 2025
**Plugin Version:** 3.2.1
**Compatible:** WordPress 6.3+, PHP 8.0+
