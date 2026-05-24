# Quick Start Guide - Testing Your VAPT Security Plugin

## Problem
The `sync-to-local.sh` script returns "No such file or directory" because your T: drive is not mounted in WSL.

## Solution Options

### Option 1: Mount T: Drive in WSL (Recommended)

Run this command in your WSL terminal:
```bash
sudo mount -t drvfs T: /mnt/t
```

Then run the sync script:
```bash
./sync-to-local.sh vaptsecure
```

**Note:** You may need to remount after reboot. To make it permanent, add to `/etc/fstab`:
```
T: /mnt/t drvfs defaults 0 0
```

### Option 2: Manual Copy from Windows

Since you're on Windows, simply copy the files directly:

1. **Source folder** (this repo): `/workspace` (access via `\\wsl$\<DistroName>\workspace`)
2. **Destination folder**: 
   ```
   T:\~\Local925 Sites\vaptsecure\app\public\wp-content\plugins\VAPTSecurityFull-QWenCoder
   ```

**Steps:**
- Open File Explorer
- Navigate to `\\wsl$\Ubuntu\workspace` (replace Ubuntu with your distro name)
- Copy all files except `.git`, `node_modules`, etc.
- Paste to `T:\~\Local925 Sites\vaptsecure\app\public\wp-content\plugins\VAPTSecurityFull-QWenCoder`

### Option 3: Use WP-CLI (If Available)

If you have WP-CLI installed in WSL:
```bash
# Activate the plugin
wp plugin activate VAPTSecurityFull-QWenCoder --path="/mnt/t/\$/Local925 Sites/vaptsecure/app/public"

# Or run tests
wp plugin list --path="/mnt/t/\$/Local925 Sites/vaptsecure/app/public"
```

## After Syncing

1. Visit: http://vaptsecure.local/wp-admin
2. Go to Plugins page
3. Ensure "VAPT Security Full" is activated
4. Test the features

## Troubleshooting

**"Permission denied"**: Run `sudo chmod -R 755` on the plugin folder

**Files not updating**: Delete the plugin folder and re-sync

**Can't access T: drive**: Make sure Local by Flywheel is not locking the files
