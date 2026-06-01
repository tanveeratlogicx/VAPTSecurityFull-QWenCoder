# Build Tracking - Refresh/Ping/Track Button Implementation Plan

## Overview

Add a per-row "Refresh Status" button and a bulk "Ping Selected" action to the Build Tracking tab. Both queue a `FORCE_CHECKIN` command that tells the client build to immediately send a heartbeat back to the master.

- ONLINE builds respond immediately
- OFFLINE builds respond when they next check in
- Table auto-refreshes after pinging to show updated status
- Passive 6-hour refresh catches missed scheduled updates

## Files Modified

| File | Changes |
|------|---------|
| `vapt-security.php` | +2 AJAX registrations, +2 new methods (`handle_refresh_build_status`, `handle_get_tracking_table`), +`FORCE_CHECKIN` case in `process_remote_commands()` |
| `templates/admin-domain-control.php` | Checkbox column, refresh button, "Ping Selected" button, JS handlers, CSS spin animation |

---

## Part 1: PHP - `vapt-security.php`

### 1a. Register new AJAX actions (near line 227)

```php
add_action( 'wp_ajax_vapt_refresh_build_status', [ $this, 'handle_refresh_build_status' ] );
add_action( 'wp_ajax_vapt_get_tracking_table', [ $this, 'handle_get_tracking_table' ] );
```

### 1b. `handle_refresh_build_status()` - new method

- `check_ajax_referer( 'vapt_locked_config', 'nonce' )` + `is_master_admin()` check
- Accept `$_POST['build_ids']` (comma-separated string)
- Validate each build_id exists in `vapt_build_tracking`
- Queue `['type' => 'FORCE_CHECKIN']` into `vapt_pending_commands[$bid]` for each
- Return `{ success: true, data: { queued: N, builds: [...] } }`

### 1c. `handle_get_tracking_table()` - new method

- Reads `vapt_build_tracking` fresh from DB
- Returns only the `<tbody>` inner HTML of the tracking table
- Includes checkbox column + refresh button in Actions column
- JS replaces `$('#vapt-tab-tracking .vapt-history-table tbody')` with response

### 1d. Add `FORCE_CHECKIN` case in `process_remote_commands()` (line 3067)

```php
case 'FORCE_CHECKIN':
    $this->maybe_trigger_callback();
    break;
```

---

## Part 2: PHP - Template Changes (`templates/admin-domain-control.php`)

### 2a. Table header - add checkbox column after `#` (line 896)

```php
<th style="width: 30px;"><input type="checkbox" id="vapt-select-all-tracking"></th>
```

### 2b. "Ping Selected" button - above the table

```php
<div style="margin-bottom: 10px;">
    <button id="vapt-ping-selected" class="button" disabled>
        <span class="dashicons dashicons-update" style="margin-top:4px;"></span> Ping Selected
    </button>
</div>
```

### 2c. Per-row checkbox - in each `<tr>` after the `#` cell

```php
<td style="text-align:center;"><input type="checkbox" class="vapt-tracking-checkbox" value="<?php echo esc_attr($bid); ?>"></td>
```

### 2d. Refresh button - in Actions `<td>`, before the manage button

```php
<button type="button" class="button button-small vapt-refresh-build" 
    data-id="<?php echo esc_attr($bid); ?>"
    title="Refresh Status">
    <span class="dashicons dashicons-update" style="font-size: 16px; margin-top: 3px;"></span>
</button>
```

### 2e. Update colspan for empty state row from 13 to 14

---

## Part 3: JavaScript - Handlers + Auto-Refresh

### 3a. `vaptRefreshTrackingTable()` - reusable function

- Calls `vapt_get_tracking_table` AJAX with nonce
- Replaces the `<tbody>` with returned HTML

### 3b. Per-row refresh click

- Spin the icon -> send AJAX `vapt_refresh_build_status` with single build_id
- On success: toast notification, start post-ping refresh burst

### 3c. Select All / individual checkbox toggling

- `#vapt-select-all-tracking` toggles all `.vapt-tracking-checkbox`
- Individual changes update select-all + enable/disable "Ping Selected"

### 3d. Bulk "Ping Selected" click

- Collect checked IDs -> send AJAX -> on success: toast + post-ping refresh burst

### 3e. Post-ping refresh burst

- After successful ping (single or bulk): poll `vaptRefreshTrackingTable()` every 5 seconds for up to 60 seconds
- Early-stop if all `last_seen` values have updated
- Catches ONLINE builds that respond within seconds

### 3f. Passive auto-refresh

- `setInterval` every **6 hours** (21,600,000 ms): call `vaptRefreshTrackingTable()`
- Only active when the Build Tracking tab is visible (`document.hidden` check)
- Passively catches missed scheduled updates without any user action

---

## Part 4: CSS

```css
.vapt-spin {
    animation: vapt-spin-anim 1s linear infinite;
}
@keyframes vapt-spin-anim {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
}
```

---

## UX Summary

- **Manual ping**: Click refresh icon -> spin -> "Ping Queued" toast -> table auto-refreshes every 5s for 60s -> see updated status when build responds
- **Bulk ping**: Check rows -> "Ping Selected" -> same burst behavior
- **Passive monitoring**: Table silently refreshes every 6 hours - if a build missed a scheduled update, it surfaces on the next passive cycle
