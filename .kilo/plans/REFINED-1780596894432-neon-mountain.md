# Plan: Add IP-Address Binding & Optional Single-Instance Enforcement to the Build Generator (REVISED)

## Objective
Replace the existing domain-only lock with a flexible system where a build can be tied to either a **domain** or an **IPv4 address**. Additionally, introduce an optional **Single-Instance** mode that restricts the build to one server at a time.

## Scope

### `templates/admin-domain-control.php`
1. Replace the "Domain Type" and "Domain Pattern" fields with a unified lock selector.
2. Update AJAX data for `vapt_generate_locked_config` and `vapt_generate_client_zip` to send `lock_type`, `lock_value`, and `single_instance`.
3. Update the History Table and edit/reuse form logic.

### `vapt-security.php`
1. Accept and sanitize `lock_type`, `lock_value`, and `single_instance` inputs.
2. Update the build payload and history to include these new properties.
3. Update `enforce_domain_lock()` to handle `ip` alongside the `lock_type`.
4. Implement single-instance enforcement using WordPress transients.

## Research

### Current Architecture
- Locked config `vapt-{domain}-locked-config.php` contains JSON payload with `domain_pattern` and `domain_type`.
- `enforce_domain_lock()` validates `$_SERVER['HTTP_HOST']` against `domain_type` rules (standard, wildcard, universal).
- History stores metadata in `vapt_build_history` (WordPress option, not DB table).
- Current file naming: `vapt-{sanitized_domain}-locked-config.php` or `vapt-security-{sanitized_domain}.zip`

### Key Constraints
- Domain lock must be retained as an option.
- IP lock must be a distinct alternative, not an additional check.
- Single-instance mode must enforce IP-based uniqueness.
- All builds without `lock_type` must default to existing behavior (backward compatibility).

## Detailed Steps

### Step 0: Add Helper Function for IP Validation (`includes/class-license.php`)
Add a static helper method for validating IPv4 addresses:
```php
public static function is_valid_ipv4($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
}
```

### Step 1: Form UI (`templates/admin-domain-control.php`)
1. Replace the "Domain Pattern" row with:
   - **Lock Type**: `<select id="vapt-lock-type">` with options:
     - `domain` - Domain-based lock (default)
     - `ip` - IPv4 address lock
   - **Lock Value**: `<input id="vapt-lock-value">` - changes label/placeholder based on lock type:
     - Domain mode: label "Domain Pattern", placeholder "*.example.com"
     - IP mode: label "IPv4 Address", placeholder "192.168.1.1"
2. Add **Single Instance** checkbox (`<input type="checkbox" id="vapt-single-instance">`) with tooltip explaining the feature.
3. Update the Domain Type selector - only show when lock_type is "domain". Hide when lock_type is "ip".

### Step 2: JavaScript Logic (`templates/admin-domain-control.php` - Inline JS)
1. In `$('#vapt-generate-locked-config').click(...)`:
   - Add: `lock_type: $('#vapt-lock-type').val()`
   - Add: `lock_value: $('#vapt-lock-value').val())`
   - Add: `single_instance: $('#vapt-single-instance').is(':checked') ? 1 : 0`

2. In `doGenerateClientZip()`:
   - Add same three fields to the params object.

3. Add change handler for lock type:
```javascript
$('#vapt-lock-type').change(function(){
    var type = $(this).val();
    if (type === 'ip') {
        $('#vapt-lock-type-label').text('IPv4 Address');
        $('#vapt-lock-value').attr('placeholder', '192.168.1.1');
        // Hide domain type selector
        $('#vapt-domain-type-row').hide();
    } else {
        $('#vapt-lock-type-label').text('Domain Pattern');
        $('#vapt-lock-value').attr('placeholder', '*.example.com');
        // Show domain type selector
        $('#vapt-domain-type-row').show();
    }
});
```

### Step 3: Server-Side Handlers (`vapt-security.php`)
In `handle_generate_locked_config()` and `handle_generate_client_zip()`:
```php
$lock_type = sanitize_text_field($_POST['lock_type'] ?? 'domain');
$lock_value = sanitize_text_field($_POST['lock_value'] ?? '');
$single_instance = !empty($_POST['single_instance']);

// Validate IP if lock_type is 'ip'
if ($lock_type === 'ip') {
    if (!VAPT_License::is_valid_ipv4($lock_value)) {
        wp_send_json_error(['message' => 'Invalid IPv4 address format.']);
        return;
    }
}

// For domain type, sanitize the value
if ($lock_type === 'domain' && empty($lock_value)) {
    $lock_value = sanitize_text_field($_SERVER['HTTP_HOST'] ?? 'localhost');
}
```

Add to payload:
```php
$payload['lock_type'] = $lock_type;
$payload['lock_value'] = $lock_value;
$payload['single_instance'] = $single_instance;
$payload['domain_type'] = $lock_type === 'domain' ? sanitize_text_field($_POST['domain_type'] ?? 'standard') : null;
```

### Step 4: History Update (`vapt-security.php`)
In `add_build_to_history()`:
```php
$entry = [
    'id' => $build_id,
    'domain' => $payload['lock_value'],
    'domain_type' => $payload['domain_type'] ?? 'standard',
    'lock_type' => $payload['lock_type'] ?? 'domain',
    'lock_value' => $payload['lock_value'],
    'single_instance' => $payload['single_instance'] ?? false,
    // ... existing fields ...
];

// Backward compatibility: For old builds without lock_type, set defaults
if (!isset($entry['lock_type'])) {
    $entry['lock_type'] = 'domain';
    $entry['lock_value'] = $entry['domain'];
}
```

### Step 5: History Table UI Update (`templates/admin-domain-control.php`)
1. Add new columns in `<thead>`:
   - `Lock Type` - Shows icon (🌐 for domain, 📍 for IP)
   - `Single` - Shows ✓ if enabled

2. Update row rendering loop:
```php
// Determine lock type icon
$lock_icon = (($build['lock_type'] ?? 'domain') === 'ip') ? '📍' : '🌐';
$single_icon = !empty($build['single_instance']) ? '✓' : '';
```

3. Update `.vapt-edit-build` data attributes:
```php
data-lock-type="<?php echo esc_attr($build['lock_type'] ?? 'domain'); ?>"
data-lock-value="<?php echo esc_attr($build['lock_value'] ?? $build['domain']); ?>"
data-single-instance="<?php echo esc_attr(!empty($build['single_instance']) ? '1' : '0'); ?>"
```

4. Update Edit handler:
```javascript
$('#vapt-lock-type').val(btn.data('lock-type')).trigger('change');
$('#vapt-lock-value').val(btn.data('lock-value'));
$('#vapt-single-instance').prop('checked', btn.data('single-instance') === '1');
```

### Step 6: Domain/IP Lock Enforcement (`vapt-security.php`)
In `enforce_domain_lock()`, modify to handle all lock types:
```php
private function enforce_domain_lock($force = false) {
    $payload = $this->load_locked_config();
    if (!$payload) return true; // No config = no lock
    
    // Backward compatibility
    $lock_type = $payload['lock_type'] ?? 'domain';
    $lock_value = $payload['lock_value'] ?? $payload['domain_pattern'] ?? '';
    
    // Single-instance check (run first)
    if (!empty($payload['single_instance'])) {
        $server_ip = $this->get_server_ip();
        $binding_key = 'vapt_instance_' . $payload['build_id'];
        $current_binding = get_transient($binding_key);
        
        if ($current_binding === false) {
            // First activation - store binding for 24 hours
            set_transient($binding_key, $server_ip, DAY_IN_SECONDS);
        } elseif ($current_binding !== $server_ip) {
            $this->log_security_event('single_instance_violation', [
                'build_id' => $payload['build_id'],
                'expected_ip' => $current_binding,
                'actual_ip' => $server_ip
            ]);
            return false;
        }
    }
    
    if ($lock_type === 'ip') {
        $server_ip = $this->get_server_ip();
        if ($server_ip !== $lock_value) {
            $this->log_security_event('ip_lock_violation', [
                'expected' => $lock_value,
                'actual' => $server_ip
            ]);
            return false;
        }
        return true;
    }
    
    // Domain lock (existing logic)
    $domain_pattern = $payload['domain_pattern'] ?? $lock_value;
    $domain_type = $payload['domain_type'] ?? 'standard';
    // ... existing domain validation logic ...
}
```

Add helper method:
```php
private function get_server_ip() {
    // Handle proxies/CDNs
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['HTTP_X_REAL_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? $_SERVER['SERVER_ADDR'] ?? '';
    
    // X-Forwarded-For can have multiple IPs, take the first (client)
    if (strpos($ip, ',') !== false) {
        $ip = trim(explode(',', $ip)[0]);
    }
    
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
}
```

### Step 7: File Naming Convention Update
To avoid collisions with special characters in IP addresses:
```php
private function get_config_filename($lock_value, $lock_type) {
    if ($lock_type === 'ip') {
        // Sanitize IP: replace dots with dashes
        $safe = str_replace('.', '-', $lock_value);
        return "vapt-ip-{$safe}-locked-config.php";
    }
    // Existing domain sanitization
    $safe = preg_replace('/[^a-zA-Z0-9\-.]/', '-', $lock_value);
    return "vapt-{$safe}-locked-config.php";
}
```

### Step 8: Database Migration (Backward Compatibility)
Since `vapt_build_history` is stored as a WordPress option (not DB table), no schema migration is needed. All new fields are stored within the existing JSON structure.

## Testing Checklist

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TC-01 | Domain Lock - Standard | Generate build with domain, verify activation on matching domain |
| TC-02 | Domain Lock - Wildcard | Generate with `*.example.com`, verify matches `sub.example.com` |
| TC-03 | Domain Lock - Universal | Generate with `*`, verify works on any domain |
| TC-04 | IP Lock - Valid | Generate with `192.168.1.1`, activate on server with that IP |
| TC-05 | IP Lock - Mismatch | Attempt to activate on different IP, expect rejection |
| TC-06 | IP Validation | Attempt to generate with invalid IP `abc.def`, expect error |
| TC-07 | Single Instance - First | Activate build first time, IP stored in transient |
| TC-08 | Single Instance - Duplicate | Attempt to activate same build on different server, expect rejection |
| TC-09 | Single Instance - Expiry | After 24h transient expires, new server can activate |
| TC-10 | Edit Build | Load a domain-locked build for editing, verify fields populate correctly |
| TC-11 | Edit IP Build | Load an IP-locked build for editing, verify lock type/value/cb populate |
| TC-12 | Legacy Compatibility | Existing builds without lock_type still activate normally |
| TC-13 | ZIP Filename | Generate ZIP for IP-locked build, verify filename is correct |
| TC-14 | History Table | Verify new columns show correct icons for lock type |

## Backward Compatibility Matrix

| Field | Old Builds | New Builds |
|-------|-----------|------------|
| `lock_type` | Not present → default to "domain" | Always present |
| `lock_value` | Uses `domain` field | Always present |
| `single_instance` | Not present → false | Optional |
| `domain_type` | Present | Renamed to `lock_type` context |

## Security Considerations

1. **IP Spoofing**: Server IP detection handles X-Forwarded-For, but clients behind proxies may have different visible IPs. Document this limitation.
2. **Transient Expiry**: 24-hour window allows legitimate server restarts while preventing copy-paste deployment.
3. **Audit Logging**: All lock violations are logged via `log_security_event()`.
4. **Input Sanitization**: All inputs sanitized via `sanitize_text_field()`.

## File Changes Summary

| File | Changes |
|------|---------|
| `templates/admin-domain-control.php` | Form fields, JS handlers, table columns, edit functionality |
| `vapt-security.php` | Handler updates, enforcement logic, helper methods |
| `includes/class-license.php` | IP validation helper |