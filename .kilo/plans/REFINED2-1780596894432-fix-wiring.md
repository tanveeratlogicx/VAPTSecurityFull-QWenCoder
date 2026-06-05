# Plan: Complete IP-Address Binding & Single-Instance Wiring (REFINED2)

**Status**: Gap Analysis & Implementation Roadmap  
**Base Plan**: REFINED-1780596894432-neon-mountain.md  
**Date**: 2026-06-05

---

## Executive Summary

The first refinement (REFINED-1780596894432-neon-mountain.md) laid the foundation but left critical wiring gaps:

| Component | Status | Gap |
|-----------|--------|-----|
| UI form fields | ✅ Present | `#vapt-lock-value` and `#vapt-single-instance` exist |
| Backend payload support | ✅ Present | Handlers accept `lock_type`, `lock_value`, `single_instance` |
| Enforcement logic | ✅ Present | `enforce_domain_lock()` checks IP & single-instance |
| AJAX form submission | ❌ **BROKEN** | Form still posts `domain` & `domain_type`; never sends `lock_type`, `lock_value`, `single_instance` |
| Build history storage | ❌ **BROKEN** | `add_build_to_history()` never records new fields |
| Edit/reuse build | ❌ **BROKEN** | Edit handler does not load new fields into form |
| IP validation | ⚠️ **INCOMPLETE** | No validation before config generation |
| Server IP detection | ⚠️ **INCOMPLETE** | No proxy/CDN support (`X-Forwarded-For` ignored) |

**Result**: Feature is 40% implemented. Form generates builds but new lock types are silently dropped.

---

## Root Causes

### 1. Form submission still references old `#vapt-lock-domain` selector
- File: `templates/admin-domain-control.php` lines ~1669, 1702
- The form has `#vapt-lock-value` but AJAX posts `domain: $('#vapt-lock-domain').val()`
- `#vapt-lock-domain` does not exist → undefined value is sent
- **Result**: Lock type and value are never transmitted

### 2. History entry does not capture new fields
- File: `vapt-security.php` line ~3923 (`add_build_to_history()`)
- Entry includes `domain`, `domain_type` but not `lock_type`, `lock_value`, `single_instance`
- **Result**: Builds are created but metadata is lost; edit/reuse cannot restore settings

### 3. Edit button data attributes are incomplete
- File: `templates/admin-domain-control.php` line ~1095
- Only includes `data-domain-type`; missing `data-lock-type`, `data-lock-value`, `data-single-instance`
- **Result**: Clicking edit does not populate new fields

### 4. Edit handler does not populate new fields
- File: `templates/admin-domain-control.php` line ~1779 (edit handler)
- Sets `$('#vapt-lock-type').val(btn.data('domain-type'))` (wrong field)
- Never loads `lock_value` into `#vapt-lock-value`
- Never loads `single_instance` into checkbox
- **Result**: Edit form is incomplete; user sees blank new fields

### 5. No IP validation before writing config
- File: `vapt-security.php` lines ~3485, 3631
- Accepts `lock_type === 'ip'` but does not validate `lock_value` against `is_valid_ipv4()`
- **Result**: Invalid IPs could be written to config

### 6. Server IP detection is basic
- File: `vapt-security.php` line ~475
- Uses `$_SERVER['REMOTE_ADDR']` or `$_SERVER['SERVER_ADDR']`
- Ignores proxy headers (`X-Forwarded-For`, `X-Real-IP`)
- **Result**: IP lock fails behind load balancers / CDNs

---

## Detailed Fixes

### Fix 1: Update AJAX form submission to use correct fields

**File**: `templates/admin-domain-control.php`  
**Lines**: ~1669-1671 (generate-locked-config), ~1702-1704 (doGenerateClientZip)

**Current**:
```javascript
$.post(ajaxurl, {
    action: 'vapt_generate_locked_config',
    edit_id: $('#vapt-build-id-tracking').val(),
    domain: $('#vapt-lock-domain').val(),  // ❌ WRONG: element doesn't exist
    domain_type: $('#vapt-lock-type').val(),  // ❌ This reads lock type, not domain type
    // ... other fields ...
```

**Fixed**:
```javascript
$.post(ajaxurl, {
    action: 'vapt_generate_locked_config',
    edit_id: $('#vapt-build-id-tracking').val(),
    lock_type: $('#vapt-lock-type').val(),  // ✅ Correct: get the lock type (domain/ip)
    lock_value: $('#vapt-lock-value').val(),  // ✅ Correct: get the lock value
    single_instance: $('#vapt-single-instance').is(':checked') ? 1 : 0,  // ✅ New field
    domain_type: $('#vapt-domain-type').val(),  // ✅ Correct: get domain-specific type (standard/wildcard/universal)
    // ... other fields ...
```

**Apply to both**:
- `$('#vapt-generate-locked-config').click(...)` block
- `doGenerateClientZip(extraParams)` function

---

### Fix 2: Add IP validation in handlers before writing

**File**: `vapt-security.php`  
**Lines**: ~3485-3490 (in `handle_generate_locked_config()`), ~3631-3636 (in `handle_generate_client_zip()`)

**Current**:
```php
$lock_type     = sanitize_text_field( $_POST['lock_type'] ?? 'domain' );
$lock_value    = sanitize_text_field( $_POST['lock_value'] ?? $domain_pattern );
$single_instance = ! empty( $_POST['single_instance'] );
// ... no validation ...
```

**Fixed** (insert after line 3487, then repeat for line 3633):
```php
$lock_type     = sanitize_text_field( $_POST['lock_type'] ?? 'domain' );
$lock_value    = sanitize_text_field( $_POST['lock_value'] ?? $domain_pattern );
$single_instance = ! empty( $_POST['single_instance'] );

// Validate IP if lock_type is 'ip'
if ( $lock_type === 'ip' ) {
    if ( ! VAPT_License::is_valid_ipv4( $lock_value ) ) {
        wp_send_json_error( [ 'message' => __( 'Invalid IPv4 address format.', 'vapt-security' ) ] );
        return;
    }
}

// For domain type, ensure lock_value is set
if ( $lock_type === 'domain' && empty( $lock_value ) ) {
    $lock_value = $domain_pattern;
}
```

---

### Fix 3: Store new fields in build history

**File**: `vapt-security.php`  
**Function**: `add_build_to_history()` at line ~3923

**Current entry structure**:
```php
$entry = [
    'id'          => $build_id,
    'type'        => $type,
    'status'      => 'active',
    'domain'      => $payload['domain_pattern'],
    'domain_type' => $payload['domain_type'] ?? 'standard',
    // ... other fields ...
    'time'        => time()
];
```

**Fixed** (add these three lines after `'domain_type'` assignment):
```php
$entry = [
    'id'          => $build_id,
    'type'        => $type,
    'status'      => 'active',
    'domain'      => $payload['domain_pattern'],
    'domain_type' => $payload['domain_type'] ?? 'standard',
    'lock_type'   => $payload['lock_type'] ?? 'domain',  // ✅ NEW
    'lock_value'  => $payload['lock_value'] ?? $payload['domain_pattern'],  // ✅ NEW
    'single_instance' => ! empty( $payload['single_instance'] ),  // ✅ NEW
    // ... other fields ...
    'time'        => time()
];
```

---

### Fix 4: Add data attributes to history table edit button

**File**: `templates/admin-domain-control.php`  
**Lines**: ~1095-1110 (inside `.vapt-edit-build` button declaration)

**Current**:
```php
<button type="button" class="button button-small vapt-edit-build<?php echo $disabled_class; ?>" 
     data-id="<?php echo esc_attr($build['id']); ?>" 
     data-domain="<?php echo esc_attr($build['domain']); ?>"
     data-domain-type="<?php echo esc_attr($build['domain_type'] ?? 'standard'); ?>"
     data-license-type="<?php echo esc_attr($build['license']); ?>"
     // ... other attributes ...
     title="<?php esc_attr_e( 'Edit/Reuse settings', 'vapt-security' ); ?>"
```

**Fixed** (add three new attributes after `data-domain`):
```php
<button type="button" class="button button-small vapt-edit-build<?php echo $disabled_class; ?>" 
     data-id="<?php echo esc_attr($build['id']); ?>" 
     data-domain="<?php echo esc_attr($build['domain']); ?>"
     data-lock-type="<?php echo esc_attr($build['lock_type'] ?? 'domain'); ?>"  <!-- ✅ NEW -->
     data-lock-value="<?php echo esc_attr($build['lock_value'] ?? $build['domain']); ?>"  <!-- ✅ NEW -->
     data-single-instance="<?php echo esc_attr( ! empty($build['single_instance']) ? '1' : '0' ); ?>"  <!-- ✅ NEW -->
     data-domain-type="<?php echo esc_attr($build['domain_type'] ?? 'standard'); ?>"
     data-license-type="<?php echo esc_attr($build['license']); ?>"
     // ... other attributes ...
     title="<?php esc_attr_e( 'Edit/Reuse settings', 'vapt-security' ); ?>"
```

---

### Fix 5: Update edit handler to populate new fields

**File**: `templates/admin-domain-control.php`  
**Lines**: ~1779-1805 (edit handler section)

**Current**:
```javascript
$(document).on('click', '.vapt-edit-build', function(){
    var btn = $(this);
    $('#vapt-build-id-tracking').val(btn.data('id'));
    $('#vapt-lock-domain').val(btn.data('domain')).trigger('change');  // ❌ WRONG field
    $('#vapt-lock-type').val(btn.data('domain-type')).trigger('change');  // ❌ Treats domain-type as lock-type
    // ... other fields ...
```

**Fixed**:
```javascript
$(document).on('click', '.vapt-edit-build', function(){
    var btn = $(this);
    $('#vapt-build-id-tracking').val(btn.data('id'));
    
    // ✅ NEW: Set lock type and value
    $('#vapt-lock-type').val(btn.data('lock-type')).trigger('change');
    $('#vapt-lock-value').val(btn.data('lock-value'));
    $('#vapt-single-instance').prop('checked', btn.data('single-instance') === '1' || btn.data('single-instance') === 1);
    
    // ✅ CORRECTED: Set domain type (only relevant when lock_type === 'domain')
    $('#vapt-domain-type').val(btn.data('domain-type'));
    
    // ... other fields ...
```

---

### Fix 6: Improve server IP detection with proxy support

**File**: `vapt-security.php`  
**Function**: `enforce_domain_lock()` at line ~388

**Current single-instance check** (line ~475):
```php
$stored_ip = get_option( 'vapt_single_instance_ip_' . md5( $lock_value ) );
$current_ip = $_SERVER['REMOTE_ADDR'] ?? $_SERVER['SERVER_ADDR'] ?? '';
```

**Fixed** (extract to helper method first, then use):
```php
// Add new helper method
private function get_server_ip() {
    // Check for proxy headers first (CDN/load balancer scenarios)
    $ip = '';
    
    if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
        // X-Forwarded-For can contain multiple IPs; take the first (client IP)
        $ips = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] );
        $ip = trim( $ips[0] );
    } elseif ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
        $ip = $_SERVER['HTTP_X_REAL_IP'];
    } elseif ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
        $ip = $_SERVER['REMOTE_ADDR'];
    } elseif ( ! empty( $_SERVER['SERVER_ADDR'] ) ) {
        $ip = $_SERVER['SERVER_ADDR'];
    }
    
    // Validate and return
    return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
}

// Then in enforce_domain_lock(), replace direct IP reads:
$current_ip = $this->get_server_ip();
```

---

## Implementation Sequence

### Phase 1: Critical Path (Form submission & validation)
1. **Fix 1**: Update AJAX form submission (lines 1669, 1702)
2. **Fix 2**: Add IP validation in handlers (lines 3490, 3636)
3. **Test**: Generate domain lock, generate IP lock, verify error on bad IP

### Phase 2: Persistence (History & edit)
4. **Fix 3**: Store new fields in history (line 3923)
5. **Fix 4**: Add data attributes (line 1095)
6. **Fix 5**: Update edit handler (line 1779)
7. **Test**: Generate build, edit it, verify all fields populate

### Phase 3: Enhancement (Better IP detection)
8. **Fix 6**: Add `get_server_ip()` helper
9. **Test**: Verify single-instance enforcement with proxy headers

---

## Testing Checklist

| Test | Command | Expected | Status |
|------|---------|----------|--------|
| **Form Submission** | Generate domain lock | Form data includes `lock_type: "domain"`, `lock_value: "*.example.com"` | — |
| **IP Form** | Generate IP lock with valid IP | Form data includes `lock_type: "ip"`, `lock_value: "192.168.1.1"` | — |
| **IP Validation** | Generate IP lock with `"invalid"` | Error: "Invalid IPv4 address format" | — |
| **Single Instance** | Generate with checkbox checked | Payload includes `single_instance: 1` | — |
| **History Storage** | Generate build, check option | History entry has `lock_type`, `lock_value`, `single_instance` | — |
| **Edit Domain** | Generate domain lock, click edit | `#vapt-lock-type` = "domain", `#vapt-lock-value` = correct domain | — |
| **Edit IP** | Generate IP lock, click edit | `#vapt-lock-type` = "ip", `#vapt-lock-value` = correct IP, checkbox restored | — |
| **Enforcement** | Activate IP-locked config on matching IP | Success | — |
| **Enforcement Mismatch** | Activate IP-locked config on wrong IP | Blocked | — |
| **Single Instance** | Activate on server A, then try server B | Blocked on server B | — |
| **Proxy Header** | Activate with `X-Forwarded-For: 10.0.0.1` | Correct IP detected | — |

---

## Files to Modify

1. `templates/admin-domain-control.php`
   - Lines ~1600–1650: lock type display logic (already done)
   - Lines ~1669–1671: generate-locked-config AJAX (needs fix)
   - Lines ~1702–1704: doGenerateClientZip AJAX (needs fix)
   - Lines ~1095–1110: edit button data attributes (needs fix)
   - Lines ~1779–1805: edit handler (needs fix)

2. `vapt-security.php`
   - Lines ~388–520: `enforce_domain_lock()` (needs get_server_ip helper)
   - Lines ~3485–3490: `handle_generate_locked_config()` (needs IP validation)
   - Lines ~3631–3636: `handle_generate_client_zip()` (needs IP validation)
   - Lines ~3923–3965: `add_build_to_history()` (needs new fields)

3. `includes/class-license.php`
   - Already has `is_valid_ipv4()` ✅

---

## Backward Compatibility Notes

- Old builds without `lock_type` will default to `'domain'` (line 469)
- Old history entries without new fields will work; new fields simply won't populate
- No database migrations needed (using WordPress options)
- After Fix 3, only new builds will have complete history entries

---

## Timeline Estimate

- **Phase 1** (Critical): 15 min
- **Phase 2** (Persistence): 20 min
- **Phase 3** (Enhancement): 10 min
- **Testing**: 20 min
- **Total**: ~65 min

---

## Success Criteria

✅ User can generate domain-locked build  
✅ User can generate IP-locked build (with validation)  
✅ User can enable single-instance mode  
✅ All three new fields persist in history  
✅ Edit/reuse restores all settings correctly  
✅ Enforcement works end-to-end for all lock types  
✅ Single-instance blocks duplicate activations  
✅ Backward-compatible with old builds
