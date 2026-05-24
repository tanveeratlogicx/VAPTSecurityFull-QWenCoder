# Technical Build Process

### 1. Build Trigger Mechanism
- **UI Source**: `templates/admin-domain-control.php`
- **AJAX Action**: `vapt_generate_client_zip`
- **PHP Handler**: `VAPT_Security::handle_generate_client_zip()`

### 2. Phase I: Secure Configuration Generation
- **Payload**: Encodes settings, white-label data, and domain patterns into JSON.
- **Signing**: Uses `hash_hmac` (SHA-256) with `VAPT_LOCKED_CONFIG_INTEGRITY_SALT_v2`.
- **Target File**: `vapt-{domain}-locked-config.php` (included in the ZIP root).

### 3. Phase II: Dynamic Header Rewriting
- **Target**: `vapt-security.php` (Main Plugin File).
- **Process**: Isolates the first 1000 bytes (Plugin Header) and uses Regex to replace:
    - `Plugin Name`, `Author`, `Description`, `Version`, `Requires at least`, `Requires PHP`.
- **Safety**: Only replaces within the isolated block to prevent code corruption.

### 4. Phase III: Packaging & Exclusions
The build engine uses a `RecursiveDirectoryIterator` to filter files:
- **SKIP (Permanent Exclusions)**: 
    - Folders: `.git`, `.github`, `node_modules`, `tests`, `bin`, `DevDocs`, `LegacyZips`, `kilo`, `ReqDocs`.
    - Files: `.gitignore`, `composer.json`, `package.json`, `package-lock.json`, `prompt.txt`, `vapt-config.php`, `test-config.php`, `Folder Structure.md`.
    - Technical Docs: `ARCHITECTURE.md`, `DOCUMENTATION.md`, `README.md`, `CHANGELOG.md`, `FEATURES.md`, `VERSION_CONTROL.md`, `SUPERADMIN_GUIDE.md`.
- **INCLUDE & PROCESS (Deliverables)**:
    - **README.txt**: Included under its original name. Content is dynamically updated to:
        - Replace title with White-Label name.
        - Change `Contributors: CosmicTechSol`.
        - **Aggressively strip** all mentions of "Superadmin", "Domain Control", "OTP", and "License Management" from the description and changelog.
    - **USER_GUIDE.md**: Included under its original name (not renamed) but with the white-labeled plugin name in the title.
- **Legacy Zips**: `VAPTSecurity Initial.zip`, `VAPTSecurity v105.zip` are always skipped.

### 5. Phase IV: Delivery
- **Encoding**: ZIP binary is Base64 encoded.
- **Download**: JavaScript triggers an automatic Blob-based download in the browser.
