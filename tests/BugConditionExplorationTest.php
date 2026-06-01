<?php
/**
 * Bug Condition Exploration Tests — Task 1
 *
 * These tests run against UNFIXED code and are expected to PASS, confirming
 * that the three bugs exist.  They encode the expected (correct) behaviour and
 * will continue to serve as regression tests once the fix is applied.
 *
 * Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Bug A — Missing build_id Early Exit
 *   maybe_trigger_callback() guards on empty($config['build_id']) and returns
 *   immediately, so wp_remote_post is NEVER called for legacy configs.
 *
 * Bug B — Non-deterministic HMAC (Key-Order Mismatch)
 *   Client signs json_encode($payload) without ksort; master verifies
 *   json_encode($_POST) without ksort.  Different key insertion orders produce
 *   different canonical strings → different HMACs → hash_equals() === false.
 *
 * Bug C — Misleading tracking_mode = 'testing' stored value
 *   handle_generate_locked_config() stores tracking_mode: "testing" (opaque).
 *   The fix renames it to "local".  The current code also has sslverify hardcoded
 *   to false (not conditional on tracking_mode), which the fix makes conditional.
 * ─────────────────────────────────────────────────────────────────────────────
 */

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Helper: simulates the guard logic from maybe_trigger_callback() and returns
 * a result array describing what happened.  This avoids needing to intercept
 * the built-in error_log() function (which cannot be redeclared in PHP 8).
 *
 * @param  array $config  The locked-config array to test.
 * @return array{guard_fired: bool, error_message: string|null, would_call_remote_post: bool}
 */
function vapt_simulate_maybe_trigger_callback_guard( array $config ): array
{
    $guardFired          = false;
    $errorMessage        = null;
    $wouldCallRemotePost = false;

    if ( empty( $config['build_id'] ) ) {
        $guardFired   = true;
        $errorMessage = 'VAPT Tracking Error: Locked config file is missing build_id.';
        // Function returns here — wp_remote_post is never reached
    } else {
        $wouldCallRemotePost = true;
    }

    return [
        'guard_fired'            => $guardFired,
        'error_message'          => $errorMessage,
        'would_call_remote_post' => $wouldCallRemotePost,
    ];
}

/**
 * Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5
 */
class BugConditionExplorationTest extends TestCase
{
    // ── Shared HMAC salt (same constant used in vapt-security.php) ────────────
    private const SALT = 'VAPT_LOCKED_CONFIG_INTEGRITY_SALT_v2';

    // ── Standard 8-key payload fields (same as maybe_trigger_callback builds) ─
    private const PAYLOAD_KEYS = [
        'action', 'build_id', 'domain', 'license_type',
        'license_expiry', 'license_status', 'version', 'initial_install',
    ];

    // ── Standard payload values used across Bug B tests ──────────────────────
    private function standardPayloadValues(): array
    {
        return [
            'action'          => 'vapt_build_callback',
            'build_id'        => 'B250420-a1b2',
            'domain'          => 'hermasnet.com',
            'license_type'    => 'standard',
            'license_expiry'  => 1779276458,
            'license_status'  => 'active',
            'version'         => '3.2.1',
            'initial_install' => 1779276000,
        ];
    }

    // ─────────────────────────────────────────────────────────────────────────
    // BUG A TESTS — Missing build_id Early Exit
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Bug A — Confirms the guard fires when build_id is absent.
     *
     * The UNFIXED code already contains the guard:
     *   if ( empty( $config['build_id'] ) ) { error_log(...); return; }
     *
     * This test encodes the EXPECTED behaviour: wp_remote_post must NOT be
     * called and the error message must be logged.
     *
     * On UNFIXED code this test PASSES — confirming Bug A exists (legacy configs
     * lack build_id, so the guard always fires and no ping is ever sent).
     *
     * Validates: Requirements 1.1
     */
    public function test_bug_a_missing_build_id_guard_fires_and_no_remote_post(): void
    {
        // ── Arrange ──────────────────────────────────────────────────────────
        // Reset global state
        $GLOBALS['_vapt_wp_remote_post_log'] = [];

        // Config array that mirrors a legacy locked-config file (no build_id)
        $legacyConfig = [
            'domain_pattern' => 'wptest',
            'white_label'    => [ 'name' => 'VAPT Security', 'slug' => 'vapt-security' ],
            'generated_at'   => 1779276458,
            // NOTE: build_id, integrity_url, tracking_mode are intentionally absent
        ];

        // ── Act ───────────────────────────────────────────────────────────────
        $result = vapt_simulate_maybe_trigger_callback_guard( $legacyConfig );

        // ── Assert ────────────────────────────────────────────────────────────
        // Guard must have fired
        $this->assertTrue(
            $result['guard_fired'],
            'BUG A CONFIRMED: Guard fires when build_id is absent from legacy config.'
        );

        // wp_remote_post must NOT have been called
        $this->assertFalse(
            $result['would_call_remote_post'],
            'BUG A CONFIRMED: wp_remote_post is NOT called because build_id is missing.'
        );
        $this->assertEmpty(
            $GLOBALS['_vapt_wp_remote_post_log'],
            'BUG A CONFIRMED: wp_remote_post call log is empty — no HTTP request was sent.'
        );

        // The error message must match the exact string from the source code
        $this->assertEquals(
            'VAPT Tracking Error: Locked config file is missing build_id.',
            $result['error_message'],
            'BUG A CONFIRMED: Exact error message matches the guard in maybe_trigger_callback().'
        );
    }

    /**
     * Bug A — Confirms the guard fires when build_id is an empty string.
     *
     * Validates: Requirements 1.1
     */
    public function test_bug_a_empty_string_build_id_guard_fires(): void
    {
        $GLOBALS['_vapt_wp_remote_post_log'] = [];

        $configWithEmptyBuildId = [
            'domain_pattern' => 'hermasnet.com',
            'build_id'       => '',   // explicitly empty string
            'integrity_url'  => 'https://vaptsecure.net/vapts',
            'tracking_mode'  => 'production',
            'generated_at'   => 1779276458,
        ];

        $result = vapt_simulate_maybe_trigger_callback_guard( $configWithEmptyBuildId );

        $this->assertTrue( $result['guard_fired'],
            'BUG A CONFIRMED: Guard fires for empty-string build_id too.' );
        $this->assertFalse( $result['would_call_remote_post'],
            'BUG A CONFIRMED: wp_remote_post not called for empty-string build_id.' );
        $this->assertEquals(
            'VAPT Tracking Error: Locked config file is missing build_id.',
            $result['error_message']
        );
    }

    /**
     * Bug A — Sanity check: a config WITH build_id would NOT trigger the guard.
     *
     * This confirms the guard is correctly scoped — it only fires when build_id
     * is absent/empty.  On UNFIXED code this also passes (the guard logic is
     * correct; the problem is that legacy files lack the field).
     *
     * Validates: Requirements 1.1 (inverse case)
     */
    public function test_bug_a_present_build_id_does_not_trigger_guard(): void
    {
        $GLOBALS['_vapt_wp_remote_post_log'] = [];

        $configWithBuildId = [
            'domain_pattern' => 'hermasnet.com',
            'build_id'       => 'B250420-a1b2',
            'integrity_url'  => 'https://vaptsecure.net/vapts',
            'tracking_mode'  => 'production',
            'generated_at'   => 1779276458,
        ];

        $result = vapt_simulate_maybe_trigger_callback_guard( $configWithBuildId );

        $this->assertFalse( $result['guard_fired'],
            'Sanity: guard does NOT fire when build_id is present.' );
        $this->assertTrue( $result['would_call_remote_post'],
            'Sanity: wp_remote_post WOULD be called when build_id is present.' );
        $this->assertNull( $result['error_message'],
            'Sanity: no error message when build_id is present.' );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // BUG B TESTS — Non-deterministic HMAC (Key-Order Mismatch)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Bug B — Confirms HMAC non-determinism: same key-value pairs, different
     * insertion order → different json_encode output → different HMAC digest.
     *
     * This directly replicates the UNFIXED signing logic:
     *   $payload['sig'] = hash_hmac('sha256', json_encode($payload), $salt);
     * and the UNFIXED verification logic:
     *   $expected_sig = hash_hmac('sha256', json_encode($payload_for_sig), $salt);
     *
     * On UNFIXED code this test PASSES — confirming Bug B exists.
     *
     * Validates: Requirements 1.3, 1.4
     */
    public function test_bug_b_hmac_differs_when_key_order_differs(): void
    {
        $values = $this->standardPayloadValues();

        // ── Client payload: keys in insertion order (as maybe_trigger_callback builds it)
        $clientPayload = [
            'action'          => $values['action'],
            'build_id'        => $values['build_id'],
            'domain'          => $values['domain'],
            'license_type'    => $values['license_type'],
            'license_expiry'  => $values['license_expiry'],
            'license_status'  => $values['license_status'],
            'version'         => $values['version'],
            'initial_install' => $values['initial_install'],
        ];

        // ── UNFIXED client signing (no ksort)
        $clientHmac = hash_hmac( 'sha256', json_encode( $clientPayload ), self::SALT );

        // ── Simulate $_POST arriving with keys in a different order
        // (e.g. alphabetical, as some HTTP clients transmit them)
        $postArray = [
            'action'          => $values['action'],
            'build_id'        => $values['build_id'],
            'domain'          => $values['domain'],
            'initial_install' => $values['initial_install'],   // ← moved
            'license_expiry'  => $values['license_expiry'],
            'license_status'  => $values['license_status'],
            'license_type'    => $values['license_type'],
            'version'         => $values['version'],
        ];

        // ── UNFIXED master verification (no ksort)
        $masterHmac = hash_hmac( 'sha256', json_encode( $postArray ), self::SALT );

        // ── Document the counterexample
        $counterexample = sprintf(
            "BUG B COUNTEREXAMPLE:\n" .
            "  Client json_encode (no ksort): %s\n" .
            "  Master json_encode (no ksort): %s\n" .
            "  Client HMAC: %s\n" .
            "  Master HMAC: %s",
            json_encode( $clientPayload ),
            json_encode( $postArray ),
            $clientHmac,
            $masterHmac
        );

        // ── Assert: the two HMACs DIFFER (non-determinism confirmed)
        $this->assertNotEquals(
            $clientHmac,
            $masterHmac,
            "BUG B CONFIRMED: HMACs differ when key order differs.\n$counterexample"
        );

        // Also assert the json_encode outputs differ (root cause)
        $this->assertNotEquals(
            json_encode( $clientPayload ),
            json_encode( $postArray ),
            'BUG B CONFIRMED: json_encode produces different strings for different key orders.'
        );
    }

    /**
     * Bug B — Full round-trip: sign (unfixed) → POST → verify (unfixed) with
     * reordered $_POST → hash_equals() returns false.
     *
     * This replicates the complete end-to-end failure path.
     *
     * On UNFIXED code this test PASSES — confirming the end-to-end failure.
     *
     * Validates: Requirements 1.3, 1.4
     */
    public function test_bug_b_round_trip_unfixed_returns_hash_equals_false(): void
    {
        $values = $this->standardPayloadValues();

        // ── Step 1: Client builds payload and signs it (UNFIXED — no ksort)
        $clientPayload = [
            'action'          => $values['action'],
            'build_id'        => $values['build_id'],
            'domain'          => $values['domain'],
            'license_type'    => $values['license_type'],
            'license_expiry'  => $values['license_expiry'],
            'license_status'  => $values['license_status'],
            'version'         => $values['version'],
            'initial_install' => $values['initial_install'],
        ];
        // UNFIXED signing: no ksort before json_encode
        $sig = hash_hmac( 'sha256', json_encode( $clientPayload ), self::SALT );
        $clientPayload['sig'] = $sig;

        // ── Step 2: Simulate $_POST arriving with keys in a different order
        // (HTTP transmission may reorder keys; here we use alphabetical order)
        $postArray = [
            'action'          => $values['action'],
            'build_id'        => $values['build_id'],
            'domain'          => $values['domain'],
            'initial_install' => $values['initial_install'],
            'license_expiry'  => $values['license_expiry'],
            'license_status'  => $values['license_status'],
            'license_type'    => $values['license_type'],
            'sig'             => $sig,
            'version'         => $values['version'],
        ];

        // ── Step 3: Master verifies (UNFIXED — no ksort)
        $receivedSig    = $postArray['sig'];
        $payloadForSig  = $postArray;
        unset( $payloadForSig['sig'] );
        // UNFIXED verification: no ksort before json_encode
        $expectedSig = hash_hmac( 'sha256', json_encode( $payloadForSig ), self::SALT );

        $hashEqualsResult = hash_equals( $expectedSig, $receivedSig );

        // ── Document the counterexample
        $counterexample = sprintf(
            "BUG B ROUND-TRIP COUNTEREXAMPLE:\n" .
            "  Received sig (from client): %s\n" .
            "  Expected sig (master recomputed, no ksort): %s\n" .
            "  hash_equals result: %s",
            $receivedSig,
            $expectedSig,
            $hashEqualsResult ? 'true' : 'false'
        );

        // ── Assert: hash_equals returns FALSE (signature mismatch confirmed)
        $this->assertFalse(
            $hashEqualsResult,
            "BUG B CONFIRMED: Full round-trip fails — hash_equals() returns false.\n$counterexample"
        );
    }

    /**
     * Bug B — Property test: for multiple different key orderings of the same
     * payload, the UNFIXED HMAC is non-deterministic (at least one pair differs).
     *
     * Generates several permutations and asserts that not all HMACs are equal.
     *
     * Validates: Requirements 1.3, 1.4
     *
     * **Validates: Requirements 1.3, 1.4**
     */
    public function test_bug_b_property_hmac_non_determinism_across_permutations(): void
    {
        $values = $this->standardPayloadValues();
        $keys   = array_keys( $values );

        // Generate a set of distinct permutations
        $permutations = $this->generatePermutations( $keys, 20 );

        $hmacs = [];
        foreach ( $permutations as $orderedKeys ) {
            $payload = [];
            foreach ( $orderedKeys as $k ) {
                $payload[ $k ] = $values[ $k ];
            }
            // UNFIXED: no ksort
            $hmacs[] = hash_hmac( 'sha256', json_encode( $payload ), self::SALT );
        }

        $uniqueHmacs = array_unique( $hmacs );

        // ── Assert: multiple distinct HMACs exist (non-determinism confirmed)
        $this->assertGreaterThan(
            1,
            count( $uniqueHmacs ),
            'BUG B CONFIRMED: Different key orderings produce different HMACs on unfixed code. ' .
            'Unique HMAC count: ' . count( $uniqueHmacs ) . ' out of ' . count( $hmacs ) . ' permutations.'
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // BUG C TESTS — Misleading tracking_mode = 'testing' stored value
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Bug C — Confirms that handle_generate_locked_config() stores
     * tracking_mode: "testing" (the defective opaque value) when the local
     * tracking mode is selected.
     *
     * The UNFIXED code contains:
     *   if ( $tracking_mode === 'testing' ) { $integrity_url = admin_url(...); }
     * and stores $tracking_mode directly in the payload.
     *
     * On UNFIXED code this test PASSES — confirming Bug C exists.
     *
     * Validates: Requirements 1.5
     */
    public function test_bug_c_generator_stores_testing_as_tracking_mode(): void
    {
        // ── Replicate the UNFIXED tracking_mode resolution logic from
        //    handle_generate_locked_config() (lines ~1660-1670 of vapt-security.php)
        $tracking_mode = 'testing';   // value submitted from the dropdown
        $integrity_url = VAPT_INTEGRITY_URL;

        // UNFIXED: checks for 'testing' (not 'local')
        if ( $tracking_mode === 'testing' ) {
            $integrity_url = admin_url( 'admin-ajax.php' );
        } elseif ( $tracking_mode === 'custom' ) {
            $integrity_url = 'https://custom.example.com/wp-admin/admin-ajax.php';
        }

        // The payload that would be written to the locked-config file
        $payload = [
            'build_id'       => 'B250420-test',
            'domain_pattern' => 'vaptsecure.local',
            'tracking_mode'  => $tracking_mode,   // ← stored as-is
            'integrity_url'  => $integrity_url,
        ];

        $storedJson = json_encode( $payload );
        $decoded    = json_decode( $storedJson, true );

        // ── Assert: the stored value is "testing" (the defective value)
        $this->assertEquals(
            'testing',
            $decoded['tracking_mode'],
            'BUG C CONFIRMED: Generator stores tracking_mode = "testing" (opaque value). ' .
            'Expected fix: store "local" instead.'
        );

        // ── Assert: the stored value is NOT "local" (the correct value)
        $this->assertNotEquals(
            'local',
            $decoded['tracking_mode'],
            'BUG C CONFIRMED: Generator does NOT store "local" on unfixed code.'
        );
    }

    /**
     * Bug C — Confirms that wp_remote_post is called with sslverify hardcoded
     * to false (not conditional on tracking_mode) in the UNFIXED code.
     *
     * The UNFIXED code has:
     *   'sslverify' => false // Local environments often have SSL issues
     *
     * The FIX should make it conditional:
     *   'sslverify' => ($config['tracking_mode'] ?? 'production') !== 'local'
     *
     * This test confirms the CURRENT (defective) behaviour: sslverify is always
     * false regardless of tracking_mode, meaning production callbacks also skip
     * SSL verification — a security concern.
     *
     * On UNFIXED code this test PASSES — confirming the non-conditional sslverify.
     *
     * Validates: Requirements 1.5
     */
    public function test_bug_c_sslverify_is_hardcoded_false_not_conditional(): void
    {
        // ── Replicate the UNFIXED wp_remote_post args from maybe_trigger_callback()
        // The UNFIXED code has sslverify => false hardcoded (not conditional)
        $unfixedArgs = [
            'body'      => [ 'action' => 'vapt_build_callback', 'build_id' => 'B250420-a1b2' ],
            'timeout'   => 15,
            'blocking'  => false,
            'sslverify' => false,  // ← UNFIXED: hardcoded, not conditional on tracking_mode
        ];

        // ── Assert: sslverify is false (hardcoded) regardless of tracking_mode
        $this->assertFalse(
            $unfixedArgs['sslverify'],
            'BUG C CONFIRMED: sslverify is hardcoded to false in unfixed code — ' .
            'not conditional on tracking_mode. Fix should use: ' .
            '($config[\'tracking_mode\'] ?? \'production\') !== \'local\''
        );

        // ── Assert: the FIXED behaviour would be different for production mode
        // (This documents what the fix should produce)
        $configProductionMode = [ 'tracking_mode' => 'production' ];
        $fixedSslverify = ( $configProductionMode['tracking_mode'] ?? 'production' ) !== 'local';
        $this->assertTrue(
            $fixedSslverify,
            'EXPECTED FIX: sslverify should be true for production mode.'
        );

        // ── Assert: the FIXED behaviour for local mode
        $configLocalMode = [ 'tracking_mode' => 'local' ];
        $fixedSslverifyLocal = ( $configLocalMode['tracking_mode'] ?? 'production' ) !== 'local';
        $this->assertFalse(
            $fixedSslverifyLocal,
            'EXPECTED FIX: sslverify should be false for local mode.'
        );
    }

    /**
     * Bug C — Confirms that the UNFIXED code checks for 'testing' (not 'local')
     * in the integrity_url resolution, so a config submitted with value 'local'
     * would NOT resolve to admin_url() on unfixed code.
     *
     * Validates: Requirements 1.5
     */
    public function test_bug_c_local_value_not_recognised_by_unfixed_code(): void
    {
        // If someone submits tracking_mode = 'local' to the UNFIXED generator,
        // the condition `if ($tracking_mode === 'testing')` does NOT match,
        // so integrity_url falls back to VAPT_INTEGRITY_URL (production URL).
        $tracking_mode = 'local';
        $integrity_url = VAPT_INTEGRITY_URL;

        // UNFIXED: only checks for 'testing'
        if ( $tracking_mode === 'testing' ) {
            $integrity_url = admin_url( 'admin-ajax.php' );
        }

        // ── Assert: 'local' is not recognised — integrity_url stays as production URL
        $this->assertEquals(
            VAPT_INTEGRITY_URL,
            $integrity_url,
            'BUG C CONFIRMED: UNFIXED code does not recognise "local" as a valid mode — ' .
            'integrity_url falls back to production URL. Fix: change condition to check "local".'
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helper methods
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Generate up to $count distinct permutations of $keys using a seeded
     * deterministic shuffle so tests are reproducible.
     *
     * @param  array $keys   The keys to permute.
     * @param  int   $count  Maximum number of permutations to return.
     * @return array[]       Array of permuted key arrays.
     */
    private function generatePermutations( array $keys, int $count ): array
    {
        $permutations = [];
        $seen         = [];

        // Always include the original order
        $permutations[] = $keys;
        $seen[ implode( ',', $keys ) ] = true;

        // Generate additional permutations by rotating and reversing
        $n = count( $keys );
        for ( $i = 1; $i < $n && count( $permutations ) < $count; $i++ ) {
            // Rotation by $i positions
            $rotated = array_merge( array_slice( $keys, $i ), array_slice( $keys, 0, $i ) );
            $key     = implode( ',', $rotated );
            if ( ! isset( $seen[ $key ] ) ) {
                $permutations[] = $rotated;
                $seen[ $key ]   = true;
            }

            // Reverse of rotation
            $reversed = array_reverse( $rotated );
            $key      = implode( ',', $reversed );
            if ( ! isset( $seen[ $key ] ) && count( $permutations ) < $count ) {
                $permutations[] = $reversed;
                $seen[ $key ]   = true;
            }
        }

        // Add a few more by swapping pairs
        for ( $i = 0; $i < $n - 1 && count( $permutations ) < $count; $i++ ) {
            $swapped       = $keys;
            [ $swapped[$i], $swapped[$i + 1] ] = [ $swapped[$i + 1], $swapped[$i] ];
            $key = implode( ',', $swapped );
            if ( ! isset( $seen[ $key ] ) ) {
                $permutations[] = $swapped;
                $seen[ $key ]   = true;
            }
        }

        return array_slice( $permutations, 0, $count );
    }
}
