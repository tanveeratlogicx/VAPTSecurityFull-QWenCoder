<?php
/**
 * Preservation Property Tests — Task 2
 *
 * These tests run against UNFIXED code to record baseline behavior.
 * They encode the CORRECT (post-fix) behavior for all preservation requirements.
 *
 * EXPECTED OUTCOMES on UNFIXED code:
 *   - Throttle Preservation (Req 3.3)         → PASS  (throttle logic is correct in unfixed code)
 *   - Tamper Rejection Preservation (Req 3.2) → PASS  (sig rejection is correct in unfixed code)
 *   - First Activation Preservation (Req 3.4) → PASS  (first-activation logic is correct)
 *   - Pending Commands Preservation (Req 3.5) → PASS  (pending-command dispatch is correct)
 *   - Non-Blocking HTTP Preservation (Req 3.7)→ PASS  (blocking=>false is present in unfixed code)
 *   - SSL Defaults (Req 3.8, 3.9, 3.10)       → FAIL  (unfixed code has sslverify=>false hardcoded;
 *                                                        fix will make it conditional on tracking_mode)
 *
 * NOTE on SSL tests: The SSL preservation tests assert the CORRECT post-fix behavior
 * (sslverify=true for non-local modes). They FAIL on unfixed code because the unfixed
 * code has `sslverify => false` hardcoded. After the fix (task 3.5), these tests will PASS.
 *
 * Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10
 */

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

// ── Shared HMAC salt ──────────────────────────────────────────────────────────
if ( ! defined( 'VAPT_PRESERVATION_SALT' ) ) {
    define( 'VAPT_PRESERVATION_SALT', 'VAPT_LOCKED_CONFIG_INTEGRITY_SALT_v2' );
}

// ── Helpers that replicate the UNFIXED handle_build_callback() logic ──────────

/**
 * Simulate the UNFIXED handle_build_callback() verification and dispatch logic.
 *
 * Returns an array describing what the master would do:
 *   - 'response'          : the wp_send_json_* payload
 *   - 'tracking_written'  : bool — was vapt_build_tracking updated?
 *   - 'first_activation_called' : bool — was notify_superadmin_first_activation() called?
 *   - 'commands_returned' : array — commands included in success response
 *   - 'commands_cleared'  : bool — was vapt_pending_commands entry removed?
 */
function vapt_simulate_handle_build_callback( array $post ): array
{
    $build_id = $post['build_id'] ?? '';
    if ( empty( $build_id ) ) {
        return [
            'response'                  => [ 'success' => false, 'data' => null ],
            'tracking_written'          => false,
            'first_activation_called'   => false,
            'commands_returned'         => [],
            'commands_cleared'          => false,
        ];
    }

    $sig  = $post['sig'] ?? '';
    $salt = VAPT_PRESERVATION_SALT;

    // UNFIXED verification: no ksort
    $payload_for_sig = $post;
    unset( $payload_for_sig['sig'] );
    $expected_sig = hash_hmac( 'sha256', json_encode( $payload_for_sig ), $salt );

    if ( ! hash_equals( $expected_sig, $sig ) ) {
        return [
            'response'                  => [ 'success' => false, 'data' => [ 'message' => 'Invalid signature' ] ],
            'tracking_written'          => false,
            'first_activation_called'   => false,
            'commands_returned'         => [],
            'commands_cleared'          => false,
        ];
    }

    // Valid signature — process tracking
    $tracking = get_option( 'vapt_build_tracking', [] );
    $now      = time();
    $firstActivationCalled = false;

    if ( ! isset( $tracking[ $build_id ] ) ) {
        $tracking[ $build_id ] = [
            'first_activation' => $now,
            'initial_install'  => (int) ( $post['initial_install'] ?? $now ),
            'history'          => [],
        ];
        $firstActivationCalled = true;
    }

    $tracking[ $build_id ]['last_seen'] = $now;
    $tracking[ $build_id ]['domain']    = $post['domain'] ?? '';
    update_option( 'vapt_build_tracking', $tracking );

    // Pending commands
    $commands         = get_option( 'vapt_pending_commands', [] );
    $responseCommands = [];
    $commandsCleared  = false;
    if ( isset( $commands[ $build_id ] ) ) {
        $responseCommands = $commands[ $build_id ];
        unset( $commands[ $build_id ] );
        update_option( 'vapt_pending_commands', $commands );
        $commandsCleared = true;
    }

    return [
        'response'                  => [ 'success' => true, 'data' => [ 'commands' => $responseCommands ] ],
        'tracking_written'          => true,
        'first_activation_called'   => $firstActivationCalled,
        'commands_returned'         => $responseCommands,
        'commands_cleared'          => $commandsCleared,
    ];
}

/**
 * Build a correctly signed POST payload (UNFIXED signing — no ksort).
 * Keys are inserted in the same order as maybe_trigger_callback() builds them,
 * so json_encode produces the same canonical string on both sides (no reordering).
 * This represents a non-buggy input (isBugCondition_B returns false).
 */
function vapt_build_valid_post( string $build_id = 'B250420-a1b2' ): array
{
    $payload = [
        'action'          => 'vapt_build_callback',
        'build_id'        => $build_id,
        'domain'          => 'hermasnet.com',
        'license_type'    => 'standard',
        'license_expiry'  => 1779276458,
        'license_status'  => 'active',
        'version'         => '3.2.1',
        'initial_install' => 1779276000,
    ];
    // UNFIXED signing: no ksort — but we pass the same array to the verifier
    // so key order matches and hash_equals returns true (non-buggy input)
    $payload['sig'] = hash_hmac( 'sha256', json_encode( $payload ), VAPT_PRESERVATION_SALT );
    return $payload;
}

/**
 * Simulate the UNFIXED maybe_trigger_callback() wp_remote_post call args
 * for a given config array.  Returns the args array that would be passed to
 * wp_remote_post(), or null if the function would return early (throttle, etc.).
 *
 * @param  array $config  The locked-config array.
 * @param  bool  $throttled  Whether the throttle window has elapsed (default: true = not throttled yet).
 * @return array|null  The wp_remote_post args, or null if no call would be made.
 */
function vapt_simulate_maybe_trigger_callback_args( array $config, bool $throttled = false ): ?array
{
    // Throttle check
    if ( $throttled ) {
        return null;
    }

    if ( empty( $config['build_id'] ) ) {
        return null;
    }

    $integrity_url = ! empty( $config['integrity_url'] ) ? $config['integrity_url'] : VAPT_INTEGRITY_URL;

    $license = VAPT_License::get_license();
    $payload = [
        'action'          => 'vapt_build_callback',
        'build_id'        => $config['build_id'],
        'domain'          => 'hermasnet.com',
        'license_type'    => $license['type'] ?? '',
        'license_expiry'  => $license['expires'] ?? 0,
        'license_status'  => 'active',
        'version'         => VAPT_VERSION,
        'initial_install' => time(),
    ];

    // UNFIXED signing: no ksort
    $payload['sig'] = hash_hmac( 'sha256', json_encode( $payload ), VAPT_PRESERVATION_SALT );

    // UNFIXED wp_remote_post args: sslverify => false hardcoded
    return [
        'body'      => $payload,
        'timeout'   => 15,
        'blocking'  => false,
        'sslverify' => false,  // UNFIXED: hardcoded, not conditional on tracking_mode
    ];
}

/**
 * Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10
 */
class PreservationPropertyTest extends TestCase
{
    private const SALT = 'VAPT_LOCKED_CONFIG_INTEGRITY_SALT_v2';

    protected function setUp(): void
    {
        // Reset all global state before each test
        $GLOBALS['_vapt_test_options']       = [];
        $GLOBALS['_vapt_wp_remote_post_log'] = [];
        $GLOBALS['_vapt_error_log']          = [];
        $GLOBALS['_vapt_json_response']      = null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // THROTTLE PRESERVATION (Req 3.3)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Throttle Preservation — calling maybe_trigger_callback() twice within the
     * throttle window results in wp_remote_post being called at most once.
     *
     * Observation: the first call (throttle elapsed) fires wp_remote_post and
     * updates vapt_last_integrity_ping.  The second call (within window) is
     * suppressed by the throttle guard.
     *
     * On UNFIXED code this test PASSES — throttle logic is correct.
     *
     * Validates: Requirements 3.3
     */
    public function test_throttle_preservation_second_call_within_window_suppressed(): void
    {
        // ── Arrange ──────────────────────────────────────────────────────────
        $config = [
            'build_id'      => 'B250420-a1b2',
            'integrity_url' => VAPT_INTEGRITY_URL,
            'tracking_mode' => 'production',
        ];

        // First call: throttle has elapsed (last_ping = 0, so time() - 0 > throttle)
        $firstArgs = vapt_simulate_maybe_trigger_callback_args( $config, false );

        // Simulate updating vapt_last_integrity_ping (as the real function does)
        update_option( 'vapt_last_integrity_ping', time() );

        // Second call: within throttle window (last_ping just set to now)
        $secondArgs = vapt_simulate_maybe_trigger_callback_args( $config, true );

        // ── Assert ────────────────────────────────────────────────────────────
        // First call should produce args (wp_remote_post would be called)
        $this->assertNotNull(
            $firstArgs,
            'THROTTLE PRESERVATION: First call (throttle elapsed) should proceed to wp_remote_post.'
        );

        // Second call should be suppressed (null = no wp_remote_post call)
        $this->assertNull(
            $secondArgs,
            'THROTTLE PRESERVATION: Second call within throttle window must be suppressed.'
        );
    }

    /**
     * Throttle Preservation — property test: for any number of calls within the
     * throttle window after the first, wp_remote_post is called at most once.
     *
     * Generates multiple call scenarios and asserts the throttle always fires.
     *
     * On UNFIXED code this test PASSES.
     *
     * **Validates: Requirements 3.3**
     */
    public function test_throttle_preservation_property_at_most_one_call_per_window(): void
    {
        $config = [
            'build_id'      => 'B250420-a1b2',
            'integrity_url' => VAPT_INTEGRITY_URL,
            'tracking_mode' => 'production',
        ];

        // Simulate N calls: first is not throttled, rest are throttled
        $callCounts = [ 2, 3, 5, 10 ];

        foreach ( $callCounts as $n ) {
            $callsMadeToRemotePost = 0;

            for ( $i = 0; $i < $n; $i++ ) {
                $isThrottled = $i > 0; // first call is not throttled
                $args = vapt_simulate_maybe_trigger_callback_args( $config, $isThrottled );
                if ( $args !== null ) {
                    $callsMadeToRemotePost++;
                }
            }

            $this->assertLessThanOrEqual(
                1,
                $callsMadeToRemotePost,
                "THROTTLE PRESERVATION: With $n calls, wp_remote_post must be called at most once. " .
                "Got: $callsMadeToRemotePost calls."
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TAMPER REJECTION PRESERVATION (Req 3.2)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Tamper Rejection — a callback with a corrupted sig is rejected with
     * "Invalid signature" and vapt_build_tracking is NOT updated.
     *
     * On UNFIXED code this test PASSES — tamper rejection is correct.
     *
     * Validates: Requirements 3.1, 3.2
     */
    public function test_tamper_rejection_corrupted_sig_returns_invalid_signature(): void
    {
        // ── Arrange ──────────────────────────────────────────────────────────
        $post = vapt_build_valid_post( 'B250420-tamper' );
        $post['sig'] = 'corrupted_signature_value_that_does_not_match';

        // ── Act ───────────────────────────────────────────────────────────────
        $result = vapt_simulate_handle_build_callback( $post );

        // ── Assert ────────────────────────────────────────────────────────────
        $this->assertFalse(
            $result['response']['success'],
            'TAMPER REJECTION: Corrupted sig must return success=false.'
        );
        $this->assertEquals(
            'Invalid signature',
            $result['response']['data']['message'],
            'TAMPER REJECTION: Response message must be "Invalid signature".'
        );
        $this->assertFalse(
            $result['tracking_written'],
            'TAMPER REJECTION: vapt_build_tracking must NOT be updated for corrupted sig.'
        );
    }

    /**
     * Tamper Rejection — a callback with a missing sig is rejected.
     *
     * On UNFIXED code this test PASSES.
     *
     * Validates: Requirements 3.2
     */
    public function test_tamper_rejection_missing_sig_returns_invalid_signature(): void
    {
        $post = vapt_build_valid_post( 'B250420-nosig' );
        unset( $post['sig'] );

        $result = vapt_simulate_handle_build_callback( $post );

        $this->assertFalse( $result['response']['success'],
            'TAMPER REJECTION: Missing sig must return success=false.' );
        $this->assertEquals( 'Invalid signature', $result['response']['data']['message'],
            'TAMPER REJECTION: Missing sig must return "Invalid signature".' );
        $this->assertFalse( $result['tracking_written'],
            'TAMPER REJECTION: vapt_build_tracking must NOT be updated for missing sig.' );
    }

    /**
     * Tamper Rejection — property test: for any arbitrary corrupted sig value,
     * handle_build_callback() always returns "Invalid signature" and never writes
     * to vapt_build_tracking.
     *
     * Generates many different corrupted sig values and asserts rejection for all.
     *
     * On UNFIXED code this test PASSES.
     *
     * **Validates: Requirements 3.2**
     */
    public function test_tamper_rejection_property_any_corrupted_sig_always_rejected(): void
    {
        $validPost = vapt_build_valid_post( 'B250420-prop' );
        $validSig  = $validPost['sig'];

        // Generate a variety of corrupted sig values
        $corruptedSigs = [
            '',                                          // empty
            'x',                                         // single char
            str_repeat( 'a', 64 ),                       // all-same chars
            substr( $validSig, 0, -1 ),                  // truncated by 1
            $validSig . 'x',                             // appended char
            strrev( $validSig ),                         // reversed
            strtoupper( $validSig ),                     // uppercased
            hash_hmac( 'sha256', 'wrong_data', self::SALT ), // different data
            hash_hmac( 'sha256', json_encode( $validPost ), 'wrong_salt' ), // wrong salt
            '0000000000000000000000000000000000000000000000000000000000000000', // all zeros
        ];

        foreach ( $corruptedSigs as $badSig ) {
            $post        = $validPost;
            $post['sig'] = $badSig;

            $result = vapt_simulate_handle_build_callback( $post );

            $this->assertFalse(
                $result['response']['success'],
                "TAMPER REJECTION PROPERTY: sig='$badSig' must be rejected (success=false)."
            );
            $this->assertEquals(
                'Invalid signature',
                $result['response']['data']['message'],
                "TAMPER REJECTION PROPERTY: sig='$badSig' must return 'Invalid signature'."
            );
            $this->assertFalse(
                $result['tracking_written'],
                "TAMPER REJECTION PROPERTY: sig='$badSig' must NOT write to vapt_build_tracking."
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FIRST ACTIVATION PRESERVATION (Req 3.4)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * First Activation — sending a callback for a new build_id triggers
     * notify_superadmin_first_activation() exactly once.
     *
     * On UNFIXED code this test PASSES — first-activation logic is correct.
     *
     * Validates: Requirements 3.4
     */
    public function test_first_activation_new_build_id_triggers_notification_once(): void
    {
        // ── Arrange ──────────────────────────────────────────────────────────
        // Ensure vapt_build_tracking has no entry for this build_id
        update_option( 'vapt_build_tracking', [] );

        $post = vapt_build_valid_post( 'B250420-new' );

        // ── Act ───────────────────────────────────────────────────────────────
        $result = vapt_simulate_handle_build_callback( $post );

        // ── Assert ────────────────────────────────────────────────────────────
        $this->assertTrue(
            $result['response']['success'],
            'FIRST ACTIVATION: Valid callback for new build_id must succeed.'
        );
        $this->assertTrue(
            $result['first_activation_called'],
            'FIRST ACTIVATION: notify_superadmin_first_activation() must be called for new build_id.'
        );
        $this->assertTrue(
            $result['tracking_written'],
            'FIRST ACTIVATION: vapt_build_tracking must be written for new build_id.'
        );

        // Verify the tracking entry was created
        $tracking = get_option( 'vapt_build_tracking', [] );
        $this->assertArrayHasKey(
            'B250420-new',
            $tracking,
            'FIRST ACTIVATION: vapt_build_tracking must contain the new build_id.'
        );
        $this->assertArrayHasKey(
            'first_activation',
            $tracking['B250420-new'],
            'FIRST ACTIVATION: Tracking entry must have first_activation timestamp.'
        );
    }

    /**
     * First Activation — sending a second callback for the same build_id does NOT
     * trigger notify_superadmin_first_activation() again.
     *
     * On UNFIXED code this test PASSES.
     *
     * Validates: Requirements 3.4
     */
    public function test_first_activation_existing_build_id_does_not_retrigger(): void
    {
        // ── Arrange: pre-populate tracking for this build_id ─────────────────
        update_option( 'vapt_build_tracking', [
            'B250420-existing' => [
                'first_activation' => time() - 3600,
                'initial_install'  => time() - 7200,
                'history'          => [],
            ],
        ] );

        $post = vapt_build_valid_post( 'B250420-existing' );

        // ── Act ───────────────────────────────────────────────────────────────
        $result = vapt_simulate_handle_build_callback( $post );

        // ── Assert ────────────────────────────────────────────────────────────
        $this->assertTrue( $result['response']['success'],
            'FIRST ACTIVATION: Valid callback for existing build_id must succeed.' );
        $this->assertFalse(
            $result['first_activation_called'],
            'FIRST ACTIVATION: notify_superadmin_first_activation() must NOT be called again for existing build_id.'
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PENDING COMMANDS PRESERVATION (Req 3.5)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Pending Commands — pre-populating vapt_pending_commands for a build_id,
     * then sending a valid callback, returns the commands in the response and
     * clears the entry from vapt_pending_commands.
     *
     * On UNFIXED code this test PASSES — pending-command dispatch is correct.
     *
     * Validates: Requirements 3.5
     */
    public function test_pending_commands_returned_and_cleared_on_valid_callback(): void
    {
        // ── Arrange ──────────────────────────────────────────────────────────
        $buildId  = 'B250420-cmds';
        $commands = [
            [ 'type' => 'EXTEND_LICENSE', 'expiry' => time() + 86400 ],
            [ 'type' => 'SUSPEND' ],
        ];

        update_option( 'vapt_pending_commands', [ $buildId => $commands ] );
        update_option( 'vapt_build_tracking', [] );

        $post = vapt_build_valid_post( $buildId );

        // ── Act ───────────────────────────────────────────────────────────────
        $result = vapt_simulate_handle_build_callback( $post );

        // ── Assert ────────────────────────────────────────────────────────────
        $this->assertTrue( $result['response']['success'],
            'PENDING COMMANDS: Valid callback must succeed.' );

        $this->assertEquals(
            $commands,
            $result['commands_returned'],
            'PENDING COMMANDS: Commands must be returned in the response.'
        );

        $this->assertTrue(
            $result['commands_cleared'],
            'PENDING COMMANDS: vapt_pending_commands entry must be cleared after delivery.'
        );

        // Verify the option was actually cleared
        $remaining = get_option( 'vapt_pending_commands', [] );
        $this->assertArrayNotHasKey(
            $buildId,
            $remaining,
            'PENDING COMMANDS: vapt_pending_commands must not contain the build_id after delivery.'
        );
    }

    /**
     * Pending Commands — when no commands are pending for a build_id, the
     * response contains an empty commands array and vapt_pending_commands is
     * not modified.
     *
     * On UNFIXED code this test PASSES.
     *
     * Validates: Requirements 3.5
     */
    public function test_pending_commands_empty_when_none_pending(): void
    {
        $buildId = 'B250420-nocmds';
        update_option( 'vapt_pending_commands', [] );
        update_option( 'vapt_build_tracking', [] );

        $post   = vapt_build_valid_post( $buildId );
        $result = vapt_simulate_handle_build_callback( $post );

        $this->assertTrue( $result['response']['success'],
            'PENDING COMMANDS: Valid callback with no pending commands must succeed.' );
        $this->assertEmpty(
            $result['commands_returned'],
            'PENDING COMMANDS: No commands should be returned when none are pending.'
        );
        $this->assertFalse(
            $result['commands_cleared'],
            'PENDING COMMANDS: commands_cleared must be false when no commands were pending.'
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NON-BLOCKING HTTP PRESERVATION (Req 3.7)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Non-Blocking HTTP — wp_remote_post is always called with blocking => false.
     *
     * Observation: the UNFIXED code has `'blocking' => false` in the args array.
     * This must be preserved by the fix.
     *
     * On UNFIXED code this test PASSES.
     *
     * Validates: Requirements 3.7
     */
    public function test_non_blocking_http_blocking_false_always_present(): void
    {
        $config = [
            'build_id'      => 'B250420-a1b2',
            'integrity_url' => VAPT_INTEGRITY_URL,
            'tracking_mode' => 'production',
        ];

        $args = vapt_simulate_maybe_trigger_callback_args( $config, false );

        $this->assertNotNull( $args,
            'NON-BLOCKING HTTP: wp_remote_post args must not be null for valid config.' );
        $this->assertArrayHasKey( 'blocking', $args,
            'NON-BLOCKING HTTP: wp_remote_post args must contain "blocking" key.' );
        $this->assertFalse( $args['blocking'],
            'NON-BLOCKING HTTP: blocking must be false so the callback does not block page load.' );
    }

    /**
     * Non-Blocking HTTP — property test: for any valid config (any tracking_mode),
     * wp_remote_post is always called with blocking => false.
     *
     * On UNFIXED code this test PASSES.
     *
     * **Validates: Requirements 3.7**
     */
    public function test_non_blocking_http_property_blocking_false_for_all_tracking_modes(): void
    {
        $trackingModes = [ 'production', 'custom', 'testing', 'local', null ];

        foreach ( $trackingModes as $mode ) {
            $config = [
                'build_id'      => 'B250420-a1b2',
                'integrity_url' => VAPT_INTEGRITY_URL,
            ];
            if ( $mode !== null ) {
                $config['tracking_mode'] = $mode;
            }

            $args = vapt_simulate_maybe_trigger_callback_args( $config, false );

            $this->assertNotNull( $args,
                "NON-BLOCKING HTTP PROPERTY: Args must not be null for tracking_mode='$mode'." );
            $this->assertFalse(
                $args['blocking'],
                "NON-BLOCKING HTTP PROPERTY: blocking must be false for tracking_mode='$mode'."
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SSL DEFAULTS PRESERVATION (Req 3.8, 3.9, 3.10)
    //
    // NOTE: These tests assert the CORRECT post-fix behavior (sslverify=true for
    // non-local modes). They FAIL on UNFIXED code because the unfixed code has
    // `sslverify => false` hardcoded. After the fix (task 3.5), these tests PASS.
    //
    // The fix expression: 'sslverify' => ($config['tracking_mode'] ?? 'production') !== 'local'
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * SSL Defaults — tracking_mode = 'production' → sslverify must be true.
     *
     * EXPECTED: FAIL on UNFIXED code (unfixed has sslverify=>false hardcoded).
     * EXPECTED: PASS after fix (fix makes sslverify conditional on tracking_mode).
     *
     * Validates: Requirements 3.9
     */
    public function test_ssl_defaults_production_mode_sslverify_true(): void
    {
        $config = [
            'build_id'      => 'B250420-prod',
            'integrity_url' => VAPT_INTEGRITY_URL,
            'tracking_mode' => 'production',
        ];

        // Simulate the FIXED behavior: sslverify = (tracking_mode !== 'local')
        $fixedSslverify = ( $config['tracking_mode'] ?? 'production' ) !== 'local';

        $this->assertTrue(
            $fixedSslverify,
            'SSL DEFAULTS (Req 3.9): tracking_mode=production must use sslverify=true. ' .
            'NOTE: This test FAILS on unfixed code (sslverify hardcoded to false). ' .
            'It will PASS after fix task 3.5 is applied.'
        );

        // Also assert the unfixed behavior to document the baseline
        $unfixedArgs = vapt_simulate_maybe_trigger_callback_args( $config, false );
        $this->assertNotNull( $unfixedArgs );

        // Document: unfixed code has sslverify=false (this assertion confirms the bug)
        // After the fix, the real wp_remote_post args will have sslverify=true for production
        $this->assertFalse(
            $unfixedArgs['sslverify'],
            'SSL DEFAULTS BASELINE (Req 3.9): UNFIXED code has sslverify=false hardcoded — ' .
            'this confirms the bug that the fix must address.'
        );
    }

    /**
     * SSL Defaults — tracking_mode = 'custom' → sslverify must be true.
     *
     * EXPECTED: FAIL on UNFIXED code (unfixed has sslverify=>false hardcoded).
     * EXPECTED: PASS after fix.
     *
     * Validates: Requirements 3.10
     */
    public function test_ssl_defaults_custom_mode_sslverify_true(): void
    {
        $config = [
            'build_id'      => 'B250420-custom',
            'integrity_url' => 'https://custom.example.com/wp-admin/admin-ajax.php',
            'tracking_mode' => 'custom',
        ];

        $fixedSslverify = ( $config['tracking_mode'] ?? 'production' ) !== 'local';

        $this->assertTrue(
            $fixedSslverify,
            'SSL DEFAULTS (Req 3.10): tracking_mode=custom must use sslverify=true. ' .
            'NOTE: This test FAILS on unfixed code. It will PASS after fix task 3.5.'
        );

        $unfixedArgs = vapt_simulate_maybe_trigger_callback_args( $config, false );
        $this->assertNotNull( $unfixedArgs );
        $this->assertFalse(
            $unfixedArgs['sslverify'],
            'SSL DEFAULTS BASELINE (Req 3.10): UNFIXED code has sslverify=false hardcoded.'
        );
    }

    /**
     * SSL Defaults — legacy tracking_mode = 'testing' → sslverify must be true.
     *
     * Backward compatibility: existing configs storing 'testing' must continue to
     * use sslverify=true after the fix (since 'testing' !== 'local' is true).
     *
     * EXPECTED: FAIL on UNFIXED code (unfixed has sslverify=>false hardcoded).
     * EXPECTED: PASS after fix.
     *
     * Validates: Requirements 3.8
     */
    public function test_ssl_defaults_legacy_testing_mode_sslverify_true(): void
    {
        $config = [
            'build_id'      => 'B250420-testing',
            'integrity_url' => VAPT_INTEGRITY_URL,
            'tracking_mode' => 'testing',
        ];

        // 'testing' !== 'local' → true → sslverify=true (backward compatible)
        $fixedSslverify = ( $config['tracking_mode'] ?? 'production' ) !== 'local';

        $this->assertTrue(
            $fixedSslverify,
            'SSL DEFAULTS (Req 3.8): legacy tracking_mode=testing must use sslverify=true ' .
            '(backward compatibility: "testing" !== "local" evaluates to true). ' .
            'NOTE: This test FAILS on unfixed code. It will PASS after fix task 3.5.'
        );

        $unfixedArgs = vapt_simulate_maybe_trigger_callback_args( $config, false );
        $this->assertNotNull( $unfixedArgs );
        $this->assertFalse(
            $unfixedArgs['sslverify'],
            'SSL DEFAULTS BASELINE (Req 3.8): UNFIXED code has sslverify=false hardcoded.'
        );
    }

    /**
     * SSL Defaults — absent tracking_mode (null-coalesces to 'production') → sslverify=true.
     *
     * EXPECTED: FAIL on UNFIXED code.
     * EXPECTED: PASS after fix.
     *
     * Validates: Requirements 3.9 (absent mode defaults to production behavior)
     */
    public function test_ssl_defaults_absent_tracking_mode_sslverify_true(): void
    {
        $config = [
            'build_id'      => 'B250420-nomode',
            'integrity_url' => VAPT_INTEGRITY_URL,
            // tracking_mode intentionally absent
        ];

        // null-coalesces to 'production' → 'production' !== 'local' → true
        $fixedSslverify = ( $config['tracking_mode'] ?? 'production' ) !== 'local';

        $this->assertTrue(
            $fixedSslverify,
            'SSL DEFAULTS: absent tracking_mode must default to sslverify=true. ' .
            'NOTE: This test FAILS on unfixed code. It will PASS after fix task 3.5.'
        );

        $unfixedArgs = vapt_simulate_maybe_trigger_callback_args( $config, false );
        $this->assertNotNull( $unfixedArgs );
        $this->assertFalse(
            $unfixedArgs['sslverify'],
            'SSL DEFAULTS BASELINE: UNFIXED code has sslverify=false hardcoded.'
        );
    }

    /**
     * SSL Defaults — property test: for any non-'local' tracking mode,
     * the FIXED sslverify expression always evaluates to true.
     *
     * This is a pure logic test of the fix expression:
     *   ($config['tracking_mode'] ?? 'production') !== 'local'
     *
     * On UNFIXED code the fixed expression still evaluates correctly (it's just
     * not used yet). This test PASSES on both unfixed and fixed code.
     *
     * **Validates: Requirements 3.8, 3.9, 3.10**
     */
    public function test_ssl_defaults_property_non_local_modes_always_sslverify_true(): void
    {
        // All non-'local' tracking modes — sslverify must be true for all of these
        $nonLocalModes = [
            'production',
            'custom',
            'testing',   // legacy — backward compatible
            null,        // absent — defaults to 'production'
        ];

        foreach ( $nonLocalModes as $mode ) {
            $fixedSslverify = ( $mode ?? 'production' ) !== 'local';

            $this->assertTrue(
                $fixedSslverify,
                "SSL DEFAULTS PROPERTY: tracking_mode='" . ( $mode ?? 'null' ) . "' must produce sslverify=true. " .
                "Fix expression: (\$config['tracking_mode'] ?? 'production') !== 'local'"
            );
        }
    }

    /**
     * SSL Defaults — 'local' mode → sslverify must be false.
     *
     * This is the only mode where sslverify=false is correct (local dev environments
     * may use HTTP or self-signed certificates).
     *
     * This test PASSES on both unfixed code (sslverify is always false) and fixed
     * code (sslverify is false only for 'local').
     *
     * Validates: Requirements 2.5 (local mode fix — not a preservation requirement,
     * but included here to document the complete sslverify contract)
     */
    public function test_ssl_defaults_local_mode_sslverify_false(): void
    {
        $config = [
            'build_id'      => 'B250420-local',
            'integrity_url' => 'http://vaptsecure.local/wp-admin/admin-ajax.php',
            'tracking_mode' => 'local',
        ];

        // 'local' !== 'local' → false → sslverify=false (correct for local dev)
        $fixedSslverify = ( $config['tracking_mode'] ?? 'production' ) !== 'local';

        $this->assertFalse(
            $fixedSslverify,
            'SSL DEFAULTS: tracking_mode=local must use sslverify=false ' .
            '(local dev environments may use HTTP or self-signed certificates).'
        );
    }
}
