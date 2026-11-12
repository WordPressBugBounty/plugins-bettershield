<?php
/** Explicit evidence projections. No actor inference. The only file content behind them is the named signs of compromise an added file showed, carried as rule ids and line numbers, never the bytes. @package BetterShield */
declare( strict_types=1 );
namespace BetterShield\Incidents;
use BetterShield\Events\Writer;
use BetterShield\Integrity\Packages;
use BetterShield\Support\Text;
if ( ! defined( 'ABSPATH' ) ) { exit; }
final class Signals {
	public const EVENTS = array( 'user_created', 'user_role_granted', 'user_role_changed', 'app_password_created', 'canary_used', 'canary_page_touched', 'hardening_reverted', 'login_protection_updated', 'two_factor_policy_changed', 'passkey_policy_changed', 'network_2fa_policy_changed', 'network_passkey_policy_changed', 'site_setting_changed', 'dormant_privileged_login', 'user_email_changed', 'password_changed', 'account_takeover_sequence', 'plugin_installed', 'plugin_updated', 'update_code_changed', 'store_script_host_added' );
	public static function event( array $row ): ?array {
		$type = (string) $row['event_type'];
		$context = json_decode( (string) ( $row['context'] ?? '' ), true );
		$context = is_array( $context ) ? $context : array();
		$high = (int) $row['severity'] >= Writer::SEVERITY_HIGH;
		$anchor = '';
		if ( 'canary_used' === $type ) { $anchor = 'credential'; }
		elseif ( in_array( $type, array( 'user_created', 'user_role_granted', 'app_password_created' ), true ) && $high && 'user' === $row['object_type'] && 'canary' !== ( $context['kind'] ?? '' ) ) { $anchor = 'access'; }
		elseif ( 'user_role_changed' === $type && $high ) {
			$from = explode( ',', (string) ( $context['from'] ?? '' ) );
			$to = explode( ',', (string) ( $context['to'] ?? '' ) );
			$policy = \BetterShield\Password\Policy::instance();
			if ( ( ! $policy->roles_are_privileged( $from ) && $policy->roles_are_privileged( $to ) ) || ( in_array( 'administrator', $to, true ) && ! in_array( 'administrator', $from, true ) ) ) { $anchor = 'access'; }
			else { return null; }
		}
		elseif ( in_array( $type, array( 'login_protection_updated', 'two_factor_policy_changed', 'network_2fa_policy_changed', 'network_passkey_policy_changed', 'passkey_policy_changed' ), true ) ) {
			if ( empty( $context['weakened'] ) ) { return null; }
		}
		// An account's own address or password changing is upkeep, and joins an
		// incident only on a privileged account: customer self-service never
		// lands here. Corroboration only, never an anchor; the three together
		// are the takeover sequence, which corroborates too.
		elseif ( 'user_email_changed' === $type ) { if ( ! $high || 'user' !== $row['object_type'] ) { return null; } }
		elseif ( 'password_changed' === $type ) { if ( 'user' !== $row['object_type'] || ! \BetterShield\Password\Policy::instance()->user_is_privileged( (int) $row['object_id'] ) ) { return null; } }
		// Off and straight back on with other settings is no weakening (#1833).
		elseif ( 'hardening_reverted' === $type && 'reconfigure' === ( $context['cause'] ?? '' ) ) { return null; }
		// A plugin installed or updated, and the code its update brought, are
		// often the cause of what an anchor shows, so they join an incident
		// that is open around them. Corroboration only, never an anchor: an
		// update on its own is upkeep and opens nothing (#717, #2343).
		// A store page loading a script from a site it never loaded from
		// before. Corroboration only, never an anchor: new tags are pasted in
		// every day, and one is only evidence beside something else.
		elseif ( ! in_array( $type, array( 'hardening_reverted', 'site_setting_changed', 'dormant_privileged_login', 'canary_page_touched', 'account_takeover_sequence', 'plugin_installed', 'plugin_updated', 'update_code_changed', 'store_script_host_added' ), true ) ) { return null; }
		$actor = 'user' === ( $row['actor_type'] ?? '' ) ? (int) ( $row['actor_id'] ?? 0 ) : 0;
		$details = array_intersect_key( $context, array_fill_keys( array( 'roles', 'from', 'to', 'role', 'weakened', 'days_idle', 'host' ), true ) );
		// Account labels and password names are deliberately not copied. UUIDs
		// identify revocable credentials, not their secret; management plans
		// retrieve the current credential independently before acting.
		if ( 'app_password_created' === $type ) { $details = array( 'credential_id' => (string) ( $context['uuid'] ?? '' ) ); }
		// A plugin's own name, so the row says which update it was.
		if ( 'plugin' === ( $row['object_type'] ?? '' ) && isset( $context['name'] ) ) { $details['name'] = Text::clip( (string) $context['name'], 100 ); }
		// The code files an update brought, dot-files first as Activity lists
		// them, with the count it recorded without naming.
		if ( 'update_code_changed' === $type ) {
			$files = array_slice( array_values( array_unique( array_map( static fn( $f ): string => Text::clip( (string) $f, 255 ), array_merge( (array) ( $context['hidden'] ?? array() ), (array) ( $context['files'] ?? array() ) ) ) ) ), 0, 20 );
			$details['files'] = $files; $details['more'] = max( 0, (int) ( $context['added'] ?? 0 ) + (int) ( $context['changed'] ?? 0 ) - count( $files ) );
		}
		return array( 'source_key' => hash( 'sha256', 'event:' . wp_json_encode( array( $row['occurred_at'], $type, $actor, $row['object_id'], $row['context'] ?? '' ) ) ), 'occurred_at' => $row['occurred_at'], 'anchor' => $anchor, 'announced' => self::goes_out_at_once( $row ), 'actor_id' => $actor, 'event_type' => $type,
			'snapshot' => array( 'source' => 'activity', 'source_id' => (int) $row['id'], 'object_type' => Text::clip( (string) $row['object_type'], 32 ), 'object_id' => Text::clip( (string) $row['object_id'], 1024 ), 'target_user' => 'user' === $row['object_type'] ? (int) $row['object_id'] : 0, 'details' => $details ) );
	}
	/**
	 * Whether the row that opens an incident goes out in the instant email,
	 * which then names the incident. A file row that opens one can't wait for
	 * the summary: it is critical. See `Notifier::observe()`.
	 *
	 * @param array<string, mixed> $row
	 */
	private static function goes_out_at_once( array $row ): bool {
		return (int) $row['severity'] >= Writer::SEVERITY_HIGH
			&& ! \BetterShield\Alerts\Settings::instance()->waits_for_summary( $row )
			&& ! \BetterShield\Alerts\Maintenance::report()['active'];
	}

	/**
	 * Whether a file row that opens an incident is sure to go out in the
	 * instant email. While the host takes the routine alerts, or file changes
	 * are kept for the summary, it may not, and then the incident has to be
	 * said on its own rather than skipped.
	 */
	private static function file_goes_out_at_once(): bool {
		$settings = \BetterShield\Alerts\Settings::instance()->settings();

		return ! $settings['host_managed']
			&& ! in_array( 'file_changed', (array) $settings['instant_off'], true )
			&& ! \BetterShield\Alerts\Maintenance::report()['active'];
	}

	public static function integrity( array $row ): ?array {
		if ( ! in_array( $row['change_type'], array( 'added', 'modified' ), true ) || ! in_array( $row['status'], array( 'new', 'acknowledged' ), true ) ) { return null; }
		$path = (string) $row['path'];
		$context = (string) $row['context'];
		// Baseline additions say "new since baseline", never "unpublished".
		$baseline = in_array( $context, array( 'muplugin', 'dropin', 'theme', 'unlisted' ), true );
		$core = 'core' === $context && ( str_starts_with( $path, 'wp-admin/' ) || str_starts_with( $path, 'wp-includes/' ) );
		if ( ! $baseline && ! $core && 'plugin' !== $context ) { return null; }
		if ( ! preg_match( '/\.(?:' . Packages::SERVER_PHP . ')\z/i', $path ) ) { return null; }
		return array( 'source_key' => hash( 'sha256', 'integrity:' . $row['id'] . ':' . $row['detected_at'] . ':' . $path . ':' . $row['hash_after'] ), 'occurred_at' => $row['detected_at'], 'announced' => self::file_goes_out_at_once(), 'anchor' => 'added' === $row['change_type'] && empty( $row['unconfirmed_update'] ) ? 'code' : '', 'actor_id' => 0, 'event_type' => 'added' === $row['change_type'] ? 'incident_code_added' : 'incident_code_modified',
			'snapshot' => array( 'source' => 'integrity', 'source_id' => (int) $row['id'], 'object_type' => 'file', 'object_id' => Text::clip( $path, 1024 ), 'target_user' => 0, 'details' => array( 'context' => $context, 'comparison' => $baseline ? 'saved_baseline' : 'publisher_manifest', 'sha256_or_md5' => (string) $row['hash_after'] ) + self::signs( $row ) ) );
	}
	/**
	 * The named signs of compromise an added file showed, when it showed any.
	 * They count as corroboration in `Repository::stats()`, and nothing else:
	 * no anchor, no grade, no action.
	 *
	 * @param array<string, mixed> $row
	 * @return array<string, mixed>
	 */
	private static function signs( array $row ): array {
		$signs = \BetterShield\Audit\CompromiseSigns::parse( (string) ( $row['signals'] ?? '' ) );
		return array() === $signs ? array() : array( 'signals' => $signs );
	}
}
