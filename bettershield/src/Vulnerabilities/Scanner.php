<?php
/**
 * The daily check: ask the feed about what this site runs, keep what it
 * says, and tell the log what changed.
 *
 * Runs only when a feed is bound and the owner has turned the check on —
 * it is the one place this feature reaches outside the site, and it says
 * exactly what it sends (slugs and versions, nothing else). With no feed
 * bound it records nothing and every surface says so.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Vulnerabilities;

use BetterShield\Events\Writer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Scanner {

	public const TASK           = 'bettershield_vulnerability_check';
	public const CONSENT_OPTION = 'bettershield_vulnerability_checks';

	/**
	 * The default accountless feed; an existing filter may replace or disable it.
	 */
	public static function feed(): ?Feed {
		/**
		 * The vulnerability data supply. Null means none is bound, and the
		 * check does not run.
		 *
		 * @param Feed|null $feed Null, preserving existing adapter precedence.
		 */
		$custom = false !== has_filter( 'bettershield_vulnerability_feed' );
		$feed = apply_filters( 'bettershield_vulnerability_feed', null );

		return $feed instanceof Feed ? $feed : ( $custom ? null : new HubFeed() );
	}

	/** Whether the owner has turned the check on — the guideline-7 consent. */
	public static function consented(): bool {
		return '1' === (string) get_option( self::CONSENT_OPTION, '0' );
	}

	public static function set_consent( bool $on ): void {
		update_option( self::CONSENT_OPTION, $on ? '1' : '0', false );

		Writer::instance()->record(
			'setting_changed',
			Writer::SEVERITY_LOW,
			array(
				'object_type' => 'setting',
				'object_id'   => self::CONSENT_OPTION,
				'context'     => array( 'enabled' => $on ),
			)
		);

		if ( $on ) { self::schedule(); }

		if ( ! $on ) {
			// Off means off: nothing kept that came from outside.
			State::forget();
			wp_clear_scheduled_hook( 'bettershield_inventory_recheck' );
		}
	}

	/**
	 * A plugin or theme was deleted: check the inventory again soon. Nothing
	 * to do when the plugin deleted is this one, or its files are already
	 * gone: the schedule would load classes whose files no longer exist.
	 *
	 * @param mixed $item The plugin file or theme folder WordPress deleted.
	 */
	public static function on_deleted( $item = '' ): void {
		if ( plugin_basename( BETTERSHIELD_FILE ) === (string) $item || ! file_exists( BETTERSHIELD_FILE ) ) {
			return;
		}

		self::schedule();
	}

	/** Schedule after inventory changes, honoring a service retry deadline. */
	public static function schedule( $delay = 10 ): void {
		if ( ! self::consented() ) {
			return;
		}
		$delay = is_int( $delay ) ? max( 10, min( HOUR_IN_SECONDS, $delay ) ) : 10;
		$at = max( time() + $delay, (int) get_transient( HubFeed::RETRY ) );
		$scheduled = wp_next_scheduled( 'bettershield_inventory_recheck' );
		if ( $scheduled && $scheduled < (int) get_transient( HubFeed::RETRY ) ) {
			wp_clear_scheduled_hook( 'bettershield_inventory_recheck' );
			$scheduled = false;
		}
		if ( ! $scheduled ) {
			wp_schedule_single_event( $at, 'bettershield_inventory_recheck' );
		}
	}

	/** Translation updates do not change the component inventory. */
	public static function after_upgrade( $upgrader, array $options ): void {
		if ( in_array( $options['type'] ?? '', array( 'core', 'plugin', 'theme' ), true ) ) {
			self::schedule();
		}
	}

	public static function recheck(): void {
		Inventory::fresh();
		\BetterShield\Cron\Runner::instance()->run_task( self::TASK );
		// The update that brought this recheck cleared core's update cache.
		\BetterShield\Audit\Checks::refill_update_cache();
		\BetterShield\Audit\Auditor::run();
	}

	/**
	 * Run the check. Answers with what happened, for a screen or the CLI.
	 *
	 * @return array{ran: bool, reason: string, affected: int}
	 */
	public static function run(): array {
		$feed = self::feed();

		if ( null === $feed ) {
			return array( 'ran' => false, 'reason' => 'no_feed', 'affected' => 0 );
		}

		if ( ! self::consented() ) {
			return array( 'ran' => false, 'reason' => 'not_enabled', 'affected' => 0 );
		}

		if ( ! \BetterShield\Support\Claim::claim( 'vulnerability-refresh', 60 ) ) {
			self::schedule( 60 );
			return array( 'ran' => false, 'reason' => 'busy', 'affected' => count( State::get()['affected'] ) );
		}
		try { return self::perform( $feed ); }
		finally { \BetterShield\Support\Claim::release( 'vulnerability-refresh' ); }
	}

	private static function perform( Feed $feed ): array {
		$inventory = Inventory::fresh();
		$answer    = $feed->advisories( Inventory::for_feed( $inventory ) );

		if ( is_wp_error( $answer ) ) {
			State::record_failure( $feed, $answer->get_error_message() );

			Writer::instance()->record(
				'vulnerability_check_failed',
				Writer::SEVERITY_LOW,
				array(
					'object_type' => 'feed',
					'object_id'   => $feed->id(),
					'context'     => array( 'error' => $answer->get_error_code() ),
				)
			);

			return array( 'ran' => false, 'reason' => 'feed_error', 'affected' => count( State::get()['affected'] ) );
		}

		if ( ! self::consented() ) { return array( 'ran' => false, 'reason' => 'not_enabled', 'affected' => 0 ); }
		if ( Inventory::digest( $inventory ) !== Inventory::digest( Inventory::fresh() ) ) {
			State::record_failure( $feed, __( 'Installed components changed during the check. Another check is scheduled.', 'bettershield' ), 'inventory' );
			self::schedule();
			return array( 'ran' => false, 'reason' => 'inventory_changed', 'affected' => count( State::get()['affected'] ) );
		}
		$before   = State::get()['affected'];
		$affected = Matcher::match( $inventory, (array) ( $answer['advisories'] ?? array() ) );

		State::record( $feed, (string) ( $answer['published_at'] ?? gmdate( 'c' ) ), count( $inventory ), $affected, $answer );

		self::announce( $before, $affected );

		return array( 'ran' => true, 'reason' => 'ok', 'affected' => count( $affected ) );
	}

	/**
	 * What changed since last time, as events: a newly affected item is
	 * recorded at its own severity (a critical one reaches instant alerting
	 * through the alerting path); one no longer affected — updated, removed,
	 * or the advisory withdrawn — is recorded as resolved.
	 *
	 * @param array<int, array<string, mixed>> $before
	 * @param array<int, array<string, mixed>> $after
	 */
	private static function announce( array $before, array $after ): void {
		$key = static fn( array $item ): string => $item['type'] . ':' . $item['slug'];

		$was = array();
		foreach ( $before as $item ) {
			$was[ $key( $item ) ] = $item;
		}

		$now = array();
		foreach ( $after as $item ) {
			$now[ $key( $item ) ] = $item;
		}

		$levels = array(
			'critical' => Writer::SEVERITY_CRITICAL,
			'high'     => Writer::SEVERITY_HIGH,
			'medium'   => Writer::SEVERITY_MEDIUM,
			'low'      => Writer::SEVERITY_LOW,
			'info'     => Writer::SEVERITY_INFO,
		);

		/*
		 * Which advisories, not how many. A withdrawn advisory replaced by a
		 * new one for the same component at the same severity leaves the count
		 * where it was — so the day a fresh advisory was published against
		 * something installed here, the log said nothing at all.
		 */
		$advisory_ids = static function ( array $item ): array {
			$ids = array_map(
				static function ( array $advisory ): string {
					return (string) ( $advisory['id'] ?? '' );
				},
				array_filter( $item['advisories'], static fn( array $a ): bool => 'affected' === ( $a['match_status'] ?? 'affected' ) )
			);

			sort( $ids );

			return $ids;
		};

		$switched = self::provider_switched( $before, $after );

		foreach ( $now as $k => $item ) {
			if ( 'unknown' === ( $item['match_status'] ?? '' ) ) { continue; }
			$previous = $was[ $k ] ?? null;

			/*
			 * The data moved to another provider: every advisory id changed
			 * (wordfence:… to patchstack:…), so every item already listed
			 * would read as a different advisory and alert again. On that
			 * read an item already listed is news only if it is rated higher
			 * or newly exploited; one only the new provider lists is still
			 * news. The read after compares as usual.
			 */
			if ( $switched && null !== $previous && ! self::worse_on_switch( $previous, $item ) ) {
				continue;
			}

			// New, or worse than it was, or a different advisory: worth a
			// line. The same item saying the same thing day after day is not.
			if ( null !== $previous
				&& ( $previous['match_status'] ?? 'affected' ) === ( $item['match_status'] ?? 'affected' )
				&& $previous['severity'] === $item['severity']
				&& ( $previous['severity_known'] ?? true ) === ( $item['severity_known'] ?? true )
				&& $advisory_ids( $previous ) === $advisory_ids( $item )
				&& in_array( true, array_column( $previous['advisories'], 'exploited' ), true ) === in_array( true, array_column( $item['advisories'], 'exploited' ), true )
			) {
				continue;
			}

			Writer::instance()->record(
				'vulnerability_found',
				$levels[ $item['severity'] ] ?? Writer::SEVERITY_MEDIUM,
				array(
					'object_type' => $item['type'],
					'object_id'   => $item['slug'],
					'context'     => array(
						'name'              => $item['name'],
						'installed_version' => $item['installed_version'],
						'fixed_in'          => $item['fixed_in'],
						'advisories'        => count( $item['advisories'] ),
						'severity'          => false === ( $item['severity_known'] ?? true ) ? null : $item['severity'],
						'severity_known'    => $item['severity_known'] ?? true,
						'exploited'         => in_array( true, array_column( $item['advisories'], 'exploited' ), true ),
					),
				)
			);
		}

		foreach ( $was as $k => $item ) {
			if ( isset( $now[ $k ] ) ) {
				continue;
			}

			Writer::instance()->record(
				'vulnerability_resolved',
				Writer::SEVERITY_INFO,
				array(
					'object_type' => $item['type'],
					'object_id'   => $item['slug'],
					'context'     => array( 'name' => $item['name'] ),
				)
			);
		}
	}

	/**
	 * Whether this read's data comes from another provider than the last
	 * read's: their advisory ids share no provider. Only where every id names
	 * one (`provider:id`) and both reads list something, so a first read, a
	 * feed with unprefixed ids and a read with nothing affected compare as
	 * they always did.
	 *
	 * @param array<int, array<string, mixed>> $before
	 * @param array<int, array<string, mixed>> $after
	 */
	private static function provider_switched( array $before, array $after ): bool {
		$providers = static function ( array $items ): array {
			$found = array();

			foreach ( $items as $item ) {
				foreach ( (array) ( $item['advisories'] ?? array() ) as $advisory ) {
					$id = (string) ( $advisory['id'] ?? '' );
					$at = strpos( $id, ':' );

					$found[ false === $at || 0 === $at ? '' : substr( $id, 0, $at ) ] = true;
				}
			}

			return $found;
		};

		$was = $providers( $before );
		$now = $providers( $after );

		if ( array() === $was || array() === $now || isset( $was[''] ) || isset( $now[''] ) ) {
			return false;
		}

		return array() === array_intersect_key( $was, $now );
	}

	/**
	 * Whether an item already listed got worse on a provider switch: rated
	 * higher, exploited where it was not, or confirmed where it could not be
	 * told before. A severity nobody gave counts at medium, the level the
	 * audit grades it at.
	 *
	 * @param array<string, mixed> $previous
	 * @param array<string, mixed> $item
	 */
	private static function worse_on_switch( array $previous, array $item ): bool {
		$rank = static function ( array $row ): int {
			$severity = false === ( $row['severity_known'] ?? true ) ? 'medium' : (string) ( $row['severity'] ?? 'medium' );
			$at       = array_search( $severity, Matcher::SEVERITIES, true );

			return false === $at ? (int) array_search( 'medium', Matcher::SEVERITIES, true ) : (int) $at;
		};

		$exploited = static fn( array $row ): bool => in_array( true, array_column( (array) ( $row['advisories'] ?? array() ), 'exploited' ), true );

		// Listed before as "can't tell" and now confirmed is news, as it is
		// on any other read.
		$confirmed = 'affected' === ( $item['match_status'] ?? 'affected' ) && 'affected' !== ( $previous['match_status'] ?? 'affected' );

		return $confirmed || $rank( $item ) < $rank( $previous ) || ( $exploited( $item ) && ! $exploited( $previous ) );
	}

	/**
	 * What every surface may say about the check, in one shape.
	 *
	 * @return array<string, mixed>
	 */
	public static function summary(): array {
		$feed = self::feed();

		// One read, and everything below derived from it. Each of the three
		// helpers this used to call reaches the same stored record, so the
		// answers were assembled from five reads of one thing.
		$state    = State::get();
		$has_data = '' !== $state['fetched_at'];
		$age      = State::age_days();

		return array(
			'feed_bound'   => null !== $feed,
			'feed_label'   => null !== $feed ? $feed->label() : '',
			'enabled'      => self::consented(),
			'has_data'     => $has_data,
			'fetched_at'   => $state['fetched_at'],
			'published_at' => $state['published_at'],
			'age_days'     => $age,
			'stale'        => $has_data && ( null === $age || $age >= State::STALE_AFTER_DAYS ),
			'checked'      => $state['checked'],
			'affected'     => count( $state['affected'] ),
			'unknown'      => count( array_filter( $state['affected'], static fn( array $item ): bool => 'unknown' === ( $item['match_status'] ?? '' ) ) ),
			'attribution'  => $state['attribution'],
			// Whose data the result is, so the screens can credit it.
			'provider'     => $state['provider'],
			'error'        => $state['error'],
			'error_kind'   => $state['error_kind'],
		);
	}
}
