<?php
/**
 * Who has been trying to sign in: the networks failed sign-ins came from and
 * the names they tried, added up over the last week or month.
 *
 * Every failed sign-in is already a row in the log, one per source per few
 * minutes, carrying how many more it stands for. Read one by one they cannot
 * show that a single network made most of last week's attempts, or that bots
 * are working through `admin` and the site's own author names. This adds them
 * up and stores nothing new (#1979).
 *
 * The network is the stored /24 or /64, never an address. Whether a tried name
 * is a real account is said only to someone who may list the site's users,
 * who can already read every username on the Users screen; to anyone else it
 * would give the accounts away. The offer to block a name follows the same
 * rule, since it is made only for names that are not accounts.
 *
 * Read-only.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Login;

use BetterShield\Database\Schema;
use BetterShield\Support\Ip;
use BetterShield\Support\Tier;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Attempts {

	/** The spans the panel offers, in days. */
	public const SPANS = array( 7, 30 );

	private const NETWORKS_SHOWN = 5;

	private const NAMES_SHOWN = 10;

	/** How many characters of a tried name the log keeps. */
	private const NAME_KEPT = 60;

	/** How long sign-in protection keeps each failure, as the pruner does: two days. */
	private const ATTEMPTS_KEPT = 2 * DAY_IN_SECONDS;

	/**
	 * The top networks and names tried over the span.
	 *
	 * Each row counts once plus the attempts it stands for. A row's attempts
	 * belong to its network; of the names they tried only which ones is kept,
	 * not how often, so each of those counts once.
	 *
	 * @param int  $days          7 or 30.
	 * @param bool $with_accounts Say which names are accounts, and which may be blocked.
	 * @return array{days: int, total: int, networks: array<int, array{network: string, count: int}>, names: array<int, array<string, mixed>>, marked: bool}
	 */
	public static function summary( int $days, bool $with_accounts ): array {
		$days  = in_array( $days, self::SPANS, true ) ? $days : self::SPANS[0];
		$since = max( gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS ), Tier::retention_floor() );

		/*
		 * The log keeps one row per source per few minutes, and a burst's
		 * extra count rides only on that source's next row, so a burst that
		 * ends is never added (#2612). Sign-in protection keeps every failure
		 * for its last two days, which the lockout list counts: over those
		 * days each network and name takes the higher of the two, as either
		 * can miss some (that table only while lockouts or proof of work run,
		 * and never for an allowed address). Before them, the log alone.
		 */
		$recent = max( $since, gmdate( 'Y-m-d H:i:s', time() - self::ATTEMPTS_KEPT ) );
		$older  = $since < $recent ? self::from_log( $since, $recent ) : self::nothing();
		$log    = self::from_log( $recent, null );
		$kept   = self::from_attempts( $recent );

		$total    = $older['total'] + max( $log['total'], $kept['total'] );
		$networks = $older['networks'];
		$names    = $older['names'];

		foreach ( array_unique( array_merge( array_keys( $log['networks'] ), array_keys( $kept['networks'] ) ) ) as $label ) {
			$networks[ $label ] = ( $networks[ $label ] ?? 0 ) + max( $log['networks'][ $label ] ?? 0, $kept['networks'][ $label ] ?? 0 );
		}

		foreach ( array_unique( array_merge( array_keys( $log['names'] ), array_keys( $kept['names'] ) ) ) as $name ) {
			$names[ (string) $name ] = ( $names[ (string) $name ] ?? 0 ) + max( $log['names'][ $name ] ?? 0, $kept['names'][ $name ] ?? 0 );
		}

		$top_networks = array();
		foreach ( self::top( $networks, self::NETWORKS_SHOWN ) as $network => $count ) {
			$top_networks[] = array(
				'network' => (string) $network,
				'count'   => $count,
			);
		}

		$blocked  = $with_accounts ? self::blocked_names() : array();
		$top_name = array();

		foreach ( self::top( $names, self::NAMES_SHOWN ) as $name => $count ) {
			$name  = (string) $name;
			$entry = array(
				'name'  => $name,
				'count' => $count,
			);

			if ( $with_accounts ) {
				$account = get_user_by( 'login', $name ) instanceof \WP_User;
				$listed  = in_array( strtolower( $name ), $blocked, true );

				$entry['account'] = $account;
				$entry['blocked'] = $listed;
				// A masked email or anything else the blocklist would store
				// differently from how it reads here is not offered. Nor is a
				// name at the log's 60-character cut: it may be the start of a
				// longer one, which a block on it would never refuse (#2612).
				$entry['blockable'] = ! $account && ! $listed && sanitize_user( $name, true ) === $name && mb_strlen( $name ) < self::NAME_KEPT;
			}

			$top_name[] = $entry;
		}

		return array(
			'days'     => $days,
			'total'    => $total,
			'networks' => $top_networks,
			'names'    => $top_name,
			'marked'   => $with_accounts,
		);
	}

	/**
	 * Failed sign-ins in the log from $since, before $until where given:
	 * each row once, plus the attempts it stands for.
	 *
	 * @return array{total: int, networks: array<string, int>, names: array<string, int>}
	 */
	private static function from_log( string $since, ?string $until ): array {
		global $wpdb;

		$table = Schema::table( 'events' );
		$scope = Schema::site_where( 'events' );
		$upper = null === $until ? '' : $wpdb->prepare( ' AND occurred_at < %s', $until );

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the scope is Schema::site_where(), built from integers; $upper is prepared above; every value is bound.
		$by_network = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ip_prefix, COUNT(*) AS total FROM %i WHERE {$scope} AND event_type = 'login_failed' AND occurred_at >= %s{$upper} GROUP BY ip_prefix",
				$table,
				$since
			)
		);

		$by_name = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT object_id, COUNT(*) AS total FROM %i WHERE {$scope} AND event_type = 'login_failed' AND occurred_at >= %s{$upper} AND object_id IS NOT NULL AND object_id <> '' GROUP BY object_id",
				$table,
				$since
			)
		);

		// Only the rows that stand for more than themselves are read whole,
		// and their counts added here rather than with JSON functions not
		// every supported database has.
		$carried = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ip_prefix, context FROM %i WHERE {$scope} AND event_type = 'login_failed' AND occurred_at >= %s{$upper} AND context LIKE %s LIMIT 20000",
				$table,
				$since,
				'%' . $wpdb->esc_like( '"unlogged_attempts"' ) . '%'
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$out = self::nothing();

		// Every row counts toward the total, including one whose name could
		// not be stored (a login in a script the log keeps no letters of) or
		// whose network could not be read.
		foreach ( is_array( $by_network ) ? $by_network : array() as $row ) {
			$out['total'] += (int) $row->total;
			$label         = Ip::prefix_label( null !== $row->ip_prefix ? (string) $row->ip_prefix : null );

			if ( null !== $label ) {
				$out['networks'][ $label ] = ( $out['networks'][ $label ] ?? 0 ) + (int) $row->total;
			}
		}

		foreach ( is_array( $by_name ) ? $by_name : array() as $row ) {
			$out['names'][ (string) $row->object_id ] = ( $out['names'][ (string) $row->object_id ] ?? 0 ) + (int) $row->total;
		}

		foreach ( is_array( $carried ) ? $carried : array() as $row ) {
			$context = json_decode( (string) $row->context, true );

			if ( ! is_array( $context ) ) {
				continue;
			}

			$more          = max( 0, (int) ( $context['unlogged_attempts'] ?? 0 ) );
			$out['total'] += $more;
			$label         = Ip::prefix_label( null !== $row->ip_prefix ? (string) $row->ip_prefix : null );

			if ( null !== $label && $more > 0 ) {
				$out['networks'][ $label ] = ( $out['networks'][ $label ] ?? 0 ) + $more;
			}

			foreach ( is_array( $context['unlogged_names'] ?? null ) ? $context['unlogged_names'] : array() as $name ) {
				if ( is_string( $name ) && '' !== $name ) {
					$out['names'][ $name ] = ( $out['names'][ $name ] ?? 0 ) + 1;
				}
			}
		}

		return $out;
	}

	/**
	 * Failed sign-ins sign-in protection kept from $since, one row each.
	 *
	 * @return array{total: int, networks: array<string, int>, names: array<string, int>}
	 */
	private static function from_attempts( string $since ): array {
		global $wpdb;

		$table = Schema::table( 'login_attempts' );

		$by_network = $wpdb->get_results( $wpdb->prepare( "SELECT ip_prefix, COUNT(*) AS total FROM %i WHERE surface = 'signin' AND outcome = 'failed' AND occurred_at >= %s GROUP BY ip_prefix", $table, $since ) );
		$by_name    = $wpdb->get_results( $wpdb->prepare( "SELECT username, COUNT(*) AS total FROM %i WHERE surface = 'signin' AND outcome = 'failed' AND occurred_at >= %s AND username IS NOT NULL AND username <> '' GROUP BY username", $table, $since ) );

		$out = self::nothing();

		foreach ( is_array( $by_network ) ? $by_network : array() as $row ) {
			$out['total'] += (int) $row->total;
			$label         = Ip::prefix_label( null !== $row->ip_prefix ? (string) $row->ip_prefix : null );

			if ( null !== $label ) {
				$out['networks'][ $label ] = ( $out['networks'][ $label ] ?? 0 ) + (int) $row->total;
			}
		}

		foreach ( is_array( $by_name ) ? $by_name : array() as $row ) {
			$out['names'][ (string) $row->username ] = ( $out['names'][ (string) $row->username ] ?? 0 ) + (int) $row->total;
		}

		return $out;
	}

	/**
	 * No sign-ins counted.
	 *
	 * @return array{total: int, networks: array<string, int>, names: array<string, int>}
	 */
	private static function nothing(): array {
		return array(
			'total'    => 0,
			'networks' => array(),
			'names'    => array(),
		);
	}

	/**
	 * The highest counts first, ties in a stable order.
	 *
	 * @param array<string|int, int> $counts
	 * @return array<string|int, int>
	 */
	private static function top( array $counts, int $limit ): array {
		uksort(
			$counts,
			static function ( $a, $b ) use ( $counts ): int {
				return array( $counts[ $b ], (string) $a ) <=> array( $counts[ $a ], (string) $b );
			}
		);

		return array_slice( $counts, 0, $limit, true );
	}

	/**
	 * The names already refused from every network, lowercased.
	 *
	 * @return string[]
	 */
	private static function blocked_names(): array {
		$names = array();

		foreach ( Protection::instance()->settings()['blocklist'] as $entry ) {
			if ( is_array( $entry ) && '' !== (string) ( $entry['username'] ?? '' ) && '' === (string) ( $entry['range'] ?? '' ) && '' === (string) ( $entry['ua'] ?? '' ) ) {
				$names[] = strtolower( (string) $entry['username'] );
			}
		}

		return $names;
	}
}
