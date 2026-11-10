<?php
/**
 * Whether anything is actually using the thing you are about to switch off.
 *
 * Every preview until now answered the same kind of question: **who is
 * structurally affected.** It queries the shape of the site — how many accounts
 * hold an application password, which roles reach the dashboard. That is a
 * useful question and it is not the one owners ask. They ask *"is anything
 * really using this right now?"*, and for several items there is nothing
 * structural to count at all: XML-RPC has no capability holders to enumerate,
 * so its preview was a generic caution and the item stayed off.
 *
 * This answers from the activity log, which is evidence rather than shape.
 *
 * **Two things it must never do.** It must never say "nothing has used this"
 * when the honest answer is "nothing has used it since this plugin started
 * looking a week ago" — that is a claim about a site made from a window it
 * does not cover, on the screen where somebody decides whether to break their
 * own integration. And it must never be read as permission: "nothing used it
 * in thirty days" is a fact about thirty days, and the copy names the number.
 *
 * The window is the retention this site keeps, so it is exactly the
 * evidence this plugin is allowed to hold and never a claim beyond it. Fixed
 * at thirty days it was both: correct on a free site and, on a site keeping
 * ninety, a sentence that called a third of the log the whole of it — on the
 * screen where somebody decides whether to switch off something a monthly
 * integration depends on.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening;

use BetterShield\Database\Schema;
use BetterShield\Support\Tier;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Usage {

	/**
	 * The event that means "something used this", per item.
	 *
	 * Only items where an event genuinely means use. An absent entry means
	 * this class has nothing to say, and saying nothing is correct — the shape
	 * questions the previews already ask are not replaced by this.
	 */
	private const EVIDENCE = array(
		'xmlrpc'                => 'xmlrpc_used',
		'application_passwords' => 'app_password_used',
	);

	/**
	 * What the log knows about this item being used, in sentences, or nothing.
	 *
	 * Read for the options being previewed: refusing application passwords
	 * only for accounts that can manage the site stops only their uses, so
	 * only theirs are counted, and the sentence says it is about them.
	 *
	 * @param array<string, mixed> $options The options the preview is for.
	 * @return string[]
	 */
	public static function lines( string $item, array $options = array() ): array {
		$type = self::EVIDENCE[ $item ] ?? null;

		if ( null === $type ) {
			return array();
		}

		$covered = null;

		if ( 'application_passwords' === $item && Item\ApplicationPasswords::MODE_PRIVILEGED === ( $options['mode'] ?? '' ) ) {
			$covered = static function ( int $user_id ): bool {
				$user = $user_id > 0 ? get_userdata( $user_id ) : false;

				return $user instanceof \WP_User && Item\ApplicationPasswords::is_privileged( $user );
			};
		}

		// How far back the question may be asked: no further than the log
		// reaches, and no further than this plugin has been watching. The
		// sentence below says the number is the log's whole reach, so the
		// number has to be exactly that.
		$window = min( Tier::retention_days(), self::days_watched() );

		// Nothing to say yet. A day of evidence is not a month of evidence,
		// and dressing it as one is the failure this whole class has to avoid.
		if ( $window < 1 ) {
			return array();
		}

		$seen = self::seen( $type, $window, $covered );

		if ( 0 === $seen['count'] && null !== $covered ) {
			return array(
				sprintf(
					/* translators: %d: a number of days. */
					_n(
						'No covered account has used one in the last %d day (as far back as the log goes).',
						'No covered account has used one in the last %d days (as far back as the log goes).',
						$window,
						'bettershield'
					),
					$window
				),
			);
		}

		if ( 0 === $seen['count'] ) {
			return array(
				sprintf(
					/* translators: %d: a number of days. */
					_n(
						'Nothing has used this in the last %d day (as far back as the log goes).',
						'Nothing has used this in the last %d days (as far back as the log goes).',
						$window,
						'bettershield'
					),
					$window
				),
			);
		}

		/*
		 * Hours, not requests. Both listeners take an hourly claim before
		 * recording, so one row means "something happened in this hour" and a
		 * busy endpoint produces the same one row as a quiet one. Reported as
		 * a count of uses, seven hundred rows stood for tens of thousands of
		 * calls — a number this class has no business inventing, on the screen
		 * where somebody decides whether to break their own integration.
		 *
		 * Two phrases rather than one sentence with two numbers in it: the
		 * count and the window pluralize independently, and folding them into
		 * one _n() made the window agree with the count — "5 times in the last
		 * 1 days" on a site watched for a day.
		 */
		$hours = sprintf(
			/* translators: %d: a number of hours. */
			_n( '%d separate hour', '%d separate hours', $seen['count'], 'bettershield' ),
			$seen['count']
		);

		$days = sprintf(
			/* translators: %d: a number of days. */
			_n( '%d day', '%d days', $window, 'bettershield' ),
			$window
		);

		if ( null !== $covered ) {
			return array(
				sprintf(
					/* translators: 1: a number of hours, e.g. "5 separate hours", 2: a number of days, e.g. "30 days", 3: how long ago, e.g. "2 hours". */
					__( 'A covered account used one on %1$s in the last %2$s, most recently %3$s ago. Applying this stops it.', 'bettershield' ),
					$hours,
					$days,
					human_time_diff( $seen['last'] )
				),
			);
		}

		return array(
			sprintf(
				/* translators: 1: a number of hours, e.g. "5 separate hours", 2: a number of days, e.g. "30 days", 3: how long ago, e.g. "2 hours". */
				__( 'Something used this on %1$s in the last %2$s, most recently %3$s ago. Switching this off stops it.', 'bettershield' ),
				$hours,
				$days,
				human_time_diff( $seen['last'] )
			),
		);
	}

	/**
	 * How many days this plugin has been keeping a log at all.
	 *
	 * The same guard the dormant-account check needs and for the same reason:
	 * a tool that has been watching for three days cannot answer a question
	 * about thirty, and answering anyway is how a screen teaches somebody that
	 * it is wrong.
	 */
	private static function days_watched(): int {
		$since = strtotime( (string) get_option( 'bettershield_activated_at', '' ) );

		if ( false === $since ) {
			return 0;
		}

		return (int) floor( ( time() - $since ) / DAY_IN_SECONDS );
	}

	/**
	 * In how many separate clock hours this event happened inside the window,
	 * and when last.
	 *
	 * Hours rather than rows: each credential writes its own row for an hour,
	 * so two used in the same minute were two rows, and read as two hours.
	 * Grouped by account as well, so the uses a mode leaves alone can be left
	 * out of the count.
	 *
	 * @param callable(int): bool|null $covered Which accounts' uses count, or null for all.
	 * @return array{count: int, last: int}
	 */
	private static function seen( string $type, int $days, ?callable $covered = null ): array {
		global $wpdb;

		$since = gmdate( 'Y-m-d H:i:s.v', time() - ( $days * DAY_IN_SECONDS ) );

		// site_id leads the index this read depends on, so a WHERE that omits
		// it cannot seek: the engine falls back to scanning the whole index.
		// Every row this plugin writes carries 0, and the tables are per-blog.
		//
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- one bounded read on the plugin's own table, on a preview somebody asked for; the site predicate is integers assembled by Schema::site_where(), and nothing from a request reaches the string.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT actor_id, SUBSTRING( occurred_at, 1, 13 ) AS hour_of, MAX(occurred_at) AS last FROM %i WHERE ' . Schema::site_where( 'events' ) . ' AND event_type = %s AND occurred_at > %s GROUP BY actor_id, hour_of LIMIT 20000',
				Schema::table( 'events' ),
				$type,
				$since
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$hours = array();
		$last  = 0;
		$asked = array();

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$actor = (int) $row->actor_id;

			if ( null !== $covered ) {
				$asked[ $actor ] = $asked[ $actor ] ?? $covered( $actor );

				if ( ! $asked[ $actor ] ) {
					continue;
				}
			}

			$hours[ (string) $row->hour_of ] = true;
			$last                            = max( $last, (int) strtotime( (string) $row->last . ' UTC' ) );
		}

		return array(
			'count' => count( $hours ),
			'last'  => $last,
		);
	}
}
