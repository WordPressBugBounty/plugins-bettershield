<?php
/**
 * A daily digest of the activity log, chained to the day before it.
 *
 * The whole spine rests on the log being true. Today it is an ordinary table:
 * anybody with database access — which is to say, anybody who achieved the
 * thing the log exists to record — can delete the rows describing how they got
 * in, and nothing anywhere would show that a row had ever been there. `id` is
 * `AUTO_INCREMENT`, so a gap is not proof either: the pruner makes gaps, and a
 * request that rolls back makes gaps.
 *
 * Sealing each day answers one question about the log: **has anything in the
 * retained window been altered or removed since it was written?** — with "the
 * seal for 3 September covered 412 rows and term 118 no longer matches" as the
 * answer, rather than a vague warning.
 *
 * **A daily seal, deliberately, and not per-row chaining.** The write path
 * does not change: `Writer::flush()` stays exactly one INSERT per request,
 * which `WriterTest` asserts and which the never-slows-your-site pledge
 * depends on. Per-row chaining needs each row to know the previous row's hash,
 * which serializes concurrent requests against a shared value — the opposite
 * of what this plugin promises about busy sites.
 *
 * **This never claims tamper-proof, and the standing rule says so.** Somebody
 * who can write to the database can also rewrite the seals. What a chain buys
 * is that doing so has to be *complete and deliberate* — every later day
 * recomputed — rather than a single DELETE nobody would ever see. That is a
 * meaningful difference and it is not the same as prevention.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Events;

use BetterShield\Database\Pruner;
use BetterShield\Database\Schema;
use BetterShield\Support\Tier;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Seal {

	public const OPTION = 'bettershield_log_seals';

	/**
	 * Where the daily check leaves its answer.
	 *
	 * `verify()` recomputes a digest over every row inside retention, so it
	 * must never run on a request somebody is waiting on. The task looks once
	 * a day and writes down what it found; everything else reads that.
	 */
	public const VERDICT_OPTION = 'bettershield_log_seal_verdict';

	/**
	 * Set when a reseal could not finish, and cleared when one does: the days
	 * it was to take again, or null for every day.
	 *
	 * A reseal runs only after rows have changed under their seals: carried
	 * into a network table with new ids, or rewritten by an erasure. One that
	 * stopped leaves those seals describing rows that are no longer there in
	 * that form, so the daily check finishes it before it checks anything.
	 */
	public const RESEAL_OPTION = 'bettershield_log_reseal_owed';

	/**
	 * Set once the first daily check of a version that signs owed reseals
	 * has looked for one written by a version that did not. See carry_over().
	 */
	public const CARRIED_OPTION = 'bettershield_log_reseal_carried';

	/**
	 * The columns a seal is taken over, by the format named on its record.
	 *
	 * The first format left two of the row's columns out: the address prefix,
	 * which says which network an action came from, and the entry path, which
	 * says which door. Either could be rewritten on a sealed row and the day
	 * still verified intact. Widening the digest changes it for every day ever
	 * sealed, so the column set is versioned on the record rather than
	 * replaced: a seal is checked under the format it was written with, every
	 * new one is written under the current format, and nothing is resealed —
	 * a chain rewritten by an upgrade would look exactly like a chain
	 * rewritten by an intruder. A record that names no format is the first.
	 *
	 * Every field that carries meaning, in a fixed order; the order is part of
	 * the format.
	 */
	private const FORMATS = array(
		1 => array( 'id', 'occurred_at', 'event_type', 'severity', 'actor_type', 'actor_id', 'actor_label', 'object_type', 'object_id', 'context' ),
		2 => array( 'id', 'occurred_at', 'event_type', 'severity', 'actor_type', 'actor_id', 'actor_label', 'object_type', 'object_id', 'context', 'ip_prefix', 'entry_path' ),
	);

	/** The format every seal is written under now. */
	public const FORMAT = 2;

	/**
	 * How many days of seals are kept.
	 *
	 * A seal for a day whose rows the pruner has already removed can never be
	 * verified again, so keeping it past retention would be keeping a question
	 * nothing can answer. Derived from the longest retention the log allows
	 * rather than written down beside it, because the two drifting apart is
	 * precisely the thing this is here to prevent — and it had drifted, to
	 * more than a year of seals against thirty days of rows.
	 *
	 * The week of slack keeps a seal alive for a day whose rows are still
	 * there after a site drops from the longer retention to the shorter one.
	 */
	public static function max_days(): int {
		return Tier::RETENTION_DAYS_MAX + 7;
	}

	/**
	 * Seal what is finished, then check what is sealed, and write the answer
	 * down. Called by the daily task.
	 *
	 * Checking is the half that was missing. The seals were written every day
	 * and read by one WP-CLI command, so a chain that had broken said so only
	 * to somebody who already suspected it and knew to ask — which is not the
	 * reader this exists for.
	 */
	public static function run_and_check(): void {
		self::carry_over();

		/*
		 * A reseal owed by a run that could not finish comes first. Until it
		 * is done the seals describe rows as they were before this plugin
		 * renumbered or rewrote them, and checking them would report each of
		 * those days as altered. While it still cannot finish, the last
		 * verdict stands and the reseal stays owed for the next check.
		 */
		if ( self::reseal_owed() ) {
			if ( self::owed_is_genuine() ) {
				self::reseal_site( self::owed_days(), self::owed_failing() );
			} else {
				self::refuse_owed();
			}
		}

		self::run();

		if ( self::reseal_owed() ) {
			return;
		}

		self::record( self::verify() );
	}

	/**
	 * Write a check's answer down where the finding, the Activity screen and
	 * the alerts read it.
	 *
	 * The daily task and `wp bettershield verify-log` both check; only the
	 * task wrote its answer down, so a broken day found on demand left the
	 * dashboard saying the log was intact until the next daily run (#2087).
	 *
	 * @param array{checked: int, intact: int, broken: array<int, array<string, mixed>>, unverifiable: int, unreadable: string[]} $result What verify() answered.
	 * @return bool Whether the days that do not match differ from the ones stored before.
	 */
	public static function record( array $result ): bool {
		$before = self::broken_days();
		$broken = $result['broken'];

		// A day that could not be read is held at what the last check found:
		// clearing it would close the finding only for the next check to
		// open it again, and tell the owner twice about one day.
		foreach ( $before as $held ) {
			if ( in_array( (string) ( $held['day'] ?? '' ), $result['unreadable'], true ) ) {
				$broken[] = $held;
			}
		}

		update_option(
			self::VERDICT_OPTION,
			array(
				'checked_at'   => time(),
				'broken'       => $broken,
				'intact'       => $result['intact'],
				'unverifiable' => $result['unverifiable'],
			),
			false
		);

		$named = static function ( array $days ): array {
			$keys = array_map( static fn( $day ): string => (string) ( $day['day'] ?? '' ) . '|' . (string) ( $day['reason'] ?? '' ), $days );
			sort( $keys );

			return $keys;
		};

		return $named( $before ) !== $named( $broken );
	}

	/**
	 * The days that did not match, as the last daily check found them. Empty
	 * where the check has not run, which is not the same as nothing being
	 * wrong — the audit check says which it is.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function broken_days(): array {
		$stored = get_option( self::VERDICT_OPTION, array() );

		return is_array( $stored ) && isset( $stored['broken'] ) && is_array( $stored['broken'] )
			? $stored['broken']
			: array();
	}

	/**
	 * How long after a day ends before it is sealed.
	 *
	 * A row is stamped when it is recorded and written when its request
	 * ends. A request that recorded something just before midnight and ended
	 * after the seal ran in another wrote its row into a day already sealed,
	 * and the next check reported that day edited: a tamper finding nobody
	 * caused and nothing clears. An hour outlasts the requests that buffer.
	 */
	public static function grace(): int {
		return max( 0, (int) apply_filters( 'bettershield_seal_grace', HOUR_IN_SECONDS ) );
	}

	/**
	 * Seal every completed day that has not been sealed yet.
	 *
	 * Today is never sealed: rows are still arriving, and a seal that has to
	 * be revised is not a seal. Nor is a day that ended within the grace
	 * above, while a request that began in it may still be writing.
	 */
	public static function run(): void {
		$sealed = self::all();
		$today  = gmdate( 'Y-m-d', time() - self::grace() );

		foreach ( self::unsealed_days( $sealed, $today ) as $day ) {
			$previous = self::last_digest( $sealed );
			$computed = self::compute( $day );

			// Each day is bound to the one sealed before it, so a day that
			// could not be read holds back every day after it until the next
			// pass. Sealed past it, they would be bound to the wrong day.
			if ( false === $computed ) {
				break;
			}

			if ( null === $computed ) {
				continue;
			}

			$sealed[ $day ] = array(
				'rows'      => $computed['rows'],
				'first_id'  => $computed['first_id'],
				'last_id'   => $computed['last_id'],
				'digest'    => self::chain( $previous, $computed['digest'] ),
				'previous'  => $previous,
				'sealed_at' => time(),
				'format'    => self::FORMAT,
			);
		}

		$max = self::max_days();

		if ( count( $sealed ) > $max ) {
			$sealed = array_slice( $sealed, -$max, null, true );
		}

		ksort( $sealed );
		update_option( self::OPTION, $sealed, false );
	}

	/**
	 * Check every seal against the rows that are there now.
	 *
	 * `unreadable` names the days whose rows could not be read just now: they
	 * are neither intact nor broken, and they are not the days retention took.
	 *
	 * @return array{checked: int, intact: int, broken: array<int, array<string, mixed>>, unverifiable: int, unreadable: string[]}
	 */
	public static function verify(): array {
		$sealed   = self::all();
		$previous = '';
		$result   = array(
			'checked'      => 0,
			'intact'       => 0,
			'broken'       => array(),
			'unverifiable' => 0,
			'unreadable'   => array(),
		);

		/*
		 * The list is trimmed to the seal window, so its oldest entry is bound
		 * to a day the window no longer holds. Checking that binding against the
		 * empty string the running digest starts at reported the trim itself as
		 * a rewritten earlier day — a high-severity finding about tampering,
		 * raised against a log nobody had touched, on any site whose pruner is
		 * behind. The first entry examined has nothing in front of it; from the
		 * second on the binding is checked exactly as before, so a rewrite still
		 * cannot hide behind a trim.
		 */
		$first = true;

		// Asked once rather than once a day, and asked live so a retention change
		// moves the line with it. A longer retention moves it back over days
		// the shorter one already pruned, so the line is never earlier than
		// how far the pruner went.
		$floor  = Tier::retention_floor();
		$pruned = Pruner::pruned_through();

		if ( $pruned > $floor ) {
			$floor = $pruned;
		}

		foreach ( $sealed as $day => $record ) {
			++$result['checked'];

			$is_root = $first;
			$first   = false;

			/*
			 * The seal window deliberately outlives retention, so much of the
			 * list is days whose rows the pruner is entitled to have taken. Such
			 * a day can never be checked again, whatever the table currently
			 * holds — and that is the answer the branch below already reaches for
			 * it, after recomputing a digest over a whole day of rows to get
			 * there. On the shorter retention that is most of the list, daily.
			 */
			if ( (string) $day . ' 00:00:00.000' < $floor ) {
				++$result['unverifiable'];
				$previous = (string) $record['digest'];

				continue;
			}

			$computed = self::compute( (string) $day, self::format_of( $record ) );

			// A failed read says nothing about the day: not intact, and not
			// the removal an empty day inside the floor reads as.
			if ( false === $computed ) {
				$result['unreadable'][] = (string) $day;
				$previous               = (string) $record['digest'];

				continue;
			}

			if ( null === $computed || 0 === $computed['rows'] ) {
				/*
				 * An empty day has two causes and they are opposites. Past the
				 * retention floor the pruner took the rows, which is this
				 * plugin doing its job — not tampering, and the honest answer
				 * is that the day can no longer be checked.
				 *
				 * Inside the floor nothing here removes rows, so a day that
				 * was sealed with rows and now has none is the cheapest way to
				 * empty a log: delete the day rather than edit it. Reported as
				 * unverifiable, that read as a shrug at exactly the thing the
				 * seal exists to catch.
				 */
				if ( (string) $day . ' 00:00:00.000' >= $floor ) {
					$result['broken'][] = array(
						'day'         => (string) $day,
						'rows_sealed' => (int) $record['rows'],
						'rows_now'    => 0,
						'reason'      => 'rows_removed',
					);
					$previous           = (string) $record['digest'];

					continue;
				}

				++$result['unverifiable'];
				$previous = (string) $record['digest'];

				continue;
			}

			$expected   = self::chain( (string) $record['previous'], $computed['digest'] );
			$continuous = $is_root || hash_equals( (string) $record['previous'], $previous );

			if ( hash_equals( (string) $record['digest'], $expected ) && $continuous ) {
				++$result['intact'];
				$previous = (string) $record['digest'];

				continue;
			}

			$result['broken'][] = array(
				'day'          => (string) $day,
				'rows_sealed'  => (int) $record['rows'],
				'rows_now'     => (int) $computed['rows'],
				// Which of the two failed says what happened: a row changed,
				// or a whole earlier day was rewritten under this one.
				'reason'       => $continuous ? 'contents_changed' : 'chain_broken',
			);

			$previous = (string) $record['digest'];
		}

		return $result;
	}

	/**
	 * Whether a reseal could not finish and has not been finished since.
	 */
	public static function reseal_owed(): bool {
		return false !== get_option( self::RESEAL_OPTION, false );
	}

	/**
	 * The days an owed reseal is to take again, or null for every day.
	 *
	 * @return string[]|null
	 */
	private static function owed_days(): ?array {
		$owed = get_option( self::RESEAL_OPTION, false );

		return is_array( $owed ) && isset( $owed['days'] ) && is_array( $owed['days'] )
			? array_values( array_map( 'strval', $owed['days'] ) )
			: null;
	}

	/**
	 * The days an owed reseal must not take again: they had failed their seal
	 * before the change it was owed for.
	 *
	 * @return string[]
	 */
	private static function owed_failing(): array {
		$owed = get_option( self::RESEAL_OPTION, false );

		return is_array( $owed ) && isset( $owed['failing'] ) && is_array( $owed['failing'] )
			? array_values( array_map( 'strval', $owed['failing'] ) )
			: array();
	}

	/**
	 * Why an owed reseal was begun, each reason with the days it was for, so
	 * finishing it later says the same — every reason, not only the last.
	 *
	 * @return array<string, string[]|null>
	 */
	private static function owed_reasons(): array {
		$owed    = get_option( self::RESEAL_OPTION, false );
		$reasons = array();

		foreach ( (array) ( is_array( $owed ) ? ( $owed['reasons'] ?? array() ) : array() ) as $reason => $days ) {
			$reasons[ (string) $reason ] = is_array( $days ) ? array_values( array_map( 'strval', $days ) ) : null;
		}

		return $reasons;
	}

	/**
	 * Whether the owed reseal on record is one this plugin wrote.
	 *
	 * The seals exist to show when somebody edited the log in the database,
	 * and an owed reseal is honoured as this plugin's own: written there by
	 * hand, with every day and a reason of "erasure", it had every edited
	 * day sealed again as genuine and reported as the owner's erasure (#1384).
	 * So the record carries a proof keyed on the site's secret keys, which
	 * live in wp-config.php rather than in the database. An entry without a
	 * valid one is not trusted — including one left by a version before the
	 * proof, whose days are then checked like any other, once.
	 */
	private static function owed_is_genuine(): bool {
		$owed = get_option( self::RESEAL_OPTION, false );

		if ( ! is_array( $owed ) || ! is_string( $owed['proof'] ?? null ) ) {
			return false;
		}

		return hash_equals( self::proof( self::owed_days(), self::owed_failing(), self::owed_reasons(), (int) ( $owed['at'] ?? 0 ) ), $owed['proof'] );
	}

	/**
	 * Take over, once, an owed reseal written by a version that did not sign
	 * them.
	 *
	 * Such a record has no proof, so the first check after the update refused
	 * this plugin's own reseal and reported the day it was owed for as edited:
	 * a tamper finding for an erasure the owner made, with nothing to clear
	 * it. Signed here, on the first check this code makes and never again,
	 * it is finished as owed and said as carried over. A version without the
	 * proof honoured any record it found, so nothing is given here that the
	 * update took away; a record without one written after this check is
	 * still refused (#1384).
	 */
	private static function carry_over(): void {
		if ( '1' === get_option( self::CARRIED_OPTION ) ) {
			return;
		}

		update_option( self::CARRIED_OPTION, '1', false );

		$owed = get_option( self::RESEAL_OPTION, false );

		if ( false === $owed || ( is_array( $owed ) && is_string( $owed['proof'] ?? null ) ) ) {
			return;
		}

		// The earliest record was a bare time, owed for every day.
		$days = is_array( $owed ) ? self::owed_days() : null;

		/*
		 * Said only as carried over. A record without a proof says whatever
		 * whoever wrote it put there, and the marker that makes this happen
		 * once is a row in the same database: a reason taken from it would be
		 * told to anything holding a copy of the seals as this plugin's own
		 * (#1384).
		 */
		$reasons = array( 'carried_over_from_update' => $days );

		self::sign(
			$days,
			is_array( $owed ) ? self::owed_failing() : array(),
			$reasons,
			is_array( $owed ) ? (int) ( $owed['at'] ?? time() ) : (int) $owed
		);
	}

	/**
	 * Which sites' owed reseals this plugin wrote, read before the keys their
	 * proofs are made with change: every site of a network, whose key is the
	 * network's, or this one.
	 *
	 * @return int[] The sites to sign again once the keys have changed.
	 */
	public static function owed_before_rekey(): array {
		$sites = is_multisite() ? self::network_sites() : array( get_current_blog_id() );
		$owed  = array();

		foreach ( $sites as $site ) {
			$switched = is_multisite() && get_current_blog_id() !== $site && switch_to_blog( $site );

			try {
				if ( self::reseal_owed() && self::owed_is_genuine() ) {
					$owed[] = $site;
				}
			} finally {
				if ( $switched ) {
					restore_current_blog();
				}
			}
		}

		return $owed;
	}

	/**
	 * Every site of this network, a page at a time. The key a rotation moves
	 * is this network's, so its sites are the ones asked.
	 *
	 * @return int[]
	 */
	private static function network_sites(): array {
		$sites  = array();
		$offset = 0;

		do {
			$page = array_map(
				'intval',
				get_sites(
					array(
						'fields'     => 'ids',
						'number'     => 100,
						'offset'     => $offset,
						'network_id' => get_current_network_id(),
					)
				)
			);

			$sites   = array_merge( $sites, $page );
			$offset += 100;
		} while ( 100 === count( $page ) );

		return $sites;
	}

	/**
	 * Sign those owed reseals again under the keys now in force.
	 *
	 * The proof is keyed on the site's sign-in keys, and rotating them left an
	 * owed reseal this plugin wrote failing its own proof: the next check
	 * refused it, and a day it was owed for was reported edited. Only the
	 * records that were genuine before the change are signed again.
	 *
	 * @param int[] $sites From owed_before_rekey().
	 */
	public static function resign_owed( array $sites ): void {
		foreach ( $sites as $site ) {
			$switched = is_multisite() && get_current_blog_id() !== $site && switch_to_blog( $site );

			try {
				$owed = get_option( self::RESEAL_OPTION, false );

				if ( is_array( $owed ) ) {
					self::sign( self::owed_days(), self::owed_failing(), self::owed_reasons(), (int) ( $owed['at'] ?? 0 ) );
				}
			} finally {
				if ( $switched ) {
					restore_current_blog();
				}
			}
		}
	}

	/**
	 * Write an owed reseal with its proof.
	 *
	 * @param string[]|null                $days
	 * @param string[]                     $failing
	 * @param array<string, string[]|null> $reasons
	 */
	private static function sign( ?array $days, array $failing, array $reasons, int $at ): void {
		update_option(
			self::RESEAL_OPTION,
			array(
				'at'      => $at,
				'days'    => $days,
				'failing' => $failing,
				'reasons' => $reasons,
				'proof'   => self::proof( $days, $failing, $reasons, $at ),
			),
			false
		);
	}

	/**
	 * @param string[]|null                 $days
	 * @param string[]                      $failing
	 * @param array<string, string[]|null>  $reasons
	 */
	private static function proof( ?array $days, array $failing, array $reasons, int $at ): string {
		ksort( $reasons );

		return hash_hmac( 'sha256', (string) wp_json_encode( array( $days, array_values( $failing ), $reasons, $at ) ), wp_salt( 'auth' ) . '|bettershield_log_reseal' );
	}

	/**
	 * Drop an owed reseal this plugin did not write, and say so. Its days are
	 * then checked as they stand, so a day edited in the database is reported
	 * as changed rather than sealed again as genuine.
	 */
	private static function refuse_owed(): void {
		$owed    = get_option( self::RESEAL_OPTION, false );
		$days    = self::owed_days();
		$reasons = array_keys( self::owed_reasons() );

		// A record from before the proof named one reason.
		if ( is_array( $owed ) && is_string( $owed['reason'] ?? null ) && '' !== $owed['reason'] ) {
			$reasons[] = $owed['reason'];
		}

		delete_option( self::RESEAL_OPTION );

		Writer::instance()->record(
			'log_reseal_refused',
			Writer::SEVERITY_HIGH,
			array(
				'object_type' => 'log',
				'object_id'   => 'seals',
				'context'     => array(
					'reasons' => array_values( array_unique( $reasons ) ),
					'days'    => null === $days ? 'all' : count( $days ),
				),
			)
		);
	}

	/**
	 * Record a reseal that could not finish, joined with any already owed.
	 * Either one covering every day makes the whole debt every day. The days
	 * that had failed before are kept with it, so finishing it later cannot
	 * take them again either.
	 *
	 * @param string[]|null                $days    The days to take again, or null for every day.
	 * @param string[]                     $failing The days never to take again.
	 * @param array<string, string[]|null> $reasons Why the rows changed, each reason with its days.
	 */
	private static function owe( ?array $days, array $failing = array(), array $reasons = array() ): void {
		if ( self::reseal_owed() && self::owed_is_genuine() ) {
			$earlier = self::owed_days();
			$days    = null === $earlier || null === $days ? null : array_values( array_unique( array_merge( $earlier, $days ) ) );
			$failing = array_values( array_unique( array_merge( self::owed_failing(), $failing ) ) );
			$reasons = self::join_reasons( self::owed_reasons(), $reasons );
		}

		$days    = null === $days ? null : array_values( array_map( 'strval', $days ) );
		$failing = array_values( array_map( 'strval', $failing ) );

		self::sign( $days, $failing, $reasons, time() );
	}

	/**
	 * Two sets of reasons as one, each reason keeping every day it was for:
	 * a reason never takes another's place (#1384).
	 *
	 * @param array<string, string[]|null> $a
	 * @param array<string, string[]|null> $b
	 * @return array<string, string[]|null>
	 */
	private static function join_reasons( array $a, array $b ): array {
		foreach ( $b as $reason => $days ) {
			if ( ! array_key_exists( $reason, $a ) ) {
				$a[ $reason ] = $days;
				continue;
			}

			$a[ $reason ] = null === $a[ $reason ] || null === $days ? null : array_values( array_unique( array_merge( $a[ $reason ], $days ) ) );
		}

		return $a;
	}

	/**
	 * Which of these sealed days fail their seal now: their rows changed or
	 * went, or the day before them is not the one they were bound to. Asked
	 * before this plugin rewrites rows on them, so the reseal that follows
	 * takes again only days that were genuine before it — one already failing
	 * keeps failing, rather than being sealed as genuine with the rewrite.
	 *
	 * A day that cannot be read is counted as failing: nothing here vouches
	 * for a day it could not check. A day not sealed, or past what retention
	 * keeps, has no seal to fail.
	 *
	 * @param string[] $days
	 * @return string[]
	 */
	public static function failing_days( array $days ): array {
		$sealed = self::all();
		$asked  = array_flip( array_map( 'strval', $days ) );
		$floor  = Tier::retention_floor();
		$pruned = Pruner::pruned_through();

		if ( $pruned > $floor ) {
			$floor = $pruned;
		}

		$failing  = array();
		$previous = null;

		foreach ( $sealed as $day => $record ) {
			$day    = (string) $day;
			$before = $previous;

			$previous = (string) ( $record['digest'] ?? '' );

			if ( ! isset( $asked[ $day ] ) || $day . ' 00:00:00.000' < $floor ) {
				continue;
			}

			if ( null !== $before && ! hash_equals( (string) ( $record['previous'] ?? '' ), $before ) ) {
				$failing[] = $day;
				continue;
			}

			$computed = self::compute( $day, self::format_of( $record ) );

			if ( false === $computed || null === $computed || 0 === $computed['rows'] || ! hash_equals( (string) $record['digest'], self::chain( (string) $record['previous'], $computed['digest'] ) ) ) {
				$failing[] = $day;
			}
		}

		return $failing;
	}

	/**
	 * @return array<string, array<string, mixed>>
	 */
	public static function all(): array {
		$stored = get_option( self::OPTION, array() );

		return is_array( $stored ) ? $stored : array();
	}

	/**
	 * Take the seals again after this plugin changed rows under them.
	 *
	 * With no days named, every day is taken again over the rows it can see
	 * now. That is for one situation only: the site's rows have been carried
	 * into a table they share with the rest of a network, which gives every one
	 * of them a new `id` — and `id` is part of what each day's digest is taken
	 * over. Left alone, every sealed day of this site would report itself as
	 * rewritten, which is exactly the alarm the seal exists to raise and
	 * exactly the wrong thing to raise it about.
	 *
	 * With days named, the days an erasure rewrote, only those are taken again.
	 * Every day after the first of them is bound to the day before it as that
	 * day now stands, but only once its own rows have been checked against its
	 * seal: one that changed since, and not by this, keeps its digest so the
	 * check reports it. Taking it again would seal somebody else's edit as
	 * genuine.
	 *
	 * Whole or not at all: each day is bound to the one before it, so a list
	 * rechained halfway reports the boundary as a broken chain. The work is the
	 * same shape and size the daily check already does — one indexed range read
	 * per sealed day — so it is done in one pass, and the caller decides
	 * whether there is room for it before starting.
	 *
	 * A day whose rows retention has already taken cannot be recomputed. Its
	 * binding is rewritten so the days after it still chain, and it goes on
	 * reading as unverifiable, which is what it was before. A day that cannot
	 * be read just now leaves every seal as it was, rather than rechaining
	 * over what part of it was read, and leaves the reseal owed: the rows
	 * have already changed, so the daily check finishes it before it checks.
	 *
	 * A day named in `$failing` had failed its seal before the change this
	 * reseal follows, and is never taken again: its digest stays, so the check
	 * goes on reporting it rather than reading it as genuine.
	 *
	 * A reseal that finishes says so on `bettershield_log_resealed`, with the
	 * reason it was asked for. Anything holding a copy of the seals somewhere
	 * else has to hear it: from outside, a chain this plugin rewrote looks
	 * exactly like one somebody else rewrote.
	 *
	 * @param string[]|null $changed The days rewritten, or null for every day.
	 * @param string[]      $failing The days that failed their seal before.
	 * @param string        $reason  Why the rows changed: `erasure` or `network_migration`.
	 * @return array{days: int, recomputed: int}
	 */
	public static function reseal_site( ?array $changed = null, array $failing = array(), string $reason = '' ): array {
		/*
		 * A reseal still owed is taken with this one. Finishing clears the
		 * debt, so finishing without the days owed dropped them unresealed,
		 * and the next check reported each as altered. Either one covering
		 * every day makes this one every day, and a day the owed one was to
		 * leave failing stays failing.
		 */
		$reasons = '' === $reason ? array() : array( $reason => null === $changed ? null : array_values( array_map( 'strval', $changed ) ) );

		if ( self::reseal_owed() ) {
			// Only one this plugin wrote is taken with it. One written by
			// hand would otherwise ride along with a genuine erasure and seal
			// every edited day as the erasure's (#1384).
			if ( self::owed_is_genuine() ) {
				$owed    = self::owed_days();
				$changed = null === $owed || null === $changed ? null : array_values( array_unique( array_merge( $owed, array_map( 'strval', $changed ) ) ) );
				$failing = array_values( array_unique( array_merge( self::owed_failing(), array_map( 'strval', $failing ) ) ) );
				$reasons = self::join_reasons( self::owed_reasons(), $reasons );
			} else {
				self::refuse_owed();
			}
		}

		$sealed = self::all();
		$days   = array_keys( $sealed );
		$named  = null === $changed ? null : array_flip( array_map( 'strval', $changed ) );
		$failed = array_flip( array_map( 'strval', $failing ) );

		$previous   = '';
		$recomputed = 0;

		foreach ( $days as $day ) {
			$day         = (string) $day;
			$record      = $sealed[ $day ];
			$taken_again = null === $named || isset( $named[ $day ] );

			// One that had already failed is left exactly as it is, binding
			// and digest, so the check reports it as it would have before.
			if ( isset( $failed[ $day ] ) ) {
				$previous = (string) ( $record['digest'] ?? '' );
				continue;
			}

			// Before the first day taken again, every binding still holds.
			if ( ! $taken_again && hash_equals( (string) ( $record['previous'] ?? '' ), $previous ) ) {
				$previous = (string) ( $record['digest'] ?? '' );
				continue;
			}

			$computed = self::compute( $day, $taken_again ? self::FORMAT : self::format_of( $record ) );

			if ( false === $computed ) {
				self::owe( null === $named ? null : array_map( 'strval', array_keys( $named ) ), array_map( 'strval', array_keys( $failed ) ), $reasons );

				return array(
					'days'       => count( $days ),
					'recomputed' => 0,
				);
			}

			if ( null === $computed ) {
				$sealed[ $day ]['previous'] = $previous;
				$sealed[ $day ]['digest']   = self::chain( $previous, '' );
			} elseif ( $taken_again ) {
				$sealed[ $day ] = array(
					'rows'        => $computed['rows'],
					'first_id'    => $computed['first_id'],
					'last_id'     => $computed['last_id'],
					'digest'      => self::chain( $previous, $computed['digest'] ),
					'previous'    => $previous,
					'sealed_at'   => (int) ( $record['sealed_at'] ?? time() ),
					// Kept apart from sealed_at: when the day was first closed
					// out is a different fact from when its digest was taken
					// again over the same rows in a new place.
					'resealed_at' => time(),
					// Taken again, so taken under the current format.
					'format'      => self::FORMAT,
				);

				++$recomputed;
			} elseif ( hash_equals( (string) $record['digest'], self::chain( (string) $record['previous'], $computed['digest'] ) ) ) {
				// Unchanged since it was sealed: bound to the day before it as
				// that day now stands.
				$sealed[ $day ]['previous'] = $previous;
				$sealed[ $day ]['digest']   = self::chain( $previous, $computed['digest'] );
			} else {
				// Changed since it was sealed, and not by this. Its binding
				// moves so the chain still runs through it, and its digest
				// stays, so the check reports its contents changed.
				$sealed[ $day ]['previous'] = $previous;
			}

			$previous = (string) $sealed[ $day ]['digest'];
		}

		ksort( $sealed );
		update_option( self::OPTION, $sealed, false );
		delete_option( self::RESEAL_OPTION );

		$result = array(
			'days'       => count( $days ),
			'recomputed' => $recomputed,
		);

		/**
		 * Fires when the seals have been taken again because this plugin
		 * changed rows under them.
		 *
		 * A copy of the seals kept anywhere else stops matching from the first
		 * day taken again, so whatever keeps one hears it here, with the
		 * reason, rather than finding out later and reading it as tampering.
		 *
		 * @param string        $reason  Why the rows changed: `erasure`, `network_migration`, or '' when no caller said.
		 * @param string[]|null $changed The days whose rows changed, or null for every day.
		 * @param array         $result  `days` sealed and `recomputed` over their rows.
		 */
		$all_days = null === $named ? null : array_map( 'strval', array_keys( $named ) );

		// Once for each reason, with the days that reason was for: a pending
		// reason is never overwritten by the next one (#1384). A reseal no
		// caller named still says it happened, with no reason.
		foreach ( array() === $reasons ? array( '' => $all_days ) : $reasons as $why => $days ) {
			// The record of it, so a reason given to anything outside has a
			// row on this site to answer to.
			Writer::instance()->record(
				'log_resealed',
				Writer::SEVERITY_MEDIUM,
				array(
					'object_type' => 'log',
					'object_id'   => 'seals',
					'context'     => array(
						'reason'     => (string) $why,
						'days'       => null === $days ? 'all' : $days,
						'recomputed' => $recomputed,
					),
				)
			);

			do_action( 'bettershield_log_resealed', (string) $why, $days, $result );
		}

		return $result;
	}

	/**
	 * Whether a day's digest kept somewhere else still describes the rows
	 * this site holds for that day.
	 *
	 * The digest compared is the copy, never this site's own record of it: a
	 * value the site stored itself proves nothing about the site, because
	 * whoever could rewrite the rows could rewrite the seal beside them. So
	 * the day's rows are read as they stand now and chained to the day before
	 * as the site records it, and the result is held up against the copy. A
	 * match says the day's rows, and the chain this site binds them to, are
	 * what they were when the copy was taken.
	 *
	 * One day's rows, read the way the daily check reads them, so it is fit
	 * for a request a person made and not for a loop over the whole log.
	 *
	 * @param string $day    The day, `Y-m-d`, in UTC.
	 * @param string $digest The day's digest as it was kept elsewhere.
	 * @return string `matches`, `differs`, `unverifiable` (no seal for the day,
	 *                or its rows are past retention) or `unreadable` (the
	 *                rows could not be read just now).
	 */
	public static function compare( string $day, string $digest ): string {
		$sealed = self::all();
		$floor  = Tier::retention_floor();
		$pruned = Pruner::pruned_through();

		if ( $pruned > $floor ) {
			$floor = $pruned;
		}

		if ( $day . ' 00:00:00.000' < $floor ) {
			return 'unverifiable';
		}

		// The digest being compared came from this site's own seal of that
		// day. Inside retention, a seal that is no longer here was removed,
		// which is a difference, not a question nothing can answer.
		if ( ! isset( $sealed[ $day ] ) || ! is_array( $sealed[ $day ] ) ) {
			return $day < gmdate( 'Y-m-d' ) ? 'differs' : 'unverifiable';
		}

		$record   = $sealed[ $day ];
		$computed = self::compute( $day, self::format_of( $record ) );

		if ( false === $computed ) {
			return 'unreadable';
		}

		// Sealed with rows and holding none inside retention: removed, which
		// the daily check reports the same way.
		if ( null === $computed || 0 === $computed['rows'] ) {
			return 'differs';
		}

		$now = self::chain( (string) ( $record['previous'] ?? '' ), $computed['digest'] );

		return hash_equals( $now, strtolower( trim( $digest ) ) ) ? 'matches' : 'differs';
	}

	/**
	 * The rows this site seals.
	 *
	 * Named in one place because both statements have to agree: a seal
	 * computed over one set of rows and checked over another would report
	 * tampering on a network the moment a neighbor wrote anything.
	 */
	private static function scope(): string {
		return Schema::site_where( 'events' );
	}

	/**
	 * The format a stored record was written under.
	 *
	 * @param array<string, mixed> $record
	 */
	private static function format_of( array $record ): int {
		$format = (int) ( $record['format'] ?? 1 );

		return isset( self::FORMATS[ $format ] ) ? $format : self::FORMAT;
	}

	/**
	 * How many of a day's rows are read at once.
	 *
	 * A day holds as many rows as the site was busy, and nothing about a log
	 * bounds that. Sealing is not only the daily task's work either — the same
	 * pass runs inline behind an admin page where the schedule has not fired —
	 * so a whole day arriving in one result set is somebody's request holding
	 * all of it.
	 */
	public const BATCH = 500;

	private static function batch(): int {
		/**
		 * Filters how many of a day's rows are read at once while sealing.
		 *
		 * The digest is fed one row at a time in `id` order, so it is the same
		 * value whatever this is; only how much of a day is resident at once
		 * changes.
		 *
		 * @param int $rows Rows read per statement.
		 */
		return max( 1, (int) apply_filters( 'bettershield_seal_batch', self::BATCH ) );
	}

	/**
	 * The digest of one day's rows, in `id` order, over the columns the named
	 * format covers.
	 *
	 * Read in `id`-ordered batches and hashed as each arrives, so the answer
	 * does not depend on the batch size — only on the rows and their order.
	 * That equality is what lets the size change at all: a digest that moved
	 * with it would make every day sealed before the change read as a day
	 * somebody had rewritten.
	 *
	 * Null for a day with no rows. False when a read failed: a failed read
	 * comes back empty, which is also how a day ends, and taken for the end
	 * it made the rows read before it the whole day.
	 *
	 * @return array{rows: int, first_id: int, last_id: int, digest: string}|false|null
	 */
	private static function compute( string $day, int $format = self::FORMAT ): array|false|null {
		global $wpdb;

		$columns = self::FORMATS[ $format ] ?? self::FORMATS[ self::FORMAT ];
		$batch   = self::batch();
		$next    = gmdate( 'Y-m-d', (int) strtotime( $day . ' UTC' ) + DAY_IN_SECONDS ) . ' 00:00:00.000';

		$running  = hash_init( 'sha256' );
		$counted  = 0;
		$first_id = 0;
		$after    = 0;

		while ( true ) {
			// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the plugin's own log, read once per day by a scheduled task; the column list is this class's own constant, the site predicate is integers assembled by Schema::site_where(), and nothing from a request reaches the string.
			$rows = (array) $wpdb->get_results(
				$wpdb->prepare(
					'SELECT ' . implode( ', ', $columns ) . '
					 FROM %i
					 WHERE ' . self::scope() . ' AND occurred_at >= %s AND occurred_at < %s AND id > %d
					 ORDER BY id ASC
					 LIMIT %d',
					Schema::table( 'events' ),
					$day . ' 00:00:00.000',
					// Half-open on the next midnight: the column carries
					// milliseconds, so a strict bound at 23:59:59.999 excluded
					// a representable instant — one unsealed millisecond a day
					// that "verified intact" was quietly wrong about.
					$next,
					$after,
					$batch
				)
			);
			// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

			if ( '' !== $wpdb->last_error ) {
				return false;
			}

			$last = $after;

			foreach ( $rows as $row ) {
				// Verification recomputes rather than comparing against
				// anything stored per row, so the columns and their order have
				// to be the ones the record was written with — which is what
				// the format names.
				$values = array();

				foreach ( $columns as $column ) {
					$values[] = (string) $row->$column;
				}

				hash_update( $running, implode( "\x1f", $values ) . "\x1e" );

				$last = (int) $row->id;

				if ( 0 === $counted ) {
					$first_id = $last;
				}

				++$counted;
			}

			/*
			 * `id` leads every format, so the cursor always moves; comparing it
			 * is what keeps a format that ever stopped naming the column from
			 * turning a scheduled task into a statement it repeats forever.
			 */
			if ( count( $rows ) < $batch || $last <= $after ) {
				break;
			}

			$after = $last;
		}

		if ( 0 === $counted ) {
			return null;
		}

		return array(
			'rows'     => $counted,
			'first_id' => $first_id,
			'last_id'  => $last,
			'digest'   => hash_final( $running ),
		);
	}

	/**
	 * One day's digest, bound to the day before it.
	 *
	 * The binding is what makes a single quiet deletion insufficient: changing
	 * one day changes its digest, which every later day was computed from.
	 */
	private static function chain( string $previous, string $digest ): string {
		return hash( 'sha256', $previous . '|' . $digest );
	}

	/**
	 * @param array<string, array<string, mixed>> $sealed
	 */
	private static function last_digest( array $sealed ): string {
		if ( array() === $sealed ) {
			return '';
		}

		$last = end( $sealed );

		return (string) ( $last['digest'] ?? '' );
	}

	/**
	 * Completed days with rows in them that nothing has sealed yet.
	 *
	 * @param array<string, array<string, mixed>> $sealed
	 * @return string[]
	 */
	private static function unsealed_days( array $sealed, string $today ): array {
		global $wpdb;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- as above.
		$days = (array) $wpdb->get_col(
			$wpdb->prepare(
				'SELECT DISTINCT DATE(occurred_at) FROM %i WHERE ' . self::scope() . ' AND occurred_at < %s ORDER BY 1 ASC',
				Schema::table( 'events' ),
				$today . ' 00:00:00.000'
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$out = array();

		foreach ( $days as $day ) {
			$day = (string) $day;

			if ( '' !== $day && ! isset( $sealed[ $day ] ) ) {
				$out[] = $day;
			}
		}

		return $out;
	}
}
