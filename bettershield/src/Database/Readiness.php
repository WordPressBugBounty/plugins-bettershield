<?php
/**
 * What the migration proved, in the owner's words.
 *
 * `Schema` records which capabilities its proofs passed and when each last
 * changed. This turns that record into something a person can act on: what
 * the capability is, what stops working while it is unavailable, since when,
 * what the database said, and whether running the migration again could
 * mend it.
 *
 * Every answer here costs one option read and no queries. It is asked on the
 * overview payload and by an audit check, and neither may go to the database
 * to find out whether the database is there.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Database;

use BetterShield\Support\Time;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Readiness {

	/**
	 * How long a capability may be unavailable before it is worth reporting.
	 *
	 * The migration retries hourly on its own, so anything shorter reports a
	 * site that is already mending itself — and the hour is the same hour the
	 * retry waits, so a capability past it is one the automatic attempt has
	 * had its turn at.
	 */
	private const GRACE = HOUR_IN_SECONDS;

	/**
	 * Every capability, ready or not, as the overview payload carries it.
	 *
	 * The whole set rather than the failures alone: a reader that only ever
	 * sees a list when something is wrong cannot tell "nothing is wrong" from
	 * "nothing was asked".
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function report(): array {
		$labels       = self::labels();
		$consequences = self::consequences();
		$rows         = array();

		foreach ( Schema::capabilities() as $capability ) {
			$state = Schema::readiness_for( $capability );

			// Nothing recorded for it: a site that has not run an install
			// since the map arrived. `Schema::ready()` answers such a site
			// from the version, and so does this — there is no state to
			// report and nothing to repair.
			if ( null === $state ) {
				continue;
			}

			$rows[] = array(
				'capability'  => $capability,
				'label'       => $labels[ $capability ] ?? $capability,
				'consequence' => $consequences[ $capability ] ?? '',
				'ready'       => $state['ready'],
				'since'       => Time::utc_iso( $state['stamped_at'] ),
				'reason'      => $state['ready'] ? '' : $state['reason'],
				// The migration creates every one of these, so a repair is an
				// answer to all of them. The field is here so the screen asks
				// rather than assumes: an offer to mend something that cannot
				// be mended is worse than no offer.
				'repairable'  => true,
			);
		}

		return $rows;
	}

	/**
	 * The capabilities that are not available, in the same shape.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function degraded(): array {
		return array_values(
			array_filter(
				self::report(),
				static function ( array $row ): bool {
					return ! $row['ready'];
				}
			)
		);
	}

	/**
	 * A capability that has been unavailable for more than an hour.
	 *
	 * The audit's `test`: evidence when there is something to report, null
	 * when there is not. A capability that went down a minute ago passes —
	 * the migration retries on its own and most of them come back without
	 * anybody being told anything.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function finding(): ?array {
		$cutoff = time() - self::GRACE;
		$late   = array();

		foreach ( self::degraded() as $row ) {
			$since = null === $row['since'] ? false : strtotime( (string) $row['since'] );

			// A record with no readable moment in it is not evidence that an
			// hour has passed, and this check may only say what it knows.
			if ( false === $since || $since > $cutoff ) {
				continue;
			}

			$late[] = $row;
		}

		if ( array() === $late ) {
			return null;
		}

		return array(
			'capabilities' => wp_list_pluck( $late, 'label' ),
			'since'        => (string) $late[0]['since'],
			'reason'       => (string) $late[0]['reason'],
		);
	}

	/**
	 * What each capability is, said the way somebody who did not build it
	 * would say it. These are read on the first screen of the plugin, so they
	 * name the thing the owner would recognize rather than the table.
	 *
	 * @return array<string, string>
	 */
	private static function labels(): array {
		return array(
			'events'             => __( 'The activity log', 'bettershield' ),
			'entry_path'         => __( 'The activity log’s entry-path column', 'bettershield' ),
			'findings'           => __( 'Audit findings', 'bettershield' ),
			'login_attempts'     => __( 'Sign-in attempts', 'bettershield' ),
			'lockouts'           => __( 'Sign-in lockouts', 'bettershield' ),
			'undo'               => __( 'The undo ledger', 'bettershield' ),
			'observed_changes'   => __( 'The undo ledger’s lookup by action', 'bettershield' ),
			'integrity_baseline' => __( 'The file baseline', 'bettershield' ),
			'integrity_changes'  => __( 'Recorded file changes', 'bettershield' ),
			'passkeys'           => __( 'Passkeys', 'bettershield' ),
			'passkey_verification' => __( 'Passkey verification', 'bettershield' ),
			'passkey_discoverable' => __( 'Passkey sign-in without a username', 'bettershield' ),
			'invocation_connection' => __( 'Agent call connections', 'bettershield' ),
			'claims'             => __( 'Work claims', 'bettershield' ),
			'agent_invocations'  => __( 'Agent invocations', 'bettershield' ),
			'incidents'          => __( 'Incidents', 'bettershield' ),
			'incident_evidence'  => __( 'Incident evidence', 'bettershield' ),
			'write_proposals'    => __( 'Agent write proposals', 'bettershield' ),
		);
	}

	/**
	 * What stops working while a capability is unavailable.
	 *
	 * Stated as the consequence rather than the cause. Somebody reading this
	 * is being told a part of the product is not running, and the only useful
	 * next sentence is what they are not getting while it is not.
	 *
	 * @return array<string, string>
	 */
	private static function consequences(): array {
		return array(
			'events'             => __( 'No new entries are logged. Existing entries are kept.', 'bettershield' ),
			'entry_path'         => __( 'New log entries omit each action’s source (AI assistant, REST API, WP-CLI or site code).', 'bettershield' ),
			'findings'           => __( 'Audits are not saved. The score and report do not update.', 'bettershield' ),
			'login_attempts'     => __( 'Failed sign-ins are not counted, so no lockout starts.', 'bettershield' ),
			'lockouts'           => __( 'Sign-in lockouts cannot be started, held or cleared.', 'bettershield' ),
			'undo'               => __( 'Actions with an undo are refused: the undo cannot be recorded.', 'bettershield' ),
			'observed_changes'   => __( 'Looking up an earlier action can be slow.', 'bettershield' ),
			'integrity_baseline' => __( 'With nothing to compare against, changed files are not reported.', 'bettershield' ),
			'integrity_changes'  => __( 'Changed files are noticed but not listed on the Files screen.', 'bettershield' ),
			'passkeys'           => __( 'Passkeys cannot be added or used to sign in.', 'bettershield' ),
			'passkey_verification' => __( 'Passkeys cannot be added or removed. Existing passkeys still work.', 'bettershield' ),
			'passkey_discoverable' => __( 'New passkeys are saved without noting whether they sign in without a username.', 'bettershield' ),
			'invocation_connection' => __( 'Agent calls are recorded without the connection that made them.', 'bettershield' ),
			'claims'             => __( 'Scheduled tasks may run twice or not at all.', 'bettershield' ),
			'agent_invocations'  => __( 'Abilities API calls are not recorded. The agent activity screen stays empty.', 'bettershield' ),
			'incidents'          => __( 'Related records are not joined into incidents.', 'bettershield' ),
			'incident_evidence'  => __( 'The records behind an incident are not kept alongside it.', 'bettershield' ),
			'write_proposals'    => __( 'Protections an agent needs you to confirm cannot be applied. Those it applies directly still work.', 'bettershield' ),
		);
	}
}
