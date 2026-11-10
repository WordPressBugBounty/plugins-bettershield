<?php
/**
 * REST data for the Overview screen.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Audit\Auditor;
use BetterShield\Capabilities;
use BetterShield\Database\Readiness;
use BetterShield\Database\Schema;
use BetterShield\Events\SinceLastVisit;
use BetterShield\Events\Writer;
use BetterShield\Onboarding\QuickSetup;
use BetterShield\Onboarding\Release;
use BetterShield\Onboarding\Usage;
use BetterShield\Support\Claim;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class OverviewController {

	/** How many times the migration may be run again from the button in an hour. */
	private const REPAIRS_PER_HOUR = 6;

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	public function register_routes(): void {
		register_rest_route(
			'bettershield/v1',
			'/overview',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static function (): \WP_REST_Response {
					/*
					 * Both merged here rather than inside
					 * `Auditor::overview()`, which is shared with the read
					 * ability, the dashboard widget and the diagnostics
					 * report. Each belongs to a person looking at a screen:
					 * the unread-changes block advances that person's stamp,
					 * and the release panel is put away per account — so a
					 * shared payload carrying either answers one administrator
					 * differently from the next, and answers the weekly digest
					 * with a panel cron can never dismiss.
					 *
					 * The route answers any credential that may read the
					 * posture, so only a signed-in browser session counts as
					 * the visit: an application password polling it is handed
					 * the block and consumes nothing.
					 */
					/*
					 * The block is activity-log rows, with the actors' names, and
					 * a reader who may see the posture but not the log is refused
					 * by every activity route. They get none, and their visit is
					 * not consumed by a request that showed them nothing.
					 */
					$since = current_user_can( Capabilities::READ_ACTIVITY )
						? SinceLastVisit::block( get_current_user_id(), true === Permissions::interactive() )
						: null;

					return rest_ensure_response(
						array_merge(
							self::screen_payload(),
							array( 'since_last_visit' => $since )
						)
					);
				},
				'permission_callback' => static function (): bool {
					return current_user_can( Capabilities::READ_POSTURE );
				},
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/posture',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					return self::posture( (string) $request->get_param( 'since' ) );
				},
				'permission_callback' => static function (): bool {
					return current_user_can( Capabilities::READ_POSTURE );
				},
				'args'                => array(
					'since' => array(
						'type'              => 'string',
						'default'           => '',
						'pattern'           => '^(|[0-9]{4}-[0-9]{2}-[0-9]{2})$',
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'rest_sanitize_request_arg',
					),
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/audit',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function (): \WP_REST_Response {
					// A person pressed Run audit: a file they removed after the
					// weekly sweep listed it is asked about again first, and a
					// server that does not read the quarantine's deny rule is
					// asked whether it serves a kept copy.
					\BetterShield\Audit\ExposedArtifacts::recheck_exposed();
					\BetterShield\Files\Quarantine::ask_the_server();
					\BetterShield\Hardening\ServerRules::ask();

					Auditor::run();

					// The screen replaces its whole payload with this answer,
					// so it carries what the screen draws. The unread-changes
					// block is deliberately not here: pressing a button is not
					// the moment to consume somebody's unread changes.
					return rest_ensure_response( self::screen_payload() );
				},
				'permission_callback' => static function (): bool {
					return current_user_can( Capabilities::MANAGE );
				},
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/schema/repair',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function () {
					return self::repair_schema();
				},
				/*
				 * The capability alone, which is the side of the rule a repair
				 * belongs on: it creates what a migration failed to create and
				 * can take nothing away, so it is a change that only adds — the
				 * same reading that leaves applying a protection open to a
				 * token. A provisioning script that finishes a migration a
				 * shared host interrupted is doing the thing this plugin exists
				 * for, and the alternative would put the button behind a
				 * password prompt this screen has nowhere to draw.
				 */
				'permission_callback' => array( Permissions::class, 'manage' ),
			)
		);
	}

	/**
	 * The days a comparison can start from, and what changed since one of
	 * them: the one asked for, or when none was, the latest recorded day at
	 * least a week old, else the oldest there is.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	private static function posture( string $since ) {
		$days = Auditor::posture_days();

		if ( '' === $since && array() !== $days ) {
			$week  = gmdate( 'Y-m-d', time() - WEEK_IN_SECONDS );
			$since = $days[0]['day'];

			foreach ( $days as $day ) {
				if ( $day['day'] <= $week ) {
					$since = $day['day'];
				}
			}
		}

		$diff = '' === $since ? null : Auditor::posture_since( $since );

		if ( is_wp_error( $diff ) ) {
			return $diff;
		}

		return rest_ensure_response(
			array(
				'days' => $days,
				'diff' => $diff,
			)
		);
	}

	/**
	 * Run the migration again, and say what it managed.
	 *
	 * Additive in both directions: the installer creates what is missing and
	 * leaves what is there, so there is nothing to write to the undo ledger
	 * and nothing a second press could make worse. What it cannot do is
	 * promise success — a database that refused to create a table an hour ago
	 * may refuse again, and the answer then is the refusal itself rather than
	 * a quiet failure the owner has to infer from an unchanged screen.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	private static function repair_schema() {
		/*
		 * The capability again, inside the callback. The permission callback
		 * is the gate; this is the invariant, and it holds wherever the route
		 * is reached from.
		 */
		if ( ! current_user_can( Capabilities::MANAGE ) ) {
			return new \WP_Error(
				'bettershield_cannot_manage',
				__( 'You do not have permission to run this.', 'bettershield' ),
				array( 'status' => 403 )
			);
		}

		/*
		 * A ceiling of its own, because this route removes the two bounds that
		 * hold everywhere else: `retry_migration()` clears the hourly back-off
		 * and the per-request record, which is the whole point of a person
		 * pressing the button and is no answer at all to a loop. The migration
		 * introspects every table this plugin owns each time it runs, and the
		 * capability alone reaches this — so an application password does too.
		 * Six an hour is more than a person pressing a button ever needs, and
		 * more than a provisioning script needs either.
		 */
		$pressed = Claim::bump_or_fail( 'schema_repair', HOUR_IN_SECONDS );

		/*
		 * And the one place in this plugin where a counter that cannot be read
		 * lets the request through rather than refusing it. Everywhere else a
		 * missing count means a ceiling that is not holding, so the safe answer
		 * is no. Here the count lives in a table this route exists to put back:
		 * refusing because the claims table is missing would take away the only
		 * remedy for the claims table being missing.
		 */
		if ( null !== $pressed && $pressed > self::REPAIRS_PER_HOUR ) {
			return new \WP_Error(
				'bettershield_rate_limited',
				__( 'There were too many requests in the last hour. Try again later.', 'bettershield' ),
				array( 'status' => 429 )
			);
		}

		$before = Readiness::degraded();

		Schema::retry_migration();

		$after = Readiness::degraded();

		// Named rather than counted: which capability is still down is what
		// the owner is told, and what the log has to carry a week later.
		$still = wp_list_pluck( $after, 'capability' );
		$fixed = array_values( array_diff( wp_list_pluck( $before, 'capability' ), $still ) );

		// The reason as the database gave it, which is the only part of this
		// that is not ours to phrase.
		$reason = array() === $after ? '' : (string) $after[0]['reason'];

		Writer::instance()->record(
			array() === $after ? 'schema_repaired' : 'schema_repair_failed',
			array() === $after ? Writer::SEVERITY_INFO : Writer::SEVERITY_MEDIUM,
			array(
				'actor_type'  => 'user',
				'actor_id'    => get_current_user_id(),
				'object_type' => 'schema',
				'context'     => array(
					'repaired'  => $fixed,
					'unusable'  => $still,
					'reason'    => $reason,
				),
			)
		);

		return rest_ensure_response(
			array(
				'repaired'  => array() === $after,
				'readiness' => Readiness::report(),
				'reason'    => '' === $reason ? null : $reason,
			)
		);
	}

	/**
	 * Audit again after a save that changed what a check reads, and answer
	 * with what the audit found: the same run and the same payload an
	 * applied hardening item answers with, so the finding the save closed is
	 * closed in the answer rather than on the next Run audit.
	 *
	 * @return array{overview: array<string, mixed>, findings: array<int, array<string, mixed>>}
	 */
	public static function reaudited(): array {
		Auditor::run();

		return array(
			'overview' => self::screen_payload(),
			'findings' => Auditor::findings_for_reader(),
		);
	}

	/**
	 * The posture payload plus what only a screen shows.
	 *
	 * Also what an action on the app answers with, so the screen's copy of
	 * the overview keeps its side panels and release note and shows the
	 * change just made. The unread-changes block is never part of it: only
	 * a visit may consume it, and the store keeps the one it has.
	 *
	 * @return array<string, mixed>
	 */
	public static function screen_payload(): array {
		/*
		 * The writer holds a request's events until the request ends, and
		 * the receipts and the activity panel are counted from the table. An
		 * action answering with this payload (Run audit, Apply fix, Undo)
		 * would otherwise be the one thing its own answer left out.
		 */
		Writer::instance()->flush();

		return array_merge(
			Auditor::overview(),
			// What the last update added, once, for whoever has not seen it.
			array( 'release' => Release::panel() ),
			// The side panels: three summaries, each of a document with a
			// screen of its own.
			array( 'panels' => self::panels() ),
			// The two things the Quick Setup leaves behind on the dashboard:
			// the card offering it to a site it never opened for, and the one
			// reminder a skipped usage question earns. Both are for whoever
			// may act on them, and nobody else.
			array( 'onboarding' => self::onboarding() ),
			// Whether the score is waiting for the first file check.
			array( 'first_scan' => \BetterShield\Integrity\FirstScan::report() ),
			// Which security plugin does which job, where there is another
			// one: said on the dashboard, not only in the setup that asked.
			array( 'neighbors' => \BetterShield\Onboarding\Coexistence::split( QuickSetup::state()['coexistence'] ) ),
			// Whether this site is where it was, and if not, the question.
			array( 'site_identity' => current_user_can( Capabilities::MANAGE ) ? \BetterShield\Onboarding\SiteIdentity::overview() : null ),
			// Whether these screens are in the reader's language, for
			// Settings to say so: null for a reader who works in English.
			array( 'language' => \BetterShield\Support\Language::report() )
		);
	}

	/**
	 * @return array{setup: ?array{url: string, resume: bool}, rerun: ?string, usage_reminder: bool}
	 */
	private static function onboarding(): array {
		if ( ! current_user_can( Capabilities::MANAGE ) ) {
			return array(
				'setup'          => null,
				'rerun'          => null,
				'usage_reminder' => false,
			);
		}

		$state = QuickSetup::state();

		return array(
			'setup'          => QuickSetup::offer_due()
				? array(
					'url'    => QuickSetup::url(),
					// Somebody who stopped part way is offered the rest of it.
					'resume' => 'pending' === $state['status'] && '' !== $state['step'] && 'welcome' !== $state['step'],
				)
				: null,
			// A finished setup is out of the menu; Settings links to it here.
			'rerun'          => QuickSetup::is_done() ? QuickSetup::url() : null,
			'usage_reminder' => Usage::reminder_due(),
		);
	}

	/**
	 * The three summaries the Overview shows beside the score.
	 *
	 * Counts and a handful of rows, never a document. Each of these has a
	 * screen of its own that serves the whole thing, and the endpoints behind
	 * those screens are not summaries: the hardening one describes every item
	 * and probes each for conflicts, and the file one pages two hundred
	 * changes. Reading either from here would put that work on the screen
	 * shown 95% of the time, to draw four lines in a sidebar.
	 *
	 * So each is assembled here from the cheap half of its own source — an
	 * option read per protection, one grouped count over the change table,
	 * one indexed page of the log — and each is gated by the capability its
	 * own screen is gated by. `/overview` answers to READ_POSTURE, which is
	 * the weakest of the three: a reader who may see the score may not see
	 * the activity log, and a panel that leaked it would be the endpoint
	 * granting what the capability withholds. A panel a reader may not have
	 * is null rather than empty, so the screen can tell "not for you" from
	 * "nothing to show".
	 *
	 * @return array<string, mixed>
	 */
	private static function panels(): array {
		return array(
			'protection' => self::protection_panel(),
			'files'      => self::files_panel(),
			'activity'   => self::activity_panel(),
			'recent'     => self::recent_panel(),
			'unusual'    => self::unusual_panel(),
		);
	}

	/**
	 * What was applied from this screen lately, each still with its undo.
	 *
	 * The hardening family alone, and deliberately: those are the actions
	 * this screen's own buttons produce, and they are the ones it can offer a
	 * working undo for — one press of `revertItem()`, the same call the fix
	 * rows make. The ledger holds other families whose revert paths run
	 * through other endpoints, and a row offering an undo the screen cannot
	 * perform would be worse than no row at all.
	 *
	 * An entry already reverted stays in the list and says so. "You applied
	 * this and then put it back" is the history somebody is looking for here,
	 * and dropping the second half of it makes the first half look like it
	 * never happened.
	 *
	 * @return array<string, mixed>|null
	 */
	private static function recent_panel(): ?array {
		if ( ! current_user_can( Capabilities::MANAGE ) ) {
			return null;
		}

		$definitions = \BetterShield\Hardening\Items::all();
		$manager     = \BetterShield\Hardening\Manager::instance();
		$entries     = array();

		foreach ( \BetterShield\Undo\Ledger::recent( 'harden_', 8 ) as $row ) {
			$item = substr( $row['action_key'], strlen( 'harden_' ) );

			// A key from a removed item, or one of the `_action` variants that
			// belongs to a control rather than to the item itself. Neither has
			// a row to draw.
			if ( ! isset( $definitions[ $item ] ) ) {
				continue;
			}

			$state = $manager->item_state( $item );

			$entries[] = array(
				'item'       => $item,
				'label'      => (string) $definitions[ $item ]['title'],
				'at'         => $row['at'],
				// What the ledger says happened, not what is true now: an
				// entry reverted from another screen still reads as reverted.
				'reverted'   => null !== $row['reverted_at'],
				/*
				 * Whether the undo on this row can work. The item's live state
				 * decides it, not the ledger: an entry can be open while the
				 * item has since been turned off elsewhere, and the revert
				 * endpoint answers that press with a refusal.
				 */
				'undoable'   => $manager->is_active( $item ),
				// Whether that undo takes back everything, for the choice the
				// item is applied with, as the Hardening screen's row says:
				// HSTS on every subdomain stays in the browsers that saw it.
				'reversible' => \BetterShield\Hardening\Items::is_reversible( $item, is_array( $state['options'] ?? null ) ? $state['options'] : array() ),
			);
		}

		return array( 'entries' => $entries );
	}

	/**
	 * Who holds an item that is in force without its switch, in the words
	 * the Hardening row uses.
	 */
	private static function enforced_words( string $id ): string {
		$by = \BetterShield\Onboarding\SafeFixes::enforced_by( $id );

		if ( 'host' === $by ) {
			return __( 'set by your host', 'bettershield' );
		}

		return '' === $by
			? __( 'already in force on this site', 'bettershield' )
			/* translators: %s: another plugin's name. */
			: sprintf( __( 'set by %s', 'bettershield' ), $by );
	}

	/**
	 * An item's own few words for the choice it was applied with, for items
	 * that take one. Null for the rest, and for an item's default.
	 *
	 * @param array<string, mixed> $state
	 */
	private static function scope_of( string $id, array $state ): ?string {
		$handler = \BetterShield\Hardening\Items::handlers()[ $id ] ?? null;

		if ( null === $handler || ! method_exists( $handler, 'scope' ) ) {
			return null;
		}

		return $handler::scope( $state );
	}

	/**
	 * How many protections are on, out of how many there are, and which.
	 *
	 * `Manager::is_active()` is an option read, which is what makes the whole
	 * list affordable here; `describe_all()` is the one that cannot be.
	 *
	 * @return array<string, mixed>|null
	 */
	private static function protection_panel(): ?array {
		if ( ! current_user_can( Capabilities::MANAGE ) ) {
			return null;
		}

		$manager     = \BetterShield\Hardening\Manager::instance();
		$definitions = \BetterShield\Hardening\Items::all();
		$groups      = \BetterShield\Hardening\Items::groups();
		$items       = array();
		$active      = 0;
		$in_force    = 0;

		foreach ( \BetterShield\Hardening\Items::ids() as $id ) {
			$on    = $manager->is_active( $id );
			$group = isset( $definitions[ $id ]['group'] ) ? (string) $definitions[ $id ]['group'] : '';
			// Off here, but the server or another plugin already does it, so
			// it isn't counted as off (#2655).
			$elsewhere = ! $on && \BetterShield\Onboarding\SafeFixes::enforced_without_us( $id );

			if ( $on ) {
				++$active;
			}

			if ( $elsewhere ) {
				++$in_force;
			}

			$items[] = array(
				'key'    => $id,
				'label'  => isset( $definitions[ $id ]['title'] ) ? (string) $definitions[ $id ]['title'] : $id,
				'group'  => $group,
				// The Protect tab the item is on. The panel counts every item,
				// and Protect keeps them on two tabs, so it says where.
				'screen' => isset( $groups[ $group ]['screen'] ) ? (string) $groups[ $group ]['screen'] : 'hardening',
				'active' => $on,
				'in_force_elsewhere' => $elsewhere,
				// The narrower choice an item was applied with, beside its
				// title: "Disable XML-RPC" switched on read as the whole
				// endpoint closed when only pingbacks were.
				'scope'  => $on ? self::scope_of( $id, $manager->item_state( $id ) ) : ( $elsewhere ? self::enforced_words( $id ) : null ),
			);
		}

		return array(
			'active'   => $active,
			'in_force' => $in_force,
			'total'    => count( $items ),
			'items'    => $items,
			// Every protection's count, as every other screen says it.
			'count'    => \BetterShield\Hardening\ProtectionCount::all(),
		);
	}

	/**
	 * How many file changes are open, what kind they are, where most of them
	 * come from, and the few most worth a first look.
	 *
	 * The counts are the grouped queries the file screen already runs; the
	 * samples are the three loudest rows, not the three newest. A site whose
	 * change table is missing throws rather than answering, and an unreadable
	 * table is not the same as a clean site — so the count goes null and the
	 * screen says it could not read rather than reporting zero.
	 *
	 * @return array<string, mixed>|null
	 */
	private static function files_panel(): ?array {
		if ( ! current_user_can( Capabilities::MANAGE ) ) {
			return null;
		}

		try {
			$counts  = \BetterShield\Integrity\Report::open_count();
			$samples = \BetterShield\Integrity\Report::loudest_open( 3 );
		} catch ( \RuntimeException $error ) {
			return array( 'open' => null, 'samples' => array() );
		}

		if ( ! empty( $counts['read_failed'] ) ) {
			return array( 'open' => null, 'samples' => array() );
		}

		// Nothing open is a clean site only when a check ran lately and
		// compared everything. It is also what no check at all leaves, and a
		// check that could not compare part of the site, or one too old to
		// speak for today; the card has to be able to tell those apart.
		$result = \BetterShield\Integrity\Scanner::last_result();
		$core   = (int) $counts['total'] > 0 ? \BetterShield\Integrity\Packages::core() : null;

		return array(
			'open'         => (int) ( $counts['total'] ?? 0 ),
			// Not open, and still differing from the published copy: with any
			// marked, the card cannot say the files match.
			'expected'     => \BetterShield\Integrity\Report::suppressed_total(),
			// By kind, so a count that is mostly files of a removed plugin
			// does not read as a site full of altered code, with the added
			// files that can run counted on their own.
			'kinds'        => array(
				'modified'   => (int) $counts['modified'],
				'added'      => (int) $counts['added'],
				'removed'    => (int) $counts['removed'],
				'unreadable' => (int) $counts['unreadable'],
				'added_code' => (int) $counts['total'] > 0 ? \BetterShield\Integrity\Report::open_added_code() : 0,
			),
			// WordPress core first, where its own files changed (#2118), then
			// the plugins and themes most of them belong to, largest first.
			'sources'      => array_merge(
				null !== $core ? array(
					array(
						'name'      => __( 'WordPress', 'bettershield' ),
						'version'   => $core['version'],
						'installed' => true,
						'core'      => true,
						'modified'  => $core['modified'],
						'added'     => $core['added'],
						'removed'   => $core['removed'],
					),
				) : array(),
				array_map(
				static function ( array $group ): array {
					return array(
						'name'      => $group['name'],
						'version'   => $group['version'],
						'installed' => \BetterShield\Integrity\Packages::is_installed( $group['context'], $group['slug'] ),
						'modified'  => $group['modified'],
						'added'     => $group['added'],
						'removed'   => $group['removed'],
					);
				},
				(int) $counts['total'] > 0 ? array_slice( \BetterShield\Integrity\Packages::all(), 0, null !== $core ? 2 : 3 ) : array()
				),
				// The root, drop-ins, must-use plugins and configuration
				// files belong to no release, so they have a line of their
				// own, named as the screen's Location filter names them, or
				// the lines above added up to less than the card's total (#2484).
				array_sum( $counts['other'] ) > 0 ? array(
					array(
						'name'      => __( 'Other files (wp-config.php, must-use plugins)', 'bettershield' ),
						'version'   => '',
						'installed' => true,
						'modified'  => $counts['other']['modified'],
						'added'     => $counts['other']['added'],
						'removed'   => $counts['other']['removed'],
					),
				) : array()
			),
			'samples'      => $samples,
			'ever_run'     => null !== $result,
			'last_run_at'  => isset( $result['finished_at'] ) ? (string) $result['finished_at'] : null,
			'stale'        => \BetterShield\Integrity\Report::is_stale(),
			'unverifiable' => isset( $result['unverifiable'] ) ? count( (array) $result['unverifiable'] ) : 0,
			// Of those, the plugins nothing publishes: their files are watched
			// against the copy first seen, so they are not "not compared"
			// (#1969).
			'watched'      => isset( $result['unverifiable'] ) ? count( array_filter( (array) $result['unverifiable'], array( \BetterShield\Integrity\Report::class, 'is_watched' ) ) ) : 0,
		);
	}

	/**
	 * What was unusual for this site in the last day, against its own last
	 * thirty: absent when nothing was, which is most days, and for everybody
	 * who may not read the log it comes from.
	 *
	 * @return array<string, mixed>|null
	 */
	private static function unusual_panel(): ?array {
		if ( ! current_user_can( Capabilities::READ_ACTIVITY ) ) {
			return null;
		}

		$panel = \BetterShield\Events\Unusual::panel();

		return array() === $panel['notes'] ? null : $panel;
	}

	/**
	 * The last few entries in the activity log.
	 *
	 * Its own capability, which `/overview` does not require: the score is
	 * readable by somebody the log is not.
	 *
	 * @return array<string, mixed>|null
	 */
	private static function activity_panel(): ?array {
		if ( ! current_user_can( Capabilities::READ_ACTIVITY ) ) {
			return null;
		}

		/*
		 * This week's rows, the same week the count beside the tab is of:
		 * the latest four from any date sat under a count of this week's,
		 * so a quiet site read "0" above four rows from last month.
		 */
		$page   = \BetterShield\Events\Query::page(
			array(
				'per_page' => 4,
				'from'     => gmdate( 'Y-m-d\\TH:i:s\\Z', time() - WEEK_IN_SECONDS ),
			)
		);
		// The count reads as zero where the table is not there; that is unknown, not none.
		$agents = \BetterShield\Database\Schema::ready( 'agent_invocations' ) ? \BetterShield\Agents\Invocations::counts() : array();

		return array(
			'events' => $page['events'],
			// What two of the Activity screens hold, for the counts beside
			// their names: the incidents open now, and the agent requests on
			// record. Null where the count could not be read.
			'counts' => array(
				'incidents_open' => \BetterShield\Incidents\Repository::open_count(),
				'agent_requests' => isset( $agents['all'] ) ? (int) $agents['all'] : null,
			),
		);
	}
}
