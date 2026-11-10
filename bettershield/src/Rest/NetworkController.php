<?php
/**
 * REST surface for the network screens.
 *
 * Three reads: every site's posture, where the move to the shared tables
 * stands, and the log of the whole network. They exist only on a network, and
 * only a network administrator is answered — a super administrator may read
 * every site here, and may not name a site the network does not have.
 *
 * The roll-up is expensive: it switches into every site to read what that
 * site's own last audit found. So it is served from the cache the roll-up
 * keeps, with one route to rebuild it. Progress is the opposite shape — one
 * network option, read live — and is never served stale.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Admin\Network;
use BetterShield\Database\NetworkMigration;
use BetterShield\Events\Query;
use BetterShield\Events\Sampling;
use BetterShield\Support\Tier;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/*
 * The plugin-owned events table, for which no core API exists, read without a
 * cache on purpose: an activity log served from a stale copy is a log that
 * omits the most recent thing that happened, which is the entry most likely to
 * matter.
 */
// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

final class NetworkController {

	public function register(): void {
		/*
		 * There is no network to read on a single site, and no capability that
		 * would answer for one. Nothing is registered rather than registered
		 * and then refused: a route that exists and always says no is a route
		 * somebody eventually writes a client against.
		 */
		if ( ! is_multisite() ) {
			return;
		}

		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	/**
	 * The site filter, on the two routes that take one.
	 *
	 * Validated against the network itself rather than merely against being a
	 * number: a network administrator reads every site of *this* network, and
	 * a blog id that is not on it is the request being wrong rather than a
	 * quietly empty answer.
	 *
	 * @return array<string, mixed>
	 */
	private static function sites_arg(): array {
		return array(
			'type'              => 'array',
			'required'          => false,
			'items'             => array( 'type' => 'integer' ),
			'validate_callback' => array( self::class, 'validate_sites' ),
			'sanitize_callback' => 'wp_parse_id_list',
		);
	}

	/**
	 * @param mixed            $value
	 * @param \WP_REST_Request $request
	 * @return true|\WP_Error
	 */
	public static function validate_sites( $value, $request, string $param ) {
		$shape = rest_validate_request_arg( $value, $request, $param );

		if ( is_wp_error( $shape ) ) {
			return $shape;
		}

		$ids = wp_parse_id_list( $value );

		// One page is read for a list of named sites; a longer one is refused
		// with the number, not cut short in silence.
		if ( count( $ids ) > Network::page_size() ) {
			return new \WP_Error(
				'rest_invalid_param',
				sprintf(
					/* translators: %d: how many sites one request may name. */
					__( 'Name at most %d sites at a time.', 'bettershield' ),
					Network::page_size()
				),
				array( 'status' => 400 )
			);
		}

		foreach ( $ids as $id ) {
			// Site lookup is global; validate current-network membership explicitly.
			$site = get_site( $id );
			if ( null === $site || (int) $site->network_id !== get_current_network_id() ) {
				return new \WP_Error(
					'rest_invalid_param',
					sprintf(
						/* translators: %d: a numeric site identifier. */
						__( 'Site %d is not on this network.', 'bettershield' ),
						$id
					),
					array( 'status' => 400 )
				);
			}
		}

		return true;
	}

	/**
	 * The log's filters, matching the per-site route's so the two cannot
	 * narrow the same record differently.
	 *
	 * Every one names a validator as well as a sanitizer. Core runs a
	 * validator only where the argument names one, and it falls back to its
	 * own combined parser only for an argument that names no sanitizer either.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private static function filter_args(): array {
		return ActivityController::filter_args();
	}

	public function register_routes(): void {
		$may_read = static function (): bool {
			return Permissions::network_read();
		};

		register_rest_route(
			'bettershield/v1',
			'/network/sites',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => array( $this, 'sites' ),
				'permission_callback' => $may_read,
				'args'                => array(
					'sites'  => self::sites_arg(),
					// The site a page starts after; zero for the first.
					'cursor' => array(
						'type'              => 'integer',
						'required'          => false,
						'minimum'           => 0,
						'default'           => 0,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'absint',
					),
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/network/sites/refresh',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				// Rebuilding a cache of what every site already says about
				// itself changes nothing on any of them, so it asks for
				// nothing more than reading it does.
				'callback'            => array( $this, 'refresh' ),
				'permission_callback' => $may_read,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/network/undo',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => array( $this, 'undo_list' ),
				'permission_callback' => $may_read,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/network/undo/revert',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'undo_revert' ),
				// Putting a network ruling back is a change to every site.
				'permission_callback' => static function () {
					return Permissions::network_manage();
				},
				// Not declared required: core checks a required argument before
				// the permission callback, so a caller with no business on this
				// route would be told about a missing field instead of refused.
				'args'                => array(
					'token' => array(
						'type'              => 'string',
						'required'          => false,
						'pattern'           => '^[a-f0-9]{32}$',
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'sanitize_text_field',
					),
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/network/migration',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => array( $this, 'migration' ),
				'permission_callback' => $may_read,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/network/activity',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => array( $this, 'activity' ),
				'permission_callback' => $may_read,
				'args'                => array_merge(
					array(
						'cursor' => array(
							'type'              => 'integer',
							'required'          => false,
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'absint',
						),
						'sites'  => self::sites_arg(),
					),
					self::filter_args()
				),
			)
		);
	}

	/* ---- the network's own undo list ------------------------------------------ */

	/**
	 * The network rulings that can be put back.
	 *
	 * They are recorded in the main site's undo table, under surfaces named
	 * for the network; the main site's own settings history is in the same
	 * table and is not the network's to show, so the ledger is asked for the
	 * network's scope rather than for everything the table holds.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private static function network_entries(): array {
		$main = (int) get_main_site_id();

		switch_to_blog( $main );

		try {
			$entries = \BetterShield\Undo\SettingsLedger::recent( 50, \BetterShield\Undo\SettingsLedger::SCOPE_NETWORK );
		} finally {
			restore_current_blog();
		}

		return $entries;
	}

	public function undo_list(): \WP_REST_Response {
		return rest_ensure_response( array( 'entries' => self::network_entries() ) );
	}

	/**
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function undo_revert( \WP_REST_Request $request ) {
		$token = (string) $request->get_param( 'token' );

		if ( '' === $token ) {
			return new \WP_Error( 'bettershield_missing_token', __( 'Say which change to put back.', 'bettershield' ), array( 'status' => 400 ) );
		}

		$known = array_column( self::network_entries(), 'token' );

		// A site's own token is refused here rather than reverted on the
		// main site by a network administrator who never saw that screen.
		if ( ! in_array( $token, $known, true ) ) {
			return new \WP_Error( 'bettershield_not_a_network_change', __( 'That change is not one of the network’s.', 'bettershield' ), array( 'status' => 404 ) );
		}

		switch_to_blog( (int) get_main_site_id() );

		try {
			$result = \BetterShield\Undo\SettingsLedger::revert( $token, \BetterShield\Undo\SettingsLedger::SCOPE_NETWORK );
		} finally {
			restore_current_blog();
		}

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return rest_ensure_response( array( 'reverted' => true, 'entries' => self::network_entries() ) );
	}

	/* ---- the roll-up ---------------------------------------------------------- */

	/**
	 * @return int[]
	 */
	private function requested_sites( \WP_REST_Request $request ): array {
		return array_values( array_map( 'intval', (array) ( $request->get_param( 'sites' ) ?? array() ) ) );
	}

	public function sites( \WP_REST_Request $request ): \WP_REST_Response {
		return rest_ensure_response( $this->rollup( false, $this->requested_sites( $request ), (int) $request->get_param( 'cursor' ) ) );
	}

	public function refresh(): \WP_REST_Response {
		return rest_ensure_response( $this->rollup( true, array() ) );
	}

	/**
	 * The roll-up as the screen draws it.
	 *
	 * Migration state is merged in here rather than cached with the rest: it
	 * changes while the copy runs, and the cached half does not.
	 *
	 * @param int[] $only
	 * @return array<string, mixed>
	 */
	private function rollup( bool $fresh, array $only, int $cursor = 0 ): array {
		// Sites named by id are read by id: a filter for a site past the
		// first page is answered for that site, never searched for in it.
		$data     = array() === $only
			? Network::rollup( $fresh, $cursor )
			: array(
				'sites'       => Network::rollup_for( $only ),
				'built_at'    => time(),
				// Said rather than cut quietly, should the list ever be
				// longer than a page; the argument refuses that first.
				'capped'      => Network::more_than_a_page( $only ),
				'next_cursor' => 0,
				'total'       => Network::total(),
			);
		$switched = (array) ( NetworkMigration::state()['switched'] ?? array() );
		$sites    = array();

		foreach ( $data['sites'] as $site ) {
			$id = (int) $site['id'];

			$sites[] = array(
				'id'                 => $id,
				'name'               => (string) $site['name'],
				'url'                => (string) $site['url'],
				'admin'              => (string) $site['admin'],
				'installed'          => (bool) ( $site['installed'] ?? true ),
				'score'              => isset( $site['score'] ) && null !== $site['score'] ? (int) $site['score'] : null,
				'grade'              => isset( $site['grade'] ) && null !== $site['grade'] ? (string) $site['grade'] : null,
				'open_findings'      => isset( $site['open_findings'] ) && null !== $site['open_findings'] ? (int) $site['open_findings'] : null,
				'audited_at'         => $site['audited_at'] ?? null,
				'migrated'           => Network::migrated( $switched, $id ),
				'recovery_link'      => (bool) ( $site['recovery_link'] ?? false ),
				'policies_effective' => $site['policies_effective'] ?? null,
			);
		}

		return array(
			'sites'       => $sites,
			'built_at'    => (int) $data['built_at'],
			'capped'      => (bool) $data['capped'],
			'max_sites'   => Network::MAX_SITES,
			// How many sites the network has, so the page can say what it is
			// a page of, and where the next page starts.
			'total'       => (int) ( $data['total'] ?? count( $sites ) ),
			'next_cursor' => (int) ( $data['next_cursor'] ?? 0 ),
		);
	}

	/* ---- the migration -------------------------------------------------------- */

	public function migration(): \WP_REST_Response {
		$state   = NetworkMigration::state();
		$current = (array) ( $state['current'] ?? array() );
		$blog    = (int) ( $current['blog_id'] ?? 0 );
		$counts  = self::carried_over( (array) ( $state['switched'] ?? array() ) );

		return rest_ensure_response(
			array(
				'status'        => (string) ( $state['status'] ?? NetworkMigration::STATUS_PENDING ),
				'complete'      => NetworkMigration::is_complete(),
				'retrying'      => ! empty( $state['error'] ),
				// Stored as bare UTC; marked, as every stored time this API returns.
				'started_at'    => \BetterShield\Support\Time::utc_iso( (string) ( $state['started_at'] ?? '' ) ),
				'finished_at'   => \BetterShield\Support\Time::utc_iso( (string) ( $state['finished_at'] ?? '' ) ),
				'sites_total'   => $counts['total'],
				'sites_done'    => $counts['done'],
				'current'       => array(
					'site_id'    => $blog,
					'site_label' => $blog > 0 ? Network::site_label( $blog ) : '',
					'table'      => (string) ( $current['table'] ?? '' ),
				),
				/*
				 * Rows already present under a global unique key, which the
				 * copy leaves exactly as it found them. Reported because a
				 * count that is not zero is the one thing on this card an
				 * administrator may want to ask about.
				 */
				'ignored_rows'  => self::total( $state['ignored'] ?? array() ),
				'resealed_days' => self::total( $state['resealed'] ?? array() ),
			)
		);
	}

	/**
	 * How many of this network's sites are carried over, counted now and by
	 * the rule the sites table marks each row with.
	 *
	 * The stored figures are written by the hourly task, so before its first
	 * run the card read "0 of 0" above a table showing the main site carried
	 * over, and a site added or removed since moved one and not the other.
	 * Only sites that still exist are counted, the main site among them.
	 *
	 * @param array<string, mixed> $switched
	 * @return array{done: int, total: int}
	 */
	private static function carried_over( array $switched ): array {
		$total = Network::total();
		$ids   = array_values( array_unique( array_merge( array( (int) get_main_site_id() ), array_map( 'intval', array_keys( $switched ) ) ) ) );
		// The ids the record names and nothing past them: a lookup rather
		// than a walk, so there is nothing to page through or be capped.
		$found = get_sites(
			array(
				'fields'     => 'ids',
				'site__in'   => $ids,
				'number'     => count( $ids ),
				'network_id' => get_current_network_id(),
			)
		);
		$done  = 0;

		foreach ( $found as $id ) {
			if ( Network::migrated( $switched, (int) $id ) ) {
				++$done;
			}
		}

		return array(
			'done'  => min( $done, $total ),
			'total' => $total,
		);
	}

	/**
	 * Every number in a progress figure, however it is grouped.
	 *
	 * The copy records these per site and per table; the card says one number,
	 * so it is summed here rather than teaching the screen the shape of a
	 * record that is not its business.
	 *
	 * @param mixed $value
	 */
	private static function total( $value ): int {
		if ( is_numeric( $value ) ) {
			return (int) $value;
		}

		if ( ! is_array( $value ) ) {
			return 0;
		}

		$sum = 0;

		foreach ( $value as $part ) {
			$sum += self::total( $part );
		}

		return $sum;
	}

	/* ---- the union log -------------------------------------------------------- */

	/**
	 * @return array{area: string, search: string, actor: string, from: string, to: string, prefix: string, network: bool, sites: int[]}
	 */
	private function filters( \WP_REST_Request $request ): array {
		return array(
			'area'    => (string) $request->get_param( 'area' ),
			'search'  => (string) $request->get_param( 'search' ),
			'actor'   => (string) $request->get_param( 'actor' ),
			'from'    => (string) $request->get_param( 'from' ),
			'to'      => (string) $request->get_param( 'to' ),
			'prefix'  => (string) $request->get_param( 'prefix' ),
			// Said explicitly, never inferred from the site filter: a read
			// widens because this route asked it to, not because a query
			// string named a site.
			'network' => true,
			'sites'   => $this->requested_sites( $request ),
		);
	}

	public function activity( \WP_REST_Request $request ): \WP_REST_Response {
		$filters = $this->filters( $request );
		$cursor  = (int) $request->get_param( 'cursor' );

		$page = Query::page( array_merge( $filters, array( 'cursor' => $cursor ) ) );

		$answer = array(
			'events'         => $page['events'],
			'next_cursor'    => $page['next_cursor'],
			'retention_days' => Tier::retention_days(),
			'counts'         => $this->counts_by_area( $filters ),
			'actors'         => Query::actors( 40, $filters ),
			'actors_total'   => Query::actors_total( $filters ),
			// What the log is currently leaving out, so the screen can say so
			// rather than presenting a capped list as the whole story.
			'sampling'       => array(
				'threshold' => Sampling::threshold(),
				'engaged'   => Sampling::engaged(),
			),
		);

		/*
		 * Every site the filter may name, so the control offers the network
		 * rather than only the sites this page happens to hold rows from.
		 *
		 * On the first page of a view only. It is one option read per site to
		 * build and it is identical on every page, so sending it with each
		 * "show older entries" would charge a two-hundred-site network for a
		 * dropdown it already has on screen.
		 */
		if ( 0 === $cursor ) {
			$sites = array();

			foreach ( Network::site_labels() as $id => $label ) {
				$sites[] = array(
					'id'    => (int) $id,
					'label' => $label,
				);
			}

			$answer['sites'] = $sites;

			// The filter offers one page of sites; how many there are in all,
			// so it can say when it is not offering every one of them.
			$answer['sites_total'] = Network::total();
		}

		return rest_ensure_response( $answer );
	}

	/**
	 * One definition of the per-area counts, the log's own, read across the
	 * network's sites.
	 *
	 * @param array<string, mixed> $filters
	 * @return array<string, int>
	 */
	private function counts_by_area( array $filters ): array {
		return Query::counts_by_area( array_merge( $filters, array( 'network' => true ) ) );
	}
}
