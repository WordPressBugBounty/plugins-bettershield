<?php
/**
 * REST surface for the activity log.
 *
 * Read-only, and gated on the activity capability rather than the manage one:
 * reading the record is a different privilege from changing the site, and
 * separating them is what lets an owner hand someone the log without handing
 * them the controls.
 *
 * The page itself comes from Events\Query, which the WP-CLI command reads
 * through as well, and so do the per-area counts beside it; this class owns
 * the route.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Capabilities;
use BetterShield\Support\Tier;
use BetterShield\Events\Query;
use BetterShield\Support\Ip;
use BetterShield\Events\Sampling;
use BetterShield\Events\Seal;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ActivityController {

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	/**
	 * The filters, shared by the listing and the export so one cannot narrow
	 * the log differently from the other.
	 *
	 * Every one names a validator as well as a sanitizer. Core runs a
	 * validator only where the argument names one, and it falls back to its
	 * own combined parser only for an argument that names no sanitizer either
	 * — so a schema written with a hand-rolled sanitizer and nothing else
	 * describes a shape and enforces none of it.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function filter_args(): array {
		$text = array(
			'type'              => 'string',
			'required'          => false,
			'validate_callback' => array( self::class, 'validate_filter' ),
			'sanitize_callback' => 'sanitize_text_field',
		);

		return array(
			'area'   => array(
				'type'              => 'string',
				'required'          => false,
				'validate_callback' => array( self::class, 'validate_filter' ),
				'sanitize_callback' => 'sanitize_key',
			),
			'search'  => $text,
			'actor'   => $text,
			'from'    => $text,
			'to'      => $text,
			// One network, as a row labels it, never an address. Its own
			// validator, so a wrong one is told what a network looks like
			// rather than that the area and the dates were wrong.
			'prefix'  => array( 'validate_callback' => array( self::class, 'validate_prefix' ) ) + $text,
		);
	}

	/**
	 * @param mixed $value
	 * @return bool|\WP_Error
	 */
	public static function validate_prefix( $value, \WP_REST_Request $request, string $param ) {
		$shape = rest_validate_request_arg( $value, $request, $param );
		if ( is_wp_error( $shape ) ) {
			return $shape;
		}
		return '' === trim( (string) $value ) || null !== Ip::from_label( trim( (string) $value ) )
			? true
			: new \WP_Error( 'bettershield_invalid_activity_network', __( 'Use a /24 network for IPv4, like 203.0.113.0/24, or a /64 for IPv6.', 'bettershield' ), array( 'status' => 400 ) );
	}

	/**
	 * @param mixed $value
	 * @return bool|\WP_Error
	 */
	public static function validate_filter( $value, \WP_REST_Request $request, string $param ) {
		$shape = rest_validate_request_arg( $value, $request, $param );
		if ( is_wp_error( $shape ) ) {
			return $shape;
		}
		// The network answers for itself above; read here it would put the
		// area-and-dates refusal on a request whose only fault is the network.
		return Query::valid_filters( array_diff_key( $request->get_params(), array( 'prefix' => true ) ) )
			? true
			: new \WP_Error( 'bettershield_invalid_activity_filter', __( 'Choose a valid activity area and calendar dates, with the start no later than the end.', 'bettershield' ), array( 'status' => 400 ) );
	}

	/**
	 * Where the next page starts: a row id, so anything that is not a number
	 * is the request being wrong rather than a silent zero that quietly hands
	 * back the first page again.
	 *
	 * @return array<string, mixed>
	 */
	private static function cursor_arg(): array {
		return array(
			'type'              => 'integer',
			'required'          => false,
			'validate_callback' => 'rest_validate_request_arg',
			'sanitize_callback' => 'absint',
		);
	}

	public function register_routes(): void {
		$may_read = static function (): bool {
			return current_user_can( Capabilities::READ_ACTIVITY );
		};

		register_rest_route(
			'bettershield/v1',
			'/activity',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => array( $this, 'list_events' ),
				'permission_callback' => $may_read,
				'args'                => array_merge(
					array( 'cursor' => self::cursor_arg() ),
					self::filter_args()
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/activity/export',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => array( $this, 'export_events' ),
				// The same capability as reading it on screen. An export is the
				// same record in a different container, and gating it higher
				// would only teach people to copy rows out by hand.
				'permission_callback' => $may_read,
				'args'                => self::filter_args() + array(
					/*
					 * The one container there is. Undeclared, a caller asking
					 * for another got CSV back with nothing saying its choice
					 * was dropped (#2200); asked for by name, it is refused.
					 */
					'format' => array(
						'type'              => 'string',
						'enum'              => array( 'csv' ),
						'required'          => false,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'sanitize_key',
					),
				),
			)
		);
	}

	/**
	 * @return array{area: string, search: string, actor: string, from: string, to: string, prefix: string}
	 */
	private function filters( \WP_REST_Request $request ): array {
		return array(
			'area'   => (string) $request->get_param( 'area' ),
			'search' => (string) $request->get_param( 'search' ),
			'actor'  => (string) $request->get_param( 'actor' ),
			'from'   => (string) $request->get_param( 'from' ),
			'to'     => (string) $request->get_param( 'to' ),
			'prefix' => (string) $request->get_param( 'prefix' ),
		);
	}

	public function list_events( \WP_REST_Request $request ): \WP_REST_Response {
		$filters = $this->filters( $request );

		$page = Query::page(
			array_merge( $filters, array( 'cursor' => (int) $request->get_param( 'cursor' ) ) )
		);

		return rest_ensure_response(
			array(
				'events'         => $page['events'],
				'next_cursor'    => $page['next_cursor'],
				'retention_days' => Tier::retention_days(),
				'counts'         => $this->counts_by_area( $filters ),
				'actors'         => Query::actors(),
				// How many there are, which the list above stops short of.
				'actors_total'   => Query::actors_total(),
				// What the log is currently leaving out, so the screen can say
				// so rather than presenting a capped list as the whole story.
				'can_manage'     => Permissions::manage(),
				'sampling'       => array(
					'threshold' => Sampling::threshold(),
					'engaged'   => Sampling::engaged(),
				),
				/*
				 * Which finished days are sealed, and which of them did not
				 * match when the daily task last checked.
				 *
				 * Two option reads, and deliberately not `Seal::verify()`:
				 * verifying recomputes a digest over every sealed day's rows,
				 * which is the daily task's work and not a list endpoint's.
				 * What is reported here is what that task wrote down.
				 *
				 * The days are UTC, because that is what a seal is taken over.
				 * The screen renders times in the reader's own zone, so it
				 * maps each row to its own UTC day rather than assuming a
				 * local day is one sealed day — on most of the world it spans
				 * two.
				 *
				 * An empty `broken` is not a claim that the chain is intact:
				 * it is also what a site whose daily check has never run
				 * reports. `checked_at` is how the screen tells those apart.
				 */
				'seals'          => self::seals(),
			)
		);
	}

	/**
	 * What the seal chain says about the days on screen.
	 *
	 * @return array{sealed: string[], broken: string[], checked_at: ?string}
	 */
	private static function seals(): array {
		// The class's own name for it, so a rename cannot leave this reading
		// an option nothing writes and reporting a check that never ran.
		$verdict = get_option( Seal::VERDICT_OPTION, array() );
		$checked = is_array( $verdict ) && ! empty( $verdict['checked_at'] ) ? (int) $verdict['checked_at'] : 0;

		return array(
			'sealed'     => array_map( 'strval', array_keys( Seal::all() ) ),
			'broken'     => array_values( array_unique( array_map( 'strval', wp_list_pluck( Seal::broken_days(), 'day' ) ) ) ),
			'checked_at' => $checked > 0 ? gmdate( 'c', $checked ) : null,
		);
	}

	/**
	 * The filtered log, as the text of a CSV file plus what it contains.
	 *
	 * Handed over as data rather than as a raw download, because the REST
	 * server JSON-encodes whatever a route returns: a CSV body would arrive
	 * wrapped in quotes with its newlines escaped, which is not a spreadsheet.
	 * The browser assembles the file from this, the same way the settings
	 * export already does, and the row count and the completeness travel
	 * beside it instead of in headers nobody would read.
	 */
	public function export_events( \WP_REST_Request $request ): \WP_REST_Response {
		$export = Query::export( $this->filters( $request ) );

		return rest_ensure_response(
			array(
				'csv'      => $export['csv'],
				'rows'     => $export['rows'],
				'complete' => $export['complete'],
				'filename' => 'bettershield-activity-' . gmdate( 'Y-m-d' ) . '.csv',
			)
		);
	}

	/**
	 * How many events each area holds, defined once beside the listing they
	 * describe: two definitions would let the chips advertise numbers the list
	 * could not produce.
	 *
	 * @param array<string, string> $filters
	 * @return array<string, int>
	 */
	private function counts_by_area( array $filters ): array {
		return Query::counts_by_area( $filters );
	}
}
