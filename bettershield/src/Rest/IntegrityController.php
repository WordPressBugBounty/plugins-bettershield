<?php
/**
 * REST surface for the file integrity check.
 *
 * Reading the state needs the activity capability, the same as reading the
 * log: it is a record of what was found. Acting on it — starting a check,
 * putting a file back, marking a change expected — needs the manage
 * capability, because each of those changes the site or what it reports.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Capabilities;
use BetterShield\Files\Quarantine;
use BetterShield\Hardening\Item\ContentSecurityPolicy;
use BetterShield\Integrity\IncomingPackage;
use BetterShield\Integrity\Packages;
use BetterShield\Integrity\Report;
use BetterShield\Integrity\Restore;
use BetterShield\Integrity\Scanner;
use BetterShield\Integrity\Unpublished;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class IntegrityController {

	/**
	 * The largest violation report worth decoding, in bytes.
	 *
	 * Generous by two orders of magnitude for what a browser sends, and the
	 * only bound on the one route here that answers without a session.
	 */
	private const MAX_REPORT_BYTES = 65536;

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	public function register_routes(): void {
		$may_read = static function (): bool {
			return current_user_can( Capabilities::READ_ACTIVITY );
		};

		$may_manage = static function (): bool {
			return current_user_can( Capabilities::MANAGE );
		};

		// Every route below that can lower this site's defenses asks for a
		// signed-in browser session. A credential exempt from the sign-in gate
		// may read, and may add protection, but may not take any away.
		$interactive_manage = static function () {
			return Permissions::interactive_manage();
		};

		// Writing, or letting go of, a file in the code a network shares is
		// the network's to do, not one site's.
		$network_code = static function ( $allowed ) {
			return true === $allowed ? Permissions::shared_code( false ) : $allowed;
		};

		/*
		 * The open changes narrowed on the server, so a filter covers every
		 * page and not only the rows loaded: where they live, what kind of
		 * change, how loud, and a piece of the path. Each may be left empty.
		 */
		$filter_args = array(
			'place'       => array(
				'type'              => 'string',
				'enum'              => array_merge( array( '' ), array_keys( Report::PLACES ) ),
				'default'           => '',
				'validate_callback' => 'rest_validate_request_arg',
				'sanitize_callback' => 'rest_sanitize_request_arg',
			),
			'change_type' => array(
				'type'              => 'string',
				'enum'              => array_merge( array( '' ), Report::CHANGE_TYPES ),
				'default'           => '',
				'validate_callback' => 'rest_validate_request_arg',
				'sanitize_callback' => 'rest_sanitize_request_arg',
			),
			'severity'    => array(
				'type'              => 'string',
				'enum'              => array_merge( array( '' ), Report::SEVERITIES ),
				'default'           => '',
				'validate_callback' => 'rest_validate_request_arg',
				'sanitize_callback' => 'rest_sanitize_request_arg',
			),
			'search'      => array(
				'type'              => 'string',
				'maxLength'         => Report::SEARCH_MAX,
				'default'           => '',
				'validate_callback' => 'rest_validate_request_arg',
				'sanitize_callback' => 'sanitize_text_field',
			),
		);

		// The newest change a decision about every match was counted up to.
		$through = array(
			'type'              => 'integer',
			'required'          => true,
			'minimum'           => 1,
			'validate_callback' => 'rest_validate_request_arg',
			'sanitize_callback' => 'rest_sanitize_request_arg',
		);

		$filtered = static fn( \WP_REST_Request $request ): array => Report::filter_of( $request->get_params() );

		register_rest_route(
			'bettershield/v1',
			'/integrity',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static function ( \WP_REST_Request $request ) use ( $filtered ) {
					$data = Report::all( (string) $request->get_param( 'cursor' ), $filtered( $request ) );
					return $data['changes_error'] ? new \WP_Error( 'bettershield_integrity_unavailable', $data['changes_error'], array( 'status' => 503 ) ) : rest_ensure_response( $data );
				},
				'args' => array_merge( array( 'cursor' => array( 'type' => 'string', 'validate_callback' => 'rest_validate_request_arg', 'sanitize_callback' => 'rest_sanitize_request_arg', 'default' => '', 'maxLength' => 47, 'pattern' => '^(|[0-4]\\|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z\\|[1-9][0-9]{0,18})$' ) ), $filter_args ),
				'permission_callback' => $may_read,
			)
		);

		// The rest of the files marked expected, a page at a time, with the
		// count of all of them.
		register_rest_route(
			'bettershield/v1',
			'/integrity/expected',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$page = Report::suppressed_page( (string) $request->get_param( 'cursor' ) );
					return is_wp_error( $page ) ? $page : rest_ensure_response( array_merge( $page, array( 'total' => Report::suppressed_total() ) ) );
				},
				'args' => array( 'cursor' => array( 'type' => 'string', 'validate_callback' => 'rest_validate_request_arg', 'sanitize_callback' => 'rest_sanitize_request_arg', 'default' => '', 'maxLength' => 45, 'pattern' => '^(|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z\\|[1-9][0-9]{0,18})$' ) ),
				'permission_callback' => $may_read,
			)
		);

		// The rest of the markings made a group at a time, a page at a time,
		// with the count of all of them.
		register_rest_route(
			'bettershield/v1',
			'/integrity/batches',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static fn( \WP_REST_Request $request ): \WP_REST_Response => rest_ensure_response( array_merge( Packages::batches_page( (int) $request->get_param( 'cursor' ) ), array( 'total' => Packages::batches_total() ) ) ),
				'args'                => array(
					'cursor' => array(
						'type'              => 'integer',
						'minimum'           => 0,
						'default'           => 0,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'rest_sanitize_request_arg',
					),
				),
				'permission_callback' => $may_read,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/integrity/scan',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'scan' ),
				'permission_callback' => $may_manage,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/integrity/changes/(?P<id>\d+)/preview',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$result = Restore::preview(
						(int) $request->get_param( 'id' ),
						(string) $request->get_param( 'path' ),
						true === $request->get_param( 'whole' )
					);

					return is_wp_error( $result ) ? $result : rest_ensure_response( $result );
				},
				// A preview reaches the network and reads a file. That is not a
				// read of our own record, so it takes the higher capability.
				'permission_callback' => $may_manage,
				'args'                => array(
					/*
					 * Which file, where the record names a whole package. The
					 * value is checked against that package's own list of
					 * differences before anything is fetched or read; this
					 * only bounds its shape.
					 */
					'path'  => array(
						'type'              => 'string',
						'required'          => false,
						'maxLength'         => 1024,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'sanitize_text_field',
					),
					// The whole file rather than the part that differs, where
					// it fits one comparison.
					'whole' => array(
						'type'              => 'boolean',
						'required'          => false,
						'default'           => false,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'rest_sanitize_request_arg',
					),
				),
			)
		);

		/*
		 * A package that differs from its published copy, adopted.
		 *
		 * A plugin built from source or patched for a client differs at every
		 * update, forever, and an owner who cannot say so learns to ignore the
		 * report. The adoption names one version and the hash of every file in
		 * it, so it goes quiet for exactly that copy and no further.
		 *
		 * It is still an action that stops a difference being reported, which
		 * is the side of the line the whole guard is drawn around: an
		 * application password may not do it, and where the owner asked to be
		 * asked, neither may a session without the password again. Naming one
		 * version and being reversible make it a smaller act, not a different
		 * kind of one.
		 */
		register_rest_route(
			'bettershield/v1',
			'/integrity/packages/(?P<slug>[A-Za-z0-9][A-Za-z0-9._-]{0,190})/adopt',
			array(
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'adopt' ),
					'permission_callback' => static function () use ( $interactive_manage, $network_code ) {
						return $network_code( $interactive_manage() );
					},
					'args'                => array(
						'version' => array(
							'type'              => 'string',
							'required'          => true,
							'maxLength'         => 32,
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'sanitize_text_field',
						),
					),
				),
				array(
					'methods'             => \WP_REST_Server::DELETABLE,
					'callback'            => array( $this, 'undo_adoption' ),
					'permission_callback' => static function () use ( $interactive_manage, $network_code ) {
						return $network_code( $interactive_manage() );
					},
					'args'                => array(
						'token' => array(
							'type'              => 'string',
							'required'          => true,
							'maxLength'         => 64,
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'sanitize_text_field',
						),
					),
				),
			)
		);

		/*
		 * One plugin's changes at one recorded version, as a group: what
		 * marking them would cover, marking them, taking a marking back, and
		 * comparing them again. Marking and taking back sit behind the same
		 * guard as marking one row; the preview and the comparison change no
		 * decision and take none away.
		 *
		 * A plugin nobody publishes keeps whatever folder it shipped in, in
		 * any case, or is one file, so preview and expect read a wider slug
		 * than the routes that ask a directory about it.
		 */
		$group_args = array(
			'context' => array(
				'type'              => 'string',
				'enum'              => array( 'plugin', 'theme', Unpublished::CONTEXT_UNLISTED ),
				'default'           => 'plugin',
				'validate_callback' => 'rest_validate_request_arg',
				'sanitize_callback' => 'sanitize_key',
			),
			'version' => array(
				'type'              => 'string',
				'required'          => true,
				'maxLength'         => 32,
				'validate_callback' => 'rest_validate_request_arg',
				'sanitize_callback' => 'sanitize_text_field',
			),
		);

		register_rest_route(
			'bettershield/v1',
			'/integrity/packages/(?P<slug>[A-Za-z0-9][A-Za-z0-9._-]{0,190})/preview',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$preview = Packages::preview( (string) $request['context'], (string) $request['slug'], (string) $request['version'] );

					return is_wp_error( $preview ) ? $preview : rest_ensure_response( $preview );
				},
				'permission_callback' => $may_manage,
				'args'                => $group_args,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/integrity/packages/(?P<slug>[A-Za-z0-9][A-Za-z0-9._-]{0,190})/expect',
			array(
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function ( \WP_REST_Request $request ) {
						$result = Packages::expect( (string) $request['context'], (string) $request['slug'], (string) $request['version'], (int) $request['count'], (string) $request['digest'] );

						return is_wp_error( $result ) ? $result : rest_ensure_response(
							array(
								'expected'  => $result,
								'integrity' => Report::all(),
							)
						);
					},
					'permission_callback' => static function () use ( $interactive_manage, $network_code ) {
						return $network_code( $interactive_manage() );
					},
					'args'                => array_merge(
						$group_args,
						array(
							'count'  => array(
								'type'              => 'integer',
								'required'          => true,
								'minimum'           => 1,
								'validate_callback' => 'rest_validate_request_arg',
								'sanitize_callback' => 'absint',
							),
							// Which rows the preview listed, so a group whose
							// rows changed at the same count is refused too.
							'digest' => array(
								'type'              => 'string',
								'required'          => true,
								'pattern'           => '^[a-f0-9]{64}$',
								'validate_callback' => 'rest_validate_request_arg',
								'sanitize_callback' => 'sanitize_text_field',
							),
						)
					),
				),
				array(
					'methods'             => \WP_REST_Server::DELETABLE,
					'callback'            => static function ( \WP_REST_Request $request ) {
						$result = Packages::undo( (string) $request['token'] );

						return is_wp_error( $result ) ? $result : rest_ensure_response(
							array(
								'returned'  => $result['count'],
								'integrity' => Report::all(),
							)
						);
					},
					'permission_callback' => static function () use ( $interactive_manage, $network_code ) {
						return $network_code( $interactive_manage() );
					},
					'args'                => array(
						'token' => array(
							'type'              => 'string',
							'required'          => true,
							'maxLength'         => 64,
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'sanitize_text_field',
						),
					),
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/integrity/packages/(?P<slug>[A-Za-z0-9][A-Za-z0-9._-]{0,190})/recheck',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$result = Packages::recheck( (string) $request['slug'], (int) $request['after'] );

					return is_wp_error( $result ) ? $result : rest_ensure_response(
						array(
							'rechecked' => $result,
							'integrity' => Report::all(),
						)
					);
				},
				'permission_callback' => static function () use ( $may_manage, $network_code ) {
					return $network_code( $may_manage() );
				},
				'args'                => array(
					'after' => array(
						'type'              => 'integer',
						'default'           => 0,
						'minimum'           => 0,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'absint',
					),
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/integrity/changes/(?P<id>\d+)/restore',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'restore' ),
				'permission_callback' => static function () use ( $may_manage, $network_code ) {
					return $network_code( $may_manage() );
				},
			)
		);

		// A file nobody published, kept in quarantine with an inert file in
		// its place (#1971). Under the same guard as putting a file back, and
		// the incident response's own gate inside.
		register_rest_route(
			'bettershield/v1',
			'/integrity/changes/(?P<id>\d+)/quarantine',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'keep_in_quarantine' ),
				'permission_callback' => static function () use ( $may_manage, $network_code ) {
					return $network_code( $may_manage() );
				},
			)
		);

		// Marking a change expected, and taking that back: the same decision
		// in both directions, behind the same guard.
		register_rest_route(
			'bettershield/v1',
			'/integrity/changes/(?P<id>\d+)/suppress',
			array(
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'suppress' ),
					// Accepting a change to code every site runs is the
					// network's decision, as restoring it is (#2615).
					'permission_callback' => static function () use ( $interactive_manage, $network_code ) {
						return $network_code( $interactive_manage() );
					},
				),
				array(
					'methods'             => \WP_REST_Server::DELETABLE,
					'callback'            => array( $this, 'unsuppress' ),
					'permission_callback' => static function () use ( $interactive_manage, $network_code ) {
						return $network_code( $interactive_manage() );
					},
				),
			)
		);

		$selection = static function ( int $most ): array {
			return array(
				'type'              => 'array',
				'required'          => true,
				'minItems'          => 1,
				'maxItems'          => $most,
				'items'             => array(
					'type'    => 'integer',
					'minimum' => 1,
				),
				'validate_callback' => 'rest_validate_request_arg',
				'sanitize_callback' => 'rest_sanitize_request_arg',
			);
		};

		// A selection of changes marked expected as one decision, and that
		// marking taken back: one row's decision, made for many, behind the
		// same guard.
		register_rest_route(
			'bettershield/v1',
			'/integrity/changes/expect',
			array(
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function ( \WP_REST_Request $request ) {
						$result = Packages::expect_selection( array_map( 'intval', (array) $request['ids'] ) );

						return is_wp_error( $result ) ? $result : rest_ensure_response(
							array(
								'expected'  => $result,
								'integrity' => Report::all(),
							)
						);
					},
					// On a network the changes are the network's shared code, kept
					// in one record for every site: marking hundreds of them
					// expected is the network's to do, as writing them is.
					'permission_callback' => static function () use ( $interactive_manage, $network_code ) {
						return $network_code( $interactive_manage() );
					},
					'args'                => array( 'ids' => $selection( Packages::MAX_SELECTION ) ),
				),
				array(
					'methods'             => \WP_REST_Server::DELETABLE,
					'callback'            => static function ( \WP_REST_Request $request ) {
						$result = Packages::undo( (string) $request['token'] );

						return is_wp_error( $result ) ? $result : rest_ensure_response(
							array(
								'returned'  => $result['count'],
								'integrity' => Report::all(),
							)
						);
					},
					'permission_callback' => static function () use ( $interactive_manage, $network_code ) {
						return $network_code( $interactive_manage() );
					},
					'args'                => array(
						'token' => array(
							'type'              => 'string',
							'required'          => true,
							'maxLength'         => 64,
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'sanitize_text_field',
						),
					),
				),
			)
		);

		/*
		 * The official copies of several changed files put back after one
		 * question, each exactly as one alone. It adds protection, as one
		 * restore does, and writes into the code the network shares, as one
		 * restore does.
		 */
		register_rest_route(
			'bettershield/v1',
			'/integrity/changes/restore',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$result = Restore::apply_many( array_map( 'intval', (array) $request['ids'] ) );

					return is_wp_error( $result ) ? $result : rest_ensure_response( array_merge( $result, array( 'integrity' => Report::all() ) ) );
				},
				'permission_callback' => static function () use ( $may_manage, $network_code ) {
					return $network_code( $may_manage() );
				},
				'args'                => array( 'ids' => $selection( Restore::BATCH_MAX ) ),
			)
		);

		// What every open change a filter matches holds, counted across every
		// page, before a decision about all of them.
		register_rest_route(
			'bettershield/v1',
			'/integrity/changes/matching',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static fn( \WP_REST_Request $request ): \WP_REST_Response => rest_ensure_response( Report::matching( $filtered( $request ) ) ),
				'permission_callback' => $may_manage,
				'args'                => $filter_args,
			)
		);

		/*
		 * Every open change a filter matches marked expected as one decision,
		 * held to the count and the newest row the owner was shown. Taken back
		 * through the selection's own DELETE, as one marking. On a network,
		 * the network's to do, as a selection is.
		 */
		register_rest_route(
			'bettershield/v1',
			'/integrity/changes/matching/expect',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) use ( $filtered ) {
					$filter = $filtered( $request );
					$result = Packages::expect_matching( $filter, (int) $request['seen'], (int) $request['through'] );

					return is_wp_error( $result ) ? $result : rest_ensure_response(
						array(
							'expected'  => $result,
							'integrity' => Report::all( '', $filter ),
						)
					);
				},
				'permission_callback' => static function () use ( $interactive_manage, $network_code ) {
					return $network_code( $interactive_manage() );
				},
				'args'                => array_merge(
					$filter_args,
					array(
						'seen'    => array(
							'type'              => 'integer',
							'required'          => true,
							'minimum'           => 1,
							'maximum'           => Packages::MAX_BATCH,
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'rest_sanitize_request_arg',
						),
						'through' => $through,
					)
				),
			)
		);

		/*
		 * The official copies of the open changes a filter matches put back,
		 * a few a request from where the last stopped, each exactly as one
		 * alone. It adds protection, as one restore does, and writes into the
		 * code the network shares, as one restore does.
		 */
		register_rest_route(
			'bettershield/v1',
			'/integrity/changes/matching/restore',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) use ( $filtered ) {
					$filter = $filtered( $request );
					$result = Restore::apply_matching( $filter, (int) $request['through'], (int) $request['after'], (int) $request['limit'] );

					return is_wp_error( $result ) ? $result : rest_ensure_response( array_merge( $result, array( 'integrity' => Report::all( '', $filter ) ) ) );
				},
				'permission_callback' => static function () use ( $may_manage, $network_code ) {
					return $network_code( $may_manage() );
				},
				'args'                => array_merge(
					$filter_args,
					array(
						'through' => $through,
						'after'   => array(
							'type'              => 'integer',
							'minimum'           => 0,
							'default'           => 0,
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'rest_sanitize_request_arg',
						),
						'limit'   => array(
							'type'              => 'integer',
							'minimum'           => 1,
							'maximum'           => Restore::BATCH_MAX,
							'default'           => Restore::BATCH_MAX,
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'rest_sanitize_request_arg',
						),
					)
				),
			)
		);

		/*
		 * The quarantine folder is sealed against being served, so a copy is
		 * streamed through here or not at all. Reading the list is a read;
		 * downloading is capability-gated and logged, because handing somebody
		 * the bytes of a file displaced for being altered is a security-
		 * relevant act; deleting is the one irreversible thing in this plugin,
		 * so it asks for the session like every other irreversible thing.
		 */
		register_rest_route(
			'bettershield/v1',
			'/quarantine',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				/*
				 * Paged, like the ability that reads the same ledger. This
				 * answered from the single-page reader and returned `items`
				 * alone, so the screen showed the newest two hundred entries
				 * and nothing in the response said there were more — the
				 * unreachable-and-never-told state the paged reader was
				 * written to end, left in place for the one caller that is a
				 * person looking at it.
				 */
				'callback'            => static function ( \WP_REST_Request $request ): \WP_REST_Response {
					$page = Quarantine::page( max( 0, (int) $request['before_id'] ) );

					return rest_ensure_response(
						array(
							'items'          => $page['items'],
							'has_more'       => $page['has_more'],
							'next_before_id' => $page['next_before_id'],
						)
					);
				},
				'args'                => array(
					'before_id' => array(
						'type'              => 'integer',
						'required'          => false,
						'minimum'           => 0,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'absint',
						'description'       => 'Continue from an earlier page: only entries older than this ledger row.',
					),
				),
				'permission_callback' => $may_read,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/quarantine/(?P<token>[a-f0-9]{16,64})/download',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$fetched = Quarantine::fetch( (string) $request['token'] );

					if ( is_wp_error( $fetched ) ) {
						return $fetched;
					}

					/*
					 * Base64 rather than raw bytes, and a .txt filename: this
					 * is evidence being carried off the site, and nothing about
					 * the response should let a browser treat it as anything
					 * executable.
					 */
					return rest_ensure_response(
						array(
							'filename' => $fetched['filename'],
							'base64'   => base64_encode( $fetched['bytes'] ),
						)
					);
				},
				// The bytes are a shared file's, and on a network the kept
				// copy can be one only the network's administrator put there.
				'permission_callback' => static function () use ( $may_manage, $network_code ) {
					return $network_code( $may_manage() );
				},
			)
		);

		/*
		 * What a put-back or a delete answers with: the entry acted on, as it
		 * now stands, for the screen to update where it is without dropping
		 * the older pages it has loaded; and the first page as the read route
		 * pages it. These answered with the unpaged reader, the newest two
		 * hundred and nothing saying more were kept, and the screen put that
		 * in place of every page it held.
		 */
		$after_action = static function ( string $token ): array {
			$page = Quarantine::page();

			return array(
				'item'           => Quarantine::item( $token ),
				'items'          => $page['items'],
				'has_more'       => $page['has_more'],
				'next_before_id' => $page['next_before_id'],
			);
		};

		/*
		 * Putting a displaced file back: the undo every restore generates and
		 * promises on screen, which until now nothing could invoke. It puts
		 * the version that was there back in place, so it is the direction
		 * that removes protection and asks for a person accordingly.
		 */
		register_rest_route(
			'bettershield/v1',
			'/quarantine/(?P<token>[a-f0-9]{16,64})/restore',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) use ( $after_action ) {
					$done = Quarantine::put_back( (string) $request['token'] );

					// Whether the difference is listed again, so the screen says
					// what happened rather than what usually does.
					return is_wp_error( $done ) ? $done : rest_ensure_response(
						array_merge(
							$after_action( (string) $request['token'] ),
							array(
								'reported'  => (bool) $done['reported'],
								'integrity' => Report::all(),
							)
						)
					);
				},
				'permission_callback' => static function () use ( $interactive_manage, $network_code ) {
					return $network_code( $interactive_manage() );
				},
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/quarantine/(?P<token>[a-f0-9]{16,64})',
			array(
				'methods'             => \WP_REST_Server::DELETABLE,
				'callback'            => static function ( \WP_REST_Request $request ) use ( $after_action ) {
					$done = Quarantine::forget( (string) $request['token'] );

					return is_wp_error( $done ) ? $done : rest_ensure_response( $after_action( (string) $request['token'] ) );
				},
				'permission_callback' => static function () use ( $interactive_manage, $network_code ) {
					return $network_code( $interactive_manage() );
				},
			)
		);

		/*
		 * Several kept copies at once, after one question that named how
		 * many: put back, or removed for good. Each goes exactly as one alone,
		 * with its own record and line in the log, and one that cannot is
		 * named with the reason the single action gives. Both ask what the
		 * single ones ask.
		 */
		register_rest_route(
			'bettershield/v1',
			'/quarantine/batch',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$tokens = array_map( 'strval', (array) $request['tokens'] );
					$put    = 'put_back' === (string) $request['action'];
					$result = $put ? Quarantine::put_back_many( $tokens ) : Quarantine::forget_many( $tokens );

					if ( is_wp_error( $result ) ) {
						return $result;
					}

					// Each entry as it now stands, for the screen to update in
					// place without dropping the pages it has loaded.
					$result['items'] = array_values( array_filter( array_map( array( Quarantine::class, 'item' ), $tokens ) ) );

					if ( $put ) {
						$result['integrity'] = Report::all();
					}

					return rest_ensure_response( $result );
				},
				'permission_callback' => static function () use ( $interactive_manage, $network_code ) {
					return $network_code( $interactive_manage() );
				},
				'args'                => array(
					'action' => array(
						'type'              => 'string',
						'required'          => true,
						'enum'              => array( 'put_back', 'remove' ),
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'rest_sanitize_request_arg',
					),
					'tokens' => array(
						'type'              => 'array',
						'required'          => true,
						'minItems'          => 1,
						'maxItems'          => Quarantine::BATCH_MAX,
						'items'             => array(
							'type'    => 'string',
							'pattern' => '^[a-f0-9]{16,64}$',
						),
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'rest_sanitize_request_arg',
					),
				),
			)
		);

		/*
		 * Browsers post violation reports here with no session, which they
		 * must — it is a report about a page a visitor loaded. Everything that
		 * makes that safe is inside the receiver: a per-source rate limit, a
		 * hard cap on distinct kinds kept, and only the origin of a blocked
		 * address ever stored.
		 */
		register_rest_route(
			'bettershield/v1',
			'/csp-report',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ): \WP_REST_Response {
					$body = (string) $request->get_body();

					// The receiver's rate limit runs after the decode, so
					// without this an unauthenticated caller can hand the
					// parser as much as the request limit allows on every
					// request. A real violation report is a few hundred bytes.
					if ( strlen( $body ) > self::MAX_REPORT_BYTES ) {
						return new \WP_REST_Response( null, 204 );
					}

					$body = json_decode( $body, true );

					if ( is_array( $body ) && isset( $body['csp-report'] ) && is_array( $body['csp-report'] ) ) {
						ContentSecurityPolicy::receive( $body['csp-report'] );
					}

					// 204 whatever happened: a browser has nothing to do with
					// the answer, and saying more would let somebody probe
					// what was accepted.
					return new \WP_REST_Response( null, 204 );
				},
				'permission_callback' => '__return_true',
			)
		);
	}

	/**
	 * How long the button on the screen may spend before it answers.
	 *
	 * Somebody is waiting on a browser, and a request that runs until the
	 * server kills it answers nothing at all — the run's whole design is that
	 * stopping early is normal and the cursor survives. So this does one
	 * bounded piece of the work and hands back the progress the response
	 * already carries.
	 */
	private const INLINE_SECONDS = 5.0;

	/**
	 * Start a check, or carry on one already running.
	 *
	 * A site large enough to exceed the budget keeps its cursor and finishes on
	 * the schedule, which the response says.
	 */
	public function scan(): \WP_REST_Response {
		// The cached manifests are discarded only where this call is what
		// starts a run, and only under the run's own claim — which is what
		// `tick()` does with the flag.
		// Past the first check, a screen waiting on the score is carrying on the
		// probes still owed, and ticking would start a whole new check.
		if ( ! \BetterShield\Integrity\FirstScan::carry_on() ) {
			Scanner::tick( self::INLINE_SECONDS, null, true );
		}

		return rest_ensure_response( array_merge( Report::all(), array( 'first_scan_running' => \BetterShield\Integrity\FirstScan::report()['running'] ) ) );
	}

	/**
	 * Keep one file nobody published in quarantine, and answer with the
	 * report as it now stands.
	 */
	public function keep_in_quarantine( \WP_REST_Request $request ) {
		$result = \BetterShield\Integrity\KeepInQuarantine::apply( (int) $request->get_param( 'id' ) );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return rest_ensure_response(
			array(
				'quarantined' => $result,
				'integrity'   => Report::all(),
			)
		);
	}

	public function restore( \WP_REST_Request $request ) {
		$result = Restore::apply( (int) $request->get_param( 'id' ) );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return rest_ensure_response(
			array(
				'restored'  => $result,
				'integrity' => Report::all(),
			)
		);
	}

	/**
	 * Record that a package's difference from its published copy is the
	 * owner's own work.
	 */
	public function adopt( \WP_REST_Request $request ) {
		$result = IncomingPackage::adopt(
			(string) $request->get_param( 'slug' ),
			(string) $request->get_param( 'version' )
		);

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return rest_ensure_response(
			array(
				'adopted'   => $result,
				'integrity' => Report::all(),
			)
		);
	}

	/**
	 * And take that back, which puts the difference on the screen again.
	 */
	public function undo_adoption( \WP_REST_Request $request ) {
		$result = IncomingPackage::revert_adoption( (string) $request->get_param( 'token' ) );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return rest_ensure_response( array( 'integrity' => Report::all() ) );
	}

	public function suppress( \WP_REST_Request $request ) {
		$result = Restore::suppress( (int) $request->get_param( 'id' ) );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return rest_ensure_response(
			array(
				'integrity' => Report::all(),
				'undo'      => $result['undo'],
			)
		);
	}

	/**
	 * Report a change marked expected again.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function unsuppress( \WP_REST_Request $request ) {
		$result = Restore::unsuppress( (int) $request->get_param( 'id' ) );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return rest_ensure_response( array( 'integrity' => Report::all() ) );
	}
}
