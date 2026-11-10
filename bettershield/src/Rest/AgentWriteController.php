<?php
/**
 * The owner's side of the write ladder.
 *
 * An agent describes a change and can go no further. What turns that
 * description into permission is a person, on this route, in their own
 * browser session: reading the plan, confirming their password where the site
 * asks for one, and allowing that single change. The confirmation this mints
 * is returned once and appears nowhere else — not in a log, not in a later
 * read of the same proposal, not in an option.
 *
 * The listing is deliberately the owner's view rather than an agent's: it
 * carries who allowed what and what became of it, which is the half the
 * ability surface has no business answering.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Abilities\Proposals;
use BetterShield\Abilities\Registrar;
use BetterShield\Events\Writer;
use BetterShield\Hardening\Items;
use BetterShield\Recovery\SafeMode;
use BetterShield\Support\Time;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AgentWriteController {

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	public function register_routes(): void {
		register_rest_route(
			'bettershield/v1',
			'/agents/proposals',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'permission_callback' => array( Permissions::class, 'manage' ),
				'args'                => array(
					'status' => array(
						'type'              => 'string',
						'default'           => 'open',
						'enum'              => array( 'open', 'all' ),
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'rest_sanitize_request_arg',
					),
					'after'  => array(
						'type'              => 'integer',
						'default'           => 0,
						'minimum'           => 0,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'rest_sanitize_request_arg',
					),
				),
				'callback'            => array( $this, 'list_proposals' ),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/agents/proposals/(?P<id>[0-9]+)/allow',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				// The same guard every route that can lower a defense carries:
				// a person's own session rather than a token, and the password
				// again where the owner asked for it. An application password
				// may carry a confirmation somebody minted and may never mint
				// one, which is this line.
				'permission_callback' => array( Permissions::class, 'interactive_manage' ),
				'callback'            => array( $this, 'allow' ),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/agents/proposals/(?P<id>[0-9]+)/withdraw',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'permission_callback' => array( Permissions::class, 'interactive_manage' ),
				'callback'            => array( $this, 'withdraw' ),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/agents/write-access',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'permission_callback' => static function ( \WP_REST_Request $request ) {
					// Changes off is never asked for the password; on is (#1820).
					return Permissions::interactive_manage_access( false !== rest_sanitize_boolean( $request['enabled'] ?? true ) );
				},
				'args'                => array(
					'enabled' => array(
						'required'          => true,
						'type'              => 'boolean',
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'rest_sanitize_request_arg',
					),
				),
				'callback'            => array( $this, 'set_write_access' ),
			)
		);
	}

	/* ---- routes ---------------------------------------------------------------- */

	public function list_proposals( \WP_REST_Request $request ): \WP_REST_Response {
		/*
		 * The opt-in and the capability it carries are two stores, and this
		 * screen is the one that draws both. Put back in step before the
		 * answer is assembled, so it never draws the contradiction — the
		 * switch on, the capability off, and every write refused.
		 */
		Registrar::reconcile_write_capability();

		$page = Proposals::page(
			(string) $request['status'],
			max( 0, (int) $request['after'] ),
			Proposals::PER_PAGE
		);

		return rest_ensure_response(
			array(
				'proposals'          => array_map( array( $this, 'shape' ), $page['proposals'] ),
				'next_cursor'        => $page['next_cursor'],
				'read_enabled'       => Registrar::is_enabled(),
				'write_enabled'      => Registrar::write_enabled(),
				'capability_granted' => Registrar::write_capability_held(),
				'sudo_required'      => Sudo::required(),
				// Why a sign-in change cannot be allowed from this account,
				// in the words the allow refuses with: the switch being off
				// and an account with no password to re-enter are two
				// answers, and only the site can tell them apart.
				'password_reason'    => Sudo::required() ? null : Registrar::password_reason(),
				// How many are waiting for an answer, whatever this page is
				// showing: the same cached count the menu's bubble reads, so
				// the heading here and the bubble there cannot disagree.
				'open_requests'      => Proposals::open_count(),
				// The site's own clock, so a screen reads every deadline
				// against the clock that set it rather than the reader's.
				'now'                => gmdate( 'c' ),
			)
		);
	}

	/**
	 * Mint the one confirmation a proposal will ever carry.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function allow( \WP_REST_Request $request ) {
		// Asked again inside the callback, not only at the route: the guard
		// above admits a person, and this is the question of whether this site
		// offers a write surface to anybody at all.
		$session = Permissions::interactive_manage();

		if ( true !== $session ) {
			return is_wp_error( $session ) ? $session : self::denied();
		}

		if ( ! Registrar::can_write() ) {
			return self::denied();
		}

		if ( Sudo::required() ) {
			$confirmed = Sudo::confirmed();

			if ( true !== $confirmed ) {
				return $confirmed;
			}
		}

		$proposal = Proposals::find( (int) $request['id'] );

		if ( null === $proposal ) {
			return new \WP_Error( 'bettershield_unknown_proposal', __( 'There is no such proposed change.', 'bettershield' ), array( 'status' => 404 ) );
		}

		$refusal = self::refusal_for( Proposals::status_of( $proposal ) );

		if ( null !== $refusal ) {
			return $refusal;
		}

		/*
		 * Not while the site is standing its protections down. Safe mode is
		 * the way back in, and nothing it holds off is enforced until it ends
		 * — so allowing a change to how people sign in here records it as
		 * applied and starts it biting at the instant the way back in closes,
		 * which is the one moment nobody wants a moved sign-in door.
		 */
		if ( SafeMode::is_active() && ! empty( $proposal->plan['changes_signing_in'] ) ) {
			return new \WP_Error(
				'bettershield_safe_mode',
				__( 'Sign-in changes cannot be allowed in safe mode. Leave safe mode, then allow it.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		/*
		 * A change to how people sign in applies only with a password
		 * re-entered here, at the allow. Where the gate asks nobody — it is
		 * off, or this account has no password to give — the confirmation
		 * could never apply, and minting it anyway spent the proposal and an
		 * hourly slot on a refusal recorded as an unverified recovery link.
		 * So it is refused here, first, with the reason that fits. Taking
		 * one of these protections off is not held behind it.
		 */
		if ( ! empty( $proposal->plan['changes_signing_in'] ) && 'revert' !== ( $proposal->plan['action'] ?? '' ) && ! Sudo::required() ) {
			return new \WP_Error(
				'bettershield_password_confirmation_needed',
				Registrar::password_reason(),
				array( 'status' => 409 )
			);
		}

		/*
		 * Whether a password was actually re-entered, rather than whether the
		 * gate was satisfied. A site with the confirmation switched off
		 * satisfies it without anybody proving anything, and so does safe
		 * mode, which stands the gate down along with everything else. The
		 * items that change how people sign in need the proof rather than the
		 * answer, so this asks the narrower question.
		 */
		$with_sudo    = Sudo::required() && Sudo::password_confirmed_recently( get_current_user_id() );
		$confirmation = Proposals::mint( (int) $proposal->id, get_current_user_id(), $with_sudo );

		if ( null === $confirmation ) {
			return new \WP_Error(
				'bettershield_proposal_allowed',
				__( 'That change has already been allowed.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		$minted = Proposals::find( (int) $proposal->id );

		Writer::instance()->record(
			'write_confirmation_minted',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => (string) $proposal->target_type,
				'object_id'   => (string) $proposal->target,
				'context'     => array(
					'ability'     => (string) $proposal->ability,
					'proposal_id' => (int) $proposal->id,
					'confirmed'   => $with_sudo,
				),
			)
		);

		return rest_ensure_response(
			array(
				// Once. It is stored as a digest and read back by nothing.
				'confirmation' => $confirmation,
				'expires_at'   => Time::utc_iso( (string) $proposal->expires_at ),
				'proposal'     => $this->shape( null === $minted ? $proposal : $minted ),
			)
		);
	}

	/**
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function withdraw( \WP_REST_Request $request ) {
		$session = Permissions::interactive_manage();

		if ( true !== $session ) {
			return is_wp_error( $session ) ? $session : self::denied();
		}

		$proposal = Proposals::find( (int) $request['id'] );

		if ( null === $proposal ) {
			return new \WP_Error( 'bettershield_unknown_proposal', __( 'There is no such proposed change.', 'bettershield' ), array( 'status' => 404 ) );
		}

		$status = Proposals::status_of( $proposal );

		if ( 'spent' === $status || 'withdrawn' === $status || 'declined' === $status ) {
			$refusal = self::refusal_for( $status );

			return null === $refusal ? self::denied() : $refusal;
		}

		Proposals::withdraw( (int) $proposal->id );

		// Declining a plan nobody allowed is not withdrawing an allowed one,
		// and the log said "Allowed change withdrawn" for both.
		Writer::instance()->record(
			'proposed' === $status ? 'agent_proposal_declined' : 'write_confirmation_withdrawn',
			Writer::SEVERITY_LOW,
			array(
				'object_type' => (string) $proposal->target_type,
				'object_id'   => (string) $proposal->target,
				'context'     => array(
					'ability'     => (string) $proposal->ability,
					'proposal_id' => (int) $proposal->id,
				),
			)
		);

		$withdrawn = Proposals::find( (int) $proposal->id );

		return rest_ensure_response( array( 'proposal' => $this->shape( null === $withdrawn ? $proposal : $withdrawn ) ) );
	}

	/**
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function set_write_access( \WP_REST_Request $request ) {
		$result = Registrar::set_write_enabled( (bool) $request['enabled'] );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return rest_ensure_response(
			array(
				'enabled'            => Registrar::write_enabled(),
				'capability_granted' => Registrar::write_capability_held(),
			)
		);
	}

	/* ---- shaping --------------------------------------------------------------- */

	/**
	 * One proposal as the owner's screen reads it.
	 *
	 * The digest of the confirmation is not here and cannot be: the class that
	 * owns the table takes it off every row on the way out.
	 *
	 * @return array<string, mixed>
	 */
	private function shape( object $row ): array {
		$minted_by = null;

		if ( null !== $row->minted_by && (int) $row->minted_by > 0 ) {
			$user      = get_userdata( (int) $row->minted_by );
			$minted_by = array(
				'id'           => (int) $row->minted_by,
				'display_name' => $user instanceof \WP_User ? $user->display_name : '',
			);
		}

		$plan = is_array( $row->plan ) ? $row->plan : array();

		return array(
			'id'            => (int) $row->id,
			'ability'       => (string) $row->ability,
			'ability_label' => self::ability_label( (string) $row->ability ),
			'target'        => (string) $row->target,
			'target_label'  => self::target_label( (string) $row->target_type, (string) $row->target, $plan ),
			'target_type'   => (string) $row->target_type,
			'plan'          => self::owner_plan( (string) $row->target_type, $plan ),
			'state_digest'  => (string) $row->state_digest,
			'proposed_at'   => Time::utc_iso( (string) $row->proposed_at ),
			'expires_at'    => Time::utc_iso( (string) $row->expires_at ),
			'status'        => Proposals::status_of( $row ),
			'minted_by'     => $minted_by,
			'minted_at'     => null === $row->minted_at ? null : Time::utc_iso( (string) $row->minted_at ),
			'spent_at'      => null === $row->spent_at ? null : Time::utc_iso( (string) $row->spent_at ),
			'outcome'       => null === $row->outcome ? null : (string) $row->outcome,
			/*
			 * Whether a way back was kept, and not the handle to it. This
			 * route is the management capability alone, which an application
			 * password reaches; the handle is the thing that performs the
			 * undo, and configuration reads here hand out no such thing. The
			 * revert control lives on the item's own screen, behind the
			 * session guard that every weakening action asks for.
			 */
			'revertable'    => null !== $row->undo_token,
		);
	}

	/**
	 * What the ability does, in the owner's words rather than its name.
	 *
	 * Kept here rather than read from the registry: the registry holds nothing
	 * while the opt-in is off, and this screen is exactly where somebody goes
	 * to read what happened after they turned it off.
	 */
	private static function ability_label( string $ability ): string {
		$labels = array(
			'bettershield/apply-hardening'   => __( 'Apply a protection', 'bettershield' ),
			'bettershield/revert-hardening'  => __( 'Take a protection off', 'bettershield' ),
			'bettershield/mark-file-expected' => __( 'Accept a file change', 'bettershield' ),
			'bettershield/set-incident-status' => __( 'Change an incident status', 'bettershield' ),
			'bettershield/restore-file'      => __( 'Put a file back', 'bettershield' ),
			'bettershield/deactivate-plugin' => __( 'Switch a plugin off', 'bettershield' ),
		) + \BetterShield\Abilities\WriteFixes::labels();

		foreach ( \BetterShield\Abilities\WriteAccess::labels() as $short => $label ) {
			$labels[ 'bettershield/' . $short ] = $label;
		}

		if ( isset( $labels[ $ability ] ) ) {
			return $labels[ $ability ];
		}

		// An add-on's confirmed action carries its own label.
		$extension = \BetterShield\Abilities\WriteExtensions::named( (string) preg_replace( '#^bettershield/#', '', $ability ) );

		return null !== $extension && is_string( $extension['label'] ?? null ) ? $extension['label'] : $ability;
	}

	/**
	 * What the change is about, named the way the rest of the product names it.
	 */
	private static function target_label( string $target_type, string $target, array $plan = array() ): string {
		if ( 'sessions' === $target_type ) {
			return 'site' === $target
				? __( 'Sessions for every account', 'bettershield' )
				: sprintf( /* translators: %s: the account's name. */ __( 'Sessions for %s', 'bettershield' ), self::account_name( (int) $target ) );
		}

		if ( 'mcp_app' === $target_type && is_string( $plan['app_name'] ?? null ) && '' !== $plan['app_name'] ) {
			return $plan['app_name'];
		}

		if ( 'lockdown' === $target_type ) {
			return __( 'This site', 'bettershield' );
		}

		if ( 'hardening_item' !== $target_type ) {
			return $target;
		}

		$item = Items::all()[ $target ] ?? null;

		return null === $item ? $target : (string) $item['title'];
	}

	/**
	 * An account as the owner's own screen names it.
	 *
	 * The plan an assistant reads says "Account #N" where the display name is
	 * the login (#1822); the person approving it manages the site's users,
	 * and Site Activity names the same account by its display name.
	 */
	private static function account_name( int $user_id ): string {
		$user = $user_id > 0 ? get_userdata( $user_id ) : false;

		if ( $user instanceof \WP_User && '' !== trim( (string) $user->display_name ) ) {
			return (string) $user->display_name;
		}

		/* translators: %d: an account's ID. */
		return sprintf( __( 'Account #%d', 'bettershield' ), $user_id );
	}

	/**
	 * The plan as the owner reads it: the account named the way Site Activity
	 * names it, in place of the label the assistant was given.
	 *
	 * @param array<string, mixed> $plan The stored plan.
	 * @return array<string, mixed>
	 */
	private static function owner_plan( string $target_type, array $plan ): array {
		if ( 'sessions' !== $target_type || 'user' !== ( $plan['scope'] ?? null ) || ! is_string( $plan['user_name'] ?? null ) || '' === $plan['user_name'] || ! is_array( $plan['effect'] ?? null ) ) {
			return $plan;
		}

		$name = self::account_name( (int) ( $plan['user_id'] ?? 0 ) );

		foreach ( $plan['effect'] as $index => $line ) {
			if ( is_string( $line ) ) {
				$plan['effect'][ $index ] = str_replace( $plan['user_name'], $name, $line );
			}
		}

		return $plan;
	}

	/**
	 * The refusal a proposal in this state gets, or null when it is answerable.
	 */
	private static function refusal_for( string $status ): ?\WP_Error {
		$refusals = array(
			'spent'     => array( 'bettershield_proposal_spent', __( 'That change has already been made.', 'bettershield' ) ),
			'withdrawn' => array( 'bettershield_proposal_withdrawn', __( 'That change was withdrawn.', 'bettershield' ) ),
			'declined'  => array( 'bettershield_proposal_declined', __( 'That change was declined.', 'bettershield' ) ),
			'expired'   => array( 'bettershield_proposal_expired', __( 'That plan has run out. Ask for the change again.', 'bettershield' ) ),
			'allowed'   => array( 'bettershield_proposal_allowed', __( 'That change has already been allowed.', 'bettershield' ) ),
		);

		if ( ! isset( $refusals[ $status ] ) ) {
			return null;
		}

		return new \WP_Error( $refusals[ $status ][0], $refusals[ $status ][1], array( 'status' => 409 ) );
	}

	private static function denied(): \WP_Error {
		return new \WP_Error(
			'bettershield_write_denied',
			__( 'Agents are not allowed to change this site.', 'bettershield' ),
			array( 'status' => 403 )
		);
	}
}
