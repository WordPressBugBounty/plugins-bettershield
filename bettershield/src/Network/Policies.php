<?php
/**
 * The two policies a network sets once, for every site under it.
 *
 * Everything else this plugin stores belongs to one site: a site's own
 * administrator decides its posture, and no neighbor's setting reaches it.
 * These two are the exception, and the exception is narrow on purpose —
 * requiring a second factor, and requiring a passkey — because those are the
 * two an operator running fifty sites cannot enforce by asking fifty people.
 *
 * **The network's part is a floor, never an override.** The roles a site
 * enforces are the network's roles plus its own, and where the network sets a
 * grace window the shorter of the two applies. A site may add; it may not take
 * away. That composition is what keeps the site's own screen honest: a saved
 * value never silently stops applying, and the only thing a site cannot do is
 * remove something it did not set.
 *
 * The clock stays per site. Each site's grace window runs from the first time
 * that site saw the account, because a window shared across a network would
 * hand somebody a deadline set on a site they have never opened.
 *
 * **Arming the passkey policy asks a question about every site.** Naming a
 * role there stops a password opening those accounts, and the way back is a
 * recovery link or a printed code — both of which are per site. So a widening
 * walks the network and refuses while any site is without one, naming the
 * first. A network is exactly where this is easy to get wrong: the site the
 * operator is looking at has a link, and the twelve they are not looking at
 * decide whether the policy is safe.
 *
 * On a single site every read here answers the empty policy and every write
 * refuses. There is no network to set anything for, and a stored value nothing
 * could have written would be a surprise waiting for the day the site joins
 * one.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Network;

use BetterShield\Events\Writer;
use BetterShield\Recovery\OfflineCodes;
use BetterShield\Recovery\RecoveryLink;
use BetterShield\TwoFactor\Policy as TwoFactorPolicy;
use BetterShield\Undo\SettingsLedger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Policies {

	/** The two network options, which live in the network's own store. */
	public const OPTION_TWO_FACTOR = 'bettershield_network_two_factor_policy';

	/** When each role joined the network's two-factor list, by role. */
	public const TWO_FACTOR_ROLES_SINCE = 'bettershield_network_two_factor_roles_since';
	public const OPTION_PASSKEY    = 'bettershield_network_passkey_policy';

	/**
	 * How many sites a walk from here reads before it reports being capped.
	 *
	 * The same bound the roll-up uses, for the same reason: a page that reads
	 * every site of an unbounded network is a page that stops loading. Where
	 * the answer decides whether a password keeps working, being capped is a
	 * refusal rather than a silent yes.
	 */
	public const MAX_SITES = 200;

	/**
	 * The roles WordPress ships with.
	 *
	 * A network policy names role slugs, and roles are per site: a site
	 * without WooCommerce has no `shop_manager`, and the main site's list is
	 * not every site's. So the accepted set is the main site's roles together
	 * with these five, which exist on every site by construction. A role a
	 * given site lacks matches nobody there, and the site's card says so.
	 *
	 * @var string[]
	 */
	private const BUILT_IN_ROLES = array( 'administrator', 'editor', 'author', 'contributor', 'subscriber' );

	/* ---- reading --------------------------------------------------------------- */

	/**
	 * @return array{roles: string[], grace_days: int}
	 */
	public static function two_factor(): array {
		$stored = self::stored( self::OPTION_TWO_FACTOR );

		return array(
			'roles'      => self::role_list( $stored['roles'] ?? array() ),
			'grace_days' => max( 0, min( 90, (int) ( $stored['grace_days'] ?? 14 ) ) ),
		);
	}

	/**
	 * @return array{roles: string[]}
	 */
	public static function passkey(): array {
		$stored = self::stored( self::OPTION_PASSKEY );

		return array( 'roles' => self::role_list( $stored['roles'] ?? array() ) );
	}

	/**
	 * Whether a network administrator has ever saved this policy.
	 *
	 * Distinct from "it names no roles", and the difference is what a site's
	 * card reads: an unset policy is a network that has not decided, and a set
	 * one that names nobody is a network that decided nothing is required. The
	 * grace window only counts toward the floor once the policy is set, or an
	 * unvisited screen's default would quietly shorten every site's window.
	 */
	public static function two_factor_is_set(): bool {
		return array() !== self::stored( self::OPTION_TWO_FACTOR );
	}

	public static function passkey_is_set(): bool {
		return array() !== self::stored( self::OPTION_PASSKEY );
	}

	/**
	 * When each role the network requires a second factor of joined that
	 * list, so a site can tell a requirement that never lapsed from one set
	 * again. A site kept this for its own list only, and a role the network
	 * required again ran on the clock of its earlier spell: no grace at all.
	 *
	 * @return array<string, int>
	 */
	public static function two_factor_roles_since(): array {
		$stored = is_multisite() ? get_site_option( self::TWO_FACTOR_ROLES_SINCE, array() ) : array();

		return is_array( $stored ) ? array_map( 'intval', $stored ) : array();
	}

	/**
	 * @param mixed $option
	 * @param mixed $value
	 */
	public static function two_factor_list_added( $option, $value ): void {
		self::two_factor_list_changed( $option, $value, array() );
	}

	/**
	 * Start the spell of each role the network's list gained, and forget the
	 * roles it lost. Hooked on every write of the policy, undo included.
	 *
	 * @param mixed $option
	 * @param mixed $value
	 * @param mixed $old
	 */
	public static function two_factor_list_changed( $option, $value, $old ): void {
		$before = is_array( $old ) ? self::role_list( $old['roles'] ?? array() ) : array();
		$after  = is_array( $value ) ? self::role_list( $value['roles'] ?? array() ) : array();
		$since  = self::two_factor_roles_since();

		foreach ( array_diff( $after, $before ) as $role ) {
			$since[ $role ] = time();
		}

		update_site_option( self::TWO_FACTOR_ROLES_SINCE, array_intersect_key( $since, array_flip( $after ) ) );
	}

	public static function two_factor_list_deleted(): void {
		delete_site_option( self::TWO_FACTOR_ROLES_SINCE );
	}

	/* ---- the floor ------------------------------------------------------------- */

	/**
	 * The roles a site actually requires a second factor of: its own, plus the
	 * network's.
	 *
	 * @param string[] $site_roles
	 * @return string[]
	 */
	public static function effective_two_factor_roles( array $site_roles ): array {
		return self::union( $site_roles, self::two_factor()['roles'] );
	}

	/**
	 * The grace window a site actually gives: the shorter of its own and the
	 * network's, where the network has set one.
	 *
	 * Shorter rather than longer, because the network's window is the promise
	 * an operator made about the whole estate — a site lengthening it past
	 * that would opt itself out of the deadline without saying so. A site
	 * asking for less time than the network keeps its own answer.
	 */
	public static function effective_grace( int $site_grace ): int {
		if ( ! self::two_factor_is_set() ) {
			return $site_grace;
		}

		return min( $site_grace, self::two_factor()['grace_days'] );
	}

	/**
	 * @param string[] $site_roles
	 * @return string[]
	 */
	public static function effective_passkey_roles( array $site_roles ): array {
		return self::union( $site_roles, self::passkey()['roles'] );
	}

	/**
	 * The roles a site is enforcing because the network named them, out of the
	 * ones it is about to stop naming itself.
	 *
	 * A site's own screen lists the roles that site chose. Letting it uncheck
	 * one the network requires would save a list that is not what the site
	 * enforces — the role would still be covered by the floor above it, and
	 * the screen would be a lie from that moment on. So the save is refused
	 * and says where the requirement was set.
	 *
	 * @param string[] $before
	 * @param string[] $after
	 * @param string[] $network
	 * @return string[]
	 */
	public static function network_roles_removed( array $before, array $after, array $network ): array {
		return array_values( array_intersect( array_diff( $before, $after ), $network ) );
	}

	/* ---- writing --------------------------------------------------------------- */

	/**
	 * @param array<string, mixed> $input
	 * @return array{roles: string[], grace_days: int}|\WP_Error
	 */
	public static function update_two_factor( array $input ) {
		$refusal = self::refuse_off_a_network() ?? self::refuse_without_the_network_capability();

		if ( null !== $refusal ) {
			return $refusal;
		}

		$current = self::two_factor() + array( 'set' => self::two_factor_is_set() );
		$next    = self::validate_two_factor( $input );

		if ( is_wp_error( $next ) ) {
			return $next;
		}

		$unset = self::unsets( $input );

		return self::on_site(
			(int) get_main_site_id(),
			static function () use ( $current, $next, $unset ) {
				// Before the write, so the way back exists whether or not the
				// write succeeds — the order every settings surface uses.
				if ( false === SettingsLedger::record( 'network_two_factor_policy', $current, $next + array( 'set' => true ) ) ) {
					return new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
				}

				if ( $unset ) {
					delete_site_option( self::OPTION_TWO_FACTOR );
					$next = self::two_factor();
				} else {
					update_site_option( self::OPTION_TWO_FACTOR, $next );
				}

				$weakened = self::weakening( $current, $next );

				Writer::instance()->record(
					'network_2fa_policy_changed',
					array() === $weakened ? Writer::SEVERITY_MEDIUM : Writer::SEVERITY_HIGH,
					array(
						'object_type' => 'policy',
						'context'     => array(
							'roles'      => $next['roles'],
							'grace_days' => $next['grace_days'],
							'set'        => ! $unset,
							'weakened'   => $weakened,
						),
					)
				);

				return $next;
			}
		);
	}

	/**
	 * @param array<string, mixed> $input
	 * @return array{roles: string[]}|\WP_Error
	 */
	public static function update_passkey( array $input ) {
		$refusal = self::refuse_off_a_network() ?? self::refuse_without_the_network_capability();

		if ( null !== $refusal ) {
			return $refusal;
		}

		$current = self::passkey() + array( 'set' => self::passkey_is_set() );
		$next    = self::validate_passkey( $input );

		if ( is_wp_error( $next ) ) {
			return $next;
		}

		$unset = self::unsets( $input );

		return self::on_site(
			(int) get_main_site_id(),
			static function () use ( $current, $next, $unset ) {
				if ( false === SettingsLedger::record( 'network_passkey_policy', $current, $next + array( 'set' => true ) ) ) {
					return new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
				}

				if ( $unset ) {
					delete_site_option( self::OPTION_PASSKEY );
					$next = self::passkey();
				} else {
					update_site_option( self::OPTION_PASSKEY, $next );
				}

				$weakened = self::weakening( $current, $next );

				Writer::instance()->record(
					'network_passkey_policy_changed',
					array() === $weakened ? Writer::SEVERITY_MEDIUM : Writer::SEVERITY_HIGH,
					array(
						'object_type' => 'policy',
						'context'     => array( 'roles' => $next['roles'], 'set' => ! $unset, 'weakened' => $weakened ),
					)
				);

				return $next;
			}
		);
	}

	/* ---- what an input would become -------------------------------------------- */

	/**
	 * Whether this write puts a policy back to never having been saved.
	 *
	 * Only a revert can ask for that, carrying the `set: false` it recorded
	 * before the first save. No save can: choosing nothing is a set policy
	 * that names nobody, which is a different decision.
	 *
	 * @param array<string, mixed> $input
	 */
	private static function unsets( array $input ): bool {
		return SettingsLedger::is_reverting() && array_key_exists( 'set', $input ) && false === $input['set'];
	}

	/**
	 * Compare identities, not counts: an equal-sized role swap can weaken a policy.
	 *
	 * @param array<string, mixed> $before
	 * @param array<string, mixed> $after
	 * @return string[]
	 */
	private static function weakening( array $before, array $after ): array {
		$reasons = array();
		if ( array() !== array_diff( $before['roles'], $after['roles'] ) ) {
			$reasons[] = 'roles no longer required';
		}
		if ( isset( $before['grace_days'], $after['grace_days'] ) && $after['grace_days'] > $before['grace_days'] ) {
			$reasons[] = 'grace period lengthened';
		}
		return $reasons;
	}

	/**
	 * Separate from the write, so a dry run can ask the same question the save
	 * will.
	 *
	 * @param array<string, mixed> $input
	 * @return array{roles: string[], grace_days: int}|\WP_Error
	 */
	public static function validate_two_factor( array $input ) {
		$current = self::two_factor();
		$roles   = self::clean_roles( isset( $input['roles'] ) ? (array) $input['roles'] : $current['roles'] );

		if ( is_wp_error( $roles ) ) {
			return $roles;
		}

		/*
		 * The grace bound belongs to the site policy, and is asked of it
		 * rather than restated here — one bound, one message, one place it can
		 * change. Only the days are named: the roles this class judges are the
		 * network's, against a role list the site validator does not use, and
		 * naming any there would have the main site's own policy answer a
		 * question that was never about it. The value goes over as it came,
		 * not cast: (int) '' is 0, which the site validator refuses as text
		 * and would accept as a number.
		 */
		$days   = $input['grace_days'] ?? $current['grace_days'];
		$bounds = self::on_site(
			(int) get_main_site_id(),
			static function () use ( $days ) {
				return TwoFactorPolicy::instance()->validate( array( 'grace_days' => $days ) );
			}
		);

		if ( is_wp_error( $bounds ) ) {
			return $bounds;
		}

		return array(
			'roles'      => $roles,
			'grace_days' => (int) $bounds['grace_days'],
		);
	}

	/**
	 * @param array<string, mixed> $input
	 * @return array{roles: string[]}|\WP_Error
	 */
	public static function validate_passkey( array $input ) {
		$current = self::passkey();
		$roles   = self::clean_roles( isset( $input['roles'] ) ? (array) $input['roles'] : $current['roles'] );

		if ( is_wp_error( $roles ) ) {
			return $roles;
		}

		/*
		 * Widening is a question about membership rather than about size:
		 * swapping one role for another leaves the count where it was while
		 * arming the policy for accounts it did not cover a moment ago. So the
		 * test is what the change adds, and narrowing stays open — a network
		 * that has lost its way back has to be able to take roles out.
		 *
		 * The site-level version of this asks one site whether it has a way
		 * back. This one has to ask all of them, because the policy reaches
		 * all of them: a site with no recovery link becomes passwordless with
		 * nothing to open it, and it will not be the site the operator is
		 * looking at.
		 */
		if ( array() !== array_diff( $roles, $current['roles'] ) ) {
			$walk = self::recovery_walk();

			if ( $walk['capped'] ) {
				return new \WP_Error(
					'bettershield_network_too_large_to_check',
					sprintf(
						/* translators: %d: number of sites. */
						__( 'There are too many sites to confirm each has a recovery method, so password sign-in was not turned off.', 'bettershield' ),
						self::MAX_SITES
					),
					array( 'status' => 409 )
				);
			}

			if ( array() !== $walk['missing'] ) {
				return new \WP_Error(
					'bettershield_no_way_back',
					sprintf(
						/* translators: %s: the name of a site on the network. */
						__( 'Give every site a fresh recovery link or recovery codes first; %s has neither. With passwords off, a lost passkey needs one.', 'bettershield' ),
						self::site_name( (int) $walk['missing'][0] )
					),
					array( 'status' => 409 )
				);
			}
		}

		return array( 'roles' => $roles );
	}

	/* ---- the recovery walk ------------------------------------------------------ */

	/**
	 * The sites of this network with no way back: no usable recovery link and
	 * no printed codes.
	 *
	 * Read by switching into each site, because both credentials are per site
	 * and neither can be answered from outside it. Bounded, and the bound is
	 * reported rather than swallowed — see `recovery_walk()`.
	 *
	 * @return int[]
	 */
	public static function missing_recovery_sites(): array {
		return self::recovery_walk()['missing'];
	}

	/**
	 * The same walk with its bound said: which sites have no way back, and
	 * whether the network was larger than the walk. Read by the main site's
	 * audit, which asks again on every run what widening the policy asked
	 * once.
	 *
	 * @return array{missing: int[], capped: bool}
	 */
	public static function recovery_walk(): array {
		if ( ! is_multisite() ) {
			return array(
				'missing' => array(),
				'capped'  => false,
			);
		}

		// One past the cap, so a network larger than this reads as capped
		// rather than as a silence that means "every site is fine".
		$ids     = get_sites(
			array(
				'fields'     => 'ids',
				'number'     => self::MAX_SITES + 1,
				// The policy being widened is this network's, so the sites
				// it has to be safe for are this network's.
				'network_id' => get_current_network_id(),
			)
		);
		$capped  = count( $ids ) > self::MAX_SITES;
		$ids     = array_slice( $ids, 0, self::MAX_SITES );
		$missing = array();

		foreach ( $ids as $id ) {
			$has = self::on_site(
				(int) $id,
				static function (): bool {
					return RecoveryLink::usable() || OfflineCodes::exist();
				}
			);

			if ( ! $has ) {
				$missing[] = (int) $id;
			}
		}

		return array(
			'missing' => $missing,
			'capped'  => $capped,
		);
	}

	/* ---- roles ------------------------------------------------------------------ */

	/**
	 * The roles a network policy may name, with their labels.
	 *
	 * @return array<int, array{slug: string, label: string}>
	 */
	public static function available_roles(): array {
		$out = self::on_site(
			(int) get_main_site_id(),
			static function (): array {
				$roles = array();

				foreach ( wp_roles()->roles as $slug => $role ) {
					$roles[ (string) $slug ] = isset( $role['name'] )
						? translate_user_role( (string) $role['name'] )
						: (string) $slug;
				}

				return $roles;
			}
		);

		foreach ( self::BUILT_IN_ROLES as $slug ) {
			if ( ! isset( $out[ $slug ] ) ) {
				$out[ $slug ] = $slug;
			}
		}

		$list = array();

		foreach ( $out as $slug => $label ) {
			$list[] = array(
				'slug'  => (string) $slug,
				'label' => (string) $label,
			);
		}

		return $list;
	}

	/**
	 * @param mixed $roles
	 * @return string[]|\WP_Error
	 */
	private static function clean_roles( $roles ) {
		$known = array_column( self::available_roles(), 'slug' );
		$clean = array();

		foreach ( (array) $roles as $role ) {
			$role = sanitize_key( (string) $role );

			if ( '' === $role ) {
				continue;
			}

			if ( ! in_array( $role, $known, true ) ) {
				return new \WP_Error(
					'bettershield_unknown_role',
					__( 'A network policy can name only the main site’s roles and WordPress’s built-in roles.', 'bettershield' ),
					array( 'status' => 400 )
				);
			}

			$clean[] = $role;
		}

		return array_values( array_unique( $clean ) );
	}

	/* ---- plumbing --------------------------------------------------------------- */

	/**
	 * @return array<string, mixed>
	 */
	private static function stored( string $option ): array {
		if ( ! is_multisite() ) {
			return array();
		}

		$stored = get_site_option( $option, array() );

		return is_array( $stored ) ? $stored : array();
	}

	/**
	 * @param mixed $roles
	 * @return string[]
	 */
	private static function role_list( $roles ): array {
		return array_values( array_unique( array_filter( array_map( 'strval', (array) $roles ) ) ) );
	}

	/**
	 * @param string[] $site
	 * @param string[] $network
	 * @return string[]
	 */
	private static function union( array $site, array $network ): array {
		return array_values( array_unique( array_merge( array_map( 'strval', $site ), $network ) ) );
	}

	/**
	 * Run a piece of work as another site of the network, and come back.
	 *
	 * The one place this class crosses a site boundary, so the restore cannot
	 * be forgotten in a branch: a network read that left the request on
	 * another site would have every query after it answer for the wrong one.
	 *
	 * @param callable $work
	 * @return mixed
	 */
	private static function on_site( int $blog_id, callable $work ) {
		if ( ! is_multisite() ) {
			return $work();
		}

		switch_to_blog( $blog_id );

		try {
			return $work();
		} finally {
			restore_current_blog();
		}
	}

	private static function site_name( int $blog_id ): string {
		$details = get_site( $blog_id );

		if ( ! $details instanceof \WP_Site ) {
			/* translators: %d: a site's numeric identifier. */
			return sprintf( __( 'Site %d', 'bettershield' ), $blog_id );
		}

		$name = trim( (string) $details->blogname );

		return '' !== $name ? $name : untrailingslashit( $details->domain . $details->path );
	}

	/**
	 * A single site has no network to set a policy for, and says so rather
	 * than writing a value nothing would ever read.
	 */
	private static function refuse_off_a_network(): ?\WP_Error {
		if ( is_multisite() ) {
			return null;
		}

		return new \WP_Error(
			'bettershield_not_a_network',
			__( 'This site is not on a network; use its own settings screen.', 'bettershield' ),
			array( 'status' => 400 )
		);
	}

	/**
	 * Whoever is asking holds the capability a network's settings answer to.
	 *
	 * Asked here rather than only where the network screen calls in. The two
	 * writers above are reached by more than one route — the screen, and the
	 * undo that puts a ruling back — and a check that lives on one route is a
	 * check the other one does not make. `manage_network_options` rather than
	 * the broader `manage_network`, matching what the network's own permission
	 * asks for: reading the estate and changing its settings are different
	 * questions.
	 */
	private static function refuse_without_the_network_capability(): ?\WP_Error {
		if ( current_user_can( 'manage_network_options' ) ) {
			return null;
		}

		return new \WP_Error(
			'bettershield_not_a_network_administrator',
			__( 'Only a network administrator can set a policy for every site.', 'bettershield' ),
			array( 'status' => 403 )
		);
	}
}
