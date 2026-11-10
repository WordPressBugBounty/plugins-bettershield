<?php
/**
 * Hardening item: keep low-privilege accounts out of the dashboard.
 *
 * `admin_gate` answers a signed-*out* visitor at /wp-admin/ with a 404. This
 * is the other half: accounts that are signed in and have no business there.
 *
 * On a store or a membership site those are the most numerous accounts and
 * the least trusted — a customer who bought something once, a subscriber who
 * registered to read one post. wp-admin hands every one of them the media
 * library, the profile screen, and any screen a plugin registered without
 * thinking hard about who could reach it. None of that is what the account
 * was created for, and all of it is surface.
 *
 * **Two accounts are never restricted, whatever the settings say.** Anybody
 * who can manage this site, and anybody who can manage this plugin. A
 * hardening item that could shut the owner out of their own dashboard would
 * be the exact failure this plugin exists to prevent, so the guard is in the
 * code rather than in the instructions.
 *
 * **And the profile screen always stays reachable.** A person's own password,
 * their own two-factor enrollment, and the list of devices signed in to their
 * account all live there — the last of those exists precisely so an author or
 * a subscriber whose password leaked can act without needing a capability.
 * Locking them out of it to reduce surface would take away the one page that
 * lets them defend themselves, which is a worse trade than the surface is
 * worth.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

use BetterShield\Capabilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AdminAreaAccess {

	/**
	 * Screens a restricted account keeps.
	 *
	 * `admin-post.php` is reached by front-end features while signed in — a
	 * cart, a form, a like button — so blocking it would break the site for
	 * the very people this restricts. `profile.php` is the page somebody
	 * defends their own account from.
	 *
	 * Two more used to be listed and never reached this list. `admin-ajax.php`
	 * is answered earlier, by the AJAX check in should_restrict(); the two
	 * asset loaders do not boot plugins at all, so nothing of ours runs on
	 * them.
	 */
	private const ALWAYS_OPEN = array(
		'admin-post.php',
		'profile.php',
	);

	/**
	 * The capabilities that mean there is work here.
	 *
	 * Held once because three places have to agree about it: what the screen
	 * offers, what the validator accepts, and what enforcement exempts. They
	 * did not, so editor, author and contributor were all offered, all
	 * accepted and all counted, and not one of them was ever sent home.
	 */
	private const WORKS_HERE = array(
		'edit_posts',
		'upload_files',
		'list_users',
		'moderate_comments',
	);

	/**
	 * The capabilities that make restricting an account impossible, whatever
	 * the settings say: running the site, running this plugin, or having work
	 * in the dashboard.
	 *
	 * @return string[]
	 */
	private static function never_restricted(): array {
		return array_merge( array( 'manage_options', Capabilities::MANAGE ), self::WORKS_HERE );
	}

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public static function fields(): array {
		$choices = array();

		foreach ( wp_roles()->roles as $slug => $role ) {
			// A role that can manage the site is not offered: selecting it
			// would do nothing, and offering a control that does nothing is
			// how an owner comes to distrust the screen.
			if ( self::role_can_manage( (string) $slug ) ) {
				continue;
			}

			$choices[] = array(
				'value' => (string) $slug,
				'label' => translate_user_role( (string) $role['name'] ),
			);
		}

		return array(
			array(
				'key'         => 'roles',
				'label'       => __( 'Which accounts to keep out', 'bettershield' ),
				// Said once, behind the row's ⓘ, rather than again under the choice.
				'description' => '',
				'required'    => true,
				'default'     => 'subscriber',
				'multiple'    => true,
				'choices'     => $choices,
			),
		);
	}

	/**
	 * @param array<string, mixed> $options
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function validate( array $options ) {
		$given = $options['roles'] ?? array( 'subscriber' );

		// A list typed on the command line arrives as one string, and WP-CLI
		// keeps only the last of a repeated flag: --roles=subscriber,customer
		// is how more than one is asked for there. No role slug has a comma.
		if ( is_string( $given ) ) {
			$given = explode( ',', $given );
		}

		$roles = array_values( array_unique( array_filter( array_map( 'trim', array_map( 'strval', array_filter( (array) $given, 'is_scalar' ) ) ) ) ) );
		$known = array_keys( wp_roles()->roles );

		foreach ( $roles as $role ) {
			if ( ! in_array( $role, $known, true ) ) {
				return new \WP_Error( 'bettershield_unknown_role', __( 'That is not a role on this site.', 'bettershield' ) );
			}

			if ( self::role_can_manage( $role ) ) {
				return new \WP_Error(
					'bettershield_role_manages_site',
					__( 'Roles that can manage this site are never kept out. Choose a role that cannot.', 'bettershield' )
				);
			}
		}

		if ( array() === $roles ) {
			return new \WP_Error( 'bettershield_no_roles', __( 'Choose at least one role.', 'bettershield' ) );
		}

		return array( 'roles' => $roles );
	}

	/**
	 * @param array<string, mixed> $options
	 * @return string[]
	 */
	public static function preview( array $options ): array {
		$validated = self::validate( $options );

		if ( is_wp_error( $validated ) ) {
			return array();
		}

		/*
		 * Counted the way enforcement decides, and in one query rather than a
		 * full pass over the capabilities meta per role selected.
		 *
		 * Counting by role name alone promised something that would not
		 * happen: one account can hold several roles, so the subscriber a
		 * store also made an editor was counted here and exempted at runtime.
		 * `capability__not_in` excludes both the roles carrying those
		 * capabilities and any account granted one directly.
		 */
		$found = new \WP_User_Query(
			array(
				'role__in'           => $validated['roles'],
				'capability__not_in' => self::never_restricted(),
				'fields'             => 'ID',
				'number'             => 1,
				'count_total'        => true,
			)
		);

		$count = (int) $found->get_total();

		// A count of none is not a sentence about sending anybody (#2575).
		if ( 0 === $count ) {
			return array( __( 'No account is affected right now.', 'bettershield' ) );
		}

		return array(
			sprintf(
				/* translators: %d: number of accounts. */
				_n(
					'Sends %d account home from any dashboard page except its own profile.',
					'Sends %d accounts home from any dashboard page except their own profile.',
					$count,
					'bettershield'
				),
				$count
			),
		);
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function summary( array $state ): ?string {
		$options = isset( $state['options'] ) && is_array( $state['options'] ) ? $state['options'] : array();
		$roles   = isset( $options['roles'] ) ? (array) $options['roles'] : array();

		if ( array() === $roles ) {
			return null;
		}

		$names = array();

		foreach ( $roles as $role ) {
			$names[] = translate_user_role( (string) ( wp_roles()->roles[ $role ]['name'] ?? $role ) );
		}

		return implode( ', ', $names );
	}

	/**
	 * A plugin that already does this and disagrees about which screens stay
	 * open would produce a redirect loop, which is worth saying before rather
	 * than after.
	 *
	 * The classes are a parameter so both answers can be tested. They are
	 * global names, so a suite that needs one present has to define it for
	 * every test that runs after it — and the branch that matters most here is
	 * the one where none of them is, which is every ordinary site.
	 *
	 * @param array<string, string>|null $plugins Class name => display name.
	 */
	public static function conflict( ?array $plugins = null ): ?string {
		$plugins = null === $plugins
			? array( 'WooCommerce' => 'WooCommerce', 'bbPress' => 'bbPress' )
			: $plugins;

		foreach ( $plugins as $class => $name ) {
			if ( class_exists( $class ) ) {
				return sprintf(
					/* translators: %s: plugin name. */
					__( '%s already keeps customers out of the dashboard. Using both is safe; check where customers land after applying.', 'bettershield' ),
					$name
				);
			}
		}

		return null;
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function enforce( array $state ): void {
		add_action( 'admin_init', array( self::class, 'gate' ), 1 );
		add_filter( 'show_admin_bar', array( self::class, 'hide_bar' ) );
	}

	/**
	 * Whether what enforce() attaches is still attached on this request.
	 * Switched on is not the same as working: another plugin's
	 * remove_filter() leaves the item reading active with nothing in force.
	 *
	 * @param array<string, mixed> $state
	 */
	public static function is_enforced( array $state ): bool {
		unset( $state );

		return false !== has_action( 'admin_init', array( self::class, 'gate' ) )
			&& false !== has_filter( 'show_admin_bar', array( self::class, 'hide_bar' ) );
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function unenforce( array $state ): void {
		remove_action( 'admin_init', array( self::class, 'gate' ), 1 );
		remove_filter( 'show_admin_bar', array( self::class, 'hide_bar' ) );
	}

	public static function gate(): void {
		if ( ! self::should_restrict() || self::is_always_open() ) {
			return;
		}

		\BetterShield\Hardening\Monitor::queue( 'admin_area_access', true, true );
		wp_safe_redirect( home_url( '/' ) );
		exit;
	}

	/**
	 * @param mixed $show
	 */
	public static function hide_bar( $show ): bool {
		// A bar full of links to places the account cannot reach is worse than
		// no bar: every one of them is a redirect waiting to confuse somebody.
		return self::should_restrict() ? false : (bool) $show;
	}

	/**
	 * Whether the account making this request is one of the restricted ones.
	 *
	 * Public so the decision can be read without staging a request.
	 */
	public static function should_restrict(): bool {
		$state = \BetterShield\Hardening\Manager::instance()->item_state( 'admin_area_access' );
		return ! empty( $state['active'] ) && self::would_restrict( $state['options'] ?? array() );
	}

	public static function would_gate( array $options ): bool { return self::would_restrict( $options ) && ! self::is_always_open(); }

	public static function would_restrict( array $options ): bool {
		if ( ! is_user_logged_in() || wp_doing_ajax() || wp_doing_cron() ) {
			return false;
		}

		// Safe mode stands every enforcement down, and this is enforcement.
		if ( \BetterShield\Recovery\SafeMode::is_active() ) {
			return false;
		}

		/*
		 * The two accounts this can never apply to, guarded here rather than
		 * only at the point the roles are chosen: a role that gains the
		 * capability later must stop being restricted at that moment, not at
		 * the next time somebody edits the settings.
		 */
		if ( current_user_can( 'manage_options' ) || current_user_can( Capabilities::MANAGE ) ) {
			return false;
		}

		if ( is_multisite() && is_super_admin() ) {
			return false;
		}

		$roles = isset( $options['roles'] ) ? (array) $options['roles'] : array();

		if ( array() === array_intersect( (array) wp_get_current_user()->roles, $roles ) ) {
			return false;
		}

		/*
		 * Naming a role is not the same as naming an account. WordPress lets
		 * one account hold several roles, and a store or a membership plugin
		 * hands out a customer role beside whatever the person already had —
		 * so an editor who bought something was shut out of the dashboard they
		 * work in, by a setting whose whole purpose is to keep customers out
		 * of a place they have no work to do.
		 *
		 * Asked as what the account can do rather than what it is called. Any
		 * one of these means there is work here for them; a plain customer or
		 * subscriber has none of them and is still kept out.
		 */
		foreach ( self::WORKS_HERE as $capability ) {
			if ( current_user_can( $capability ) ) {
				return false;
			}
		}

		return true;
	}

	private static function is_always_open(): bool {
		global $pagenow;

		return in_array( (string) $pagenow, self::ALWAYS_OPEN, true );
	}

	/**
	 * Whether a role holds the rights that make restricting it meaningless.
	 *
	 * The same question enforcement asks of the account in front of it, put
	 * to a role instead. Anything this answers true for is neither offered
	 * nor accepted, because choosing it would change nothing.
	 */
	private static function role_can_manage( string $slug ): bool {
		$role = wp_roles()->get_role( $slug );

		if ( null === $role ) {
			return false;
		}

		foreach ( self::never_restricted() as $capability ) {
			if ( ! empty( $role->capabilities[ $capability ] ) ) {
				return true;
			}
		}

		return false;
	}
}
