<?php
/**
 * Hardening item: move the sign-in page to an address the owner chooses.
 *
 * What this does and does not do, stated the way the screen states it: it
 * cuts the automated bot traffic that hammers wp-login.php by name, and it
 * does not stop a targeted attacker, who has other ways to learn the address.
 * Quieter logs and fewer lockout events are the honest benefit.
 *
 * Entirely runtime: filters rewrite every URL core builds for wp-login.php
 * to the chosen address, a front-controller hook serves the real login page
 * there, and direct requests to wp-login.php get 404. No file is written and
 * no rewrite rule is added, so undo is instant.
 *
 * The lockout question is answered by safe mode, not by this item being
 * careful. An owner who forgets the address uses the recovery link exactly
 * as if locked out by 2FA: safe mode pauses all enforcement, wp-login.php
 * answers again, and the invariant test covers the sequence.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

use BetterShield\Hardening\Manager;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginUrl {

	/**
	 * Paths the slug must not shadow. Core namespaces, plus names whose only
	 * effect would be confusion.
	 *
	 * Names carrying a dot are not listed: SLUG_PATTERN admits letters,
	 * numbers, dashes and underscores only, and is checked first, so no such
	 * slug can ever reach this list.
	 */
	private const RESERVED = array(
		'wp-admin',
		'wp-content',
		'wp-includes',
		'wp-json',
		'wp-login',
		'wp-signup',
		'wp-activate',
		'feed',
		'embed',
		'admin',
	);

	/**
	 * Query keys WordPress itself dispatches on, which no public query var
	 * list carries: wp-admin and admin-post route on `action`, and REST is
	 * reached through `rest_route` on a site without pretty permalinks.
	 */
	private const RESERVED_QUERY_KEYS = array( 'action', 'rest_route' );

	/**
	 * The slug currently being enforced, set at boot from stored state.
	 */
	private static string $slug = '';

	/** Whether enforcing took core's admin shortcuts away, so reverting gives back only what it took. */
	private static bool $took_shortcuts = false;

	/**
	 * What a sign-in address may be made of.
	 *
	 * Held once and used twice — by the validator that refuses, and by the
	 * field that travels to the screen so the reader is told while they type
	 * rather than when the save fails. Two copies of a rule are two rules
	 * eventually, and this one decides whether somebody can reach their own
	 * sign-in form.
	 *
	 * Deliberately a plain character class: it has to mean the same thing to
	 * PHP and to a browser, and anything cleverer would only mean the same
	 * thing until it did not.
	 */
	public const SLUG_PATTERN = '^[a-z0-9_-]{1,200}$';

	/** The rule in words, for the field that shows it and the refusal alike. */
	public static function slug_rule(): string {
		return __( 'Use 1 to 200 characters: letters, numbers, dashes and underscores.', 'bettershield' );
	}

	/**
	 * The field that hides the dashboard in the same save, and its answer for
	 * doing so. Only the Protection screen's row answers it (`screen_only`):
	 * everything else that moves the address leaves the dashboard to its own
	 * switch.
	 */
	public const DASHBOARD_FIELD = 'admin_visitors';
	private const DASHBOARD_HIDE = 'hide';

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public static function fields(): array {
		return array(
			array(
				'key'         => 'slug',
				'label'       => __( 'New sign-in address', 'bettershield' ),
				'description' => __( 'Write the new address down somewhere outside this site. The usual sign-in page stops working.', 'bettershield' ),
				'placeholder' => 'sign-in',
				'required'    => true,
				'pattern'      => self::SLUG_PATTERN,
				// Stored lowercased, so the screen checks it lowercased too:
				// "MyLogin" is "mylogin", not a broken rule.
				'lowercase'    => true,
				// The words the screen says when the pattern is broken —
				// the same sentence the refusal below uses, so a reader who
				// meets both meets one message.
				'pattern_note' => self::slug_rule(),
			),
			array(
				'key'         => self::DASHBOARD_FIELD,
				'label'       => __( 'Signed-out visitors who open /wp-admin/', 'bettershield' ),
				'description' => __( '“See page not found” also turns on Dashboard privacy for visitors. Undoing this address turns it off again.', 'bettershield' ),
				'screen_only' => true,
				'default'     => self::DASHBOARD_HIDE,
				'choices'     => array(
					array(
						'value' => self::DASHBOARD_HIDE,
						'label' => __( 'See page not found', 'bettershield' ),
					),
					array(
						'value' => 'sign_in',
						'label' => __( 'Go to the sign-in page', 'bettershield' ),
					),
				),
			),
		);
	}

	/**
	 * Whether this save asked for the dashboard to be hidden along with it.
	 * Read before validate(), which keeps only what the address itself needs.
	 *
	 * @param array<string, mixed> $options What the caller sent.
	 */
	public static function asks_to_hide_dashboard( array $options ): bool {
		return self::DASHBOARD_HIDE === ( $options[ self::DASHBOARD_FIELD ] ?? '' );
	}

	/**
	 * The address being put back after a move that failed half way, for
	 * this request only. It was in use a moment ago, so content found there
	 * since is what the move was escaping, not a reason to leave the
	 * standard sign-in page answering instead. Every other rule still holds.
	 */
	private static ?string $restoring = null;

	/** Allow the address in use to be put back (null to stop). */
	public static function restoring( ?string $slug ): void {
		self::$restoring = null === $slug ? null : strtolower( trim( $slug ) );
	}

	/**
	 * Whether the settings document being planned or applied turns the
	 * dashboard privacy item on, for this request only: the note asking for
	 * it would otherwise be shown beside the change that makes it.
	 */
	private static bool $gate_coming = false;

	/**
	 * Run $work, the plan or apply of a settings document, with what that
	 * document sets taken into account here.
	 *
	 * Its address is treated as one being put back when another active
	 * plugin already answers at that address. Taking that address over keeps
	 * the one people already use: whatever lives there was already behind
	 * the other plugin's sign-in page, and the two can stand on one address
	 * while the other is still on. Any other address is left to the usual
	 * checks.
	 *
	 * And when it turns the dashboard privacy item on, the note asking for
	 * that item is not given.
	 *
	 * @param array<string, mixed> $document
	 * @param callable(): mixed    $work
	 * @return mixed What $work returned.
	 */
	public static function for_document( array $document, callable $work ) {
		$wanted = $document['hardening']['login_url'] ?? null;
		$slug   = is_array( $wanted ) && rest_sanitize_boolean( $wanted['active'] ?? false ) && is_scalar( $wanted['options']['slug'] ?? null )
			? strtolower( trim( (string) $wanted['options']['slug'] ) )
			: '';
		$take   = '' !== $slug && self::served_by_another_plugin( $slug );
		$gate   = $document['hardening']['admin_gate'] ?? null;
		$gate   = is_array( $gate ) && rest_sanitize_boolean( $gate['active'] ?? false );

		if ( ! $take && ! $gate ) {
			return $work();
		}

		$was_restoring = self::$restoring;
		$was_gate      = self::$gate_coming;

		if ( $take ) {
			self::$restoring = $slug;
		}

		if ( $gate ) {
			self::$gate_coming = true;
		}

		try {
			return $work();
		} finally {
			self::$restoring   = $was_restoring;
			self::$gate_coming = $was_gate;
		}
	}

	/**
	 * Why an address another plugin already answers at cannot be taken over,
	 * or null when it can: the rules for an address apply, but not the check
	 * for content already there, which that plugin's page was covering.
	 */
	public static function takeover_refusal( string $slug ): ?string {
		$slug            = strtolower( trim( $slug ) );
		$was             = self::$restoring;
		self::$restoring = $slug;

		try {
			$valid = self::validate( array( 'slug' => $slug ) );
		} finally {
			self::$restoring = $was;
		}

		return is_wp_error( $valid ) ? $valid->get_error_message() : null;
	}

	/**
	 * Whether this item is on at the address another active plugin answers
	 * at, as taking that address over leaves it: both answer there, and it
	 * keeps working whichever of them is switched off.
	 */
	public static function shares_its_address(): bool {
		$manager = Manager::instance();

		if ( ! $manager->is_active( 'login_url' ) ) {
			return false;
		}

		$slug = $manager->item_state( 'login_url' )['options']['slug'] ?? '';

		return is_string( $slug ) && '' !== $slug && self::served_by_another_plugin( $slug );
	}

	/** Whether an active plugin that moves the sign-in page answers at this address. */
	private static function served_by_another_plugin( string $slug ): bool {
		$ours = strtolower( untrailingslashit( (string) wp_parse_url( home_url( '/' . $slug ), PHP_URL_PATH ) ) );

		foreach ( \BetterShield\Onboarding\Coexistence::moved_sign_in_addresses() as $address ) {
			if ( strtolower( untrailingslashit( (string) wp_parse_url( $address, PHP_URL_PATH ) ) ) === $ours ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * @param array<string, mixed> $options
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function validate( array $options ) {
		$slug = isset( $options['slug'] ) ? strtolower( trim( (string) $options['slug'] ) ) : '';

		if ( 1 !== preg_match( '/' . self::SLUG_PATTERN . '/', $slug ) ) {
			return new \WP_Error( 'bettershield_bad_slug', self::slug_rule() );
		}

		if ( in_array( $slug, self::RESERVED, true ) || self::shadows_a_query_key( $slug ) ) {
			return new \WP_Error( 'bettershield_reserved_slug', __( 'That address is already part of WordPress. Choose another.', 'bettershield' ) );
		}

		// The decoy's path would answer with the sign-in form, and the decoy
		// would stop firing while its own test still said it matched. The
		// decoy refuses the sign-in address; this is the other direction.
		$decoy = \BetterShield\Agents\DecoyPage::report();
		if ( $decoy['enabled'] && $decoy['slug'] === $slug ) {
			return new \WP_Error( 'bettershield_slug_decoy', __( 'That address is your decoy URL (Agents › Agent surface). Choose another, or turn the decoy URL off first.', 'bettershield' ) );
		}

		/*
		 * On at an address another plugin answers at, ours may stay there
		 * but not move while that plugin is on: only one address could work.
		 */
		$competing = self::competing_plugin();
		if ( null !== $competing && self::shares_its_address() && ! self::served_by_another_plugin( $slug ) ) {
			return new \WP_Error(
				'bettershield_slug_competing',
				sprintf(
					/* translators: %s: plugin name. */
					__( '%s answers at your current sign-in address. Deactivate it before you move to another one.', 'bettershield' ),
					$competing
				)
			);
		}

		// Any public content already at that address — a page, a post, a
		// custom type, a category — would be shadowed by the sign-in form.
		if ( null !== self::$restoring && self::$restoring === $slug ) {
			return array( 'slug' => $slug );
		}

		$taken = null !== get_page_by_path( $slug, OBJECT, array_values( get_post_types( array( 'public' => true ) ) ) )
			|| 0 !== url_to_postid( home_url( '/' . $slug . '/' ) )
			|| null !== term_exists( $slug, 'category' )
			|| null !== term_exists( $slug, 'post_tag' );

		if ( $taken || self::routed_elsewhere( $slug ) || self::belongs_to_a_site( $slug ) ) {
			return new \WP_Error( 'bettershield_slug_taken', __( 'Something already lives at that address. Choose another.', 'bettershield' ) );
		}

		return array( 'slug' => $slug );
	}

	/** Whether WordPress keeps this name for itself. */
	public static function is_reserved_name( string $slug ): bool {
		return in_array( $slug, self::RESERVED, true );
	}

	/**
	 * A page or post about to be published at the sign-in address is given
	 * the next free one instead, as WordPress gives a second "store" page
	 * "store-2".
	 *
	 * The address is refused at apply when something lives there, and
	 * nothing stopped a page being published there afterwards: the sign-in
	 * form answered in its place, and every menu and sitemap link to the page
	 * handed out the address this item hides (#2081). Imports and plugins
	 * that create pages go through the same function.
	 *
	 * Only content that would answer at the address itself: a top-level
	 * page, or a post where posts are addressed by name alone.
	 *
	 * @param string $slug        The slug WordPress settled on.
	 * @param int    $post_id     The post.
	 * @param string $post_status Its status.
	 * @param string $post_type   Its type.
	 * @param int    $post_parent Its parent.
	 */
	public static function steer_post_slug( $slug, $post_id, $post_status, $post_type, $post_parent ) {
		if ( '' === self::$slug || ! is_string( $slug ) || strtolower( $slug ) !== self::$slug ) {
			return $slug;
		}

		$type = get_post_type_object( (string) $post_type );

		if ( ! $type instanceof \WP_Post_Type || ! $type->public ) {
			return $slug;
		}

		// A custom type answers under its own base (/docs/…), never at the
		// address itself.
		$at_the_root = 'page' === $type->name
			? 0 === (int) $post_parent
			: 'post' === $type->name && '/%postname%/' === trailingslashit( (string) get_option( 'permalink_structure' ) );

		if ( ! $at_the_root ) {
			return $slug;
		}

		// Content already published there keeps its address on its next save:
		// renamed, it and every page under it would move with no redirect.
		// The finding names it instead.
		$existing = (int) $post_id > 0 ? get_post( (int) $post_id ) : null;

		if ( $existing instanceof \WP_Post && 'publish' === $existing->post_status && strtolower( $existing->post_name ) === self::$slug ) {
			return $slug;
		}

		return wp_unique_post_slug( $slug . '-2', (int) $post_id, (string) $post_status, (string) $post_type, (int) $post_parent );
	}

	/**
	 * What a visitor would see at the sign-in address if the sign-in form
	 * were not there: published content, or a route of the site's own. Null
	 * where nothing else answers there.
	 *
	 * The address is refused at apply when something lives there; this asks
	 * again later, for what reached it another way: a page from before the
	 * slug filter above, a direct write, a plugin's own route (#2081).
	 *
	 * @param string $slug The address the sign-in page answers at.
	 * @return array{address: string, content: string, type: string, id: int}|null
	 */
	public static function shadowed_content( string $slug ): ?array {
		if ( '' === $slug || '' === (string) get_option( 'permalink_structure' ) ) {
			return null;
		}

		$id   = url_to_postid( home_url( '/' . $slug . '/' ) );
		$post = $id > 0 ? get_post( $id ) : null;

		if ( $post instanceof \WP_Post && 'publish' === $post->post_status ) {
			return array(
				'address' => self::url_for( $slug ),
				'content' => html_entity_decode( get_the_title( $post ), ENT_QUOTES, 'UTF-8' ),
				'type'    => (string) $post->post_type,
				'id'      => (int) $post->ID,
			);
		}

		if ( self::routed_elsewhere( $slug ) ) {
			return array(
				'address' => self::url_for( $slug ),
				'content' => '',
				'type'    => 'route',
				'id'      => 0,
			);
		}

		return null;
	}

	/**
	 * Whether WordPress already serves this address from one of its own
	 * routes: a year's archive at /2026/, say. Content by name is asked about
	 * above; this is the rest of what the rewrite rules answer.
	 *
	 * Matched as `WP::parse_request()` matches, first rule wins. A rule that
	 * only looks a page or post up by name answers for every address that
	 * has no route of its own, so it counts only when that content exists,
	 * which the checks above have already asked.
	 */
	private static function routed_elsewhere( string $slug ): bool {
		global $wp_rewrite;

		if ( ! $wp_rewrite instanceof \WP_Rewrite || ! $wp_rewrite->using_permalinks() ) {
			return false;
		}

		foreach ( (array) $wp_rewrite->wp_rewrite_rules() as $match => $query ) {
			if ( 1 !== preg_match( '#^' . $match . '#', $slug, $matches ) && 1 !== preg_match( '#^' . $match . '#', $slug . '/', $matches ) ) {
				continue;
			}

			parse_str( (string) wp_parse_url( \WP_MatchesMapRegex::apply( (string) $query, $matches ), PHP_URL_QUERY ), $vars );

			$routes = array_diff( array_keys( array_filter( $vars, static fn( $value ): bool => '' !== $value ) ), array( 'pagename', 'name', 'attachment', 'page' ) );

			return array() !== $routes;
		}

		return false;
	}

	/**
	 * Whether the address is a path WordPress hands to another site of a
	 * subdirectory network before this one sees the request: a site's own
	 * path, or a name core keeps back for the main site's routes (#2227).
	 */
	private static function belongs_to_a_site( string $slug ): bool {
		if ( ! is_multisite() || is_subdomain_install() || '' === (string) get_option( 'permalink_structure' ) ) {
			return false;
		}

		if ( is_main_site() && in_array( $slug, get_subdirectory_reserved_names(), true ) ) {
			return true;
		}

		$site = get_site();

		if ( ! $site instanceof \WP_Site ) {
			return true;
		}

		// Asked the way core routes a subdirectory network: one segment past
		// the network's path. On a subsite that segment is its own, so the
		// address stays its own whatever follows.
		$network  = get_network();
		$segments = 1 + count( array_filter( explode( '/', trim( $network instanceof \WP_Network ? $network->path : '/', '/' ) ) ) );
		$found    = get_site_by_path( $site->domain, trailingslashit( $site->path ) . $slug . '/', $segments );

		return $found instanceof \WP_Site && (int) $found->blog_id !== (int) $site->blog_id;
	}

	/**
	 * Whether the slug is also a query key WordPress reads for its own
	 * routing.
	 *
	 * On a site without pretty permalinks the chosen address is a query key,
	 * so a slug that WordPress already dispatches on would turn every URL
	 * carrying that key into the sign-in page — `?page=` alone would take
	 * every plugin settings screen on the site with it. The live list is read
	 * rather than copied, so a query var a theme or plugin registered counts
	 * too and the answer cannot drift from core's.
	 */
	private static function shadows_a_query_key( string $slug ): bool {
		if ( in_array( $slug, self::RESERVED_QUERY_KEYS, true ) ) {
			return true;
		}

		$wp = isset( $GLOBALS['wp'] ) ? $GLOBALS['wp'] : null;

		return $wp instanceof \WP && in_array( $slug, (array) $wp->public_query_vars, true );
	}

	/**
	 * @param array<string, mixed> $options Validated.
	 * @return array{tokens: string[], notes: string[]}
	 */
	public static function apply( array $options ): array {
		return array(
			'tokens' => array(),
			'notes'  => array(
				// The address itself is not here: it is live state, and a
				// sentence stored at apply time would go stale the moment the
				// site address changed. summary() answers with it instead.
				__( 'Keep a copy off this site. If lost, the recovery link restores the standard address.', 'bettershield' ),
			),
		);
	}

	/**
	 * What applying this particular answer would produce, said before it is
	 * applied. The generic effect lines describe the shape of the change; this
	 * names the address the owner just typed.
	 *
	 * @param array<string, mixed> $options Validated.
	 * @return string[]
	 */
	public static function preview( array $options ): array {
		$slug = isset( $options['slug'] ) ? (string) $options['slug'] : '';

		if ( '' === $slug ) {
			return array();
		}

		return array(
			sprintf(
				/* translators: %s: the sign-in URL the chosen address would produce. */
				__( 'Serves the sign-in page at %s.', 'bettershield' ),
				self::url_for( $slug )
			),
		);
	}

	/**
	 * The address the sign-in page answers at while this is applied — the one
	 * thing an owner opens this item to read.
	 *
	 * @param array<string, mixed> $state
	 */
	public static function summary( array $state ): ?string {
		$slug = isset( $state['options']['slug'] ) ? (string) $state['options']['slug'] : '';

		if ( empty( $state['active'] ) || '' === $slug ) {
			return null;
		}

		return self::url_for( $slug );
	}

	/**
	 * @param array<string, mixed> $state Unused; nothing persists but the option row.
	 * @return true
	 */
	public static function revert( array $state ) {
		return true;
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function enforce( array $state ): void {
		$slug = isset( $state['options']['slug'] ) ? (string) $state['options']['slug'] : '';

		if ( '' === $slug ) {
			return;
		}

		self::$slug = $slug;

		// Every URL core builds for wp-login.php comes out of site_url() or
		// network_site_url(); rewriting there catches login, logout, lost
		// password, the login form's own postback, and emailed links alike.
		add_filter( 'site_url', array( self::class, 'rewrite_login_url' ), 10, 3 );
		add_filter( 'network_site_url', array( self::class, 'rewrite_login_url' ), 10, 3 );
		add_filter( 'wp_redirect', array( self::class, 'rewrite_redirect' ) );
		add_filter( 'redirect_canonical', array( self::class, 'refuse_canonical_login' ) );
		add_filter( 'login_url', array( self::class, 'blank_link_on_404' ), 20, 3 );
		add_filter( 'register_url', array( self::class, 'blank_link_on_404' ), 20 );
		add_filter( 'lostpassword_url', array( self::class, 'blank_link_on_404' ), 20 );

		// Content published later at the address is given another one.
		add_filter( 'wp_unique_post_slug', array( self::class, 'steer_post_slug' ), 10, 5 );

		// Serve the login page at the chosen address, and refuse the old one.
		add_action( 'wp_loaded', array( self::class, 'maybe_serve_login' ) );
		add_action( 'init', array( self::class, 'maybe_refuse_direct_login' ), 1 );

		/*
		 * Core answers a 404 on /login, /login.php, /admin and /dashboard by
		 * redirecting to wp_login_url() or admin_url(), and with the address
		 * rewritten above that redirect carries the new one. One request to a
		 * path every scanner already tries handed it out, with the dashboard
		 * hidden and nothing on the card saying so. Those paths now answer as
		 * any other unknown path does.
		 */
		if ( remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 ) ) {
			self::$took_shortcuts = true;
		}
	}

	/**
	 * Whether what enforce() attaches is still attached on this request.
	 * Switched on is not the same as working: another plugin's
	 * remove_filter() leaves the item reading active with nothing in force.
	 *
	 * @param array<string, mixed> $state
	 */
	public static function is_enforced( array $state ): bool {
		if ( '' === (string) ( $state['options']['slug'] ?? '' ) ) {
			return false;
		}

		return false !== has_filter( 'site_url', array( self::class, 'rewrite_login_url' ) )
			&& false !== has_filter( 'network_site_url', array( self::class, 'rewrite_login_url' ) )
			&& false !== has_filter( 'wp_redirect', array( self::class, 'rewrite_redirect' ) )
			&& false !== has_filter( 'redirect_canonical', array( self::class, 'refuse_canonical_login' ) )
			&& false !== has_action( 'wp_loaded', array( self::class, 'maybe_serve_login' ) )
			&& false !== has_action( 'init', array( self::class, 'maybe_refuse_direct_login' ) );
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function unenforce( array $state ): void {
		self::$slug = '';

		remove_filter( 'site_url', array( self::class, 'rewrite_login_url' ), 10 );
		remove_filter( 'network_site_url', array( self::class, 'rewrite_login_url' ), 10 );
		remove_filter( 'wp_redirect', array( self::class, 'rewrite_redirect' ) );
		remove_filter( 'redirect_canonical', array( self::class, 'refuse_canonical_login' ) );
		remove_filter( 'login_url', array( self::class, 'blank_link_on_404' ), 20 );
		remove_filter( 'register_url', array( self::class, 'blank_link_on_404' ), 20 );
		remove_filter( 'lostpassword_url', array( self::class, 'blank_link_on_404' ), 20 );
		remove_filter( 'wp_unique_post_slug', array( self::class, 'steer_post_slug' ), 10 );
		remove_action( 'wp_loaded', array( self::class, 'maybe_serve_login' ) );
		remove_action( 'init', array( self::class, 'maybe_refuse_direct_login' ), 1 );
		remove_action( 'wp_loaded', array( self::class, 'draw_missing_page' ), PHP_INT_MAX );

		if ( self::$took_shortcuts ) {
			add_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );
			self::$took_shortcuts = false;
		}
	}

	/**
	 * Another plugin that moves or hides the sign-in page. Two features
	 * rewriting the same address do not compose: whichever runs last wins,
	 * and the owner may end up with an address neither one told them about.
	 *
	 * Read from the same map Quick Setup's coexistence step reads, so the
	 * step's "BetterShield's own option stays off" and this warning name the
	 * same plugins: by the name on the Plugins screen, and only while that
	 * plugin's own switch for moving the address is on. A list of its own,
	 * checked by class, warned for plugins with their move switched off and
	 * said nothing for others the step credited.
	 */
	public static function competing_plugin(): ?string {
		$names = \BetterShield\Onboarding\Coexistence::doing( 'login_url' );

		return array() === $names ? null : implode( ', ', $names );
	}

	/**
	 * Not while another plugin moves the address: only the last one to run
	 * answers, so the address the owner saved there stops working (#2767).
	 * Taking over the address that plugin answers at is the exception: both
	 * then answer at the one address, and it keeps working whichever of them
	 * is switched off (see for_document()).
	 *
	 * @return array{available: bool, note: ?string, reason?: string}
	 */
	public static function availability(): array {
		$competing = self::competing_plugin();

		/*
		 * Already on at the address that plugin answers at, it isn't the
		 * other plugin's to handle: both answer there. Moving it to another
		 * address while that plugin is on is refused by validate().
		 */
		if ( null === $competing || ( null !== self::$restoring && self::served_by_another_plugin( self::$restoring ) ) || self::shares_its_address() ) {
			return array(
				'available' => true,
				'note'      => null,
			);
		}

		return array(
			'available' => false,
			'reason'    => 'other_plugin',
			'note'      => sprintf(
				/* translators: %s: plugin name. */
				__( '%s already moves your sign-in page. Only one address can work, so turn that plugin’s address off before you use this one.', 'bettershield' ),
				$competing
			),
		);
	}

	public static function conflict(): ?string {
		/*
		 * Every note that applies, in one answer, the competing plugin's
		 * first. Each case used to return on its own, so with a cache plugin
		 * active the card never said that /wp-admin/ hands out the new
		 * address, which is the note that keeps this fix from undoing itself.
		 */
		$notes = array();

		// Off here, availability() already says this. On, it's a clash to sort out,
		// unless both answer at the one address, as taking that address over leaves them.
		$competing = self::competing_plugin();
		if ( null !== $competing && \BetterShield\Hardening\Manager::instance()->is_active( 'login_url' ) ) {
			$notes[] = self::shares_its_address()
				? sprintf(
					/* translators: %s: plugin name. */
					__( '%s answers at the same sign-in address, so the two don’t clash. Deactivating it leaves this address working.', 'bettershield' ),
					$competing
				)
				: sprintf(
					/* translators: %s: plugin name. */
					__( '%s also moves your sign-in page, and only one address can work. Turn one of them off.', 'bettershield' ),
					$competing
				);
		}

		$caches = array(
			'WP_ROCKET_VERSION'   => 'WP Rocket',
			'W3TC'                => 'W3 Total Cache',
			'WPCACHEHOME'         => 'WP Super Cache',
			'LSCWP_V'             => 'LiteSpeed Cache',
		);

		foreach ( $caches as $constant => $name ) {
			if ( defined( $constant ) ) {
				$notes[] = sprintf(
					/* translators: %s: caching plugin name. */
					__( 'In %s, exclude the new sign-in address from caching, or the sign-in form may stop working.', 'bettershield' ),
					$name
				);
				break;
			}
		}

		if ( is_multisite() ) {
			$notes[] = __( 'On this network, the address changes for this site only.', 'bettershield' );
		}

		// The rename rewrites every sign-in link WordPress builds, and one of
		// those is the redirect a signed-out visitor gets from /wp-admin/. So
		// anyone who asks for the dashboard is handed the new address — which
		// is most of what this item was for. The row offers to hide it in the
		// same save, as a choice the owner can see; nothing else turns the
		// gate on, so a card still says so whenever it is off.
		if ( ! self::$gate_coming && ! Manager::instance()->is_active( 'admin_gate' ) ) {
			$notes[] = Manager::instance()->is_active( 'login_url' )
				? __( 'Signed-out visitors who open /wp-admin/ are sent to the new address. Also turn on "Dashboard privacy for visitors".', 'bettershield' )
				: __( 'Signed-out visitors who open /wp-admin/ are sent to the new address unless "Dashboard privacy for visitors" is on.', 'bettershield' );
		}

		// Core's comment form and reply links send a signed-out visitor to
		// sign in, so with sign-in required to comment every post prints the
		// address. Hiding them would stop members commenting (#2223).
		if ( get_option( 'comment_registration' ) ) {
			$notes[] = __( 'Comments here need a sign-in, so every post’s comment form links to the new address.', 'bettershield' );
		}

		return array() === $notes ? null : implode( ' ', $notes );
	}

	/* ---- runtime --------------------------------------------------------- */

	/**
	 * The sign-in URL for a slug, in the form this site can actually serve:
	 * a path when pretty permalinks route requests, a query otherwise.
	 */
	public static function url_for( string $slug ): string {
		if ( get_option( 'permalink_structure' ) ) {
			return self::base_url() . $slug . '/';
		}

		return add_query_arg( $slug, '', self::base_url() );
	}

	/**
	 * The address the sign-in address is built on, with a trailing slash.
	 * Building it and answering it both read this, so they can't disagree.
	 */
	private static function base_url(): string {
		$home = home_url( '/' );

		/**
		 * Filters the base the sign-in address is built on and answered at,
		 * for a site that serves it under a language prefix, say.
		 *
		 * @param string $home The site's home address, with a trailing slash.
		 */
		$base = apply_filters( 'bettershield_login_home_url', $home );

		return is_string( $base ) && '' !== $base ? trailingslashit( $base ) : $home;
	}

	/**
	 * Rewrite any URL core built for wp-login.php to the chosen address,
	 * carrying the query along.
	 *
	 * @param string      $url    The URL site_url() built.
	 * @param string      $path   The path it was asked for.
	 * @param string|null $scheme Unused; part of the filter signature.
	 */
	public static function rewrite_login_url( string $url, string $path = '', $scheme = null ): string {
		if ( '' === self::$slug || ! self::is_login_script_url( $url ) || self::keeps_address_private() ) {
			return $url;
		}

		// Interim logins and postbacks carry their query; keep it.
		$query = (string) wp_parse_url( $url, PHP_URL_QUERY );

		// A password-protected post's form posts to wp-login.php on every
		// public page and in every feed. Moved, it printed the hidden address
		// for anybody to read, so it stays where it was and is let through
		// there, as signing out is.
		if ( self::is_postpass( $query ) ) {
			return $url;
		}

		$new = self::url_for( self::$slug );

		return '' === $query ? $new : $new . ( str_contains( $new, '?' ) ? '&' : '?' ) . $query;
	}

	/**
	 * Whether this request answers a signed-out visitor from a place that
	 * must not name the chosen address, so a sign-in URL keeps its old name.
	 *
	 * The install script runs network-active plugins and sits outside the
	 * dashboard gate, and it answers anybody with a link to sign in. Only that
	 * script: the activation script also installs, and its links are real.
	 *
	 * A form plugin's preview address is a public URL that sends a signed-out
	 * visitor to sign in from the front end, where the gate does not act. The
	 * sign-in page itself is excepted: a form there has to post to it.
	 *
	 * A signed-out 404 is what a scanner gets for guessing, so links and sign-in
	 * forms a theme prints on one do not name the address either.
	 */
	private static function keeps_address_private(): bool {
		global $pagenow;

		if ( 'install.php' === $pagenow || self::is_signed_out_404() ) {
			return true;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- only whether the parameter is present; nothing is read from it.
		if ( ! isset( $_GET['gf_page'] ) || 'wp-login.php' === $pagenow || ! class_exists( 'GFForms', false ) ) {
			return false;
		}

		// A URL can be built before pluggable functions are loaded.
		return function_exists( 'is_user_logged_in' ) && ! is_user_logged_in();
	}

	/** Asked only once the query has run, since is_404() means nothing before it. */
	private static function is_signed_out_404(): bool {
		return did_action( 'wp' ) > 0 && is_404() && ! is_user_logged_in();
	}

	/**
	 * A sign-in, register or lost-password link on a signed-out 404 page goes
	 * nowhere. A sign-in redirect keeps a real address, under its old name:
	 * a redirect to "#" would strand the visitor on the page it came from.
	 *
	 * @param string $url          The link.
	 * @param string $redirect     Where to return afterward; unused.
	 * @param bool   $force_reauth Whether auth_redirect() is asking.
	 */
	public static function blank_link_on_404( $url, $redirect = '', $force_reauth = false ) {
		if ( '' === self::$slug || $force_reauth || ! self::is_signed_out_404() ) {
			return $url;
		}

		return '#';
	}

	/**
	 * Redirects to wp-login.php — auth_redirect() above all — go to the
	 * chosen address instead.
	 *
	 * Unlike the two URL filters, which only ever see addresses this site
	 * built for itself, this one sees every redirect the site issues, to any
	 * host. A substring match on the whole location therefore caught another
	 * site's sign-in page — a sister site, a central sign-in, any integration
	 * that sends somebody to a login elsewhere — and sent the visitor here
	 * instead, carrying the other site's query string. So the host is checked
	 * first, and a redirect that leaves this site is left alone.
	 */
	public static function rewrite_redirect( string $location ): string {
		if ( '' === self::$slug || ! self::is_login_script_url( $location ) ) {
			return $location;
		}

		$host = (string) wp_parse_url( $location, PHP_URL_HOST );

		if ( '' !== $host ) {
			/*
			 * This site's own two hosts, and not the network's. `url_for()`
			 * always builds this subsite's address, so a redirect aimed at the
			 * network main login — central sign-in, a sister-site integration,
			 * some multisite flows — was rewritten to a different site,
			 * carrying the other site's query string. On subdomain and
			 * domain-mapped networks `network_site_url()` is another site's
			 * host, which is exactly the case the host check exists to leave
			 * alone; on subdirectory networks it equals `home_url()`'s host,
			 * so dropping it changes nothing there.
			 */
			$ours = array_filter(
				array(
					strtolower( (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST ) ),
					strtolower( (string) wp_parse_url( site_url( '/' ), PHP_URL_HOST ) ),
				)
			);

			if ( ! in_array( strtolower( $host ), $ours, true ) ) {
				return $location;
			}
		}

		return self::rewrite_login_url( $location );
	}

	/**
	 * No canonical redirect to wp-login.php.
	 *
	 * Core's canonical redirect tidies a request into the address it should
	 * have used: /index.php/wp-login.php becomes /wp-login.php. The redirect
	 * filter above then rewrote that to the moved address, so a request that
	 * never reached the sign-in page was handed it. A canonical redirect to
	 * the old name is canceled, and the request answers as the unknown path
	 * it is. maybe_refuse_direct_login() refuses the paths known to do this
	 * before the redirect is built; this catches any spelling it does not.
	 *
	 * @param string|false $redirect_url The address core would redirect to.
	 * @return string|false
	 */
	public static function refuse_canonical_login( $redirect_url ) {
		if ( '' === self::$slug || ! is_string( $redirect_url ) ) {
			return $redirect_url;
		}

		return self::names_login_script( (string) wp_parse_url( $redirect_url, PHP_URL_PATH ) ) ? false : $redirect_url;
	}

	/**
	 * Whether a URL is one for wp-login.php itself: its path ends in it.
	 *
	 * Core builds sign-in URLs only this way. Matched anywhere in the URL,
	 * any redirect whose query or a later path segment merely carried the
	 * name — a canonical redirect of /a-post/?x=wp-login.php, or of
	 * /index.php/wp-login.php;x — was rewritten to the moved address and
	 * handed it to whoever asked.
	 */
	private static function is_login_script_url( string $url ): bool {
		$path = (string) wp_parse_url( $url, PHP_URL_PATH );

		return '/wp-login.php' === strtolower( (string) strrchr( '/' . $path, '/' ) );
	}

	/** Whether any segment of a path names wp-login.php, in any case or encoding. */
	private static function names_login_script( string $path ): bool {
		foreach ( explode( '/', $path ) as $segment ) {
			if ( 'wp-login.php' === strtolower( trim( rawurldecode( $segment ) ) ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether the current request asks for the chosen address.
	 *
	 * Public and argument-taking so the decision is testable without a
	 * request: pass the request path and query.
	 *
	 * The query form is honored only where url_for() actually hands it out —
	 * at the site root, with plain permalinks, with an empty value. Honored
	 * more widely than it is issued, any URL carrying the key becomes the
	 * sign-in page: /wp-admin/admin.php?page=… would take every settings
	 * screen on the site with it, and an ordinary post URL with the key
	 * appended would serve the form under a public address.
	 *
	 * @param array<string, mixed> $query
	 */
	public static function is_login_request( string $request_path, array $query ): bool {
		if ( '' === self::$slug ) {
			return false;
		}

		$prefix = untrailingslashit( (string) wp_parse_url( self::base_url(), PHP_URL_PATH ) );

		if ( '' !== $prefix && 0 !== strncasecmp( $request_path, $prefix, strlen( $prefix ) ) ) {
			return false;
		}

		$relative = trim( '/' . ltrim( substr( $request_path, strlen( $prefix ) ), '/' ), '/' );

		/*
		 * In any letter case, as the site's other addresses answer. The slug
		 * is stored lowercased, so an owner who chose "SideDoor" and typed it
		 * that way was shown a 404 with the standard sign-in page closed
		 * (#2078).
		 */
		if ( strtolower( $relative ) === self::$slug ) {
			return true;
		}

		if ( '' !== $relative || '' !== (string) get_option( 'permalink_structure' ) ) {
			return false;
		}

		foreach ( $query as $key => $value ) {
			if ( strtolower( (string) $key ) === self::$slug ) {
				return is_string( $value ) && '' === $value;
			}
		}

		return false;
	}

	/**
	 * Serve wp-login.php at the chosen address.
	 */
	public static function maybe_serve_login(): void {
		// wp_loaded fires on every request that boots WordPress, admin screens
		// and background dispatchers included. None of them is ever the chosen
		// address, and serving a sign-in form in place of their response would
		// end the request they were making.
		if ( is_admin() || wp_doing_ajax() || wp_doing_cron() ) {
			return;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- path compared against a fixed slug; nothing is stored or echoed.
		$request_path = (string) wp_parse_url( isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '', PHP_URL_PATH );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- routing on the address, not handling a submitted action.
		if ( ! self::is_login_request( $request_path, $_GET ) ) {
			return;
		}

		$signed_in_to = self::signed_in_destination();

		if ( null !== $signed_in_to ) {
			nocache_headers();
			wp_safe_redirect( $signed_in_to );
			exit;
		}

		/*
		 * wp-login.php is written to run at the top level, where its variables
		 * are globals. Required from inside a method they would be locals of
		 * this method, and the file's own functions — login_header() reaches
		 * for $error, $interim_login and $action, login_footer() for
		 * $interim_login — would be reading different variables entirely: the
		 * header loses the error it was meant to print, and the form reads
		 * variables nothing ever set. Declaring them here hands the file the
		 * real globals, which is what it would have had.
		 */
		global $pagenow, $action, $error, $errors, $interim_login, $user_login;

		$pagenow = 'wp-login.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- wp-login.php and everything hooked to it read this to know where they are.

		require_once ABSPATH . 'wp-login.php';
		exit;
	}

	/**
	 * Where someone already signed in goes instead of the sign-in form: the
	 * dashboard, or the address they were heading to when it is on this site.
	 * Null when the form has to answer: a sign-in being posted, an action such
	 * as signing out or a password reset, the dashboard asking for the
	 * password again, and the small sign-in window.
	 *
	 * Asked only on a request that isn't posting, so a form left open in
	 * another tab still signs in.
	 */
	public static function signed_in_destination(): ?string {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- routing on the address; nothing is stored, and the destination is validated.
		if (
			! is_user_logged_in()
			|| ( isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'] )
			|| isset( $_REQUEST['action'] )
			|| ! empty( $_REQUEST['reauth'] )
			|| ! empty( $_REQUEST['interim-login'] )
		) {
			return null;
		}

		$asked = isset( $_REQUEST['redirect_to'] ) && is_string( $_REQUEST['redirect_to'] ) ? wp_unslash( $_REQUEST['redirect_to'] ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		// An empty address validates as empty, which would redirect nowhere.
		$to = '' === $asked ? admin_url() : wp_validate_redirect( $asked, admin_url() );

		/**
		 * Filters where someone already signed in goes from the sign-in
		 * address. Sent with wp_safe_redirect(), so it has to be on this site.
		 *
		 * @param string $to      The dashboard, or the redirect_to they asked for.
		 * @param int    $user_id Who is signed in.
		 */
		$filtered = apply_filters( 'bettershield_login_signed_in_redirect', $to, get_current_user_id() );

		return is_string( $filtered ) && '' !== $filtered ? $filtered : $to;
	}

	/**
	 * 404 for wp-login.php reached by its old name, and for the sign-up and
	 * retired registration scripts that would redirect to the new one. Runs
	 * early on init so nothing hooked to the login page fires first.
	 *
	 * Our own serve needs no exemption here: init has already fired by the
	 * time wp_loaded runs, so nothing re-enters this after $pagenow is set to
	 * wp-login.php for the include.
	 */
	public static function would_refuse_direct_login(): bool {
		/*
		 * The chosen address always answers. Another plugin that serves a
		 * sign-in page sets $pagenow to wp-login.php on its own address as
		 * early as plugins_loaded; when that address is ours too, reading
		 * $pagenow alone refused it, and nobody could sign in (#2873).
		 */
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- routing on the address, not handling a submitted action.
		if ( self::is_login_request( self::request_path(), $_GET ) ) {
			return false;
		}

		if ( ! self::names_a_refused_path() ) {
			return false;
		}

		/**
		 * Filters whether a path the moved sign-in page closes stays closed.
		 * Asked only for those paths, and never for the chosen address. Return
		 * false to keep a path open; on /wp-login.php that reopens the old
		 * address.
		 *
		 * @param bool   $refuse Whether it is refused. Always true when asked.
		 * @param string $path   The request path.
		 */
		return (bool) apply_filters( 'bettershield_login_refuse', true, self::request_path() );
	}

	/** Whether this request is for a path the moved sign-in page closes. */
	private static function names_a_refused_path(): bool {
		global $pagenow;

		/*
		 * On a single site core's sign-up script does nothing but redirect to
		 * the registration address, which is the moved one, whether
		 * registration is open or not — so anyone who asked for it was handed
		 * the address this item hides. It goes the way of the old address. On
		 * a network it is the network's own sign-up page, and is left alone.
		 */
		if ( 'wp-signup.php' === $pagenow && ! is_multisite() ) {
			return true;
		}

		/*
		 * Nor core's retired registration script. The file is long gone, but a
		 * rewrite rule still routes any path ending in its name to the front
		 * page, and the canonical redirect then sends the visitor on to the
		 * registration address, the moved one, whether registration is open or
		 * not. The script never runs, so it is read off the address rather
		 * than off $pagenow. On a network that redirect goes to the network's
		 * sign-up page, which names nothing this item hides.
		 */
		if ( ! is_multisite() && self::asks_for_register_script() ) {
			return true;
		}

		/*
		 * Nor wp-login.php named after another script. /index.php/wp-login.php
		 * runs index.php wherever the server passes path info on, and core's
		 * canonical redirect then sends the visitor to /wp-login.php, which
		 * the redirect filter rewrote to the moved address (#1842). The old
		 * name is refused wherever it appears in the path, as it is when
		 * wp-login.php itself answers.
		 */
		if ( 'wp-login.php' !== $pagenow && ! self::names_login_script( self::request_path() ) ) {
			return false;
		}

		// A signed-in user's logout must keep working even from the old
		// address: refusing it would strand a session nobody can end.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read to route, not to act; wp-login.php checks the nonce itself.
		$action = isset( $_GET['action'] ) ? sanitize_key( wp_unslash( (string) $_GET['action'] ) ) : '';
		if ( 'logout' === $action && is_user_logged_in() ) {
			return false;
		}

		// A visitor entering a protected post's password: the form posts
		// here so that it never names the moved address (see above).
		if ( 'postpass' === $action && isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'] && self::only_postpass_requested() ) {
			return false;
		}

		return true;
	}

	/**
	 * Has this request carry on as one for an address nothing lives at, with
	 * the theme drawn once everything has loaded.
	 */
	private static function answer_as_a_missing_page(): void {
		global $pagenow;

		$pagenow = 'index.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- the script asked for is not answering; core and the theme read this.

		// The request parser prefers path info, which still names the old address.
		unset( $_SERVER['PATH_INFO'] );
		$_SERVER['REQUEST_URI'] = trailingslashit( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ) ) . str_repeat( '-/', 10 );

		add_action( 'wp_loaded', array( self::class, 'draw_missing_page' ), PHP_INT_MAX );
	}

	/**
	 * The theme's not-found page, ending the request. Runs last on wp_loaded,
	 * before the script that was asked for carries on.
	 */
	public static function draw_missing_page(): void {
		global $wp_query;

		if ( ! defined( 'WP_USE_THEMES' ) ) {
			define( 'WP_USE_THEMES', true );
		}

		wp();

		// A query string or plain permalinks can still find something.
		if ( ! $wp_query->is_404() ) {
			$wp_query->set_404();
		}

		status_header( 404 );
		nocache_headers();

		require_once ABSPATH . WPINC . '/template-loader.php';
		exit;
	}

	/** Whether this request names core's retired registration script, at any depth. */
	private static function asks_for_register_script(): bool {
		return 'wp-register.php' === strtolower( rawurldecode( basename( self::request_path() ) ) );
	}

	/** The path of the current request, as the browser sent it. */
	private static function request_path(): string {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared against fixed names; nothing is stored or echoed.
		return (string) wp_parse_url( isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '', PHP_URL_PATH );
	}

	/**
	 * Whether every place wp-login.php could read its action from names the
	 * password form. It acts on `$_REQUEST['action']`, where a posted field
	 * or a cookie outranks the query string, so a query of `action=postpass`
	 * with another action posted would be served the sign-in form at the old
	 * address, and the form names the moved one.
	 */
	private static function only_postpass_requested(): bool {
		// phpcs:ignore WordPress.Security.NonceVerification -- read to route, not to act; compared only.
		foreach ( array( $_REQUEST, $_POST, $_COOKIE ) as $source ) {
			if ( isset( $source['action'] ) && 'postpass' !== $source['action'] ) {
				return false;
			}
		}

		return true;
	}

	/** Whether a wp-login.php query is the protected-post password form's. */
	private static function is_postpass( string $query ): bool {
		parse_str( $query, $vars );

		return 'postpass' === ( $vars['action'] ?? '' );
	}

	public static function maybe_refuse_direct_login(): void {
		if ( ! self::would_refuse_direct_login() ) { return; }

		// Anything but a posted form looks like every other missing page, so
		// the move doesn't stand out. A post is what password-guessing bots
		// send, so it keeps the plain page, which costs no theme render.
		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || 'POST' !== $_SERVER['REQUEST_METHOD'] ) {
			self::answer_as_a_missing_page();

			return;
		}

		status_header( 404 );
		nocache_headers();

		wp_die(
			esc_html__( 'This page is not available.', 'bettershield' ),
			esc_html__( 'Not found', 'bettershield' ),
			array( 'response' => 404 )
		);
	}
}
