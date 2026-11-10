<?php
/**
 * The network's own screen, in Network Admin.
 *
 * Without this, a network administrator has to open each subsite's dashboard
 * one at a time to learn anything at all about it. It is the same application
 * the per-site screens are, mounted against routes that read the network's own
 * tables: every site's posture on one page, where the move to the shared
 * tables stands, the policies set above every site, and the one link that
 * opens all of them.
 *
 * **Reading a network is expensive and the roll-up is cached.** Switching into
 * a hundred subsites to read two options each is not something to do on every
 * page load, so the roll-up is built once and kept for a while, with a control
 * to rebuild it. The screen says how old the figures are rather than implying
 * they are live.
 *
 * **Fast-moving state is deliberately not in it.** Where each site stands in
 * the migration comes from the network option on every request, because a
 * progress figure an hour behind the thing it describes is worse than none.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Admin;

use BetterShield\Audit\Auditor;
use BetterShield\Database\Schema;
use BetterShield\Recovery\OfflineCodes;
use BetterShield\Recovery\RecoveryLink;
use BetterShield\Support\Areas;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Network {

	private const TRANSIENT = 'bettershield_network_rollup';

	/** How long a roll-up stands before it is rebuilt. */
	private const FRESH_SECONDS = 3600;

	/**
	 * How many subsites one page walks.
	 *
	 * Switching into every site of a large network in one request is what a
	 * page cannot afford, so the walk is paged: this many sites a request, in
	 * site order, the next page asked for by the last site's id.
	 */
	public const MAX_SITES = 200;

	/**
	 * Page hooks returned by registration, so assets load on our screens only.
	 *
	 * @var string[]
	 */
	private static array $hooks = array();

	public static function register(): void {
		if ( ! is_multisite() ) {
			return;
		}

		add_action( 'network_admin_menu', array( self::class, 'add_menu' ) );

		// `admin_enqueue_scripts` fires in network admin as well; `admin_menu`
		// does not, which is why the menu above has its own hook and this one
		// does not need a second.
		add_action( 'admin_enqueue_scripts', array( self::class, 'enqueue_assets' ) );

		// The network menu's mark, as the site menu draws it.
		add_action( 'admin_enqueue_scripts', array( Menu::class, 'paint_mark' ) );
		Quiet::register();
	}

	public static function add_menu(): void {
		self::$hooks[] = (string) add_menu_page(
			__( 'BetterShield', 'bettershield' ),
			__( 'BetterShield', 'bettershield' ),
			Sections::NETWORK_CAPABILITY,
			Sections::NETWORK_ROOT,
			array( self::class, 'render' ),
			Menu::menu_icon(),
			78
		);

		foreach ( Sections::network() as $slug => $section ) {
			$hook = add_submenu_page(
				Sections::NETWORK_ROOT,
				$section['label'],
				$section['label'],
				$section['capability'],
				$slug,
				array( self::class, 'render' )
			);

			// A section the current user cannot reach registers nothing and
			// answers false. Casting that to a string would put an empty entry
			// in the list every hook is later matched against.
			if ( is_string( $hook ) ) {
				self::$hooks[] = $hook;
			}
		}

		// The shared code's changes are the network's to accept or restore, on
		// the screen of the site that runs the check.
		add_submenu_page(
			Sections::NETWORK_ROOT,
			__( 'File Changes', 'bettershield' ),
			__( 'File Changes', 'bettershield' ),
			Sections::NETWORK_CAPABILITY,
			get_admin_url( (int) get_main_site_id(), 'admin.php?page=bettershield-activity&tab=files' )
		);

		foreach ( self::$hooks as $hook ) {
			Quiet::claim( $hook );
		}
	}

	public static function render(): void {
		if ( ! current_user_can( Sections::NETWORK_CAPABILITY ) ) {
			wp_die( esc_html__( 'You cannot see this.', 'bettershield' ), '', array( 'response' => 403 ) );
		}

		echo '<div id="bettershield-root" class="bs-root"></div>';
	}

	/**
	 * Assets load on our screens only — never admin-wide.
	 */
	public static function enqueue_assets( string $hook ): void {
		if ( ! in_array( $hook, self::$hooks, true ) ) {
			return;
		}

		Menu::enqueue_app( self::config(), $hook );
	}

	/**
	 * The slug being viewed. Read from the request because WordPress has
	 * already decided it, and already refused anyone without the capability.
	 */
	private static function current_section(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reading which screen is open, not acting on a submission.
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';

		return Sections::network_exists( $page ) ? $page : Sections::NETWORK_ROOT;
	}

	/**
	 * The tab being viewed, resolved the way a site's is: an unknown tab falls
	 * back to its own section's first, never to another section.
	 */
	private static function current_tab( string $section ): string {
		$tabs = Sections::network()[ $section ]['tabs'] ?? array();

		if ( array() === $tabs ) {
			return '';
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- as above.
		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( (string) $_GET['tab'] ) ) : '';

		return isset( $tabs[ $tab ] ) ? $tab : (string) array_key_first( $tabs );
	}

	/**
	 * The navigation model the network interface renders from.
	 *
	 * Two things differ from the per-site model and both matter. Every URL is
	 * a network-admin URL, because `menu_page_url()` builds one against the
	 * site that happened to serve the request and would send every click to
	 * that site's own dashboard. And the REST root is named explicitly as the
	 * main site's: the routes carrying network state are registered there, and
	 * a bundle that resolved its own root would be asking whichever site
	 * answered for rows it does not have.
	 *
	 * @return array<string, mixed>
	 */
	private static function config(): array {
		$sections = array();

		foreach ( Sections::network() as $slug => $definition ) {
			if ( ! current_user_can( $definition['capability'] ) ) {
				continue;
			}

			$url  = network_admin_url( 'admin.php?page=' . $slug );
			$tabs = array();

			foreach ( $definition['tabs'] as $tab_slug => $label ) {
				$tabs[] = array(
					'slug'  => $tab_slug,
					'label' => $label,
					'url'   => add_query_arg( 'tab', $tab_slug, $url ),
				);
			}

			$sections[] = array(
				'slug'      => $slug,
				'label'     => $definition['label'],
				'url'       => $url,
				'tabs'      => $tabs,
				'show_tabs' => count( $tabs ) > 1,
			);
		}

		$section = self::current_section();

		return array(
			'network'  => true,
			'section'  => $section,
			'tab'      => self::current_tab( $section ),
			'sections' => $sections,
			'nav'      => Navigation::build( $sections, Sections::network() ),
			// The log's own filter chips, translated here for the same reason
			// the section labels are.
			'areas'    => array(
				'activity' => Areas::label_list(
					array_values( array_unique( array_values( \BetterShield\Events\Types::areas() ) ) )
				),
			),
			'brand'    => __( 'BetterShield', 'bettershield' ),
			// The tier, as every site screen is told it, so the sidebar names
			// the add-on here too while it is network-active.
			'tier'     => \BetterShield\Support\Tier::current(),
			'restRoot' => (string) get_rest_url( (int) get_main_site_id() ),
			'limits'   => array(
				'max_sites' => self::MAX_SITES,
			),
		);
	}

	/**
	 * How many sites one page walks: two hundred, or fewer where a host asks.
	 */
	public static function page_size(): int {
		/**
		 * How many sites the network overview reads per page.
		 *
		 * @param int $size At most two hundred; less where switching into a
		 *                  site is slow on this host.
		 */
		return max( 1, min( self::MAX_SITES, (int) apply_filters( 'bettershield_network_page_size', self::MAX_SITES ) ) );
	}

	/**
	 * One page of the network's site ids, in site order, after a given site.
	 *
	 * `capped` says there are sites past this page, and `next_cursor` is the
	 * id to ask for the next one after (zero on the last page). Read straight
	 * from the sites table because core's query has no "after this id": an
	 * offset would skip or repeat a site whenever one is added or removed
	 * between two pages.
	 *
	 * @return array{ids: int[], capped: bool, next_cursor: int}
	 */
	public static function site_ids( int $after = 0 ): array {
		global $wpdb;

		// The current network only, never a request parameter: core's own
		// default elsewhere is every network on the installation.
		$size = self::page_size();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- bounded, one page of ids.
		$ids  = array_map( 'intval', (array) $wpdb->get_col( $wpdb->prepare( 'SELECT blog_id FROM %i WHERE site_id = %d AND blog_id > %d ORDER BY blog_id ASC LIMIT %d', $wpdb->blogs, get_current_network_id(), max( 0, $after ), $size + 1 ) ) );

		$capped = count( $ids ) > $size;
		$ids    = array_slice( $ids, 0, $size );

		return array(
			'ids'         => $ids,
			'capped'      => $capped,
			'next_cursor' => $capped ? (int) end( $ids ) : 0,
		);
	}

	/**
	 * How many sites the network has, so a page can say what it is a page of.
	 */
	public static function total(): int {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- one count.
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE site_id = %d', $wpdb->blogs, get_current_network_id() ) );
	}

	/**
	 * Each site's name, for the places that need to say which site a row came
	 * from without paying for the whole roll-up.
	 *
	 * The log's site filter is the case: it needs an id and a name per site
	 * and nothing else, and building the roll-up to learn them would run an
	 * audit query against every site on the network to draw a dropdown.
	 *
	 * @return array<int, string>
	 */
	public static function site_labels(): array {
		$labels = array();

		foreach ( self::site_ids()['ids'] as $id ) {
			$labels[ $id ] = self::site_label( $id );
		}

		return $labels;
	}

	/**
	 * One site's name, or its id where it has none to give.
	 */
	public static function site_label( int $blog_id ): string {
		$name = (string) get_blog_option( $blog_id, 'blogname', '' );

		return '' !== $name ? $name : sprintf(
			/* translators: %d: a numeric site identifier on a network. */
			__( 'Site %d', 'bettershield' ),
			$blog_id
		);
	}

	/**
	 * Whether a site's rows have been carried over to the network tables.
	 *
	 * Read from the migration state rather than from the cached roll-up: it
	 * moves while the copy runs, and a table saying "not yet carried over"
	 * for an hour after it was would be reporting the cache rather than the
	 * network.
	 *
	 * @param array<string, mixed> $switched The migration state's own map.
	 */
	public static function migrated( array $switched, int $blog_id ): bool {
		// The main site's tables have always been the base-prefix tables, so
		// it is carried over by construction and nothing was copied for it.
		if ( (int) get_main_site_id() === $blog_id ) {
			return true;
		}

		$done = (array) ( $switched[ (string) $blog_id ] ?? array() );

		foreach ( Schema::NETWORK_TABLES as $table ) {
			if ( empty( $done[ $table ] ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * One page of subsites, with what each one's own tables say about it.
	 *
	 * Each page is its own cache entry, with its own hour: kept together in
	 * one entry, every later page grew it and every read restarted the hour
	 * of all of them, so the first page could be served long after it was
	 * built. The entries are named under a generation that a refresh moves
	 * on, which retires every page at once without listing them.
	 *
	 * @return array{sites: array<int, array<string, mixed>>, built_at: int, capped: bool, next_cursor: int, total: int}
	 */
	public static function rollup( bool $fresh = false, int $after = 0 ): array {
		$key = self::TRANSIENT . '_' . self::generation( $fresh ) . '_' . max( 0, $after );

		if ( ! $fresh ) {
			$cached = get_site_transient( $key );

			if ( is_array( $cached ) && isset( $cached['sites'] ) ) {
				return $cached;
			}
		}

		$walk = self::site_ids( $after );
		$page = array(
			'sites'       => self::read_sites( $walk ),
			'built_at'    => time(),
			'capped'      => $walk['capped'],
			'next_cursor' => $walk['next_cursor'],
			'total'       => self::total(),
		);

		set_site_transient( $key, $page, self::FRESH_SECONDS );

		return $page;
	}

	/**
	 * Retire every cached page, so the next read is built afresh. A deleted
	 * site stayed on the table, with links to nowhere, for as long as the
	 * page it was cached on lived.
	 */
	public static function forget_rollup(): void {
		/*
		 * Core creates a site with wp_installing() on, and while it is a
		 * transient is kept in the request's memory only. Without a
		 * persistent object cache the new generation never reached the
		 * database, and the table went on serving the page from before the
		 * site existed (#1828).
		 */
		$installing = wp_installing();

		if ( $installing ) {
			wp_installing( false );
		}

		try {
			self::generation( true );
		} finally {
			if ( $installing ) {
				wp_installing( true );
			}
		}
	}

	/**
	 * Which generation of cached pages is current, moved on by a refresh.
	 */
	private static function generation( bool $next ): int {
		$state      = get_site_transient( self::TRANSIENT );
		$generation = is_array( $state ) ? (int) ( $state['generation'] ?? 0 ) : 0;

		if ( $next ) {
			++$generation;
			set_site_transient( self::TRANSIENT, array( 'generation' => $generation ), 0 );
		}

		return $generation;
	}

	/**
	 * The same row, for sites named by id rather than by page: a filter for
	 * site 250 is answered for site 250, not searched for in the first page.
	 * Not cached; the ids are few and already validated as this network's.
	 *
	 * @param int[] $ids
	 * @return array<int, array<string, mixed>>
	 */
	public static function rollup_for( array $ids ): array {
		return self::read_sites( array( 'ids' => array_slice( array_values( array_unique( array_map( 'intval', $ids ) ) ), 0, self::page_size() ) ) );
	}

	/**
	 * Whether a list of named sites is longer than one page reads, so the
	 * answer can say it was cut rather than look whole.
	 *
	 * @param int[] $ids
	 */
	public static function more_than_a_page( array $ids ): bool {
		return count( array_unique( array_map( 'intval', $ids ) ) ) > self::page_size();
	}

	/**
	 * Read each site's row, switching into it and out again.
	 *
	 * @param array{ids: int[]} $walk
	 * @return array<int, array<string, mixed>>
	 */
	private static function read_sites( array $walk ): array {
		$sites = array();

		foreach ( $walk['ids'] as $id ) {
			switch_to_blog( (int) $id );

			try {
				/*
				 * Whether this plugin has ever been through this site at all. A
				 * site created outside an activation, or one a bounded activation
				 * walk never reached, has no tables — and reading its overview
				 * would mean querying tables that are not there, filling the page
				 * with database errors and then reporting the result as "Not
				 * audited yet", which is a different and much more comforting
				 * sentence than the truth. The stamp is an autoloaded option on
				 * that site, so asking costs nothing.
				 */
				$installed = Schema::current() > 0;

				/*
				 * Read, and only read. `Auditor::overview()` runs no checks and
				 * changes nothing — it reports what that site's last audit found.
				 * Running an audit from here would be this page deciding to do
				 * work on somebody else's site.
				 */
				$overview = $installed ? Auditor::overview() : array();

				/*
				 * No audit, no score. The overview's arithmetic on a site with no
				 * audit on record is 100 minus nothing, and carrying that figure
				 * beside a blank audit date graded a site never examined as a
				 * perfect one. Nothing audited is not the same as nothing found.
				 */
				$audited_at = $overview['generated_at'] ?? null;

				$sites[] = array(
					'id'                 => (int) $id,
					'name'               => (string) get_bloginfo( 'name' ),
					'url'                => (string) home_url( '/' ),
					'admin'              => (string) admin_url( 'admin.php?page=bettershield' ),
					'installed'          => $installed,
					'score'              => null !== $audited_at ? ( $overview['score'] ?? null ) : null,
					'grade'              => null !== $audited_at ? ( $overview['grade'] ?? null ) : null,
					// Gated on the same audit date the score is, for the same
					// reason: a site nobody has examined has no count of open
					// findings, and a zero beside a blank audit date reads as
					// examined and clean.
					'open_findings'      => null !== $audited_at ? (int) ( $overview['open_findings'] ?? 0 ) : null,
					'audited_at'         => $audited_at,
					/*
					 * Whether this site holds a way back in that works: a usable
					 * recovery link or printed codes, the same test the passkey
					 * policy's refusal applies. Widening that policy may not arm
					 * while one site lacks both, so the table names those sites
					 * rather than leaving the refusal unexplained, and no site
					 * holding printed codes is marked as having no way back.
					 */
					'recovery_link'      => $installed && ( RecoveryLink::usable() || OfflineCodes::exist() ),
					'policies_effective' => $installed ? self::effective_policies() : null,
				);

			} finally {
				restore_current_blog();
			}
		}

		return $sites;
	}

	/**
	 * How many roles each policy names on the site currently switched in, once
	 * the network's floor is added to that site's own choice.
	 *
	 * Null while there is no network policy store to add: a column that
	 * invents a number is worse than one that says it has none yet.
	 *
	 * @return array{two_factor_roles: int, passkey_roles: int}|null
	 */
	private static function effective_policies(): ?array {
		$store = '\\BetterShield\\Network\\Policies';

		if ( ! class_exists( $store ) ) {
			return null;
		}

		$two_factor = (array) ( \BetterShield\TwoFactor\Policy::instance()->settings()['roles'] ?? array() );
		$passkey    = (array) ( \BetterShield\Passkeys\Policy::instance()->settings()['roles'] ?? array() );

		return array(
			'two_factor_roles' => count( (array) call_user_func( array( $store, 'effective_two_factor_roles' ), $two_factor ) ),
			'passkey_roles'    => count( (array) call_user_func( array( $store, 'effective_passkey_roles' ), $passkey ) ),
		);
	}
}
