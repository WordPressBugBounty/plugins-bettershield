<?php
/**
 * The agent surface: what agents CAN do on this site, as distinct from what
 * they did.
 *
 * Two inventories. The ability inventory reads the live registry — plugins
 * register on every request, so a cached table would lie — and adds the one
 * column that turns a list into a finding: whether the ability's permission
 * callback admits users below administrators. That answer is computed by
 * ASKING the callback, never by executing the ability: a probe that ran
 * things to see what happens would be the attack it is meant to surface.
 *
 * The application-password inventory covers the credential every agent
 * integration actually authenticates with. Core keeps the records; nothing
 * lists them across users — so no security plugin's owner knows how many
 * agent credentials their site has quietly accumulated, or how many have
 * been dead for months. The names appear on the owner's screen only; the
 * ability output carries counts and ages, because a list of credential
 * names is more than an agent needs.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Abilities;

use BetterShield\Agents\Canary;
use BetterShield\Agents\Capture;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AgentSurface {

	public const ACCESS_DENIED  = 'denied';
	public const ACCESS_ALLOWED = 'allowed';
	public const ACCESS_UNKNOWN = 'unknown';

	/**
	 * Days after which an unused application password counts as stale.
	 */
	public const STALE_DAYS = 90;

	/**
	 * How many credential holders are read at once. Every one of them is a
	 * hydrated account with its meta, and the sites this feature is for are
	 * the ones with thousands.
	 */
	public const HOLDER_PAGE = 200;

	/**
	 * The capability grant used for probing: what a subscriber holds.
	 *
	 * @var array<string, bool>|null
	 */
	private static ?array $probe_caps = null;

	/** The borrowed identity the probe wears, resolved once per request. */
	private static ?int $probe_user = null;

	/**
	 * How many probe sessions are open. The identity is swapped in when the
	 * outermost one opens and put back when it closes, so an inventory of
	 * fifty abilities swaps once rather than fifty times.
	 */
	private static int $probe_depth = 0;

	/** Who was signed in when the outermost session opened. */
	private static int $probe_restore = 0;

	/**
	 * The capability grant that is in force for the length of a session. Held
	 * so the closure that is removed is the one that was added.
	 */
	private static ?\Closure $probe_grant = null;

	/* ---- ability inventory ---------------------------------------------- */

	/**
	 * Every registered ability, read from the registry at request time.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function abilities(): array {
		if ( ! class_exists( 'WP_Abilities_Registry' ) ) {
			return array();
		}

		$registered = \WP_Abilities_Registry::get_instance()->get_all_registered();

		/*
		 * Every gate is asked inside one session rather than one each. Swapping
		 * the identity fires an action other plugins listen to, and the answers
		 * all want the same borrowed account — so a site with fifty abilities
		 * used to fire it a hundred times to ask one question fifty ways.
		 *
		 * The rest of the row — where the ability came from, what it declares —
		 * is resolved outside the session, because reading a plugin header is
		 * not a question about who may call anything.
		 */
		$access = array();

		self::open_probe();

		try {
			foreach ( $registered as $name => $ability ) {
				$access[ (string) $name ] = self::probe( $ability );
			}
		} finally {
			self::close_probe();
		}

		$out = array();

		foreach ( $registered as $name => $ability ) {
			$annotations = self::annotations_of( $ability );

			$source = self::source_of( $ability );

			$out[] = array(
				'name'                  => (string) $name,
				'registering_source'    => $source,
				// The name a person knows the plugin by; the slug stays as the
				// stable key. Read from the plugin header, so it is whatever the
				// plugin calls itself.
				'registering_source_label' => self::source_label( $source ),
				// As declared. Annotations carry no runtime enforcement, and
				// reporting them as declared is the point: an undeclared
				// write ability LOOKS read-only to tooling that trusts hints.
				'annotated_readonly'    => (bool) ( $annotations['readonly'] ?? false ),
				'annotated_destructive' => (bool) ( $annotations['destructive'] ?? true ),
				'exposed_in_rest'       => self::rest_exposure_of( $ability ),
				'low_privilege_access'  => $access[ (string) $name ] ?? self::ACCESS_UNKNOWN,
			);
		}

		return $out;
	}

	/**
	 * Probe answers for this request, by ability name. An audit and a screen
	 * fetch in the same request ask the same question; another plugin's
	 * permission callback should hear it once.
	 *
	 * @var array<string, string>
	 */
	private static array $probe_memo = array();

	/**
	 * Whether an ability's permission callback admits a low-privilege user.
	 *
	 * The probe swaps in a **signed-in** identity holding exactly a
	 * subscriber's capabilities, asks the callback, and restores the world.
	 * Signed in matters: a callback of `is_user_logged_in()` is a real and
	 * common way to gate an ability, and probing while signed out answered
	 * "denied" for abilities that any logged-in visitor could in fact run —
	 * the column reporting safety where there was none.
	 * The ability is never executed, and any surprise — an exception, a
	 * non-boolean — answers "unknown", never "allowed": the column exists to
	 * make findings, and a finding must not be guessable into existence.
	 *
	 * What the callback is asked *with* matters as much as who it is asked
	 * as. See `probe_input()`.
	 *
	 * @param mixed $ability
	 */
	public static function probe( $ability ): string {
		if ( ! is_object( $ability ) || ! method_exists( $ability, 'check_permissions' ) ) {
			return self::ACCESS_UNKNOWN;
		}

		$name = method_exists( $ability, 'get_name' ) ? (string) $ability->get_name() : '';
		if ( '' !== $name && isset( self::$probe_memo[ $name ] ) ) {
			return self::$probe_memo[ $name ];
		}

		$answer = self::probe_now( $ability );
		if ( '' !== $name ) {
			self::$probe_memo[ $name ] = $answer;
		}

		return $answer;
	}

	/** Test seam: forget this request's probe answers. */
	public static function forget_probes(): void {
		self::$probe_memo = array();
		self::$probe_user = null;
		self::$probe_caps = null;
	}

	/**
	 * Borrow the identity, hold the capabilities down, and stop recording.
	 *
	 * Nested calls are counted rather than repeated: an inventory opens one
	 * session around the whole loop and each ability opens one of its own
	 * inside it, and only the outermost touches the current user.
	 *
	 * @return bool False when there is no identity to borrow, which is a
	 *              question that cannot be asked rather than an answer.
	 */
	private static function open_probe(): bool {
		if ( self::$probe_depth > 0 ) {
			++self::$probe_depth;

			return true;
		}

		$probe_id = self::probe_user_id();

		if ( 0 === $probe_id ) {
			return false;
		}

		// Exactly a subscriber's capabilities and nothing else. Merging onto
		// whoever is really signed in would leave an administrator's caps in
		// place and report every ability as reachable by anyone.
		self::$probe_grant = static function (): array {
			if ( null === self::$probe_caps ) {
				$role             = get_role( 'subscriber' );
				self::$probe_caps = null !== $role ? array_filter( $role->capabilities ) : array( 'read' => true );
			}

			return self::$probe_caps;
		};

		self::$probe_restore = get_current_user_id();

		wp_set_current_user( $probe_id );
		add_filter( 'user_has_cap', self::$probe_grant, PHP_INT_MAX );

		/*
		 * This is a question, not a call, and the invocation record must not
		 * read it as one. The refusal below is the answer the column exists
		 * to print — recorded, it would be one fabricated refusal per
		 * registered ability every time this screen loads, each raising the
		 * alertable event that is this product's most valuable signal.
		 */
		Capture::suspend();

		self::$probe_depth = 1;

		return true;
	}

	/** Give the world back, once the outermost session closes. */
	private static function close_probe(): void {
		if ( self::$probe_depth < 1 ) {
			return;
		}

		--self::$probe_depth;

		if ( self::$probe_depth > 0 ) {
			return;
		}

		Capture::resume();

		if ( null !== self::$probe_grant ) {
			remove_filter( 'user_has_cap', self::$probe_grant, PHP_INT_MAX );
			self::$probe_grant = null;
		}

		wp_set_current_user( self::$probe_restore );
		self::$probe_restore = 0;
	}

	private static function probe_now( $ability ): string {
		if ( ! self::open_probe() ) {
			// Nobody to ask as. Answering anyway would be inventing a caller
			// this site does not have, and every finding this column feeds
			// would be made out of that invention.
			return self::ACCESS_UNKNOWN;
		}

		try {
			$asked = self::probe_input( $ability );

			// No input a real caller could send means no honest question to
			// ask. Answering anyway is how the column would start reporting
			// what an ability does with a hole where its object goes.
			if ( ! $asked['honest'] ) {
				return self::ACCESS_UNKNOWN;
			}

			$result = $ability->check_permissions( $asked['input'] );

			// Core wraps a throwing callback into a WP_Error and coerces
			// anything non-boolean to false — so a clean boolean is a real
			// answer, and everything else is a gate that could not be read.
			if ( true === $result ) {
				return self::ACCESS_ALLOWED;
			}
			if ( false === $result ) {
				return self::ACCESS_DENIED;
			}

			return self::ACCESS_UNKNOWN;
		} catch ( \Throwable $e ) {
			return self::ACCESS_UNKNOWN;
		} finally {
			self::close_probe();
		}
	}

	/**
	 * The input a real invocation would carry, or the answer that there is none.
	 *
	 * The probe used to ask every callback with a hard-coded empty array, and
	 * that is not input any caller could send. `execute()` validates against
	 * the ability's own schema before the permission callback ever runs, so an
	 * ability whose schema requires an object id is never reached with the id
	 * missing — while a callback like `current_user_can( 'edit_post',
	 * $input['id'] )` answers something for the hole anyway. Which direction
	 * it answers wrong in depends on how that callback treats absent input,
	 * and both directions land in a high-severity finding.
	 *
	 * So the smallest input a real caller could actually send is built here
	 * and put through the ability's own validator:
	 *
	 * - The schema's top-level `default` is used when it declares one, which
	 *   is what `normalize_input()` does for a caller who sends nothing.
	 * - An object schema otherwise gets the empty object, because that is what
	 *   a caller sends when every property is optional.
	 * - Anything else gets null, the only value a caller can send to an
	 *   ability with no schema at all.
	 *
	 * If the validator refuses that, the ability needs something this code
	 * would have to invent — an id, a slug, a path into the site's own
	 * content — and inventing one is guessing. The answer is "unknown", which
	 * this column already carries and which no finding is made from.
	 *
	 * The `wp_ability_normalize_input` filter is deliberately not fired.
	 * `normalize_input()` is a public step of executing, third-party code
	 * hangs off it, and running it to look at something is the beginning of
	 * running it. The built-in default handling is what gets copied instead.
	 *
	 * @param mixed $ability
	 * @return array{honest: bool, input: mixed}
	 */
	private static function probe_input( $ability ): array {
		$schema = method_exists( $ability, 'get_input_schema' ) ? (array) $ability->get_input_schema() : array();

		if ( array() === $schema ) {
			// With no schema, core refuses any input but null, so null is the
			// only thing a caller can send and there is nothing to validate.
			return array(
				'honest' => true,
				'input'  => null,
			);
		}

		if ( array_key_exists( 'default', $schema ) ) {
			$input = $schema['default'];
		} elseif ( 'object' === ( $schema['type'] ?? '' ) || isset( $schema['properties'] ) ) {
			$input = array();
		} else {
			$input = null;
		}

		if ( method_exists( $ability, 'validate_input' ) && true === $ability->validate_input( $input ) ) {
			return array(
				'honest' => true,
				'input'  => $input,
			);
		}

		/*
		 * For this plugin's own abilities the answer is knowable without
		 * guessing: every one of their permission callbacks is a capability
		 * check that never reads the input, so a placeholder in each required
		 * field asks exactly the question a real caller's id would. The
		 * placeholder still has to pass the ability's own validator — a schema
		 * this code cannot satisfy is still answered "unknown". Nothing here
		 * applies to another plugin's ability, whose callback may well read
		 * the id it was handed.
		 */
		$name = method_exists( $ability, 'get_name' ) ? (string) $ability->get_name() : '';

		if ( 0 === strpos( $name, 'bettershield/' ) ) {
			$placeholder = self::placeholder_input( $schema );

			if ( null !== $placeholder && method_exists( $ability, 'validate_input' ) && true === $ability->validate_input( $placeholder ) ) {
				return array(
					'honest' => true,
					'input'  => $placeholder,
				);
			}
		}

		return array(
			'honest' => false,
			'input'  => null,
		);
	}

	/**
	 * The smallest object that fills every required property of a schema with
	 * a value of the declared type, or null where the schema is not an object
	 * with named properties.
	 *
	 * @param array<string, mixed> $schema
	 * @return array<string, mixed>|null
	 */
	private static function placeholder_input( array $schema ): ?array {
		if ( 'object' !== ( $schema['type'] ?? '' ) || ! isset( $schema['properties'] ) || ! is_array( $schema['properties'] ) ) {
			return null;
		}

		$input = array();

		foreach ( (array) ( $schema['required'] ?? array() ) as $key ) {
			$property = $schema['properties'][ $key ] ?? null;

			if ( ! is_array( $property ) ) {
				return null;
			}

			$input[ $key ] = self::placeholder_value( $property );
		}

		return $input;
	}

	/**
	 * @param array<string, mixed> $property
	 * @return mixed
	 */
	private static function placeholder_value( array $property ) {
		if ( isset( $property['enum'] ) && is_array( $property['enum'] ) && array() !== $property['enum'] ) {
			return reset( $property['enum'] );
		}

		switch ( (string) ( $property['type'] ?? 'string' ) ) {
			case 'integer':
			case 'number':
				return isset( $property['minimum'] ) ? $property['minimum'] : 1;
			case 'boolean':
				return false;
			case 'array':
				return array();
			case 'object':
				return array();
			default:
				$length = isset( $property['minLength'] ) ? max( 1, (int) $property['minLength'] ) : 1;

				return str_repeat( 'a', $length );
		}
	}

	/**
	 * An identity for the probe to wear: signed in, and with its capabilities
	 * forced down to a subscriber's by the filter above.
	 *
	 * An existing account is borrowed rather than created, because a probe that
	 * writes to the site is not a probe. Which account hardly matters — the
	 * capabilities are replaced wholesale — but a real id is what makes
	 * `is_user_logged_in()` and `get_current_user_id()` answer the way they
	 * would for a genuine low-privilege visitor.
	 *
	 * A site with no identity to borrow answers 0, and the caller turns that
	 * into "unknown" rather than into an answer: there is no signed-in visitor
	 * to simulate, so there is no honest question to ask.
	 */
	private static function probe_user_id(): int {
		if ( null !== self::$probe_user ) {
			return self::$probe_user;
		}

		$args = array(
			'number'  => 1,
			'fields'  => 'ID',
			'orderby' => 'ID',
			'order'   => 'ASC',
		);

		/*
		 * On a network, `WP_User::has_cap()` returns true for a super admin
		 * before the grant filter is consulted at all — so an identity
		 * borrowed from one holds every capability however hard the grant
		 * holds it down, and every ability reads as reachable by anybody.
		 * Excluded by login, because the login is what the network keeps its
		 * list of them in. Not excluded on a single site, where the short
		 * circuit does not exist and the grant does replace the whole set:
		 * doing it there would rule out every administrator and leave the
		 * ordinary one-account site with nothing to ask as.
		 */
		if ( is_multisite() ) {
			$supers = get_super_admins();

			if ( is_array( $supers ) && array() !== $supers ) {
				$args['login__not_in'] = $supers;
			}
		}

		$ids = get_users( $args );

		self::$probe_user = array() === $ids ? 0 : (int) $ids[0];

		return self::$probe_user;
	}

	/* ---- application passwords -------------------------------------------- */

	/**
	 * Every user holding application passwords.
	 *
	 * @param bool $with_names Whether to include per-password names — the
	 *                         owner's screen only, never the ability output.
	 * @return array<int, array<string, mixed>>
	 */
	public static function application_passwords( bool $with_names = false ): array {
		if ( ! class_exists( 'WP_Application_Passwords' ) ) {
			return array();
		}

		$now = time();
		$out = array();

		/*
		 * The decoy is dormant on purpose, which is the whole of what it does.
		 * It is listed like any other credential and never aged: counting it
		 * toward the oldest unused one would have this plugin report its own
		 * tripwire as a credential somebody has forgotten to revoke.
		 */
		$planted = Canary::planted();
		$decoy   = null === $planted ? '' : $planted['uuid'];

		$page = 1;

		/*
		 * A page of ids at a time, ordered so the walk is stable. This asked
		 * for every holder at once, as fully hydrated accounts — and it is
		 * read on the Overview an owner opens, so on the agency site the
		 * feature exists for that is the user table in memory before the first
		 * row is shaped. Ordered by id because the sweep resumes by it.
		 */
		do {
			$ids = get_users(
				array(
					'meta_key'     => \WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- bounded by users holding app passwords; an admin-screen and daily-audit read, never front-end.
					'meta_compare' => 'EXISTS',
					'fields'       => 'ID',
					'number'       => self::HOLDER_PAGE,
					'paged'        => $page,
					'orderby'      => 'ID',
					'order'        => 'ASC',
				)
			);

			if ( array() === $ids ) {
				break;
			}

			// One read for the page's accounts and their meta together, rather
			// than one for every holder in it.
			cache_users( $ids );

			foreach ( $ids as $id ) {
				$user = get_userdata( (int) $id );

				if ( ! $user instanceof \WP_User ) {
					continue;
				}

				$out = self::add_holder( $out, $user, $with_names, $decoy, $now );
			}

			++$page;
		} while ( count( $ids ) === self::HOLDER_PAGE );

		return $out;
	}

	/**
	 * One holder's row, appended.
	 *
	 * @param array<int, array<string, mixed>> $out
	 * @return array<int, array<string, mixed>>
	 */
	private static function add_holder( array $out, \WP_User $user, bool $with_names, string $decoy, int $now ): array {
		$passwords = \WP_Application_Passwords::get_user_application_passwords( $user->ID );

		if ( array() === $passwords ) {
			return $out;
		}

		$oldest_unused = 0;
		$names         = array();

		foreach ( $passwords as $password ) {
			if ( '' === $decoy || $decoy !== (string) ( $password['uuid'] ?? '' ) ) {
				// A password never used counts from its creation: dormant
				// since birth is the staler state, not a fresher one.
				$last_alive    = (int) ( $password['last_used'] ?? 0 );
				$last_alive    = $last_alive > 0 ? $last_alive : (int) ( $password['created'] ?? $now );
				$oldest_unused = max( $oldest_unused, (int) floor( ( $now - $last_alive ) / DAY_IN_SECONDS ) );
			}

			if ( $with_names ) {
				$names[] = array(
					// Which one, for the owner's screen to act on, and what it
					// is held to, if anything.
					'uuid'         => (string) ( $password['uuid'] ?? '' ),
					'limit'        => \BetterShield\Agents\PasswordLimits::get( $user->ID, (string) ( $password['uuid'] ?? '' ) ),
					// The decoy takes no limit, so the screen offers it none.
					// Asked the way PasswordLimits asks, so a decoy planted
					// from another site of a network is recognized here too.
					'decoy'        => Canary::is_decoy( $password, (int) $user->ID ),
					'name'         => (string) ( $password['name'] ?? '' ),
					'created_at'   => gmdate( 'c', (int) ( $password['created'] ?? 0 ) ),
					'last_used_at' => ( $password['last_used'] ?? null ) ? gmdate( 'c', (int) $password['last_used'] ) : null,
				);
			}
		}

		$row = array(
			'user_id'            => $user->ID,
			'login'              => $user->user_login,
			'role'               => implode( ', ', (array) $user->roles ),
			'count'              => count( $passwords ),
			'oldest_unused_days' => $oldest_unused,
		);

		if ( $with_names ) {
			$row['passwords'] = $names;
		}

		$out[] = $row;

		return $out;
	}

	/* ---- finding feeds ------------------------------------------------------- */

	/**
	 * Write-shaped abilities reachable over REST by low-privilege users:
	 * the combination that is a finding rather than a fact.
	 *
	 * @return string[] Ability names.
	 */
	public static function low_privilege_writes(): array {
		$names = array();

		foreach ( self::abilities() as $ability ) {
			if ( ! $ability['annotated_readonly'] && $ability['exposed_in_rest'] && self::ACCESS_ALLOWED === $ability['low_privilege_access'] ) {
				$names[] = $ability['name'];
			}
		}

		return $names;
	}

	/**
	 * @return array{accounts: int, passwords: int}
	 */
	public static function stale_password_summary(): array {
		$accounts  = 0;
		$passwords = 0;

		foreach ( self::application_passwords() as $holder ) {
			if ( $holder['oldest_unused_days'] >= self::STALE_DAYS ) {
				++$accounts;
				$passwords += $holder['count'];
			}
		}

		return array(
			'accounts'  => $accounts,
			'passwords' => $passwords,
		);
	}

	/**
	 * Passwords held by an account that can change the site, with no route or
	 * address limit on them. The decoy takes no limit, so it is never counted.
	 *
	 * @return array{accounts: int, passwords: int}
	 */
	public static function unlimited_privileged_password_summary(): array {
		$accounts  = 0;
		$passwords = 0;

		foreach ( self::application_passwords( true ) as $holder ) {
			$user = get_userdata( (int) $holder['user_id'] );

			if ( ! $user instanceof \WP_User || ! \BetterShield\Hardening\Item\ApplicationPasswords::is_privileged( $user ) ) {
				continue;
			}

			$unlimited = count(
				array_filter(
					$holder['passwords'],
					static fn( array $password ): bool => ! $password['decoy'] && empty( $password['limit'] )
				)
			);

			if ( $unlimited > 0 ) {
				++$accounts;
				$passwords += $unlimited;
			}
		}

		return array(
			'accounts'  => $accounts,
			'passwords' => $passwords,
		);
	}

	/* ---- internals ------------------------------------------------------------- */

	/**
	 * @param mixed $ability
	 * @return array<string, mixed>
	 */
	private static function annotations_of( $ability ): array {
		if ( is_object( $ability ) && method_exists( $ability, 'get_meta_item' ) ) {
			$annotations = $ability->get_meta_item( 'annotations' );

			if ( is_array( $annotations ) ) {
				return $annotations;
			}
		}

		return array();
	}

	/**
	 * @param mixed $ability
	 */
	private static function rest_exposure_of( $ability ): bool {
		if ( is_object( $ability ) && method_exists( $ability, 'get_meta_item' ) ) {
			return (bool) $ability->get_meta_item( 'show_in_rest' );
		}

		return false;
	}

	/**
	 * A source slug as a person would say it: the plugin's own name from its
	 * header, or a fixed word for core, must-use plugins and the unknown.
	 */
	public static function source_label( string $source ): string {
		switch ( $source ) {
			case 'wordpress':
				return 'WordPress';
			case 'mu-plugin':
				return __( 'Must-use plugin', 'bettershield' );
			case 'unknown':
				return __( 'Unknown source', 'bettershield' );
		}

		$names = self::plugin_names();

		return $names[ $source ] ?? $source;
	}

	/**
	 * Plugin directory => plugin name, from the headers, once per request.
	 * A single-file plugin has no directory; its file name minus .php stands
	 * in, which is also what source_of() yields for it.
	 *
	 * @return array<string, string>
	 */
	private static function plugin_names(): array {
		static $names = null;

		if ( null !== $names ) {
			return $names;
		}

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$names = array();
		foreach ( get_plugins() as $file => $header ) {
			$dir = (string) strtok( $file, '/' );
			$key = str_contains( $file, '/' ) ? $dir : (string) preg_replace( '/\.php$/', '', $file );

			// The first plugin file in a directory names it; a second one in
			// the same directory is a rarity not worth a guess.
			if ( ! isset( $names[ $key ] ) && '' !== (string) $header['Name'] ) {
				$names[ $key ] = wp_strip_all_tags( (string) $header['Name'] );
			}
		}

		return $names;
	}

	/**
	 * Which plugin (or core) registered an ability, by where its execute
	 * callback lives. A heuristic, labeled as what it is.
	 *
	 * @param mixed $ability
	 */
	private static function source_of( $ability ): string {
		if ( ! is_object( $ability ) ) {
			return 'unknown';
		}

		try {
			// WP_Ability exposes no getter for its callbacks; the property is
			// protected. Reading it through reflection is the only way to
			// attribute an ability to a plugin, and it reads — never calls.
			$property = new \ReflectionProperty( $ability, 'execute_callback' );

			// A no-op since 8.1 and deprecated in 8.5, where the notice is
			// written into the response body for any client that does not ask
			// for JSON — which is how a raw request to the audit route came
			// back as invalid JSON. Still required on the 8.0 floor, so it is
			// guarded rather than removed.
			if ( PHP_VERSION_ID < 80100 ) {
				$property->setAccessible( true );
			}
			$callback = $property->getValue( $ability );

			if ( is_array( $callback ) ) {
				$reflection = new \ReflectionMethod( is_object( $callback[0] ) ? get_class( $callback[0] ) : (string) $callback[0], (string) $callback[1] );
			} elseif ( $callback instanceof \Closure || ( is_string( $callback ) && function_exists( $callback ) ) ) {
				$reflection = new \ReflectionFunction( $callback );
			} else {
				return 'unknown';
			}

			$file = (string) $reflection->getFileName();

			if ( '' === $file ) {
				return 'unknown';
			}

			return self::source_path( $file );
		} catch ( \Throwable $e ) {
			return 'unknown';
		}
	}
	/**
	 * Where the Abilities API runtime was loaded from when a plugin carries it
	 * (WordPress before 6.9), or '' when core provides it. Null until read.
	 */
	private static ?string $runtime = null;

	/**
	 * Before 6.9 the runtime, and core's own abilities with it, comes from a
	 * plugin's bundled copy, so attributing by folder put `core/get-user-info`
	 * under that plugin — this one, warning about itself. Only the copy that
	 * actually defined the functions counts, and only in the package's own
	 * layout, so no other folder can borrow the name.
	 */
	private static function runtime(): string {
		if ( null === self::$runtime ) {
			self::$runtime = '';

			try {
				$file = function_exists( 'wp_register_ability' ) ? wp_normalize_path( (string) ( new \ReflectionFunction( 'wp_register_ability' ) )->getFileName() ) : '';
			} catch ( \Throwable $e ) {
				$file = '';
			}

			if ( str_ends_with( $file, '/abilities-api/includes/abilities-api.php' ) ) {
				self::$runtime = trailingslashit( dirname( $file, 2 ) );
			}
		}

		return self::$runtime;
	}

	/** Follow core's registered symlink map, with directory boundaries, without executing a callback. */
	public static function source_path( string $file ): string {
		global $wp_plugin_paths;
		$file = wp_normalize_path( $file );
		if ( '' !== self::runtime() && str_starts_with( $file, self::runtime() ) ) { return 'wordpress'; }
		$paths = (array) $wp_plugin_paths; arsort( $paths );
		foreach ( $paths as $directory => $real ) {
			if ( str_starts_with( $file, trailingslashit( $real ) ) ) { $file = $directory . substr( $file, strlen( $real ) ); break; }
		}
		foreach ( array_unique( array( WP_PLUGIN_DIR, realpath( WP_PLUGIN_DIR ) ?: WP_PLUGIN_DIR ) ) as $directory ) {
			$prefix = trailingslashit( wp_normalize_path( $directory ) );
			if ( str_starts_with( $file, $prefix ) ) { $relative = substr( $file, strlen( $prefix ) ); return str_contains( $relative, '/' ) ? (string) strtok( $relative, '/' ) : (string) preg_replace( '/\.php$/', '', $relative ); }
		}
		foreach ( array( ABSPATH . WPINC, ABSPATH . 'wp-admin' ) as $directory ) {
			if ( str_starts_with( $file, trailingslashit( wp_normalize_path( realpath( $directory ) ?: $directory ) ) ) ) { return 'wordpress'; }
		}
		if ( defined( 'WPMU_PLUGIN_DIR' ) ) {
			foreach ( array( WPMU_PLUGIN_DIR, realpath( WPMU_PLUGIN_DIR ) ?: WPMU_PLUGIN_DIR ) as $directory ) { if ( str_starts_with( $file, trailingslashit( wp_normalize_path( $directory ) ) ) ) { return 'mu-plugin'; } }
		}
		return 'unknown';
	}

}
