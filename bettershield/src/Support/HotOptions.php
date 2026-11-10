<?php
/**
 * The options this plugin reads on an ordinary front-end page view.
 *
 * They are declared in one place because the same defect keeps arriving
 * through them, and it is invisible in review every time: a small
 * `get_option()` on a hook that runs for visitors, against an option nobody
 * autoloaded. WordPress caches present autoloaded options together in one
 * read; an option that is absent, or present but not autoloaded, is looked up
 * again on every single request on any host without a persistent object cache.
 * So the cost is not the read — the read is correct — it is the flag, and the
 * flag is set somewhere else entirely from the code that pays for it.
 *
 * It has happened four times: the recorded PHP version, the verification state,
 * the auth-key secret — read on every page view of sites that had never turned
 * that fix on at all — and the sampling state, which is written only once a
 * flood threshold is crossed, so on an ordinary site the quiet state was the
 * expensive one. Each was fixed where it happened. None of those fixes stopped
 * the next one, because the mistake is structural.
 *
 * Two of them also had a second half worth naming, because it is the same
 * mistake read backwards: code that *deleted* its option when the feature was
 * switched off or the window closed, handing the site the exact cost the
 * absence was supposed to mean. An option in this list is emptied, never
 * deleted; uninstall is what removes it.
 *
 * Declaring them here does two things a fix in place cannot. Activation and
 * the schema migration seed the whole list, so a site pays for none of them
 * whether it was installed yesterday or updated from a version that predates
 * the flag. And the list is something a test can hold the code to — the guard
 * that goes with this one drives a front-end request and watches the queries,
 * rather than reading the list back to itself.
 *
 * Adding one is a line. The bar for being on it is only this: the plugin reads
 * it on a request a visitor makes.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class HotOptions {

	/**
	 * What an add-on's declared option name has to begin with.
	 *
	 * The seam writes to whatever row a declared name points at, so the name
	 * has to be one the declaring add-on owns. This product's add-ons name
	 * their options after it; anything else is another plugin's row.
	 */
	private const PREFIX = 'bettershield';

	/**
	 * Name to the value the option is seeded with when the site has none.
	 *
	 * The seeded value must read the same as the option's absence, because
	 * seeding happens on sites that have never used the feature — an empty
	 * string for the secret is "no secret", an empty array for a record is "no
	 * record". Nothing here changes behavior; it only stops the absence
	 * costing a query.
	 *
	 * @return array<string, mixed>
	 */
	public static function all(): array {
		return self::with_add_ons( self::ours() );
	}

	/**
	 * The same list, plus anything an add-on reads on a visitor's request.
	 *
	 * An add-on pays exactly the cost this class exists to remove, on exactly
	 * the same hooks, and it cannot add a line to the list above — so without
	 * a seam its only remaining options are to seed on its own activation,
	 * which misses every site where it is already active, or to pay the query.
	 *
	 * The bar is the one stated above, and so is the rule about the seeded
	 * value: it has to read the same as the option's absence, because seeding
	 * happens on sites that have never used the feature. A name this plugin
	 * already owns is never replaced — these reads are what the list was
	 * built to answer for.
	 *
	 * @param array<string, mixed> $ours
	 * @return array<string, mixed>
	 */
	private static function with_add_ons( array $ours ): array {
		/**
		 * Options an add-on reads on a request a visitor makes.
		 *
		 * @since 1.0.0
		 *
		 * @param array<string, mixed> $extra Option name to the value it is seeded with.
		 */
		$extra = apply_filters( 'bettershield_hot_options', array() );

		if ( ! is_array( $extra ) ) {
			return $ours;
		}

		foreach ( $extra as $name => $default ) {
			// A name, and not one of ours. Anything else is ignored rather
			// than trusted: this list decides what gets written to the
			// options table on every activation and every migration.
			if ( ! is_string( $name ) || '' === $name || isset( $ours[ $name ] ) ) {
				continue;
			}

			/*
			 * And a name the declaring add-on plausibly owns.
			 *
			 * Seeding creates what is absent and autoloads what is not, which
			 * is a write to whatever row the name points at. Nothing else here
			 * constrains that name, so an add-on could have named a core
			 * option, or an unrelated plugin's large one, and had its autoload
			 * flag flipped on every activation and every schema migration — a
			 * row this plugin has no business rewriting. The prefix is the
			 * ownership rule: this product's add-ons name their options after
			 * it, and anything else is somebody else's row.
			 */
			if ( 0 !== strpos( $name, self::PREFIX ) ) {
				continue;
			}

			$ours[ $name ] = $default;
		}

		return $ours;
	}

	/**
	 * This plugin's own.
	 *
	 * @return array<string, mixed>
	 */
	private static function ours(): array {
		return array(
			// Read on every request to decide whether every protection is
			// currently stood down.
			'bettershield_safe_mode_until'  => 0,
			// Read on every request to enforce whatever is applied.
			'bettershield_hardening'        => array(),
			'bettershield_hardening_monitors' => array(),
			'bettershield_observed_changes' => array( 'enabled' => false, 'used' => 0 ),
			'bettershield_account_suspensions' => array(),
			// Read on every request the login and session controls touch.
			'bettershield_login_protection' => array(),
			// Read before anything can ask for a salt, to decide whether to
			// mix one in — including on sites where the item is switched off,
			// which is what made this the cost a site paid for a fix it had
			// never turned on.
			'bettershield_auth_secret'      => '',
			// Read at shutdown on front-end page views, to decide whether any
			// applied protection is due to be looked at again.
			'bettershield_verification'     => array(),
			// Read at shutdown on every request the event writer drains,
			// which includes ordinary front-end page views — and it is normally
			// absent, because it is written only once a per-type flood
			// threshold is crossed. So the quiet state was the expensive one.
			'bettershield_event_rates'      => array(),
			// Read on every request from WordPress 7.1 up, to decide whether
			// the ability lifecycle is recorded. On by default, so the row is
			// normally absent — which is the state that costs the query.
			'bettershield_agent_capture'    => '1',
			// Read on the sampled page views that measure what this plugin
			// costs. One in twenty rather than all of them, but a measurement
			// that pays for itself with a query is not a measurement worth
			// publishing.
			'bettershield_front_end_cost'   => array(),
			// Read on every request, before the abilities hook is armed. Off
			// on a site that has never opened the Agents screen, which is the
			// state that costs the query.
			'bettershield_abilities_enabled' => '',
			// Read on every request, to decide whether the site is locked
			// down. Absent on every site that has never used it.
			'bettershield_lockdown'         => array(),
			// Read on every front-end page view, to decide whether the URL is
			// the decoy. Absent until the feature is configured — and written
			// autoloaded once it is, so the cost does not come back with it.
			'bettershield_decoy_page'       => array(),
		);
	}

	/**
	 * @return string[]
	 */
	public static function names(): array {
		return array_keys( self::all() );
	}

	/**
	 * The same list for a network, where two of these live once for all of its
	 * sites rather than once per site.
	 *
	 * Sitemeta has no autoload flag, so this list cannot make a network option
	 * free the way the list above makes a site option free — the first ask of
	 * each request is a row read on a host with no persistent object cache,
	 * and that is the price of a value the sites have to agree on. What it
	 * does buy is presence: a network option that exists is one cache key,
	 * while an absent one is that read plus a second key recording that it is
	 * missing. And it puts the two of them somewhere a reader can find them,
	 * which is the point of the list above as well.
	 *
	 * The seeded value reads the same as the option's absence, with one
	 * deliberate exception. The sign-in secret is seeded from the main site's
	 * own, because a single site that becomes a network already holds a key it
	 * has been signing cookies with — replacing it here would sign every
	 * account out at the moment of the upgrade, with nothing said.
	 *
	 * @return array<string, mixed>
	 */
	public static function network(): array {
		return array(
			// Read on every request of every site, to decide whether the
			// network as a whole is standing enforcement down.
			\BetterShield\Recovery\SafeMode::NETWORK_OPTION => 0,
			// Read before anything can ask for a salt, on every site.
			\BetterShield\Hardening\Item\AuthKeys::OPTION  => '',
		);
	}

	/**
	 * @return string[]
	 */
	public static function network_names(): array {
		return array_keys( self::network() );
	}

	/**
	 * Seed the network's two, once for the network.
	 *
	 * `add_site_option` writes only what is missing, so this is safe to run
	 * from every site of a walk and from every upgrade: the first site through
	 * carries the main site's existing secret over, and nobody after it
	 * overwrites what is now the network's key.
	 */
	public static function seed_network(): void {
		if ( ! is_multisite() ) {
			return;
		}

		$main = get_main_site_id();

		foreach ( self::network() as $name => $default ) {
			$seed = \BetterShield\Hardening\Item\AuthKeys::OPTION === $name
				// Read from the main site by id rather than from whichever
				// site happens to be running this, so the walk that seeds it
				// carries the same value whichever site it reaches first.
				? (string) get_blog_option( $main, $name, '' )
				: $default;

			add_site_option( $name, $seed );
		}
	}

	/**
	 * Put every one of them where it costs nothing to read.
	 *
	 * Both halves are needed and neither covers the other. `add_option` seeds
	 * what is missing but will not touch an option that already exists, and a
	 * site that updated rather than reinstalled arrives here with whatever flag
	 * its rows were first written with — `update_option` only revisits the flag
	 * when the value changes, so without the second half the query per page
	 * view survives the update and goes away only if something happens to
	 * rewrite the row.
	 *
	 * Run from activation and from the schema migration, so both paths land in
	 * the same state.
	 */
	public static function seed(): void {
		foreach ( self::all() as $name => $default ) {
			// False means the site already has one, so only its flag can need
			// moving. Read from the return value rather than from a separate
			// existence check, which would be a second read of the same row.
			if ( add_option( $name, $default, '', true ) ) {
				continue;
			}

			// Present on the floor and everything above it; guarded so the
			// class stays readable on anything older that reaches it.
			if ( function_exists( 'wp_set_option_autoload' ) ) {
				wp_set_option_autoload( $name, true );
			}
		}

		self::seed_network();
	}
}
