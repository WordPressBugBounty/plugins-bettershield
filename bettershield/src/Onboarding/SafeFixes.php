<?php
/**
 * The five fixes the Quick Setup offers, and nothing else.
 *
 * Each one is an existing hardening item, applied through the same manager
 * and the same undo ledger as a press on the Hardening tab, so there is no
 * second way of changing the site to keep in step with the first. What sets
 * these five apart is that none of them can lock anybody out or break a page:
 * nothing that gates signing in, nothing about the admin area, nothing that
 * rewrites a shared file.
 *
 * One of them does change what signing in says. Stopping username discovery
 * gives a wrong password and an unknown username the same answer, and answers
 * a password reset the same way whether or not the account exists. That keeps
 * nobody out, and it is ticked by default, so its line in the setup says so
 * rather than leaving it to the Hardening tab.
 *
 * The list is closed on purpose. The sign-in address, the admin gate,
 * application passwords, authentication keys, HSTS, PHP in uploads, sensitive
 * files, a content security policy and XML-RPC are all left to the Hardening
 * tab, where each has room to explain what it could break.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Onboarding;

use BetterShield\Audit\Auditor;
use BetterShield\Audit\Checks;
use BetterShield\Hardening\Item\DirectoryBrowsing;
use BetterShield\Hardening\Manager;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SafeFixes {

	/**
	 * The hardening item behind each fix, and the audit check that says
	 * whether it is already in force. Directory browsing has no check: its
	 * state is read from the folders themselves.
	 */
	private const ITEMS = array(
		'file_editor'        => 'file_editor_enabled',
		'version_disclosure' => 'version_disclosed',
		'directory_browsing' => null,
		'user_enumeration'   => 'user_listing_public',
		'security_headers'   => 'security_headers_missing',
	);

	/**
	 * Where the last applied set is kept: each fix it applied, in order, with
	 * the undo token the manager gave it. Undoing the set goes by token, so a
	 * fix changed by hand since, or one that was on before the set, is never
	 * taken away by it.
	 */
	public const SET_OPTION = 'bettershield_setup_fix_set';

	/**
	 * The fixes this setup turned on: the ones its Safe Fixes step applied,
	 * and the ones the Ready step's switches put back on. Kept apart from the
	 * set, which undoing the set clears: a fix switched back on after that
	 * was counted as "already on", as if it had been on before setup ran
	 * (#2248).
	 */
	public const APPLIED_OPTION = 'bettershield_setup_fix_applied';

	/**
	 * The item ids, in the order the screen lists them.
	 *
	 * @return string[]
	 */
	public static function ids(): array {
		return array_keys( self::ITEMS );
	}

	public static function is_offered( string $item ): bool {
		return array_key_exists( $item, self::ITEMS );
	}

	/**
	 * What the owner reads for each fix.
	 *
	 * @return array<string, array{title: string, description: string}>
	 */
	private static function copy(): array {
		return array(
			'file_editor'        => array(
				'title'       => __( 'Turn off the file editor', 'bettershield' ),
				'description' => __( 'Stops theme and plugin files being edited from the dashboard.', 'bettershield' ),
			),
			'version_disclosure' => array(
				'title'       => __( 'Hide the WordPress version', 'bettershield' ),
				'description' => __( 'Removes the version number from your pages.', 'bettershield' ),
			),
			'directory_browsing' => array(
				'title'       => __( 'Folder listing protection', 'bettershield' ),
				'description' => __( 'Stops folder contents being listed in a browser.', 'bettershield' ),
			),
			'user_enumeration'   => array(
				'title'       => __( 'Hide usernames', 'bettershield' ),
				// What changes at sign-in stays on the line; the reset form's
				// answer goes behind the ⓘ (#1329).
				'description' => __( 'Hides usernames from public pages, and sign-in errors no longer reveal whether a username exists.', 'bettershield' ),
				'detail'      => __( 'A password reset always says a link was sent.', 'bettershield' ),
			),
			'security_headers'   => array(
				'title'       => __( 'Turn on browser protections', 'bettershield' ),
				'description' => __( 'Tells visitors’ browsers to turn on built-in protections, such as not letting other sites show your pages in a frame.', 'bettershield' ),
			),
		);
	}

	/**
	 * Where each fix stands right now, read from the site rather than from
	 * anything this setup remembers.
	 *
	 * `on` is whether the protection is in force. `ours` is whether this
	 * plugin is the thing providing it, which is what decides whether an Undo
	 * can be offered: a fix set in wp-config.php or by another plugin is on,
	 * and not this plugin's to take away.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function describe(): array {
		$manager = Manager::instance();
		$copy    = self::copy();
		$out     = array();

		foreach ( self::ITEMS as $item => $check ) {
			$ours = $manager->is_active( $item );
			$on   = $ours || self::in_force_elsewhere( $item, $check );

			$out[] = array(
				'id'          => $item,
				'title'       => $copy[ $item ]['title'],
				'description' => $copy[ $item ]['description'],
				// The why behind the row's ⓘ, where it has one.
				'detail'      => $copy[ $item ]['detail'] ?? '',
				'on'          => $on,
				'ours'        => $ours,
				'source'      => $ours ? 'bettershield' : ( $on ? self::source_of( $item ) : '' ),
				// Which plugin, where it is another one.
				'source_name' => $ours ? '' : Coexistence::applied_elsewhere( $item ),
			);
		}

		return $out;
	}

	/**
	 * How many of the five are on.
	 */
	public static function on_count(): int {
		return count( array_filter( self::describe(), static fn( array $fix ): bool => (bool) $fix['on'] ) );
	}

	/**
	 * This plugin's own switch went off: the last audit passed with it on, so
	 * that answer says nothing about the server or another plugin (#2655).
	 */
	public static function switched_off( string $item ): void {
		$check = self::ITEMS[ $item ] ?? null;

		if ( null !== $check && in_array( $item, array( 'security_headers', 'version_disclosure' ), true ) ) {
			Auditor::forget_answer( $check );
		}
	}

	/**
	 * Whether one of the safe fixes is in force without this plugin's switch
	 * (the server refuses folder listing, another plugin does it), so the
	 * Hardening screen and the Overview say what the Quick Setup says
	 * (#2632). Beyond the safe fixes, for what the web server is seen refusing
	 * or a setting already off where this plugin's switch would turn it off.
	 */
	public static function enforced_without_us( string $item ): bool {
		// Not one of the safe fixes, and still in force without the switch
		// when the web server refuses xmlrpc.php: the probe's stored answer,
		// read without a request.
		if ( 'xmlrpc' === $item ) {
			return ! Manager::instance()->is_active( $item ) && \BetterShield\Audit\XmlRpc::blocked();
		}

		if ( in_array( $item, array( 'uploads_php', 'sensitive_files' ), true ) ) {
			return ! Manager::instance()->is_active( $item ) && \BetterShield\Hardening\ServerRules::enforced( $item );
		}

		if ( 'php_error_display' === $item ) {
			$checks = Checks::all();

			return ! Manager::instance()->is_active( $item ) && isset( $checks['debug_display_enabled']['test'] ) && null === ( $checks['debug_display_enabled']['test'] )();
		}

		if ( 'application_passwords' === $item ) {
			return ! Manager::instance()->is_active( $item ) && null !== \BetterShield\Hardening\Item\ApplicationPasswords::conflict();
		}

		if ( ! array_key_exists( $item, self::ITEMS ) || Manager::instance()->is_active( $item ) ) {
			return false;
		}

		// Only the answers read without a request: these are asked on every
		// Hardening and Overview read. The header and version checks fetch a
		// page, so for those two the last audit's answer stands in: it passed
		// with this switch off, so the server or another plugin does it
		// (#2655).
		$cheap = array( 'directory_browsing', 'file_editor' );

		if ( in_array( $item, $cheap, true ) ) {
			return self::in_force_elsewhere( $item, self::ITEMS[ $item ] );
		}

		if ( '' !== Coexistence::applied_elsewhere( $item ) ) {
			return true;
		}

		$check = self::ITEMS[ $item ];

		return in_array( $item, array( 'security_headers', 'version_disclosure' ), true ) && null !== $check && Auditor::passed_last_run( $check );
	}

	/**
	 * Who enforces an item that is in force without this plugin's switch: the
	 * other plugin's name, `host` where the server or its configuration is
	 * what was seen, and empty where the site only shows it's in force.
	 */
	public static function enforced_by( string $item ): string {
		$plugin = Coexistence::applied_elsewhere( $item );

		if ( '' !== $plugin ) {
			return $plugin;
		}

		if ( 'file_editor' === $item ) {
			return defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ? 'host' : '';
		}

		return in_array( $item, array( 'xmlrpc', 'uploads_php', 'sensitive_files', 'directory_browsing' ), true ) ? 'host' : '';
	}

	/**
	 * Whether a fix is in force without this plugin having applied it.
	 */
	private static function in_force_elsewhere( string $item, ?string $check ): bool {
		// Another security plugin that does it with a switch of its own.
		if ( '' !== Coexistence::applied_elsewhere( $item ) ) {
			return true;
		}

		if ( 'directory_browsing' === $item ) {
			$uploads = wp_get_upload_dir();
			$base    = is_array( $uploads ) ? (string) ( $uploads['basedir'] ?? '' ) : '';

			// No uploads folder at all is nothing to list, not a fix in force.
			if ( '' === $base || ! is_dir( $base ) ) {
				return false;
			}

			// Or the web server, asked for such a folder, refused to list it.
			return array() === DirectoryBrowsing::bare_directories( $base, 1 ) || \BetterShield\Audit\FolderListing::refused();
		}

		// Nothing this plugin can enforce hides usernames, so only its own
		// switch counts; the check would only restate that.
		if ( 'user_enumeration' === $item || null === $check ) {
			return false;
		}

		$checks = Checks::all();

		if ( ! isset( $checks[ $check ]['test'] ) || ! is_callable( $checks[ $check ]['test'] ) ) {
			return false;
		}

		try {
			return null === ( $checks[ $check ]['test'] )();
		} catch ( \Throwable $unreadable ) {
			unset( $unreadable );

			return false;
		}
	}

	/**
	 * Where a fix this plugin did not apply comes from, when that can be named.
	 */
	private static function source_of( string $item ): string {
		if ( '' !== Coexistence::applied_elsewhere( $item ) ) {
			return 'plugin';
		}

		if ( 'file_editor' === $item && (
			( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) || ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS )
		) ) {
			return 'wp-config';
		}

		return 'elsewhere';
	}

	/**
	 * What each fix that is not on yet would do, read before anything is
	 * applied: the same dry run a Hardening preview reads, with its effect
	 * lines, its conflict warning and whether it can work on this server.
	 *
	 * `recommended` is false for a fix with a conflict or one this server
	 * cannot honor, and the screen starts those unticked: a set that breaks
	 * one site in a hundred is worse than applying them one at a time.
	 *
	 * @return array<int, array{id: string, effect: string[], conflict_warning: ?string, available: bool, availability_note: ?string, recommended: bool}>
	 */
	public static function preview(): array {
		$manager = Manager::instance();
		$out     = array();

		foreach ( self::describe() as $fix ) {
			if ( $fix['on'] ) {
				continue;
			}

			$probe = $manager->dry_run( $fix['id'] );

			if ( is_wp_error( $probe ) ) {
				continue;
			}

			$out[] = array(
				'id'                => $fix['id'],
				'effect'            => array_values( array_map( 'strval', (array) $probe['effect'] ) ),
				'conflict_warning'  => null === $probe['conflict_warning'] ? null : (string) $probe['conflict_warning'],
				'available'         => (bool) $probe['available'],
				'availability_note' => null === $probe['availability_note'] ? null : (string) $probe['availability_note'],
				'recommended'       => (bool) $probe['available'] && null === $probe['conflict_warning'],
			);
		}

		return $out;
	}

	/**
	 * Apply the fixes that were ticked and are not already on.
	 *
	 * Each goes through the manager on its own, so each has its own ledger row
	 * and its own undo, and one that cannot be applied does not stop the rest.
	 * The audit runs once at the end rather than once per fix, so the grade on
	 * the Ready step is read after all of them.
	 *
	 * A fix whose dry run warns of a conflict is held unless `$confirmed`
	 * names it, which the screen does only for one ticked after its warning
	 * was shown: unticking it there is the promise, and this is what keeps it
	 * when the ticks arrive before the preview does. One this server cannot
	 * honor is not applied at all.
	 *
	 * `$rejoin` is the Ready step's switch putting back on a fix it switched
	 * off: a fix of the recorded set rejoins that set under its new token,
	 * and one the set never held leaves the set as it is. Without it, the
	 * newest set replaces the record of an older one.
	 *
	 * @param string[] $items     The ticked fixes.
	 * @param string[] $confirmed The ticked fixes whose conflict warning was shown.
	 * @param bool     $rejoin    Whether fixes switched off on the Ready step are being put back on.
	 * @return array{applied: string[], failed: array<string, string>, held: string[]}
	 */
	public static function apply( array $items, array $confirmed = array(), bool $rejoin = false ): array {
		$manager = Manager::instance();
		$current = array();

		foreach ( self::describe() as $fix ) {
			$current[ $fix['id'] ] = $fix;
		}

		$applied   = array();
		$failed    = array();
		$held      = array();
		$set       = array();
		$confirmed = array_map( 'strval', $confirmed );

		foreach ( array_values( array_unique( array_map( 'strval', $items ) ) ) as $item ) {
			if ( ! self::is_offered( $item ) || ! empty( $current[ $item ]['on'] ) ) {
				continue;
			}

			$probe = $manager->dry_run( $item );

			if ( ! is_wp_error( $probe ) && empty( $probe['available'] ) ) {
				$failed[ $item ] = null !== $probe['availability_note'] ? (string) $probe['availability_note'] : __( 'This fix cannot work on this server.', 'bettershield' );
				continue;
			}

			if ( ! is_wp_error( $probe ) && null !== $probe['conflict_warning'] && ! in_array( $item, $confirmed, true ) ) {
				$held[]          = $item;
				$failed[ $item ] = sprintf(
					/* translators: %s: why the fix may conflict with something already on the site. */
					__( '%s Left off. Tick it and apply again to apply it anyway.', 'bettershield' ),
					(string) $probe['conflict_warning']
				);
				continue;
			}

			$result = $manager->apply( $item );

			if ( is_wp_error( $result ) ) {
				$failed[ $item ] = $result->get_error_message();
				continue;
			}

			$applied[] = $item;
			$set[]     = array(
				'item'  => $item,
				'token' => (string) ( $result['undo_token'] ?? '' ),
			);
		}

		if ( array() !== $applied && $rejoin ) {
			/*
			 * Switched off and on again at the end of the setup: a fix of the
			 * recorded set is still that set, under the token it now carries.
			 * Recorded as a set of its own, it replaced the set, and the other
			 * fixes lost the undo that takes them back together. A fix the set
			 * never held (one applied on the Hardening tab, say) keeps its own
			 * Undo there and leaves the set alone.
			 */
			$stored   = get_option( self::SET_OPTION, array() );
			$recorded = self::recorded_set();
			$tokens   = array_column( $set, 'token', 'item' );
			$changed  = false;

			foreach ( $recorded as $index => $entry ) {
				if ( isset( $tokens[ $entry['item'] ] ) ) {
					$recorded[ $index ]['token'] = $tokens[ $entry['item'] ];
					$changed                     = true;
				}
			}

			if ( $changed ) {
				update_option(
					self::SET_OPTION,
					array(
						'at'    => is_array( $stored ) && isset( $stored['at'] ) ? (int) $stored['at'] : time(),
						'items' => $recorded,
					),
					false
				);
			}
		} elseif ( array() !== $applied ) {
			// The newest set replaces the record of an older one. The fixes an
			// older set applied keep their own Undo on the Hardening tab.
			update_option(
				self::SET_OPTION,
				array(
					'at'    => time(),
					'items' => $set,
				),
				false
			);
		}

		if ( array() !== $applied ) {
			/*
			 * What setup turned on, for the Ready step's count. A run replaces
			 * the record as it replaces the set; a fix put back on from the
			 * Ready step joins it, whether or not the set still holds it, so it
			 * is counted as applied there rather than as already on (#2248).
			 */
			$before = $rejoin ? self::applied_record() : array();

			update_option( self::APPLIED_OPTION, array_values( array_unique( array_merge( $before, $applied ) ) ), false );

			Auditor::run();
		}

		return array(
			'applied' => $applied,
			'failed'  => $failed,
			'held'    => $held,
		);
	}

	/**
	 * The fixes of the last applied set that the set can still take back:
	 * still applied by this plugin, under the token the set recorded.
	 *
	 * @return string[]
	 */
	public static function set_items(): array {
		$manager = Manager::instance();
		$items   = array();

		foreach ( self::recorded_set() as $entry ) {
			if ( $manager->is_active( $entry['item'] ) && ( $manager->item_state( $entry['item'] )['token'] ?? '' ) === $entry['token'] ) {
				$items[] = $entry['item'];
			}
		}

		return $items;
	}

	/**
	 * The fixes this setup turned on that this plugin still has on: what the
	 * Ready step counts as applied, every other fix on being one that was on
	 * before setup ran (#2248).
	 *
	 * A site whose setup ran before the record was kept counts the set, as
	 * the Ready step did before.
	 *
	 * @return string[]
	 */
	public static function applied_items(): array {
		if ( false === get_option( self::APPLIED_OPTION, false ) ) {
			return self::set_items();
		}

		$manager = Manager::instance();

		return array_values( array_filter( self::applied_record(), static fn( string $item ): bool => $manager->is_active( $item ) ) );
	}

	/**
	 * The recorded fixes setup turned on, with anything malformed or no
	 * longer offered left out.
	 *
	 * @return string[]
	 */
	private static function applied_record(): array {
		$stored = get_option( self::APPLIED_OPTION, array() );

		return array_values( array_unique( array_filter( is_array( $stored ) ? $stored : array(), static fn( $item ): bool => is_string( $item ) && self::is_offered( $item ) ) ) );
	}

	/**
	 * Undo the last applied set, newest first, by the token each fix was
	 * applied under.
	 *
	 * A fix changed since the set applied it — undone and applied again, or
	 * given new options — carries a different token and is left as it is and
	 * named; a fix that is already off is named too. A fix that was on before
	 * the set was never in it. The record is cleared afterwards, so the set
	 * can be undone once.
	 *
	 * @return array{reverted: string[], skipped: array<string, string>}|\WP_Error
	 */
	public static function undo_set() {
		$set = self::recorded_set();

		if ( array() === $set ) {
			return new \WP_Error( 'bettershield_no_fix_set', __( 'There is no set of fixes to undo.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$manager  = Manager::instance();
		$reverted = array();
		$skipped  = array();
		$kept     = array();

		foreach ( array_reverse( $set ) as $entry ) {
			if ( ! $manager->is_active( $entry['item'] ) ) {
				$skipped[ $entry['item'] ] = __( 'Already undone.', 'bettershield' );
				continue;
			}

			$result = $manager->revert_if_token( $entry['item'], $entry['token'] );

			if ( is_wp_error( $result ) ) {
				$stale = 'bettershield_stale_item' === $result->get_error_code();

				$skipped[ $entry['item'] ] = $stale
					? __( 'Changed since it was applied, so it was left alone.', 'bettershield' )
					: $result->get_error_message();

				// A fix changed since is no longer the set's to take back. One
				// that could not be undone just now (another change holding the
				// protections, say) still is, and stays on the set for a retry.
				if ( ! $stale ) {
					$kept[] = $entry;
				}

				continue;
			}

			$reverted[] = $entry['item'];
		}

		/*
		 * The record went whatever happened, so a fix skipped for a moment
		 * left the set for good: the retry answered "no set to undo" with the
		 * fix still on. It goes only when nothing in it is left to undo.
		 */
		if ( array() === $kept ) {
			delete_option( self::SET_OPTION );
		} else {
			$stored = get_option( self::SET_OPTION, array() );

			update_option(
				self::SET_OPTION,
				array(
					'at'    => is_array( $stored ) ? (int) ( $stored['at'] ?? time() ) : time(),
					'items' => array_reverse( $kept ),
				),
				false
			);
		}

		if ( array() !== $reverted ) {
			Auditor::run();
		}

		return array(
			'reverted' => $reverted,
			'skipped'  => $skipped,
			// The ones still on the set, which undoing the set again will try.
			'kept'     => array_column( array_reverse( $kept ), 'item' ),
		);
	}

	/**
	 * The recorded set, with anything malformed or no longer offered left out.
	 *
	 * @return array<int, array{item: string, token: string}>
	 */
	private static function recorded_set(): array {
		$stored = get_option( self::SET_OPTION, array() );
		$set    = array();

		foreach ( is_array( $stored ) ? (array) ( $stored['items'] ?? array() ) : array() as $entry ) {
			if ( is_array( $entry ) && is_string( $entry['item'] ?? null ) && is_string( $entry['token'] ?? null ) && '' !== $entry['token'] && self::is_offered( $entry['item'] ) ) {
				$set[] = array(
					'item'  => $entry['item'],
					'token' => $entry['token'],
				);
			}
		}

		return $set;
	}

	/**
	 * Undo one fix this plugin applied, through the same revert the Hardening
	 * tab uses.
	 *
	 * @return true|\WP_Error
	 */
	public static function undo( string $item ) {
		if ( ! self::is_offered( $item ) ) {
			return new \WP_Error( 'bettershield_not_a_safe_fix', __( 'That is not one of the Quick Setup fixes.', 'bettershield' ), array( 'status' => 400 ) );
		}

		if ( ! Manager::instance()->is_active( $item ) ) {
			return new \WP_Error( 'bettershield_not_applied', __( 'That fix is not applied, so there is nothing to undo.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$result = Manager::instance()->revert( $item );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		Auditor::run();

		return true;
	}
}
