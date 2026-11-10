<?php
/**
 * Fix for "A user is named "admin"" (#2430).
 *
 * The account keeps everything it has: its ID, posts, role, password,
 * passkeys and sessions. Only the username changes, to one the owner types
 * and core's own rules accept. WordPress has no screen for this, so without
 * it the owner's only way was a second account and a deletion.
 *
 * The old name is kept first, and undo puts it back while "admin" is still
 * free. Renaming the account doing the renaming would end its session, since
 * the sign-in cookie names the account by its username; so that session is
 * carried over to the new name rather than ended.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Audit\Auditor;
use BetterShield\Events\Writer;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AdminUsername {

	public const ACTION = 'admin_username_renamed';

	/** The name the finding is about. */
	public const NAME = 'admin';

	/** The other columns a rename may change, by the key the undo keeps each under. */
	private const COLUMNS = array(
		'user_nicename' => 'nicename',
		'display_name'  => 'display',
	);

	/**
	 * The account named "admin", if there is one, and whether this reader
	 * may rename it.
	 *
	 * @return array{account: array<string, mixed>|null, refused: string, network: bool}
	 */
	public static function state(): array {
		$id   = (int) username_exists( self::NAME );
		$user = $id > 0 ? get_userdata( $id ) : false;

		return array(
			'account' => $user instanceof \WP_User ? array(
				'id'    => $id,
				'login' => (string) $user->user_login,
				'you'   => get_current_user_id() === $id,
				'posts' => (int) count_user_posts( $id ),
			) : null,
			'refused' => $user instanceof \WP_User ? self::refusal( $id ) : '',
			'network' => is_multisite(),
		);
	}

	/**
	 * Why this reader may not rename the account, or ''.
	 *
	 * On a network the username is the network's: it signs in on every
	 * site, so the say over it is the network administrator's.
	 */
	public static function refusal( int $id ): string {
		if ( ! current_user_can( 'edit_user', $id ) ) {
			return __( 'You cannot change this account.', 'bettershield' );
		}

		if ( is_multisite() && ! current_user_can( 'manage_network_users' ) ) {
			return __( 'On a network, a username signs in on every site, so a network administrator renames it.', 'bettershield' );
		}

		return '';
	}

	/**
	 * What is wrong with a new username, by core's rules, or ''.
	 *
	 * Core's own checks, in its own order: the characters a username may
	 * hold, its length, the names this site refuses, and a name or email
	 * address another account already signs in with. A network keeps to the
	 * stricter rule its sign-up form uses.
	 */
	public static function invalid( string $name, int $id ): string {
		if ( '' === trim( $name ) || sanitize_user( $name, true ) !== $name || ! validate_username( $name ) ) {
			return __( 'Use only letters, numbers, spaces and these marks: . - _ @', 'bettershield' );
		}

		if ( mb_strlen( $name ) > 60 ) {
			return __( 'Use 60 characters or fewer.', 'bettershield' );
		}

		if ( is_multisite() && ( preg_match( '/[^a-z0-9]/', $name ) || strlen( $name ) < 4 ) ) {
			return __( 'On a network, use at least 4 lowercase letters or numbers, with no spaces or marks.', 'bettershield' );
		}

		if ( 0 === strcasecmp( $name, self::NAME ) ) {
			return __( 'Choose a name other than admin.', 'bettershield' );
		}

		/** This filter is documented in wp-includes/user.php */
		$illegal = array_map( 'strtolower', (array) apply_filters( 'illegal_user_logins', array() ) ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core's own filter, asked as core asks it.

		if ( in_array( strtolower( $name ), $illegal, true ) ) {
			return __( 'That username is not allowed on this site.', 'bettershield' );
		}

		if ( username_exists( $name ) ) {
			return __( 'Another account already uses that username.', 'bettershield' );
		}

		$by_email = email_exists( $name );

		if ( false !== $by_email && (int) $by_email !== $id ) {
			return __( 'Another account signs in with that as its email address.', 'bettershield' );
		}

		return '';
	}

	/**
	 * Rename the account called "admin", kept first for undo.
	 *
	 * @return array{from: string, to: string, you: bool, undo: string}|\WP_Error
	 */
	public static function rename( string $name ) {
		$id = (int) username_exists( self::NAME );

		if ( $id <= 0 ) {
			return new \WP_Error( 'bettershield_no_admin', __( 'No account is named admin now, so nothing was changed.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$refusal = self::refusal( $id );

		if ( '' !== $refusal ) {
			return new \WP_Error( 'bettershield_account_refused', $refusal, array( 'status' => 403 ) );
		}

		$invalid = self::invalid( $name, $id );

		if ( '' !== $invalid ) {
			return new \WP_Error( 'bettershield_username_invalid', $invalid, array( 'status' => 400 ) );
		}

		// The author slug and the shown name, where they still say "admin".
		$also  = self::also( $id, $name );
		$prior = array( 'user' => $id, 'login' => self::NAME );
		$after = array( 'login' => $name );

		foreach ( $also as $column => $value ) {
			$prior[ self::COLUMNS[ $column ] ] = self::NAME;
			$after[ self::COLUMNS[ $column ] ] = $value;
		}

		// Kept before anything changes: no record, no change.
		$token = Ledger::open( self::ACTION, $prior, $after );

		if ( null === $token ) {
			return new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}

		$you = get_current_user_id() === $id;

		if ( ! self::set_login( $id, self::NAME, $name, $also ) ) {
			Ledger::mark_reverted( $token );

			return new \WP_Error( 'bettershield_rename_failed', __( 'The username could not be changed. Nothing else was touched; try again.', 'bettershield' ), array( 'status' => 500 ) );
		}

		self::recorded( $id, self::NAME, $name, $token );
		Auditor::run();

		return array(
			'from' => self::NAME,
			'to'   => $name,
			'you'  => $you,
			'undo' => $token,
		);
	}

	/**
	 * Put the name "admin" back, while no other account has taken it and
	 * the account still has the name it was given here.
	 *
	 * @return array{login: string, you: bool}|\WP_Error
	 */
	public static function undo( string $token ) {
		$entry = '' === $token ? null : Ledger::find( $token );

		if ( null === $entry || self::ACTION !== (string) $entry->action_key ) {
			return new \WP_Error( 'bettershield_unknown_token', __( 'No undo record exists for that change.', 'bettershield' ), array( 'status' => 404 ) );
		}

		if ( null !== $entry->reverted_at ) {
			return new \WP_Error( 'bettershield_already_reverted', __( 'That change has already been undone.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$id   = (int) ( $entry->prior_state['user'] ?? 0 );
		$to   = (string) ( $entry->applied_state['login'] ?? '' );
		$user = $id > 0 ? get_userdata( $id ) : false;

		if ( ! $user instanceof \WP_User || $user->user_login !== $to ) {
			return new \WP_Error( 'bettershield_renamed_since', __( 'The account was renamed again since, so it keeps the name it has.', 'bettershield' ), array( 'status' => 409 ) );
		}

		if ( username_exists( self::NAME ) ) {
			return new \WP_Error( 'bettershield_admin_taken', __( 'Another account is named admin now, so this one keeps its new name.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$refusal = self::refusal( $id );

		if ( '' !== $refusal ) {
			return new \WP_Error( 'bettershield_account_refused', $refusal, array( 'status' => 403 ) );
		}

		// The slug and the shown name go back only where the rename set them
		// and nothing has changed them since; a slug another account took in
		// the meantime stays that account's.
		$back = array();

		foreach ( self::COLUMNS as $column => $key ) {
			if ( ! isset( $entry->applied_state[ $key ] ) || (string) $user->{$column} !== (string) $entry->applied_state[ $key ] ) {
				continue;
			}

			if ( 'user_nicename' === $column && self::slug_taken( self::NAME, $id ) ) {
				continue;
			}

			$back[ $column ] = (string) ( $entry->prior_state[ $key ] ?? self::NAME );
		}

		if ( ! self::set_login( $id, $to, self::NAME, $back ) ) {
			return new \WP_Error( 'bettershield_rename_failed', __( 'The username could not be changed back. Try again.', 'bettershield' ), array( 'status' => 500 ) );
		}

		Ledger::mark_reverted( $token );
		self::recorded( $id, $to, self::NAME, '' );
		Auditor::run();

		return array(
			'login' => self::NAME,
			'you'   => get_current_user_id() === $id,
		);
	}

	/**
	 * The other columns the rename changes with the username: the author
	 * slug, which puts the old name in every author address, while it is
	 * still "admin" and the new slug is free; and the shown name while it is
	 * exactly "admin".
	 *
	 * @return array<string, string> Column => new value.
	 */
	private static function also( int $id, string $name ): array {
		$user = get_userdata( $id );
		$also = array();

		if ( ! $user instanceof \WP_User ) {
			return $also;
		}

		$slug = sanitize_title( mb_substr( $name, 0, 50 ) );

		if ( self::NAME === (string) $user->user_nicename && '' !== $slug && self::NAME !== $slug && ! self::slug_taken( $slug, $id ) ) {
			$also['user_nicename'] = $slug;
		}

		if ( self::NAME === (string) $user->display_name ) {
			$also['display_name'] = $name;
		}

		return $also;
	}

	/** Whether another account already has this author slug. */
	private static function slug_taken( string $slug, int $id ): bool {
		$other = get_user_by( 'slug', $slug );

		return $other instanceof \WP_User && (int) $other->ID !== $id;
	}

	/**
	 * Whether this rename can still be undone: the account still has the
	 * name it was given, "admin" is still free, and this reader may rename
	 * it. Each way back still open, for the list kept after the finding
	 * closes.
	 *
	 * @return array<int, array{name: string, to: string, undo: string}>
	 */
	public static function open_renames(): array {
		$open = array();

		foreach ( Ledger::open_token_page( self::ACTION, PHP_INT_MAX, 10 ) as $token ) {
			$entry = Ledger::find( $token );
			$id    = null !== $entry && is_array( $entry->prior_state ) ? (int) ( $entry->prior_state['user'] ?? 0 ) : 0;
			$to    = null !== $entry && is_array( $entry->applied_state ) ? (string) ( $entry->applied_state['login'] ?? '' ) : '';
			$user  = $id > 0 ? get_userdata( $id ) : false;

			if ( ! $user instanceof \WP_User || '' === $to || $user->user_login !== $to || username_exists( self::NAME ) || '' !== self::refusal( $id ) ) {
				continue;
			}

			$open[] = array(
				'name' => self::NAME,
				'to'   => $to,
				'undo' => $token,
			);
		}

		return $open;
	}

	/**
	 * One account's username changed, only while it is still `$from`, and
	 * this session carried over where it is that account's.
	 *
	 * Core's update functions leave a username alone, so the row is written
	 * here and the caches core keeps of it are cleared as core clears them.
	 */
	private static function set_login( int $id, string $from, string $to, array $also = array() ): bool {
		global $wpdb;

		$before = get_userdata( $id );

		if ( ! $before instanceof \WP_User || $before->user_login !== $from ) {
			return false;
		}

		// The sign-in cookie names its account; read before the name moves.
		$remember = self::remembered();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- core has no API that changes a username; the caches are cleared below.
		$changed = $wpdb->update( $wpdb->users, array( 'user_login' => $to ) + $also, array( 'ID' => $id, 'user_login' => $from ) );

		clean_user_cache( $before );
		wp_cache_delete( $to, 'userlogins' );

		if ( isset( $also['user_nicename'] ) ) {
			wp_cache_delete( $also['user_nicename'], 'userslugs' );
		}

		if ( 1 !== $changed ) {
			return false;
		}

		if ( get_current_user_id() === $id ) {
			self::keep_session( $id, $remember );
		}

		return true;
	}

	/**
	 * Whether this browser's sign-in was a "Remember me" one: core gives
	 * that cookie fourteen days and any other two.
	 */
	private static function remembered(): bool {
		$cookie = wp_parse_auth_cookie( '', 'logged_in' );

		return is_array( $cookie ) && (int) $cookie['expiration'] - time() > 3 * DAY_IN_SECONDS;
	}

	/**
	 * The same session, under the new name. The cookie names the account by
	 * its username, so without new cookies the next request would be signed
	 * out; the session token is kept, so nothing else about it changes.
	 */
	private static function keep_session( int $id, bool $remember ): void {
		$token = wp_get_session_token();

		if ( '' === $token ) {
			return;
		}

		wp_set_auth_cookie( $id, $remember, is_ssl(), $token );
	}

	private static function recorded( int $id, string $from, string $to, string $undo ): void {
		Writer::instance()->record(
			'username_changed',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $id,
				'context'     => array_filter(
					array(
						'from' => $from,
						'to'   => $to,
						'undo' => $undo,
					)
				),
			)
		);
	}
}
