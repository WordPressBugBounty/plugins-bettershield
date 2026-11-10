<?php
/**
 * A person's own sign-ins, and the ability to end one they do not recognize.
 *
 * `Sessions` manages sessions at the administrator's level: the whole list for
 * the whole site, and an end-everything button per account. That is the right
 * tool for the person running the site and the wrong one for everybody else.
 * The everyday need is personal and surgical — somebody notices a sign-in from
 * a place they have never been and wants to end *that one*, now, without
 * losing the work in front of them.
 *
 * **It lives on the profile screen, not on this plugin's own.** Every screen
 * this plugin draws needs a capability an author or a subscriber does not
 * have, and those are exactly the accounts that most need this: an editor
 * whose password leaked has no way to see it and no way to act. Core's profile
 * screen needs nothing beyond being signed in, and is where a person already
 * looks for things about their own account.
 *
 * **Server-rendered, not the admin app.** The app is enqueued on this plugin's
 * screens only, and loading it onto `profile.php` for one panel would put a
 * React bundle on a core screen for everybody on the site.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Login;

use BetterShield\Events\Writer;
use BetterShield\Support\ClientIp;
use BetterShield\Support\Ip;
use BetterShield\Support\Text;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class MySessions {

	private const ACTION = 'bettershield_end_session';

	/** The query argument that carries how many sessions the last press ended. */
	private const ENDED_ARG = 'bettershield_ended';

	/** The query argument set when the last press reported a session as not the owner's. */
	private const REPORTED_ARG = 'bettershield_reported';

	private static ?MySessions $instance = null;

	/** Whether the list is being drawn on a store's My Account tab. */
	private bool $in_store = false;

	public static function instance(): MySessions {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	public function register(): void {
		add_action( 'show_user_profile', array( $this, 'render' ) );
		add_action( 'admin_post_' . self::ACTION, array( $this, 'handle' ) );
	}

	/**
	 * The signed-in user's own live sessions, newest first.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public function mine(): array {
		$user_id = get_current_user_id();

		if ( 0 === $user_id ) {
			return array();
		}

		$stored = get_user_meta( $user_id, 'session_tokens', true );

		if ( ! is_array( $stored ) ) {
			return array();
		}

		$current = (string) wp_get_session_token();
		$now     = time();
		$out     = array();

		foreach ( $stored as $verifier => $session ) {
			if ( ! is_array( $session ) || (int) ( $session['expiration'] ?? 0 ) < $now ) {
				continue;
			}

			$out[] = array(
				'handle'       => $this->handle_for( (string) $verifier ),
				// Which row is the device the person is reading this on. Ending
				// it would sign them out mid-sentence, so it is labeled and
				// offered last.
				'is_current'   => '' !== $current && hash_equals( (string) $verifier, hash( 'sha256', $current ) ),
				'signed_in_at' => (int) ( $session['login'] ?? 0 ),
				'last_seen_at' => Sessions::last_seen( $session ),
				// The network, never the address — resolved and truncated the
				// same way the activity log does it, so a person behind a CDN
				// is shown where they were rather than where their CDN was.
				'network'      => Sessions::network_label( $session ),
				'browser'      => Text::clip( (string) ( $session['ua'] ?? '' ), 120 ),
				// What a person reads; the raw string stays on the tooltip.
				'device'       => Sessions::device_label( (string) ( $session['ua'] ?? '' ) ),
			);
		}

		usort(
			$out,
			static function ( array $a, array $b ): int {
				// Newest sign-in breaks the tie: with the idle timeout off no
				// activity is recorded, and the list fell back to oldest first.
				return array( $b['last_seen_at'], $b['signed_in_at'] ) <=> array( $a['last_seen_at'], $a['signed_in_at'] );
			}
		);

		return $out;
	}

	/**
	 * End one of the signed-in user's own sessions.
	 *
	 * Ending a device the owner recognizes is upkeep. Reporting one they do
	 * not is the start of an investigation, and was logged as the same
	 * routine sign-out, medium, so it raised no alert and read later as
	 * somebody tidying up (#2240). A report is its own row, high.
	 *
	 * @param string $handle   The session's handle.
	 * @param bool   $reported Whether the owner said the session was not theirs.
	 * @return bool Whether a session was found and ended.
	 */
	public function end_one( string $handle, bool $reported = false ): bool {
		$user_id = get_current_user_id();

		if ( 0 === $user_id || ! $this->per_session_supported() ) {
			return false;
		}

		$stored = get_user_meta( $user_id, 'session_tokens', true );

		if ( ! is_array( $stored ) ) {
			return false;
		}

		foreach ( array_keys( $stored ) as $verifier ) {
			if ( ! hash_equals( $this->handle_for( (string) $verifier ), $handle ) ) {
				continue;
			}

			unset( $stored[ $verifier ] );

			if ( array() === $stored ) {
				delete_user_meta( $user_id, 'session_tokens' );
			} else {
				update_user_meta( $user_id, 'session_tokens', $stored );
			}

			Writer::instance()->record(
				$reported ? 'session_reported_by_owner' : 'session_ended_by_owner',
				$reported ? Writer::SEVERITY_HIGH : Writer::SEVERITY_MEDIUM,
				array(
					'actor_type'  => 'user',
					'actor_id'    => $user_id,
					'object_type' => 'session',
					'object_id'   => (string) $user_id,
					'context'     => array( 'scope' => 'one' ),
				)
			);

			return true;
		}

		return false;
	}

	/**
	 * End everything except the device this was asked from.
	 *
	 * Always available: core's own `destroy_others()` takes the current token
	 * and needs no assumption about where sessions are stored. Recorded only
	 * when something was ended: with no other device signed in, a press logged
	 * "Signed out of a device" for nothing.
	 *
	 * @return int How many sessions were ended.
	 */
	public function end_others(): int {
		$token = (string) wp_get_session_token();

		if ( '' === $token ) {
			return 0;
		}

		$manager = \WP_Session_Tokens::get_instance( get_current_user_id() );
		$before  = count( $manager->get_all() );

		$manager->destroy_others( $token );

		$ended = max( 0, $before - count( $manager->get_all() ) );

		if ( 0 === $ended ) {
			return 0;
		}

		Writer::instance()->record(
			'session_ended_by_owner',
			Writer::SEVERITY_MEDIUM,
			array(
				'actor_type'  => 'user',
				'actor_id'    => get_current_user_id(),
				'object_type' => 'session',
				'object_id'   => (string) get_current_user_id(),
				'context'     => array( 'scope' => 'others' ),
			)
		);

		return $ended;
	}

	/**
	 * Whether ending a single session is possible on this site.
	 *
	 * Sessions live in user meta unless something replaced the manager, and
	 * ending one means removing its entry. A site that swapped the manager
	 * keeps the "end everything else" button, which core supports whatever the
	 * storage is, and loses the per-row one — rather than being offered a
	 * button that would silently do nothing.
	 */
	public function per_session_supported(): bool {
		// Asked of the manager this site actually built, rather than by
		// re-running the filter core used to choose it: a site that swapped
		// the class through some other route still answers correctly.
		return \WP_Session_Tokens::get_instance( get_current_user_id() ) instanceof \WP_User_Meta_Session_Tokens;
	}

	/**
	 * An opaque, stable name for one session.
	 *
	 * Not the verifier itself. The verifier is derived from the session token,
	 * and while knowing it does not let anybody forge that token, there is no
	 * reason to put a value derived from a live credential into a form on a
	 * page. Keyed with the plugin's own secret, so it means nothing anywhere
	 * else either.
	 */
	private function handle_for( string $verifier ): string {
		return substr( hash_hmac( 'sha256', 'session|' . $verifier, ClientIp::signing_secret() ), 0, 32 );
	}

	/* ---- the panel ---------------------------------------------------------- */

	/**
	 * The same list on a store's My Account tab, with its buttons dressed the
	 * way the store's theme dresses its own.
	 */
	public function render_in_store(): void {
		$this->in_store = true;

		try {
			$this->render();
		} finally {
			$this->in_store = false;
		}
	}

	/**
	 * When a session was last active, as the site's own date and time
	 * format, which the profile script then says in the reader's time, as
	 * the app's screens do. A fixed "j M Y, H:i" in site time read six hours
	 * apart from the same sign-in on Activity (#1934).
	 */
	private static function when( int $at ): string {
		return sprintf(
			'<time datetime="%1$s" data-bs-local>%2$s</time>',
			esc_attr( gmdate( 'Y-m-d\TH:i:s\Z', $at ) ),
			esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $at ) )
		);
	}

	public function render(): void {
		$sessions = $this->mine();

		if ( count( $sessions ) < 1 ) {
			return;
		}

		echo '<h2 id="bettershield-sessions">' . esc_html__( 'Where you are signed in', 'bettershield' ) . '</h2>';
		$description = __( 'Don’t recognize a device? Choose “This Was Not Me” to sign it out and add a note to the site’s activity log. Then change your password.', 'bettershield' );

		// Session tokens live on the account, which a network shares, so a
		// session ended here is ended on every site of it.
		if ( is_multisite() ) {
			$description .= ' ' . __( 'Signing out here signs you out of every site in this multisite network.', 'bettershield' );
		}

		echo '<p class="description">' . esc_html( $description ) . '</p>';

		// What the last press did, said where it was pressed.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- a count to display, read after the redirect.
		$ended = isset( $_GET[ self::ENDED_ARG ] ) ? absint( wp_unslash( $_GET[ self::ENDED_ARG ] ) ) : null;

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- a flag to display, read after the redirect.
		$reported = isset( $_GET[ self::REPORTED_ARG ] );

		if ( 1 === $ended && $reported ) {
			$this->render_next_steps( count( $sessions ) > 1 );
		} elseif ( null !== $ended ) {
			echo '<div class="notice notice-success inline"><p>' . esc_html(
				0 === $ended
					? __( 'No other devices were signed in, so nothing changed.', 'bettershield' )
					: sprintf(
						/* translators: %d: how many devices were signed out. */
						_n( 'Signed out of %d device.', 'Signed out of %d devices.', $ended, 'bettershield' ),
						$ended
					)
			) . '</p></div>';
		}

		// Its own box scrolls on a narrow screen, so the page does not.
		echo '<div style="max-width:60em;overflow-x:auto"><table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Device', 'bettershield' ) . '</th>';
		echo '<th>' . esc_html__( 'IP address', 'bettershield' ) . '</th>';
		// When each signed in, always there: while idle sign-out is off no
		// activity is recorded, and the rows had no time to tell them apart
		// by (#2111).
		echo '<th>' . esc_html__( 'Signed in', 'bettershield' ) . '</th>';
		echo '<th>' . esc_html__( 'Last active', 'bettershield' ) . '</th>';
		echo '<th><span class="screen-reader-text">' . esc_html__( 'Actions', 'bettershield' ) . '</span></th></tr></thead><tbody>';

		foreach ( $sessions as $session ) {
			echo '<tr><td>';
			if ( '' !== $session['device'] ) {
				echo '<span title="' . esc_attr( $session['browser'] ) . '">' . esc_html( $session['device'] ) . '</span>';
			} else {
				echo esc_html__( 'Unknown device', 'bettershield' );
			}

			if ( $session['is_current'] ) {
				echo ' <strong>' . esc_html__( '— this device', 'bettershield' ) . '</strong>';
			}

			echo '</td><td>' . esc_html( '' !== $session['network'] ? ( Ip::address_label( Ip::from_label( $session['network'] ) ) ?? $session['network'] ) : __( 'Not recorded', 'bettershield' ) ) . '</td>';
			echo '<td>' . ( $session['signed_in_at'] > 0 ? self::when( (int) $session['signed_in_at'] ) : esc_html__( 'Not recorded', 'bettershield' ) ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- when() escapes what it prints.
			// Not recorded while idle sign-out is off, rather than the sign-in
			// time read as the last activity (#2068). A dash in the cell and
			// the reason once under the table, as the Login & access screen
			// says it: the same sentence in every row read as clutter (#2842).
			echo '<td>' . ( $session['last_seen_at'] > 0 ? self::when( (int) $session['last_seen_at'] ) : '<span aria-hidden="true">—</span><span class="screen-reader-text">' . esc_html__( 'Not recorded', 'bettershield' ) . '</span>' ) . '</td><td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- when() escapes what it prints.

			if ( ! $session['is_current'] && $this->per_session_supported() ) {
				// Which device, in the name: up to ninety rows each read
				// "This Was Not Me" alike (#1928).
				$device = '' !== $session['device'] ? $session['device'] : __( 'An unnamed device', 'bettershield' );
				$format = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );

				$which  = $session['last_seen_at'] > 0
					? sprintf(
						/* translators: 1: a device, e.g. "Chrome on macOS"; 2: when it was last active. */
						__( '%1$s, last active %2$s', 'bettershield' ),
						$device,
						wp_date( $format, (int) $session['last_seen_at'] )
					)
					: sprintf(
						/* translators: 1: a device, e.g. "Chrome on macOS"; 2: when it signed in. */
						__( '%1$s, signed in %2$s', 'bettershield' ),
						$device,
						wp_date( $format, (int) $session['signed_in_at'] )
					);

				// Two meanings, two buttons: an old laptop is signed out
				// without saying it was somebody else, and a report is
				// recorded as one (#2240).
				$this->button( 'one', $session['handle'], __( 'Sign Out', 'bettershield' ), $which );
				echo ' ';
				$this->button( 'report', $session['handle'], __( 'This Was Not Me', 'bettershield' ), $which );
			}

			echo '</td></tr>';
		}

		echo '</tbody></table></div>';

		if ( array() !== array_filter( $sessions, static fn( array $session ): bool => $session['last_seen_at'] <= 0 ) ) {
			echo '<p class="description">' . esc_html__( 'Last activity shows once idle sign-out is on.', 'bettershield' ) . '</p>';
		}

		// Only when there is another device to sign out of, and only on a
		// store's My Account tab: wp-admin's profile already has WordPress's
		// own "Log Out Everywhere Else" for the same thing.
		if ( $this->in_store && array() !== array_filter( $sessions, static fn( array $session ): bool => ! $session['is_current'] ) ) {
			echo '<p>';
			$this->button( 'others', '', __( 'Log Out Everywhere Else', 'bettershield' ) );
			echo '</p>';
		}
	}

	/**
	 * What to do after reporting a session as not yours, which the intro
	 * promises: the password first, then the other devices, then the other
	 * ways in. The page only said "Signed out of 1 device." (#2240).
	 *
	 * @param bool $others Whether another device is still signed in.
	 */
	private function render_next_steps( bool $others ): void {
		$store    = StoreAccount::url_for( wp_get_current_user() );
		$password = null !== $store && function_exists( 'wc_get_account_endpoint_url' )
			? (string) wc_get_account_endpoint_url( 'edit-account' )
			: admin_url( 'profile.php#password' );

		echo '<div class="notice notice-warning inline"><p><strong>' . esc_html__( 'That device is signed out, and the site’s activity log notes it was not you. Next:', 'bettershield' ) . '</strong></p><ol>';
		echo '<li><a href="' . esc_url( $password ) . '">' . esc_html__( 'Change your password now.', 'bettershield' ) . '</a></li>';

		if ( $others ) {
			echo '<li>';
			$this->button( 'others', '', __( 'Log Out Everywhere Else', 'bettershield' ) );
			echo '</li>';
		}

		echo '<li><a href="#bettershield-two-factor">' . esc_html__( 'Check your two-factor sign-in.', 'bettershield' ) . '</a>';

		// Application passwords are on wp-admin's profile only.
		if ( null === $store ) {
			echo ' <a href="#application-passwords-section">' . esc_html__( 'Review your application passwords.', 'bettershield' ) . '</a>';
		}

		echo '</li></ol></div>';
	}

	/**
	 * A nonce link, not a form. This panel renders inside core's own profile
	 * form (`show_user_profile` fires within it), where a nested form start
	 * tag is dropped by the HTML parser — a submit button here would have
	 * saved the profile instead of ending the session, silently.
	 */
	private function button( string $scope, string $handle, string $label, string $which = '' ): void {
		$url = wp_nonce_url(
			add_query_arg(
				array(
					'action' => self::ACTION,
					'scope'  => $scope,
					'handle' => $handle,
				),
				admin_url( 'admin-post.php' )
			),
			self::ACTION
		);

		/*
		 * A theme's button class on an inline link wraps as an inline box, and
		 * the padded lines of a label too long for a narrow screen, or for a
		 * table cell, overlap and clip. On a store the link is laid out as a
		 * box that grows with its label instead; wp-admin's own buttons are
		 * boxes already.
		 */
		echo '<a class="' . esc_attr( $this->in_store ? 'button wp-element-button' : 'button' ) . '"'
			. ( $this->in_store ? ' style="display:inline-block;max-width:100%"' : '' )
			. ' href="' . esc_url( $url ) . '"'
			. ( '' !== $which
				? ' aria-label="' . esc_attr(
					sprintf(
						/* translators: 1: a control's words, e.g. "This Was Not Me"; 2: what it acts on. */
						_x( '%1$s: %2$s', 'a control, then what it acts on', 'bettershield' ),
						$label,
						$which
					)
				) . '"'
				: '' )
			. '>' . esc_html( $label ) . '</a>';
	}

	public function handle(): void {
		if ( ! is_user_logged_in() ) {
			wp_die( esc_html__( 'Sign in first.', 'bettershield' ), '', array( 'response' => 403 ) );
		}

		check_admin_referer( self::ACTION );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- verified immediately above.
		$scope = isset( $_REQUEST['scope'] ) ? sanitize_key( wp_unslash( (string) $_REQUEST['scope'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- as above.
		$handle = isset( $_REQUEST['handle'] ) ? sanitize_text_field( wp_unslash( (string) $_REQUEST['handle'] ) ) : '';

		/*
		 * Only ever the signed-in user's own sessions. There is no user id in
		 * this request and no way to name somebody else's — ending another
		 * account's session is an administrator's act and lives on the
		 * administrator's screen, behind the capability.
		 */
		$ended = null;

		if ( 'others' === $scope ) {
			$ended = $this->end_others();
		} elseif ( in_array( $scope, array( 'one', 'report' ), true ) && '' !== $handle ) {
			$ended = $this->end_one( $handle, 'report' === $scope ) ? 1 : 0;
		}

		$back = AccountPage::front_end_url( wp_get_current_user(), 'bettershield-sessions' ) ?? admin_url( 'profile.php#bettershield-sessions' );

		if ( null !== $ended ) {
			$back = add_query_arg( 'report' === $scope ? array( self::ENDED_ARG => $ended, self::REPORTED_ARG => 1 ) : array( self::ENDED_ARG => $ended ), $back );
		}

		wp_safe_redirect( $back );
		exit;
	}
}
