<?php
/**
 * Whether this site is where it was: noticing a staging copy or a move.
 *
 * A copy of a site carries everything the original had: its alert
 * addresses, its hub connection, its usage identity, its recovery link. On a
 * staging copy that means alerts about the copy reaching the owner as if they
 * were about the live site, and a hub that sees two sites as one; after a
 * move it means a recovery link that points at the old address.
 *
 * So the address and the folder the site runs from are remembered, and when
 * either changes the owner is asked which it is. Nothing is decided for them:
 * the Overview names what changed and lists what each answer does before it
 * does it, and each answer has one undo that puts back what it changed.
 *
 * - A staging copy: alerts are muted, the hub's connection is refused, and
 *   usage reporting stops, on this copy only. The live site, with its own
 *   database, is untouched.
 * - A move: the new address becomes the one remembered, and the owner is sent
 *   to issue a recovery link for it and to check the files here. Those two
 *   are the owner's own steps, on the screens that do them, because a
 *   recovery link has to be seen to be stored.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Onboarding;

use BetterShield\Alerts\Settings as AlertSettings;
use BetterShield\Events\Writer;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SiteIdentity {

	/** Where the address and folder this site is known by are kept. */
	public const OPTION = 'bettershield_site_identity';

	/** The undo record an answer writes. */
	public const UNDO = 'site_identity_answer';

	/**
	 * The undo of the move whose card the owner said they are done with. The
	 * card goes; the undo stays open.
	 */
	public const DONE_OPTION = 'bettershield_site_identity_done';

	/** What marks an address kept out of a search-replace's reach. */
	private const ENCODED = 'b64:';

	public const STAGING = 'staging';
	public const MOVED   = 'moved';

	/**
	 * The site as it is now: its address without the scheme, and a digest of
	 * the folder it runs from, so a copy on another server is told apart from
	 * a copy at another address.
	 *
	 * @return array{home: string, root: string}
	 */
	public static function current(): array {
		return array(
			'home' => self::address( home_url( '/' ) ),
			'root' => hash( 'sha256', self::folder_of( ABSPATH ) ),
		);
	}

	/**
	 * The folder a site runs from, as it is compared: a release folder of an
	 * atomic deploy read as one folder.
	 *
	 * Capistrano, Deployer, Envoyer and Trellis serve each deploy from its
	 * own `releases/<id>` folder behind a `current` symlink, and PHP resolves
	 * ABSPATH through the symlink, so every deploy read as the site running
	 * from somewhere else and the Overview asked again.
	 */
	public static function folder_of( string $path ): string {
		$path = wp_normalize_path( untrailingslashit( $path ) );

		return (string) preg_replace( '#/releases/[^/]+(?=/|$)#', '/releases/*', $path );
	}

	/**
	 * What is remembered, or null before the first look.
	 *
	 * @return array{home: string, root: string, role: string, original: string, recorded_at: int}|null
	 */
	public static function recorded(): ?array {
		$stored = get_option( self::OPTION, null );

		if ( ! is_array( $stored ) || ! isset( $stored['home'], $stored['root'] ) ) {
			return null;
		}

		return array(
			'home'        => self::decoded( (string) $stored['home'] ),
			'root'        => (string) $stored['root'],
			'role'        => self::STAGING === ( $stored['role'] ?? '' ) ? self::STAGING : 'live',
			'original'    => self::decoded( (string) ( $stored['original'] ?? '' ) ),
			'recorded_at' => (int) ( $stored['recorded_at'] ?? 0 ),
		);
	}

	/**
	 * Remember the site as it is, the first time it is looked at, and say
	 * nothing: there is nothing yet to compare against.
	 */
	public static function remember_first(): void {
		// Looked at means somebody's dashboard, not the admin-ajax.php or
		// admin-post.php request `admin_init` also fires on with nobody signed
		// in, which a store's queue runner makes about once a minute.
		if ( wp_doing_ajax() || ! is_user_logged_in() ) {
			return;
		}

		if ( null !== self::recorded() ) {
			return;
		}

		update_option( self::OPTION, self::stored( array_merge( self::current(), array( 'role' => 'live', 'recorded_at' => time() ) ) ), false );
	}

	/**
	 * A record as it is written: its addresses in a form a search-replace on
	 * the host name does not touch.
	 *
	 * Written as plain text, a move or copy made with `wp search-replace
	 * 'old.example' 'new.example'` rewrote the remembered address with
	 * everything else, so an in-place move was never noticed and a copy was
	 * named a copy of itself. The folder was already kept as a digest; the
	 * address has to be read back, because the card shows it.
	 *
	 * @param array<string, mixed> $record
	 * @return array<string, mixed>
	 */
	private static function stored( array $record ): array {
		foreach ( array( 'home', 'original' ) as $key ) {
			if ( isset( $record[ $key ] ) && '' !== (string) $record[ $key ] ) {
				$record[ $key ] = self::ENCODED . base64_encode( (string) $record[ $key ] ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- not obfuscation: kept out of reach of a search-replace, and read back by decoded().
			}
		}

		return $record;
	}

	/**
	 * An address as it was written: encoded since the search-replace fix,
	 * plain before it.
	 */
	private static function decoded( string $value ): string {
		if ( 0 !== strpos( $value, self::ENCODED ) ) {
			return $value;
		}

		$plain = base64_decode( substr( $value, strlen( self::ENCODED ) ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- the other half of stored().

		return is_string( $plain ) ? $plain : '';
	}

	/**
	 * What changed since the site was last remembered, or null when nothing
	 * did.
	 *
	 * @return array{from: string, to: string, kind: string}|null
	 */
	public static function change(): ?array {
		$recorded = self::recorded();

		if ( null === $recorded ) {
			return null;
		}

		$now = self::current();

		if ( $recorded['home'] !== $now['home'] ) {
			return array(
				'from' => $recorded['home'],
				'to'   => $now['home'],
				'kind' => 'address',
			);
		}

		// A record written before release folders were read as one holds the
		// folder as it was, which is still this folder.
		if ( $recorded['root'] !== $now['root'] && $recorded['root'] !== hash( 'sha256', wp_normalize_path( untrailingslashit( ABSPATH ) ) ) ) {
			return array(
				'from' => $recorded['home'],
				'to'   => $now['home'],
				'kind' => 'server',
			);
		}

		/*
		 * A copy marked staging before stored() kept addresses out of a
		 * search-replace's reach holds them as plain host names. Pushed over
		 * the live site with the copy's host name search-replaced into the
		 * live site's, its own address became the live site's, and at the
		 * same folder, which a container or a host that keeps one path for
		 * every copy gives it, nothing above differs: the live site stayed a
		 * staging copy for good and was never asked. Such a record, at the
		 * very address it names as the live site's, is asked about once
		 * more. A copy kept at that address on another server reads the
		 * same and is asked once too; either answer writes the record
		 * encoded, and the question is not asked again.
		 */
		if ( self::STAGING === $recorded['role'] && '' !== $recorded['original'] && $recorded['original'] === $now['home'] && self::written_plain() ) {
			return array(
				'from' => $recorded['home'],
				'to'   => $now['home'],
				'kind' => 'original',
			);
		}

		return null;
	}

	/**
	 * Whether the record holds its address as it was written before
	 * stored(): a plain host name, which a search-replace may already have
	 * rewritten.
	 */
	private static function written_plain(): bool {
		$stored = get_option( self::OPTION, null );

		return is_array( $stored ) && isset( $stored['home'] ) && 0 !== strpos( (string) $stored['home'], self::ENCODED );
	}

	/**
	 * Whether this site has been marked a staging copy, and is still where
	 * that answer was given.
	 *
	 * A host's "push staging to live" copies the staging role onto the live
	 * site with everything else, and the live site then refused the hub, sent
	 * no alert and reported no usage until somebody answered on the Overview.
	 * A copy that is no longer at the address and folder it was marked staging
	 * at is asked again, and behaves as the live site until it is answered.
	 */
	public static function is_staging(): bool {
		$recorded = self::recorded();

		return null !== $recorded && self::STAGING === $recorded['role'] && null === self::change();
	}

	/**
	 * Whether this site was marked a staging copy somewhere other than where
	 * it runs now: the question the Overview and every admin screen ask.
	 */
	public static function left_staging(): bool {
		$recorded = self::recorded();

		return null !== $recorded && self::STAGING === $recorded['role'] && null !== self::change();
	}

	/**
	 * Whether the alerts are muted only because a staging answer muted them,
	 * on a site that is no longer where that answer was given. A mute the
	 * owner set themselves is theirs, and stands wherever the site is.
	 */
	public static function staging_mute_lapsed(): bool {
		$stored = get_option( self::OPTION, null );

		return is_array( $stored ) && ! empty( $stored['muted_by_staging'] ) && self::left_staging();
	}

	/**
	 * On every admin screen, for whoever can answer it: a site marked a
	 * staging copy is running somewhere else. Only the Overview asked, and
	 * alerts were muted, so nobody was told.
	 */
	public static function notice(): void {
		if ( ! current_user_can( \BetterShield\Capabilities::MANAGE ) || ! self::left_staging() ) {
			return;
		}

		// At the live site's own address nothing that is compared has changed,
		// so "another address or another server" is not what the owner sees.
		$said = 'original' === ( self::change()['kind'] ?? '' )
			? __( 'BetterShield: this site was marked as a test (staging) copy but now runs at the live site’s address.', 'bettershield' )
			: __( 'BetterShield: this site was marked as a test (staging) copy but now runs at a new address.', 'bettershield' );

		$said .= ' ' . __( 'Is it still a test copy, or the live site? Until you answer, alerts are sent and BetterShield Hub can connect.', 'bettershield' );

		echo '<div class="notice notice-warning"><p>' . esc_html( $said ) . ' <a href="' . esc_url( admin_url( 'admin.php?page=bettershield' ) ) . '">' . esc_html__( 'Answer now', 'bettershield' ) . '</a></p></div>';
	}

	/**
	 * What each answer would do, said before it is done.
	 *
	 * @return array<string, string[]>
	 */
	public static function plan(): array {
		$plan = array(
			self::STAGING => array(
				__( 'Mute alerts from this copy.', 'bettershield' ),
				__( 'Refuse the hub’s connection here, so it only reaches the live site.', 'bettershield' ),
				__( 'Stop usage reporting from this copy.', 'bettershield' ),
				__( 'Send no lockout or new sign-in location emails from this copy.', 'bettershield' ),
				__( 'Remember this address as staging, and show that on the Overview.', 'bettershield' ),
			),
			self::MOVED   => array(
				__( 'Remember this as the site’s address and server.', 'bettershield' ),
				__( 'Then issue a recovery link for this address, since yours points at the old one.', 'bettershield' ),
				__( 'Then re-run the file check for this server.', 'bettershield' ),
			),
		);

		/**
		 * What each answer would do, for an add-on that stops something of its
		 * own on a staging copy to say so before the answer is given.
		 *
		 * @param array<string, string[]> $plan Lines by answer.
		 */
		$filtered = apply_filters( 'bettershield_site_identity_plan', $plan );

		return is_array( $filtered ) ? $filtered : $plan;
	}

	/**
	 * Answer the question, with one undo for everything the answer changed.
	 *
	 * @return array{undo: string, answer: string}|\WP_Error
	 */
	public static function answer( string $answer ) {
		if ( ! in_array( $answer, array( self::STAGING, self::MOVED ), true ) ) {
			return new \WP_Error( 'bettershield_bad_answer', __( 'Say whether this is a staging copy or a move.', 'bettershield' ), array( 'status' => 400 ) );
		}

		$change = self::change();

		if ( null === $change ) {
			return new \WP_Error( 'bettershield_nothing_changed', __( 'This site has not moved, so there is nothing to answer.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$prior  = get_option( self::OPTION, null );
		$alerts = AlertSettings::instance();
		$muted  = (bool) $alerts->settings()['muted'];

		$token = Ledger::open(
			self::UNDO,
			array(
				'identity'     => $prior,
				'alerts_muted' => $muted,
			),
			array( 'answer' => $answer )
		);

		if ( null === $token ) {
			return new \WP_Error( 'bettershield_undo_unavailable', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}

		$now = self::current();

		// Already a staging copy, asked again because its address or its
		// folder changed: what that first answer recorded still stands.
		$was_staging = is_array( $prior ) && self::STAGING === ( $prior['role'] ?? '' );

		if ( self::STAGING === $answer ) {
			if ( ! $muted ) {
				$result = $alerts->update_settings( array( 'muted' => true ) );

				if ( is_wp_error( $result ) ) {
					Ledger::mark_reverted( $token );

					return $result;
				}
			}

			update_option(
				self::OPTION,
				self::stored(
					array_merge(
						$now,
						array(
							'role'             => self::STAGING,
						// The live site it is a copy of. Asked again after its
						// address or folder changed, the address just before is
						// the earlier staging one, or its own: the first
						// answer's still names the live site.
							'original'         => $was_staging && '' !== self::decoded( (string) ( $prior['original'] ?? '' ) ) ? self::decoded( (string) $prior['original'] ) : $change['from'],
							'recorded_at'      => time(),
							// So a later move can un-mute what this muted, and
							// nothing the owner muted themselves. A second
							// staging answer finds the mute the first one set,
							// which is still staging's, not the owner's.
							'muted_by_staging' => ! $muted || ( $was_staging && ! empty( $prior['muted_by_staging'] ) ),
						)
					)
				),
				false
			);
		} else {
			// A staging copy that has become the live site: what marking it
			// staging muted is heard again.
			if ( is_array( $prior ) && ! empty( $prior['muted_by_staging'] ) && $muted ) {
				$result = $alerts->update_settings( array( 'muted' => false ) );

				if ( is_wp_error( $result ) ) {
					Ledger::mark_reverted( $token );

					return $result;
				}
			}

			update_option( self::OPTION, self::stored( array_merge( $now, array( 'role' => 'live', 'recorded_at' => time() ) ) ), false );
		}

		Writer::instance()->record(
			self::STAGING === $answer ? 'site_marked_staging' : 'site_marked_moved',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'site',
				'object_id'   => $now['home'],
				'context'     => array(
					'from' => $change['from'],
					'kind' => $change['kind'],
					'undo' => $token,
				),
			)
		);

		return array(
			'undo'   => $token,
			'answer' => $answer,
		);
	}

	/**
	 * Put back what an answer changed: what was remembered, and the alerts
	 * as they were. The question is asked again.
	 *
	 * @return true|\WP_Error
	 */
	public static function undo( string $token ) {
		$entry = Ledger::find( $token );

		if ( null === $entry || self::UNDO !== (string) $entry->action_key ) {
			return new \WP_Error( 'bettershield_unknown_undo', __( 'There is no such answer on record.', 'bettershield' ), array( 'status' => 404 ) );
		}

		if ( null !== $entry->reverted_at ) {
			return new \WP_Error( 'bettershield_already_reverted', __( 'That answer has already been taken back.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$prior = is_array( $entry->prior_state ) ? $entry->prior_state : array();

		if ( is_array( $prior['identity'] ?? null ) ) {
			update_option( self::OPTION, $prior['identity'], false );
		} else {
			delete_option( self::OPTION );
		}

		$alerts = AlertSettings::instance();

		if ( (bool) $alerts->settings()['muted'] !== (bool) ( $prior['alerts_muted'] ?? false ) ) {
			$alerts->update_settings( array( 'muted' => (bool) ( $prior['alerts_muted'] ?? false ) ) );
		}

		Ledger::mark_reverted( $token );

		Writer::instance()->record(
			'site_identity_undone',
			Writer::SEVERITY_LOW,
			array(
				'object_type' => 'site',
				'object_id'   => self::current()['home'],
			)
		);

		return true;
	}

	/**
	 * Whether taking an answer back would quieten the site: mute alerts that
	 * are heard now, or mark it a staging copy again, which refuses the hub
	 * and stops usage reports. Taking back "it moved" on a copy that had been
	 * marked staging does both. An answer that cannot be taken back is not
	 * judged here; the undo itself refuses it.
	 */
	public static function undo_quietens( string $token ): bool {
		$entry = Ledger::find( $token );

		if ( null === $entry || self::UNDO !== (string) $entry->action_key || null !== $entry->reverted_at ) {
			return false;
		}

		$prior    = is_array( $entry->prior_state ) ? $entry->prior_state : array();
		$identity = is_array( $prior['identity'] ?? null ) ? $prior['identity'] : array();
		$mutes    = ! empty( $prior['alerts_muted'] ) && ! (bool) AlertSettings::instance()->settings()['muted'];

		return $mutes || ( self::STAGING === ( $identity['role'] ?? '' ) && ! self::is_staging() );
	}

	/**
	 * Hide the card left after a move, keeping its undo open. Only the open
	 * answer of a move has that card; anything else is refused.
	 *
	 * @return true|\WP_Error
	 */
	public static function done( string $token ) {
		$entry = '' !== $token && self::open_undo() === $token ? Ledger::find( $token ) : null;

		if ( null === $entry || ! is_array( $entry->applied_state ) || self::MOVED !== ( $entry->applied_state['answer'] ?? '' ) ) {
			return new \WP_Error( 'bettershield_nothing_to_hide', __( 'There is no card after a move to hide.', 'bettershield' ), array( 'status' => 409 ) );
		}

		update_option( self::DONE_OPTION, $token, false );

		return true;
	}

	/**
	 * The one answer that can still be taken back, newest first, or ''.
	 */
	public static function open_undo(): string {
		$tokens = Ledger::open_tokens( self::UNDO, 1 );

		return $tokens[0] ?? '';
	}

	/**
	 * For the Overview: what changed, if anything, what each answer does,
	 * and whether this is a staging copy.
	 *
	 * @return array<string, mixed>
	 */
	public static function overview(): array {
		$recorded = self::recorded();
		$undo     = self::open_undo();
		$entry    = '' !== $undo ? Ledger::find( $undo ) : null;

		return array(
			'change'   => self::change(),
			'plan'     => self::plan(),
			'staging'  => self::is_staging(),
			'original' => null !== $recorded ? $recorded['original'] : '',
			'undo'     => $undo,
			// Which answer that undo takes back, so the card left after a
			// move, its two steps and its undo, is drawn on every visit and
			// not only in the moment it was answered.
			'answer'   => null !== $entry && is_array( $entry->applied_state ) ? (string) ( $entry->applied_state['answer'] ?? '' ) : '',
			// Whether the owner said they are done with that card. Kept
			// against the one undo, so a later move shows its card again.
			'done'     => '' !== $undo && get_option( self::DONE_OPTION, '' ) === $undo,
		);
	}

	/**
	 * An address the way two copies of a site are compared: host and path,
	 * lowercased, without the scheme or a trailing slash.
	 */
	private static function address( string $url ): string {
		$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
		$port = wp_parse_url( $url, PHP_URL_PORT );
		$path = untrailingslashit( (string) wp_parse_url( $url, PHP_URL_PATH ) );

		return $host . ( $port ? ':' . $port : '' ) . $path;
	}
}
