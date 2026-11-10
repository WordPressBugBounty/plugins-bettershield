<?php
/**
 * A way back in that does not depend on email.
 *
 * The recovery link is the owner's guaranteed way back, and it has one
 * dependency the invariant it serves does not: it arrives by email, and it is
 * replaced by email. An owner whose mail is broken, whose address has changed,
 * or whose inbox is the thing that was breached has a link they cannot receive
 * — and the whole point of a break-glass credential is that it works on the
 * day everything else does not.
 *
 * So: a small set of codes, shown once, meant to be printed and put somewhere
 * that is not this site. Each opens safe mode exactly once and is spent.
 *
 * **Nothing here weakens the link.** These are an addition rather than a
 * replacement, they enter the same safe mode through the same door, and every
 * refusal is counted by the same throttle. A site with codes still has its
 * link; a site with neither still has whatever it had before.
 *
 * **Spent means spent, decided by the database.** A code that could be
 * redeemed twice because two requests read the set before either wrote it back
 * would be a break-glass credential that is not single-use — so the write
 * carries the set it expects to replace, and the second request loses.
 *
 * **They are shown exactly once.** Only hashes are kept, which is what makes
 * a stolen copy of this site's database not a way into it.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Recovery;

use BetterShield\Events\Writer;
use BetterShield\Login\Protection;
use BetterShield\Support\Claim;
use BetterShield\Support\ClientIp;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class OfflineCodes {

	/** How many are issued at a time. */
	public const COUNT = 8;

	private const OPTION = 'bettershield_recovery_codes';

	/**
	 * How many wrong codes one address may cost this site in an hour.
	 *
	 * Far above what somebody reading a printed card off by one hand needs,
	 * and far below what guessing sixteen hex characters would take — the cap
	 * is here for what each attempt costs, not for the odds of one landing.
	 */
	private const GUESS_CAP    = 10;
	private const GUESS_WINDOW = HOUR_IN_SECONDS;

	/**
	 * Held for the read, the verify and the write together. Short, because it
	 * is a lock over three statements rather than a rate limit, and nothing
	 * holding it is waiting on anything slower than a bcrypt loop.
	 */
	private const SPEND_CLAIM   = 'offline_code_spend';
	private const SPEND_SECONDS = 15;

	/** Whether the last refusal was the guessing cap rather than the code. */
	private static bool $paused = false;

	/**
	 * Issue a fresh set, replacing whatever was there.
	 *
	 * The codes come back once and are never retrievable again. Only their
	 * hashes are stored.
	 *
	 * An empty set means the store refused the write and no codes were
	 * issued. Codes handed out and never stored open nothing, and shown once
	 * they cannot be checked against anything afterward — so a refused write
	 * hands back nothing and records nothing, the way `attempt()` on the
	 * spending side of this class already refuses on its own.
	 *
	 * `update_option()` also answers false for a value that has not changed, so
	 * what is checked is that the option holds the set afterward rather than
	 * that the write reported a change.
	 *
	 * @return string[] The codes, to be shown and then forgotten, or none.
	 */
	public static function issue(): array {
		$codes  = array();
		$hashes = array();

		for ( $i = 0; $i < self::COUNT; $i++ ) {
			/*
			 * Sixteen hex characters — 64 bits, which is far more than a
			 * second factor needs because this is not a second factor. It is
			 * the whole credential, presented by somebody with no session, and
			 * it opens safe mode on its own. Grouped in fours so it can be
			 * read off paper and typed without losing your place.
			 */
			$raw = bin2hex( random_bytes( 8 ) );

			// Two codes of one set with the same tag would share a key.
			if ( isset( $hashes[ self::tag( $raw ) ] ) ) {
				--$i;
				continue;
			}

			$codes[]                    = implode( '-', str_split( $raw, 4 ) );
			$hashes[ self::tag( $raw ) ] = password_hash( $raw, PASSWORD_DEFAULT );
		}

		if ( ! update_option( self::OPTION, $hashes, false ) && get_option( self::OPTION ) !== $hashes ) {
			return array();
		}

		Writer::instance()->record(
			'recovery_link_generated',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'recovery',
				'object_id'   => 'offline_codes',
				'context'     => array(
					'count' => self::COUNT,
					// So a reader can tell this row from the emailed link's.
					'kind'  => 'offline_codes',
				),
			)
		);

		return $codes;
	}

	/** How many are left unspent. */
	public static function remaining(): int {
		$hashes = get_option( self::OPTION, array() );

		return is_array( $hashes ) ? count( $hashes ) : 0;
	}

	/**
	 * Whether a set was ever issued here, used up or not: the last code used
	 * leaves an empty set on record, where none was ever issued leaves none.
	 * Told apart so the screens do not say "None issued" of a used-up set.
	 */
	public static function ever_issued(): bool {
		return is_array( get_option( self::OPTION, null ) );
	}

	/** Whether this site has any at all. */
	public static function exist(): bool {
		return self::remaining() > 0;
	}

	public static function forget(): void {
		delete_option( self::OPTION );
	}

	/**
	 * Whether a value has the shape of a printed code: sixteen hex digits once
	 * the separators a person types are taken out. A recovery link's token is
	 * sixty-four, so the recovery page can tell which one it was handed
	 * without checking either.
	 */
	public static function shaped_like_code( string $submitted ): bool {
		return 1 === preg_match( '/^[a-f0-9]{16}$/', self::normalize( $submitted ) );
	}

	/**
	 * A short keyed fingerprint a code's hash is filed under (#2773).
	 *
	 * Behind a proxy nobody has named, every visitor shares one guessing
	 * cap, so strangers can fill it. Past it, the bcrypt set is checked only
	 * for a code whose fingerprint is on file: a random guess matches one in
	 * about two million, so guessing still costs this site nothing, and the
	 * owner's own code is not refused for what strangers did.
	 *
	 * Six hex characters of an HMAC under this plugin's own secret. A stolen
	 * database still leaves forty bits of each code behind bcrypt.
	 */
	private static function tag( string $code ): string {
		return 't' . substr( hash_hmac( 'sha256', 'offline_code|' . $code, ClientIp::signing_secret() ), 0, 6 );
	}

	/**
	 * Whether the last refusal was the pause on guessing, not the code. The
	 * page says so then: telling an owner whose code is fine that it is not
	 * valid sends them to throw it away.
	 */
	public static function paused(): bool {
		return self::$paused;
	}

	private static function normalize( string $submitted ): string {
		return strtolower( (string) preg_replace( '/[^0-9a-fA-F]/', '', $submitted ) );
	}

	/**
	 * Spend a code and enter safe mode, or refuse.
	 *
	 * The refusal is deliberately indistinguishable from the recovery link's:
	 * same throttle, same answer, so the page never says whether a code was
	 * real, spent, or never issued. A pause on guessing is said as a pause
	 * (see paused()), which tells nothing about the code either.
	 */
	public static function attempt( string $submitted ): bool {
		$submitted    = self::normalize( $submitted );
		self::$paused = false;

		// Every code this plugin issues is sixteen hex characters, so anything
		// else was never one and is refused before it can reach the log.
		if ( ! self::shaped_like_code( $submitted ) ) {
			return false;
		}

		/*
		 * Checking a code means a bcrypt verify against every code still
		 * unspent, and this runs for anyone who can reach the site — no
		 * account, no session. A wrong sixteen-hex value matches none of them,
		 * so it costs the whole set. Counted per address in one statement, and
		 * refused before the set is even read.
		 *
		 * Per address only while the address is somebody: behind a proxy
		 * nobody has named, every visitor is one address, and eleven guesses
		 * by a stranger took the printed codes away from the owner — on the
		 * day the codes exist for. `rate_bucket()` counts that case site-wide
		 * with a cap to match, so the bound on what guessing costs holds. And
		 * past that shared cap a code is still checked when its fingerprint is
		 * on file (see tag()): strangers filled it, and the owner's valid code
		 * was refused as not valid (#2773).
		 *
		 * Per address, too, only while the address is not the request's own to
		 * write. On an edge nobody has vouched for, the client address is a
		 * header: one connection rotating it had a fresh bucket per value and
		 * guessing cost it nothing to keep doing. What counts there is the
		 * address the request really arrived from — the one half of the pair
		 * it did not choose — and everybody that edge forwards shares it, so
		 * it counts against the shared cap.
		 */
		$resolved = ClientIp::resolve( Protection::trusted_proxies(), Protection::cloudflare() );
		$bucket = ClientIp::rate_bucket( $resolved, 'ocrate', self::GUESS_CAP );

		$count = Claim::bump_or_fail( $bucket['key'], self::GUESS_WINDOW );

		if ( null === $count ) {
			RecoveryLink::record_failure();

			return false;
		}

		$over = $count > $bucket['cap'];

		$tag = self::tag( $submitted );

		/*
		 * One address's own cap is that address's own doing. Past the shared
		 * one, a code with no hash filed under its fingerprint is refused
		 * here, before the spend is claimed: a flood of guesses holding the
		 * claim would turn the owner's code away just the same.
		 */
		if ( $over && ( ! $bucket['shared'] || ! array_key_exists( $tag, (array) get_option( self::OPTION, array() ) ) ) ) {
			self::$paused = true;
			RecoveryLink::record_failure();

			return false;
		}

		/*
		 * The whole read, verify and write is taken as one, because the write
		 * replaces the entire set: two requests spending different codes would
		 * each write back what they read, and the second would restore the
		 * code the first had just spent. A break-glass credential that is not
		 * single-use is not single-use.
		 *
		 * A caller that loses is refused, which is the same answer a wrong
		 * code gets and by design indistinguishable from it. The claim is
		 * released on every path out, so a genuine retry a moment later is not
		 * held off by a window it has no way to see.
		 */
		if ( ! Claim::claim( self::SPEND_CLAIM, self::SPEND_SECONDS ) ) {
			RecoveryLink::record_failure();

			return false;
		}

		$hashes = get_option( self::OPTION, array() );

		if ( ! is_array( $hashes ) || array() === $hashes ) {
			Claim::release( self::SPEND_CLAIM );
			RecoveryLink::record_failure();

			return false;
		}

		// Past the shared cap, only the hash filed under this code's
		// fingerprint is checked, so a guess costs no bcrypt there.
		foreach ( $hashes as $index => $hash ) {
			if ( $over && $tag !== $index ) {
				continue;
			}

			if ( ! is_string( $hash ) || ! password_verify( $submitted, $hash ) ) {
				continue;
			}

			$remaining = $hashes;
			unset( $remaining[ $index ] );

			// A set issued before fingerprints is a plain list, kept as one.
			if ( ! update_option( self::OPTION, is_string( $index ) ? $remaining : array_values( $remaining ), false ) ) {
				Claim::release( self::SPEND_CLAIM );

				return false;
			}

			Claim::release( self::SPEND_CLAIM );

			$duration = (int) apply_filters( 'bettershield_safe_mode_duration', HOUR_IN_SECONDS );

			// One entry, recorded by the door itself. How many codes are left
			// travels with it rather than as a second row.
			SafeMode::enter( $duration, 'recovery_code', array( 'remaining' => count( $remaining ) ) );

			return true;
		}

		Claim::release( self::SPEND_CLAIM );
		self::$paused = $over;
		RecoveryLink::record_failure();

		return false;
	}
}
