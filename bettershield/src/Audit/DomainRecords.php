<?php
/**
 * Whether the site's domain says who may send its mail and who may issue
 * its certificates.
 *
 * WordPress sends its password resets from the site's own domain. A domain
 * with no SPF record and no DMARC policy gives a receiving mail server
 * nothing to check that against, so a message pretending to come from the
 * site is delivered as readily as a real one, and "reset your password"
 * phishing aimed at the site's own users looks exactly like the site. A
 * missing CAA record lets any certificate authority issue for the domain.
 *
 * Asked with the server's own DNS lookups, the same resolver that delivers
 * its mail: nothing is sent to any service this plugin chooses. A lookup
 * that fails is a stated "could not tell", never a missing record, and a
 * domain nobody outside the machine can resolve is not asked about at all.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Audit;

use BetterShield\Support\Environment;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class DomainRecords {

	/** Where the last answer is kept. */
	public const OPTION = 'bettershield_domain_records';

	/**
	 * Names set aside for private use, which the public DNS never answers
	 * for. Kept here rather than among the environment's local names, which
	 * grade the site as a development copy.
	 */
	private const PRIVATE_USE = array( '.internal', '.home.arpa' );

	/** The longest record kept whole; past it a record is kept as unknown. */
	private const RECORD_MAX = 2048;

	/** A problem that lets somebody else send mail as the domain. */
	private const SPOOFING = array( 'spf_missing', 'spf_multiple', 'spf_allows_all', 'dmarc_missing', 'dmarc_multiple' );

	/**
	 * Look the records up, and remember the answer.
	 *
	 * @return array{checked_at: string, domain: string, reliable: bool, reason?: string, problems: string[], spf?: string, spf_records?: array<int, ?string>, dmarc?: string, dmarc_at?: string, caa?: ?bool, ns?: string[], mx?: string[]}
	 */
	public static function lookup(): array {
		$domain = self::domain();
		$answer = array(
			'checked_at' => gmdate( 'c' ),
			'domain'     => $domain,
			'reliable'   => true,
			'problems'   => array(),
		);

		// An address, public or private, has no domain name to keep records
		// at: its dotted parts would be looked up as names and read as
		// missing records.
		$is_address = false !== filter_var( trim( $domain, '[]' ), FILTER_VALIDATE_IP );

		if ( '' === $domain || $is_address || false === strpos( $domain, '.' ) || Environment::is_local_host( $domain ) || self::private_use( $domain ) ) {
			return self::unreliable( $answer, 'not_public' );
		}

		/*
		 * A name the public DNS does not answer for (unregistered, or one
		 * only an intranet knows) answers "nothing" to every lookup, and that
		 * read as no SPF, no DMARC and no CAA. The site's own host is asked
		 * for an address first: none, and there are no records to miss.
		 */
		$addresses = self::records( strtolower( (string) wp_parse_url( network_home_url(), PHP_URL_HOST ) ), 'A' );

		if ( null === $addresses ) {
			return self::unreliable( $answer, 'lookup_failed' );
		}

		if ( array() === $addresses ) {
			return self::unreliable( $answer, 'not_public' );
		}

		$txt = self::records( $domain, 'TXT' );

		if ( null === $txt ) {
			return self::unreliable( $answer, 'lookup_failed' );
		}

		$spf = self::starting( $txt, 'v=spf1' );

		if ( array() === $spf ) {
			$answer['problems'][] = 'spf_missing';
		} elseif ( count( $spf ) > 1 ) {
			$answer['problems'][] = 'spf_multiple';
		} elseif ( 1 === preg_match( '/(?:^|\s)\+?all(?:\s|$)/i', $spf[0] ) ) {
			// A mechanism with no qualifier is a pass (RFC 7208 4.6.2), so a
			// bare all lets every server send exactly as +all does.
			$answer['problems'][] = 'spf_allows_all';
		}

		if ( array() !== $spf ) {
			$answer['spf'] = \BetterShield\Support\Text::clip( $spf[0], 255 );
		}

		/*
		 * Every SPF record whole, for the Fix panel's merged value (#2203):
		 * a value built from a clipped record would drop what was cut. One
		 * longer than any real record is kept as unknown, never cut.
		 */
		$answer['spf_records'] = array();

		foreach ( $spf as $record ) {
			$answer['spf_records'][] = strlen( $record ) > self::RECORD_MAX ? null : $record;
		}

		/*
		 * A subdomain without a policy of its own is covered by the one above
		 * it, so the lookup climbs until it finds one. Stopping at two labels
		 * is an approximation of where the registered domain starts; on a
		 * suffix like co.uk it asks one name too many, which finds nothing.
		 */
		$dmarc = null;

		foreach ( self::names_up( $domain ) as $name ) {
			$records = self::records( '_dmarc.' . $name, 'TXT' );

			if ( null === $records ) {
				return self::unreliable( $answer, 'lookup_failed' );
			}

			$found = self::starting( $records, 'v=DMARC1' );

			if ( array() !== $found ) {
				$dmarc              = $found[0];
				$answer['dmarc_at'] = '_dmarc.' . $name;

				// More than one at a name ends the lookup with no policy at
				// all (RFC 7489 6.6.3), whatever either of them says.
				if ( count( $found ) > 1 ) {
					$answer['problems'][] = 'dmarc_multiple';
					$dmarc                = '';
				}

				break;
			}
		}

		if ( null === $dmarc ) {
			$answer['problems'][] = 'dmarc_missing';
		} elseif ( '' !== $dmarc ) {
			$answer['dmarc'] = \BetterShield\Support\Text::clip( $dmarc, 255 );
			// Whole, for a Fix that keeps every tag but the policy (#2203).
			$answer['dmarc_full'] = strlen( $dmarc ) > self::RECORD_MAX ? null : $dmarc;

			/*
			 * A policy found above the site's own domain applies to it as a
			 * subdomain, by its sp= tag where it has one and p= otherwise
			 * (RFC 7489 6.3). Read by p= alone, p=reject; sp=none read as
			 * protected and p=none; sp=reject as monitor-only.
			 */
			$tag = '_dmarc.' . $domain !== $answer['dmarc_at'] && 1 === preg_match( '/(?:^|;)\s*sp\s*=/i', $dmarc ) ? 'sp' : 'p';

			if ( 1 === preg_match( '/(?:^|;)\s*' . $tag . '\s*=\s*none\s*(?:;|$)/i', $dmarc ) ) {
				$answer['problems'][] = 'dmarc_monitor_only';
			}
		}

		// CAA is inherited the same way. A resolver that cannot ask for it at
		// all leaves it unknown rather than missing.
		$answer['caa'] = null;

		foreach ( self::names_up( $domain ) as $name ) {
			$records = self::records( $name, 'CAA' );

			if ( null === $records ) {
				$answer['caa'] = null;
				break;
			}

			if ( array() !== $records ) {
				$answer['caa'] = true;
				break;
			}

			$answer['caa'] = false;
		}

		if ( false === $answer['caa'] ) {
			$answer['problems'][] = 'caa_missing';
		}

		/*
		 * Where the domain's records are managed, and who receives its mail,
		 * for the Fix panel only: the name servers say which DNS service to
		 * open, and the mail servers which sending service SPF may name. A
		 * failed lookup of either leaves it unknown and changes no finding.
		 */
		$answer['ns'] = array();

		foreach ( self::names_up( $domain ) as $name ) {
			$records = self::records( $name, 'NS' );

			if ( null === $records ) {
				break;
			}

			if ( array() !== $records ) {
				$answer['ns'] = array_slice( array_map( 'strtolower', $records ), 0, 8 );
				break;
			}
		}

		$mx           = self::records( $domain, 'MX' );
		$answer['mx'] = null === $mx ? array() : array_slice( array_map( 'strtolower', $mx ), 0, 8 );

		update_option( self::OPTION, $answer, false );

		return $answer;
	}

	/**
	 * The last answer, or nothing if this has never run.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function last(): ?array {
		$stored = get_option( self::OPTION, null );

		return is_array( $stored ) && isset( $stored['checked_at'] ) ? $stored : null;
	}

	/**
	 * The domain WordPress sends its mail from: the site's host, without a
	 * leading `www.`, which is how WordPress builds its default sender.
	 */
	public static function domain(): string {
		$host = strtolower( (string) wp_parse_url( network_home_url(), PHP_URL_HOST ) );

		return str_starts_with( $host, 'www.' ) ? substr( $host, 4 ) : $host;
	}

	/**
	 * Whether a set of problems lets somebody send mail as the domain.
	 *
	 * @param string[] $problems
	 */
	public static function allows_spoofing( array $problems ): bool {
		return array() !== array_intersect( $problems, self::SPOOFING );
	}

	/** Whether a name is one set aside for private use. */
	private static function private_use( string $domain ): bool {
		foreach ( self::PRIVATE_USE as $suffix ) {
			if ( str_ends_with( $domain, $suffix ) || ltrim( $suffix, '.' ) === $domain ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * What a problem means and what to do about it.
	 */
	public static function describe( string $problem, string $domain ): string {
		switch ( $problem ) {
			case 'spf_missing':
				/* translators: %s: the site's domain. */
				return sprintf( __( '%s doesn’t list which services may send its email. BetterShield shows the record to add.', 'bettershield' ), $domain );
			case 'spf_multiple':
				return __( 'More than one SPF record: mail servers treat that as an error and may ignore both. Merge them into one.', 'bettershield' );
			case 'spf_allows_all':
				/* translators: %s: the site's domain. */
				return sprintf( __( 'The SPF record ends in all or +all, letting any server send as %s. Change it to ~all or -all.', 'bettershield' ), $domain );
			case 'dmarc_missing':
				/*
				 * On a subdomain site the record usually wanted is the one at
				 * the domain the name is registered under, which covers the
				 * subdomain too. Which name that is cannot be told from the
				 * labels alone (example.co.uk is registered under three), so
				 * it is described rather than named.
				 */
				if ( substr_count( $domain, '.' ) > 1 ) {
					/* translators: %s: the site's domain. */
					return sprintf( __( 'No DMARC policy says what to do with failing mail. Add a TXT record starting with v=DMARC1 at _dmarc.%s, or at _dmarc. on your registered domain.', 'bettershield' ), $domain );
				}

				/* translators: %s: the site's domain. */
				return sprintf( __( 'No DMARC policy says what to do with failing mail. Add a TXT record starting with v=DMARC1 at _dmarc.%s.', 'bettershield' ), $domain );
			case 'dmarc_multiple':
				/* translators: %s: the site's domain. */
				return sprintf( __( 'More than one DMARC record applies to %s: mail servers then apply no policy at all. Merge them into one.', 'bettershield' ), $domain );
			case 'dmarc_monitor_only':
				// Read by sp= on a subdomain that inherits its policy, so the
				// advice names both tags rather than telling an owner whose
				// p= is already reject to change it.
				return __( 'Email that fails checks is still delivered. Once your own email passes, change the policy to quarantine or reject.', 'bettershield' );
			case 'caa_missing':
				/* translators: %s: the site's domain. */
				return sprintf( __( 'Any company can issue an SSL certificate for %s. Add a record naming the one your host uses.', 'bettershield' ), $domain );
		}

		return '';
	}

	/**
	 * A domain and each name above it, down to two labels.
	 *
	 * @return string[]
	 */
	private static function names_up( string $domain ): array {
		$labels = explode( '.', $domain );
		$names  = array();

		while ( count( $labels ) >= 2 ) {
			$names[] = implode( '.', $labels );
			array_shift( $labels );
		}

		return $names;
	}

	/**
	 * The records of one type at one name, as strings: an empty list when
	 * there are none, and null when the lookup itself failed.
	 *
	 * @return string[]|null
	 */
	private static function records( string $name, string $type ): ?array {
		/**
		 * Short-circuits one DNS lookup.
		 *
		 * Return an array of record strings, an empty array for none, or false
		 * for a failed lookup. For a host that answers DNS for PHP from
		 * somewhere other than its resolver.
		 *
		 * @param array<int, string>|false|null $records Null to look it up.
		 * @param string                        $name    The name asked about.
		 * @param string                        $type    TXT, CAA, NS, MX, or A for the host's addresses, v4 or v6.
		 */
		$pre = apply_filters( 'bettershield_pre_dns_lookup', null, $name, $type );

		if ( false === $pre ) {
			return null;
		}

		if ( is_array( $pre ) ) {
			return array_values( array_map( 'strval', $pre ) );
		}

		$constants = 'A' === $type ? array( 'DNS_A', 'DNS_AAAA' ) : array( 'DNS_' . $type );
		$flags     = 0;

		foreach ( $constants as $constant ) {
			if ( ! defined( $constant ) ) {
				return null;
			}

			$flags |= (int) constant( $constant );
		}

		if ( ! function_exists( 'dns_get_record' ) ) {
			return null;
		}

		$found = @dns_get_record( $name, $flags ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a failed lookup is answered as "could not tell", not as a warning in somebody's log.

		if ( ! is_array( $found ) ) {
			return null;
		}

		$out = array();

		foreach ( $found as $record ) {
			if ( 'A' === $type ) {
				$out[] = (string) ( $record['ip'] ?? $record['ipv6'] ?? '' );
			} elseif ( 'NS' === $type || 'MX' === $type ) {
				$out[] = rtrim( (string) ( $record['target'] ?? '' ), '.' );
			} elseif ( 'TXT' === $type ) {
				$out[] = isset( $record['entries'] ) && is_array( $record['entries'] ) ? implode( '', $record['entries'] ) : (string) ( $record['txt'] ?? '' );
			} else {
				$out[] = trim( (string) ( $record['tag'] ?? '' ) . ' ' . (string) ( $record['value'] ?? '' ) );
			}
		}

		return $out;
	}

	/**
	 * The records that begin with a version tag, compared the way receiving
	 * servers compare it.
	 *
	 * @param string[] $records
	 * @return string[]
	 */
	private static function starting( array $records, string $tag ): array {
		$out = array();

		foreach ( $records as $record ) {
			$record = trim( $record );

			if ( 0 === stripos( $record, $tag ) && ( strlen( $record ) === strlen( $tag ) || in_array( $record[ strlen( $tag ) ], array( ' ', ';' ), true ) ) ) {
				$out[] = $record;
			}
		}

		return $out;
	}

	/**
	 * Record a lookup that could not tell, and answer with it.
	 *
	 * @param array<string, mixed> $answer
	 * @return array<string, mixed>
	 */
	private static function unreliable( array $answer, string $reason ): array {
		$answer['reliable'] = false;
		$answer['reason']   = $reason;
		$answer['problems'] = array();

		update_option( self::OPTION, $answer, false );

		return $answer;
	}
}
