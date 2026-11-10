<?php
/**
 * Fix for the domain's mail and certificate records (#2203).
 *
 * The exact records to publish for each family that has a problem: one SPF
 * value (SpfRecord), a DMARC record, and a CAA record naming the authority
 * that issued the site's certificate. With them, where the domain's DNS is
 * managed, read from its name servers. Built from the last stored lookup,
 * never from one made in the request; Check again asks the daily task to
 * run early, and the finding moves only when it stores a reliable answer.
 *
 * DNS lives outside this site, so nothing here changes anything and there
 * is no Undo: the finding closes when a later lookup sees the records.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Audit\Certificate;
use BetterShield\Audit\DomainRecords;
use BetterShield\Cron\Runner;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class DomainMailRecords {

	/** The daily task that looks the records up. */
	public const TASK = 'bettershield_domain_records';

	/** How long Check again waits between two asks. */
	public const ASK_EVERY = 2 * MINUTE_IN_SECONDS;

	/** When Check again was last asked, kept per site. */
	private const ASKED = 'bettershield_domain_records_asked';

	/**
	 * DNS services, by a part of their name servers: what the panel calls
	 * them and where their records are edited. Only the service is kept,
	 * never an account.
	 */
	private const PROVIDERS = array(
		// phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- a link the owner follows to edit their records; nothing is loaded from it.
		'.ns.cloudflare.com'     => array( 'cloudflare', 'Cloudflare', 'https://dash.cloudflare.com/' ),
		'awsdns-'                => array( 'route53', 'Amazon Route 53', 'https://console.aws.amazon.com/route53/v2/hostedzones' ),
		'.domaincontrol.com'     => array( 'godaddy', 'GoDaddy', 'https://dcc.godaddy.com/control/portfolio' ),
		'.registrar-servers.com' => array( 'namecheap', 'Namecheap', 'https://ap.www.namecheap.com/domains/list/' ),
		'.googledomains.com'     => array( 'google', 'Google Cloud DNS', 'https://console.cloud.google.com/net-services/dns/zones' ),
		'ns-cloud-'              => array( 'google', 'Google Cloud DNS', 'https://console.cloud.google.com/net-services/dns/zones' ),
		'.digitalocean.com'      => array( 'digitalocean', 'DigitalOcean', 'https://cloud.digitalocean.com/networking/domains' ),
		'.azure-dns.'            => array( 'azure', 'Azure DNS', 'https://portal.azure.com/' ),
		'.ovh.net'               => array( 'ovh', 'OVHcloud', 'https://www.ovh.com/manager/' ),
		'.gandi.net'             => array( 'gandi', 'Gandi', 'https://admin.gandi.net/domain/' ),
	);

	/** Mail servers that name their sending service without doubt. */
	private const MAIL_HOSTS = array(
		'.google.com'                  => '_spf.google.com',
		'.googlemail.com'              => '_spf.google.com',
		'.mail.protection.outlook.com' => 'spf.protection.outlook.com',
		'.zoho.com'                    => 'zoho.com',
		'.zoho.eu'                     => 'zoho.eu',
	);

	/** A sending plugin's mailer, by the name it stores, and its SPF include. */
	private const MAILERS = array(
		'gmail'      => '_spf.google.com',
		'outlook'    => 'spf.protection.outlook.com',
		'sendgrid'   => 'sendgrid.net',
		'mailgun'    => 'mailgun.org',
		'postmark'   => 'spf.mtasv.net',
		'sparkpost'  => 'sparkpostmail.com',
		'amazonses'  => 'amazonses.com',
		'ses'        => 'amazonses.com',
		'sendinblue' => 'spf.brevo.com',
		'brevo'      => 'spf.brevo.com',
		'zoho'       => 'zoho.com',
	);

	/** Certificate authorities, by the organization in the certificate, and their CAA name. */
	private const AUTHORITIES = array(
		'let\'s encrypt'        => 'letsencrypt.org',
		'google trust services' => 'pki.goog',
		'digicert'              => 'digicert.com',
		'sectigo'               => 'sectigo.com',
		'zerossl'               => 'sectigo.com',
		'comodo'                => 'sectigo.com',
		'globalsign'            => 'globalsign.com',
		'amazon'                => 'amazon.com',
		'godaddy'               => 'godaddy.com',
		'starfield'             => 'godaddy.com',
		'entrust'               => 'entrust.net',
		'ssl corporation'       => 'ssl.com',
		'buypass'               => 'buypass.com',
	);

	/**
	 * What the panel shows: each record to publish, or why none is offered,
	 * and where the domain's DNS is managed.
	 *
	 * @return array{reliable: bool, domain: string, checked_at: string, checking: bool, records: array<int, array<string, mixed>>, provider: ?array{key: string, label: string, url: string}}
	 */
	public static function state(): array {
		$last    = DomainRecords::last();
		$pending = Runner::pending_request();
		$state   = array(
			'reliable'   => is_array( $last ) && ! empty( $last['reliable'] ),
			'domain'     => is_array( $last ) ? (string) ( $last['domain'] ?? '' ) : DomainRecords::domain(),
			'checked_at' => is_array( $last ) ? (string) ( $last['checked_at'] ?? '' ) : '',
			'checking'   => is_array( $pending ) && self::TASK === ( $pending['hook'] ?? '' ),
			'records'    => array(),
			'provider'   => null,
		);

		if ( ! $state['reliable'] ) {
			return $state;
		}

		$problems = (array) ( $last['problems'] ?? array() );
		$domain   = $state['domain'];

		if ( array() !== array_intersect( $problems, array( 'spf_missing', 'spf_multiple', 'spf_allows_all' ) ) ) {
			$state['records'][] = self::spf( $last, $domain );
		}

		if ( array() !== array_intersect( $problems, array( 'dmarc_missing', 'dmarc_multiple', 'dmarc_monitor_only' ) ) ) {
			$state['records'][] = self::dmarc( $last, $problems, $domain );
		}

		if ( in_array( 'caa_missing', $problems, true ) ) {
			$state['records'][] = self::caa( $domain );
		}

		$state['provider'] = self::provider( (array) ( $last['ns'] ?? array() ) );

		return $state;
	}

	/**
	 * Ask the daily lookup to run now, in the background. Refused while one
	 * is waiting, and within two minutes of the last ask.
	 *
	 * @return true|\WP_Error
	 */
	public static function check_again( int $user_id ) {
		$asked = (int) get_option( self::ASKED, 0 );

		if ( $asked > time() - self::ASK_EVERY ) {
			return new \WP_Error( 'bettershield_domain_check_soon', __( 'The records were asked for a moment ago. Try again in two minutes.', 'bettershield' ), array( 'status' => 429 ) );
		}

		$queued = Runner::instance()->request_run( self::TASK, $user_id );

		if ( true === $queued ) {
			update_option( self::ASKED, time(), false );
		}

		return $queued;
	}

	/**
	 * The SPF record to publish.
	 *
	 * @param array<string, mixed> $last The stored lookup.
	 * @return array<string, mixed>
	 */
	private static function spf( array $last, string $domain ): array {
		$records = (array) ( $last['spf_records'] ?? array() );
		$row     = array(
			'family' => 'spf',
			'host'   => $domain,
			'type'   => 'TXT',
		);

		// A lookup from before this kept only the first record, clipped; so
		// does one that found a record too long to keep whole.
		if ( ( ! isset( $last['spf_records'] ) && isset( $last['spf'] ) ) || in_array( null, $records, true ) ) {
			return $row + array( 'refused' => self::refusal( 'unreadable' ) );
		}

		$proposal = SpfRecord::propose( array_map( 'strval', $records ), self::includes( $last ) );

		if ( isset( $proposal['refused'] ) ) {
			return $row + array( 'refused' => self::refusal( $proposal['refused'] ) );
		}

		return $row + array(
			'value'    => $proposal['value'],
			'replaces' => count( $records ),
			'added'    => $proposal['added'],
		) + self::spf_note( (string) $proposal['value'] );
	}

	/**
	 * What to check before publishing an SPF value that this cannot check
	 * itself. The ten-lookup limit counts the lookups inside every include
	 * too, which only resolving each of them would show; and one DNS string
	 * holds 255 characters, so a longer value is split into quoted strings by
	 * most DNS hosts and must be split by hand in some editors and zone files.
	 *
	 * @return array{note?: string}
	 */
	private static function spf_note( string $value ): array {
		$notes = array();

		if ( 1 === preg_match( '/(?:^|\s)[+\-~?]?(?:include:|redirect=)/i', $value ) ) {
			$notes[] = __( 'Each include also counts the lookups inside it, and SPF allows ten in all. Check the total with an SPF checker before you publish.', 'bettershield' );
		}

		if ( strlen( $value ) > 255 ) {
			$notes[] = __( 'This value is longer than 255 characters. If your DNS editor refuses it, split it into quoted parts of up to 255 characters each, written one after another.', 'bettershield' );
		}

		return array() === $notes ? array() : array( 'note' => implode( ' ', $notes ) );
	}

	/**
	 * The DMARC record to publish: a new one at p=none, one policy where two
	 * cancel out, or the one there with its policy raised and every other
	 * tag, the reporting addresses among them, kept.
	 *
	 * @param array<string, mixed> $last     The stored lookup.
	 * @param string[]             $problems Its problems.
	 * @return array<string, mixed>
	 */
	private static function dmarc( array $last, array $problems, string $domain ): array {
		$at  = (string) ( $last['dmarc_at'] ?? '' );
		$row = array(
			'family' => 'dmarc',
			'host'   => '' !== $at ? $at : '_dmarc.' . $domain,
			'type'   => 'TXT',
		);

		if ( in_array( 'dmarc_missing', $problems, true ) ) {
			return array(
				'family' => 'dmarc',
				'host'   => '_dmarc.' . $domain,
				'type'   => 'TXT',
				// Reports go nowhere unless the owner chooses an address.
				'value'  => 'v=DMARC1; p=none;',
			);
		}

		if ( in_array( 'dmarc_multiple', $problems, true ) ) {
			return $row + array(
				'refused' => sprintf(
					/* translators: %s: where the DMARC records are, e.g. _dmarc.example.com. */
					__( 'Keep one DMARC record at %s and delete the others. With two, mail servers apply no policy at all.', 'bettershield' ),
					$row['host']
				),
			);
		}

		$full = $last['dmarc_full'] ?? null;

		if ( ! is_string( $full ) || '' === $full ) {
			return $row + array( 'refused' => self::refusal( 'unreadable' ) );
		}

		// The tag that applies: sp= where the policy is inherited and has one.
		$tag   = '_dmarc.' . $domain !== $at && 1 === preg_match( '/(?:^|;)\s*sp\s*=/i', $full ) ? 'sp' : 'p';
		$value = preg_replace( '/((?:^|;)\s*' . $tag . '\s*=\s*)none(\s*(?:;|$))/i', '${1}quarantine${2}', $full, 1 );

		return $row + array(
			'value' => (string) $value,
			'note'  => __( 'Change it once DMARC reports show your own mail passing.', 'bettershield' ),
		);
	}

	/**
	 * The CAA record to publish, naming the authority that issued the
	 * site's certificate where it is known, and Let's Encrypt, said to be a
	 * default, where it is not.
	 *
	 * @return array<string, mixed>
	 */
	private static function caa( string $domain ): array {
		$issuer = strtolower( Certificate::issuer() );
		$name   = '';

		foreach ( self::AUTHORITIES as $organization => $caa ) {
			if ( '' !== $issuer && str_contains( $issuer, $organization ) ) {
				$name = $caa;
				break;
			}
		}

		return array(
			'family' => 'caa',
			'host'   => $domain,
			'type'   => 'CAA',
			'value'  => '0 issue "' . ( '' !== $name ? $name : 'letsencrypt.org' ) . '"',
			'note'   => '' !== $name
				? sprintf(
					/* translators: %s: a certificate authority, e.g. "Let's Encrypt". */
					__( 'For %s, which issued this site’s current certificate.', 'bettershield' ),
					Certificate::issuer()
				)
				: __( 'Let’s Encrypt is a common default, not the authority found here. Name the one your host uses if it differs.', 'bettershield' ),
		);
	}

	/**
	 * Sending services SPF should name: the one the domain's mail servers
	 * belong to, and the one a sending plugin is set to use, each where it
	 * names one service without doubt. Only the service's name is read from
	 * a plugin's settings, never a key or a password.
	 *
	 * @param array<string, mixed> $last The stored lookup.
	 * @return string[]
	 */
	private static function includes( array $last ): array {
		$found = array();
		$mx    = array();

		foreach ( (array) ( $last['mx'] ?? array() ) as $host ) {
			$mx[] = self::match( '.' . ltrim( (string) $host, '.' ), self::MAIL_HOSTS );
		}

		$mx = array_unique( $mx );

		if ( 1 === count( $mx ) && null !== $mx[0] ) {
			$found[] = $mx[0];
		}

		foreach ( self::mailers() as $mailer ) {
			if ( isset( self::MAILERS[ $mailer ] ) ) {
				$found[] = self::MAILERS[ $mailer ];
			}
		}

		return array_values( array_unique( $found ) );
	}

	/**
	 * The mailer a sending plugin is set to, by name only.
	 *
	 * @return string[]
	 */
	private static function mailers(): array {
		$out   = array();
		$smtp  = get_option( 'wp_mail_smtp' );
		$fluid = get_option( 'fluentmail-settings' );

		if ( is_array( $smtp ) && isset( $smtp['mail']['mailer'] ) && is_string( $smtp['mail']['mailer'] ) ) {
			$out[] = strtolower( $smtp['mail']['mailer'] );
		}

		if ( is_array( $fluid ) && isset( $fluid['misc']['default_connection'] ) && is_string( $fluid['misc']['default_connection'] ) ) {
			$provider = $fluid['connections'][ $fluid['misc']['default_connection'] ]['provider_settings']['provider'] ?? null;

			if ( is_string( $provider ) ) {
				$out[] = strtolower( $provider );
			}
		}

		return $out;
	}

	/**
	 * The DNS service the name servers belong to, where all of them belong
	 * to one this knows.
	 *
	 * @param string[] $servers The domain's name servers.
	 * @return array{key: string, label: string, url: string}|null
	 */
	private static function provider( array $servers ): ?array {
		$seen = array();

		foreach ( $servers as $server ) {
			$seen[] = self::match( '.' . ltrim( strtolower( (string) $server ), '.' ), self::PROVIDERS );
		}

		$seen = array_values( array_unique( $seen, SORT_REGULAR ) );

		if ( 1 !== count( $seen ) || null === $seen[0] ) {
			return null;
		}

		return array(
			'key'   => $seen[0][0],
			'label' => $seen[0][1],
			'url'   => $seen[0][2],
		);
	}

	/**
	 * The entry whose key appears in a host name, or null.
	 *
	 * @param array<string, mixed> $table By the part of a host name each is known by.
	 * @return mixed
	 */
	private static function match( string $host, array $table ) {
		foreach ( $table as $part => $entry ) {
			// A domain ending (".zoho.com") matches the end of the name only,
			// so one that merely contains it is not taken for that service.
			$suffix = str_starts_with( $part, '.' ) && ! str_ends_with( $part, '.' );

			if ( $suffix ? str_ends_with( $host, $part ) : str_contains( $host, $part ) ) {
				return $entry;
			}
		}

		return null;
	}

	/** Why no SPF value is offered, in words. */
	private static function refusal( string $reason ): string {
		switch ( $reason ) {
			case 'conflict':
				return __( 'The SPF records disagree, so they are not merged here. Keep one record that lists every service you send mail through.', 'bettershield' );
			case 'lookups':
				return __( 'Merged, the record would need more than 10 DNS lookups, which mail servers refuse. Remove services you no longer send through first.', 'bettershield' );
			default:
				return __( 'Part of the record could not be read, so no value is offered. Edit it by hand: one record, ending in ~all or -all.', 'bettershield' );
		}
	}
}
