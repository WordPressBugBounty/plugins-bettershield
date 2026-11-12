<?php
/**
 * Accountless, consented vulnerability intelligence.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Vulnerabilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class HubFeed implements Feed {
	public const ENDPOINT = 'https://hub.bettershield.ai/v1/intelligence/check';
	public const RETRY = 'bettershield_intelligence_retry';

	/**
	 * The data providers the Hub answers from. The answer's shape is the
	 * same for each; the provider names whose ids they are, so each id is
	 * prefixed with it and its revision count is its own.
	 */
	public const PROVIDERS = array( 'wordfence', 'patchstack' );

	/**
	 * The name a stored result carries. Kept as it was first written, so a
	 * result stored before there was a choice of provider is still this
	 * supply's: it names the supply, and the provider is kept beside it
	 * (State's `provider`).
	 */
	public function id(): string {
		return 'hub-wordfence';
	}

	public function label(): string {
		return __( 'BetterShield Hub', 'bettershield' );
	}

	/** Fetch only with consent, keeping refusals distinct and retries scheduled. */
	public function advisories( array $inventory ) {
		if ( ! Scanner::consented() ) {
			return self::error( 'intelligence_not_enabled' );
		}
		$retry_at = (int) get_transient( self::RETRY );
		if ( $retry_at > time() ) {
			Scanner::schedule( $retry_at - time() );
			return self::error( 'intelligence_backoff' );
		}
		$inventory = Inventory::for_feed( $inventory );
		if ( count( $inventory ) > 1000 || ! $inventory ) {
			return self::error( 'intelligence_inventory_limit' );
		}
		$endpoint = apply_filters( 'bettershield_intelligence_endpoint', self::ENDPOINT );
		if ( self::ENDPOINT !== $endpoint ) {
			return self::error( 'intelligence_endpoint_refused' );
		}
		$response = \BetterShield\Support\Http::post( $endpoint, array(
			'timeout' => 15, 'redirection' => 0, 'limit_response_size' => 8 * 1024 * 1024,
			'user-agent' => 'BetterShield/' . BETTERSHIELD_VERSION,
			'headers' => array( 'Content-Type' => 'application/json', 'Accept' => 'application/json' ),
			'body' => wp_json_encode( array( 'schema_version' => 1, 'inventory' => $inventory ) ),
			'cookies' => array(),
		), array( 200, 429, 503 ) );
		if ( is_wp_error( $response ) ) {
			return self::error( 'intelligence_transport' );
		}
		$status = wp_remote_retrieve_response_code( $response );
		if ( in_array( $status, array( 429, 503 ), true ) ) {
			$retry = (string) wp_remote_retrieve_header( $response, 'retry-after' );
			$delay = ctype_digit( $retry ) ? min( HOUR_IN_SECONDS, max( 60, (int) $retry ) ) : 300;
			set_transient( self::RETRY, time() + $delay, $delay );
			Scanner::schedule( $delay );
			return self::error( 429 === $status ? 'intelligence_rate_limited' : 'intelligence_service_unavailable' );
		}
		return self::decode( wp_remote_retrieve_body( $response ), $inventory );
	}

	public static function error( string $code = 'intelligence_invalid_response' ): \WP_Error {
		// What failed, and only that: whether an earlier result is kept is the
		// screen's to say, and a site that never had one has none (#2136).
		return new \WP_Error( $code, __( 'BetterShield Hub did not return vulnerability data', 'bettershield' ) );
	}

	/** Validate the complete response before any state is replaced. */
	public static function decode( string $body, array $inventory ) {
		// Keep JSON object/list distinctions: an empty object is not an empty
		// advisory list and must never clear previously recorded findings.
		$raw = json_decode( $body, false, 32 );
		if ( ! is_object( $raw ) || ! is_array( $raw->advisories ?? null ) ) {
			return self::error();
		}
		foreach ( $raw->advisories as $entry ) {
			if ( ! is_object( $entry ) || ! is_object( $entry->component ?? null ) || ! is_object( $entry->attribution ?? null ) || ! is_array( $entry->attribution->notices ?? null ) ) {
				return self::error();
			}
			foreach ( array( 'affected_ranges', 'patched_ranges', 'patched_versions', 'cve_ids', 'references' ) as $field ) {
				if ( ! is_array( $entry->$field ?? null ) ) {
					return self::error();
				}
			}
			foreach ( array_merge( $entry->affected_ranges, $entry->patched_ranges, $entry->attribution->notices ) as $object ) {
				if ( ! is_object( $object ) ) {
					return self::error();
				}
			}
		}
		unset( $raw );
		$data = json_decode( $body, true, 32 );
		if ( ! is_array( $data ) || 1 !== ( $data['schema_version'] ?? null ) || ! in_array( $data['provider'] ?? null, self::PROVIDERS, true )
			|| Inventory::digest( $inventory ) !== ( $data['inventory_digest'] ?? null )
			|| true !== ( $data['complete'] ?? null ) || false !== ( $data['stale'] ?? null )
			|| ! isset( $data['revision'] ) || ! is_int( $data['revision'] ) || $data['revision'] < 1
			|| ! self::timestamp( $data['fetched_at'] ?? null ) || strtotime( $data['fetched_at'] ) > time() + 300
			|| strtotime( $data['fetched_at'] ) <= time() - State::STALE_AFTER_DAYS * DAY_IN_SECONDS
			|| ! self::list_of( $data['advisories'] ?? null, 100000 ) ) {
			return self::error();
		}
		$components = array();
		foreach ( $inventory as $item ) {
			$components[ $item['type'] . ':' . strtolower( $item['slug'] ) ] = true;
		}
		$provider = (string) $data['provider'];
		$previous = State::get();
		// Each provider keeps its own revision count, so an answer from
		// another provider than the last one starts a fresh count: the first
		// answer after a switch is accepted whatever the old count was.
		if ( 'hub-wordfence' === $previous['feed'] && $provider === $previous['provider'] && $data['revision'] < $previous['revision'] ) {
			return self::error();
		}
		$out = array();
		$seen = array();
		$attribution = array();
		foreach ( $data['advisories'] as $advisory ) {
			if ( ! self::valid_advisory( $advisory, $provider ) ) {
				return self::error();
			}
			$key = $advisory['component']['type'] . ':' . strtolower( $advisory['component']['slug'] );
			$id = $key . ':' . $advisory['provider_id'];
			if ( ! isset( $components[ $key ] ) || isset( $seen[ $id ] ) ) {
				return self::error();
			}
			$seen[ $id ] = true;
			$attribution[ wp_json_encode( $advisory['attribution'] ) ] = $advisory['attribution'];
			$out[] = $advisory + array(
				'id' => $provider . ':' . $advisory['provider_id'],
				'type' => $advisory['component']['type'], 'slug' => $advisory['component']['slug'],
				'fixed_in' => null, 'affected_max' => null, 'disclosed_at' => $advisory['published_at'] ?? '',
			);
		}
		return array( 'advisories' => $out, 'published_at' => $data['fetched_at'], 'revision' => $data['revision'], 'provider' => $provider, 'attribution' => array_values( $attribution ) );
	}

	private static function list_of( $value, int $max ): bool {
		return is_array( $value ) && count( $value ) <= $max && ( ! $value || array_keys( $value ) === range( 0, count( $value ) - 1 ) );
	}

	private static function text( $value, int $max, bool $empty = true ): bool {
		return is_string( $value ) && 1 === preg_match( '//u', $value ) && strlen( $value ) <= $max && ( $empty || '' !== $value );
	}

	private static function version( $value ): bool {
		// The service limits versions by UTF-16 characters; prose has separate byte limits.
		if ( ! is_string( $value ) || '' === $value || '*' === $value || 1 !== preg_match( '//u', $value ) ) {
			return false;
		}
		$characters = preg_match_all( '/./us', $value );
		$surrogates = preg_match_all( '/[\x{10000}-\x{10FFFF}]/u', $value );
		return $characters + $surrogates <= 128 && ! preg_match( '/(?:^\s|\s$|[\x00-\x1f\x7f])/u', $value );
	}

	private static function timestamp( $value ): bool {
		if ( ! is_string( $value ) || 1 !== preg_match( '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/', $value ) || false === strtotime( $value ) ) {
			return false;
		}
		try {
			new \DateTimeImmutable( $value );

		} catch ( \Exception $e ) {
			return false;
		}
		$errors = \DateTimeImmutable::getLastErrors();
		return false === $errors || ( 0 === $errors['warning_count'] && 0 === $errors['error_count'] );
	}

	private static function url( $value ): bool {
		if ( ! self::text( $value, 2048, false ) || ! filter_var( $value, FILTER_VALIDATE_URL ) ) {
			return false;
		}
		$p = wp_parse_url( $value );
		return is_array( $p ) && in_array( $p['scheme'] ?? '', array( 'https', 'http' ), true ) && ! isset( $p['user'] ) && ! isset( $p['pass'] );
	}

	private static function ranges( $ranges, bool $required ): bool {
		if ( ! self::list_of( $ranges, 200 ) || ( $required && ! $ranges ) ) {
			return false;
		}
		foreach ( $ranges as $r ) {
			if ( ! is_array( $r ) || count( $r ) !== 4 || ! array_key_exists( 'from', $r ) || ! array_key_exists( 'to', $r )
				|| ! is_bool( $r['from_inclusive'] ?? null ) || ! is_bool( $r['to_inclusive'] ?? null )
				|| ( null !== $r['from'] && ! self::version( $r['from'] ) ) || ( null !== $r['to'] && ! self::version( $r['to'] ) ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * @param mixed  $a        One advisory as answered.
	 * @param string $provider The answer's own provider, which every advisory in it must name.
	 */
	private static function valid_advisory( $a, string $provider ): bool {
		$required = array( 'schema_version', 'provider', 'provider_id', 'component', 'title', 'severity', 'cvss_score', 'informational', 'exploited', 'affected_ranges', 'patched_versions', 'patched_ranges', 'remediation', 'cve_ids', 'references', 'published_at', 'updated_at', 'attribution' );
		if ( ! is_array( $a ) || array_diff( $required, array_keys( $a ) ) || array_diff( array_keys( $a ), $required )
			|| 1 !== $a['schema_version'] || $provider !== $a['provider'] || ! self::text( $a['provider_id'], 200, false ) || ! preg_match( '/^[A-Za-z0-9_.:-]+$/', $a['provider_id'] )
			|| ! is_array( $a['component'] ) || count( $a['component'] ) !== 2 || ! in_array( $a['component']['type'] ?? null, array( 'core', 'plugin', 'theme' ), true )
			|| ! self::text( $a['component']['slug'] ?? null, 200, false ) || ! preg_match( '/^[A-Za-z0-9][A-Za-z0-9._-]*$/D', $a['component']['slug'] )
			|| ! self::text( $a['title'], 2000, false ) || ( null !== $a['severity'] && ! in_array( $a['severity'], Matcher::SEVERITIES, true ) )
			|| ( null !== $a['cvss_score'] && ( ! is_numeric( $a['cvss_score'] ) || is_string( $a['cvss_score'] ) || $a['cvss_score'] < 0 || $a['cvss_score'] > 10 ) )
			|| ! is_bool( $a['informational'] ) || ( null !== $a['exploited'] && ! is_bool( $a['exploited'] ) )
			|| ! self::ranges( $a['affected_ranges'], true ) || ! self::ranges( $a['patched_ranges'], false )
			|| ! self::list_of( $a['patched_versions'], 200 ) || ! self::list_of( $a['cve_ids'], 100 ) || ! self::list_of( $a['references'], 100 )
			|| ( null !== $a['remediation'] && ! self::text( $a['remediation'], 10000 ) ) ) {
			return false;
		}
		foreach ( array( 'published_at', 'updated_at' ) as $field ) {
			if ( null !== $a[ $field ] && ! self::timestamp( $a[ $field ] ) ) {
				return false;
			}
		}
		foreach ( $a['patched_versions'] as $v ) {
			if ( ! self::version( $v ) ) {
				return false;
			}
		}
		foreach ( $a['cve_ids'] as $v ) {
			if ( ! is_string( $v ) || ! preg_match( '/^CVE-\d{4}-\d{4,}$/', $v ) ) {
				return false;
			}
		}
		foreach ( $a['references'] as $v ) {
			if ( ! self::url( $v ) ) {
				return false;
			}
		}
		$t = $a['attribution'];
		if ( ! is_array( $t ) || count( $t ) !== 2 || ! array_key_exists( 'message', $t ) || ( null !== $t['message'] && ! self::text( $t['message'], 20000 ) ) || ! self::list_of( $t['notices'] ?? null, 50 ) ) {
			return false;
		}
		foreach ( $t['notices'] as $n ) {
			if ( ! is_array( $n ) || count( $n ) !== 4 || ! self::text( $n['source'] ?? null, 200, false ) || ! self::text( $n['notice'] ?? null, 20000, false ) || ! self::text( $n['license'] ?? null, 20000, false ) || ! array_key_exists( 'license_url', $n ) || ( null !== $n['license_url'] && ! self::url( $n['license_url'] ) ) ) {
				return false;
			}
		}
		return true;
	}
}
