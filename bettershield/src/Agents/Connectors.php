<?php
/**
 * What this site's AI connector credentials are, where they are kept, and who
 * can read them.
 *
 * A report, not a control. Core's own documentation states both facts this
 * class surfaces — that database-stored keys are not encrypted, and that
 * there is no per-plugin scoping — and neither is fixable from inside the
 * same PHP process. Reporting is the honest half, and it is the whole of what
 * this file does.
 *
 * The claim is deliberately narrower than it first appears, because the wide
 * version is wrong. Core registers these settings with `show_in_rest`, but
 * `_wp_connectors_rest_settings_dispatch` masks the value on the way out: an
 * API key comes back as bullets, and an application password comes back as
 * sixteen bullets. Reading the credential over REST is NOT the exposure, and
 * saying it is would be the kind of overstatement that discredits the rest of
 * the report. The username on an application-password connector is the one
 * value that is genuinely returned unmasked.
 *
 * The real exposure is in-process and needs no route at all: the credential
 * is an option, an environment variable or a constant, and every plugin
 * running on the site can read all three directly. That is what this reports.
 *
 * Nothing here returns a credential. The last four characters are the most
 * that ever leaves this class, and only so an owner can tell one key from
 * another.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Agents;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Connectors {

	/**
	 * The WordPress version that ships the connector registry. Named once
	 * here, and asked about by presence rather than by number below.
	 */
	public const REQUIRES_WP = '7.0';

	/**
	 * Whether this platform has connectors at all. Below it there is nothing
	 * to report and the section is absent rather than a placeholder.
	 */
	public static function is_available(): bool {
		return function_exists( 'wp_get_connectors' );
	}

	/**
	 * The whole report.
	 *
	 * @return array{available: bool, connectors: array<int, array<string, mixed>>, configured_count: int, readable_by_plugin_count: int, advisory: string}
	 */
	public static function report( bool $include_hints = true ): array {
		$include_hints = $include_hints && ( ! function_exists( 'rest_get_authenticated_app_password' ) || null === rest_get_authenticated_app_password() );
		$available  = self::is_available();
		$connectors = $available ? self::connectors( $include_hints ) : array();

		$configured = 0;

		foreach ( $connectors as $connector ) {
			if ( $connector['configured'] ) {
				++$configured;
			}
		}

		return array(
			'available'                => $available,
			'connectors'               => $connectors,
			'configured_count'         => $configured,
			'readable_by_plugin_count' => self::active_plugin_count(),
			'advisory'                 => self::advisory( $configured > 0 ),
		);
	}

	/**
	 * One entry per connector that takes a credential. Connectors that
	 * authenticate with nothing are left out: they have no credential to be
	 * exposed, and listing them would pad the report with rows that carry no
	 * finding.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private static function connectors( bool $include_hints ): array {
		$out = array();

		foreach ( wp_get_connectors() as $id => $data ) {
			$auth   = isset( $data['authentication'] ) && is_array( $data['authentication'] ) ? $data['authentication'] : array();
			$method = isset( $auth['method'] ) ? (string) $auth['method'] : 'none';

			if ( 'api_key' !== $method && 'application_password' !== $method ) {
				continue;
			}

			$setting  = isset( $auth['setting_name'] ) ? (string) $auth['setting_name'] : '';
			$env      = isset( $auth['env_var_name'] ) ? (string) $auth['env_var_name'] : '';
			$constant = isset( $auth['constant_name'] ) ? (string) $auth['constant_name'] : '';

			$resolved = self::resolve( $method, $setting, $env, $constant );

			$out[] = array(
				'id'             => (string) $id,
				'label'          => isset( $data['name'] ) ? (string) $data['name'] : (string) $id,
				'type'           => isset( $data['type'] ) ? (string) $data['type'] : '',
				'method'         => $method,
				'configured'     => 'none' !== $resolved['source'],
				'storage_source' => $resolved['source'],
				// Identification is for the interactive owner only.
				'key_hint'       => $include_hints ? $resolved['hint'] : null,
				'encryption'     => self::encryption_status( $resolved['source'] ),
				/*
				 * Whether the credential's own setting is readable over REST,
				 * and what actually comes back if it is. Two fields rather
				 * than one because the answer is genuinely two-part, and
				 * collapsing it to "exposed: yes" would say something untrue.
				 */
				'rest_registered' => '' !== $setting && self::is_registered_in_rest( $setting ),
				'rest_value'      => 'application_password' === $method ? 'username_only' : 'masked',
			);
		}

		return $out;
	}

	/**
	 * Where the credential is actually coming from, and its last four
	 * characters.
	 *
	 * The precedence — environment, then constant, then database — is core's
	 * own, and it is reproduced here rather than borrowed: the function core
	 * uses for it is marked private, and a shipped feature should not rest on
	 * an underscore-prefixed function that may change without a deprecation.
	 *
	 * @return array{source: string, hint: ?string}
	 */
	private static function resolve( string $method, string $setting, string $env, string $constant ): array {
		if ( '' !== $env ) {
			$value = getenv( $env );

			if ( is_string( $value ) && '' !== $value ) {
				return array(
					'source' => 'env',
					'hint'   => self::hint( $value ),
				);
			}
		}

		if ( '' !== $constant && defined( $constant ) ) {
			$value = constant( $constant );

			if ( is_string( $value ) && '' !== $value ) {
				return array(
					'source' => 'constant',
					'hint'   => self::hint( $value ),
				);
			}
		}

		if ( '' !== $setting ) {
			$stored = get_option( $setting, '' );

			// An application-password connector stores a pair; the password
			// is the credential, and the username is not a secret.
			if ( 'application_password' === $method && is_array( $stored ) ) {
				$password = isset( $stored['password'] ) ? (string) $stored['password'] : '';

				if ( '' !== $password ) {
					return array(
						'source' => 'database',
						'hint'   => self::hint( $password ),
					);
				}
			}

			if ( is_string( $stored ) && '' !== $stored ) {
				return array(
					'source' => 'database',
					'hint'   => self::hint( $stored ),
				);
			}
		}

		return array(
			'source' => 'none',
			'hint'   => null,
		);
	}

	/**
	 * The last four characters, and only when there are enough of them that
	 * four is not most of the value. A short credential gives up nothing.
	 */
	private static function hint( string $value ): ?string {
		return strlen( $value ) > 8 ? substr( $value, -4 ) : null;
	}

	/**
	 * Whether core registered this setting for REST at all. It only does so
	 * when the connector's own plugin is active, so this is a real difference
	 * between two sites with the same connector list.
	 */
	private static function is_registered_in_rest( string $setting ): bool {
		$registered = get_registered_settings();

		if ( ! isset( $registered[ $setting ] ) ) {
			return false;
		}

		$show = $registered[ $setting ]['show_in_rest'] ?? false;

		return false !== $show;
	}

	/**
	 * Core's documented position, stated as the platform fact it is.
	 *
	 * `not_encrypted` for a database-stored credential is not this plugin
	 * finding a defect — it is core's own documented current behavior, and an
	 * encryption ticket is open upstream. A credential in the environment or
	 * in a constant is not in the database at all, which is a different
	 * property and is worth saying rather than calling it encrypted, which it
	 * also is not.
	 */
	private static function encryption_status( string $source ): string {
		switch ( $source ) {
			case 'database':
				return 'not_encrypted';
			case 'env':
			case 'constant':
				return 'outside_the_database';
			default:
				return 'not_configured';
		}
	}

	/**
	 * How many plugins are running, which is the number that can read every
	 * credential above. Not an accusation about any of them: it is the size
	 * of the trusted set, and the point is that the platform offers no way to
	 * make it smaller.
	 */
	private static function active_plugin_count(): int {
		$active = get_option( 'active_plugins', array() );
		$count  = is_array( $active ) ? count( $active ) : 0;

		if ( is_multisite() ) {
			$network = get_site_option( 'active_sitewide_plugins', array() );
			$count  += is_array( $network ) ? count( $network ) : 0;
		}

		return $count;
	}

	/**
	 * The advisory, written as a statement of how the platform works.
	 *
	 * Calm on purpose, and the tone is the feature: an owner who reads this
	 * and feels informed will act, and one who feels alarmed will either
	 * dismiss it or blame the connector. The link is to core's own open
	 * ticket, which is checkable, rather than to a summary of it.
	 *
	 * Two wordings, because one sentence cannot be true in both states. On a
	 * site holding no credential, "every plugin can read every credential
	 * here" describes a set that is empty — which reads as a warning about
	 * nothing and teaches the reader to discount the next one. Said in the
	 * future tense it is the same fact and it is the one worth knowing before
	 * a key is pasted in rather than after.
	 */
	private static function advisory( bool $any_configured ): string {
		// The line above already says whether anything is stored.
		return $any_configured
			? __( 'WordPress saves these keys without encryption, so any active plugin can read them.', 'bettershield' )
			: __( 'WordPress saves these keys without encryption, so any active plugin could read one added later.', 'bettershield' );
	}

	/**
	 * The link that belongs beside the advisory.
	 */
	public static function reference_url(): string {
		return 'https://core.trac.wordpress.org/ticket/64789';
	}
}
