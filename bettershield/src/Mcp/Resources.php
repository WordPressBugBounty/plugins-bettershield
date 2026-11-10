<?php
/**
 * What an assistant can read by address rather than by calling a tool (#557).
 *
 * Resources are the protocol's re-readable context: the posture, the
 * integrity report, one check explained, one day of the log. Each is a thin
 * name for a read tool this server already offers, with the arguments the
 * address carries, so a resource is answered by exactly the tool it names:
 * the read opt-in, the connection's scope, the tools the owner left an app,
 * the account's own reach and the record of the call all apply unchanged.
 * A resource whose tool this connection is not offered is not listed, and
 * reading it anyway is refused the way calling the tool would be.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Mcp;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Resources {

	/** The scheme every address here is written in. */
	public const SCHEME = 'bettershield://';

	/**
	 * The fixed addresses: address => tool, and what the list says of it.
	 *
	 * @return array<string, array{tool: string, name: string, title: string, description: string}>
	 */
	public static function fixed(): array {
		return array(
			self::SCHEME . 'posture'   => array(
				'tool'        => 'get-security-posture',
				'name'        => 'posture',
				'title'       => __( 'Security posture', 'bettershield' ),
				'description' => __( 'The score, the grade and every open finding, each explained in plain language.', 'bettershield' ),
			),
			self::SCHEME . 'integrity' => array(
				'tool'        => 'get-integrity-status',
				'name'        => 'integrity',
				'title'       => __( 'File integrity', 'bettershield' ),
				'description' => __( 'Which core, plugin and theme files differ from their published copies, and which are new.', 'bettershield' ),
			),
			self::SCHEME . 'recovery'  => array(
				'tool'        => 'get-recovery-readiness',
				'name'        => 'recovery',
				'title'       => __( 'Recovery readiness', 'bettershield' ),
				'description' => __( 'Whether each way back in works today. Never the recovery link or a code.', 'bettershield' ),
			),
			self::SCHEME . 'settings'  => array(
				'tool'        => 'get-site-settings',
				'name'        => 'settings',
				'title'       => __( 'Site settings', 'bettershield' ),
				'description' => __( 'Email alerts, the password policy and whether a security contact file is published. No addresses.', 'bettershield' ),
			),
		);
	}

	/**
	 * The addresses that take a value: template => tool, and what the list
	 * says of it.
	 *
	 * @return array<string, array{tool: string, name: string, title: string, description: string}>
	 */
	public static function templates(): array {
		return array(
			self::SCHEME . 'findings/{check_id}' => array(
				'tool'        => 'get-audit-check',
				'name'        => 'finding',
				'title'       => __( 'One finding', 'bettershield' ),
				'description' => __( 'One check’s explanation, its risk and its last recorded status, by the check’s id as the posture lists it.', 'bettershield' ),
			),
			self::SCHEME . 'activity/{date}'     => array(
				'tool'        => 'query-activity',
				'name'        => 'activity-day',
				'title'       => __( 'One day of activity', 'bettershield' ),
				'description' => __( 'The activity log for one day in UTC, written YYYY-MM-DD, up to two hundred events.', 'bettershield' ),
			),
		);
	}

	/**
	 * The fixed resources this connection is offered, in the protocol's shape.
	 *
	 * @param string[] $offered The tool names this connection is offered.
	 * @return array<int, array<string, string>>
	 */
	public static function listed( array $offered ): array {
		$out = array();

		foreach ( self::fixed() as $uri => $resource ) {
			if ( in_array( $resource['tool'], $offered, true ) ) {
				$out[] = array(
					'uri'         => $uri,
					'name'        => $resource['name'],
					'title'       => $resource['title'],
					'description' => $resource['description'],
					'mimeType'    => 'application/json',
				);
			}
		}

		return $out;
	}

	/**
	 * The templates this connection is offered, in the protocol's shape.
	 *
	 * @param string[] $offered The tool names this connection is offered.
	 * @return array<int, array<string, string>>
	 */
	public static function listed_templates( array $offered ): array {
		$out = array();

		foreach ( self::templates() as $template => $resource ) {
			if ( in_array( $resource['tool'], $offered, true ) ) {
				$out[] = array(
					'uriTemplate' => $template,
					'name'        => $resource['name'],
					'title'       => $resource['title'],
					'description' => $resource['description'],
					'mimeType'    => 'application/json',
				);
			}
		}

		return $out;
	}

	/**
	 * The tool an address is answered by, and the arguments it carries, or
	 * null for an address this server does not have.
	 *
	 * @return array{tool: string, arguments: array<string, mixed>}|null
	 */
	public static function resolve( string $uri ): ?array {
		$fixed = self::fixed();

		if ( isset( $fixed[ $uri ] ) ) {
			return array(
				'tool'      => $fixed[ $uri ]['tool'],
				'arguments' => array(),
			);
		}

		if ( 1 === preg_match( '#^bettershield://findings/([a-z0-9_-]{1,128})$#', $uri, $match ) ) {
			return array(
				'tool'      => 'get-audit-check',
				'arguments' => array( 'check_id' => $match[1] ),
			);
		}

		if ( 1 === preg_match( '#^bettershield://activity/(\d{4})-(\d{2})-(\d{2})$#', $uri, $match ) && checkdate( (int) $match[2], (int) $match[3], (int) $match[1] ) ) {
			$day = gmmktime( 0, 0, 0, (int) $match[2], (int) $match[3], (int) $match[1] );

			return array(
				'tool'      => 'query-activity',
				'arguments' => array(
					'since' => gmdate( 'Y-m-d\TH:i:s\Z', $day ),
					'until' => gmdate( 'Y-m-d\TH:i:s\Z', $day + DAY_IN_SECONDS ),
					'limit' => 200,
				),
			);
		}

		return null;
	}
}
