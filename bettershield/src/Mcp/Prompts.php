<?php
/**
 * Workflows the site offers an assistant, rather than waiting to be asked
 * (#557).
 *
 * A prompt is text: what to read and how to answer, written by the site so
 * the help a person gets does not depend on knowing what to type. None of
 * them carries site data or changes anything. Each names the resources it
 * reads, and is offered only while the tools behind those are, so a prompt
 * never sends an assistant to something it would be refused.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Mcp;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Prompts {

	/**
	 * Every prompt: name => title, description, arguments and the tools it
	 * needs.
	 *
	 * @return array<string, array{title: string, description: string, arguments: array<int, array{name: string, description: string, required: bool}>, needs: string[]}>
	 */
	public static function all(): array {
		return array(
			'triage-findings'     => array(
				'title'       => __( 'Triage the open findings', 'bettershield' ),
				'description' => __( 'Read the open findings and say what to do first, and why.', 'bettershield' ),
				'arguments'   => array(),
				'needs'       => array( 'get-security-posture' ),
			),
			'explain-finding'     => array(
				'title'       => __( 'Explain a finding to someone without an account', 'bettershield' ),
				'description' => __( 'One finding in plain words, for a client or a colleague who cannot sign in.', 'bettershield' ),
				'arguments'   => array(
					array(
						'name'        => 'check_id',
						'description' => __( 'The finding’s id, as the posture lists it.', 'bettershield' ),
						'required'    => true,
					),
				),
				'needs'       => array( 'get-audit-check' ),
			),
			'getting-back-in'     => array(
				'title'       => __( 'Walk through getting back in', 'bettershield' ),
				'description' => __( 'Which ways back in work today, and the steps for a locked-out owner.', 'bettershield' ),
				'arguments'   => array(),
				'needs'       => array( 'get-recovery-readiness' ),
			),
			'review-file-changes' => array(
				'title'       => __( 'Review changed files', 'bettershield' ),
				'description' => __( 'Compare the site’s files with their published copies and summarize what changed.', 'bettershield' ),
				'arguments'   => array(),
				'needs'       => array( 'get-integrity-status' ),
			),
		);
	}

	/**
	 * The prompts this connection is offered, in the protocol's shape.
	 *
	 * @param string[] $offered The tool names this connection is offered.
	 * @return array<int, array<string, mixed>>
	 */
	public static function listed( array $offered ): array {
		$out = array();

		foreach ( self::all() as $name => $prompt ) {
			if ( array() !== array_diff( $prompt['needs'], $offered ) ) {
				continue;
			}

			$entry = array(
				'name'        => $name,
				'title'       => $prompt['title'],
				'description' => $prompt['description'],
			);

			if ( array() !== $prompt['arguments'] ) {
				$entry['arguments'] = $prompt['arguments'];
			}

			$out[] = $entry;
		}

		return $out;
	}

	/**
	 * One prompt's messages, or a WP_Error saying why there are none.
	 *
	 * @param array<string, mixed> $arguments
	 * @param string[]             $offered The tool names this connection is offered.
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function get( string $name, array $arguments, array $offered ) {
		$all = self::all();

		if ( ! isset( $all[ $name ] ) || array() !== array_diff( $all[ $name ]['needs'], $offered ) ) {
			return new \WP_Error(
				'bettershield_mcp_unknown_prompt',
				/* translators: %s: the prompt name that was asked for. */
				sprintf( __( 'This site offers no prompt called %s to this connection.', 'bettershield' ), $name )
			);
		}

		$text = self::text( $name, $arguments );

		if ( is_wp_error( $text ) ) {
			return $text;
		}

		return array(
			'description' => $all[ $name ]['description'],
			'messages'    => array(
				array(
					'role'    => 'user',
					'content' => array(
						'type' => 'text',
						'text' => $text,
					),
				),
			),
		);
	}

	/**
	 * What one prompt asks of the assistant.
	 *
	 * @param array<string, mixed> $arguments
	 * @return string|\WP_Error
	 */
	private static function text( string $name, array $arguments ) {
		switch ( $name ) {
			case 'triage-findings':
				return __( 'Read the resource bettershield://posture. Then tell me which open findings to deal with first, in order. Put critical and high findings ahead of the rest, and among those, the ones marked remediable first: they can be fixed in one step and undone. For each, say in one or two sentences what the risk is and what fixing it changes for the people who use the site. Leave out snoozed findings unless I ask. Do not apply anything: ask me first.', 'bettershield' );

			case 'explain-finding':
				$check = isset( $arguments['check_id'] ) && is_string( $arguments['check_id'] ) ? strtolower( trim( $arguments['check_id'] ) ) : '';

				if ( 1 !== preg_match( '/^[a-z0-9_-]{1,128}$/', $check ) ) {
					return new \WP_Error( 'bettershield_mcp_prompt_argument', __( 'This prompt needs check_id: a finding’s id, as the posture lists it.', 'bettershield' ) );
				}

				return sprintf(
					/* translators: %s: the resource address of one finding. */
					__( 'Read the resource %s. Then explain this finding to someone who has no account on the site, such as a client or a colleague: what it means, why it matters for this site, and what the site’s owner will do about it. Use plain words, no jargon or internal names, and keep it under 150 words. Do not include anything from the site that would help someone attack it.', 'bettershield' ),
					Resources::SCHEME . 'findings/' . $check
				);

			case 'getting-back-in':
				return __( 'Read the resource bettershield://recovery. Then tell me which ways back into this site work today and which do not: the recovery link, printed offline codes, an administrator’s email address, and the email check. For any that do not work, say what to do now, while I can still sign in. Then walk me through what to do if I am locked out, step by step, using only the ways that work. Never ask me for a recovery link, a code or a password.', 'bettershield' );

			case 'review-file-changes':
				return __( 'Read the resource bettershield://integrity. Then summarize which files differ from their published copies and which are new, grouped by core, plugin and theme. Say which changes look expected, such as a plugin updated outside its usual channel, and which deserve a closer look, such as PHP files that appeared in uploads or a core file that changed. Do not restore or quarantine anything: ask me first.', 'bettershield' );
		}

		return new \WP_Error( 'bettershield_mcp_unknown_prompt', __( 'There is no such prompt.', 'bettershield' ) );
	}
}
