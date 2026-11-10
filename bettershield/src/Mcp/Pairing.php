<?php
/**
 * The credential an administrator mints so one assistant can reach this site.
 *
 * A pairing token is 32 bytes of randomness, handed back in plaintext exactly
 * once and never again. What stays behind is its SHA-256 digest and the last
 * four characters, which is enough to compare a presented token in constant
 * time and enough for an owner to tell one credential from another — and not
 * enough for anything, this plugin included, to reconstruct it.
 *
 * The record also names the administrator who minted it. Every call the token
 * authenticates runs as that account, so the credential can never reach past
 * what the person behind it may do, and an account that is deleted or demoted
 * takes its pairing with it.
 *
 * State lives in one option rather than a table: it is a single row per site,
 * it is read on requests that are already paying for an option cache, and a
 * table would have to be migrated for nothing.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Mcp;

use BetterShield\Capabilities;
use BetterShield\Support\Claim;
use BetterShield\Support\Text;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Pairing {

	/** Where the pairing record is kept. */
	public const OPTION = 'bettershield_mcp_pairing';

	/** The path segment of the pretty endpoint, shared with discovery. */
	public const ENDPOINT_PATH = 'bettershield/mcp';

	/**
	 * What a configuration snippet writes where the token belongs.
	 *
	 * A read of the connection never carries the token, so the snippets a
	 * screen shows cannot either. The placeholder is loud enough that pasting
	 * it unedited fails immediately rather than half-working.
	 */
	public const TOKEN_PLACEHOLDER = 'PASTE_YOUR_TOKEN_HERE';

	/** The environment variable Codex is told to read the token from. */
	public const CODEX_TOKEN_ENV = 'BETTERSHIELD_TOKEN';

	/**
	 * How long between two writes recording that the token was used.
	 *
	 * A connected assistant makes many calls a minute and every one of them
	 * would otherwise be an option write on a request nobody is waiting on
	 * but the database still pays for.
	 */
	private const LAST_USED_THROTTLE = 60;

	/** The claim every write to the record is taken behind. */
	private const LOCK_KEY = 'mcp_pairing_write';

	/** How long that claim is held for, if the holder never gives it back. */
	private const LOCK_TTL = 5;

	/**
	 * The record as this request has already read it.
	 *
	 * One authenticated call asks for the digest, the account, the scope and
	 * the last-used stamp, and each of those was a separate read of the same
	 * row. Held here for the request and dropped the moment anything writes.
	 *
	 * @var array<string, mixed>|null
	 */
	private static ?array $memo = null;

	/**
	 * The credential digest this request authenticated against, once a
	 * last-used write has been queued for it. Empty when none has.
	 */
	private static string $queued = '';

	/**
	 * The endpoint a person pastes into their assistant.
	 */
	public static function endpoint(): string {
		return home_url( '/' . self::ENDPOINT_PATH );
	}

	/**
	 * The endpoint that works whatever the permalink settings are.
	 *
	 * The pretty path above is a rewrite rule, and a site on plain permalinks
	 * has none. This one is the REST namespace itself, which is always served.
	 */
	public static function fallback_endpoint(): string {
		return rest_url( 'bettershield/v1/mcp' );
	}

	/**
	 * Whether the pretty address is routed on this site at all.
	 *
	 * The pretty endpoint is a rewrite rule, and a site on plain permalinks
	 * has no rewrite rules: every unknown path is answered by the front page,
	 * with a 200 and a page. On such a site the REST address is the only one
	 * that reaches this plugin.
	 */
	public static function pretty_routed(): bool {
		return '' !== (string) get_option( 'permalink_structure', '' );
	}

	/**
	 * The address a person is actually handed: the pretty one where it is
	 * routed, the REST one where it is not.
	 *
	 * Distinct from `endpoint()`, which stays the resource the browser sign-in
	 * flow is built around whatever the permalink settings say. That flow
	 * needs the pretty address to exist, and the screen says so rather than
	 * handing out an address that answers with a page.
	 */
	public static function address(): string {
		return self::pretty_routed() ? self::endpoint() : self::fallback_endpoint();
	}

	/**
	 * The stored record, with every field present.
	 *
	 * @return array{token_hash: string, hint: string, connected_at: int, user_id: int, last_used: int, scope: string}
	 */
	public static function state(): array {
		if ( null !== self::$memo ) {
			/** @var array{token_hash: string, hint: string, connected_at: int, user_id: int, last_used: int, scope: string} */
			return self::$memo;
		}

		$stored = get_option( self::OPTION, array() );

		if ( ! is_array( $stored ) ) {
			$stored = array();
		}

		self::$memo = array(
			'token_hash'   => isset( $stored['token_hash'] ) ? (string) $stored['token_hash'] : '',
			'hint'         => isset( $stored['hint'] ) ? (string) $stored['hint'] : '',
			'connected_at' => isset( $stored['connected_at'] ) ? (int) $stored['connected_at'] : 0,
			'user_id'      => isset( $stored['user_id'] ) ? (int) $stored['user_id'] : 0,
			'last_used'    => isset( $stored['last_used'] ) ? (int) $stored['last_used'] : 0,
			/*
			 * A record with no scope in it is read as the smaller one. That is
			 * the safe direction, and a visible one: the connection screen
			 * names the scope, and replacing the credential is how it widens.
			 */
			'scope'        => Scopes::normalize( isset( $stored['scope'] ) ? (string) $stored['scope'] : '' ),
			'write_generation' => (string) ( $stored['write_generation'] ?? '' ),
		);

		/** @var array{token_hash: string, hint: string, connected_at: int, user_id: int, last_used: int, scope: string} */
		return self::$memo;
	}

	/**
	 * Forget what this request has read. The record lives and dies with the
	 * request in production; a test process is many requests in one lifetime.
	 */
	public static function reset_request_state(): void {
		self::$memo   = null;
		self::$queued = '';
	}

	public static function is_connected(): bool {
		return '' !== self::state()['token_hash'];
	}

	/** The administrator every call on this credential runs as. */
	public static function user_id(): int {
		return self::state()['user_id'];
	}

	/** The last four characters of the token, so one can be told from another. */
	public static function hint(): string {
		return self::state()['hint'];
	}

	/**
	 * What this credential is allowed to do. An empty string when nothing is
	 * paired, so a screen can tell "read only" from "nothing here".
	 */
	public static function scope(): string {
		$state = self::state();

		return '' === $state['token_hash'] ? '' : WriteGrants::scope( $state );
	}

	/**
	 * Whether a presented token is this site's.
	 *
	 * Compared as digests rather than as secrets: the stored value is a hash,
	 * so there is nothing here to leak, and `hash_equals` keeps the comparison
	 * itself from saying how much of a guess was right.
	 */
	public static function verify( string $presented ): bool {
		$stored = self::state()['token_hash'];

		if ( '' === $stored || '' === $presented ) {
			return false;
		}

		return hash_equals( $stored, self::digest( $presented ) );
	}

	/**
	 * Mint a credential, replacing whatever was there.
	 *
	 * Returns the plaintext, which is the only time it exists outside the
	 * caller's own memory. Rotation is the same act: a leaked token is
	 * answered by minting another, and the previous one stops working in the
	 * same statement.
	 */
	public static function mint( int $user_id, string $scope = Scopes::READ_WRITE ): string {
		$token = bin2hex( random_bytes( 32 ) );
		$grant = WriteGrants::issue( $scope );

		self::guarded(
			static function () use ( $token, $user_id, $grant ): void {
				update_option(
					self::OPTION,
					array(
						'token_hash'   => self::digest( $token ),
						'hint'         => substr( $token, -4 ),
						'connected_at' => time(),
						'user_id'      => $user_id,
						'last_used'    => 0,
						'scope'        => WriteGrants::scope( $grant ),
						'write_generation' => $grant['write_generation'],
					),
					false
				);
			}
		);

		return $token;
	}

	/** Persist the smaller scope, while the consent generation protects against stale writers. */
	public static function narrow_write_scope(): void {
		self::guarded( static function (): void {
			wp_cache_delete( self::OPTION, 'options' );
			$stored = get_option( self::OPTION, array() );
			if ( is_array( $stored ) && ! empty( $stored['token_hash'] ) ) {
				$stored['scope'] = Scopes::READ_ONLY;
				update_option( self::OPTION, $stored, false );
			}
		} );
	}

	/**
	 * Take the credential away, and every granted application with it.
	 *
	 * Disconnect is the one switch an owner reaches for when something has
	 * gone wrong, so it has to mean all of it rather than the half that was
	 * minted from this screen.
	 */
	public static function forget(): void {
		self::guarded(
			static function (): void {
				delete_option( self::OPTION );
			}
		);

		OAuth::revoke_all();
	}

	/**
	 * Note that the credential was just used, at most once a minute — and
	 * write it down after the answer has gone.
	 *
	 * The write is a full rewrite of the record plus a claim, on the one
	 * request an assistant is waiting for, and nothing depends on it having
	 * landed by the time the response is written. The OAuth side of this
	 * endpoint already records a client's use at shutdown for the same reason.
	 */
	public static function touch(): void {
		if ( '' !== self::$queued ) {
			return;
		}

		$state = self::state();

		if ( '' === $state['token_hash'] ) {
			return;
		}

		if ( time() - $state['last_used'] < self::LAST_USED_THROTTLE ) {
			return;
		}

		self::$queued = $state['token_hash'];

		add_action( 'shutdown', array( self::class, 'flush_last_used' ), 85 );
	}

	/**
	 * The write itself. Public because `shutdown` calls it.
	 *
	 * A read-modify-write over the whole record is the shape that puts back
	 * whatever it read a moment before, so the record is read again inside the
	 * claim and the write is abandoned unless the credential this request
	 * authenticated against is still the one stored. A disconnect or a
	 * rotation landing in that window is the case that matters: the first is
	 * the switch an owner reaches for when something has gone wrong, and the
	 * second hands them a plaintext that exists nowhere else and cannot be
	 * shown again.
	 */
	public static function flush_last_used(): void {
		$expected = self::$queued;

		if ( '' === $expected ) {
			return;
		}

		self::$queued = '';

		self::guarded(
			static function () use ( $expected ): void {
				// What is stored now, not this request's copy: a narrowing
				// keeps the token and changes its scope, and a stale copy
				// written back would put the old scope back with it.
				wp_cache_delete( self::OPTION, 'options' );

				$stored = get_option( self::OPTION, array() );

				if ( ! is_array( $stored )
					|| ! isset( $stored['token_hash'] )
					|| ! hash_equals( (string) $stored['token_hash'], $expected )
				) {
					return;
				}

				$stored['last_used'] = time();

				update_option( self::OPTION, $stored, false );
			}
		);
	}

	/**
	 * Run one write to the record with nobody else in between.
	 *
	 * The claim orders two writers; it does not authorize either. A claim that
	 * cannot be taken lets the write go ahead anyway, because refusing to
	 * record a use — or to mint a credential — would turn a busy moment into a
	 * connection that cannot be made. What makes the write safe is the re-read
	 * inside it, not the claim around it.
	 */
	private static function guarded( callable $write ): void {
		$held = Claim::claim( self::LOCK_KEY, self::LOCK_TTL );

		try {
			$write();
		} finally {
			if ( $held ) {
				Claim::release( self::LOCK_KEY );
			}

			self::$memo = null;
		}
	}

	/**
	 * The administrator who minted the credential, named for a screen.
	 *
	 * Null when nothing is paired, and null when the account is gone — which
	 * is the same state the server reaches when it refuses the credential, so
	 * the screen and the door agree.
	 *
	 * @return array{id: int, display_name: string}|null
	 */
	public static function granted_by(): ?array {
		$user_id = self::user_id();

		if ( $user_id <= 0 ) {
			return null;
		}

		$user = get_userdata( $user_id );

		if ( ! $user ) {
			return null;
		}

		return array(
			'id'           => $user_id,
			'display_name' => Text::clip( (string) $user->display_name, 191 ),
		);
	}

	/**
	 * Ready-to-paste configuration for the assistants people actually use.
	 *
	 * Two shapes, because there are two ways in. A client that speaks OAuth
	 * takes the endpoint and nothing else — it discovers the rest and asks an
	 * administrator on screen. A client with a headers field takes the
	 * fallback endpoint and a bearer token, and the token is a placeholder
	 * here: this payload is a read, and a read never carries the credential.
	 *
	 * @return array<string, array<string, string>>
	 */
	public static function snippets(): array {
		$endpoint = self::address();
		$fallback = self::fallback_endpoint();

		return array(
			'claude_remote'  => array( 'url' => $endpoint ),
			'claude_desktop' => array( 'json' => self::bearer_json( 'bettershield', $fallback ) ),
			'cursor'         => array( 'json' => self::bearer_json( 'bettershield', $fallback ) ),
			'codex'          => array(
				'toml'      => self::codex_toml( 'bettershield', $fallback ),
				'token_env' => self::CODEX_TOKEN_ENV,
			),
			'chatgpt'        => array(
				'url'  => $endpoint,
				'auth' => 'oauth',
			),
		);
	}

	/**
	 * Codex's own form: a table in its config.toml, where an `mcpServers`
	 * JSON block is a parse error that stops it starting. The token is not
	 * written into the file at all; Codex reads it from the environment
	 * variable the table names.
	 */
	private static function codex_toml( string $name, string $url ): string {
		// A TOML basic string, so a backslash or a quote in the address
		// cannot end it early.
		$url = str_replace( array( '\\', '"' ), array( '\\\\', '\\"' ), $url );

		return '[mcp_servers.' . $name . "]\n"
			. 'url = "' . $url . "\"\n"
			. 'bearer_token_env_var = "' . self::CODEX_TOKEN_ENV . "\"\n";
	}

	/**
	 * The portable `mcpServers` block, with the token left as a placeholder.
	 */
	private static function bearer_json( string $name, string $url ): string {
		$json = wp_json_encode(
			array(
				'mcpServers' => array(
					$name => array(
						'url'     => $url,
						'headers' => array( 'Authorization' => 'Bearer ' . self::TOKEN_PLACEHOLDER ),
					),
				),
			),
			JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
		);

		return is_string( $json ) ? $json : '';
	}

	/**
	 * The instruction a person pastes into an assistant so it sets itself up.
	 *
	 * Written as a request from the site owner rather than as documentation,
	 * because that is what it is: the assistant reads it, adds the connection
	 * and reports back what it can see.
	 */
	public static function prompt(): string {
		$lines = array(
			__( 'Add this remote MCP server to your connections so you can check the security of my WordPress site, then use it.', 'bettershield' ),
			'',
			__( 'Server name: BetterShield', 'bettershield' ) ,
			sprintf(
				/* translators: %s: the site's MCP endpoint URL. */
				__( 'Server URL: %s', 'bettershield' ),
				self::address()
			),
			__( 'Transport: streamable HTTP', 'bettershield' ),
			__( 'Authentication: sign in through the browser when prompted, or paste the connection token as a bearer token if your client has no browser step.', 'bettershield' ),
			self::pretty_routed()
				? sprintf(
					/* translators: %s: the site's REST fallback endpoint URL. */
					__( 'If the server URL does not answer, use %s instead.', 'bettershield' ),
					self::fallback_endpoint()
				)
				: '',
			'',
			__( 'Once it is connected, call the get-security-posture tool and tell me the score, the grade, and what the open findings mean.', 'bettershield' ),
		);

		/**
		 * The setup instruction shown on the connection screen.
		 *
		 * @param string $prompt The default text.
		 */
		return (string) apply_filters( 'bettershield_mcp_prompt', implode( "\n", $lines ) );
	}

	/**
	 * Whether an account may hold a pairing at all.
	 *
	 * The same question the server asks on every call, in one place, so the
	 * screen cannot offer a credential the door would refuse.
	 */
	public static function may_hold( \WP_User $user ): bool {
		return user_can( $user, Capabilities::MANAGE );
	}

	/** How a token is stored: as its digest, and never as itself. */
	private static function digest( string $token ): string {
		return hash( 'sha256', $token );
	}
}
