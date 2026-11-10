<?php
/**
 * Who is on the wire, and one row per tool call saying what they asked for.
 *
 * The invocation record this plugin already keeps is the better record — it has
 * the duration, the outcome the lifecycle actually reached, and every ability
 * on the site rather than only ours — but it needs WordPress 7.1 to exist at
 * all, and this endpoint answers on every supported version. So the transport
 * writes its own row, once per `tools/call`, on every version: below 7.1 it is
 * the only record that a call happened, and above it it is the only record that
 * names the credential, because the invocation table has a column for the
 * account and none for the credential the account was reached through.
 *
 * What the row carries about the credential is what an owner can act on: which
 * kind it was, and the four characters the connection screen shows beside a
 * pairing or the identifier it shows beside an application. Never the
 * credential — the site does not hold it in a form that could be written down.
 *
 * Exactly one row per call. The server calls this from the single place a tool
 * call is answered, and the flag below is keyed on the JSON-RPC message the
 * answer belongs to — so one message answered twice is one row, while a batch
 * asking for the same tool under two ids is two calls and two rows.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Mcp;

use BetterShield\Agents\Capture;
use BetterShield\Events\Writer;
use BetterShield\Support\Text;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Audit {

	/** A credential an administrator minted from the connection screen. */
	public const PAIRING = 'pairing';

	/** A registered application holding a grant somebody approved. */
	public const APP = 'app';

	/** The object type the transport's own rows carry, so they read apart. */
	public const OBJECT_TYPE = 'mcp_tool';

	/**
	 * The errors that mean the call was refused rather than failed: the site
	 * or the connection does not allow it. Anything else that did not
	 * complete failed.
	 */
	public const REFUSALS = array(
		'bettershield_mcp_reads_off',
		'bettershield_mcp_writes_off',
		'bettershield_mcp_out_of_scope',
		'bettershield_mcp_account_cannot_write',
		'ability_invalid_permissions',
		AppTools::REFUSAL,
	);

	private static string $kind = '';

	private static string $id = '';

	/**
	 * The calls this request has already recorded, keyed on the message each
	 * answer belongs to, so a call answered twice cannot be recorded twice.
	 *
	 * @var array<string, true>
	 */
	private static array $recorded = array();

	/**
	 * The fallback key for a call carrying no message id of its own. Nothing
	 * routes one here today; if anything ever does, it is one row per call
	 * rather than one row per request.
	 */
	private static int $sequence = 0;

	/** Which message of this request is being answered. */
	private static int $message = 0;

	/**
	 * Name the credential this request authenticated with.
	 *
	 * Called by the door and nowhere else, the moment a credential is accepted
	 * and before anything runs on its behalf.
	 */
	public static function identify( string $kind, string $id ): void {
		self::$kind = $kind;
		self::$id   = $id;
	}

	public static function kind(): string {
		return self::$kind;
	}

	public static function id(): string {
		return self::$id;
	}

	/**
	 * The connection this request came in on, as kind and the part of it the
	 * connection screen shows: `app:<client id>` or `pairing:<hint>`. Null
	 * when no credential of this server's was accepted.
	 */
	public static function connection(): ?string {
		return '' === self::$kind ? null : self::$kind . ':' . self::$id;
	}

	/**
	 * What an owner reads for a connection: the application's name, or the
	 * manual credential with the characters shown beside it. Read now, so a
	 * renamed or removed application reads as it is.
	 */
	public static function connection_label( string $connection ): string {
		list( $kind, $id ) = array_pad( explode( ':', $connection, 2 ), 2, '' );

		if ( self::PAIRING === $kind ) {
			/* translators: %s: the last characters of the credential, as the connection screen shows them. */
			return sprintf( __( 'Manual credential ··%s', 'bettershield' ), $id );
		}

		$name = self::APP === $kind ? OAuth::client_name( $id ) : null;

		return null !== $name ? $name : $id;
	}

	/**
	 * Forget the request's credential and its counters. Production never needs
	 * this — the state lives and dies with the request — but a test process is
	 * many requests in one lifetime.
	 */
	public static function reset_request_state(): void {
		self::$kind     = '';
		self::$id       = '';
		self::$recorded = array();
		self::$sequence = 0;
		self::$message  = 0;

		Networks::reset_request_state();
	}

	/**
	 * A new message is being dispatched.
	 *
	 * What tells two executions apart is which message asked for them, and a
	 * client-supplied id cannot do that: nothing stops a batch from carrying
	 * the same id twice, and the server runs both. Counted here, where the
	 * server knows it has moved on to the next message, rather than derived
	 * from anything the client sent.
	 */
	public static function begin_message(): void {
		++self::$message;
	}

	/**
	 * Record one tool call.
	 *
	 * @param mixed $arguments What the caller sent, digested and never kept.
	 * @param mixed $message_id The JSON-RPC id of the message being answered.
	 */
	public static function tool_called( string $tool, string $ability, $arguments, string $outcome, string $error_code = '', $message_id = null ): void {
		$digest = Capture::digest( $arguments );

		$key = self::call_key( $message_id, $tool, $digest );

		if ( isset( self::$recorded[ $key ] ) ) {
			return;
		}

		self::$recorded[ $key ] = true;

		$context = array(
			'tool'    => Text::clip( $tool, 191 ),
			'outcome' => $outcome,
			// Which kind of credential, and the part of it the connection
			// screen already shows. Never the credential.
			'via'     => '' === self::$kind ? 'unknown' : self::$kind,
			/*
			 * Whether a matching invocation record exists to join to. Below
			 * WordPress 7.1 the lifecycle filters never fire, and an owner
			 * reading this row later needs to know whether the absence of an
			 * invocation row means nothing ran or means nothing was watching.
			 */
			'recorded_by_capture' => Capture::is_available() && Capture::is_enabled(),
		);

		if ( '' !== self::$id ) {
			$context['credential'] = Text::clip( self::$id, 191 );
		}

		if ( null !== $digest ) {
			$context['input_digest'] = $digest;
		}

		if ( '' !== $error_code ) {
			$context['error'] = Text::clip( $error_code, 64 );
		}

		/*
		 * Named by its ability only when there is one. A tool nobody
		 * registered was recorded as `bettershield/<name>`, as though that
		 * ability existed, and a call that named no tool as an empty object.
		 */
		$known  = '' !== $ability && function_exists( 'wp_has_ability' ) && wp_has_ability( $ability );
		$object = $known ? $ability : $tool;

		// Said in so many words when the server answered that there is no
		// such tool, rather than that the site was not offering it.
		if ( 'bettershield_mcp_unknown_tool' === $error_code ) {
			$context['unknown_tool'] = true;
		}

		// Where this connection has been used from: a network it never has
		// been is worth a row of its own (#1880).
		// Before WordPress 6.9 there is no ability to look up, so nothing it
		// ran can be told apart as a write.
		if ( '' !== self::$kind ) {
			$writes = false;
			if ( $known && function_exists( 'wp_get_ability' ) ) {
				$writes = ! Tools::is_read_tool( wp_get_ability( $ability ) );
			}
			Networks::observe( self::$kind . ':' . self::$id, $writes );
		}

		Writer::instance()->record(
			'ability_used',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => self::OBJECT_TYPE,
				'context'     => $context,
			) + ( '' === $object ? array() : array( 'object_id' => $object ) )
		);
	}

	/**
	 * What makes two of these the same call.
	 *
	 * Which message the answer belongs to, the tool, and what was asked of it.
	 * Answering one message twice is one call; two messages are two.
	 *
	 * The message is identified by the server's own count of how many it has
	 * dispatched, not by the id the client put on it. An id is content — a
	 * batch may carry the same one twice, with the same tool and the same
	 * arguments, and the server dispatches both with a real side effect each.
	 * Keyed on content alone those two collapsed into one key and the second
	 * execution left no row, which is the same silence as the earlier
	 * different-arguments case, one step further in.
	 *
	 * The id and the digest stay in the key so that a single message recorded
	 * twice along two paths is still one row.
	 *
	 * @param mixed $message_id
	 */
	private static function call_key( $message_id, string $tool, ?string $digest ): string {
		if ( is_scalar( $message_id ) && '' !== (string) $message_id ) {
			return 'msg:' . self::$message . '|id:' . (string) $message_id . '|' . $tool . '|' . (string) $digest;
		}

		++self::$sequence;

		return 'seq:' . self::$sequence . '|' . $tool;
	}
}
