<?php
/**
 * The endpoint an assistant talks to, and the door it has to get through.
 *
 * The protocol is JSON-RPC 2.0 over a single HTTP POST, so the whole server
 * surface is five methods: introduce yourself, are you there, what can you do,
 * do this, and an acknowledgement for the notifications a client sends that
 * expect no answer. Batches are a list of those, and both the list and the body
 * carrying it are bounded — the length of either is chosen by whoever is
 * calling, and one authenticated POST should not be able to ask for a hundred
 * thousand tool runs.
 *
 * The door is one question asked in one place. A bearer credential — a pairing
 * token or an access token from the browser sign-in flow — names the
 * administrator who granted it and the scope it was granted with, and the
 * request then runs as that person. So every ability's own permission callback
 * still decides what happens: this class never grants anything, it only says
 * whose permissions apply and how far they reach.
 *
 * **The credential is checked before the lockout is.** A counter that stands in
 * front of authentication refuses the site's own connected assistant because a
 * stranger on the same network guessed wrong ten times; one that stands behind
 * it refuses only callers who were going to be refused anyway, and tells them
 * to come back later instead of pretending the credential was the problem.
 *
 * A call carrying no credential is answered with a 401 and a header naming
 * where the metadata about this endpoint lives. That header is the whole of
 * what a client with no token has to go on, so it is present on the refusal
 * for a locked-out network too — a bare refusal with nothing attached reads to
 * a client as a server that has no sign-in flow at all.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Mcp;

use BetterShield\Events\Writer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Server {

	/** The revision of the protocol this server answers. */
	public const PROTOCOL_VERSION = '2025-06-18';

	/**
	 * How much of a request body is read, and answered.
	 *
	 * A message is a method name and a few arguments. Half a megabyte is
	 * headroom rather than a budget, and the point of having any number at all
	 * is that without one the size of the read is chosen by the caller. Held
	 * here rather than at the pretty path alone, because the REST route is the
	 * one that is always served and it was reading whatever arrived.
	 */
	public const MAX_BODY_BYTES = 524288;

	/**
	 * How many messages one batch may carry.
	 *
	 * A real client batches a handful: an initialize, a notification, a list.
	 * Anything past this is not a client working, and the cost of finding that
	 * out one message at a time is paid by the site.
	 */
	public const MAX_BATCH = 20;

	/** The hash of the scoped wire catalog, outside the protocol-defined serverInfo. */
	public const META_CATALOG_HASH = 'bettershield/catalog_hash';

	/** The error codes JSON-RPC reserves, and the one this server adds. */
	private const PARSE_ERROR        = -32700;
	private const INVALID_REQUEST    = -32600;
	private const METHOD_NOT_FOUND   = -32601;
	private const INVALID_PARAMS     = -32602;
	private const UNAUTHORIZED       = -32001;
	private const RESOURCE_NOT_FOUND = -32002;
	private const INTERNAL_ERROR     = -32603;

	/**
	 * Answer one request.
	 */
	public static function handle( \WP_REST_Request $request ): \WP_REST_Response {
		// The credential's scope is a fact about this request and nothing
		// after it: left set past the return, every ability run later in the
		// same process read as an assistant's call.
		try {
			return self::handle_request( $request );
		} finally {
			self::$scope      = null;
			self::$credential = null;
			self::$catalogs   = array();
		}
	}

	private static function handle_request( \WP_REST_Request $request ): \WP_REST_Response {
		self::$scope      = null;
		self::$credential = null;
		self::$catalogs   = array();

		if ( ! Manager::is_enabled() ) {
			return self::refusal( self::UNAUTHORIZED, __( 'Assistant access is turned off on this site.', 'bettershield' ), 403 );
		}

		/*
		 * A lockdown turns off every credential that is not a person at a
		 * browser, and an assistant's token or an app's grant is one: perhaps
		 * the very thing the owner is responding to. Paused, read and write,
		 * before any credential is looked at, so nothing here counts as a
		 * failed attempt either.
		 */
		if ( \BetterShield\Recovery\Lockdown::is_active() ) {
			// Named for a program as well as a person, so a client can tell a pause from a failure without reading prose.
			return self::refusal( self::UNAUTHORIZED, __( 'This site is locked down, so assistant connections are paused until the owner lifts it.', 'bettershield' ), 403, array( 'reason' => 'lockdown' ) );
		}

		$body = (string) $request->get_body();

		// Before the credential, because the size of what arrived is decided
		// by the caller and reading past this point is the cost being refused.
		if ( strlen( $body ) > self::MAX_BODY_BYTES ) {
			return self::refusal( self::INVALID_REQUEST, __( 'That request is larger than this endpoint accepts.', 'bettershield' ), 413 );
		}

		$presented  = self::bearer( $request );
		$credential = '' === $presented ? null : self::authenticate( $presented );
		self::$scope      = null === $credential ? null : (string) $credential['scope'];
		self::$credential = null === $credential ? null : $credential['kind'] . ':' . $credential['id'];

		if ( null === $credential ) {
			// Only a caller who has already been refused is asked about the
			// lockout, so a credential this site recognizes is never turned
			// away by somebody else's guesses.
			if ( '' !== $presented && RateLimiter::is_locked() ) {
				$response = self::refusal( self::UNAUTHORIZED, __( 'Too many failed attempts from this network. Try again later.', 'bettershield' ), 429 );
				$response->header( 'WWW-Authenticate', self::challenge() );
				$response->header( 'Retry-After', (string) RateLimiter::retry_after() );

				return $response;
			}

			if ( '' !== $presented ) {
				RateLimiter::record_failure();
			}

			$response = self::refusal( self::UNAUTHORIZED, __( 'This request carried no credential this site recognizes.', 'bettershield' ), 401 );
			$response->header( 'WWW-Authenticate', self::challenge() );

			return $response;
		}

		RateLimiter::clear();

		// Every ability run from here is recorded as having come through this
		// door rather than through the dashboard's own, on a credential this
		// request can name without ever holding it.
		Writer::enter_assistant();
		Audit::identify( (string) $credential['kind'], (string) $credential['id'] );

		// An assistant holds a bearer credential, not a browser. Nothing run
		// on its behalf may answer it with the cookies of a signed-in session,
		// which would hand it the whole of an administrator's login.
		add_filter( 'send_auth_cookies', '__return_false', PHP_INT_MAX );

		$scope = (string) $credential['scope'];

		$decoded = json_decode( $body, true );

		if ( null === $decoded && JSON_ERROR_NONE !== json_last_error() ) {
			return self::refusal( self::PARSE_ERROR, __( 'The request body is not valid JSON.', 'bettershield' ), 400 );
		}

		if ( ! is_array( $decoded ) || array() === $decoded ) {
			// An empty array is both the empty batch and the empty object, and
			// neither is a message. It used to be acknowledged as though a
			// notification had been delivered.
			return self::refusal( self::INVALID_REQUEST, __( 'That is not a request this server can read.', 'bettershield' ), 400 );
		}

		if ( array_key_exists( 0, $decoded ) ) {
			if ( count( $decoded ) > self::MAX_BATCH ) {
				return self::refusal(
					self::INVALID_REQUEST,
					sprintf(
						/* translators: %d: how many messages one batch may carry. */
						__( 'That batch carries more than the %d messages this server answers at once.', 'bettershield' ),
						self::MAX_BATCH
					),
					400
				);
			}

			return self::announce( $request, $credential, $scope, self::batch( $decoded, $scope ), array_column( $decoded, 'method' ) );
		}

		$answer = self::dispatch( $decoded, $scope );

		// A notification is a message with no id: it is acknowledged and no
		// body is returned, which is what the protocol asks for.
		return self::announce(
			$request,
			$credential,
			$scope,
			null === $answer ? new \WP_REST_Response( null, 202 ) : new \WP_REST_Response( $answer, 200 ),
			array( is_scalar( $decoded['method'] ?? null ) ? (string) $decoded['method'] : '' )
		);
	}

	/** Where each connection's last-read tool list is remembered, by credential. */
	private const SEEN_OPTION = 'bettershield_mcp_tools_seen';

	/** How many connections are remembered before the oldest is forgotten. */
	private const SEEN_LIMIT = 100;

	/**
	 * Tell a connection whose tool list has changed since it last read it.
	 *
	 * The list is not fixed: the write opt-in adds four tools and takes them
	 * away, the deactivation switch adds two, an update adds more. A client
	 * told `listChanged: false` cached the list at initialize and never read
	 * it again, so an owner who turned a switch on went back to an assistant
	 * that said it had no such tool, and nothing told either of them why.
	 *
	 * This endpoint answers one request at a time and holds no stream of its
	 * own, so the notification the protocol names for this rides on the next
	 * answer: when the client accepts an event stream — which the transport
	 * asks every client to — the answer goes out as one, the notification
	 * first and the result after it. A client that accepts only JSON is told
	 * in initialize's instructions to read the list again when told to, and
	 * gets nothing more, because there is nowhere to put it.
	 *
	 * A connection this site has not seen list its tools since this shipped
	 * is told once, so an assistant connected before the switch was turned
	 * learns of it on its next call rather than at its next connection.
	 *
	 * @param array<string, mixed> $credential
	 * @param array<int, mixed>    $methods The methods this request carried.
	 */
	private static function announce( \WP_REST_Request $request, array $credential, string $scope, \WP_REST_Response $response, array $methods ): \WP_REST_Response {
		$key     = (string) $credential['kind'] . ':' . (string) $credential['id'];
		$current = self::tools_version( $scope );
		$seen    = self::seen();

		if ( in_array( 'initialize', $methods, true ) || in_array( 'tools/list', $methods, true ) ) {
			self::remember( $seen, $key, $current );

			return $response;
		}

		if ( isset( $seen[ $key ] ) && $seen[ $key ] === $current ) {
			return $response;
		}

		if ( false === strpos( (string) $request->get_header( 'accept' ), 'text/event-stream' ) ) {
			return $response;
		}

		self::remember( $seen, $key, $current );

		$messages = array(
			array(
				'jsonrpc' => '2.0',
				'method'  => 'notifications/tools/list_changed',
			),
		);

		if ( 202 !== $response->get_status() ) {
			$messages[] = $response->get_data();
		}

		$body = '';

		foreach ( $messages as $message ) {
			$body .= "event: message\ndata: " . wp_json_encode( $message ) . "\n\n";
		}

		$stream = new \WP_REST_Response( new EventStream( $body ), 200 );
		$stream->header( 'Content-Type', 'text/event-stream' );
		$stream->header( 'Cache-Control', 'no-cache' );

		return $stream;
	}

	/** A short name for the tool list a scope sees: the names, in order. */
	private static function tools_version( string $scope ): string {
		return md5( implode( "\n", array_column( self::catalog( $scope ), 'name' ) ) );
	}

	/** @var array<string, array<int, array<string, mixed>>> Catalogs live only for this request. */
	private static array $catalogs = array();

	/** @return array<int, array<string, mixed>> */
	private static function catalog( string $scope ): array {
		if ( ! isset( self::$catalogs[ $scope ] ) ) {
			self::$catalogs[ $scope ] = Tools::catalog( $scope );
		}
		return self::$catalogs[ $scope ];
	}

	/** @return array<string, string> */
	private static function seen(): array {
		$stored = get_option( self::SEEN_OPTION, array() );

		return is_array( $stored ) ? $stored : array();
	}

	/**
	 * @param array<string, string> $seen
	 */
	private static function remember( array $seen, string $key, string $version ): void {
		if ( ( $seen[ $key ] ?? null ) === $version ) {
			return;
		}

		unset( $seen[ $key ] );
		$seen[ $key ] = $version;

		while ( count( $seen ) > self::SEEN_LIMIT ) {
			array_shift( $seen );
		}

		update_option( self::SEEN_OPTION, $seen, false );
	}

	/**
	 * A list of messages, answered as a list of the ones that wanted answers.
	 *
	 * @param array<int, mixed> $messages
	 */
	private static function batch( array $messages, string $scope ): \WP_REST_Response {
		$answers = array();

		foreach ( $messages as $message ) {
			$answer = self::dispatch( is_array( $message ) ? $message : array(), $scope );

			if ( null !== $answer ) {
				$answers[] = $answer;
			}
		}

		return array() === $answers
			? new \WP_REST_Response( null, 202 )
			: new \WP_REST_Response( $answers, 200 );
	}

	/**
	 * One message. Null means it was a notification and wants no answer.
	 *
	 * @param array<string, mixed> $message
	 * @return array<string, mixed>|null
	 */
	private static function dispatch( array $message, string $scope ): ?array {
		/*
		 * JSON-RPC 2.0 first: a message without `"jsonrpc": "2.0"`, with an id
		 * that is not a string, number or null, a method that is not a string
		 * or params that are not structured is not a request. They were
		 * answered as though they were, an object id echoed back. Checked
		 * before the notification rule, because a message that is not a
		 * request is not a notification either, and goes unanswered only when
		 * it is one. The id is echoed only when it is one an id can be.
		 */
		$has_id = array_key_exists( 'id', $message );
		$valid  = ! $has_id || null === $message['id'] || is_string( $message['id'] ) || is_int( $message['id'] ) || is_float( $message['id'] );

		if ( ! $valid || '2.0' !== ( $message['jsonrpc'] ?? null ) || ! is_string( $message['method'] ?? null ) || ( isset( $message['params'] ) && ! is_array( $message['params'] ) ) ) {
			return self::error( $valid && $has_id ? $message['id'] : null, self::INVALID_REQUEST, __( 'That message is not a JSON-RPC 2.0 request: it needs "jsonrpc": "2.0", a method name, and an id that is a string or a number.', 'bettershield' ) );
		}

		/*
		 * A notification is a message with no id, and JSON-RPC 2.0 §4.1 says a
		 * server must not answer one. Nothing here runs from one either: a
		 * tool call whose outcome the caller has said it will not read is a
		 * change to this site that nobody is going to be told about, which is
		 * not a thing this endpoint does. The client's own acknowledgement is
		 * the 202 the caller sends back.
		 */
		if ( ! array_key_exists( 'id', $message ) ) {
			return null;
		}

		// The server has moved on to the next message. What the client called
		// it is not what tells it apart from the one before.
		Audit::begin_message();

		$id     = $message['id'];
		$params = isset( $message['params'] ) && is_array( $message['params'] ) ? $message['params'] : array();

		$method = (string) $message['method'];

		switch ( $method ) {
			case 'initialize':
				return self::result(
					$id,
					array(
						'protocolVersion' => self::PROTOCOL_VERSION,
						// Resources and prompts follow the tools they stand on, so
						// the tools' notice is the one to act on (#557).
						'capabilities'    => array(
							'tools'     => array( 'listChanged' => true ),
							'resources' => array( 'listChanged' => false ),
							'prompts'   => array( 'listChanged' => false ),
						),
						'serverInfo'      => self::identity(),
						'_meta'           => array( self::META_CATALOG_HASH => Tools::catalog_hash( $scope, self::catalog( $scope ) ) ),
						'instructions'    => __( 'The tool list changes when the site owner turns a switch on or off. When this server sends notifications/tools/list_changed, read tools/list again, and resources/list and prompts/list with it.', 'bettershield' ),
					)
				);

			case 'ping':
				return self::result( $id, (object) array() );

			case 'tools/list':
				$tools = self::catalog( $scope );
				return self::result( $id, array( 'tools' => $tools, '_meta' => array( self::META_CATALOG_HASH => Tools::catalog_hash( $scope, $tools ) ) ) );

			case 'tools/call':
				return self::call( $id, $params, $scope );

			case 'resources/list':
				return self::result( $id, array( 'resources' => Resources::listed( self::offered( $scope ) ) ) );

			case 'resources/templates/list':
				return self::result( $id, array( 'resourceTemplates' => Resources::listed_templates( self::offered( $scope ) ) ) );

			case 'resources/read':
				return self::read( $id, $params, $scope );

			case 'prompts/list':
				return self::result( $id, array( 'prompts' => Prompts::listed( self::offered( $scope ) ) ) );

			case 'prompts/get':
				$name   = isset( $params['name'] ) && is_scalar( $params['name'] ) ? (string) $params['name'] : '';
				$prompt = Prompts::get( $name, isset( $params['arguments'] ) && is_array( $params['arguments'] ) ? $params['arguments'] : array(), self::offered( $scope ) );

				return is_wp_error( $prompt ) ? self::error( $id, self::INVALID_PARAMS, $prompt->get_error_message() ) : self::result( $id, $prompt );

			default:
				return self::error(
					$id,
					self::METHOD_NOT_FOUND,
					sprintf(
						/* translators: %s: the JSON-RPC method that was asked for. */
						__( 'There is no method called %s here.', 'bettershield' ),
						$method
					)
				);
		}
	}

	/**
	 * How this server introduces itself.
	 *
	 * `name` is the machine handle and never changes; the rest is what a
	 * client puts on the card a person then decides about — a readable title,
	 * the site to read about the product, and a mark, so the entry says what
	 * it is rather than showing whatever the client guessed from the address.
	 *
	 * The last three arrived in a later revision of the protocol than the one
	 * declared here, which is why the declared revision is unchanged: a client
	 * that does not know them ignores them, and one that does gets them now
	 * rather than at the next revision bump.
	 *
	 * The images are served from this plugin's own folder. Nothing here
	 * reaches another site for them, and a client that cannot load one falls
	 * back to its own placeholder.
	 *
	 * @return array<string, mixed>
	 */
	private static function identity(): array {
		$icon = static function ( string $file, string $type, string $size ): array {
			return array(
				'src'      => plugins_url( 'assets/images/' . $file, BETTERSHIELD_FILE ),
				'mimeType' => $type,
				'sizes'    => array( $size ),
			);
		};

		return array(
			'name'       => 'bettershield',
			'title'      => 'BetterShield',
			'version'    => defined( 'BETTERSHIELD_VERSION' ) ? BETTERSHIELD_VERSION : '',
			'websiteUrl' => 'https://bettershield.ai',
			'icons'      => array(
				$icon( 'icon-256.png', 'image/png', '256x256' ),
				$icon( 'icon-512.png', 'image/png', '512x512' ),
				// The mark itself, which scales to whatever a card asks for.
				$icon( 'mark-light.svg', 'image/svg+xml', 'any' ),
			),
		);
	}

	/**
	 * Run a tool, record that it was run, and wrap whatever came back.
	 *
	 * A refusal comes back as a successful message carrying an error flag
	 * rather than as a transport failure, which is what lets the assistant
	 * read the reason and say it to the person instead of reporting that the
	 * site is down. A scope refusal is the case that most needs it: the
	 * assistant has to be able to tell somebody how to widen the connection.
	 *
	 * @param mixed                $id
	 * @param array<string, mixed> $params
	 * @return array<string, mixed>
	 */
	private static function call( $id, array $params, string $scope ): array {
		$name = isset( $params['name'] ) && is_scalar( $params['name'] ) ? (string) $params['name'] : '';

		if ( '' === $name ) {
			Audit::tool_called( '', '', null, 'failed', 'no_tool_named', $id );

			return self::error( $id, self::INVALID_PARAMS, __( 'No tool was named.', 'bettershield' ) );
		}

		/*
		 * The arguments are an object. A list, or anything else, used to run
		 * the tool as though `{}` had been sent: an answer to a question the
		 * caller did not ask. An empty list decodes as the empty object does,
		 * so it is let through as one.
		 */
		$arguments = $params['arguments'] ?? array();

		if ( ! is_array( $arguments ) || ( array() !== $arguments && array_keys( $arguments ) === range( 0, count( $arguments ) - 1 ) ) ) {
			Audit::tool_called( $name, Tools::ability_name( $name ), null, 'failed', 'arguments_not_object', $id );

			return self::error( $id, self::INVALID_PARAMS, __( 'The tool’s arguments must be an object.', 'bettershield' ) );
		}

		try {
			$result = Tools::invoke( $name, $arguments, $scope );
		} finally {
			// A call can change switches or registration before the next message in a batch.
			self::$catalogs = array();
		}

		if ( is_wp_error( $result ) ) {
			Audit::tool_called( $name, Tools::ability_name( $name ), $arguments, 'failed', (string) $result->get_error_code(), $id );

			return self::error_result( $id, $result->get_error_message() );
		}

		// Both halves of the answer in the JSON types the tool's schema names.
		$result  = Tools::shaped( $name, $result );
		$encoded = wp_json_encode( $result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );

		if ( ! is_string( $encoded ) ) {
			/*
			 * A non-finite float, a resource, a structure too deep to encode.
			 * None of this plugin's own abilities returns one today, and the
			 * answer if one ever does has to be a refusal: an empty success is
			 * the one answer nobody can act on, and a row beside it saying the
			 * call completed makes the log disagree with what the caller saw.
			 */
			Audit::tool_called( $name, Tools::ability_name( $name ), $arguments, 'failed', 'result_not_encodable', $id );

			return self::error_result( $id, __( 'That tool answered with something this server could not write as JSON, so there is no result to report.', 'bettershield' ) );
		}

		Audit::tool_called( $name, Tools::ability_name( $name ), $arguments, 'completed', '', $id );

		$payload = array(
			'content' => array(
				array(
					'type' => 'text',
					'text' => $encoded,
				),
			),
			'isError' => false,
		);

		/*
		 * The same answer in the shape the tool's own output schema describes,
		 * which is what a client validates against. The protocol's structured
		 * result is a JSON object and nothing else, so a list is carried by
		 * the text block alone.
		 */
		if ( $result instanceof \stdClass || ( is_array( $result ) && ! array_key_exists( 0, $result ) ) ) {
			$payload['structuredContent'] = array() === $result ? (object) array() : $result;
		}

		return self::result( $id, $payload );
	}

	/** The tool names this connection is offered: what resources and prompts stand on. */
	private static function offered( string $scope ): array {
		return array_column( self::catalog( $scope ), 'name' );
	}

	/**
	 * One resource, read by the tool its address names (#557).
	 *
	 * The tool is run as a call to it would be, through the same gates, and
	 * recorded the same way, so reading by address is not a way around
	 * anything a call would meet.
	 *
	 * @param mixed                $id
	 * @param array<string, mixed> $params
	 * @return array<string, mixed>
	 */
	private static function read( $id, array $params, string $scope ): array {
		$uri      = isset( $params['uri'] ) && is_string( $params['uri'] ) ? $params['uri'] : '';
		$resolved = Resources::resolve( $uri );

		if ( null === $resolved ) {
			return self::error(
				$id,
				self::RESOURCE_NOT_FOUND,
				/* translators: %s: the resource address that was asked for. */
				sprintf( __( 'There is no resource at %s here.', 'bettershield' ), '' === $uri ? __( '(no address)', 'bettershield' ) : $uri ),
				array( 'uri' => $uri )
			);
		}

		$tool = $resolved['tool'];

		try {
			$result = Tools::invoke( $tool, $resolved['arguments'], $scope );
		} finally {
			self::$catalogs = array();
		}

		if ( is_wp_error( $result ) ) {
			Audit::tool_called( $tool, Tools::ability_name( $tool ), $resolved['arguments'], 'failed', (string) $result->get_error_code(), $id );

			return self::error( $id, self::read_error_code( $result ), $result->get_error_message(), array( 'uri' => $uri ) );
		}

		$encoded = wp_json_encode( Tools::shaped( $tool, $result ), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );

		if ( ! is_string( $encoded ) ) {
			Audit::tool_called( $tool, Tools::ability_name( $tool ), $resolved['arguments'], 'failed', 'result_not_encodable', $id );

			return self::error( $id, self::INTERNAL_ERROR, __( 'That resource answered with something this server could not write as JSON.', 'bettershield' ) );
		}

		Audit::tool_called( $tool, Tools::ability_name( $tool ), $resolved['arguments'], 'completed', '', $id );

		return self::result(
			$id,
			array(
				'contents' => array(
					array(
						'uri'      => $uri,
						'mimeType' => 'application/json',
						'text'     => $encoded,
					),
				),
			)
		);
	}

	/**
	 * The protocol's code for a tool's refusal of a resource read: what is
	 * not on record is not found, an argument the tool will not take is an
	 * invalid parameter, and every other refusal is a gate.
	 */
	private static function read_error_code( \WP_Error $error ): int {
		$data   = $error->get_error_data();
		$status = is_array( $data ) ? (int) ( $data['status'] ?? 0 ) : 0;

		if ( 404 === $status ) {
			return self::RESOURCE_NOT_FOUND;
		}

		if ( 400 === $status || 'ability_invalid_input' === $error->get_error_code() ) {
			return self::INVALID_PARAMS;
		}

		return self::UNAUTHORIZED;
	}

	/**
	 * A refusal a client can read and repeat to a person.
	 *
	 * A successful message carrying an error flag rather than a transport
	 * failure, so the assistant says the reason instead of reporting that the
	 * site is down.
	 *
	 * @param mixed $id
	 * @return array<string, mixed>
	 */
	private static function error_result( $id, string $message ): array {
		return self::result(
			$id,
			array(
				'content' => array(
					array(
						'type' => 'text',
						'text' => $message,
					),
				),
				'isError' => true,
			)
		);
	}

	/* ---- the door ------------------------------------------------------------- */

	/**
	 * Whether the credential is one of this site's, whose it is and how far it
	 * reaches.
	 *
	 * Two paths, one outcome: the request runs as the administrator who
	 * granted the credential with the scope it was granted, or it does not run.
	 *
	 * @return array{kind: string, id: string, scope: string, user_id: int}|null
	 */
	private static function authenticate( string $presented ): ?array {
		if ( '' === $presented ) {
			return null;
		}

		if ( Pairing::verify( $presented ) ) {
			$user_id = Pairing::user_id();

			if ( ! self::become( $user_id ) ) {
				return null;
			}

			$scope = Pairing::scope();

			Pairing::touch();

			return array(
				'kind'    => Audit::PAIRING,
				'id'      => Pairing::hint(),
				'scope'   => '' === $scope ? Scopes::READ_ONLY : $scope,
				'user_id' => $user_id,
			);
		}

		$grant = OAuth::validate_token( $presented );

		if ( null === $grant || ! self::become( (int) $grant['user_id'] ) ) {
			return null;
		}

		return array(
			'kind'    => Audit::APP,
			'id'      => (string) $grant['client_id'],
			'scope'   => (string) $grant['scope'],
			'user_id' => (int) $grant['user_id'],
		);
	}

	/** The scope of the credential this request arrived on, for the length of the request. */
	private static ?string $scope = null;

	/**
	 * The scope of the credential behind the current request, or null when
	 * the request did not come through this endpoint at all.
	 *
	 * What an ability asks when its answer depends on how far the caller was
	 * trusted: a plan proposed over a connection a person allowed to change
	 * the site comes back with its own confirmation; the same plan over a
	 * read-only connection is for the dashboard to allow.
	 */
	public static function current_scope(): ?string {
		return self::$scope;
	}

	/** Which credential this request arrived on, for the length of the request. */
	private static ?string $credential = null;

	/**
	 * The credential behind the current request, as its kind and id (an app's
	 * client id, or the pairing's hint), or null when the request did not
	 * come through this endpoint at all.
	 *
	 * What the hourly ceilings count by, so one connection's changes do not
	 * spend another's.
	 */
	public static function current_credential(): ?string {
		return self::$credential;
	}

	/**
	 * Run the rest of this request as the account that granted the credential.
	 *
	 * The capability is checked here rather than trusted from when the
	 * credential was minted: an account that has since been deleted, or had
	 * the capability taken away, takes its grants with it at that moment
	 * rather than at the next time somebody thinks to revoke them. So does an
	 * account whose name this site has since refused to let sign in.
	 */
	private static function become( int $user_id ): bool {
		if ( ! self::may_act_as( $user_id ) ) {
			return false;
		}

		wp_set_current_user( $user_id );

		// An assistant's calls are the requests a stalled schedule most needs
		// to be rescued from, and the account is only known from here on.
		\BetterShield\Cron\Runner::instance()->rescue_from_request();

		return true;
	}

	/**
	 * Whether calls may run as this account: one that still exists, may hold
	 * a credential, and whose name this site has not refused. The door asks
	 * on every call; the screen and the self-test ask the same, so neither
	 * can call healthy a credential the door refuses.
	 */
	public static function may_act_as( int $user_id ): bool {
		$user = $user_id > 0 ? get_userdata( $user_id ) : false;

		return $user instanceof \WP_User && Pairing::may_hold( $user ) && ! \BetterShield\Login\Protection::instance()->blocks_name( $user );
	}

	/**
	 * The header that tells a client where to read about this endpoint.
	 *
	 * The path-suffixed form, which belongs to this endpoint rather than to
	 * the site root, so a second plugin serving its own assistant endpoint
	 * here does not answer for ours.
	 */
	public static function challenge(): string {
		return sprintf( 'Bearer resource_metadata="%s"', OAuth::resource_metadata_url() );
	}

	/**
	 * The bearer credential, or an empty string when none was offered.
	 *
	 * The header and nothing else. A credential in a URL is a credential in
	 * the access log, in the proxy's log, in the browser's history and in the
	 * next request's `Referer`, and no configuration field is worth that.
	 */
	private static function bearer( \WP_REST_Request $request ): string {
		$header = $request->get_header( 'authorization' );

		if ( is_string( $header ) && 1 === preg_match( '/^Bearer\s+(.+)$/i', trim( $header ), $matched ) ) {
			return trim( $matched[1] );
		}

		return '';
	}

	/* ---- envelopes ------------------------------------------------------------ */

	/**
	 * @param mixed $id
	 * @param mixed $result
	 * @return array<string, mixed>
	 */
	private static function result( $id, $result ): array {
		return array(
			'jsonrpc' => '2.0',
			'id'      => $id,
			'result'  => $result,
		);
	}

	/**
	 * @param mixed                     $id
	 * @param array<string, mixed>|null $data What a program can read about the error beside its message.
	 * @return array<string, mixed>
	 */
	private static function error( $id, int $code, string $message, ?array $data = null ): array {
		$error = array(
			'code'    => $code,
			'message' => $message,
		);

		if ( null !== $data ) {
			$error['data'] = $data;
		}

		return array(
			'jsonrpc' => '2.0',
			'id'      => $id,
			'error'   => $error,
		);
	}

	/**
	 * @param array<string, mixed>|null $data What a program can read about the refusal beside its message.
	 */
	private static function refusal( int $code, string $message, int $status, ?array $data = null ): \WP_REST_Response {
		return new \WP_REST_Response( self::error( null, $code, $message, $data ), $status );
	}
}
