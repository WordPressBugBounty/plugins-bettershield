<?php
/**
 * The tool catalog, which is this plugin's abilities and nothing else.
 *
 * There is no hand-written list here. Every ability registered under this
 * plugin's namespace is one tool: its own schema is the tool's schema, its own
 * description is the tool's description and its own annotations are the tool's
 * annotations, so the catalog an assistant reads and the surface this plugin
 * actually offers cannot drift apart.
 *
 * Tool names may not contain a slash, so the namespace comes off:
 * `bettershield/get-security-posture` is the tool `get-security-posture`. The
 * mapping is reversible, which is what lets a call resolve back to exactly one
 * ability.
 *
 * **Read and write are decided by the declaration and by the registration,
 * never by the name.** An ability is a read tool when its own `readonly`
 * annotation says so and a write tool in every other case, the unannotated one
 * included; and on top of that, every ability the second opt-in registers is
 * behind the write scope whatever it annotates. Both halves are needed. The
 * annotation alone lets a plan through — a plan is truthfully read-only about
 * the site and still writes a row, spends an hourly allowance and puts an item
 * in front of the owner to allow, none of which a connection left read-only was
 * meant to reach. The registration list alone says nothing about an ability
 * another plugin adds through the filter, which the annotation answers. A
 * prefix rule answers neither: it reads the wrong answer off a tool that
 * computes something and then saves it.
 *
 * Nothing here decides permission. Each ability runs its own callback inside
 * `execute()`, under the administrator the credential was granted by, so an
 * assistant reaches precisely what that person reaches and no further. What
 * this file does add is a plain answer when a tool is absent because an opt-in
 * is off: an assistant told "no such tool" would report the site broken, and
 * the truth is that the owner has not turned that surface on.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Mcp;

use BetterShield\Abilities\Registrar;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Tools {

	/** The namespace every ability of ours carries, and every tool name loses. */
	public const PREFIX = 'bettershield/';

	/**
	 * The catalog a credential of this scope may call, in the shape a client
	 * expects.
	 *
	 * A read-only credential is not shown the tools it would be refused. The
	 * refusal exists anyway, because a client may hold a stale catalog, but a
	 * client that reads this list and offers the site owner a tool that cannot
	 * work is a worse experience than one that never offers it.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function catalog( string $scope = Scopes::READ_WRITE ): array {
		// A connection runs as its account, so a scope wider than that
		// account's reach offers nothing it cannot use.
		$writes = Scopes::allows_write( $scope ) && Registrar::can_write();
		// Asked once rather than per ability: a scope that may write is
		// refused nothing, so the list is only ever built to refuse with.
		$gated = $writes ? array() : Registrar::write_ability_names();
		$tools = array();

		// Asked once: whether this connection's account reads the network.
		// The release's manifest describes a site's own connection, without them.
		$network = ! \BetterShield\Abilities\ReadSurface::$describing_release && ( 0 === get_current_user_id() || \BetterShield\Abilities\ReadSurface::can_read_network() );

		foreach ( self::abilities() as $ability ) {
			if ( ! $writes && self::needs_write_scope( $ability, $gated ) ) {
				continue;
			}

			// A network read offered to a site's administrator could only
			// answer "does not have necessary permission" (#1825).
			if ( ! $network && in_array( $ability->get_name(), \BetterShield\Abilities\ReadSurface::NETWORK_READS, true ) ) {
				continue;
			}

			// A tool the owner unticked for this application (#1879).
			if ( AppTools::refuses( self::tool_name( $ability->get_name() ) ) ) {
				continue;
			}

			$schema = $ability->get_input_schema();

			$entry = array(
				'name'        => self::tool_name( $ability->get_name() ),
				'description' => (string) $ability->get_description(),
				'inputSchema' => is_array( $schema ) && array() !== $schema
					? self::as_objects( $schema )
					: array(
						'type'       => 'object',
						'properties' => (object) array(),
					),
			);

			// The other half of the declaration. The revision of the protocol
			// this server answers carries it, every ability here declares one,
			// and a catalog that drops it is a catalog that has drifted from
			// the surface it promises to be.
			$output = method_exists( $ability, 'get_output_schema' ) ? $ability->get_output_schema() : array();

			if ( is_array( $output ) && array() !== $output ) {
				$entry['outputSchema'] = self::as_objects( $output );
			}

			$entry['annotations'] = self::annotations_of( $ability );

			$tools[] = $entry;
		}

		return $tools;
	}

	/**
	 * The hash of the catalog a credential of this scope is served: what a
	 * client keeps beside the list it read, so it reads the list again only
	 * when the two differ. It moves when a tool is added, removed or renamed,
	 * when a description, schema or annotation changes, and when a switch
	 * changes what this scope is offered, and for nothing else.
	 *
	 * @param array<int, array<string, mixed>>|null $catalog The list this request already built for the scope, or null to build it.
	 */
	public static function catalog_hash( string $scope = Scopes::READ_WRITE, ?array $catalog = null ): string {
		return self::digest_of( null === $catalog ? self::catalog( $scope ) : $catalog );
	}

	/**
	 * The hash of a list of tools, computed from the list as JSON so a client
	 * can recompute it from the list it was served: the tools in name order,
	 * every object's keys in byte order, encoded with slashes and Unicode left
	 * unescaped, as SHA-256 written `sha256:` and hex.
	 *
	 * @param array<int, mixed> $tools Tool entries, as arrays or as decoded objects.
	 */
	public static function digest_of( array $tools ): string {
		$name = static function ( $tool ): string {
			if ( is_array( $tool ) ) {
				return (string) ( $tool['name'] ?? '' );
			}

			return is_object( $tool ) && isset( $tool->name ) ? (string) $tool->name : '';
		};

		usort(
			$tools,
			static function ( $a, $b ) use ( $name ): int {
				return strcmp( $name( $a ), $name( $b ) );
			}
		);

		return 'sha256:' . hash( 'sha256', (string) wp_json_encode( self::canonical( $tools ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) );
	}

	/**
	 * A value with every object's keys in byte order, all the way down. A list
	 * keeps its order, and an object stays an object even when it is empty, so
	 * the JSON is the same whichever way the value was built.
	 *
	 * @param mixed $value
	 * @return mixed
	 */
	private static function canonical( $value ) {
		$walk = static function ( $inner ) {
			return self::canonical( $inner );
		};

		if ( $value instanceof \stdClass ) {
			$fields = get_object_vars( $value );
			ksort( $fields, SORT_STRING );

			return (object) array_map( $walk, $fields );
		}

		if ( ! is_array( $value ) ) {
			return $value;
		}

		if ( array() !== $value && array_keys( $value ) !== range( 0, count( $value ) - 1 ) ) {
			ksort( $value, SORT_STRING );
		}

		return array_map( $walk, $value );
	}

	/**
	 * Run one tool, if this scope may.
	 *
	 * @param array<string, mixed> $arguments Decoded arguments.
	 * @return mixed|\WP_Error
	 */
	public static function invoke( string $name, array $arguments, string $scope = Scopes::READ_WRITE ) {
		if ( ! Registrar::is_available() || ! function_exists( 'wp_has_ability' ) || ! function_exists( 'wp_get_ability' ) ) {
			return new \WP_Error(
				'bettershield_mcp_no_runtime',
				__( 'This site cannot offer tools: the abilities runtime this plugin needs is not loaded.', 'bettershield' ),
				array( 'status' => 500 )
			);
		}

		$ability = self::PREFIX . $name;

		// Asked about before it is asked for: fetching an ability that is not
		// registered is a misuse notice in core, and a tool name is chosen by
		// whoever is calling — so a client with a stale catalog would write
		// into this site's error log once per call.
		if ( ! wp_has_ability( $ability ) ) {
			return self::absent( $name );
		}

		$resolved = wp_get_ability( $ability );

		if ( ! $resolved ) {
			return self::absent( $name );
		}

		// Asked first: the owner said no to this tool for this application,
		// whatever its scope would allow (#1879).
		if ( AppTools::refuses( $name ) ) {
			return new \WP_Error(
				AppTools::REFUSAL,
				sprintf(
					/* translators: %s: the tool name that was asked for. */
					__( 'The site owner has not allowed this app to use %s. They can allow it under Agents › Connect.', 'bettershield' ),
					$name
				),
				array( 'status' => 403 )
			);
		}

		$changes = self::needs_write_scope( $resolved, Registrar::write_ability_names() );

		if ( $changes && Scopes::allows_write( $scope ) && ! Registrar::can_write() ) {
			return new \WP_Error(
				'bettershield_mcp_account_cannot_write',
				sprintf(
					/* translators: %s: the tool name that was asked for. */
					__( 'The account this connection runs as may not change this site through an agent, so %s is out of its reach. An administrator can connect instead.', 'bettershield' ),
					$name
				),
				array( 'status' => 403 )
			);
		}

		if ( ! Scopes::allows_write( $scope ) && $changes ) {
			return new \WP_Error(
				'bettershield_mcp_out_of_scope',
				sprintf(
					/* translators: %s: the tool name that was asked for. */
					__( 'This connection may read this site and not change it, so %s is out of its reach. To allow changes, replace the connection token and choose to allow changes, or connect the application again and allow changes when this site asks.', 'bettershield' ),
					$name
				),
				array( 'status' => 403 )
			);
		}

		return $resolved->execute( $arguments );
	}

	/**
	 * A tool's answer written in the JSON types its output schema names.
	 *
	 * PHP has one array for a list and for a map, so an empty map encodes as
	 * `[]`. A client validating the structured answer against the schema
	 * reads that as the wrong type and refuses the whole answer: a plan for
	 * an item that takes no options came back with `"options": []` where an
	 * object is declared. Walked by the schema, so every field it calls an
	 * object is written as one, at any depth, and nothing else changes.
	 *
	 * @param mixed $result
	 * @return mixed
	 */
	public static function shaped( string $name, $result ) {
		$ability = function_exists( 'wp_has_ability' ) && wp_has_ability( self::PREFIX . $name ) ? wp_get_ability( self::PREFIX . $name ) : null;
		$schema  = $ability && method_exists( $ability, 'get_output_schema' ) ? $ability->get_output_schema() : array();

		return is_array( $schema ) && array() !== $schema ? self::to_shape( $result, $schema ) : $result;
	}

	/**
	 * @param mixed                $value
	 * @param array<string, mixed> $schema
	 * @return mixed
	 */
	private static function to_shape( $value, array $schema ) {
		if ( ! is_array( $value ) ) {
			return $value;
		}

		$types = (array) ( $schema['type'] ?? array() );
		$list  = array() === $value || array_keys( $value ) === range( 0, count( $value ) - 1 );

		if ( $list && in_array( 'array', $types, true ) ) {
			$items = isset( $schema['items'] ) && is_array( $schema['items'] ) ? $schema['items'] : array();

			return array() === $items ? $value : array_map(
				static function ( $item ) use ( $items ) {
					return self::to_shape( $item, $items );
				},
				$value
			);
		}

		if ( ! in_array( 'object', $types, true ) ) {
			return $value;
		}

		if ( array() === $value ) {
			return (object) array();
		}

		$properties = isset( $schema['properties'] ) && is_array( $schema['properties'] ) ? $schema['properties'] : array();

		foreach ( $value as $key => $field ) {
			if ( isset( $properties[ $key ] ) && is_array( $properties[ $key ] ) ) {
				$value[ $key ] = self::to_shape( $field, $properties[ $key ] );
			}
		}

		return $value;
	}

	/**
	 * Whether this scope has to carry write for that tool to be reachable.
	 *
	 * Two questions, and the smaller scope is refused on either. The first is
	 * the ability's own `readonly` declaration. The second is whether it is one
	 * of the abilities the write opt-in registers: those are the write
	 * workflow, and preparing a plan belongs to it however truthfully the plan
	 * declares that it changes nothing about the site. A plan writes a
	 * proposal row, takes a slot out of the hour's allowance, and lands in the
	 * owner's queue as a change to allow — so a connection whose owner chose
	 * "look, do not touch" neither sees one nor gets one.
	 *
	 * @param mixed    $ability
	 * @param string[] $gated The abilities the second opt-in registers.
	 */
	private static function needs_write_scope( $ability, array $gated ): bool {
		if ( ! self::is_read_tool( $ability ) ) {
			return true;
		}

		$name = is_object( $ability ) && method_exists( $ability, 'get_name' ) ? (string) $ability->get_name() : '';

		return '' !== $name && in_array( $name, $gated, true );
	}

	/**
	 * Whether a tool changes anything, as its own ability declares it.
	 *
	 * The only question asked is whether `readonly` is exactly true. A missing
	 * annotation, a null, a string: all of them are a write tool. Core's
	 * annotation defaults are null rather than false, so an ability nobody
	 * annotated arrives here indistinguishable from one nobody thought about,
	 * and both belong behind the larger scope.
	 *
	 * @param mixed $ability
	 */
	public static function is_read_tool( $ability ): bool {
		return true === ( self::annotation_meta( $ability )['readonly'] ?? null );
	}

	/**
	 * The hints the protocol carries, from the ability's own declaration.
	 *
	 * They are hints. The specification tells clients not to trust them and
	 * this server does not enforce anything with them — the permission callback
	 * and the scope above are the gates. What they are for is the sentence a
	 * client shows a person before it calls something.
	 *
	 * @param mixed $ability
	 * @return array<string, mixed>
	 */
	private static function annotations_of( $ability ): array {
		$declared = self::annotation_meta( $ability );
		$readonly = self::is_read_tool( $ability );

		$annotations = array();

		$label = is_object( $ability ) && method_exists( $ability, 'get_label' ) ? (string) $ability->get_label() : '';

		if ( '' !== $label ) {
			$annotations['title'] = $label;
		}

		$annotations['readOnlyHint'] = $readonly;

		// The protocol's own default for both of these is the cautious one, and
		// an undeclared annotation is answered with it rather than with a
		// promise the ability never made.
		$annotations['destructiveHint'] = isset( $declared['destructive'] ) && null !== $declared['destructive']
			? (bool) $declared['destructive']
			: ! $readonly;

		$annotations['idempotentHint'] = isset( $declared['idempotent'] ) && null !== $declared['idempotent']
			? (bool) $declared['idempotent']
			: false;

		return $annotations;
	}

	/**
	 * The declared annotations, however this runtime exposes them.
	 *
	 * @param mixed $ability
	 * @return array<string, mixed>
	 */
	private static function annotation_meta( $ability ): array {
		if ( ! is_object( $ability ) || ! method_exists( $ability, 'get_meta_item' ) ) {
			return array();
		}

		$annotations = $ability->get_meta_item( 'annotations', array() );

		return is_array( $annotations ) ? $annotations : array();
	}

	/**
	 * Why a tool is not there, said in terms of the switch that governs it.
	 *
	 * The write list here answers a different question from the scope gate
	 * above: an ability that is not registered has no annotation to read, so
	 * the only way to say "that one is behind the second opt-in" is to ask the
	 * registrar what it would have registered.
	 */
	private static function absent( string $name ): \WP_Error {
		if ( ! Registrar::is_enabled() ) {
			return new \WP_Error(
				'bettershield_mcp_reads_off',
				__( 'Agent access to this site is turned off, so no tool is offered. An administrator turns it on under Agents.', 'bettershield' ),
				array( 'status' => 403 )
			);
		}

		if ( in_array( $name, self::write_tool_names(), true ) && ! Registrar::write_enabled() ) {
			return new \WP_Error(
				'bettershield_mcp_writes_off',
				__( 'Changing this site through an agent is turned off, so this tool is not offered. An administrator turns it on under Agents.', 'bettershield' ),
				array( 'status' => 403 )
			);
		}

		return new \WP_Error(
			'bettershield_mcp_unknown_tool',
			sprintf(
				/* translators: %s: the tool name that was asked for. */
				__( 'There is no tool called %s here.', 'bettershield' ),
				$name
			),
			array( 'status' => 404 )
		);
	}

	/**
	 * The tool names that exist only behind the second opt-in.
	 *
	 * @return string[]
	 */
	private static function write_tool_names(): array {
		return array_map(
			static function ( string $ability ): string {
				return self::tool_name( $ability );
			},
			Registrar::write_ability_names()
		);
	}

	/**
	 * Every registered ability of ours.
	 *
	 * @return array<int, \WP_Ability>
	 */
	private static function abilities(): array {
		if ( ! function_exists( 'wp_get_abilities' ) ) {
			return array();
		}

		$ours = array();

		foreach ( wp_get_abilities() as $ability ) {
			if ( ! is_object( $ability ) || ! method_exists( $ability, 'get_name' ) ) {
				continue;
			}

			if ( 0 === strpos( (string) $ability->get_name(), self::PREFIX ) ) {
				$ours[] = $ability;
			}
		}

		return $ours;
	}

	/** An ability name as a tool name. */
	private static function tool_name( string $ability ): string {
		return 0 === strpos( $ability, self::PREFIX )
			? substr( $ability, strlen( self::PREFIX ) )
			: str_replace( '/', '-', $ability );
	}

	/** A tool name as the ability it resolves to. */
	public static function ability_name( string $tool ): string {
		return self::PREFIX . $tool;
	}

	/**
	 * An empty `properties` written as an object rather than an array.
	 *
	 * A schema with no properties encodes as `[]` from PHP, and a client
	 * validating against the specification reads that as the wrong type and
	 * refuses the whole catalog. Nested schemas are walked first, so a
	 * field-less object inside one is fixed too.
	 *
	 * @param array<string, mixed> $schema
	 * @return array<string, mixed>
	 */
	private static function as_objects( array $schema ): array {
		foreach ( $schema as $key => $value ) {
			if ( is_array( $value ) ) {
				$schema[ $key ] = self::as_objects( $value );
			}
		}

		if ( isset( $schema['properties'] ) && array() === $schema['properties'] ) {
			$schema['properties'] = (object) array();
		}

		return $schema;
	}
}
