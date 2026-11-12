<?php
/**
 * Scripts on a store that may be reading card details.
 *
 * Card-stealing code is often put where no file changes: a Custom HTML widget,
 * a block theme's footer template, a snippet plugin's saved code, or the
 * checkout page itself. The file check can't see any of those, so this reads
 * them, as text, and asks the named signs of compromise (`CompromiseSigns`)
 * about each script it finds.
 *
 * What it looks at is what a script does, never whether it is new, so turning
 * something on or off, updating a plugin, switching a theme or editing a page
 * can't set it off, and a tracking tag someone pasted isn't its business. Four
 * rules keep it quiet:
 *
 * - **Stores only.** Card details pass through a store's checkout. Elsewhere
 *   it reads nothing.
 * - **One flag and one alert per script.** A flagged script is told once, by
 *   its own row. Accept stores its hash, and it stays quiet until it changes.
 * - **Never "all clear".** With nothing to say it says nothing: a short list
 *   of tests can't promise a store is clean.
 * - **Nothing is run or fetched.** A script loaded from a file on this site is
 *   read from disk, inside the install, with a size cap. One loaded from
 *   another site is never fetched or flagged. Its host is only noted, and a
 *   host first seen after the first sweep is written as a row an open incident
 *   can take as evidence. That row opens nothing and sends nothing.
 *
 * It reads every post and option, so it runs in chunks from the scheduler
 * with a wall-clock budget, never on a page view, and a sweep's answer only
 * replaces the last one when the sweep is complete.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Audit;

use BetterShield\Events\Writer;
use BetterShield\Support\Text;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class StoreScripts {

	/** The finding. */
	public const CHECK = 'store_script_reads_cards';

	/** The scheduled sweep. */
	public const TASK = 'bettershield_store_scripts';

	/** What the last sweep found, where a sweep got to, what was accepted. */
	public const OPTION = 'bettershield_store_scripts';

	/** How long one tick may read for. */
	private const BUDGET_SECONDS = 8.0;

	/** Rows read per query. */
	private const CHUNK = 100;

	/** A complete sweep stands this long before the next one starts. */
	private const SWEEP_EVERY = DAY_IN_SECONDS;

	/** The largest text read from one row or file. */
	private const MAX_BYTES = 1048576;

	/** The most flagged scripts kept and listed. */
	public const MAX_LISTED = 50;

	/** The most hosts remembered. */
	private const MAX_HOSTS = 500;

	/** The most accepted scripts remembered. */
	private const MAX_ACCEPTED = 200;

	/** Widgets that print what the owner typed. */
	private const PRINTING_OPTIONS = array( 'widget_block', 'widget_custom_html', 'widget_text' );

	/** Options that hold a snippet plugin's code. */
	private const SNIPPET_OPTIONS = array( 'dnsp_settings' );

	/** Post types a block theme prints its header and footer from. */
	private const TEMPLATE_TYPES = array( 'wp_template', 'wp_template_part' );

	/** A snippet plugin's post type, published when its code runs. */
	private const SNIPPET_TYPE = 'wpcode';

	/** The sweep's phases, in order. */
	private const PHASES = array( 'options', 'posts', 'snippets' );

	/**
	 * Whether this site is a store.
	 *
	 * WooCommerce itself, not the cart and checkout tags: a theme can define
	 * those, and only a real store takes card details.
	 */
	public static function applies(): bool {
		return class_exists( 'WooCommerce' ) || did_action( 'woocommerce_init' ) > 0;
	}

	/**
	 * The scheduled tick: read on from where the last one stopped.
	 */
	public static function run(): void {
		if ( ! self::applies() ) {
			return;
		}

		$state = self::state_raw();

		// A complete sweep stands for a day.
		if ( null === $state['sweep'] && $state['done_at'] > 0 && time() - $state['done_at'] < self::SWEEP_EVERY ) {
			return;
		}

		if ( null === $state['sweep'] ) {
			$state['sweep'] = array(
				'phase' => 0,
				'after' => 0,
				'flags' => array(),
				'hosts' => array(),
			);
		}

		$until = microtime( true ) + self::BUDGET_SECONDS;
		$found = null;

		while ( null !== $state['sweep'] && microtime( true ) < $until ) {
			$phase = self::PHASES[ $state['sweep']['phase'] ] ?? null;

			if ( null === $phase ) {
				$found = (array) $state['sweep']['flags'];
				$state = self::finish( $state );
				break;
			}

			$rows = self::read( $phase, (int) $state['sweep']['after'] );

			if ( array() === $rows ) {
				++$state['sweep']['phase'];
				$state['sweep']['after'] = 0;
				continue;
			}

			foreach ( $rows as $row ) {
				$state['sweep'] = self::look( $state['sweep'], $row );
				$state['sweep']['after'] = (int) $row['id'];
			}
		}

		// An Accept or Flag It Again pressed while this tick read stands:
		// the owner's choices are read again now, not kept from the start.
		$fresh             = self::state_raw();
		$state['accepted'] = $fresh['accepted'];
		$state['flags']    = null === $found ? $fresh['flags'] : array_diff_key( $found, $fresh['accepted'] );

		unset( $state['accepted_hashes'] );
		update_option( self::OPTION, $state, false );
	}

	/**
	 * Read one chunk of a phase, after the given id.
	 *
	 * @return array<int, array{id: int, place: string, where: string, text: string, tests: string[], raw: bool}>
	 */
	private static function read( string $phase, int $after ): array {
		global $wpdb;

		$rows = array();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- a resumable sweep of the site's own rows from the scheduler, read once in chunks.
		if ( 'options' === $phase ) {
			$named = array_merge( self::PRINTING_OPTIONS, self::SNIPPET_OPTIONS );
			$found = $wpdb->get_results(
				$wpdb->prepare(
					'SELECT option_id, option_name, option_value FROM %i WHERE option_id > %d AND option_name NOT LIKE %s AND option_name NOT LIKE %s AND option_name NOT LIKE %s AND ( option_value LIKE %s OR option_name IN (' . implode( ',', array_fill( 0, count( $named ), '%s' ) ) . ') ) ORDER BY option_id LIMIT %d',
					array_merge(
						array( $wpdb->options, $after, $wpdb->esc_like( '_transient' ) . '%', $wpdb->esc_like( '_site_transient' ) . '%', $wpdb->esc_like( 'bettershield' ) . '%', '%' . $wpdb->esc_like( '<script' ) . '%' ),
						$named,
						array( self::CHUNK )
					)
				),
				ARRAY_A
			);

			foreach ( (array) $found as $option ) {
				$name    = (string) $option['option_name'];
				$snippet = in_array( $name, self::SNIPPET_OPTIONS, true );

				// One row per widget, named as the Widgets screen names it, so
				// the owner can tell which widget to open.
				if ( in_array( $name, self::PRINTING_OPTIONS, true ) ) {
					foreach ( self::widgets( $name, (string) $option['option_value'] ) as $widget ) {
						$rows[] = array(
							'id'    => (int) $option['option_id'],
							'place' => 'option:' . $name,
							'where' => 'widget',
							'label' => Text::clip( $widget['label'], 191 ),
							'text'  => $widget['text'],
							'tests' => CompromiseSigns::SCRIPT_WHERE_IT_RUNS,
							'raw'   => false,
						);
					}

					continue;
				}

				$rows[] = array(
					'id'    => (int) $option['option_id'],
					'place' => 'option:' . $name,
					'where' => $snippet ? 'snippet' : 'option',
					'label' => Text::clip( $name, 191 ),
					'text'  => (string) $option['option_value'],
					'tests' => $snippet ? CompromiseSigns::SCRIPT_WHERE_IT_RUNS : CompromiseSigns::SCRIPT,
					'raw'   => $snippet,
				);
			}
		} elseif ( 'posts' === $phase ) {
			$pages = array_values( array_filter( array( (int) get_option( 'woocommerce_checkout_page_id' ), (int) get_option( 'woocommerce_cart_page_id' ) ) ) );
			$pages = array() === $pages ? array( 0 ) : $pages;
			$found = $wpdb->get_results(
				$wpdb->prepare(
					'SELECT ID, post_type, post_title, post_name, post_status, post_content FROM %i WHERE ID > %d AND post_status IN (%s, %s, %s) AND ( post_content LIKE %s OR post_type IN (%s, %s, %s) OR ID IN (' . implode( ',', array_fill( 0, count( $pages ), '%d' ) ) . ') ) ORDER BY ID LIMIT %d',
					array_merge(
						array( $wpdb->posts, $after, 'publish', 'private', 'future', '%' . $wpdb->esc_like( '<script' ) . '%', self::TEMPLATE_TYPES[0], self::TEMPLATE_TYPES[1], self::SNIPPET_TYPE ),
						$pages,
						array( self::CHUNK )
					)
				),
				ARRAY_A
			);

			foreach ( (array) $found as $post ) {
				$type     = (string) $post['post_type'];
				$snippet  = self::SNIPPET_TYPE === $type;
				$template = in_array( $type, self::TEMPLATE_TYPES, true );
				$page     = in_array( (int) $post['ID'], $pages, true );

				// A snippet only runs while it is published.
				if ( $snippet && 'publish' !== $post['post_status'] ) {
					continue;
				}

				$rows[] = array(
					'id'    => (int) $post['ID'],
					'place' => 'post:' . (int) $post['ID'],
					'where' => $snippet ? 'snippet' : ( $template ? 'template' : ( $page ? 'checkout_page' : 'post' ) ),
					'label' => Text::clip( '' !== (string) $post['post_title'] ? (string) $post['post_title'] : (string) $post['post_name'], 191 ),
					'text'  => (string) $post['post_content'],
					'tests' => $snippet || $template || $page ? CompromiseSigns::SCRIPT_WHERE_IT_RUNS : CompromiseSigns::SCRIPT,
					'raw'   => $snippet,
				);
			}
		} else {
			// A snippet plugin's own table. Missing on most sites, so a
			// refused read is an empty phase, not an error to report.
			$suppressed = $wpdb->suppress_errors( true );
			$found      = $wpdb->get_results(
				$wpdb->prepare( 'SELECT id, name, code FROM %i WHERE id > %d AND active = 1 ORDER BY id LIMIT %d', $wpdb->prefix . 'snippets', $after, self::CHUNK ),
				ARRAY_A
			);
			$wpdb->suppress_errors( $suppressed );

			foreach ( (array) $found as $snippet ) {
				$rows[] = array(
					'id'    => (int) $snippet['id'],
					'place' => 'snippets:' . (int) $snippet['id'],
					'where' => 'snippet',
					'label' => Text::clip( (string) $snippet['name'], 191 ),
					'text'  => (string) $snippet['code'],
					'tests' => CompromiseSigns::SCRIPT_WHERE_IT_RUNS,
					'raw'   => true,
				);
			}
		}
		// phpcs:enable

		return $rows;
	}

	/**
	 * Ask the tests about one row's scripts, and note the hosts it loads from.
	 *
	 * @param array<string, mixed> $sweep
	 * @param array<string, mixed> $row
	 * @return array<string, mixed>
	 */
	private static function look( array $sweep, array $row ): array {
		$text = substr( (string) $row['text'], 0, self::MAX_BYTES );
		// Scripts kept inside JSON or a block's attributes escape the slash.
		$text = str_replace( '<\/script', '</script', $text );

		$scripts = array();

		// A snippet's code runs as it is, with or without script tags; PHP
		// tests only make sense there.
		if ( ! empty( $row['raw'] ) ) {
			$scripts[] = array(
				'text'  => $text,
				'tests' => array_merge( (array) $row['tests'], CompromiseSigns::PHP ),
				'file'  => '',
			);
		}

		if ( preg_match_all( '/<script\b([^>]*)>(.*?)<\/script\s*>/is', $text, $found, PREG_SET_ORDER ) ) {
			foreach ( $found as $script ) {
				$src = self::src( (string) $script[1] );

				if ( '' !== trim( (string) $script[2] ) && empty( $row['raw'] ) ) {
					$scripts[] = array(
						'text'  => (string) $script[2],
						'tests' => (array) $row['tests'],
						'file'  => '',
					);
				}

				if ( '' === $src ) {
					continue;
				}

				$file = self::local_file( $src );

				if ( null !== $file ) {
					$read = self::read_file( $file );

					if ( '' !== $read ) {
						// A file on this site is held to the tests that hold
						// anywhere: plugins' own files name card fields.
						$scripts[] = array(
							'text'  => $read,
							'tests' => CompromiseSigns::SCRIPT,
							'file'  => $file,
						);
					}
				} else {
					$host = strtolower( (string) wp_parse_url( $src, PHP_URL_HOST ) );

					if ( '' !== $host && ! isset( $sweep['hosts'][ $host ] ) && count( $sweep['hosts'] ) < self::MAX_HOSTS ) {
						$sweep['hosts'][ $host ] = 1;
					}
				}
			}
		}

		foreach ( $scripts as $script ) {
			$matched = CompromiseSigns::match( (string) $script['text'], (array) $script['tests'] );

			if ( array() === $matched ) {
				continue;
			}

			$hash = hash( 'sha256', (string) $script['text'] );

			if ( isset( $sweep['flags'][ $hash ] ) || count( $sweep['flags'] ) >= self::MAX_LISTED ) {
				continue;
			}

			$sweep['flags'][ $hash ] = array(
				'hash'  => $hash,
				'place' => Text::clip( (string) $row['place'], 255 ),
				'where' => (string) $row['where'],
				'label' => (string) $row['label'],
				'file'  => '' !== $script['file'] ? Text::clip( self::relative( (string) $script['file'] ), 255 ) : '',
				'tests' => array_column( $matched, 'test' ),
				'line'  => (int) $matched[0]['line'],
			);
		}

		return $sweep;
	}

	/**
	 * A sweep is complete: its answer replaces the last one, each newly
	 * flagged script is told once, and a host first seen now is noted.
	 *
	 * @param array<string, mixed> $state
	 * @return array<string, mixed>
	 */
	private static function finish( array $state ): array {
		$sweep  = (array) $state['sweep'];
		$before = (array) $state['flags'];
		$flags  = array_diff_key( (array) $sweep['flags'], array_flip( (array) $state['accepted_hashes'] ) );

		foreach ( $flags as $hash => $flag ) {
			if ( isset( $before[ $hash ] ) ) {
				continue;
			}

			Writer::instance()->record(
				'store_script_flagged',
				Writer::SEVERITY_HIGH,
				array(
					'actor_type'  => 'system',
					'object_type' => 'script',
					'object_id'   => Text::clip( (string) $hash, 16 ),
					'context'     => array(
						'where' => $flag['where'],
						'label' => $flag['label'],
						'file'  => $flag['file'],
						'tests' => $flag['tests'],
						'line'  => $flag['line'],
					),
				)
			);
		}

		// The first sweep learns the hosts. After it, a new one is noted.
		$known = (array) $state['hosts'];

		if ( $state['sweeps'] > 0 ) {
			foreach ( array_keys( (array) $sweep['hosts'] ) as $host ) {
				if ( isset( $known[ $host ] ) ) {
					continue;
				}

				Writer::instance()->record(
					'store_script_host_added',
					Writer::SEVERITY_INFO,
					array(
						'actor_type'  => 'system',
						'object_type' => 'host',
						'object_id'   => Text::clip( (string) $host, 191 ),
						'context'     => array( 'host' => Text::clip( (string) $host, 191 ) ),
					)
				);
			}
		}

		foreach ( array_keys( (array) $sweep['hosts'] ) as $host ) {
			if ( ! isset( $known[ $host ] ) && count( $known ) < self::MAX_HOSTS ) {
				$known[ $host ] = time();
			}
		}

		$state['flags']   = $flags;
		$state['hosts']   = $known;
		$state['sweep']   = null;
		$state['done_at'] = time();
		++$state['sweeps'];

		return $state;
	}

	/**
	 * Each widget a printing widget option holds: what it prints, and the
	 * name the Widgets screen shows for it.
	 *
	 * @return array<int, array{label: string, text: string}>
	 */
	private static function widgets( string $option, string $value ): array {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_unserialize -- the option's own stored array, read with no objects allowed.
		$stored = is_serialized( $value ) ? @unserialize( $value, array( 'allowed_classes' => false ) ) : null; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a damaged option is read as text below.

		// Unreadable as widgets: read it as one piece of text, as before.
		if ( ! is_array( $stored ) ) {
			return array(
				array(
					'label' => $option,
					'text'  => $value,
				),
			);
		}

		$type = array(
			'widget_block'       => __( 'Block', 'bettershield' ),
			'widget_custom_html' => __( 'Custom HTML', 'bettershield' ),
			'widget_text'        => __( 'Text', 'bettershield' ),
		)[ $option ] ?? $option;

		$widgets = array();

		foreach ( $stored as $number => $widget ) {
			if ( ! is_int( $number ) || ! is_array( $widget ) ) {
				continue;
			}

			$text  = (string) ( $widget['content'] ?? $widget['text'] ?? '' );
			$title = trim( wp_strip_all_tags( (string) ( $widget['title'] ?? '' ) ) );

			if ( '' === $text ) {
				continue;
			}

			$widgets[] = array(
				/* translators: 1: a widget's type, such as Custom HTML; 2: its title. */
				'label' => '' !== $title ? sprintf( __( '%1$s “%2$s”', 'bettershield' ), $type, $title ) : sprintf(
					/* translators: 1: a widget's type, such as Custom HTML; 2: its number among widgets of that type. */
					__( '%1$s #%2$d, with no title', 'bettershield' ),
					$type,
					$number
				),
				'text'  => $text,
			);
		}

		return $widgets;
	}

	/** The address a script tag loads, or an empty string. */
	private static function src( string $attributes ): string {
		return preg_match( '/\bsrc\s*=\s*(["\']?)([^"\'\s>]+)\1/i', $attributes, $m ) ? html_entity_decode( (string) $m[2], ENT_QUOTES ) : '';
	}

	/**
	 * The file on this site a script address names, inside the install, or
	 * null when it names another site or nothing readable.
	 */
	private static function local_file( string $src ): ?string {
		$src  = str_starts_with( $src, '//' ) ? 'https:' . $src : $src;
		$host = wp_parse_url( $src, PHP_URL_HOST );
		$path = (string) wp_parse_url( $src, PHP_URL_PATH );

		if ( null !== $host ) {
			$ours = array_filter( array( wp_parse_url( home_url(), PHP_URL_HOST ), wp_parse_url( site_url(), PHP_URL_HOST ) ) );

			if ( ! in_array( strtolower( (string) $host ), array_map( 'strtolower', $ours ), true ) ) {
				return null;
			}
		}

		if ( ! preg_match( '/\.js\z/i', $path ) ) {
			return null;
		}

		// The address's path from the site's own root.
		$root = (string) wp_parse_url( site_url(), PHP_URL_PATH );
		$path = '' !== $root && str_starts_with( $path, untrailingslashit( $root ) . '/' ) ? substr( $path, strlen( untrailingslashit( $root ) ) ) : $path;
		$real = realpath( ABSPATH . ltrim( rawurldecode( $path ), '/' ) );
		$base = realpath( ABSPATH );

		if ( false === $real || false === $base || ! str_starts_with( $real, trailingslashit( $base ) ) || ! is_file( $real ) ) {
			return null;
		}

		return $real;
	}

	/** A local script's text, or an empty string when it is too big or unreadable. */
	private static function read_file( string $file ): string {
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a file removed since the page named it is an ordinary miss, answered below.
		$size = @filesize( $file );

		if ( false === $size || $size > self::MAX_BYTES ) {
			return '';
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- a local file inside the install, read as text up to the cap; a miss is answered below.
		$text = @file_get_contents( $file, false, null, 0, self::MAX_BYTES );

		return is_string( $text ) ? $text : '';
	}

	/** A path from the install's root. */
	private static function relative( string $file ): string {
		$base = trailingslashit( (string) realpath( ABSPATH ) );

		return str_starts_with( $file, $base ) ? substr( $file, strlen( $base ) ) : basename( $file );
	}

	/**
	 * What is stored, with every key present.
	 *
	 * @return array{flags: array<string, array<string, mixed>>, accepted: array<string, array<string, mixed>>, accepted_hashes: string[], hosts: array<string, int>, sweep: ?array<string, mixed>, sweeps: int, done_at: int}
	 */
	private static function state_raw(): array {
		$state    = get_option( self::OPTION, array() );
		$state    = is_array( $state ) ? $state : array();
		$accepted = isset( $state['accepted'] ) && is_array( $state['accepted'] ) ? $state['accepted'] : array();

		return array(
			'flags'           => isset( $state['flags'] ) && is_array( $state['flags'] ) ? $state['flags'] : array(),
			'accepted'        => $accepted,
			'accepted_hashes' => array_keys( $accepted ),
			'hosts'           => isset( $state['hosts'] ) && is_array( $state['hosts'] ) ? $state['hosts'] : array(),
			'sweep'           => isset( $state['sweep'] ) && is_array( $state['sweep'] ) ? $state['sweep'] : null,
			'sweeps'          => (int) ( $state['sweeps'] ?? 0 ),
			'done_at'         => (int) ( $state['done_at'] ?? 0 ),
		);
	}

	/**
	 * The audit's answer: the scripts flagged by the last complete sweep and
	 * not accepted, or null. Null too before a sweep has finished, and on a
	 * site that isn't a store: there is nothing to say, never "all clear".
	 *
	 * @return array<string, mixed>|null
	 */
	public static function evidence(): ?array {
		if ( ! self::applies() ) {
			return null;
		}

		$state = self::state_raw();
		$flags = array_values( array_diff_key( $state['flags'], array_flip( $state['accepted_hashes'] ) ) );

		if ( array() === $flags ) {
			return null;
		}

		return array(
			'scripts' => array_map( array( self::class, 'described' ), $flags ),
			'total'   => count( $flags ),
		);
	}

	/**
	 * One flagged script in a sentence, for the evidence: where it is and
	 * what it was seen doing. Never its text.
	 *
	 * @param array<string, mixed> $flag
	 */
	public static function described( array $flag ): string {
		$label = (string) $flag['label'];

		switch ( (string) $flag['where'] ) {
			case 'widget':
				/* translators: %s: a widget's type and title, such as Custom HTML “Offers”. */
				$place = sprintf( __( 'The widget %s', 'bettershield' ), $label );
				break;
			case 'template':
				/* translators: %s: a block template's name. */
				$place = sprintf( __( 'The theme template “%s”', 'bettershield' ), $label );
				break;
			case 'checkout_page':
				/* translators: %s: a page title. */
				$place = sprintf( __( 'The store page “%s”', 'bettershield' ), $label );
				break;
			case 'snippet':
				/* translators: %s: a snippet's name. */
				$place = sprintf( __( 'The code snippet “%s”', 'bettershield' ), $label );
				break;
			case 'post':
				/* translators: %s: a post or page title. */
				$place = sprintf( __( 'The post or page “%s”', 'bettershield' ), $label );
				break;
			default:
				/* translators: %s: a setting's name. */
				$place = sprintf( __( 'The saved setting “%s”', 'bettershield' ), $label );
		}

		if ( '' !== (string) $flag['file'] ) {
			/* translators: 1: where a script is loaded; 2: the file it loads. */
			$place = sprintf( __( '%1$s, loading %2$s', 'bettershield' ), $place, (string) $flag['file'] );
		}

		$words = array(
			CompromiseSigns::HIDES_WHERE_IT_SENDS  => __( 'hides where it sends data', 'bettershield' ),
			CompromiseSigns::DECODES_AND_RUNS      => __( 'decodes code and runs it', 'bettershield' ),
			CompromiseSigns::PACKED                => __( 'is packed so it can’t be read', 'bettershield' ),
			CompromiseSigns::CARD_FIELDS_AND_SEND  => __( 'names card fields and can send them', 'bettershield' ),
			CompromiseSigns::PHP_DECODES_AND_RUNS  => __( 'decodes PHP and runs it', 'bettershield' ),
			CompromiseSigns::PHP_SENDS_CARD_FIELDS => __( 'sends card fields to another site', 'bettershield' ),
		);
		$seen  = implode( ', ', array_map( static fn( $test ): string => $words[ $test ] ?? (string) $test, (array) $flag['tests'] ) );

		/* translators: 1: where a script is; 2: what it was seen doing; 3: a line number. */
		return sprintf( __( '%1$s: it %2$s (line %3$d).', 'bettershield' ), $place, $seen, (int) $flag['line'] );
	}

	/**
	 * One flagged script as screens and the evidence show it: where it is and
	 * which test matched. Never its text.
	 *
	 * @param array<string, mixed> $flag
	 * @return array<string, mixed>
	 */
	private static function listed( array $flag ): array {
		return array(
			'key'   => (string) $flag['hash'],
			'where' => (string) $flag['where'],
			'label' => (string) $flag['label'],
			'file'  => (string) $flag['file'],
			'tests' => array_values( (array) $flag['tests'] ),
			'line'  => (int) $flag['line'],
			'words' => self::described( $flag ),
		);
	}

	/**
	 * What the fix screen shows: the flagged scripts and the accepted ones.
	 *
	 * @return array<string, mixed>
	 */
	public static function state(): array {
		$state = self::state_raw();

		return array(
			'store'    => self::applies(),
			'checked'  => $state['done_at'] > 0,
			'scripts'  => array_map( array( self::class, 'listed' ), array_values( array_diff_key( $state['flags'], array_flip( $state['accepted_hashes'] ) ) ) ),
			'accepted' => array_map( array( self::class, 'listed' ), array_values( $state['accepted'] ) ),
		);
	}

	/**
	 * Accept one flagged script: its hash is kept, and the same script is not
	 * flagged again. A changed script has another hash and is.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function accept( string $key ) {
		$state = self::state_raw();

		if ( ! isset( $state['flags'][ $key ] ) ) {
			return new \WP_Error( 'bettershield_script_unknown', __( 'That script isn’t on the list any more. Open the finding again.', 'bettershield' ), array( 'status' => 404 ) );
		}

		$flag = $state['flags'][ $key ];
		unset( $state['flags'][ $key ] );
		$state['accepted'][ $key ] = $flag;
		$state['accepted']         = array_slice( $state['accepted'], -self::MAX_ACCEPTED, null, true );
		unset( $state['accepted_hashes'] );

		update_option( self::OPTION, $state, false );

		Writer::instance()->record(
			'store_script_accepted',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'script',
				'object_id'   => Text::clip( $key, 16 ),
				'context'     => array(
					'where' => $flag['where'],
					'label' => $flag['label'],
					'file'  => $flag['file'],
				),
			)
		);

		return self::state();
	}

	/**
	 * Take an accepted script back: it is flagged again, without a second
	 * alert, since it was told once already.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function unaccept( string $key ) {
		$state = self::state_raw();

		if ( ! isset( $state['accepted'][ $key ] ) ) {
			return new \WP_Error( 'bettershield_script_unknown', __( 'That script isn’t on the list any more. Open the finding again.', 'bettershield' ), array( 'status' => 404 ) );
		}

		$flag = $state['accepted'][ $key ];
		unset( $state['accepted'][ $key ], $state['accepted_hashes'] );
		$state['flags'][ $key ] = $flag;

		update_option( self::OPTION, $state, false );

		Writer::instance()->record(
			'store_script_unaccepted',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'script',
				'object_id'   => Text::clip( $key, 16 ),
				'context'     => array(
					'where' => $flag['where'],
					'label' => $flag['label'],
					'file'  => $flag['file'],
				),
			)
		);

		return self::state();
	}
}
