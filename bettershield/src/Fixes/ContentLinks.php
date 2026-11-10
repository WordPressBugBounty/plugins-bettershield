<?php
/**
 * Fix for "Published content still points at plain HTTP" (#1291).
 *
 * Rewrites this site's own `http://` address to `https://` in published
 * post content of public post types, in batches a request at a time. Rows
 * holding serialized data are left alone (#2283).
 * Links to other hosts are never touched: whether they serve HTTPS is only
 * known by asking them, and this plugin makes no such call.
 *
 * Each changed post keeps its original content beside it, with a digest of
 * what it was changed to, so Undo puts it back byte for byte and skips a
 * post edited since. One run changes at most 5,000 posts; running it again
 * does the rest. Core's `https_migration_required` flag is never touched
 * (#2283): its on-the-fly rewrite also covers excerpts, widgets, custom CSS,
 * unpublished posts and builder meta, none of which this changes.
 *
 * Offered only while the site address is HTTPS.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Audit\Auditor;
use BetterShield\Audit\MixedContent;
use BetterShield\Events\Writer;
use BetterShield\Support\Server;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ContentLinks {

	/** The run in progress or last finished: its ledger token, counts and cursor. */
	public const OPTION = 'bettershield_content_links';

	/** Beside each changed post: its original content, the run, and a digest of the new. */
	public const META = '_bettershield_http_original';

	/** The ledger row each run is recorded under. */
	public const LEDGER_KEY = 'content_links_https';

	/** The most posts one run changes. */
	public const RUN_MAX = 5000;

	/** Posts read and written per request. */
	private const BATCH = 50;

	/**
	 * What the panel shows.
	 *
	 * @return array<string, mixed>
	 */
	public static function state(): array {
		$run = self::run();

		return array(
			'https'       => Server::address_is_https(),
			'origin'      => MixedContent::own_origin(),
			'remaining'   => Server::address_is_https() ? self::remaining() : 0,
			'core_covers' => MixedContent::core_rewrites(),
			'run'         => null === $run ? null : array(
				'changed'  => (int) $run['changed'],
				'kept'     => (int) ( $run['kept'] ?? $run['changed'] ),
				'done'     => ! empty( $run['done'] ),
				'undone'   => ! empty( $run['undone'] ),
				'capped'   => ! empty( $run['capped'] ),
				'skipped'  => array_values( (array) ( $run['skipped'] ?? array() ) ),
			),
			'run_max'     => self::RUN_MAX,
		);
	}

	/**
	 * The finished rewrite still to be undone, for the list of ways back
	 * kept after the finding closes (#2658), or null: its Undo puts back
	 * every run not yet undone.
	 *
	 * @return array{undo: string, posts: int}|null
	 */
	public static function open_run(): ?array {
		$run = self::run();

		if ( null === $run || empty( $run['done'] ) || ! empty( $run['undone'] ) ) {
			return null;
		}

		return array(
			'undo'  => (string) $run['token'],
			'posts' => (int) ( $run['kept'] ?? $run['changed'] ),
		);
	}

	/**
	 * How many published posts the rewrite would change. Counted with the
	 * rewrite's own test (#2283): a plain LIKE also counted links it skips
	 * (http://example.org.evil.test, a port, a trailing dot in prose), so
	 * the button never went away.
	 */
	public static function remaining(): int {
		if ( '' === MixedContent::own_origin() ) {
			return 0;
		}

		$after = 0;
		$count = 0;

		do {
			$rows = self::rows( $after, 500 );

			foreach ( $rows as $row ) {
				$after = (int) $row->ID;
				$count += self::ours( (string) $row->post_content ) ? 1 : 0;
			}
		} while ( 500 === count( $rows ) );

		return $count;
	}

	/** Whether the rewrite changes this content: our own address, not serialized. */
	private static function ours( string $content ): bool {
		// Serialized data (#2283): a string's length is stored beside it, so
		// a longer https:// would leave the whole value unreadable.
		return ! is_serialized( $content ) && 1 === preg_match( MixedContent::own_pattern(), $content );
	}

	/**
	 * The published rows of public post types after a cursor that mention
	 * this site's own address, in ID order (#2283). Only public types: a
	 * plugin's own types (ACF field groups among them) keep settings in
	 * post_content, often serialized, and are no page anybody reads.
	 *
	 * @return array<int, object>
	 */
	private static function rows( int $after, int $limit ): array {
		global $wpdb;

		$types = self::types();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- reads post content directly so the original can be put back byte for byte, with no filter between. The fragment is placeholders built from a count.
		return (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ID, post_content FROM {$wpdb->posts} WHERE post_status = 'publish' AND post_type IN (" . implode( ',', array_fill( 0, count( $types ), '%s' ) ) . ') AND ID > %d AND post_content LIKE %s ORDER BY ID ASC LIMIT %d',
				array_merge( $types, array( $after, '%' . $wpdb->esc_like( MixedContent::own_origin() ) . '%', max( 1, $limit ) ) )
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
	}

	/**
	 * The public post types, never empty.
	 *
	 * @return string[]
	 */
	private static function types(): array {
		$types = array_values( array_map( 'strval', get_post_types( array( 'public' => true ) ) ) );

		return array() === $types ? array( 'post', 'page' ) : $types;
	}

	/**
	 * One batch of the rewrite. The first call opens the run; each one after
	 * continues it until nothing is left or the run reaches its cap.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function rewrite() {
		global $wpdb;

		if ( ! Server::address_is_https() ) {
			return new \WP_Error( 'bettershield_links_not_https', __( 'The site address is not HTTPS, so its links are left as they are.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$origin = MixedContent::own_origin();

		if ( '' === $origin ) {
			return new \WP_Error( 'bettershield_links_no_host', __( 'The site address has no host to look for.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$run = self::run();

		// A finished or undone run is the last one; this starts the next.
		if ( null === $run || ! empty( $run['done'] ) ) {
			$token = Ledger::open( self::LEDGER_KEY, array(), array( 'origin' => $origin ) );

			if ( null === $token ) {
				return new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
			}

			// Earlier runs not yet undone stay undoable (#2283): Undo puts
			// back every one of them, not only the last.
			$earlier = null !== $run && empty( $run['undone'] );

			$run = array(
				'token'   => $token,
				'tokens'  => array_merge( $earlier ? self::tokens( $run ) : array(), array( $token ) ),
				'changed' => 0,
				'kept'    => $earlier ? (int) ( $run['kept'] ?? $run['changed'] ) : 0,
				'cursor'  => 0,
				'done'    => false,
				'undone'  => false,
				'capped'  => false,
				'skipped' => array(),
			);
		}

		$pattern = MixedContent::own_pattern();
		$https   = set_url_scheme( $origin, 'https' );
		$limit   = min( self::BATCH, self::RUN_MAX - (int) $run['changed'] );

		$rows = self::rows( (int) $run['cursor'], $limit );

		foreach ( $rows as $row ) {
			$run['cursor'] = (int) $row->ID;
			$before        = (string) $row->post_content;

			// Serialized data, or only a longer host (example.org.test): not
			// a row this changes.
			if ( ! self::ours( $before ) ) {
				continue;
			}

			$after = (string) preg_replace( $pattern, $https, $before );

			// The original first: a post changed with nothing to come back to
			// is the one thing this may never leave behind.
			if ( ! update_post_meta( (int) $row->ID, self::META, array( 'run' => $run['token'], 'content' => $before, 'digest' => md5( $after ) ) ) ) {
				continue;
			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- written directly so the original can be put back byte for byte, with no filter, revision or kses pass between.
			if ( false === $wpdb->update( $wpdb->posts, array( 'post_content' => $after ), array( 'ID' => (int) $row->ID ) ) ) {
				delete_post_meta( (int) $row->ID, self::META );
				continue;
			}

			clean_post_cache( (int) $row->ID );
			++$run['changed'];
			$run['kept'] = (int) ( $run['kept'] ?? 0 ) + 1;
		}

		$capped  = (int) $run['changed'] >= self::RUN_MAX;
		$drained = count( $rows ) < max( 1, $limit );

		if ( $capped || $drained ) {
			$run['done']   = true;
			$run['capped'] = $capped && self::remaining() > 0;

			// Core's https_migration_required flag stays as it is (#2283):
			// clearing it would bring plain HTTP back in every place this
			// does not reach, excerpts, widgets and builder meta among them.

			Writer::instance()->record(
				'content_links_rewritten',
				Writer::SEVERITY_INFO,
				array(
					'object_type' => 'content',
					'object_id'   => $run['token'],
					'context'     => array( 'posts' => (int) $run['changed'] ),
				)
			);

			MixedContent::refresh();
			Auditor::run();
		}

		update_option( self::OPTION, $run, false );

		return self::state();
	}

	/**
	 * One batch of the undo: each post the runs not yet undone changed goes
	 * back to its original, unless it was edited since, which is skipped and
	 * named.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function undo() {
		global $wpdb;

		$run = self::run();

		if ( null === $run || empty( $run['done'] ) || ! empty( $run['undone'] ) ) {
			return new \WP_Error( 'bettershield_links_nothing_to_undo', __( 'There is no finished rewrite to undo.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$tokens = self::tokens( $run );

		// Paged by post ID past a cursor, as the rewrite is (#2283): a post
		// whose update fails, or whose record names another run, keeps its
		// record, and without a cursor it came back every batch, forever.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the posts the runs changed, by the record kept beside each.
		$ids = array_map( 'intval', (array) $wpdb->get_col( $wpdb->prepare( "SELECT DISTINCT post_id FROM {$wpdb->postmeta} WHERE meta_key = %s AND post_id > %d ORDER BY post_id ASC LIMIT %d", self::META, (int) ( $run['undo_cursor'] ?? 0 ), self::BATCH ) ) );

		foreach ( $ids as $id ) {
			$run['undo_cursor'] = $id;

			$kept = get_post_meta( $id, self::META, true );
			$post = get_post( $id );

			if ( ! is_array( $kept ) || ! in_array( (string) ( $kept['run'] ?? '' ), $tokens, true ) ) {
				continue;
			}

			// Edited since: its content is somebody's newer work.
			if ( ! $post instanceof \WP_Post || md5( (string) $post->post_content ) !== (string) ( $kept['digest'] ?? '' ) ) {
				$run['skipped'][] = array(
					'id'    => $id,
					'title' => $post instanceof \WP_Post ? (string) $post->post_title : '',
				);
				delete_post_meta( $id, self::META );
				continue;
			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- byte for byte, as it was.
			if ( false !== $wpdb->update( $wpdb->posts, array( 'post_content' => (string) $kept['content'] ), array( 'ID' => $id ) ) ) {
				delete_post_meta( $id, self::META );
				clean_post_cache( $id );
			}
		}

		if ( count( $ids ) < self::BATCH ) {
			$run['undone'] = true;

			foreach ( $tokens as $token ) {
				Ledger::mark_reverted( $token );
			}

			Writer::instance()->record(
				'content_links_restored',
				Writer::SEVERITY_MEDIUM,
				array(
					'object_type' => 'content',
					'object_id'   => (string) $run['token'],
					'context'     => array( 'skipped' => count( (array) $run['skipped'] ) ),
				)
			);

			MixedContent::refresh();
			Auditor::run();
		}

		update_option( self::OPTION, $run, false );

		return self::state();
	}

	/**
	 * The ledger tokens of a run and the earlier ones it carries.
	 *
	 * @param array<string, mixed> $run The run.
	 * @return string[]
	 */
	private static function tokens( array $run ): array {
		return array_values( array_unique( array_map( 'strval', (array) ( $run['tokens'] ?? array( $run['token'] ) ) ) ) );
	}

	/**
	 * The run on record, or null.
	 *
	 * @return array<string, mixed>|null
	 */
	private static function run(): ?array {
		$run = get_option( self::OPTION, null );

		return is_array( $run ) && isset( $run['token'] ) ? $run : null;
	}
}
