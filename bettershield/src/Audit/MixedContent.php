<?php
/**
 * Published content still pointing at plain HTTP.
 *
 * A site moved to HTTPS years ago can still show a broken padlock, and the
 * cause is almost always an address typed into a post before the move. The
 * browser either blocks the asset or drops the lock, and either way the
 * visitor is told the site is not secure — which is the one thing an owner
 * who paid for a certificate did not expect to still be true.
 *
 * **This reads the database rather than fetching a page.** A loopback request
 * would see the rendered result and would therefore also catch a theme or a
 * plugin doing it, which is genuinely more thorough — and it would cost a
 * request on a site that may be slow, for a question whose commonest answer
 * is sitting in `post_content`. The passive answer comes first for exactly
 * this reason, and a verifier that cannot see everything says so rather than
 * claiming it did.
 *
 * So this reports what it can see and does not claim to have looked
 * everywhere. The finding's own wording says where it looked.
 *
 * **And it is asked once a day, never on a request.** There is no index that
 * can serve a leading wildcard, so both queries below read every published
 * post's content in full — which is work a site with fifty thousand posts
 * feels, and which was being paid for by whoever opened the dashboard.
 * The answer is stored with the day it was taken and every reader gets that,
 * exactly as the certificate and the exposed-artifact probe already work.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Audit;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class MixedContent {

	/** Where the last answer is kept. */
	public const OPTION = 'bettershield_mixed_content';

	/**
	 * How many offending posts are named. A site with a hundred has a
	 * find-and-replace job, not a list to read.
	 */
	public const MAX_NAMED = 10;

	/**
	 * Look now, and store what was found. Called by the daily task.
	 *
	 * @return array{checked_at: string, total: int, posts: array<int, array<string, mixed>>}|null
	 */
	public static function refresh(): ?array {
		// Mixed content is not what is wrong with a site served over plain
		// HTTP, and the stored answer goes with the condition that produced
		// it: a site that moves back would otherwise keep reporting one.
		if ( ! Certificate::site_is_https() ) {
			delete_option( self::OPTION );

			return null;
		}

		$total = self::count_in_published_content();

		/*
		 * A run that could not count keeps whatever the last one learned and
		 * marks the row unreadable, rather than replacing it with a zero
		 * nobody measured. The check then says it could not tell — which
		 * leaves an open finding open, and never resolves one.
		 */
		if ( null === $total ) {
			$previous = self::last();

			$unknown = is_array( $previous )
				? $previous
				: array( 'checked_at' => gmdate( 'c' ), 'total' => 0, 'posts' => array() );

			$unknown['reliable']      = false;
			$unknown['unreadable_at'] = gmdate( 'c' );

			update_option( self::OPTION, $unknown, false );

			return null;
		}

		$posts = 0 === $total ? array() : self::in_published_content();

		/*
		 * After an address switch through the options, WordPress rewrites the
		 * site's own http:// address on output (`https_migration_required`),
		 * so a browser never receives those links as plain HTTP. They are not
		 * counted while it does; links to other hosts still are (#1291).
		 */
		$covered = $total > 0 && self::core_rewrites();

		if ( $covered ) {
			$foreign = self::foreign_only();

			if ( null !== $foreign ) {
				$total = $foreign['total'];
				$posts = $foreign['posts'];
			}
		}

		$answer = array(
			'checked_at' => gmdate( 'c' ),
			'total'      => $total,
			// The commonest answer is zero, and on that site the second query
			// never runs.
			'posts'      => $posts,
			// Said in the row rather than inferred from it, so a reader never
			// has to tell a measured zero from an unmeasured one.
			'reliable'   => true,
			'core_covers' => $covered,
		);

		update_option( self::OPTION, $answer, false );

		return $answer;
	}

	/**
	 * The last answer, or nothing if this has never run.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function last(): ?array {
		$stored = get_option( self::OPTION, null );

		return is_array( $stored ) && isset( $stored['checked_at'] ) ? $stored : null;
	}

	/**
	 * How many published posts load something over plain HTTP.
	 *
	 * Separate from the named list, because the named list is capped and a
	 * capped list with no total cannot be told from a complete one. Ten of ten
	 * and ten of four hundred are different sites and were the same finding.
	 */
	public static function count_in_published_content(): ?int {
		global $wpdb;

		$shapes = self::shapes();
		$where  = self::where_clause( $shapes );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, PluginCheck.Security.DirectDB.UnescapedDBParameter -- as below: reached only from refresh(), on the daily task; the interpolated fragment is placeholders built from a literal count.
		$count = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->posts}
				 WHERE post_status = 'publish'
				   AND ( {$where} )",
				$shapes
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, PluginCheck.Security.DirectDB.UnescapedDBParameter

		/*
		 * Null is the query not running, never an answer of none: a COUNT
		 * that succeeds returns exactly one row. This one reads every
		 * published post's content in full, which is the shape a host kills
		 * on a statement timeout — and cast to an integer that killed query
		 * became "no mixed content on this site", which is the one thing this
		 * check must never say by accident.
		 */
		return null === $count ? null : (int) $count;
	}

	/**
	 * Published posts whose content loads something over plain HTTP.
	 *
	 * The id and the title, and deliberately nothing else. An edit link used
	 * to travel with each one: `get_edit_post_link()` answers null where there
	 * is no user, so the same finding held a full admin address when a person
	 * pressed the button and an empty string when the schedule wrote it —
	 * and nothing rendered it as a link either way. The screen runs in the
	 * admin and can build one from the id.
	 *
	 * @return array<int, array{id: int, title: string}>
	 */
	public static function in_published_content(): array {
		global $wpdb;

		$shapes = self::shapes();
		$where  = self::where_clause( $shapes );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- reached only from refresh(), on the daily task, never on a request; the interpolated fragment is placeholders built from a literal count, and every value is passed through prepare().
		$rows = (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ID, post_title FROM {$wpdb->posts}
				 WHERE post_status = 'publish'
				   AND ( {$where} )
				 ORDER BY ID DESC
				 LIMIT %d",
				array_merge( $shapes, array( self::MAX_NAMED ) )
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$found = array();

		foreach ( $rows as $row ) {
			$found[] = array(
				'id'    => (int) $row->ID,
				'title' => (string) $row->post_title,
			);
		}

		return $found;
	}

	/** Whether WordPress rewrites the site's own http:// address on output now. */
	public static function core_rewrites(): bool {
		if ( ! function_exists( 'wp_should_replace_insecure_home_url' ) ) {
			require_once ABSPATH . WPINC . '/https-migration.php';
		}

		return (bool) wp_should_replace_insecure_home_url();
	}

	/**
	 * The site's own origin over plain HTTP, as links to it are written:
	 * `http://example.org` or `http://example.org:8080`. Empty without a host.
	 */
	public static function own_origin(): string {
		$home = wp_parse_url( home_url() );
		$host = (string) ( $home['host'] ?? '' );

		return '' === $host ? '' : 'http://' . $host . ( isset( $home['port'] ) ? ':' . (int) $home['port'] : '' );
	}

	/**
	 * A pattern for the site's own http:// origin and nothing longer: not
	 * `example.org.evil.test`, not `example.org:8080` on a site without a
	 * port, not `example.organic`.
	 */
	public static function own_pattern(): string {
		return '#' . preg_quote( self::own_origin(), '#' ) . '(?![a-z0-9.:\-])#i';
	}

	/**
	 * The posts that load something over plain HTTP from a host other than
	 * this site, read in batches from the ones the shapes match. Null when a
	 * batch could not be read.
	 *
	 * @return array{total: int, posts: array<int, array{id: int, title: string}>}|null
	 */
	private static function foreign_only(): ?array {
		global $wpdb;

		$shapes = self::shapes();
		$where  = self::where_clause( $shapes );
		$own    = self::own_pattern();
		$after  = 0;
		$total  = 0;
		$posts  = array();

		do {
			// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- as above: the daily task only; the fragment is placeholders built from a literal count.
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT ID, post_title, post_content FROM {$wpdb->posts}
					 WHERE post_status = 'publish' AND ID > %d
					   AND ( {$where} )
					 ORDER BY ID ASC
					 LIMIT 200",
					array_merge( array( $after ), $shapes )
				)
			);
			// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

			if ( ! is_array( $rows ) || '' !== $wpdb->last_error ) {
				return null;
			}

			foreach ( $rows as $row ) {
				$after = (int) $row->ID;

				// The content with this site's own address taken out: what is
				// left loading over plain HTTP is another host's.
				if ( self::loads_plain_http( (string) preg_replace( $own, 'https://own.invalid', (string) $row->post_content ) ) ) {
					++$total;

					if ( count( $posts ) < self::MAX_NAMED ) {
						$posts[] = array(
							'id'    => (int) $row->ID,
							'title' => (string) $row->post_title,
						);
					}
				}
			}
		} while ( count( $rows ) === 200 );

		return array(
			'total' => $total,
			'posts' => $posts,
		);
	}

	/** Whether content still matches one of the loading shapes. */
	private static function loads_plain_http( string $content ): bool {
		foreach ( self::shapes() as $shape ) {
			if ( false !== stripos( $content, trim( $shape, '%' ) ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * The attribute shapes that actually load something.
	 *
	 * Shared by the count and the named list, so the two can never disagree
	 * about what counts — which they would within a release of each other if
	 * this list were written twice.
	 *
	 * A plain link to an http:// page is a link, not mixed content: the
	 * browser follows it when somebody clicks and the padlock on this page is
	 * unaffected. Matching every `http://` would report every external link on
	 * the site and bury the handful that matter.
	 *
	 * Three shapes were matched at first, and each of the ones missing was
	 * ordinary rather than exotic: a CSS url() with quotes inside it, which is
	 * what an editor produces; `srcset`, which is what a responsive image is;
	 * `poster`, which is what a video is; and the `data-` copies a
	 * lazy-loading plugin leaves behind. Every one of them breaks the padlock,
	 * and a site full of them was told it was clean — which is the one thing a
	 * check like this must never do.
	 *
	 * @return string[]
	 */
	private static function shapes(): array {
		return array(
			'%src="http://%',
			"%src='http://%",
			'%srcset="http://%',
			"%srcset='http://%",
			'%poster="http://%',
			"%poster='http://%",
			// The CSS shape, in all three ways it is written.
			'%url(http://%',
			'%url("http://%',
			"%url('http://%",
			// The same thing inside a double-quoted attribute, where the quote
			// survives as an entity: `style="background:url(&quot;http://…"`.
			'%url(&quot;http://%',
			/*
			 * What a lazy-loading plugin moves the real address into. Matched
			 * as `data-` plus one of the two attribute names rather than any
			 * `data-` attribute, because the browser loads these and does not
			 * load an arbitrary data attribute holding a URL.
			 */
			'%data-src="http://%',
			"%data-src='http://%",
			'%data-srcset="http://%',
			"%data-srcset='http://%",
		);
	}

	/**
	 * @param string[] $shapes
	 */
	private static function where_clause( array $shapes ): string {
		return implode( ' OR ', array_fill( 0, count( $shapes ), 'post_content LIKE %s' ) );
	}
}
