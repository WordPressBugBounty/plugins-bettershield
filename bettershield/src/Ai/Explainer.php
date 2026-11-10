<?php
/**
 * A finding, explained in plain language by whatever model the site owner
 * already connected to WordPress.
 *
 * **This plugin has no API key and no field to put one in.** WordPress 7.0
 * gained a connector system: the owner configures a provider once, in core's
 * own settings, and core keeps the credential in an option, a constant or an
 * environment variable. We call `wp_ai_client_prompt()` and core resolves the
 * rest. There is nothing here to store, nothing to leak, and nothing to
 * migrate if the owner changes provider.
 *
 * **Every claim is shown beside the evidence it was built from.** The model is
 * given the finding's own recorded evidence and nothing else, and the
 * explanation is returned together with that evidence so a reader can check
 * one against the other. An explanation that cannot be checked is a claim
 * this product has no business making — the prompt says as much, and the
 * screen shows both halves.
 *
 * **It degrades to absence, never to an error.** No WordPress 7.0, no provider
 * configured, AI switched off for the site, a model that failed: in every case
 * the feature is simply not there, and the finding is exactly as readable as
 * it was before. Nothing here may block a screen.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Ai;

use BetterShield\Audit\Auditor;
use BetterShield\Events\Writer;
use BetterShield\Support\Claim;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Explainer {

	/** Why the feature is not available, where it is not. */
	public const REASON_REQUIRES_WP  = 'requires_wordpress';
	public const REASON_DISABLED     = 'disabled';
	public const REASON_NO_PROVIDER  = 'no_provider';

	/**
	 * How much of a finding's evidence may travel, in bytes once encoded.
	 *
	 * Evidence is written by this plugin's own checks and is small by
	 * construction — counts, flags, a list of header names. The bound is here
	 * so that a future check with a chattier payload cannot quietly start
	 * sending more of a site to a third party than anyone intended.
	 */
	private const MAX_EVIDENCE_BYTES = 2048;

	/**
	 * How many explanations one account may ask for in an hour.
	 *
	 * Comfortably more than reading every finding on a site in one sitting,
	 * and well below anything that reads as a loop. Counted per account rather
	 * than per site: the budget being spent is the owner's, and one person
	 * having a long afternoon must not stop everybody else asking.
	 */
	private const MAX_PER_HOUR = 20;

	/**
	 * Where an explanation is kept once it has been paid for.
	 *
	 * A finding does not change between two people opening it, and neither
	 * does the answer: the model is handed the finding's own words and its
	 * recorded evidence and nothing else, so the second ask was buying the
	 * first ask's paragraphs again. What the answer is filed under is the
	 * evidence itself, which means a finding whose facts have moved misses
	 * this by construction rather than by anybody remembering to clear it.
	 */
	private const CACHE_OPTION = 'bettershield_ai_explanations';

	/**
	 * How many explanations are kept.
	 *
	 * More than a site has findings, so ordinary reading never evicts
	 * anything, and small enough that the option stays a single short read.
	 */
	private const MAX_CACHED = 40;

	/**
	 * Where the month's asking is counted.
	 *
	 * The activity log records each ask as it happens, but it is retained for
	 * days rather than months — so "what has this cost me" cannot be answered
	 * from it, and a running total is the only honest way to show a number
	 * beside a feature that spends somebody's money.
	 */
	private const USAGE_OPTION = 'bettershield_ai_calls';

	/**
	 * Whether an explanation can be produced, and why not where it cannot.
	 *
	 * @return array{available: bool, reason: string, notice: string}
	 */
	public static function availability(): array {
		if ( ! function_exists( 'wp_ai_client_prompt' ) || ! function_exists( 'wp_supports_ai' ) ) {
			return self::unavailable(
				self::REASON_REQUIRES_WP,
				__( 'Requires WordPress 7.0.', 'bettershield' )
			);
		}

		if ( ! wp_supports_ai() ) {
			return self::unavailable(
				self::REASON_DISABLED,
				__( 'AI features are switched off for this site.', 'bettershield' )
			);
		}

		// Asks the providers the owner configured whether any of them can
		// generate text. No provider, or one that cannot, answers false — and
		// that is an ordinary state, not a failure.
		try {
			$supported = wp_ai_client_prompt( 'x' )->is_supported_for_text_generation();
		} catch ( \Throwable $e ) {
			$supported = false;
		}

		if ( ! $supported ) {
			return self::unavailable(
				self::REASON_NO_PROVIDER,
				__( 'No AI provider connected. Set one up in Settings › Connectors.', 'bettershield' )
			);
		}

		return array(
			'available' => true,
			'reason'    => '',
			'notice'    => '',
		);
	}

	/**
	 * Explain one finding, with the evidence the explanation was built from.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function explain( string $finding_key ) {
		/*
		 * The key first, and the provider second. A key naming no finding is
		 * refused whatever the site has configured, it costs a read this route
		 * was going to make anyway, and — the part that matters — asking about
		 * nothing never counts against the hour's budget below.
		 */
		$finding = self::finding( $finding_key );

		if ( null === $finding ) {
			return new \WP_Error( 'bettershield_unknown_finding', __( 'Unknown finding.', 'bettershield' ), array( 'status' => 404 ) );
		}

		$availability = self::availability();

		if ( ! $availability['available'] ) {
			return new \WP_Error(
				'bettershield_ai_unavailable',
				$availability['notice'],
				array( 'status' => 400 )
			);
		}

		$evidence = self::portable_evidence( $finding );
		$hash     = self::evidence_hash( $evidence );
		$kept     = self::kept( $finding_key, $hash );

		/*
		 * Before the budget rather than after it. The budget bounds what one
		 * account may spend, and an answer that is already written costs
		 * nothing to hand over — charging for it would let a site that is
		 * reading its own report run out of an allowance it never used.
		 */
		if ( null !== $kept ) {
			self::counted( 'cached' );

			return array(
				'finding'      => $finding_key,
				'explanation'  => (string) $kept['explanation'],
				'evidence'     => $evidence,
				// The time it was written, not the time it was read. A
				// timestamp moved forward by reading would say the model had
				// looked at the site again, which is the one thing it did not
				// do.
				'generated_at' => (string) $kept['generated_at'],
				'cached'       => true,
			);
		}

		$budget = self::within_budget();

		if ( is_wp_error( $budget ) ) {
			return $budget;
		}

		// Guarded again rather than relying on the availability check above
		// having run. That check does guard it today, but the cost of being
		// wrong here is a fatal error on the platform floor, and the cost of
		// the guard is one function_exists call on a path that is about to
		// make a network request anyway.
		if ( ! function_exists( 'wp_ai_client_prompt' ) ) {
			return new \WP_Error( 'bettershield_ai_unavailable', __( 'Requires WordPress 7.0.', 'bettershield' ), array( 'status' => 400 ) );
		}

		$result = self::generate( self::prompt( $finding, $evidence ), self::system_instruction() );

		// Counted whichever way it went: a provider that failed still took the
		// request, and a month's total that omitted the failures would be a
		// smaller number than the one on the invoice.
		self::counted( 'calls' );

		if ( is_wp_error( $result ) ) {
			self::record( $finding_key, false );

			return new \WP_Error(
				'bettershield_ai_failed',
				__( 'The explanation could not be generated: an AI provider problem, not your site. The finding is unchanged.', 'bettershield' ),
				array( 'status' => 502 )
			);
		}

		$explanation  = trim( (string) $result );
		$generated_at = gmdate( 'c' );

		self::keep( $finding_key, $hash, $explanation, $generated_at );
		self::record( $finding_key, true );

		return array(
			'finding'      => $finding_key,
			'explanation'  => $explanation,
			// Returned so the screen can show what the explanation was built
			// from, immediately beside it. This is the whole mechanism behind
			// "no receipts, no claim": the reader checks rather than trusts.
			'evidence'     => $evidence,
			'generated_at' => $generated_at,
			'cached'       => false,
		);
	}

	/**
	 * What the month's asking has cost, and what it was spared.
	 *
	 * Reset by reading rather than by a scheduled task: a stored month that is
	 * not this one is last month's bill, and answering with zeroes is the same
	 * answer without needing anything to have run.
	 *
	 * @return array{month: string, calls: int, cached: int}
	 */
	public static function counted_incident( int $id, bool $succeeded, bool $cached = false ): void {
		self::counted( $cached ? 'cached' : 'calls' );
		if ( ! $cached ) { Writer::instance()->record( 'ai_explanation_generated', Writer::SEVERITY_INFO, array( 'object_type' => 'incident', 'object_id' => (string) $id, 'context' => array( 'ok' => $succeeded ) ) ); }
	}
	/**
	 * The audit summary's share of the month's count, and its row in the log.
	 */
	public static function counted_summary( bool $succeeded, bool $cached = false ): void {
		self::counted( $cached ? 'cached' : 'calls' );
		if ( ! $cached ) { Writer::instance()->record( 'ai_explanation_generated', Writer::SEVERITY_INFO, array( 'object_type' => 'audit', 'object_id' => 'summary', 'context' => array( 'ok' => $succeeded ) ) ); }
	}
	/**
	 * An add-on's own ask: counted in the month's total beside this plugin's,
	 * with a row of its own in the log. What the owner's provider is spent on
	 * is one number, however many plugins spent it, and a row filed under
	 * another feature's name would say something that did not happen.
	 */
	public static function counted_for( string $object_type, string $object_id, bool $succeeded, bool $cached = false ): void {
		self::counted( $cached ? 'cached' : 'calls' );

		if ( ! $cached ) {
			Writer::instance()->record(
				'ai_explanation_generated',
				Writer::SEVERITY_INFO,
				array(
					'object_type' => sanitize_key( $object_type ),
					'object_id'   => sanitize_key( $object_id ),
					'context'     => array( 'ok' => $succeeded ),
				)
			);
		}
	}

	public static function usage(): array {
		$stored = get_option( self::USAGE_OPTION );
		$month  = gmdate( 'Y-m' );

		if ( ! is_array( $stored ) || $month !== ( $stored['month'] ?? '' ) ) {
			return array(
				'month'  => $month,
				'calls'  => 0,
				'cached' => 0,
			);
		}

		return array(
			'month'  => $month,
			'calls'  => (int) ( $stored['calls'] ?? 0 ),
			'cached' => (int) ( $stored['cached'] ?? 0 ),
		);
	}

	/**
	 * Add one to `calls` or to `cached`, this month.
	 */
	private static function counted( string $field ): void {
		$usage = self::usage();

		$usage[ $field ] = $usage[ $field ] + 1;

		update_option( self::USAGE_OPTION, $usage, false );
	}

	/**
	 * A fingerprint of the facts an explanation was built from.
	 *
	 * Keys are sorted before encoding because PHP keeps insertion order: the
	 * same evidence gathered in a different order would otherwise encode
	 * differently and read as a change nobody made.
	 *
	 * @param array<string, mixed> $evidence
	 */
	private static function evidence_hash( array $evidence ): string {
		ksort( $evidence, SORT_STRING );

		return hash( 'sha256', (string) wp_json_encode( $evidence ) );
	}

	/**
	 * The explanation held for this finding, if its evidence has not moved.
	 *
	 * @return array<string, mixed>|null
	 */
	private static function kept( string $finding_key, string $hash ): ?array {
		foreach ( self::cache() as $entry ) {
			if ( $finding_key === ( $entry['finding'] ?? '' ) && $hash === ( $entry['evidence_hash'] ?? '' ) ) {
				return $entry;
			}
		}

		return null;
	}

	/**
	 * @return array<int, array<string, mixed>>
	 */
	private static function cache(): array {
		$kept = get_option( self::CACHE_OPTION );

		return is_array( $kept ) ? array_values( array_filter( $kept, 'is_array' ) ) : array();
	}

	/**
	 * File one answer, oldest out.
	 */
	private static function keep( string $finding_key, string $hash, string $explanation, string $generated_at ): void {
		// One answer per finding. A check whose evidence keeps moving would
		// otherwise fill the whole store with explanations of states the site
		// has already left, and push out every other finding's.
		$kept = array_values(
			array_filter(
				self::cache(),
				static function ( array $entry ) use ( $finding_key ): bool {
					return $finding_key !== ( $entry['finding'] ?? '' );
				}
			)
		);

		$kept[] = array(
			'finding'       => $finding_key,
			'evidence_hash' => $hash,
			'explanation'   => $explanation,
			'generated_at'  => $generated_at,
		);

		while ( count( $kept ) > self::MAX_CACHED ) {
			array_shift( $kept );
		}

		update_option( self::CACHE_OPTION, $kept, false );
	}

	/**
	 * How many explanations one account may ask for in an hour here.
	 *
	 * Zero means no cap at all, and is the only value that means it: a
	 * negative one is a mistake in whatever answered, and refusing every ask
	 * shows that immediately rather than uncapping somebody's provider bill.
	 */
	public static function budget_per_hour(): int {
		/**
		 * How many explanations one account may ask for in an hour.
		 *
		 * @param int $per_hour The cap, or 0 for no cap.
		 */
		return (int) apply_filters( 'bettershield_explain_budget_per_hour', self::MAX_PER_HOUR );
	}

	/**
	 * Whether this account has already asked for as many explanations as an
	 * account asks for in an hour.
	 *
	 * Holding the capability is not a bound on spend. Every call is a
	 * generation billed to whatever provider the owner connected, and a
	 * credential walking the finding keys in a loop is indistinguishable from
	 * somebody reading their own report until the invoice arrives.
	 *
	 * @return true|\WP_Error
	 */
	public static function within_budget() {
		$budget = self::budget_per_hour();

		// Nothing to count against, so nothing is counted. The count is a
		// write, on a path that is otherwise a read and a network request;
		// taking one whose answer no branch can use would spend a row of the
		// claims table per ask for the rest of the hour.
		if ( 0 === $budget ) {
			return true;
		}

		// A fixed window, counted in one statement: parallel asks must not
		// each read the same total before any of them writes it back.
		if ( Claim::bump( 'ai_explain_' . get_current_user_id(), HOUR_IN_SECONDS ) > $budget ) {
			return new \WP_Error(
				'bettershield_ai_too_many',
				__( 'This account has reached its hourly limit for explanations. Try again shortly.', 'bettershield' ),
				array( 'status' => 429 )
			);
		}

		return true;
	}

	/**
	 * Ask the model. Answers with text or with a WP_Error, and never by
	 * raising.
	 *
	 * The client converts an exception of its own into a WP_Error, and catches
	 * nothing beyond that — so an error raised inside a provider's own code, or
	 * by anything hooked in front of the call, travels straight out of it. This
	 * feature is allowed to be absent; it is not allowed to be the reason a
	 * screen returns a 500.
	 *
	 * @return string|\WP_Error
	 */
	public static function generate( string $prompt, string $instruction ) {
		try {
			return wp_ai_client_prompt( $prompt )
				->using_system_instruction( $instruction )
				->generate_text();
		} catch ( \Throwable $e ) {
			// The message stays here. What the caller sends back is the calm
			// sentence below, because a provider's own words are written for
			// whoever wrote the provider.
			return new \WP_Error( 'bettershield_ai_threw', $e->getMessage() );
		}
	}

	/**
	 * What the model is told about its job.
	 *
	 * Written to constrain rather than to flatter: it may only use the facts
	 * it was handed, it must say when they are not enough, and it must not
	 * reach for the reassuring generality that makes an explanation feel
	 * complete while saying nothing.
	 */
	private static function system_instruction(): string {
		return implode(
			' ',
			array(
				'You explain one WordPress security finding to a site owner who is not a developer.',
				'Use only the facts given to you. Do not infer anything about the site that is not stated.',
				'If the facts are not enough to explain something, say so plainly instead of guessing.',
				'Never suggest the site has been attacked or compromised unless the facts say so.',
				'Do not recommend products, plugins or services.',
				'Write three short paragraphs, no headings and no lists: what this means, why it matters for this site, and what changes if it is fixed.',
				'Be calm and specific. No exclamation marks, no alarm, no marketing language.',
			)
		);
	}

	/**
	 * The prompt: the check's own words, and the evidence recorded for it.
	 *
	 * @param array<string, mixed> $finding
	 * @param array<string, mixed> $evidence
	 */
	private static function prompt( array $finding, array $evidence ): string {
		$lines = array(
			'Finding: ' . (string) $finding['title'],
			'Severity as rated by the scanner: ' . (string) $finding['severity'],
			'What the scanner says it means: ' . (string) $finding['why'],
			'What the scanner says could break if it is fixed: ' . (string) $finding['break_note'],
		);

		$lines[] = array() === $evidence
			? 'Evidence recorded on this site: none beyond the finding itself.'
			: 'Evidence recorded on this site: ' . (string) wp_json_encode( $evidence );

		return implode( "\n", $lines );
	}

	/**
	 * The evidence, bounded and scrubbed, as it may leave the site.
	 *
	 * The checks that produce evidence are a closed registry of this plugin's
	 * own, and none of them records an address, an email or file contents. The
	 * scrub is here anyway, because "no check does that today" is a property of
	 * today's registry and this is a third party's server.
	 *
	 * @param array<string, mixed> $finding
	 * @return array<string, mixed>
	 */
	public static function portable_evidence( array $finding ): array {
		$evidence = isset( $finding['evidence'] ) && is_array( $finding['evidence'] ) ? $finding['evidence'] : array();
		$out      = array();
		$hosts    = self::own_hosts( $evidence );

		foreach ( $evidence as $key => $value ) {
			if ( is_array( $value ) || is_object( $value ) ) {
				continue; // Structured payloads are display detail, not explanation material.
			}

			$value = (string) $value;

			/*
			 * Anything shaped like an address or an email does not travel,
			 * whatever key it arrived under.
			 *
			 * A bare address carries neither an `@` nor a scheme, so an IPv4,
			 * an IPv6 and a hostname all went out. The IP half is exact and
			 * has no false positives. Hostnames are matched only with two or
			 * more labels ending in letters, and the deliberate limit is that
			 * a filename shaped the same way — `wp-config.php` has no
			 * letters-only ending, but something like `readme.html` does not
			 * either — is not what this catches; what it must never do is let
			 * a real host through, and a name it holds back costs a sentence
			 * of context rather than anybody's privacy.
			 */
			if ( 1 === preg_match( '/@|https?:\/\//i', $value ) ) {
				continue;
			}

			if ( false !== filter_var( $value, FILTER_VALIDATE_IP ) ) {
				continue;
			}

			if ( 1 === preg_match( '/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i', $value ) ) {
				continue;
			}

			$value = self::without_addresses( $value, $hosts );

			// Only a value written as a plain number becomes one: a mode such
			// as "0666" is numeric to PHP, and as a number it lost the leading
			// zero that makes it a mode.
			$out[ (string) $key ] = 1 === preg_match( '/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/', $value ) ? $value + 0 : $value;
		}

		if ( strlen( (string) wp_json_encode( $out ) ) > self::MAX_EVIDENCE_BYTES ) {
			return array();
		}

		return $out;
	}

	/**
	 * The names this site is reached by, longest first: its own addresses,
	 * each with and without `www.`, and a domain a finding names for it.
	 *
	 * @param array<string, mixed> $evidence
	 * @return string[]
	 */
	private static function own_hosts( array $evidence ): array {
		$hosts = array();

		foreach ( array( home_url(), site_url(), network_home_url() ) as $url ) {
			$hosts[] = (string) wp_parse_url( $url, PHP_URL_HOST );
		}

		if ( isset( $evidence['domain'] ) && is_string( $evidence['domain'] ) ) {
			$hosts[] = $evidence['domain'];
		}

		$names = array();

		foreach ( $hosts as $host ) {
			$host = strtolower( trim( $host, ". \t\n\r\0\x0B" ) );

			if ( '' === $host ) {
				continue;
			}

			$names[] = $host;
			$names[] = 0 === strpos( $host, 'www.' ) ? substr( $host, 4 ) : 'www.' . $host;
		}

		$names = array_values( array_unique( array_filter( $names ) ) );

		usort(
			$names,
			static function ( string $a, string $b ): int {
				return strlen( $b ) - strlen( $a );
			}
		);

		return $names;
	}

	/**
	 * A value with the addresses inside it replaced.
	 *
	 * Matching an address only when it is the whole value let one written
	 * into a sentence through: the mail-records finding names the site's own
	 * domain in three of its sentences, and other evidence names the network
	 * a request came from. The site's own names are replaced wherever they
	 * appear, and so is anything that is an IP address, IPv4 or IPv6. A host
	 * that is not this site's is left, because a file name is shaped the same
	 * way and the explanation needs it.
	 *
	 * @param string[] $hosts From own_hosts().
	 */
	private static function without_addresses( string $value, array $hosts ): string {
		foreach ( $hosts as $host ) {
			$value = str_ireplace( $host, '[this site]', $value );
		}

		// IPv6 first, so an IPv4 written inside one goes with it. A colon is
		// part of how both are written beside other text ("ip:…", "…:8080",
		// "…: refused"), so a run is trimmed of the colons and dots around it
		// until what is left is an address, or it is left as it was.
		$value = (string) preg_replace_callback(
			'/[0-9a-f:.]*:[0-9a-f:.]*:[0-9a-f:.]*/i',
			static function ( array $match ): string {
				return self::address_in( $match[0] );
			},
			$value
		);

		return (string) preg_replace_callback(
			'/(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?!\w|\.\d)/',
			static function ( array $match ): string {
				return false !== filter_var( $match[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ? '[an address]' : $match[0];
			},
			$value
		);
	}

	/**
	 * A run of hex digits, colons and dots with the IPv6 address in it
	 * replaced, or the run unchanged where there is none.
	 */
	private static function address_in( string $run ): string {
		foreach ( array( $run, rtrim( $run, ':.' ), trim( $run, ':.' ) ) as $candidate ) {
			if ( '' !== $candidate && false !== filter_var( $candidate, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
				$at = (int) strpos( $run, $candidate );

				return substr( $run, 0, $at ) . '[an address]' . substr( $run, $at + strlen( $candidate ) );
			}
		}

		return $run;
	}

	/**
	 * @return array<string, mixed>|null
	 */
	private static function finding( string $key ): ?array {
		foreach ( Auditor::findings() as $finding ) {
			if ( $key === $finding['id'] ) {
				return $finding;
			}
		}

		return null;
	}

	/**
	 * Instrumented locally, and only locally.
	 *
	 * Whether this feature is used at all is the only evidence that will say
	 * whether the larger AI work is worth building, so it is recorded — as an
	 * activity event like every other action, readable by the owner, on their
	 * own site. Nothing is transmitted anywhere: sending usage home would need
	 * a host on the allow-list, a disclosure and an opt-in, none of which
	 * exists yet.
	 */
	private static function record( string $finding_key, bool $succeeded ): void {
		Writer::instance()->record(
			'ai_explanation_generated',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'finding',
				'object_id'   => $finding_key,
				'context'     => array( 'ok' => $succeeded ),
			)
		);
	}

	/**
	 * @return array{available: bool, reason: string, notice: string}
	 */
	private static function unavailable( string $reason, string $notice ): array {
		return array(
			'available' => false,
			'reason'    => $reason,
			'notice'    => $notice,
		);
	}
}
