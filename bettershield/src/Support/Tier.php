<?php
/**
 * Which tier this site is on, and what that changes.
 *
 * The plugin itself is the free tier, whole. A separate add-on, distributed
 * outside the plugin directory, may say the site is on a paid tier; it does
 * so through one filter, answered on every request and never cached as
 * truth. This plugin holds no license, calls no license server, and nothing
 * in it is locked, limited or switched on by the tier: the answer decides
 * only whether the plugin's own screens mention the add-on.
 *
 * How long the activity log is kept is a plain filter any code may answer,
 * read on every request and clamped to a range. **Every read is clamped to
 * what it answers now**: a filter that widened the log to ninety days and
 * then went away must not keep returning ninety days of history that is
 * physically present. The one exception is the grace an update brings
 * (`Database\RetentionGrace`): for thirty days the window is never shorter
 * than what the site had on disk when it updated.
 *
 * The pruners follow a window that shrinks a month later: for thirty days
 * after a longer one was last answered they keep to it
 * (`Database\RetentionHold`), so the rows wait on disk rather than being
 * shown, and a retention that comes back finds them.
 *
 * The add-on's absence, deactivation or lapse changes nothing here but the
 * mention: nothing breaks, nothing nags. Anything the add-on configured is
 * kept as data, so coming back restores it.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

use BetterShield\Database\Pruner;
use BetterShield\Database\RetentionGrace;
use BetterShield\Database\RetentionHold;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Tier {

	public const FREE  = 'free';
	public const ULTRA = 'ultra';

	/**
	 * The longest the activity log may be kept, in days: a year, for an
	 * add-on that offers it. The default lives with the pruner, and the
	 * seals are kept as long as this (`Events\Seal::max_days()`).
	 */
	public const RETENTION_DAYS_MAX = 365;

	/**
	 * Where the paid tier can be read about. A plain link the owner may
	 * follow from this plugin's own screens; nothing is requested from it,
	 * and while it is empty nothing anywhere mentions a paid tier.
	 */
	private const OFFER_URL = 'https://bettershield.ai/ultra';

	/**
	 * The tier this request is served at.
	 */
	public static function current(): string {
		/**
		 * The tier this site is on. A paid add-on answers 'ultra' while it
		 * is active; anything else is the free tier.
		 *
		 * @param string $tier 'free' by default.
		 */
		$tier = apply_filters( 'bettershield_tier', self::FREE );

		return self::ULTRA === $tier ? self::ULTRA : self::FREE;
	}

	public static function is_ultra(): bool {
		return self::ULTRA === self::current();
	}

	/**
	 * How far back the activity log reaches — for every read of the log, and
	 * for the alert-precision window. The pruners keep to `kept_days()`.
	 */
	public static function retention_days(): int {
		// Never shorter than what an update found kept, while its grace lasts.
		return max( self::answered_days(), RetentionGrace::days( 'activity' ) );
	}

	/**
	 * How far back the activity log is kept on disk: the window it is read
	 * in, or a longer one the filter answered within the last thirty days
	 * (`Database\RetentionHold`). The pruners delete to this, and what the
	 * plugin says it keeps about people is measured by it; nothing reads the
	 * log this far.
	 */
	public static function kept_days(): int {
		return max( self::retention_days(), RetentionHold::days( 'activity', self::answered_days() ) );
	}

	/**
	 * The oldest moment a read of the log may return, as the log stores it.
	 */
	public static function retention_floor(): string {
		return self::floor_of( self::retention_days() );
	}

	/**
	 * The oldest moment the pruners leave on disk, as the log stores it.
	 */
	public static function kept_floor(): string {
		return self::floor_of( self::kept_days() );
	}

	/**
	 * Write down what the filter answers now, for a pruner about to delete by
	 * it. The one write here; everything else in this class only reads.
	 */
	public static function note_retention(): void {
		RetentionHold::note( 'activity', self::answered_days() );
	}

	/**
	 * What the filter answers, held to its range.
	 */
	private static function answered_days(): int {
		/**
		 * How many days the activity log is kept, from thirty to 365.
		 * Anything outside that range is held to its nearer end.
		 *
		 * @param int $days Thirty by default.
		 */
		$days = (int) apply_filters( 'bettershield_activity_retention_days', Pruner::RETENTION_DAYS );

		return max( Pruner::RETENTION_DAYS, min( self::RETENTION_DAYS_MAX, $days ) );
	}

	private static function floor_of( int $days ): string {
		return ( new \DateTimeImmutable( '-' . $days . ' days', new \DateTimeZone( 'UTC' ) ) )->format( 'Y-m-d H:i:s.v' );
	}

	/**
	 * What the interface may say about a paid tier, on the plugin's own
	 * screens only: null while there is nothing to point at, or when the
	 * site is already on it. Never inside a finding, an alert or a warning.
	 *
	 * @return array{name: string, url: string, summary: string, adds: list<string>}|null
	 */
	public static function offer(): ?array {
		if ( '' === self::OFFER_URL || self::is_ultra() ) {
			return null;
		}

		return array(
			'name'    => 'BetterShield Ultra',
			'url'     => self::OFFER_URL,
			'summary' => __( 'BetterShield Ultra is for people who look after sites for others. BetterShield works in full without it.', 'bettershield' ),
			// What a customer can use in the released BetterShield Ultra, the
			// same facts as the readme's Ultra section: nothing that cannot run yet.
			'adds'    => array(
				__( 'Two-factor enrollment at sign-in, with reminders and a grace period', 'bettershield' ),
				__( 'Trusted devices and a passkey policy', 'bettershield' ),
				__( 'A per-role report of who has two-factor', 'bettershield' ),
				__( 'Your branding on the two-factor screens', 'bettershield' ),
				__( 'Alerts by email plus Slack, Microsoft Teams, Google Chat, Discord, a JSON webhook or syslog', 'bettershield' ),
				__( 'One help desk ticket per incident', 'bettershield' ),
				__( 'Incident pages in PagerDuty or Opsgenie and events streamed to Splunk, Datadog or Elastic, on WordPress 7.0 or newer', 'bettershield' ),
				__( 'Scheduled client reports', 'bettershield' ),
				__( 'Temporary access that ends on its own', 'bettershield' ),
				__( 'Cloudflare controls', 'bettershield' ),
				__( 'Hourly check of key site files', 'bettershield' ),
				__( 'Explanations with no hourly limit', 'bettershield' ),
				__( 'Ninety days of activity history', 'bettershield' ),
			),
		);
	}
}
