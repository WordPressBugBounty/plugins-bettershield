<?php
/**
 * The areas a finding can belong to.
 *
 * Grouping is by the part of the site a finding is about, not by the mechanism
 * that discovered it. That distinction is deliberate: which subsystem produced
 * a row is our vocabulary, and nobody opens a security screen wondering whether
 * the audit engine or a data feed found something. They ask whether their users
 * are safe, or whether their server is current.
 *
 * The set is small and closed on purpose. Five areas over thirty-odd checks keeps
 * every group worth clicking; a group of one is a sign the area is wrong rather
 * than that another is needed.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Areas {

	/** Who can get in, and as whom. */
	public const ACCESS = 'access';

	/** What the site volunteers to a stranger. */
	public const EXPOSURE = 'exposure';

	/** The machine underneath, and what the host controls. */
	public const SERVER = 'server';

	/** How this installation was set up. */
	public const CONFIGURATION = 'configuration';

	/** Code that arrived from somewhere else, and how current it is. */
	public const EXTENSIONS = 'extensions';

	/**
	 * This plugin's own doing. Only the activity log produces these — an audit
	 * reports on the site, not on the thing auditing it.
	 */
	public const PLUGIN = 'plugin';

	/**
	 * In display order, which is the order the chips appear in. Access first
	 * because an account is the thing most attacks are actually after, and the
	 * plugin's own actions last because they are the least surprising thing in
	 * any list they appear in.
	 *
	 * The vocabulary is shared across screens on purpose: Access has to mean
	 * the same thing on a report as it does on a log, or the chips teach two
	 * languages. Each surface uses the subset it can actually produce.
	 *
	 * Translated, so this must not be called before init.
	 *
	 * @return array<string, string>
	 */
	public static function all(): array {
		return array(
			self::ACCESS        => __( 'Sign-in & accounts', 'bettershield' ),
			self::EXPOSURE      => __( 'Public information about your site', 'bettershield' ),
			self::SERVER        => __( 'Server', 'bettershield' ),
			self::CONFIGURATION => __( 'Site settings', 'bettershield' ),
			self::EXTENSIONS    => __( 'Updates & extensions', 'bettershield' ),
			/* translators: %s: the plugin's name, or the label the site owner gave it. */
			self::PLUGIN        => sprintf( __( '%s itself', 'bettershield' ), \BetterShield\Support\Branding::name() ),
		);
	}

	public static function exists( string $slug ): bool {
		return isset( self::all()[ $slug ] );
	}

	/**
	 * Label a set of area slugs, in the canonical order and with unknown ones
	 * dropped.
	 *
	 * Callers pass the areas their own surface can actually produce, derived
	 * from their own registry rather than written out again here — a chip for
	 * an area that can never have anything in it is a permanent zero, and a
	 * second hand-maintained list is a second thing to forget to update.
	 *
	 * @param string[] $slugs
	 * @return array<int, array{slug: string, label: string}>
	 */
	public static function label_list( array $slugs ): array {
		$out = array();

		foreach ( self::all() as $slug => $label ) {
			if ( in_array( $slug, $slugs, true ) ) {
				$out[] = array(
					'slug'  => $slug,
					'label' => $label,
				);
			}
		}

		return $out;
	}
}
