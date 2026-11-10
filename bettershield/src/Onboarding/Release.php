<?php
/**
 * What an update added, and that none of it is switched on.
 *
 * Almost everything this plugin ships arrives off. Several features write to
 * people who are not the site's administrator, or add a requirement nobody
 * asked for, and a plugin that starts doing either on an update is a plugin
 * people uninstall. Shipping everything off is only half of that: without a
 * panel, the only people who learn it are the ones who read release notes.
 * Somebody on auto-update received fourteen new capabilities and was told
 * nothing at all: not that they arrived, not that they were off, and not that
 * either was on purpose.
 *
 * **The headline is the whole point, so it has to be true.** "This update
 * added six things. None of them is switched on." A feature that ever ships on
 * by default has to be stated first and plainly, and until then the suite
 * fails if a listed feature's own default is not off — a stale list here is
 * worse than no panel, because it is a promise about somebody's site.
 *
 * **Once, per version, per person, and gone when dismissed.** A panel that
 * came back after every update would be a nag, and nothing here may fill a
 * dashboard. What keeps it on the right side of that line is that it appears
 * once, sells nothing, and its headline is reassurance rather than a demand.
 * If that ever stops being true, this should be removed rather than softened.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Onboarding;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Release {

	/** The version this site was running before the current one. */
	public const CAME_FROM = 'bettershield_previous_version';

	/** Which version's panel each person has dismissed. */
	private const DISMISSED_META = 'bettershield_release_seen';

	/**
	 * What each release added, and what switching it on would change.
	 *
	 * Written by hand every release, which is the cost of it. `on_by_default`
	 * is the field that keeps the headline honest: it is asserted against the
	 * feature's real default in the suite, so a line here that claims
	 * something untrue about somebody's site fails the build.
	 *
	 * @return array<string, array<int, array{id: string, title: string, what: string, changes: string, on_by_default: bool}>>
	 */
	public static function manifest(): array {
		return array(
			// Nothing new switches itself on, or asks to be, with this update.
			'1.1.7' => array(),
			// Nothing new switches itself on, or asks to be, with this update.
			'1.1.6' => array(),
			// Nothing new switches itself on, or asks to be, with this update.
			'1.1.5' => array(),
			// Nothing new switches itself on, or asks to be, with this update.
			'1.1.4' => array(),
			// Nothing new switches itself on, or asks to be, with this update.
			'1.1.3' => array(),
			'1.1.2' => array(
				array(
					'id' => 'vulnerability_intelligence',
					'title' => __( 'Check for known security holes', 'bettershield' ),
					'source' => 'vulnerability_checks',
					'setting' => 'enabled',
					'what' => __( 'Checking WordPress, plugin and theme versions against known vulnerabilities.', 'bettershield' ),
					'changes' => __( 'Off until you turn it on in Settings. It sends your plugin, theme and WordPress names and versions to hub.bettershield.ai, daily and after updates. No account or key needed.', 'bettershield' ),
					'on_by_default' => false,
				),
			),
			'1.1.1' => array(
				array(
					/*
					 * First, as the panel's rule asks of anything on by default,
					 * and on from the update itself: the request it refuses is
					 * one nothing sends on purpose, and the time to find out a
					 * plugin was reaching for the server's credentials is
					 * before it does it again.
					 */
					'id'            => 'cloud_metadata',
					'title'         => __( 'Block plugins from reading server secrets', 'bettershield' ),
					'source'        => 'hardening',
					'setting'       => 'cloud_metadata',
					'what'          => __( 'Stops plugins from reaching addresses on cloud servers that hold passwords.', 'bettershield' ),
					'changes'       => __( 'On after this update; the activity log names each plugin refused. If a plugin needs an address, let it through in Protection › Hardening, or switch this off.', 'bettershield' ),
					'on_by_default' => true,
				),
				array(
					'id'            => 'hub_link',
					'title'         => __( 'Send security events to BetterShield Hub', 'bettershield' ),
					'source'        => 'hub_link',
					'setting'       => 'enabled',
					'what'          => __( 'Sending this site’s security events, and a regular “still online” check, to BetterShield Hub.', 'bettershield' ),
					'changes'       => __( 'Off until turned on in BetterShield › Hub, once connected to hub.bettershield.ai. Its signing key never leaves this site.', 'bettershield' ),
					'on_by_default' => false,
				),
				array(
					'id'            => 'host_ban_line',
					'title'         => __( 'Tell your server’s firewall about lockouts', 'bettershield' ),
					'source'        => 'protection',
					'setting'       => 'host_ban_line',
					'what'          => __( 'Letting your server’s firewall block visitors BetterShield locks out (for hosts that use Fail2Ban).', 'bettershield' ),
					'changes'       => __( 'Off until turned on in Protection › Login & Access. The line names only the network, never a full address or account.', 'bettershield' ),
					'on_by_default' => false,
				),
			),
			'1.1.0' => array(
				array(
					/*
					 * First in the list because the panel's own rule is that a
					 * feature which ships on by default has to be stated
					 * first and plainly. This one runs for visitors from the
					 * moment the update lands, without anybody choosing it.
					 */
					'id'            => 'request_protection',
					'title'         => __( 'Slow down comment, reset and sign-up floods', 'bettershield' ),
					'source'        => 'protection',
					'setting'       => 'surfaces',
					'what'          => __( 'Counting repeated comments, password-reset requests and sign-ups from one connection.', 'bettershield' ),
					'changes'       => __( 'On after this update. Extra comments go to moderation; repeated resets and sign-ups are slowed. Manage in Protection › Login & Access.', 'bettershield' ),
					'on_by_default' => true,
				),
				array(
					'id'            => 'assistant_connection',
					'title'         => __( 'Connect an AI assistant', 'bettershield' ),
					'source'        => 'mcp',
					'setting'       => 'enabled',
					'what'          => __( 'Letting an assistant such as Claude act on this site.', 'bettershield' ),
					/*
					 * The one switch 1.1 adds that changes who can reach the
					 * site. The Agents section carries the rest of the
					 * decisions (reading, changing, which credential) on the
					 * same strip, so the panel names the door and points at
					 * the room.
					 */
					'changes'       => __( 'Off until you turn it on in Agents.', 'bettershield' ),
					'on_by_default' => false,
				),
			),
			'1.0.0' => array(
				array(
					'id'            => 'cloudflare',
					'title'         => __( 'Confirm Cloudflare', 'bettershield' ),
					'source'        => 'protection',
					'setting'       => 'cloudflare',
					'what'          => __( 'Confirming this site is behind Cloudflare, so lockouts apply to the visitor, not Cloudflare’s address.', 'bettershield' ),
					/*
					 * The one switchable thing this release adds. Everything
					 * else it changed is a correction or a screen somebody
					 * reads, and a panel that listed those would be a list of
					 * work rather than a list of decisions somebody has to make.
					 */
					'changes'       => __( 'Until you confirm, a request from Cloudflare counts against Cloudflare’s address and the visitor address it claims.', 'bettershield' ),
					'on_by_default' => false,
				),
			),
			/*
			 * A release that added nothing switchable still gets an entry. The
			 * suite requires the running version to appear, or a release cut
			 * without anybody remembering this file would silently have no
			 * panel and nothing would say why — so an empty list is how a
			 * release says "nothing of yours changed", and `panel()` shows
			 * nobody anything, which is the truth of it.
			 */
			'0.7.0' => array(),
			'0.6.0' => array(),
			'0.5.0' => array(
				array(
					'id'            => 'agent_recording',
					'title'         => __( 'Record what AI assistants do', 'bettershield' ),
					'source'        => 'agent_capture',
					'setting'       => 'recording',
					'what'          => __( 'A record of every action AI assistants and other tools take on this site.', 'bettershield' ),
					/*
					 * The first shipped feature that arrives switched on, and
					 * the panel has to say so rather than let a reader assume
					 * this release changed nothing about their site. The
					 * reasoning is the feature's own: a record nobody switched
					 * on is the only kind that is there when something happens.
					 */
					'changes'       => __( 'This is already on. Switch it off in Agents › Permissions.', 'bettershield' ),
					'on_by_default' => true,
				),
				array(
					'id'            => 'passkey_only',
					'title'         => __( 'Passkey-only sign-in', 'bettershield' ),
					'source'        => 'passkeys',
					'setting'       => 'roles',
					'what'          => __( 'Passkey-only sign-in for a role: passwords are refused.', 'bettershield' ),
					'changes'       => __( 'It needs a working recovery link or recovery codes first.', 'bettershield' ),
					'on_by_default' => false,
				),
				array(
					'id'            => 'app_password_expiry',
					'title'         => __( 'Turn off unused app passwords', 'bettershield' ),
					'source'        => 'agent_keys',
					'setting'       => 'enabled',
					'what'          => __( 'Turning off app passwords (used by apps and tools) that haven’t been used in a long time.', 'bettershield' ),
					'changes'       => __( 'Passwords still in use are never retired, and each retirement is logged by name.', 'bettershield' ),
					'on_by_default' => false,
				),
			),
			'0.4.0' => array(
				array(
					'id'            => 'proof_of_work',
					'title'         => __( 'Sign-in puzzle', 'bettershield' ),
					'source'        => 'protection',
					'setting'       => 'proof_of_work',
					'what'          => __( 'A sign-in puzzle after repeated wrong passwords.', 'bettershield' ),
					'changes'       => __( 'It needs JavaScript and slows anyone trying many passwords. An unsolved puzzle never extends a lockout.', 'bettershield' ),
					'on_by_default' => false,
				),
				array(
					'id'            => 'two_factor_required',
					'title'         => __( 'Require two-factor', 'bettershield' ),
					'source'        => 'two_factor',
					'setting'       => 'roles',
					'what'          => __( 'Requiring two-factor for a role, with a grace period.', 'bettershield' ),
					'changes'       => __( 'It applies in the dashboard, never at sign-in, so it cannot lock anyone out. Off until you choose a role.', 'bettershield' ),
					'on_by_default' => false,
				),
				array(
					'id'            => 'new_location_notice',
					'title'         => __( 'New sign-in location emails', 'bettershield' ),
					'source'        => 'protection',
					'setting'       => 'new_location_notice',
					'what'          => __( 'Emailing account holders who sign in from an unfamiliar network.', 'bettershield' ),
					'changes'       => __( 'It emails people other than the administrator, so it is off by default.', 'bettershield' ),
					'on_by_default' => false,
				),
			),
			'0.2.0' => array(
				array(
					'id'            => 'idle_minutes',
					'title'         => __( 'Sign out when idle', 'bettershield' ),
					'source'        => 'protection',
					'setting'       => 'idle_minutes',
					'what'          => __( 'Signing people out after a period of inactivity.', 'bettershield' ),
					'changes'       => __( 'It signs you out too. Set zero to turn it off.', 'bettershield' ),
					'on_by_default' => false,
				),
				array(
					'id'            => 'session_cap',
					'title'         => __( 'Limit sign-ins per account', 'bettershield' ),
					'source'        => 'protection',
					'setting'       => 'session_cap',
					'what'          => __( 'Limiting how many sessions one account can have at once.', 'bettershield' ),
					'changes'       => __( 'Above the limit, the oldest session signs out. Zero means no limit.', 'bettershield' ),
					'on_by_default' => false,
				),
			),
		);
	}

	/**
	 * The registries a manifest entry may name.
	 *
	 * Named rather than merged. Several of these carry a setting called
	 * `enabled` and two carry one called `roles`, so a flat merge would have
	 * one feature's answer stand in for another's — and the reader would be
	 * told about their site from somebody else's setting.
	 */
	private const SOURCES = array(
		'protection' => \BetterShield\Login\Protection::class,
		'password'   => \BetterShield\Password\Policy::class,
		'passkeys'   => \BetterShield\Passkeys\Policy::class,
		'two_factor' => \BetterShield\TwoFactor\Policy::class,
		'agent_keys' => \BetterShield\Agents\Expiry::class,
		'agent_capture' => \BetterShield\Agents\Capture::class,
		'mcp'        => \BetterShield\Mcp\Manager::class,
	);

	/**
	 * One feature's value, as this site has it now.
	 *
	 * Public because the suite asks the same question of a site with nothing
	 * stored, which is what the shipped default is.
	 *
	 * @param array<string, mixed> $feature
	 * @return mixed Null where the entry names something that is not a setting.
	 */
	public static function live_value( array $feature ) {
		$source = (string) ( $feature['source'] ?? '' );

		// The Hub link keeps its state in its own record, not a settings
		// array: on is whether it is sending.
		if ( 'hub_link' === $source ) {
			return \BetterShield\Hub\Link\Link::is_on();
		}

		if ( 'vulnerability_checks' === $source ) {
			return \BetterShield\Vulnerabilities\Scanner::consented();
		}

		// A hardening item's setting is whether it is applied here.
		if ( 'hardening' === $source ) {
			$item = (string) ( $feature['setting'] ?? $feature['id'] ?? '' );

			return in_array( $item, \BetterShield\Hardening\Items::ids(), true ) ? \BetterShield\Hardening\Manager::instance()->is_active( $item ) : null;
		}

		if ( ! isset( self::SOURCES[ $source ] ) ) {
			return null;
		}

		$class = self::SOURCES[ $source ];

		// Most of these are singletons; the credential sweep is a plain class
		// with no shared state to hold. Either way what is wanted is one read
		// of the settings it owns.
		$object   = method_exists( $class, 'instance' ) ? $class::instance() : new $class();
		$settings = $object->settings();
		$setting  = (string) ( $feature['setting'] ?? $feature['id'] ?? '' );

		return array_key_exists( $setting, $settings ) ? $settings[ $setting ] : null;
	}

	/**
	 * Off, as every one of these settings expresses it: a switch that is
	 * false, a number that is zero, or a list nobody has put anything in.
	 *
	 * @param mixed $value
	 */
	private static function reads_as_off( $value ): bool {
		return false === $value || 0 === $value || '' === $value || array() === $value;
	}

	/**
	 * What to show whoever is reading, or null.
	 *
	 * @return array{from: string, to: string, features: array<int, array<string, mixed>>}|null
	 */
	public static function panel(): ?array {
		$to   = (string) ( defined( 'BETTERSHIELD_VERSION' ) ? BETTERSHIELD_VERSION : '' );
		$from = (string) get_option( self::CAME_FROM, '' );

		// A fresh install has no previous version, and first-run already owns
		// that moment. A stored version ahead of the running one is a
		// downgrade or a reinstall, where a negative diff is not a story.
		if ( '' === $from || '' === $to || version_compare( $from, $to, '>=' ) ) {
			return null;
		}

		if ( self::dismissed( $to ) ) {
			return null;
		}

		$features = self::between( $from, $to );

		if ( array() === $features ) {
			return null;
		}

		/*
		 * What is actually switched on here, now. `on_by_default` is a shipped
		 * constant describing the release, and the panel was rendering it as a
		 * present-tense claim about this site — so a reader who had switched
		 * something on was told none of it was, in the same sentence that
		 * invited them to go and switch it on.
		 */
		foreach ( $features as $index => $feature ) {
			$value                       = self::live_value( $feature );
			$features[ $index ]['is_on'] = null !== $value && ! self::reads_as_off( $value );
		}

		return array(
			'from'     => $from,
			'to'       => $to,
			'features' => $features,
		);
	}

	/**
	 * Everything added after the version this site was on, up to this one.
	 *
	 * Every release in between, not only the newest — somebody who updates
	 * twice a year skips several, and the commonest case in the wild is the
	 * one a newest-release-only panel would get wrong.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function between( string $from, string $to ): array {
		$features = array();

		foreach ( self::manifest() as $version => $added ) {
			if ( version_compare( (string) $version, $from, '>' ) && version_compare( (string) $version, $to, '<=' ) ) {
				foreach ( $added as $feature ) {
					$features[] = $feature;
				}
			}
		}

		return $features;
	}

	/**
	 * Whether this person has already seen this version's panel.
	 *
	 * Per person, not per site: a second administrator who never saw it has
	 * not been told anything.
	 */
	public static function dismissed( string $version ): bool {
		$seen = get_user_meta( get_current_user_id(), self::DISMISSED_META, true );

		return is_string( $seen ) && '' !== $seen && version_compare( $seen, $version, '>=' );
	}

	public static function dismiss( string $version ): void {
		if ( get_current_user_id() > 0 ) {
			update_user_meta( get_current_user_id(), self::DISMISSED_META, $version );
		}
	}

	/**
	 * Forget how far one person had read.
	 *
	 * Harmless on its own and still a record about somebody, so it goes when
	 * they ask to be forgotten. The cost of being wrong is that they are shown
	 * a panel they had already dismissed.
	 */
	public static function forget( int $user_id ): void {
		delete_user_meta( $user_id, self::DISMISSED_META );
	}

	/**
	 * Record where this site came from, when the running version has moved.
	 *
	 * `bettershield_version` was written only on activation, which an update
	 * does not call — so it read 0.2.0 on a site running 0.4.0, and there was
	 * no "came from" for anything to compare against. Nothing read it, which
	 * is why nobody noticed.
	 *
	 * Called from the same admin-side gate the schema migration uses, for the
	 * same reason: an update lands without a re-activation, and the first
	 * authenticated admin request afterwards is where a site catches up with
	 * itself.
	 */
	public static function note_version(): bool {
		$running = (string) ( defined( 'BETTERSHIELD_VERSION' ) ? BETTERSHIELD_VERSION : '' );
		$stored  = (string) get_option( 'bettershield_version', '' );

		if ( '' === $running || $stored === $running ) {
			return false;
		}

		// Only forward. A downgrade leaves the previous marker alone rather
		// than recording a version this site is no longer coming from.
		if ( '' !== $stored && version_compare( $stored, $running, '<' ) ) {
			update_option( self::CAME_FROM, $stored, false );
		}

		update_option( 'bettershield_version', $running, false );

		return true;
	}
}
