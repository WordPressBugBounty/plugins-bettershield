<?php
/**
 * The plugin's configuration as one versioned JSON document: exported from a
 * site that is set up the way an operator wants, imported into the next.
 *
 * Two rules hold the design together. An import is always planned before it
 * is applied, and the plan is computed by the same validators the apply will
 * run — so what the operator reads is what will happen, refusals included.
 * And an import applies through the same per-item path the dashboard uses:
 * every hardening item passes its availability check, its option validation
 * and its conflict probe, and every setting passes its validator. No import
 * bypasses anything, and every change lands in the activity log.
 *
 * **What it does not do is ledger the import as one act.** Hardening items go
 * through `Manager::apply()` and `revert()`, and each settings section is
 * applied by calling its own validator, exactly as saving that screen would —
 * so each writes the undo record that save would write, and every change an
 * import makes can be put back individually. What has no record of its own is
 * the import: there is no one way back from all of it at once, and this is the
 * only place that changes several settings in a single act.
 *
 * What the document carries: hardening state and options, the password
 * policy, login protection (thresholds, lists, proxies, sessions, honeypot),
 * the agent read opt-in, whether agent activity is recorded, when an unused
 * application password is retired, the uninstall choice, and how alerting is
 * configured — and, under `sections`, the settings an add-on declared to the
 * undo ledger as portable, each with the way back that ledger gives it.
 * What it never carries: anything per-user (two-factor enrollments, sessions),
 * any secret (the recovery link, key material, address digests), list
 * authorship — the importer is the author of what they import — and alert
 * recipients, which belong to the site they were typed on rather than to the
 * configuration being copied.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Operator;

// Above the imports, not below them: the plugin checker reads only the first
// fifty lines looking for this, and an import list that grows past that line
// takes the guard with it and has the file reported as unguarded.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use BetterShield\Abilities\Registrar;
use BetterShield\Agents\Capture;
use BetterShield\Agents\Expiry;
use BetterShield\Alerts\Settings as AlertSettings;
use BetterShield\Audit\Auditor;
use BetterShield\Disclosure\SecurityTxt;
use BetterShield\Events\Writer;
use BetterShield\Hardening\Item\LoginUrl;
use BetterShield\Hardening\Items;
use BetterShield\Hardening\Manager;
use BetterShield\Login\Protection;
use BetterShield\Network\Policies as NetworkPolicies;
use BetterShield\Passkeys\Policy as PasskeyPolicy;
use BetterShield\Password\Policy;
use BetterShield\Recovery\Preflight;
use BetterShield\Rest\Permissions;
use BetterShield\Support\UninstallChoice;
use BetterShield\TwoFactor\Policy as TwoFactorPolicy;
use BetterShield\Undo\SettingsLedger;

final class SettingsDocument {

	public const FORMAT  = 'bettershield-settings';
	public const VERSION = 1;

	/**
	 * The current configuration as a document. Recorded, because a document
	 * carries the blocklists and the sign-in address — not secrets, but a
	 * description of the site's defenses that someone chose to take away.
	 *
	 * @return array<string, mixed>
	 */
	public static function export(): array {
		$manager   = Manager::instance();
		$hardening = array();

		foreach ( Items::ids() as $item ) {
			$state = $manager->item_state( $item );

			$hardening[ $item ] = array(
				'active'  => ! empty( $state['active'] ),
				'options' => isset( $state['options'] ) && is_array( $state['options'] ) && array() !== $state['options']
					? $state['options']
					: new \stdClass(),
			);
		}

		$document = array(
			'format'           => self::FORMAT,
			'version'          => self::VERSION,
			'exported_at'      => gmdate( 'c' ),
			'plugin_version'   => defined( 'BETTERSHIELD_VERSION' ) ? BETTERSHIELD_VERSION : '',
			'hardening'        => $hardening,
			'password_policy'  => Policy::instance()->settings(),
			'login_protection' => self::portable_login_protection( Protection::instance()->settings() ),
			'abilities'        => array( 'enabled' => Registrar::is_enabled() ),
			/*
			 * Both fields, and they answer different questions: whether
			 * anything is removed at all, and what happens to the quarantined
			 * copies on the way out. A document written before there was a
			 * third answer carries only the first, and still reads correctly —
			 * which is why the boolean stays rather than being replaced.
			 */
			'uninstall'        => array(
				'remove_data' => UninstallChoice::remove_data(),
				'choice'      => UninstallChoice::choice(),
			),
			'sudo'             => array( 'enabled' => \BetterShield\Rest\Sudo::enabled() ),
			'alerts'           => self::portable_alerts( AlertSettings::instance()->settings() ),
			/*
			 * The access policies. Absent until now, which made this document
			 * quietly the wrong shape for the thing it exists for: an agency
			 * carrying a hardened posture to the next client site got the
			 * hardening, the password rules and the alerts, and neither of the
			 * two strongest access controls in the plugin.
			 *
			 * The lockdown is deliberately NOT here. It is a statement about
			 * one site at one moment — "this site is under attack right now" —
			 * and carrying it to another site would close a site nobody had
			 * decided to close.
			 */
			// Without the chosen page: its ID means nothing on another site.
			'two_factor_policy' => array_diff_key( TwoFactorPolicy::instance()->settings(), array( 'account_page' => 0 ) ),
			'passkey_policy'    => PasskeyPolicy::instance()->settings(),
			'security_txt'      => SecurityTxt::instance()->settings(),
			/*
			 * How the site treats the credentials agents authenticate with, and
			 * whether what they do is recorded at all. Both are posture rather
			 * than local history, which is what this document carries.
			 */
			'agent_capture'       => Capture::settings(),
			'app_password_expiry' => ( new Expiry() )->settings(),
		);

		/*
		 * An add-on's own settings, each under the name it gave the undo
		 * ledger. Present only where there is one, so a document from a site
		 * without an add-on is exactly the document it always was.
		 */
		$sections = array();

		foreach ( SettingsLedger::portable() as $name => $surface ) {
			$section = ( $surface['export'] )();

			if ( is_array( $section ) ) {
				$sections[ $name ] = $section;
			}
		}

		if ( array() !== $sections ) {
			$document['sections'] = $sections;
		}

		Writer::instance()->record(
			'settings_exported',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'settings',
				'context'     => array( 'version' => self::VERSION ),
			)
		);

		return $document;
	}

	/**
	 * What importing a document would do, computed without doing any of it.
	 *
	 * @param array<string, mixed> $document
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function plan( array $document ) {
		return LoginUrl::for_document( $document, static fn() => self::planned( $document ) );
	}

	/**
	 * @param array<string, mixed> $document
	 * @return array<string, mixed>|\WP_Error
	 */
	private static function planned( array $document ) {
		$checked = self::check_document( $document );
		if ( is_wp_error( $checked ) ) {
			return $checked;
		}

		$manager = Manager::instance();
		$rows    = array();
		$changes = 0;

		/*
		 * A section the file names in a shape nothing here reads — a string
		 * or number where settings belong, or a bare list — is said as that,
		 * not skipped without a row (#2249). Skipped, a hand-edited file read
		 * as "Nothing to Change", and a list read as "already matches".
		 */
		$unreadable = array();
		$sections   = array(
			'hardening'           => __( 'Hardening', 'bettershield' ),
			'password_policy'     => __( 'Password policy', 'bettershield' ),
			'login_protection'    => __( 'Login protection', 'bettershield' ),
			'two_factor_policy'   => __( 'Two-factor requirement', 'bettershield' ),
			'passkey_policy'      => __( 'Passkey-only sign-in', 'bettershield' ),
			'security_txt'        => __( 'Security contact (security.txt)', 'bettershield' ),
			'agent_capture'       => __( 'Recording agent activity', 'bettershield' ),
			'app_password_expiry' => __( 'Retiring unused application passwords', 'bettershield' ),
			'abilities'           => __( 'Agent read access', 'bettershield' ),
			'uninstall'           => __( 'When BetterShield is deleted', 'bettershield' ),
			'sudo'                => __( 'Password confirmation', 'bettershield' ),
			'alerts'              => __( 'Alerts', 'bettershield' ),
		);

		foreach ( $sections as $section => $title ) {
			if ( ! array_key_exists( $section, $document ) || self::readable( $document[ $section ] ) ) {
				continue;
			}

			$unreadable[] = array(
				'section' => $section,
				'title'   => $title,
				'action'  => 'invalid',
				'note'    => __( 'This part of the file is not in the expected format, so it is left out.', 'bettershield' ),
				'changes' => new \stdClass(),
			);

			// Gone from this copy, so no reading below can take it for settings.
			unset( $document[ $section ] );
		}

		if ( isset( $document['hardening'] ) && is_array( $document['hardening'] ) ) {
			$known = Items::all();

			foreach ( $document['hardening'] as $item => $wanted ) {
				$item    = (string) $item;
				$wanted  = is_array( $wanted ) ? $wanted : array();
				$active  = rest_sanitize_boolean( $wanted['active'] ?? false );
				$options = isset( $wanted['options'] ) && is_array( $wanted['options'] ) ? $wanted['options'] : array();

				if ( ! isset( $known[ $item ] ) ) {
					$rows[] = self::hardening_row( $item, $item, null, $active, 'unknown', __( 'This version has no such item.', 'bettershield' ) );
					continue;
				}

				$title   = (string) $known[ $item ]['title'];
				$current = $manager->is_active( $item );

				$handler = Items::handlers()[ $item ] ?? null;

				/*
				 * On at both ends is a match only when the settings match too.
				 * An item that takes settings and is on here with others is
				 * undone and applied again with the file's, so the plan says so
				 * and counts it. A file that names no settings for it has no
				 * opinion on them.
				 */
				if ( $current && $active && array() !== $options && null !== $handler && method_exists( $handler, 'validate' ) ) {
					$valid = $handler::validate( $options );

					if ( is_wp_error( $valid ) ) {
						$rows[] = self::hardening_row( $item, $title, $current, $active, 'invalid', $valid->get_error_message() );
						continue;
					}

					$here = $manager->item_state( $item )['options'] ?? array();

					if ( ! self::same_options( $valid, is_array( $here ) ? $here : array() ) ) {
						$probe = $manager->dry_run( $item, $valid );

						$row                     = self::hardening_row( $item, $title, $current, $active, 'reconfigure', __( 'On here with different settings. It will be reapplied with this file’s settings.', 'bettershield' ) );
						$row['options']          = $valid;
						$row['conflict_warning'] = is_wp_error( $probe ) ? null : $probe['conflict_warning'];
						$rows[]                  = $row;
						++$changes;
						continue;
					}
				}

				if ( $current === $active ) {
					$rows[] = self::hardening_row( $item, $title, $current, $active, 'keep', null );
					continue;
				}

				if ( ! $active ) {
					$rows[] = self::hardening_row( $item, $title, $current, $active, 'revert', null );
					++$changes;
					continue;
				}

				$probe = $manager->dry_run( $item );
				if ( is_wp_error( $probe ) ) {
					$rows[] = self::hardening_row( $item, $title, $current, $active, 'invalid', $probe->get_error_message() );
					continue;
				}

				if ( ! $probe['available'] ) {
					$rows[] = self::hardening_row( $item, $title, $current, $active, 'unavailable', (string) $probe['availability_note'], (string) $probe['availability_label'] );
					continue;
				}

				if ( null !== $handler && method_exists( $handler, 'validate' ) ) {
					$valid = $handler::validate( $options );
					if ( is_wp_error( $valid ) ) {
						$rows[] = self::hardening_row( $item, $title, $current, $active, 'invalid', $valid->get_error_message() );
						continue;
					}
					$options = $valid;
				} else {
					$options = array();
				}

				$row                     = self::hardening_row( $item, $title, $current, $active, 'apply', null );
				$row['options']          = array() === $options ? new \stdClass() : $options;
				$row['conflict_warning'] = $probe['conflict_warning'];
				$rows[]                  = $row;
				++$changes;
			}
		}

		$settings = $unreadable;

		if ( isset( $document['password_policy'] ) && is_array( $document['password_policy'] ) ) {
			$settings[] = self::settings_row(
				'password_policy',
				__( 'Password policy', 'bettershield' ),
				Policy::instance()->settings(),
				Policy::instance()->validate( $document['password_policy'] )
			);
		}

		if ( isset( $document['login_protection'] ) && is_array( $document['login_protection'] ) ) {
			$settings[] = self::settings_row(
				'login_protection',
				__( 'Login protection', 'bettershield' ),
				self::portable_login_protection( Protection::instance()->settings() ),
				// A file exported before the attempt limit had a switch of its
				// own names it `enabled`; read as the stored option of that
				// shape is, so the whole feature is not switched off with it.
				self::portable_login_protection_or_error( Protection::instance()->validate( Protection::upgraded( $document['login_protection'] ) ) )
			);
		}

		if ( isset( $document['two_factor_policy'] ) && is_array( $document['two_factor_policy'] ) ) {
			$settings[] = self::settings_row(
				'two_factor_policy',
				__( 'Two-factor requirement', 'bettershield' ),
				TwoFactorPolicy::instance()->settings(),
				TwoFactorPolicy::instance()->validate( $document['two_factor_policy'] ),
				/*
				 * A document carries one site's list, and on a network there
				 * is a second one beneath it that this import neither carries
				 * nor can change. Named in the plan, or an operator reads a
				 * row that accounts for less than the site will enforce — and
				 * the same validator refuses a document that would take the
				 * network's part away, which is the other half of the answer.
				 */
				self::network_two_factor_note()
			);
		}

		if ( isset( $document['passkey_policy'] ) && is_array( $document['passkey_policy'] ) ) {
			$settings[] = self::settings_row(
				'passkey_policy',
				__( 'Passkey-only sign-in', 'bettershield' ),
				PasskeyPolicy::instance()->settings(),
				// This validator answers about the site as well as the input —
				// widening the policy needs a way back that somebody is
				// holding — so the plan names that refusal too. An import is
				// exactly when a site is least likely to have one.
				PasskeyPolicy::instance()->validate( $document['passkey_policy'] ),
				self::network_passkey_note()
			);
		}

		if ( isset( $document['security_txt'] ) && is_array( $document['security_txt'] ) ) {
			$settings[] = self::settings_row(
				'security_txt',
				__( 'security.txt', 'bettershield' ),
				SecurityTxt::instance()->settings(),
				SecurityTxt::instance()->validate( $document['security_txt'] )
			);
		}

		if ( isset( $document['agent_capture'] ) && is_array( $document['agent_capture'] ) ) {
			$settings[] = self::settings_row(
				'agent_capture',
				__( 'Recording agent activity', 'bettershield' ),
				Capture::settings(),
				array( 'recording' => rest_sanitize_boolean( $document['agent_capture']['recording'] ?? true ) )
			);
		}

		if ( isset( $document['app_password_expiry'] ) && is_array( $document['app_password_expiry'] ) ) {
			$settings[] = self::settings_row(
				'app_password_expiry',
				__( 'Retiring unused application passwords', 'bettershield' ),
				( new Expiry() )->settings(),
				( new Expiry() )->validate( $document['app_password_expiry'] )
			);
		}

		if ( isset( $document['abilities'] ) && is_array( $document['abilities'] ) ) {
			$settings[] = self::settings_row(
				'abilities',
				__( 'Agent read access', 'bettershield' ),
				array( 'enabled' => Registrar::is_enabled() ),
				array( 'enabled' => rest_sanitize_boolean( $document['abilities']['enabled'] ?? false ) )
			);
		}

		if ( isset( $document['uninstall'] ) && is_array( $document['uninstall'] ) ) {
			$settings[] = self::settings_row(
				'uninstall',
				__( 'Data on deletion', 'bettershield' ),
				array(
					'remove_data' => UninstallChoice::remove_data(),
					'choice'      => UninstallChoice::choice(),
				),
				self::portable_uninstall( $document )
			);
		}

		if ( isset( $document['sudo'] ) && is_array( $document['sudo'] ) ) {
			$settings[] = self::settings_row(
				'sudo',
				__( 'Password confirmation', 'bettershield' ),
				array( 'enabled' => \BetterShield\Rest\Sudo::enabled() ),
				array( 'enabled' => rest_sanitize_boolean( $document['sudo']['enabled'] ?? false ) )
			);
		}

		if ( isset( $document['alerts'] ) && is_array( $document['alerts'] ) ) {
			$settings[] = self::settings_row(
				'alerts',
				__( 'Alerts', 'bettershield' ),
				self::portable_alerts( AlertSettings::instance()->settings() ),
				self::portable_alerts_or_error( AlertSettings::instance()->validate( self::portable_alerts( $document['alerts'] ) ) )
			);
		}

		// Present and not a set of sections: said, not dropped, for the same
		// reason a section nothing reads is said below.
		if ( isset( $document['sections'] ) && ! is_array( $document['sections'] ) ) {
			$settings[] = array(
				'section' => 'sections',
				'title'   => __( 'BetterShield Ultra settings', 'bettershield' ),
				'action'  => 'invalid',
				'note'    => __( 'These settings need BetterShield Ultra on this site, so they were skipped.', 'bettershield' ),
				'changes' => new \stdClass(),
			);
		}

		if ( isset( $document['sections'] ) && is_array( $document['sections'] ) ) {
			$portable = SettingsLedger::portable();

			foreach ( $document['sections'] as $name => $wanted ) {
				$name = (string) $name;

				// Read here, and written in a shape it cannot read: that is a
				// damaged file, not an add-on this site lacks.
				if ( isset( $portable[ $name ] ) && ! is_array( $wanted ) ) {
					$settings[] = array(
						'section' => $name,
						'title'   => $portable[ $name ]['label'],
						'action'  => 'invalid',
						'note'    => __( 'This section is unreadable here, so it is left out.', 'bettershield' ),
						'changes' => new \stdClass(),
					);
					continue;
				}

				/*
				 * Something wrote this section and nothing here reads it — the
				 * add-on is not on this site, or is a version without it. Said
				 * rather than dropped, so an operator does not believe settings
				 * arrived that did not. Matched on the name exactly as written,
				 * which is the name the import writes it under.
				 */
				if ( ! isset( $portable[ $name ] ) ) {
					$shown = sanitize_key( $name );

					$settings[] = array(
						'section' => '' !== $shown ? $shown : 'unknown',
						'title'   => '' !== $shown ? $shown : __( 'Unnamed section', 'bettershield' ),
						'action'  => 'unknown',
						'note'    => __( 'This site doesn’t use these settings, so they were skipped.', 'bettershield' ),
						'changes' => new \stdClass(),
					);
					continue;
				}

				$surface = $portable[ $name ];
				$current = ( $surface['export'] )();
				$planned = ( $surface['plan'] )( $wanted );
				$note    = null !== $surface['note'] ? ( $surface['note'] )( $wanted ) : null;

				$settings[] = self::settings_row(
					$name,
					$surface['label'],
					is_array( $current ) ? $current : array(),
					is_wp_error( $planned ) || is_array( $planned ) ? $planned : array(),
					is_string( $note ) && '' !== $note ? $note : null
				);
			}
		}

		foreach ( $settings as $row ) {
			if ( 'change' === $row['action'] ) {
				++$changes;
			}
		}

		return array(
			'document_version' => (int) $document['version'],
			'exported_at'      => isset( $document['exported_at'] ) ? (string) $document['exported_at'] : null,
			'hardening'        => $rows,
			'settings'         => $settings,
			'changes'          => $changes,
			'applied'          => false,
		);
	}

	/**
	 * What in this plan changes how people sign in: a sign-in item turned on
	 * or given new settings, and the two-factor requirement reaching a role
	 * it did not. The same changes the screen holds for the pre-flight.
	 *
	 * @param array<string, mixed> $plan
	 * @param array<string, mixed> $document
	 * @return string[] The items and sections, by name.
	 */
	private static function signing_in_changes( array $plan, array $document ): array {
		$changes = array();

		foreach ( $plan['hardening'] as $row ) {
			if ( in_array( $row['action'], array( 'apply', 'reconfigure' ), true ) && Permissions::needs_way_back( (string) $row['item'] ) ) {
				$changes[] = (string) $row['item'];
			}
		}

		foreach ( $plan['settings'] as $row ) {
			if ( 'two_factor_policy' !== $row['section'] || 'change' !== $row['action'] ) {
				continue;
			}

			$current = TwoFactorPolicy::instance()->settings()['roles'];
			$next    = (array) ( $document['two_factor_policy']['roles'] ?? $current );

			if ( array() !== array_diff( array_map( 'strval', array_filter( $next, 'is_scalar' ) ), $current ) ) {
				$changes[] = 'two_factor_policy';
			}
		}

		return $changes;
	}

	/**
	 * Plan, then carry the plan out through the per-item path. Returns the
	 * plan with a result on every row.
	 *
	 * A plan that changes how people sign in waits for the recovery
	 * pre-flight, as the same change made on the screen or with `harden`
	 * does: the import was a way past it. Going ahead anyway is the second
	 * confirmation, and it is recorded for each change it let through.
	 *
	 * @param array<string, mixed> $document
	 * @param bool                 $override_preflight Go ahead although the way back in is not proved.
	 * @param string               $via                'dashboard' or 'cli', for the record of going ahead.
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function apply( array $document, bool $override_preflight = false, string $via = 'dashboard' ) {
		return LoginUrl::for_document( $document, static fn() => self::applied( $document, $override_preflight, $via ) );
	}

	/**
	 * @param array<string, mixed> $document
	 * @return array<string, mixed>|\WP_Error
	 */
	private static function applied( array $document, bool $override_preflight, string $via ) {
		$plan = self::plan( $document );
		if ( is_wp_error( $plan ) ) {
			return $plan;
		}

		$signing_in = self::signing_in_changes( $plan, $document );
		$failure    = array() !== $signing_in ? Preflight::failure() : null;

		if ( null !== $failure && ! $override_preflight ) {
			return Preflight::refusal( $failure );
		}

		$manager = Manager::instance();
		$counts  = array(
			'applied'  => 0,
			'reverted' => 0,
			'failed'   => 0,
			'settings' => 0,
		);

		foreach ( $plan['hardening'] as &$row ) {
			switch ( $row['action'] ) {
				case 'apply':
					$options = is_array( $row['options'] ) ? $row['options'] : array();
					$done    = $manager->apply( $row['item'], $options );
					if ( is_wp_error( $done ) ) {
						$row['result'] = 'failed';
						$row['note']   = $done->get_error_message();
						++$counts['failed'];
					} else {
						$row['result'] = 'applied';
						++$counts['applied'];
					}
					break;

				case 'reconfigure':
					/*
					 * Undone, then applied again with the file's settings: the
					 * way the screen changes an applied item's settings, each
					 * step with its own undo record. A second step that is
					 * refused puts the item back on with the settings it had,
					 * so a refusal never leaves the protection off.
					 */
					$options  = is_array( $row['options'] ) ? $row['options'] : array();
					$previous = $manager->item_state( $row['item'] )['options'] ?? array();
					$done     = $manager->revert( $row['item'], \BetterShield\Hardening\Manager::CAUSE_RECONFIGURE );

					if ( ! is_wp_error( $done ) ) {
						$done = $manager->apply( $row['item'], $options );

						if ( is_wp_error( $done ) ) {
							$manager->apply( $row['item'], is_array( $previous ) ? $previous : array() );
						}
					}

					if ( is_wp_error( $done ) ) {
						$row['result'] = 'failed';
						$row['note']   = $done->get_error_message();
						++$counts['failed'];
					} else {
						// The plan's note said what would happen; it has.
						$row['result'] = 'changed';
						$row['note']   = __( 'Undone and applied again with the settings in this file.', 'bettershield' );
						++$counts['settings'];
					}
					break;

				case 'revert':
					$done = $manager->revert( $row['item'] );
					if ( is_wp_error( $done ) ) {
						$row['result'] = 'failed';
						$row['note']   = $done->get_error_message();
						++$counts['failed'];
					} else {
						$row['result'] = 'reverted';
						++$counts['reverted'];
					}
					break;

				default:
					$row['result'] = 'skipped';
			}
		}
		unset( $row );

		foreach ( $plan['settings'] as &$row ) {
			if ( 'change' !== $row['action'] ) {
				$row['result'] = 'skipped';
				continue;
			}

			$saved = null;
			switch ( $row['section'] ) {
				case 'password_policy':
					$saved = Policy::instance()->update_settings( $document['password_policy'] );
					break;
				case 'login_protection':
					$saved = Protection::instance()->update_settings( Protection::upgraded( $document['login_protection'] ) );
					break;
				case 'abilities':
					$saved = Registrar::set_enabled( rest_sanitize_boolean( $document['abilities']['enabled'] ?? false ) );
					break;
				case 'uninstall':
					$saved = UninstallChoice::set_choice( self::portable_uninstall( $document )['choice'] );
					break;
				case 'sudo':
					$saved = \BetterShield\Rest\Sudo::set_enabled( rest_sanitize_boolean( $document['sudo']['enabled'] ?? false ) );
					break;
				case 'two_factor_policy':
					$saved = TwoFactorPolicy::instance()->update_settings( $document['two_factor_policy'] );
					break;
				case 'passkey_policy':
					/*
					 * This one can refuse: it will not cover a role it did not
					 * cover already unless this site has a way back somebody
					 * is holding — a recovery link that still opens, or
					 * printed codes. An import is exactly the moment a fresh
					 * site has neither. The refusal travels back as the row's
					 * result rather than being swallowed, so the plan's report
					 * says which setting did not take and why.
					 */
					$saved = PasskeyPolicy::instance()->update_settings( $document['passkey_policy'] );
					break;
				case 'security_txt':
					$saved = SecurityTxt::instance()->update_settings( $document['security_txt'] );
					break;
				case 'alerts':
					$saved = AlertSettings::instance()->update_settings( self::portable_alerts( $document['alerts'] ) );
					break;
				case 'agent_capture':
					$saved = Capture::set_enabled( rest_sanitize_boolean( $document['agent_capture']['recording'] ?? true ) );
					break;
				case 'app_password_expiry':
					$saved = ( new Expiry() )->update_settings( $document['app_password_expiry'] );
					break;
				default:
					/*
					 * An add-on's section, written through the undo ledger so
					 * its way back is recorded before it is written, whatever
					 * the add-on's own write does about that.
					 */
					if ( isset( $document['sections'][ $row['section'] ] ) && is_array( $document['sections'][ $row['section'] ] ) ) {
						$saved = SettingsLedger::write_recorded( $row['section'], $document['sections'][ $row['section'] ] );
					}
					break;
			}

			if ( is_wp_error( $saved ) ) {
				$row['result'] = 'failed';
				$row['note']   = $saved->get_error_message();
				++$counts['failed'];
			} else {
				$row['result'] = 'changed';
				++$counts['settings'];
			}
		}
		unset( $row );

		if ( null !== $failure ) {
			foreach ( array_merge( $plan['hardening'], $plan['settings'] ) as $row ) {
				$change = (string) ( $row['item'] ?? $row['section'] ?? '' );

				if ( in_array( $change, $signing_in, true ) && in_array( $row['result'] ?? '', array( 'applied', 'changed' ), true ) ) {
					Preflight::overridden( $failure, $change, $via );
				}
			}
		}

		$plan['applied'] = true;
		$plan['counts']  = $counts;

		/*
		 * An import that changed nothing records nothing: a document refused
		 * from top to bottom wrote a medium "Settings imported" row and ran an
		 * audit, as though something had been carried in.
		 */
		if ( 0 === $counts['applied'] + $counts['reverted'] + $counts['settings'] ) {
			return $plan;
		}

		// The findings reflect the new state before anyone reads them.
		Auditor::run();

		Writer::instance()->record(
			'settings_imported',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'settings',
				'context'     => array_merge(
					$counts,
					array( 'document_version' => $plan['document_version'] )
				),
			)
		);

		return $plan;
	}

	/**
	 * A document must say what it is before anything in it is believed.
	 *
	 * @param array<string, mixed> $document
	 * @return true|\WP_Error
	 */
	private static function check_document( array $document ) {
		if ( ! isset( $document['format'] ) || self::FORMAT !== $document['format'] ) {
			return new \WP_Error( 'bettershield_bad_document', __( 'This is not a BetterShield settings document.', 'bettershield' ), array( 'status' => 400 ) );
		}

		$version = isset( $document['version'] ) ? (int) $document['version'] : 0;
		if ( $version < 1 || $version > self::VERSION ) {
			return new \WP_Error(
				'bettershield_document_version',
				sprintf(
					/* translators: 1: the document's version, 2: the newest version this plugin reads. Neither is shown. */
					__( 'This file is from a newer BetterShield. Update BetterShield on this site, then import again.', 'bettershield' ),
					$version,
					self::VERSION
				),
				array( 'status' => 400 )
			);
		}

		return true;
	}

	/**
	 * Whether a section is a set of named settings this plan can read: an
	 * empty one, or one keyed by name. A list of values is not (#2249).
	 *
	 * @param mixed $section
	 */
	private static function readable( $section ): bool {
		return is_array( $section ) && ( array() === $section || array_values( $section ) !== $section );
	}

	/**
	 * Whether two sets of an item's settings say the same thing: a list in
	 * another order, or keys in another order, is the same setting.
	 *
	 * @param array<string, mixed> $a
	 * @param array<string, mixed> $b
	 */
	public static function same_options( array $a, array $b ): bool {
		return self::canonical( $a ) === self::canonical( $b );
	}

	/**
	 * @param mixed $value
	 * @return mixed
	 */
	private static function canonical( $value ) {
		if ( ! is_array( $value ) ) {
			return $value;
		}

		$value = array_map( array( self::class, 'canonical' ), $value );

		if ( array_values( $value ) === $value ) {
			sort( $value );
		} else {
			ksort( $value );
		}

		return $value;
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function hardening_row( string $item, string $title, ?bool $current, bool $wanted, string $action, ?string $note, string $label = '' ): array {
		return array(
			'item'             => $item,
			'title'            => $title,
			'current'          => $current,
			'wanted'           => $wanted,
			'action'           => $action,
			'note'             => $note,
			// Why an item cannot be applied, as the short status its card shows (#2235).
			'label'            => $label,
			'conflict_warning' => null,
			'options'          => new \stdClass(),
		);
	}

	/**
	 * A settings section's row: keep, change (with what changes), or invalid
	 * (with the validator's own refusal).
	 *
	 * @param array<string, mixed>           $current
	 * @param array<string, mixed>|\WP_Error $wanted
	 * @return array<string, mixed>
	 */
	private static function settings_row( string $section, string $title, array $current, $wanted, ?string $note = null ): array {
		if ( is_wp_error( $wanted ) ) {
			return array(
				'section' => $section,
				'title'   => $title,
				'action'  => 'invalid',
				// The refusal is what an operator has to read here; a standing
				// note about the section is the smaller of the two facts and
				// gives way to it.
				'note'    => $wanted->get_error_message(),
				'changes' => new \stdClass(),
			);
		}

		$changes = \BetterShield\Undo\SettingsLedger::differences( $current, $wanted );

		return array(
			'section' => $section,
			'title'   => $title,
			'action'  => array() === $changes ? 'keep' : 'change',
			'note'    => $note,
			'changes' => array() === $changes ? new \stdClass() : $changes,
		);
	}

	/**
	 * What the two policy sections carry that this document did not bring and
	 * cannot change: the network's part.
	 *
	 * Nothing on a single site, where there is no network to have set one, and
	 * nothing where a network has never saved the policy — an unset policy is
	 * a network that has not decided rather than one that decided nothing.
	 */
	private static function network_two_factor_note(): ?string {
		if ( ! is_multisite() || ! NetworkPolicies::two_factor_is_set() ) {
			return null;
		}

		$roles = NetworkPolicies::two_factor()['roles'];

		if ( array() === $roles ) {
			return __( 'The network requires two-factor for no roles, so only this site’s list applies.', 'bettershield' );
		}

		return sprintf(
			/* translators: %s: a comma-separated list of role names. */
			__( 'The network also requires two-factor for these roles, and this site cannot remove them: %s.', 'bettershield' ),
			implode( ', ', $roles )
		);
	}

	private static function network_passkey_note(): ?string {
		if ( ! is_multisite() || ! NetworkPolicies::passkey_is_set() ) {
			return null;
		}

		$roles = NetworkPolicies::passkey()['roles'];

		if ( array() === $roles ) {
			return __( 'The network requires passkeys for no roles, so only this site’s list applies.', 'bettershield' );
		}

		return sprintf(
			/* translators: %s: a comma-separated list of role names. */
			__( 'The network also requires passkeys for these roles, and this site cannot remove them: %s.', 'bettershield' ),
			implode( ', ', $roles )
		);
	}

	/**
	 * Login protection without the parts that belong to one site: list entries
	 * lose their author and date, because on the importing site the importer
	 * is the author and the import is the date.
	 *
	 * @param array<string, mixed> $settings
	 * @return array<string, mixed>
	 */
	private static function portable_login_protection( array $settings ): array {
		foreach ( array( 'allowlist', 'blocklist' ) as $list ) {
			$entries = array();

			foreach ( (array) ( $settings[ $list ] ?? array() ) as $entry ) {
				if ( ! is_array( $entry ) ) {
					continue;
				}
				$portable = array();
				// A blocked username is a blocklist entry like an address.
				foreach ( array( 'range', 'ua', 'username', 'note' ) as $key ) {
					if ( isset( $entry[ $key ] ) && '' !== $entry[ $key ] ) {
						$portable[ $key ] = (string) $entry[ $key ];
					}
				}
				$entries[] = $portable;
			}

			$settings[ $list ] = $entries;
		}

		return $settings;
	}

	/**
	 * @param array<string, mixed>|\WP_Error $validated
	 * @return array<string, mixed>|\WP_Error
	 */
	private static function portable_login_protection_or_error( $validated ) {
		return is_wp_error( $validated ) ? $validated : self::portable_login_protection( $validated );
	}

	/**
	 * Alerting without its recipients.
	 *
	 * How loud a site is configured to be travels; who hears it does not. An
	 * operator setting up a client's site wants their own digest schedule and
	 * their own mute state, and does not want the previous site's addresses
	 * quietly subscribed to this one's alarms. Dropping the key on the way in
	 * as well as on the way out means a hand-edited document cannot smuggle
	 * them in either. What each address chose is keyed by the address, so
	 * it stays behind with them.
	 *
	 * @param array<string, mixed> $settings
	 * @return array<string, mixed>
	 */
	private static function portable_alerts( array $settings ): array {
		// Who hosts this site says nothing about the next one.
		unset( $settings['recipients'], $settings['preferences'], $settings['host_managed'] );

		return $settings;
	}

	/**
	 * @param array<string, mixed>|\WP_Error $validated
	 * @return array<string, mixed>|\WP_Error
	 */
	private static function portable_alerts_or_error( $validated ) {
		return is_wp_error( $validated ) ? $validated : self::portable_alerts( $validated );
	}

	/**
	 * What a document's uninstall section asks for, as the plan and the apply
	 * both read it.
	 *
	 * The two fields are read in the order that keeps every document meaning
	 * what it said. The boolean decides whether anything is removed: a document
	 * that says keep is honored as keep, whatever else it carries. Only once it
	 * says remove does the third answer get to refine how — which is what lets
	 * a document written before there was a third answer, carrying the boolean
	 * alone, still import exactly as it did.
	 *
	 * @param array<string, mixed> $document
	 * @return array{remove_data: bool, choice: string}
	 */
	private static function portable_uninstall( array $document ): array {
		$section = isset( $document['uninstall'] ) && is_array( $document['uninstall'] ) ? $document['uninstall'] : array();
		$remove  = rest_sanitize_boolean( $section['remove_data'] ?? false );

		if ( ! $remove ) {
			return array(
				'remove_data' => false,
				'choice'      => UninstallChoice::KEEP,
			);
		}

		$choice = UninstallChoice::normalize( $section['choice'] ?? UninstallChoice::REMOVE );

		return array(
			'remove_data' => true,
			'choice'      => UninstallChoice::KEEP === $choice ? UninstallChoice::REMOVE : $choice,
		);
	}
}
