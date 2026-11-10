<?php
/**
 * The undo ledger, extended to settings.
 *
 * "Every change is reversible" is a locked principle, and until now it was
 * true of two things: hardening items and file writes. The five settings
 * surfaces were not ledgered at all — a save wrote the new values over the old
 * ones and the previous state was gone, and a settings import rewrote all of
 * them at once with nothing to put back. The principle had a footnote nobody
 * had written down.
 *
 * This closes it, and the shape is deliberately the same as the one hardening
 * already uses: read the prior state, record it *before* the write, and revert
 * by handing that state back to the validator it came from. A revert is
 * therefore an ordinary save — it passes the same validation, records its own
 * activity event, and cannot put a site into a state the screen could not have
 * produced.
 *
 * Two properties are worth stating because they are easy to lose:
 *
 * **A revert is not itself ledgered.** Undoing an undo is the change before it,
 * and recording each one would grow a chain nobody asked for; the suppression
 * is a flag rather than a parameter so no caller can forget it.
 *
 * **Only real changes are recorded.** A save that changes nothing writes no
 * undo record, or a screen that saves on every keystroke would fill the list
 * with entries that undo nothing.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Undo;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SettingsLedger {

	/** Prefix for every action key written here. */
	private const PREFIX = 'settings_';

	/**
	 * The two things an undo list can be about, said by the caller.
	 *
	 * Almost every surface below belongs to one site, and that site's own
	 * screen lists it and puts it back. Two do not: the policies a network
	 * sets once for every site under it, whose rows live in the main site's
	 * table because a network change belongs to no subsite. Those rows sit in
	 * the same table as the main site's own history — so a list that reads the
	 * table and nothing else offered the network's rulings on the main site's
	 * settings screen, and its button put one back. That is an administrator
	 * of one site undoing a decision made for every site.
	 *
	 * The scope is a parameter rather than something inferred from the request,
	 * so a route reaches exactly what it was written to reach and a new caller
	 * has to say which of the two it means.
	 */
	public const SCOPE_SITE    = 'site';
	public const SCOPE_NETWORK = 'network';

	/** The widest window recent() reads from any one surface. */
	public const MOST_LISTED = 500;

	/**
	 * True while a revert is being applied, so the write it performs does not
	 * record an undo record of its own.
	 */
	private static bool $reverting = false;

	/**
	 * True while a write whose undo record this class has already written is
	 * under way, so a surface that records its own save does not record the
	 * same change a second time. See `write_recorded()`.
	 */
	private static bool $recorded_here = false;

	/**
	 * Whether the write under way is a revert. A surface that can be put back
	 * to a state no save can reach — a policy that was never set — accepts
	 * that state only from here.
	 */
	public static function is_reverting(): bool {
		return self::$reverting;
	}

	/**
	 * The surfaces that can be put back, and how.
	 *
	 * Each names the thing that owns the values, so a revert goes through the
	 * same validator a save does. A surface missing from here is not
	 * reversible, and adding one is two lines — which is the point of keeping
	 * the list in one place rather than in five classes.
	 *
	 * `needed_by`, where another setting stands on this one, answers the
	 * label of a setting that is on now and that writing the given state
	 * would switch off with it, or ''.
	 *
	 * @return array<string, array{label: string, read: callable, write: callable, shape?: callable, export?: callable, plan?: callable, note?: callable, needed_by?: callable}>
	 */
	private static function surfaces(): array {
		$surfaces = array(
			'login_protection' => array(
				'label' => __( 'Login protection', 'bettershield' ),
				'read'  => static fn(): array => \BetterShield\Login\Protection::instance()->settings(),
				'write' => static fn( array $v ) => \BetterShield\Login\Protection::instance()->update_settings( $v ),
				// A record written before the attempt limit had a switch of
				// its own holds it as `enabled`.
				'shape' => static fn( array $v ): array => \BetterShield\Login\Protection::upgraded( $v ),
			),
			'password_policy'  => array(
				'label' => __( 'Password policy', 'bettershield' ),
				'read'  => static fn(): array => \BetterShield\Password\Policy::instance()->settings(),
				'write' => static fn( array $v ) => \BetterShield\Password\Policy::instance()->update_settings( $v ),
			),
			'alerts'           => array(
				'label' => __( 'Alerts', 'bettershield' ),
				'read'  => static fn(): array => \BetterShield\Alerts\Settings::instance()->settings(),
				'write' => static fn( array $v ) => \BetterShield\Alerts\Settings::instance()->update_settings( $v ),
			),
			'two_factor_policy' => array(
				'label' => __( 'Two-factor policy', 'bettershield' ),
				'read'  => static fn(): array => \BetterShield\TwoFactor\Policy::instance()->settings(),
				'write' => static fn( array $v ) => \BetterShield\TwoFactor\Policy::instance()->update_settings( $v ),
			),
			'passkey_policy'   => array(
				'label' => __( 'Passkey-only sign-in', 'bettershield' ),
				'read'  => static fn(): array => \BetterShield\Passkeys\Policy::instance()->settings(),
				'write' => static fn( array $v ) => \BetterShield\Passkeys\Policy::instance()->update_settings( $v ),
			),
			/*
			 * The two a network sets once for every site under it. Their rows
			 * live in the main site's undo table, because a network change
			 * belongs to no subsite and would be invisible from every other
			 * one — the reading and the writing both happen switched there, so
			 * a revert issued from the network screen finds its own row and
			 * puts back a network value rather than a site's.
			 */
			'network_two_factor_policy' => array(
				'label' => __( 'Two-factor requirement for the network', 'bettershield' ),
				// With whether it was ever saved: putting back a first policy
				// has to leave the network undecided again, not set to the
				// defaults, which would start shortening every site's grace.
				'read'  => static fn(): array => \BetterShield\Network\Policies::two_factor() + array( 'set' => \BetterShield\Network\Policies::two_factor_is_set() ),
				'write' => static fn( array $v ) => \BetterShield\Network\Policies::update_two_factor( $v ),
			),
			'network_passkey_policy' => array(
				'label' => __( 'Passkey-only sign-in for the network', 'bettershield' ),
				'read'  => static fn(): array => \BetterShield\Network\Policies::passkey() + array( 'set' => \BetterShield\Network\Policies::passkey_is_set() ),
				'write' => static fn( array $v ) => \BetterShield\Network\Policies::update_passkey( $v ),
			),
			/*
			 * The largest blast radius of anything on this list, so it belongs
			 * on it: an owner looking for "what did I change and how do I put
			 * it back" must find the site being closed there beside everything
			 * smaller. The lift button is the same act by a shorter route.
			 */
			'lockdown'         => array(
				'label' => __( 'Site lockdown', 'bettershield' ),
				'read'  => static fn(): array => array( 'active' => \BetterShield\Recovery\Lockdown::state()['active'] ),
				'write' => static function ( array $v ) {
					if ( empty( $v['active'] ) ) {
						return \BetterShield\Recovery\Lockdown::leave( 'undo' );
					}

					return \BetterShield\Recovery\Lockdown::enter( get_current_user_id() );
				},
			),
			'security_txt'     => array(
				'label' => __( 'Security contact (security.txt)', 'bettershield' ),
				'read'  => static fn(): array => \BetterShield\Disclosure\SecurityTxt::instance()->settings(),
				'write' => static fn( array $v ) => \BetterShield\Disclosure\SecurityTxt::instance()->update_settings( $v ),
			),
			/*
			 * The one switch whose consequence is that nothing is recorded, so
			 * an owner who turned it off by accident has nothing in the record
			 * to notice it by — except this.
			 */
			'agent_capture'    => array(
				'label' => __( 'Recording agent activity', 'bettershield' ),
				'read'  => static fn(): array => \BetterShield\Agents\Capture::settings(),
				'write' => static function ( array $v ): array {
					\BetterShield\Agents\Capture::set_enabled( ! empty( $v['recording'] ) );

					return \BetterShield\Agents\Capture::settings();
				},
			),
			/*
			 * Switching this on is reversible; the credentials a sweep has
			 * already retired are not, and nothing here pretends otherwise.
			 * What can be put back is the decision.
			 */
			'app_password_expiry' => array(
				'label' => __( 'Retiring unused application passwords', 'bettershield' ),
				'read'  => static fn(): array => ( new \BetterShield\Agents\Expiry() )->settings(),
				'write' => static fn( array $v ) => ( new \BetterShield\Agents\Expiry() )->update_settings( $v ),
			),
			/*
			 * Three switches on the same screen as the list, each saved there
			 * and carried by a settings file like the rest. Standing the
			 * password gate down removes a protection; the deletion choice
			 * decides what deleting the plugin takes with it.
			 */
			'sudo'             => array(
				'label' => __( 'Password confirmation', 'bettershield' ),
				'read'  => static fn(): array => array( 'enabled' => \BetterShield\Rest\Sudo::enabled() ),
				'write' => static fn( array $v ) => \BetterShield\Rest\Sudo::set_enabled( ! empty( $v['enabled'] ) ),
			),
			'uninstall'        => array(
				'label' => __( 'When BetterShield is deleted', 'bettershield' ),
				'read'  => static fn(): array => array( 'choice' => \BetterShield\Support\UninstallChoice::choice() ),
				'write' => static fn( array $v ) => \BetterShield\Support\UninstallChoice::set_choice( (string) ( $v['choice'] ?? '' ) ),
			),
			'abilities'        => array(
				'label' => __( 'Let agents read this site', 'bettershield' ),
				'read'  => static fn(): array => array( 'enabled' => \BetterShield\Abilities\Registrar::is_enabled() ),
				'write' => static fn( array $v ) => \BetterShield\Abilities\Registrar::set_enabled( ! empty( $v['enabled'] ) ),
				// Agent changes stand on it: turning reads off takes them
				// with it, so a put-back that would do that is refused (#2140).
				'needed_by' => static fn( array $v ): string => empty( $v['enabled'] ) && \BetterShield\Abilities\Registrar::write_enabled() ? self::label_for( 'agent_writes' ) : '',
			),
			/*
			 * The rest of the agent switches, each with its way back as the
			 * read switch has (#1824).
			 */
			'agent_writes'     => array(
				'label' => __( 'Let agents change this site', 'bettershield' ),
				'read'  => static fn(): array => array( 'enabled' => \BetterShield\Abilities\Registrar::write_enabled() ),
				'write' => static fn( array $v ) => \BetterShield\Abilities\Registrar::set_write_enabled( ! empty( $v['enabled'] ) ),
			),
			'mcp'              => array(
				'label' => __( 'Let an assistant connect to this site', 'bettershield' ),
				'read'  => static fn(): array => array( 'enabled' => \BetterShield\Mcp\Manager::is_enabled() ),
				'write' => static fn( array $v ) => \BetterShield\Mcp\Manager::set_enabled( ! empty( $v['enabled'] ) ),
			),
			// The tools each connected application may use (#1879).
			'mcp_app_tools'    => array(
				'label' => __( 'Tools this app may use', 'bettershield' ),
				'read'  => static fn(): array => array( 'tools_denied' => \BetterShield\Mcp\AppTools::all() ),
				'write' => static fn( array $v ) => \BetterShield\Mcp\AppTools::put( $v['tools_denied'] ?? array() ),
			),
			'decoy_page'       => array(
				'label' => __( 'Decoy URL', 'bettershield' ),
				'read'  => static fn(): array => array_intersect_key( \BetterShield\Agents\DecoyPage::report(), array_flip( array( 'enabled', 'slug' ) ) ),
				'write' => static fn( array $v ) => \BetterShield\Agents\DecoyPage::save( ! empty( $v['enabled'] ), (string) ( $v['slug'] ?? '' ) ),
			),
			'hub_link'         => array(
				'label' => __( 'Hub link', 'bettershield' ),
				'read'  => static fn(): array => \BetterShield\Hub\Link\Link::undoable(),
				'write' => static fn( array $v ) => \BetterShield\Hub\Link\Link::put_back( $v ),
			),
		);

		/**
		 * Settings an add-on keeps, so that changing them is undoable here too.
		 *
		 * An add-on's policy is a policy: the paid add-on decides which roles
		 * must hold a second factor, how long they have and whether they may
		 * take it off again, and a change to that deserves the way back this
		 * plugin gives its own. Each entry is a label and a pair of callables —
		 * one that reads the settings as they are, one that writes a set back.
		 *
		 * A name this plugin already uses is never replaced: the undo for those
		 * is this plugin's own, and an add-on that could displace one could
		 * quietly take the way back from a setting it does not own.
		 *
		 * An entry may also say how it travels in the settings document, with
		 * two more callables: `export`, which answers the section as the
		 * document carries it, and `plan`, which takes a section from a
		 * document and answers what a write would store — or a `WP_Error`
		 * saying why it would refuse — without writing anything. A third,
		 * `note`, may say something about a section the plan should show
		 * beside it. A surface travels only with both, so nothing reaches
		 * the document without a way back: the import writes its undo record
		 * before it writes the section.
		 *
		 * @since 1.0.0
		 *
		 * @param array<string, array{label: string, read: callable, write: callable, export?: callable, plan?: callable, note?: callable}> $extra Surfaces an add-on keeps.
		 */
		$extra = apply_filters( 'bettershield_settings_ledger_surfaces', array() );

		foreach ( is_array( $extra ) ? $extra : array() as $name => $surface ) {
			if ( ! is_string( $name ) || '' === $name || isset( $surfaces[ $name ] ) ) {
				continue;
			}

			if ( ! is_array( $surface )
				|| ! isset( $surface['label'], $surface['read'], $surface['write'] )
				|| ! is_callable( $surface['read'] )
				|| ! is_callable( $surface['write'] ) ) {
				continue;
			}

			$surfaces[ $name ] = array(
				'label' => (string) $surface['label'],
				'read'  => $surface['read'],
				'write' => $surface['write'],
			);

			foreach ( array( 'export', 'plan', 'note' ) as $optional ) {
				if ( isset( $surface[ $optional ] ) && is_callable( $surface[ $optional ] ) ) {
					$surfaces[ $name ][ $optional ] = $surface[ $optional ];
				}
			}
		}

		return $surfaces;
	}

	/**
	 * The add-on surfaces that travel in the settings document: those that
	 * said both how they are exported and how a document's copy is planned.
	 *
	 * @return array<string, array{label: string, export: callable, plan: callable, note: callable|null}>
	 */
	public static function portable(): array {
		$out = array();

		foreach ( self::surfaces() as $name => $surface ) {
			if ( isset( $surface['export'], $surface['plan'] ) ) {
				$out[ $name ] = array(
					'label'  => $surface['label'],
					'export' => $surface['export'],
					'plan'   => $surface['plan'],
					'note'   => $surface['note'] ?? null,
				);
			}
		}

		return $out;
	}

	/**
	 * Write a surface's settings with the way back recorded first.
	 *
	 * For a write that is not a save on the surface's own screen — a settings
	 * import above all — and so cannot count on the surface to have recorded
	 * it. The record is written here, from what the surface reads now and what
	 * its plan says the write will store, and a record that cannot be written
	 * stops the write. A surface that records its own saves does not record
	 * this one again.
	 *
	 * @param array<string, mixed> $values What the surface is to be set to.
	 * @return mixed What the surface's write answered, or a `WP_Error`.
	 */
	public static function write_recorded( string $surface, array $values ) {
		$surfaces = self::surfaces();

		if ( ! isset( $surfaces[ $surface ] ) ) {
			return new \WP_Error( 'bettershield_unknown_surface', __( 'These settings aren’t used on this site.', 'bettershield' ), array( 'status' => 400 ) );
		}

		$found  = $surfaces[ $surface ];
		$before = ( $found['read'] )();
		$after  = isset( $found['plan'] ) ? ( $found['plan'] )( $values ) : $values;

		if ( is_wp_error( $after ) ) {
			return $after;
		}

		if ( false === self::record( $surface, is_array( $before ) ? $before : array(), is_array( $after ) ? $after : array() ) ) {
			return new \WP_Error( 'bettershield_settings_unrecorded', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}

		self::$recorded_here = true;

		try {
			return ( $found['write'] )( $values );
		} finally {
			self::$recorded_here = false;
		}
	}

	/**
	 * @return string[]
	 */
	public static function surface_keys(): array {
		return array_keys( self::surfaces() );
	}

	/**
	 * Which of the two scopes a surface belongs to.
	 *
	 * The prefix is the whole rule and it is read here alone, so a surface
	 * added to the list above cannot end up in one list by being named for the
	 * other.
	 */
	private static function scope_of( string $surface ): string {
		return str_starts_with( $surface, 'network_' ) ? self::SCOPE_NETWORK : self::SCOPE_SITE;
	}

	public static function label_for( string $surface ): string {
		$surfaces = self::surfaces();

		return isset( $surfaces[ $surface ] ) ? (string) $surfaces[ $surface ]['label'] : $surface;
	}

	/**
	 * Record what a surface looked like before a save.
	 *
	 * Called by the surface itself, before it writes, so the record exists
	 * whether or not the write that follows succeeds — the same order the
	 * hardening path uses and for the same reason.
	 *
	 * The three answers are distinct, because two of them are opposites. A
	 * token is a way back. `null` is "there is nothing here to put back" — a
	 * revert in progress, a write `write_recorded()` has already recorded, a
	 * surface that is not reversible, or a save that changed nothing. `false`
	 * is "there was something to put back and it could not be written down",
	 * which is the one answer a caller must refuse on:
	 * proceeding past it applies a change with no way back, and every change
	 * here is meant to be reversible.
	 *
	 * @param array<string, mixed> $before
	 * @param array<string, mixed> $after
	 * @return string|false|null Undo token, false if the record could not be
	 *                           written, null if there was nothing to record.
	 */
	public static function record( string $surface, array $before, array $after ): string|false|null {
		if ( self::$reverting || self::$recorded_here ) {
			return null;
		}

		if ( ! isset( self::surfaces()[ $surface ] ) ) {
			return null;
		}

		// A save that changed nothing has nothing to undo. Compared by value
		// rather than by identity: the reader and the validator build their
		// arrays in different orders, and `===` calls two identical settings
		// different because of it.
		if ( self::same( $before, $after ) ) {
			return null;
		}

		$token = Ledger::open( self::PREFIX . $surface, $before, $after );

		return null === $token ? false : $token;
	}

	/**
	 * Whether two settings arrays say the same thing, whatever order they say
	 * it in and however deeply they nest.
	 *
	 * Public so a surface can ask the question the ledger asks, before it
	 * writes an event for a change that is not one.
	 *
	 * @param array<string, mixed> $a
	 * @param array<string, mixed> $b
	 */
	public static function same( array $a, array $b ): bool {
		$normalize = static function ( array $value ) use ( &$normalize ): array {
			ksort( $value );

			foreach ( $value as $key => $item ) {
				if ( is_array( $item ) ) {
					$value[ $key ] = $normalize( $item );
				}
			}

			return $value;
		};

		return wp_json_encode( $normalize( $a ) ) === wp_json_encode( $normalize( $b ) );
	}

	/**
	 * What differs between two states of one settings surface, key by key:
	 * `from` and `to` for a value, and for a list the count of entries that
	 * come and go, which is what somebody deciding needs and keeps addresses
	 * and ranges out of the answer.
	 *
	 * Read for the keys the second state carries. The import plan says what a
	 * file would change with it, and the undo list what each record changed.
	 *
	 * @param array<string, mixed> $before
	 * @param array<string, mixed> $after
	 * @return array<string, array<string, mixed>>
	 */
	public static function differences( array $before, array $after ): array {
		$changes = array();

		foreach ( $after as $key => $value ) {
			$was = $before[ $key ] ?? null;

			/*
			 * A map of named values is compared name by name, each its own
			 * line under the setting's name. Compared as a set of values, a
			 * heading and a lead that swapped places held the same values and
			 * read as no change at all.
			 */
			if ( is_array( $value ) && array() !== $value && ! self::is_list( $value ) ) {
				foreach ( self::differences( is_array( $was ) ? $was : array(), $value ) as $name => $change ) {
					$changes[ $key . '.' . $name ] = $change;
				}

				continue;
			}

			if ( is_array( $value ) ) {
				// Lists compare as sets of their portable form.
				$before_keys = array_map( 'wp_json_encode', is_array( $was ) ? $was : array() );
				$after_keys  = array_map( 'wp_json_encode', $value );
				$added       = count( array_diff( $after_keys, $before_keys ) );
				$removed     = count( array_diff( $before_keys, $after_keys ) );

				if ( $added > 0 || $removed > 0 ) {
					$changes[ $key ] = array(
						'added'   => $added,
						'removed' => $removed,
					);
				}
				continue;
			}

			if ( $was !== $value ) {
				$changes[ $key ] = array(
					'from' => $was,
					'to'   => $value,
				);
			}
		}

		return $changes;
	}

	/** Whether an array is a list (0, 1, 2 …) rather than a map of names. */
	private static function is_list( array $value ): bool {
		return array_keys( $value ) === range( 0, count( $value ) - 1 );
	}

	/**
	 * Put a surface back to the state one record holds.
	 *
	 * The values go through the surface's own validator, so a record written
	 * before a bound tightened is refused the way any other invalid save would
	 * be, rather than forcing a state the screen could not produce.
	 *
	 * The scope the caller is asking within has to match the one the record
	 * belongs to. A site's screen holds site records and a network's holds the
	 * network's; a token from the other list is refused here rather than
	 * applied by whichever route happened to be handed it.
	 *
	 * @param string $scope One of SCOPE_SITE or SCOPE_NETWORK.
	 * @return true|\WP_Error
	 */
	public static function revert( string $token, string $scope = self::SCOPE_SITE ) {
		$entry = Ledger::find( $token );

		if ( null === $entry ) {
			return new \WP_Error( 'bettershield_unknown_undo', __( 'That change is not one this site recorded.', 'bettershield' ), array( 'status' => 404 ) );
		}

		if ( null !== $entry->reverted_at ) {
			return new \WP_Error( 'bettershield_already_reverted', __( 'That change has already been put back.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$surface = substr( (string) $entry->action_key, strlen( self::PREFIX ) );

		if ( ! str_starts_with( (string) $entry->action_key, self::PREFIX ) || ! isset( self::surfaces()[ $surface ] ) ) {
			return new \WP_Error( 'bettershield_not_a_setting', __( 'That record is not a settings change.', 'bettershield' ), array( 'status' => 400 ) );
		}

		/*
		 * Answered as "no such change" rather than as "not yours", and on
		 * purpose: the record is not one this caller was ever offered, so
		 * telling them it exists tells them something the list did not.
		 */
		if ( self::scope_of( $surface ) !== $scope ) {
			return new \WP_Error(
				'bettershield_wrong_undo_scope',
				__( 'This change can’t be undone from here. Change the setting on its own screen instead.', 'bettershield' ),
				array( 'status' => 404 )
			);
		}

		/*
		 * A record that no longer reads back is refused rather than applied. A
		 * truncated column, or one written by a build that stored a different
		 * shape, decodes to nothing — and nothing, taken as an empty array and
		 * handed to the surface's own writer, is a settings screen emptied by a
		 * button labeled "put this back". For the largest surface on the list it
		 * is a site lockdown quietly lifted.
		 */
		if ( ! is_array( $entry->prior_state ) || array() === $entry->prior_state ) {
			return new \WP_Error(
				'bettershield_undo_unreadable',
				__( 'The earlier value for this change couldn’t be found, so nothing was undone.', 'bettershield' ),
				array( 'status' => 500 )
			);
		}

		/*
		 * Both snapshots in the shape the surface reads now, where it says how
		 * an older one translates. Compared and written as they were stored,
		 * an older field name puts back a different setting from the one the
		 * record changed.
		 */
		$shape   = self::surfaces()[ $surface ]['shape'] ?? static fn( array $v ): array => $v;
		$prior   = $shape( $entry->prior_state );

		/*
		 * Put back what this change changed, and nothing else.
		 *
		 * The row holds two whole-surface snapshots, and handing the prior one
		 * straight to the writer restores every field it holds — including the
		 * ones a later, unrelated save changed afterwards. On this surface that
		 * silently removed a trusted proxy, an allowlist range or a blocklist
		 * entry somebody added since, while the screen reported success for the
		 * one setting the reader was thinking about. The Settings screen offers
		 * "Put it back" on every change in the list, not only the newest, so
		 * undoing an older one is an ordinary click.
		 *
		 * A field this change touched that has since been changed again is a
		 * field this record is no longer the last word on. That is refused
		 * rather than resolved quietly, because either answer discards
		 * somebody's decision and only one of them says so.
		 */
		$applied = is_array( $entry->applied_state ) ? $shape( $entry->applied_state ) : array();

		if ( array() !== $applied ) {
			$current = ( self::surfaces()[ $surface ]['read'] )();
			$touched = array();

			foreach ( array_keys( $prior + $applied ) as $key ) {
				$was = $prior[ $key ] ?? null;
				$became = $applied[ $key ] ?? null;

				if ( wp_json_encode( $was ) !== wp_json_encode( $became ) ) {
					$touched[] = $key;
				}
			}

			/*
			 * A newer change to the same setting that is still in place is a
			 * later decision, whatever the setting reads now. Compared by
			 * value alone, a setting turned back to where this change left it
			 * let this older change be put back over every newer one, while
			 * the newest of them was refused (#2063).
			 */
			foreach ( Ledger::open_after( (string) $entry->action_key, (int) $entry->id ) as $newer ) {
				$newer_prior   = $shape( $newer['prior'] );
				$newer_applied = $shape( $newer['applied'] );

				foreach ( $touched as $key ) {
					if ( wp_json_encode( $newer_prior[ $key ] ?? null ) !== wp_json_encode( $newer_applied[ $key ] ?? null ) ) {
						return new \WP_Error(
							'bettershield_undo_superseded',
							__( 'This setting was changed again later. Undo the newer change first.', 'bettershield' ),
							array( 'status' => 409 )
						);
					}
				}
			}

			foreach ( $touched as $key ) {
				$now = $current[ $key ] ?? null;

				if ( wp_json_encode( $now ) !== wp_json_encode( $applied[ $key ] ?? null ) ) {
					return new \WP_Error(
						'bettershield_undo_superseded',
						__( 'That setting was changed again later. Undo the newer change first.', 'bettershield' ),
						array( 'status' => 409 )
					);
				}
			}

			$merged = $current;

			foreach ( $touched as $key ) {
				if ( array_key_exists( $key, $prior ) ) {
					$merged[ $key ] = $prior[ $key ];
				} else {
					unset( $merged[ $key ] );
				}
			}

			$prior = $merged;
		}

		/*
		 * A newer change to another setting that stands on this one is a
		 * later decision too. Writing this state would switch that setting
		 * off with it, unnamed, and leave its row describing a state the site
		 * no longer has; refused as a newer change to the same setting is.
		 */
		$needed_by = isset( self::surfaces()[ $surface ]['needed_by'] ) ? (string) ( self::surfaces()[ $surface ]['needed_by'] )( $prior ) : '';

		if ( '' !== $needed_by ) {
			return new \WP_Error(
				'bettershield_undo_depended_on',
				/* translators: %s: the name of a setting, e.g. "Let agents change this site". */
				sprintf( __( '“%s” was turned on after this and needs it. Undo that first.', 'bettershield' ), $needed_by ),
				array( 'status' => 409 )
			);
		}

		self::$reverting = true;

		try {
			$result = ( self::surfaces()[ $surface ]['write'] )( $prior );
		} finally {
			// Restored however the write went, so one refused revert cannot
			// leave the next ordinary save unrecorded.
			self::$reverting = false;
		}

		if ( is_wp_error( $result ) ) {
			Ledger::mark_revert_failed( $token, (string) $result->get_error_code() );

			return $result;
		}

		Ledger::mark_reverted( $token );

		return true;
	}

	/**
	 * The settings changes that can still be put back, newest first, each
	 * carrying why the last attempt to put it back failed where there was one.
	 *
	 * Only the ones belonging to the scope asked for. The network's rulings
	 * share the main site's table with that site's own history, and a list
	 * that showed both would offer a button the caller must not be given.
	 *
	 * Up to `$limit` from each surface rather than from all of them together.
	 * One window shared by every surface let a busy one push a quiet one off
	 * the list: a password gate switched off was gone from it after twenty
	 * saves of something else, still open and revertible by a token nothing
	 * on the screen held any more.
	 *
	 * @param int    $limit The most changes listed for any one surface.
	 * @param string $scope One of SCOPE_SITE or SCOPE_NETWORK.
	 * @return array<int, array<string, mixed>>
	 */
	public static function recent( int $limit = 20, string $scope = self::SCOPE_SITE ): array {
		global $wpdb;

		$rows = array();

		foreach ( array_keys( self::surfaces() ) as $surface ) {
			if ( self::scope_of( (string) $surface ) !== $scope ) {
				continue;
			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own undo table, which has no core API; read once when the screen is opened and never cached, because a stale list would offer a change that has already been put back.
			$found = (array) $wpdb->get_results(
				$wpdb->prepare(
					'SELECT id, token, action_key, created_at, created_by, revert_failed_reason, prior_state, applied_state FROM %i
					 WHERE site_id = 0 AND action_key = %s AND reverted_at IS NULL
					 ORDER BY id DESC LIMIT %d',
					\BetterShield\Database\Schema::table( 'undo' ),
					self::PREFIX . $surface,
					max( 1, min( self::MOST_LISTED, $limit ) )
				)
			);

			$rows = array_merge( $rows, $found );
		}

		// Newest first across the surfaces, as one list.
		usort( $rows, static fn( $a, $b ): int => (int) $b->id <=> (int) $a->id );

		$out = array();

		foreach ( $rows as $row ) {
			$surface = substr( (string) $row->action_key, strlen( self::PREFIX ) );

			if ( ! isset( self::surfaces()[ $surface ] ) || self::scope_of( $surface ) !== $scope ) {
				continue;
			}

			$who = null !== $row->created_by ? get_userdata( (int) $row->created_by ) : null;

			// Both sides in today's shape, as a revert reads them, so a record
			// written before a setting was split is not said as a change to it.
			$shape   = self::surfaces()[ $surface ]['shape'] ?? static fn( array $value ): array => $value;
			$prior   = json_decode( (string) $row->prior_state, true );
			$applied = json_decode( (string) $row->applied_state, true );
			$change  = self::differences( $shape( is_array( $prior ) ? $prior : array() ), $shape( is_array( $applied ) ? $applied : array() ) );

			$out[] = array(
				'token'   => (string) $row->token,
				'surface' => $surface,
				'label'   => self::label_for( $surface ),
				// What this record changed, so six alerts saves are six
				// different rows and putting one back can say what it did.
				'summary' => array() === $change ? new \stdClass() : $change,
				// Stored UTC without a zone marker; said explicitly, or the
				// browser reads it as local time.
				'at'      => \BetterShield\Support\Time::utc_iso( (string) $row->created_at ),
				'by'      => $who instanceof \WP_User ? $who->user_login : null,
				/*
				 * Why the last attempt to put this back did not take, when there
				 * was one. The column was written and read by nothing, so a record
				 * that refused to revert offered the button again and said nothing
				 * about the refusal — which is the moment somebody most needs to
				 * be told.
				 */
				'failed'  => null !== $row->revert_failed_reason ? (string) $row->revert_failed_reason : null,
			);
		}

		return $out;
	}

	/**
	 * How many settings changes in the scope can still be put back, all of
	 * them rather than the ones a window of recent() holds, so a list that
	 * shows some can say how many more there are.
	 *
	 * @param string $scope One of SCOPE_SITE or SCOPE_NETWORK.
	 */
	public static function revertible_total( string $scope = self::SCOPE_SITE ): int {
		global $wpdb;

		$keys = array();

		foreach ( array_keys( self::surfaces() ) as $surface ) {
			if ( self::scope_of( (string) $surface ) === $scope ) {
				$keys[] = self::PREFIX . $surface;
			}
		}

		if ( array() === $keys ) {
			return 0;
		}

		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- the plugin's own undo table, which has no core API, counted when the list it describes is read and never cached; the placeholder run's length is the key list's own, and every key is bound.
		$total = (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM %i WHERE site_id = 0 AND reverted_at IS NULL AND action_key IN (' . implode( ', ', array_fill( 0, count( $keys ), '%s' ) ) . ')',
				\BetterShield\Database\Schema::table( 'undo' ),
				...$keys
			)
		);
		// phpcs:enable

		return $total;
	}
}
