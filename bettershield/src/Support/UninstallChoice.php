<?php
/**
 * The owner's answer to "when this plugin is deleted, what happens to what it
 * kept?" — three answers, and keeping everything is the default.
 *
 * Read here by the screen, the terminal and a settings import. uninstall.php
 * reads the option by name on its own, deliberately: by the time it runs
 * this class may no longer be loadable, and a deletion routine that depends
 * on the plugin's autoloader is a deletion routine that silently does the
 * wrong thing.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

use BetterShield\Events\Writer;
use BetterShield\Files\Quarantine;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class UninstallChoice {

	public const OPTION = 'bettershield_remove_data_on_uninstall';

	/** Deleting the plugin removes none of its data. */
	public const KEEP = 'keep';

	/** Deleting the plugin removes its records and leaves the quarantine folder. */
	public const REMOVE = 'remove';

	/**
	 * As `REMOVE`, plus the quarantined copies are packaged into one archive
	 * — left on disk inside the quarantine folder, for whoever has file
	 * access to the site to collect — before the copies go.
	 */
	public const PACKAGE = 'package';

	/**
	 * What is stored for each answer.
	 *
	 * `'1'` still means remove, unchanged since the answer was a toggle: a site
	 * that set it before this became a choice of three reads back as it was
	 * written, and the uninstall script's own literal check still matches it.
	 */
	private const STORED = array(
		self::KEEP    => '0',
		self::REMOVE  => '1',
		self::PACKAGE => 'package',
	);

	/** The answer this site has stored. */
	public static function choice(): string {
		return self::normalize( get_option( self::OPTION ) );
	}

	/**
	 * Any raw answer as one of the three.
	 *
	 * Accepts what is stored and what a settings document or a request body
	 * carries, because they are the same three answers written two ways, and a
	 * value nobody recognizes means keeping everything — the safe end of a
	 * choice whose other end destroys records.
	 *
	 * @param mixed $value
	 */
	public static function normalize( $value ): string {
		if ( is_string( $value ) ) {
			$value = strtolower( trim( $value ) );
		}

		if ( self::PACKAGE === $value ) {
			return self::PACKAGE;
		}

		if ( self::REMOVE === $value || '1' === $value || 1 === $value || true === $value ) {
			return self::REMOVE;
		}

		return self::KEEP;
	}

	/**
	 * Whether deleting the plugin takes its records with it.
	 *
	 * True for both answers that remove: packaging changes what happens to the
	 * quarantined copies on the way out, not whether anything goes.
	 */
	public static function remove_data(): bool {
		return self::KEEP !== self::choice();
	}

	/** Whether the quarantined copies are packaged before the folder goes. */
	public static function packages_quarantine(): bool {
		return self::PACKAGE === self::choice();
	}

	/** @return true|\WP_Error */
	public static function set_remove_data( bool $remove ) {
		return self::set_choice( $remove ? self::REMOVE : self::KEEP );
	}

	/**
	 * Store an answer, with the way back written first: what deleting the
	 * plugin takes with it is a decision like any other setting here, and one
	 * that cannot be put back is not changed.
	 *
	 * @return true|\WP_Error
	 */
	public static function set_choice( string $choice ) {
		$choice = self::normalize( $choice );
		$from   = self::choice();

		// Storing the answer that is already stored is not a change, and the
		// log is the record of what changed. A screen that saves every field
		// it shows, or an imported document asking for what is already there,
		// would otherwise fill the log with rows saying nothing happened —
		// which is the reasoning the import path already applies before it
		// gets here.
		if ( $choice === $from ) {
			return true;
		}

		$undo = \BetterShield\Undo\SettingsLedger::record( 'uninstall', array( 'choice' => $from ), array( 'choice' => $choice ) );

		if ( false === $undo ) {
			return new \WP_Error(
				'bettershield_ledger_failed',
				__( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ),
				array( 'status' => 500 )
			);
		}

		update_option( self::OPTION, self::STORED[ $choice ], false );

		/*
		 * Logged while there is still a log to write to. If the answer is one
		 * of the two that remove when the plugin is deleted, this row goes with
		 * everything else — the owner's explicit choice.
		 *
		 * Under a kind of its own, which the weekly summary counts and a busy
		 * hour does not thin, as it does the generic settings row. Moving from
		 * keeping everything to an answer that removes goes out at once: it is
		 * the step before a deletion takes the log, the findings and the undo
		 * history with it, and once that happens nothing is left to say so.
		 */
		$arms = self::KEEP === $from;

		Writer::instance()->record(
			'uninstall_choice_changed',
			$arms ? Writer::SEVERITY_HIGH : Writer::SEVERITY_INFO,
			array(
				'object_type' => 'setting',
				'object_id'   => self::OPTION,
				'context'     => array(
					'remove_data' => self::KEEP !== $choice,
					'choice'      => $choice,
					'from'        => $from,
					'weakened'    => $arms ? array( 'records removed on deletion' ) : array(),
				),
			)
		);

		return true;
	}

	/**
	 * The answer, and what the screen needs to describe what it would do.
	 *
	 * The count comes with it because the third answer is about files rather
	 * than rows: an owner offered an archive of the quarantined copies is owed
	 * the fact that there are none.
	 *
	 * @return array{choice: string, remove_data: bool, quarantined: int}
	 */
	public static function state(): array {
		return array(
			'choice'      => self::choice(),
			'remove_data' => self::remove_data(),
			'quarantined' => Quarantine::count(),
		);
	}
}
