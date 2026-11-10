<?php
/**
 * Buffered writer for the agent invocation record.
 *
 * A separate buffer from the activity log's, writing a separate table, for
 * the reason that table is separate: the volume profile is different. An
 * agent-heavy request can invoke dozens of abilities where it produces one
 * or two log events, and the two should not share a cap.
 *
 * The buffering is not an optimization, it is the feature's budget. Measured
 * on the shipped platform: listening to the whole ability lifecycle costs
 * 0.0059ms per invocation, while writing one row per invocation as it happens
 * costs 0.84ms — a hundred and fifty times more than the thing it records.
 * One INSERT per request keeps the cost where it was measured.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Agents;

use BetterShield\Database\Schema;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/*
 * A plugin-owned table with no core API, written in one batched statement.
 */
// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

final class InvocationWriter {

	/**
	 * Rows held for one request before the buffer stops accepting more.
	 *
	 * Higher than the activity log's cap because the unit is smaller and the
	 * plausible volume larger: a single agent conversation can drive a long
	 * run of abilities, and truncating it at the log's cap would cut exactly
	 * the sessions worth having a record of.
	 */
	private const MAX_BUFFER = 500;

	private static ?InvocationWriter $instance = null;

	/** @var array<int, array<string, mixed>> */
	private array $buffer = array();

	private int $dropped = 0;

	public static function instance(): InvocationWriter {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	public function register(): void {
		/*
		 * Priority 90, ahead of the activity log's flush at 100: the capture
		 * layer's own shutdown pass closes anything still open and may record
		 * an event into the activity log, and that event has to be in the
		 * log's buffer before the log drains.
		 */
		add_action( 'shutdown', array( $this, 'flush' ), 90 );
	}

	/**
	 * Stop flushing for the rest of this request and drop what is held.
	 *
	 * Same reasoning as the activity log's: the plugin can be deleted inside
	 * a live request, and shutdown then runs against classes the autoloader
	 * can no longer find. There is nowhere left to write.
	 */
	public function stand_down(): void {
		remove_action( 'shutdown', array( $this, 'flush' ), 90 );
		$this->buffer = array();
	}

	/**
	 * Queue one finished invocation record.
	 *
	 * @param array<string, mixed> $row
	 */
	public function record( array $row ): void {
		if ( count( $this->buffer ) >= self::MAX_BUFFER ) {
			++$this->dropped;

			return;
		}

		$this->buffer[] = $row;
	}

	/**
	 * How many rows this request had to drop for want of buffer.
	 *
	 * Read by the capture layer at shutdown so the omission can be stated in
	 * the activity log rather than left as a silent gap. A record that looks
	 * complete and is not is worse than one that says where it stops.
	 */
	public function dropped(): int {
		return $this->dropped;
	}

	public function flush(): void {
		$rows          = $this->buffer;
		$this->buffer  = array();
		$this->dropped = 0;

		if ( array() === $rows ) {
			return;
		}

		/*
		 * The table arrived with schema 8. Until the migration has been
		 * verified and stamped there is nowhere to put these — a narrow window
		 * on a site mid-upgrade, and one this used to pass through in silence.
		 * A record missing a request's worth of invocations reads exactly like
		 * a record of a quiet request, so the loss is stated the same way the
		 * buffer's own overflow is.
		 */
		if ( ! Schema::ready( 'agent_invocations' ) ) {
			\BetterShield\Events\Writer::instance()->record(
				'agent_capture_truncated',
				\BetterShield\Events\Writer::SEVERITY_LOW,
				array(
					'object_type' => 'agent',
					'context'     => array(
						'dropped' => count( $rows ),
						'reason'  => 'schema_not_ready',
					),
				)
			);

			return;
		}

		$this->insert( $rows );
	}

	/**
	 * Test seam.
	 */
	public function reset(): void {
		$this->buffer  = array();
		$this->dropped = 0;
	}

	/**
	 * One multi-row INSERT for the whole batch.
	 *
	 * INSERT IGNORE, deliberately: `correlation_id` is unique, and the only
	 * way a duplicate reaches here is a buffer that flushed twice for the
	 * same record. Ignoring drops that one row; without it the duplicate
	 * would reject the entire batch and lose every other invocation in the
	 * request. The unique key is a safety net and must not become a hazard.
	 *
	 * @param array<int, array<string, mixed>> $rows
	 */
	private function insert( array $rows ): void {
		global $wpdb;

		$columns = array(
			'site_id',
			'invoked_at',
			'correlation_id',
			'ability_name',
			'registering_plugin',
			'entry_path',
			'user_id',
			'outcome',
			'error_code',
			'input_digest',
			'duration_ms',
		);

		// Schema 16; until it is in place the rows are written without it.
		if ( Schema::ready( 'invocation_connection' ) ) {
			$columns[] = 'connection';
		}

		$integers = array( 'site_id', 'user_id', 'duration_ms' );

		$rows_sql = array();
		$params   = array();

		foreach ( $rows as $row ) {
			$placeholders = array();

			foreach ( $columns as $column ) {
				$value = $row[ $column ] ?? null;

				if ( null === $value ) {
					$placeholders[] = 'NULL';
				} elseif ( in_array( $column, $integers, true ) ) {
					$placeholders[] = '%d';
					$params[]       = $value;
				} else {
					$placeholders[] = '%s';
					$params[]       = $value;
				}
			}

			$rows_sql[] = '(' . implode( ',', $placeholders ) . ')';
		}

		$sql = 'INSERT IGNORE INTO %i (' . implode( ',', $columns ) . ') VALUES ' . implode( ',', $rows_sql );

		/*
		 * $sql is assembled, not interpolated: the column list is the literal
		 * whitelist above, the VALUES list holds only generated placeholders
		 * ('%d', '%s' or the NULL keyword), and the table name is bound with
		 * %i. Every value travels in $params through prepare(). Static
		 * analysis cannot see that, and per-row inserts would defeat the
		 * one-query-per-request design this class exists for.
		 */
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query( $wpdb->prepare( $sql, array_merge( array( Schema::table( 'agent_invocations' ) ), $params ) ) );
	}
}
