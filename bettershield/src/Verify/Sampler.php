<?php
/**
 * Confirms protections from the one place that can: a real visitor's page.
 *
 * Every hardening item this plugin applies is reported from its own stored
 * toggle. That reporting has been wrong more than once — an item that said
 * Applied while every write had failed, checks that called a finding resolved
 * because a flag was set while nothing was hooked at all. Each of those was
 * fixed where it happened; none of them stopped the next one, because the
 * shape of the mistake is structural: the plugin was asked whether it was
 * protecting the site and answered from memory.
 *
 * This asks the site instead.
 *
 * **It costs a visitor nothing, and that is a constraint rather than a hope.**
 * The observation reads what this process already has in memory — the headers
 * it set, the filters it hooked — and makes no request, opens no socket and
 * touches no file. It runs at `shutdown`, after the response has gone. It
 * never runs on the cart or the checkout, or on anything that is not an
 * ordinary front-end page view. And it looks at **one item per request**, the
 * one most overdue, so a site with every protection applied never pays for
 * more than a single option write on any page.
 *
 * The shape is deliberate: a passive sampler first, because it
 * costs no request at all, with a same-site loopback reserved for the one
 * check that genuinely has to make one.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Verify;

use BetterShield\Events\Writer;
use BetterShield\Hardening\Manager;
use BetterShield\Recovery\SafeMode;
use BetterShield\Support\Checkout;
use BetterShield\Support\Cost;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Sampler {

	private static ?Sampler $instance = null;

	public static function instance(): Sampler {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	public function register(): void {
		// Late on shutdown: after the page has been sent, and after the event
		// writer's own flush has been registered, so a status change recorded
		// here still travels with the batch.
		add_action( 'shutdown', array( $this, 'sample' ), 90 );
	}

	/**
	 * Look at one item, if this is a request that can see anything.
	 */
	public function sample(): void {
		if ( ! $this->request_can_observe() ) {
			return;
		}

		$item = $this->most_overdue();

		if ( null === $item ) {
			// The cost this request paid is still worth keeping — a page view
			// on which this plugin did the least is exactly the ordinary page
			// view the published figure is about.
			Cost::record();

			return;
		}

		$seen    = Cost::around( static fn (): array => Checks::observe( $item ) );
		$changed = Cost::around( static fn (): bool => State::record( $item, $seen['status'], $seen['detail'] ) );

		// After the observation, so the write it just made is inside the
		// figure. This runs at shutdown, with the response already sent.
		Cost::record();

		/*
		 * Only a change is worth a row. A protection confirmed present on
		 * every page view for a year is not news, and a log that says so is a
		 * log nobody reads.
		 */
		if ( ! $changed ) {
			return;
		}

		Writer::instance()->record(
			'hardening_verified',
			Checks::ABSENT === $seen['status'] ? Writer::SEVERITY_HIGH : Writer::SEVERITY_INFO,
			array(
				'object_type' => 'hardening',
				'object_id'   => $item,
				'context'     => array(
					'status' => $seen['status'],
				),
			)
		);
	}

	/**
	 * Whether this request is an ordinary front-end page view.
	 *
	 * Everything excluded here is excluded because observing it would either
	 * answer the wrong question or cost somebody something:
	 *
	 * - **Admin, REST, AJAX, cron and CLI** are not the request the
	 *   protections exist for, and reading a front-end guarantee from one of
	 *   them is exactly the mistake this mechanism replaces.
	 * - **The cart and the checkout** are the one path this plugin promises to
	 *   add nothing at all to, whatever the cost would have been.
	 * - **Safe mode** stands every protection down deliberately, so an absence
	 *   there is the feature working, not a fault to report. So does the
	 *   daily server-header probe, for the headers, on its own request.
	 * - **A non-GET**, because a form post is not a page.
	 */
	private function request_can_observe(): bool {
		if ( is_admin() || wp_doing_ajax() || wp_doing_cron() ) {
			return false;
		}

		if ( ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return false;
		}

		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_METHOD'] ) ) ) : '';

		if ( 'GET' !== $method ) {
			return false;
		}

		// A template actually loaded: before `wp` no conditional tag can
		// answer, and nothing observable has happened yet either.
		if ( ! did_action( 'wp' ) ) {
			return false;
		}

		if ( SafeMode::is_active() ) {
			return false;
		}

		// The daily server-header probe, for the same reason: its page leaves
		// the four headers off on purpose, so it says nothing about them.
		if ( Manager::instance()->is_header_probe() ) {
			return false;
		}

		// Asked in the one place that answers it, rather than kept as a third
		// copy: the copies drifted, and the least complete of them was the one
		// deciding whether to end somebody's session.
		return ! Checkout::is_store_path();
	}

	/**
	 * The applied, observable item whose answer is oldest — or one that has
	 * just been applied and is waiting for its first.
	 *
	 * One per request, deliberately. Checking everything on every page view
	 * would turn a page into several option writes for a question whose answer
	 * changes about as often as somebody edits a plugin.
	 */
	private function most_overdue(): ?string {
		$manager = Manager::instance();
		$oldest  = null;
		$stamp   = PHP_INT_MAX;

		foreach ( array_keys( Checks::observers() ) as $item ) {
			if ( ! $manager->is_active( $item ) || ! State::is_due( $item ) ) {
				continue;
			}

			$record = State::for_item( $item );

			// Never looked at, or asked for explicitly: nothing outranks that.
			if ( null === $record || ! empty( $record['pending'] ) ) {
				return $item;
			}

			$at = (int) ( $record['at'] ?? 0 );

			if ( $at < $stamp ) {
				$stamp  = $at;
				$oldest = $item;
			}
		}

		return $oldest;
	}
}
