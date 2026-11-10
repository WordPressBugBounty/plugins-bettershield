<?php
/**
 * Hardening manager: state, enforcement, apply and revert.
 *
 * Items apply individually, never as a batch. Every apply writes an undo
 * ledger entry BEFORE the state changes, and every apply and revert is
 * recorded in the activity log.
 *
 * Two kinds of item live here. The four original ones are runtime-only: a
 * hook added at boot, a hook removed on revert, nothing persisted but the
 * toggle. Items added since may also do work when applied — write a marked
 * block into a file, take an option — and undo that work when reverted. Those
 * are classes under Hardening\Item; this manager runs them through the same
 * apply, revert and ledger path so an item is one thing to a caller whichever
 * kind it is.
 *
 * A third path, act(), runs an item's named actions on an already-applied
 * item. It holds the same state mutex and writes the same activity events, and
 * where the action changes stored state it opens a ledger row first, carrying
 * the exact keys it is about to overwrite.
 *
 * One action cannot be ledgered and says so by returning `ledger => false`:
 * rotating the authentication keys replaces a secret, and the prior value of a
 * secret is a key. Writing it into the ledger to satisfy one rule would break
 * the harder one — no key is ever stored — and a row that put back only the
 * note beside it would name itself an undo of something it cannot undo.
 * Rotation's way back is to derive a different key again, which the item's own
 * description says.
 *
 * An action may also hand back `after`: work it settles only once its change
 * is written, so a change the ledger refused leaves nothing behind.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening;

use BetterShield\Admin\Sections;
use BetterShield\Events\Writer;
use BetterShield\Files\Guarded;
use BetterShield\Support\Claim;
use BetterShield\Support\SentHeaders;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Manager {

	private const OPTION = 'bettershield_hardening';

	/**
	 * Which of the four security headers the web server sent on its own when
	 * last asked, kept whether or not the headers item is on, for the
	 * finding to read.
	 */
	public const SERVER_HEADERS_OPTION = 'bettershield_server_headers';

	/**
	 * One key for the whole state option, since the option is written whole.
	 */
	private const MUTEX = 'hardening_state';

	private const MUTEX_SECONDS = 30;

	/**
	 * Why a protection was taken back off, recorded with the event.
	 *
	 * A person clicking Undo because something broke and an automatic
	 * rollback tripped by observed denials produced byte-identical records,
	 * and the only thing that ever told them apart was a single slot of
	 * interface state the next observation window overwrites. The difference
	 * between "somebody decided this cost too much" and "enough refusals
	 * arrived to take a protection off on its own" is the forensic fact a
	 * security tool has the least business losing, so it travels with the
	 * event, which nothing overwrites.
	 */
	public const CAUSE_MANUAL            = 'manual';
	public const CAUSE_API               = 'api';
	public const CAUSE_MONITOR_AUTO_UNDO = 'monitor_auto_undo';

	/**
	 * Taken off only to go back on with other settings in the same act, as a
	 * settings document's import does: the protection never ends up off, so
	 * this is no "Hardening undone" alarm and no weakening (#1833).
	 */
	public const CAUSE_RECONFIGURE       = 'reconfigure';

	/**
	 * Put back on its own because a change waiting to be confirmed was not:
	 * the HTTPS address switch nobody kept within its five minutes (#1289).
	 */
	public const CAUSE_NOT_KEPT          = 'not_kept';

	/** Put back because a recovery link or printed code was used. */
	public const CAUSE_RECOVERY          = 'recovery';

	/** Marks the dashboard gate as turned on by saving the sign-in address. */
	private const WITH_ADDRESS = 'with_address';

	/** The sign-in address a change is moving away from, between its undo and its apply. */
	private string $moving_address_from = '';

	private static ?Manager $instance = null;

	public static function instance(): Manager {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	/**
	 * @return array<string, array<string, mixed>>
	 */
	private function state(): array {
		$state = get_option( self::OPTION, array() );

		return is_array( $state ) ? $state : array();
	}

	/**
	 * @return array<string, mixed>
	 */
	public function item_state( string $item ): array {
		$state = $this->state();

		return isset( $state[ $item ] ) && is_array( $state[ $item ] ) ? $state[ $item ] : array();
	}

	public function is_active( string $item ): bool {
		return ! empty( $this->item_state( $item )['active'] );
	}

	/**
	 * Whether an item is applied on the network's main site: the site Network
	 * Admin runs as, where what the whole network's administrators reach is
	 * decided. This site's own answer anywhere but on a network.
	 */
	public function active_on_main_site( string $item ): bool {
		if ( ! is_multisite() || is_main_site() ) {
			return $this->is_active( $item );
		}

		$state = get_blog_option( get_main_site_id(), self::OPTION, array() );

		return is_array( $state ) && is_array( $state[ $item ] ?? null ) && ! empty( $state[ $item ]['active'] );
	}


	public function active_count(): int {
		$count = 0;

		foreach ( Items::ids() as $item ) {
			if ( $this->is_active( $item ) ) {
				++$count;
			}
		}

		return $count;
	}

	/**
	 * Hook the runtime effects of every active item. Called once at boot,
	 * before init — must not build translated definitions. Safe mode
	 * pauses everything while leaving configuration untouched.
	 */
	public function enforce(): void {
		if ( \BetterShield\Recovery\SafeMode::is_active() ) {
			return;
		}

		foreach ( Items::ids() as $item ) {
			if ( $this->is_active( $item ) ) {
				$this->enforce_item( $item );
			}
		}
	}

	/**
	 * Remove the runtime effects of every active item without changing
	 * their configured state. Used when safe mode begins mid-request.
	 */
	public function unenforce_all(): void {
		foreach ( Items::ids() as $item ) {
			if ( $this->is_active( $item ) ) {
				$this->unenforce_item( $item );
			}
		}
	}

	/**
	 * Whether an item can work here, and what else already does its job: what
	 * a read needs to say about it, without the preview's usage lines or the
	 * screen's actions, which can record state as they compute it.
	 *
	 * @return array{available: bool, availability_reason: string, availability_label: string, availability_note: ?string, conflict_warning: ?string}
	 */
	public function standing( string $item ): array {
		$items        = Items::all();
		$availability = $this->availability( $item );

		return array(
			'available'           => (bool) $availability['available'],
			'availability_reason' => $availability['reason'],
			'availability_label'  => $availability['label'],
			'availability_note'   => $availability['note'],
			'conflict_warning'  => isset( $items[ $item ] ) ? $this->conflict_of( $item, $items[ $item ] ) : null,
		);
	}

	/**
	 * Whether an item can work here at all, and nothing else about it.
	 */
	public function available( string $item ): bool {
		return isset( Items::all()[ $item ] ) && (bool) $this->availability( $item )['available'];
	}

	/**
	 * Item list with live state and pre-apply conflict warnings.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public function describe_all(): array {
		$out = array();

		foreach ( Items::all() as $id => $item ) {
			$out[] = $this->describe( $id, $item );
		}

		return $out;
	}

	/**
	 * What could go wrong applying an item: its own warning, or else that
	 * another security plugin already does the same job with a switch of its
	 * own. The owner may still apply it; a warning is what keeps the Quick
	 * Setup from ticking it and says so on the Hardening screen.
	 *
	 * @param array<string, mixed> $item
	 */
	private function conflict_of( string $id, array $item ): ?string {
		$notes     = array();
		$elsewhere = \BetterShield\Onboarding\Coexistence::applied_elsewhere( $id );

		// Another plugin already doing the job comes first, and is never
		// hidden by the item's own note: on plain permalinks the username
		// fix's note about author links replaced it, and the owner was not
		// told the fix was already in force.
		if ( '' !== $elsewhere ) {
			$notes[] = sprintf(
				/* translators: %s: the name of another security plugin. */
				__( '%s already does this with its own setting. Leave it to one of them.', 'bettershield' ),
				$elsewhere
			);
		}

		$own = ( $item['conflict'] )();

		if ( null !== $own ) {
			$notes[] = $own;
		}

		return array() === $notes ? null : implode( ' ', $notes );
	}

	/**
	 * @param array<string, mixed> $item
	 * @return array<string, mixed>
	 */
	private function describe( string $id, array $item ): array {
		$state        = $this->item_state( $id );
		$availability = $this->availability( $id );

		return array(
			'id'                => $id,
			// Which group reads this item, and therefore which screen draws it.
			'group'             => $item['group'],
			'title'             => $item['title'],
			'description'       => $item['description'],
			// The why behind the one-line description, behind an ⓘ.
			'detail'            => (string) ( $item['detail'] ?? '' ),
			// Whether applying writes a file, so the preview speaks of a
			// saved copy only where there is one (#2575).
			'writes_files'      => ! empty( $item['writes_files'] ),
			'active'            => ! empty( $state['active'] ),
			// Off here, but in force anyway: the server or another plugin
			// already does it, as the Quick Setup counts it (#2632).
			'in_force_elsewhere' => empty( $state['active'] ) && \BetterShield\Onboarding\SafeFixes::enforced_without_us( $id ),
			'in_force_by'       => \BetterShield\Onboarding\SafeFixes::enforced_by( $id ),
			'applied_at'        => $state['applied_at'] ?? null,
			// In the words of the choice it was applied with, where it took one.
			'effect'            => ( $item['effect'] )( isset( $state['options'] ) && is_array( $state['options'] ) ? $state['options'] : array() ),
			'conflict_warning'  => $this->conflict_of( $id, $item ),
			// How that line reads: a warning, unless the item's line is a
			// neutral next step (#2575).
			'conflict_tone'     => (string) ( $item['conflict_tone'] ?? 'warning' ),
			// Whether the mechanism can work on this server at all, and the
			// sentence that says why not. An item that cannot work is offered
			// as information, never as a toggle that reports success.
			'available'         => $availability['available'],
			// Why not, as a key and as the short status it reads as (#2235).
			'availability_reason' => $availability['reason'],
			'availability_label'  => $availability['label'],
			'availability_url'    => $availability['url'],
			'availability_note' => $availability['note'],
			// Where the mechanism cannot work on this server and the server
			// can be told the same thing by hand: the rule in its own syntax,
			// for the owner or the host to add (#1351). Not where the host is
			// already seen doing it.
			'server_rule'       => 'server_config' === $availability['reason'] ? $this->server_rule( $id ) : null,
			// How the note reads: a warning by default, and good news where
			// the server already does what the item cannot (#2048).
			'availability_tone' => (string) ( $availability['tone'] ?? 'warning' ),
			// What applying actually did, in the item's own words: which part
			// took, which was skipped, what could not be verified.
			'notes'             => isset( $state['notes'] ) && is_array( $state['notes'] ) ? array_values( $state['notes'] ) : array(),
			// Owner-supplied options as applied, for display only.
			'options'           => isset( $state['options'] ) && is_array( $state['options'] ) ? $state['options'] : new \stdClass(),
			// Whether undo takes back everything, for the choice it was
			// applied with: HSTS at six months, or on every subdomain, stays
			// in the browsers that saw it, and the row said "Undo never
			// expires" all the same.
			'reversible'        => Items::is_reversible( $id, isset( $state['options'] ) && is_array( $state['options'] ) ? $state['options'] : array() ),
			// One line of live state worth reading at a glance — the address
			// a moved sign-in page answers at. Computed rather than stored,
			// so it stays true if the site address changes underneath it.
			'summary'           => $this->summary( $id, $state ),
			// What an item that watches has actually seen. A card that names a
			// count and cannot say what it counted asks the owner to fix
			// something it will not name.
			'reports'           => $this->reports( $id ),
			// What an item that lets things through has let through, each with
			// the way back: the content policy's allowed sources.
			'allowed_sources'   => $this->allowed_sources( $id ),
			// Fields the owner fills in before applying, if any.
			'fields'            => isset( $item['fields'] ) ? ( $item['fields'] )() : array(),
			// Extra actions beyond apply and revert, if any.
			'actions'           => isset( $item['actions'] ) ? ( $item['actions'] )() : array(),
			// A revert that failed leaves the item applied and says why.
			'revert_failed'     => $state['revert_failed'] ?? null,
			// What the last visitor's page view actually saw. Null where this
			// item has an effect no page view can observe — which the screen
			// says outright rather than leaving blank.
			'verification'      => \BetterShield\Verify\Checks::is_observable( $id )
				? \BetterShield\Verify\State::for_item( $id )
				: null,
			'observable'        => \BetterShield\Verify\Checks::is_observable( $id ),
			'monitor'           => Monitor::describe( $id ),
		);
	}

	/**
	 * The item's own one-line statement of where it left the site, for items
	 * that have somewhere to state. Null for the rest.
	 *
	 * @param array<string, mixed> $state
	 */
	private function summary( string $id, array $state ): ?string {
		$handler = Items::handlers()[ $id ] ?? null;

		if ( null === $handler || ! method_exists( $handler, 'summary' ) ) {
			return null;
		}

		return $handler::summary( $state );
	}

	/**
	 * What an item that collects has collected, for the items that collect.
	 *
	 * Optional in the same way summary() is: an item that has nothing to show
	 * says so with an empty list rather than a missing key, so the screen
	 * reads one shape whatever it is drawing.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private function reports( string $id ): array {
		$handler = Items::handlers()[ $id ] ?? null;

		if ( null === $handler || ! method_exists( $handler, 'reports' ) ) {
			return array();
		}

		return $handler::reports();
	}

	/**
	 * @return array<int, array<string, string>>
	 */
	private function allowed_sources( string $id ): array {
		$handler = Items::handlers()[ $id ] ?? null;

		if ( null === $handler || ! method_exists( $handler, 'allowed_sources' ) ) {
			return array();
		}

		return $handler::allowed_sources();
	}

	/**
	 * Describe what applying an item would do, changing nothing.
	 *
	 * Deliberately shares no code path with apply(): a dry run that executed
	 * any part of the real thing would not be a dry run.
	 *
	 * @return array{item: string, title: string, already_active: bool, effect: string[], conflict_warning: ?string, available: bool, availability_reason: string, availability_label: string, availability_note: ?string}|\WP_Error
	 */
	public function dry_run( string $item, array $options = array() ) {
		$items = Items::all();

		if ( ! isset( $items[ $item ] ) ) {
			return new \WP_Error( 'bettershield_unknown_item', __( 'Unknown hardening item.', 'bettershield' ), array( 'status' => 404 ) );
		}

		$availability = $this->availability( $item );
		$handler      = Items::handlers()[ $item ] ?? null;

		// Each field's declared default where nothing was given for it. The
		// screen sends them with its preview, and apply's validator fills
		// them itself, so a command line that typed no flag previewed the
		// item with no choice at all: something other than what the same
		// command then applied.
		foreach ( isset( $items[ $item ]['fields'] ) ? ( $items[ $item ]['fields'] )() : array() as $field ) {
			if ( isset( $field['key'] ) && array_key_exists( 'default', $field ) && empty( $field['screen_only'] ) && ! array_key_exists( $field['key'], $options ) ) {
				$options[ $field['key'] ] = $field['default'];
			}
		}

		// What the owner typed is checked here, by the same validator apply
		// uses. A preview that cannot fail is worse than no preview: it is the
		// control offered for checking an address before committing to it, and
		// answering "that will work" to one that will not is the opposite of
		// what it is for.
		$refusal = null;

		if ( array() !== $options && null !== $handler && method_exists( $handler, 'validate' ) ) {
			$validated = $handler::validate( $options );

			if ( is_wp_error( $validated ) ) {
				$refusal = $validated->get_error_message();
			} else {
				$options = $validated;
			}
		}

		// An item whose choice changes what it does says so in its own lines;
		// the rest ignore the options they are handed. An applied item is
		// described by the choice it was applied with: the screen sends a
		// hidden field's default, and the command line sends nothing.
		$effect = ( $items[ $item ]['effect'] )(
			$this->is_active( $item )
				? (array) ( $this->item_state( $item )['options'] ?? array() )
				: ( null === $refusal ? $options : array() )
		);

		// An item that can say what the owner's own answer would produce says
		// it, rather than describing the shape of the answer.
		if ( null === $refusal && array() !== $options && null !== $handler && method_exists( $handler, 'preview' ) ) {
			$effect = array_merge( $handler::preview( $options ), $effect );
		}

		/*
		 * And what the log knows, which is a different kind of answer from
		 * everything above it. The lines above describe who is structurally
		 * affected; these say whether anything has actually used the thing in
		 * the window the log covers. For an item with no capability holders to
		 * count — XML-RPC — it is the only answer there is, and its absence is
		 * why that item stayed off on sites where turning it off was free.
		 *
		 * First, because it is the question somebody opened the preview to
		 * have answered.
		 */
		$effect = array_merge( Usage::lines( $item, $options ), $effect );

		return array(
			'item'              => $item,
			'title'             => $items[ $item ]['title'],
			'already_active'    => $this->is_active( $item ),
			'effect'            => $effect,
			'refusal'           => $refusal,
			'conflict_warning'  => $this->conflict_of( $item, $items[ $item ] ),
			'available'           => $availability['available'],
			'availability_reason' => $availability['reason'],
			'availability_label'  => $availability['label'],
			'availability_note'   => $availability['note'],
		);
	}

	/**
	 * Hold the state mutex for the length of one change.
	 *
	 * Every item's state lives in one option, read whole and written whole, so
	 * two changes to *different* items collide exactly as two changes to the
	 * same item do: each reads the array, each sets its own key, and the
	 * second write drops the first one's entry. The item then reads as not
	 * applied at the next boot while its enforcement is gone, its file tokens
	 * are lost, and its undo row stays open with nothing naming it — and the
	 * undo table is never pruned, so that row is there for good.
	 *
	 * One key covers every item because one option holds every item. Anything
	 * that reads the state, decides, and writes it back belongs in here — the
	 * daily task that continues a capped item's work included, which is why
	 * this is reachable from outside.
	 *
	 * The window is long enough for a handler that writes files and short
	 * enough that a process killed mid-apply does not leave the screen refusing
	 * changes for long; a lapsed claim is taken over by whoever comes next.
	 *
	 * @param callable():mixed $work
	 * @return mixed
	 */
	public function with_state_claimed( callable $work ) {
		if ( ! Claim::claim( self::MUTEX, self::MUTEX_SECONDS ) ) {
			return new \WP_Error(
				'bettershield_state_busy',
				__( 'Another change is being applied. Try again in a moment.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		try {
			return $work();
		} finally {
			Claim::release( self::MUTEX );
		}
	}

	/**
	 * Apply one item. Returns the undo token, or a WP_Error.
	 *
	 * @param array<string, mixed> $options Owner-supplied options for items that take them.
	 * @return array{item: string, undo_token: string, conflict_warning: ?string, notes: string[]}|\WP_Error
	 */
	public function apply( string $item, array $options = array() ) {
		return $this->with_state_claimed( fn() => $this->apply_claimed( $item, $options ) );
	}

	/**
	 * Apply one item from its row on the Protection screen, the one place a
	 * field marked `screen_only` is answered. Every other caller goes through
	 * apply() and gets only what it names.
	 *
	 * @param array<string, mixed> $options Owner-supplied options for items that take them.
	 * @return array{item: string, undo_token: string, conflict_warning: ?string, notes: string[]}|\WP_Error
	 */
	public function apply_from_screen( string $item, array $options = array() ) {
		return $this->with_state_claimed( fn() => $this->apply_claimed( $item, $options, true ) );
	}

	/**
	 * Revert one item, restoring the prior state exactly.
	 *
	 * @param string $cause One of the CAUSE_* constants: what asked for this.
	 * @return array{item: string, reverted: bool}|\WP_Error
	 */
	public function revert_if_token( string $item, string $token, string $cause = self::CAUSE_MANUAL ) {
		return $this->with_state_claimed( function () use ( $item, $token, $cause ) {
			if ( ( $this->item_state( $item )['token'] ?? '' ) !== $token ) { return new \WP_Error( 'bettershield_stale_item', __( 'The protection changed after monitoring. Review it manually.', 'bettershield' ) ); }
			return $this->revert_claimed( $item, $cause );
		} );
	}

	/**
	 * @param string $cause One of the CAUSE_* constants: what asked for this.
	 * @return array{item: string, reverted: bool}|\WP_Error
	 */
	public function revert( string $item, string $cause = self::CAUSE_MANUAL ) {
		return $this->with_state_claimed( fn() => $this->revert_claimed( $item, $cause ) );
	}

	/**
	 * A cause nobody recognizes is recorded as unrecognized rather than as a
	 * person. The whole value of the field is that an automatic rollback can
	 * never be read as somebody clicking Undo, and a default that quietly
	 * says "manual" would give that away on the first caller that forgets.
	 */
	private static function cause( string $cause ): string {
		$known = array( self::CAUSE_MANUAL, self::CAUSE_API, self::CAUSE_MONITOR_AUTO_UNDO, self::CAUSE_RECONFIGURE, self::CAUSE_NOT_KEPT, self::CAUSE_RECOVERY );

		return in_array( $cause, $known, true ) ? $cause : 'unknown';
	}

	/**
	 * How loudly a protection coming off is recorded, by what asked for it.
	 *
	 * Taken off by a person, at a screen or the command line, it reaches the
	 * owner at once, as taking off sign-in protection, a two-factor or passkey
	 * requirement, the decoy or agent recording already does. It is also the
	 * step a stolen session takes to clear the way, and most protections have
	 * no check that would report the gap afterwards. A cause nobody recognizes
	 * is graded as a person.
	 *
	 * Two causes stay in the digest. An assistant's change was confirmed by a
	 * person minutes earlier, and its own row beside this one carries that
	 * grade. The monitor's rollback was asked for in advance by whoever set its
	 * threshold. Neither is quieter than a revert that failed.
	 */
	private static function revert_severity( string $cause ): int {
		// Off and straight back on with other settings: a settings change,
		// recorded and not raised.
		if ( self::CAUSE_RECONFIGURE === $cause ) {
			return Writer::SEVERITY_LOW;
		}

		return in_array( $cause, array( self::CAUSE_API, self::CAUSE_MONITOR_AUTO_UNDO ), true )
			? Writer::SEVERITY_MEDIUM
			: Writer::SEVERITY_HIGH;
	}

	/**
	 * Run one of an item's extra actions on an applied item.
	 *
	 * @param array<string, mixed> $args What the action is about, for the actions that take something.
	 * @return array<string, mixed>|\WP_Error
	 */
	public function act( string $item, string $action, array $args = array() ) {
		return $this->with_state_claimed( fn() => $this->act_claimed( $item, $action, $args ) );
	}

	/**
	 * Rotate the sign-in key that a whole network shares.
	 *
	 * The site-level item refuses on a network and says why: one sign-in
	 * covers every site, so the key that signs it is shared, and rotating it
	 * ends every session on every site at once. That is not one site's
	 * decision, so it is offered from the network dashboard instead — and this
	 * is what that button calls.
	 *
	 * Three things happen, in this order and no other:
	 *
	 * 1. The shared secret is replaced, which makes every cookie on every site
	 *    of the network unverifiable from that instant.
	 * 2. The administrator who pressed it is handed a new session, minted under
	 *    the key that now exists. Without this the act would sign out the one
	 *    person who has to stay signed in to see it finish — and a rotation
	 *    writes no undo row, so there would be nothing to press.
	 * 3. Everything else is ended, site by site, each site's log carrying its
	 *    own row so the people affected read it where they will look.
	 *
	 * The item's per-site state is deliberately not touched. Marking it applied
	 * on a site would put a revert switch on that site's screen for a key the
	 * whole network is using, and pressing it would sign every site out again
	 * from a screen that says nothing of the kind.
	 *
	 * @param int  $actor_id The administrator performing it, whose own session is carried over.
	 * @param bool $remember Whether that session was a remembered one.
	 * @return array{rotated: bool, ended: int, accounts: int, sites: int, capped: bool, handed_off: bool}|\WP_Error
	 */
	public function rotate_network_keys( int $actor_id = 0, bool $remember = false ) {
		// The mutex is this site's, and this runs from the network dashboard,
		// which is the main site's request. It is here so two administrators
		// pressing at once do not each sweep the whole network.
		return $this->with_state_claimed( fn() => $this->rotate_network_keys_claimed( $actor_id, $remember ) );
	}

	/**
	 * @return array{rotated: bool, ended: int, accounts: int, sites: int, capped: bool, handed_off: bool}|\WP_Error
	 */
	private function rotate_network_keys_claimed( int $actor_id, bool $remember ) {
		$rotated = Item\AuthKeys::rotate_network();

		if ( is_wp_error( $rotated ) ) {
			return $rotated;
		}

		$keep_token = $actor_id > 0 ? Item\AuthKeys::hand_off_session( $actor_id, $remember ) : '';

		$swept = \BetterShield\Login\Sessions::instance()->end_across_network(
			$actor_id,
			$keep_token,
			'network_key_rotation'
		);

		$main     = get_main_site_id();
		$switched = get_current_blog_id() !== $main;

		// The rotation is the network's act, and the network's own record is
		// the main site's log — the same place the network surfaces put their
		// undo rows.
		if ( $switched ) {
			switch_to_blog( $main );
		}

		// Recorded inside a `finally`, so a write that throws still hands the
		// request back to the site it came from rather than leaving everything
		// after it addressed to the main site.
		try {
			Writer::instance()->record(
				'keys_rotated',
				Writer::SEVERITY_INFO,
				array(
					'object_type' => 'hardening',
					'object_id'   => 'auth_keys',
					'context'     => array(
						'scope'      => 'network',
						'sites'      => $swept['sites'],
						'ended'      => $swept['ended'],
						'handed_off' => '' !== $keep_token,
						// Named rather than silent: a network large enough to
						// outrun the clock has sites whose own row was never
						// written, and a record that did not say so would read
						// as though every site had been reached.
						'capped'     => $swept['capped'],
					),
				)
			);

			Writer::instance()->flush();
		} finally {
			if ( $switched ) {
				restore_current_blog();
			}
		}

		return array(
			'rotated'    => true,
			'ended'      => $swept['ended'],
			'accounts'   => $swept['accounts'],
			'sites'      => $swept['sites'],
			'capped'     => $swept['capped'],
			'handed_off' => '' !== $keep_token,
		);
	}

	/**
	 * @param array<string, mixed> $options Owner-supplied options for items that take them.
	 * @return array{item: string, undo_token: string, conflict_warning: ?string, notes: string[]}|\WP_Error
	 */
	private function apply_claimed( string $item, array $options = array(), bool $from_screen = false ) {
		$items = Items::all();

		if ( ! isset( $items[ $item ] ) ) {
			return new \WP_Error( 'bettershield_unknown_item', __( 'Unknown hardening item.', 'bettershield' ), array( 'status' => 404 ) );
		}

		if ( $this->is_active( $item ) ) {
			return new \WP_Error( 'bettershield_already_active', __( 'This item is already applied.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$availability = $this->availability( $item );
		if ( ! $availability['available'] ) {
			return new \WP_Error(
				'bettershield_unavailable',
				(string) $availability['note'],
				array(
					'status' => 409,
					'reason' => $availability['reason'],
				)
			);
		}

		$handler = Items::handlers()[ $item ] ?? null;

		$hide_dashboard = $from_screen && Item\LoginUrl::class === $handler && Item\LoginUrl::asks_to_hide_dashboard( $options );

		if ( null !== $handler && method_exists( $handler, 'validate' ) ) {
			$options = $handler::validate( $options );
			if ( is_wp_error( $options ) ) {
				$options->add_data( array( 'status' => 400 ) );

				return $options;
			}
		} else {
			$options = array();
		}

		// Ledger first: if this write fails, nothing may change.
		$token = Ledger::open(
			'harden_' . $item,
			array( 'active' => false ),
			array(
				'active'  => true,
				'options' => $options,
			)
		);

		if ( null === $token ) {
			return new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}

		$file_tokens = array();
		$notes       = array();

		if ( null !== $handler && method_exists( $handler, 'apply' ) ) {
			// Anything a previous, interrupted apply of this item left ledgered
			// but unattached is put back first, so this apply starts from the
			// state the site was in before that one.
			foreach ( Guarded::restore_open( 'harden_' . $item ) as $problem ) {
				$notes[] = $problem;
			}

			$done = $handler::apply( $options );

			if ( is_wp_error( $done ) ) {
				// The change never took effect: the ledger row closes at once, and
				// the failure is what the log carries.
				Ledger::mark_reverted( $token );

				Writer::instance()->record(
					'hardening_failed',
					Writer::SEVERITY_LOW,
					array(
						'object_type' => 'hardening',
						'object_id'   => $item,
						'context'     => array( 'reason' => $done->get_error_code() ),
					)
				);

				$done->add_data( array( 'status' => 409 ) );

				return $done;
			}

			$file_tokens = $done['tokens'] ?? array();
			$notes       = array_merge( $notes, $done['notes'] ?? array() );
		}

		$state          = $this->state();
		$state[ $item ] = array(
			'active'      => true,
			'token'       => $token,
			'applied_at'  => gmdate( 'c' ),
			'options'     => $options,
			'file_tokens' => array_values( $file_tokens ),
			'notes'       => array_values( $notes ),
		) + array_intersect_key( $state[ $item ] ?? array(), array( self::WITH_ADDRESS => true ) );
		if ( ! update_option( self::OPTION, $state, true ) && $this->item_state( $item ) !== $state[ $item ] ) {
			return new \WP_Error( 'bettershield_state_write_failed', __( 'This could not be saved. Check any recorded file changes before retrying.', 'bettershield' ), array( 'status' => 503 ) );
		}

		// Configured either way; hooked now only when enforcement is on at
		// all — under safe mode the promise is that nothing is enforced.
		if ( ! \BetterShield\Recovery\SafeMode::is_active() ) {
			$this->enforce_item( $item );
		}

		/*
		 * Applied is not the same as working, and reporting it as though it
		 * were is the mistake this plugin has now made more than once. The
		 * item is marked as wanting confirmation, and the next page a visitor
		 * loads provides it.
		 */
		if ( \BetterShield\Verify\Checks::is_observable( $item ) ) {
			\BetterShield\Verify\State::mark_pending( $item );
		}

		Writer::instance()->record(
			'hardening_applied',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'hardening',
				'object_id'   => $item,
				'context'     => array() === $notes ? array() : array( 'notes' => array_values( $notes ) ),
			)
		);

		if ( $hide_dashboard ) {
			$notes = array_merge( $notes, $this->hide_dashboard_with_address() );
		}

		if ( Item\LoginUrl::class === $handler ) {
			$this->address_changed( (string) ( $options['slug'] ?? '' ), $this->moving_address_from );
			$this->moving_address_from = '';
		}

		return array(
			'item'             => $item,
			'undo_token'       => $token,
			'conflict_warning' => $this->conflict_of( $item, $items[ $item ] ),
			'notes'            => array_values( $notes ),
		);
	}

	/** Says the sign-in address changed, when it did. */
	private function address_changed( string $new, string $old ): void {
		if ( $new === $old ) {
			return;
		}

		/**
		 * Fires after the sign-in address is applied, changed or undone. Runs
		 * while the change is still held, so don't apply or undo another
		 * protection from here.
		 *
		 * @param string $new The address now, empty when it was undone.
		 * @param string $old The address before, empty when there was none.
		 */
		do_action( 'bettershield_login_address_changed', $new, $old );
	}

	/**
	 * Turns the dashboard gate on as part of saving the sign-in address, and
	 * marks it as turned on that way, so undoing the address takes it off
	 * only if this save was what put it on. Left on the address's own undo
	 * row, a gate the owner turned on before would go too. A gate that can't
	 * go on leaves the address on, and the card's warning still shows.
	 *
	 * @return string[] What to tell the owner.
	 */
	private function hide_dashboard_with_address(): array {
		if ( $this->is_active( 'admin_gate' ) ) {
			return array();
		}

		$done = $this->apply_claimed( 'admin_gate' );

		if ( is_wp_error( $done ) ) {
			return array( __( 'Dashboard privacy for visitors could not be turned on. Turn it on from its own row.', 'bettershield' ) );
		}

		$state                                      = $this->state();
		$state['admin_gate'][ self::WITH_ADDRESS ] = true;
		update_option( self::OPTION, $state, true );

		return array();
	}

	/**
	 * Revert one item, restoring the prior state exactly.
	 *
	 * An item whose side effects cannot be undone stays applied and says why:
	 * flipping the toggle off while a file it wrote is still in place would be
	 * the interface lying about the site.
	 *
	 * @param string $cause One of the CAUSE_* constants: what asked for this.
	 * @return array{item: string, reverted: bool}|\WP_Error
	 */
	private function revert_claimed( string $item, string $cause = self::CAUSE_MANUAL ) {
		if ( ! isset( Items::all()[ $item ] ) ) {
			return new \WP_Error( 'bettershield_unknown_item', __( 'Unknown hardening item.', 'bettershield' ), array( 'status' => 404 ) );
		}

		if ( ! $this->is_active( $item ) ) {
			return new \WP_Error( 'bettershield_not_active', __( 'This item is not applied.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$state   = $this->state();
		$current = $state[ $item ];
		$token   = $current['token'] ?? null;
		$handler = Items::handlers()[ $item ] ?? null;

		// An item whose change is not every administrator's to make may
		// refuse an undo by somebody who could not have applied it, before
		// anything is touched or recorded as a failed undo.
		if ( null !== $handler && method_exists( $handler, 'refuse_revert' ) ) {
			$refused = $handler::refuse_revert();

			if ( $refused instanceof \WP_Error ) {
				return $refused;
			}
		}

		$revert_notes = array();

		if ( null !== $handler && method_exists( $handler, 'revert' ) ) {
			// Files whose undo record has vanished cannot be put back from it;
			// the revert still completes, and names them.
			$lost = Item\FileTokens::unaccounted( $current );
			if ( array() !== $lost ) {
				$revert_notes[] = sprintf(
					/* translators: %d: number of file changes without an undo record. */
					_n( '%d file change had no undo record, so it was not undone.', '%d file changes had no undo record, so they were not undone.', count( $lost ), 'bettershield' ),
					count( $lost )
				);
			}

			$undone = $handler::revert( $current );

			// Undone, with what it left as it was and why.
			if ( is_array( $undone ) && isset( $undone['notes'] ) && is_array( $undone['notes'] ) ) {
				$revert_notes = array_merge( $revert_notes, array_map( 'strval', $undone['notes'] ) );
			}

			if ( is_wp_error( $undone ) ) {
				$state[ $item ]['revert_failed'] = $undone->get_error_message();
				update_option( self::OPTION, $state, true );

				Writer::instance()->record(
					'hardening_revert_failed',
					Writer::SEVERITY_MEDIUM,
					array(
						'object_type' => 'hardening',
						'object_id'   => $item,
						'context'     => array( 'reason' => $undone->get_error_code() ),
					)
				);

				$undone->add_data( array( 'status' => 409 ) );

				return $undone;
			}
		}

		// Off and straight back on with other settings is still the same save
		// as far as the address is concerned, so the mark waits for the apply.
		$state[ $item ] = array( 'active' => false ) + ( self::CAUSE_RECONFIGURE === $cause ? array_intersect_key( $current, array( self::WITH_ADDRESS => true ) ) : array() );
		if ( ! update_option( self::OPTION, $state, true ) && $this->item_state( $item ) !== $state[ $item ] ) {
			return new \WP_Error( 'bettershield_state_write_failed', __( 'This could not be saved. Check the current state and undo record before retrying.', 'bettershield' ), array( 'status' => 503 ) );
		}

		$this->unenforce_item( $item );

		if ( is_string( $token ) ) {
			Ledger::mark_reverted( $token );
		}

		// Anything an interrupted apply of this item left ledgered but never
		// attached to its state is put back now as well.
		$revert_notes = array_merge( $revert_notes, Guarded::restore_open( 'harden_' . $item ) );

		// The protection is gone on purpose, so its last verification is not a
		// finding — it is an answer about something nobody is claiming any more.
		\BetterShield\Verify\State::forget( $item );
		\BetterShield\Onboarding\SafeFixes::switched_off( $item );

		// Nor is what the XML-RPC probe saw while this plugin was the one
		// refusing it. The probe asks again now, in the background, rather
		// than at its daily run: a host that refuses xmlrpc.php itself still
		// does, and until it is asked the site reads as serving it. Its own
		// argument, so core does not take it for the recurring event.
		if ( 'xmlrpc' === $item ) {
			delete_option( \BetterShield\Audit\XmlRpc::OPTION );
			wp_schedule_single_event( time(), \BetterShield\Audit\XmlRpc::TASK, array( time() ) );
		}

		$context = array( 'cause' => self::cause( $cause ) );

		if ( array() !== $revert_notes ) {
			$context['notes'] = $revert_notes;
		}

		Writer::instance()->record(
			'hardening_reverted',
			self::revert_severity( $context['cause'] ),
			array(
				'object_type' => 'hardening',
				'object_id'   => $item,
				'context'     => $context,
			)
		);

		// The redirect sends plain HTTP to the HTTPS address; with the address
		// back on http it would keep sending visitors to the HTTPS that just
		// failed, and after its first day with a 301 browsers keep. It goes
		// with it, recorded under the same cause so it can be told apart and
		// applied again (#2282).
		if ( Item\HttpsAddress::ITEM === $item && $this->is_active( Item\HttpsRedirect::ITEM ) ) {
			$this->revert_claimed( Item\HttpsRedirect::ITEM, $cause );
		}

		// A change of address is told once, by the apply that follows.
		if ( 'login_url' === $item ) {
			$old = (string) ( $current['options']['slug'] ?? '' );

			if ( self::CAUSE_RECONFIGURE === $cause ) {
				$this->moving_address_from = $old;
			} else {
				$this->address_changed( '', $old );
			}
		}

		// The dashboard gate the address's own save turned on goes with it. A
		// change of address keeps it: the gate is still wanted.
		if ( 'login_url' === $item && self::CAUSE_RECONFIGURE !== $cause && ! empty( $this->item_state( 'admin_gate' )[ self::WITH_ADDRESS ] ) ) {
			$this->revert_claimed( 'admin_gate', $cause );
		}

		return array(
			'item'     => $item,
			'reverted' => true,
			'notes'    => $revert_notes,
		);
	}

	/**
	 * Run one of an item's extra actions — rotate, re-check — on an applied
	 * item. The handler owns the semantics; this owns the gate.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	private function act_claimed( string $item, string $action, array $args = array() ) {
		if ( ! isset( Items::all()[ $item ] ) ) {
			return new \WP_Error( 'bettershield_unknown_item', __( 'Unknown hardening item.', 'bettershield' ), array( 'status' => 404 ) );
		}

		$handler = Items::handlers()[ $item ] ?? null;

		if ( null === $handler || ! method_exists( $handler, 'act' ) ) {
			return new \WP_Error( 'bettershield_unknown_action', __( 'This item has no such action.', 'bettershield' ), array( 'status' => 404 ) );
		}

		if ( ! $this->is_active( $item ) ) {
			return new \WP_Error( 'bettershield_not_active', __( 'This item is not applied.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$state  = $this->state();
		$result = $handler::act( $action, $state[ $item ], $args );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		// Work an action leaves for once its change is written rather than
		// before it, so a change the ledger refused leaves nothing behind.
		$after = isset( $result['after'] ) && $result['after'] instanceof \Closure ? $result['after'] : null;
		unset( $result['after'] );

		// An action whose only reversal is doing it again says so, and gets no
		// row rather than one that would name itself an undo of something it
		// cannot put back.
		$ledgerable = ! isset( $result['ledger'] ) || false !== $result['ledger'];
		unset( $result['ledger'] );

		// An action may leave the item with new notes or options. A change to
		// stored state is a change like any other, so it gets its own ledger
		// row before it is written — recording exactly the keys it is about to
		// overwrite, so the way back is the state that was there and not a
		// guess at it.
		if ( $ledgerable && isset( $result['state'] ) && is_array( $result['state'] ) ) {
			/*
			 * The keys about to be overwritten, so the row carries the state
			 * that was there rather than a guess at it. An item whose absent
			 * key means something — report-only, for the content policy —
			 * states its own prior instead, because only the item knows what
			 * its defaults are and a row built from the keys that happen to
			 * exist would carry nothing at all.
			 */
			$prior = isset( $result['prior'] ) && is_array( $result['prior'] )
				? $result['prior']
				: array_intersect_key( $state[ $item ], $result['state'] );

			unset( $result['prior'] );

			$token = Ledger::open( 'harden_' . $item . '_' . $action, $prior, $result['state'] );

			if ( null === $token ) {
				return new \WP_Error(
					'bettershield_ledger_failed',
					__( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ),
					array( 'status' => 500 )
				);
			}

			$state[ $item ] = array_merge( $state[ $item ], $result['state'] );
			update_option( self::OPTION, $state, true );
			unset( $result['state'] );

			$result['undo_token'] = $token;
		} elseif ( isset( $result['state'] ) && is_array( $result['state'] ) ) {
			unset( $result['prior'] );

			$state[ $item ] = array_merge( $state[ $item ], $result['state'] );
			update_option( self::OPTION, $state, true );
			unset( $result['state'] );
		}

		if ( null !== $after ) {
			$after();
		}

		return $result;
	}

	/**
	 * Whether the item can work here, why not as a reason key, and the short
	 * status that key reads as (#2235).
	 *
	 * @return array{available: bool, reason: string, label: string, url: ?string, tone?: string, note: ?string}
	 */
	private function availability( string $item ): array {
		$handler = Items::handlers()[ $item ] ?? null;
		$answer  = null !== $handler && method_exists( $handler, 'availability' )
			? $handler::availability()
			: array(
				'available' => true,
				'note'      => null,
			);

		$reason = $answer['available'] ? '' : (string) ( $answer['reason'] ?? '' );

		return array(
			'reason' => $reason,
			'label'  => $answer['available'] ? '' : self::availability_label( $reason ),
			// Where the next step is taken, where this screen is not the place.
			'url'    => 'network_admin' === $reason && current_user_can( Sections::NETWORK_CAPABILITY ) ? network_admin_url( 'admin.php?page=' . Sections::NETWORK_ROOT ) : null,
		) + $answer;
	}

	/**
	 * The item's rule in the syntax of the server this site runs on, for
	 * the items whose rule a server can be given by hand.
	 *
	 * @return array{server: string, label: string, where: string, text: string}|null
	 */
	private function server_rule( string $item ): ?array {
		$handler = Items::handlers()[ $item ] ?? null;

		if ( null === $handler || ! method_exists( $handler, 'server_rule' ) ) {
			return null;
		}

		return $handler::server_rule();
	}

	/**
	 * The short status for why an item cannot be applied here. Read from the
	 * item's reason key, never from its sentence, so every surface that
	 * shows the status says the same thing. A cause nobody named stays the
	 * plain "Not available here".
	 */
	public static function availability_label( string $reason ): string {
		switch ( $reason ) {
			case 'server_config':
				return __( 'Requires server configuration', 'bettershield' );
			case 'server_enforced':
				return __( 'Server check passed', 'bettershield' );
			case 'main_site':
				return __( 'Apply from the main site', 'bettershield' );
			case 'https':
				return __( 'Needs HTTPS', 'bettershield' );
			case 'network_admin':
				return __( 'Managed in Network Admin', 'bettershield' );
			case 'not_needed':
				return __( 'Not needed here', 'bettershield' );
			case 'other_plugin':
				return __( 'Handled by another plugin', 'bettershield' );
			default:
				return __( 'Not available here', 'bettershield' );
		}
	}

	/* ---- runtime effects ------------------------------------------- */

	/**
	 * Every route an item closes, declared once: hook, method, priority,
	 * accepted arguments.
	 *
	 * The audit asks whether an item is still enforcing, and it can only ask
	 * honestly if it reads the same list the item hooks from. Written out in
	 * both places, the audit checked two of the eight routes the user
	 * enumeration item attaches and called the finding resolved while the
	 * users sitemap was serving every author's login name again. Kept as data
	 * so adding a route to an item is adding it to the check.
	 *
	 * Only items whose whole effect is method callbacks appear here. An item
	 * that also removes a core hook or hangs a function on one has state the
	 * hook table cannot answer for, and `enforcement_attached()` refuses to
	 * speak for it rather than guessing.
	 *
	 * @return array<string, array<int, array{0: string, 1: string, 2: int, 3: int}>>
	 */
	private static function enforcement_routes(): array {
		return array(
			'file_editor'      => array(
				array( 'map_meta_cap', 'block_file_editor_caps', 10, 2 ),
			),

			'user_enumeration' => array(
				array( 'rest_endpoints', 'gate_rest_user_listing', 10, 1 ),
				// Priority 0: core's own canonical redirect runs on this hook at
				// 10, and that redirect is the leak.
				array( 'template_redirect', 'block_author_enumeration', 0, 1 ),
				// The third route: the users sitemap lists every author's archive,
				// whose address is the login name.
				array( 'wp_sitemaps_add_provider', 'drop_users_sitemap', 10, 2 ),
				array( 'template_redirect', 'refuse_users_sitemap', 0, 1 ),
				// And the author sitemap an SEO plugin serves in place of the
				// users sitemap, which lists the same archives. Priority 1 on
				// parse_request: the earliest of them answers later on it.
				array( 'parse_request', 'refuse_author_sitemaps', 1, 1 ),
				// And the author lists those plugins build into other places:
				// a root sitemap with indexes switched off, and an HTML sitemap.
				array( 'aioseo_sitemap_author_archives', 'list_no_authors', 10, 1 ),
				array( 'rank_math/sitemap/author/query', 'query_no_authors', 10, 1 ),
				// The fourth route, which the other three left open: an oEmbed
				// response names the author of any public post, so a single
				// embed request hands out a display name and an author URL that
				// resolves to the login name.
				array( 'oembed_response_data', 'strip_oembed_author', 10, 1 ),
				// The fifth route, and the one most actually used: the sign-in
				// form answers a wrong password and an unknown username with
				// two different sentences. Priority 99, so every gate that has
				// something specific to say has already said it.
				array( 'authenticate', 'generic_sign_in_error', 99, 1 ),
				array( 'shake_error_codes', 'shake_on_generic_error', 10, 1 ),
				// The sixth, and the one the fifth made obvious: with the
				// sign-in form saying the same thing either way, the lost
				// password form next to it was the remaining place to ask.
				// Last, so a refusal another plugin adds later is seen first.
				array( 'lostpassword_errors', 'generic_lost_password', PHP_INT_MAX, 2 ),
				// And what core answers only an account that exists, once
				// every check has passed: an email it could not send, or a
				// reset the site refuses it, printed where an unknown account
				// is redirected. Noted last, answered on wp-login.php.
				array( 'lostpassword_errors', 'note_lost_password_account', PHP_INT_MAX, 2 ),
				array( 'lost_password', 'generic_lost_password_failure', 10, 1 ),
			),
		);
	}

	/**
	 * Whether every route this item closes is still hooked.
	 *
	 * Switched on is not the same as working: a third-party `remove_action`, a
	 * plugin re-registering a provider, or a half-finished revert can leave
	 * some of an item's routes attached and others open. False here means at
	 * least one route is open, which is exactly the case an audit exists to
	 * catch.
	 *
	 * An item with no routes declared cannot be answered for, and answers
	 * false rather than green: a check that cannot see is not a check that
	 * found nothing.
	 */
	public function enforcement_attached( string $item ): bool {
		$routes = self::enforcement_routes()[ $item ] ?? array();

		foreach ( $routes as $route ) {
			// has_action() is has_filter() under another name, and one lookup
			// answers for both kinds of route.
			if ( false === has_filter( $route[0], array( $this, $route[1] ) ) ) {
				return false;
			}
		}

		return array() !== $routes;
	}

	/**
	 * Whether a handler-driven item's own hooks are still attached on this
	 * request, as its handler answers; null for an item whose handler does
	 * not say. During safe mode nothing is attached, and that is the answer.
	 */
	public function handler_enforced( string $item ): ?bool {
		$handler = Items::handlers()[ $item ] ?? null;

		if ( null === $handler || ! method_exists( $handler, 'is_enforced' ) ) {
			return null;
		}

		return (bool) $handler::is_enforced( $this->item_state( $item ) );
	}

	private function enforce_item( string $item ): void {
		$handler = Items::handlers()[ $item ] ?? null;

		if ( null !== $handler ) {
			$handler::enforce( $this->item_state( $item ) );

			return;
		}

		$routes = self::enforcement_routes()[ $item ] ?? array();

		if ( array() !== $routes ) {
			foreach ( $routes as $route ) {
				add_filter( $route[0], array( $this, $route[1] ), $route[2], $route[3] );
			}

			return;
		}

		switch ( $item ) {
			case 'security_headers':
				add_filter( 'wp_headers', array( $this, 'add_security_headers' ), 10, 2 );
				// wp_headers only runs for front-end responses WordPress renders
				// itself, so the sign-in page and the REST API — the two
				// surfaces most worth covering — received none of these. Both
				// send headers their own way.
				add_action( 'login_init', array( $this, 'send_security_headers' ), 0 );
				add_filter( 'rest_pre_serve_request', array( $this, 'send_security_headers_for_rest' ), 10, 1 );
				// And the dashboard, which had the least of these and the most
				// to lose by it: core sends two of the four to wp-admin, and
				// the two it does not are the ones that matter where uploads,
				// the media library and the installers live. The stakes were
				// backwards — full coverage on an anonymous page view, partial
				// on the screen a compromised session is after.
				add_action( 'admin_init', array( $this, 'send_security_headers' ), 0 );
				break;
		}
	}

	private function unenforce_item( string $item ): void {
		$handler = Items::handlers()[ $item ] ?? null;

		if ( null !== $handler ) {
			$handler::unenforce( $this->item_state( $item ) );

			return;
		}

		$routes = self::enforcement_routes()[ $item ] ?? array();

		if ( array() !== $routes ) {
			foreach ( $routes as $route ) {
				remove_filter( $route[0], array( $this, $route[1] ), $route[2] );
			}

			return;
		}

		switch ( $item ) {
			case 'security_headers':
				remove_filter( 'wp_headers', array( $this, 'add_security_headers' ) );
				remove_action( 'login_init', array( $this, 'send_security_headers' ), 0 );
				remove_filter( 'rest_pre_serve_request', array( $this, 'send_security_headers_for_rest' ), 10 );
				remove_action( 'admin_init', array( $this, 'send_security_headers' ), 0 );
				break;
		}
	}

	/* ---- file editor --------------------------------------------------- */

	/**
	 * @param string[] $caps
	 * @return string[]
	 */
	public function block_file_editor_caps( array $caps, string $cap ): array {
		if ( in_array( $cap, array( 'edit_plugins', 'edit_themes', 'edit_files' ), true ) ) {
			return array( 'do_not_allow' );
		}

		return $caps;
	}

	/**
	 * Require authentication for the REST user collection.
	 *
	 * @param array<string, mixed> $endpoints
	 * @return array<string, mixed>
	 */
	public function gate_rest_user_listing( array $endpoints ): array {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}

		unset( $endpoints['/wp/v2/users'], $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );

		return $endpoints;
	}

	/**
	 * Stop `?author=1` resolving a user number to a login name.
	 *
	 * WordPress answers that URL with a redirect to the author archive, whose
	 * address contains the account's login name — so the numbers 1 upward walk
	 * out the username list without touching the REST API at all. Only the
	 * numeric form is refused: `?author=some-slug` discloses nothing that the
	 * author archive it resolves to does not already publish.
	 */
	public function block_author_enumeration(): void {
		if ( is_user_logged_in() ) {
			return;
		}

		// Decided from what the query resolved to, not from the raw string:
		// WordPress reads `author` from GET and POST alike and strips
		// non-digits before resolving it, so `?author=+1`, `?author=1a` and
		// a POSTed author all reach the same archive. An author archive that
		// was reached by number (no author_name in the query) is the leak; one
		// reached by its pretty address already shows the name in the URL and
		// discloses nothing new.
		if ( ! is_author() || '' !== (string) get_query_var( 'author_name' ) ) {
			return;
		}

		// A scanner's first question, already caught here: counted as a known
		// probe where the owner turned that surface on (#690).
		\BetterShield\Login\Probes::instance()->note_author_probe();

		wp_safe_redirect( home_url( '/' ), 302 );
		exit;
	}

	/**
	 * Take the author out of an oEmbed response for a visitor who is not
	 * signed in.
	 *
	 * `author_name` is a display name and `author_url` is the author archive,
	 * whose address is the login name under pretty permalinks — the same fact
	 * the other three routes are closed to hide. Signed-in requests are left
	 * alone, as they are everywhere else in this item: this closes a public
	 * leak, it does not degrade the editor.
	 *
	 * @param array<string, mixed> $data
	 * @return array<string, mixed>
	 */
	public function strip_oembed_author( $data ) {
		if ( ! is_array( $data ) || is_user_logged_in() ) {
			return $data;
		}

		unset( $data['author_name'], $data['author_url'] );

		return $data;
	}

	/**
	 * Keep the users provider out of the sitemap index. Posts and pages keep
	 * theirs; only the list of author archives — one login name per entry —
	 * is withheld.
	 *
	 * @param mixed  $provider
	 * @param string $name
	 * @return mixed
	 */
	public function drop_users_sitemap( $provider, string $name ) {
		return 'users' === $name ? false : $provider;
	}

	/**
	 * And a direct request for it answers 404.
	 *
	 * Withholding the provider keeps the users sitemap out of the index, but
	 * core's renderer returns without a word when it is asked for a provider
	 * it does not have, and the request then falls through to an ordinary
	 * page: wp-sitemap-users-1.xml answered 200 with the front page in it,
	 * which reads as "there is something here". There is not, and this says
	 * so the way a missing page does.
	 */
	public function refuse_users_sitemap(): void {
		if ( 'users' !== get_query_var( 'sitemap' ) ) {
			return;
		}

		global $wp_query;

		$wp_query->set_404();
		status_header( 404 );
		nocache_headers();
	}

	/**
	 * Close the author sitemap an SEO plugin serves in place of core's.
	 *
	 * The widely used SEO plugins replace the core sitemaps with their own,
	 * and each lists every author's archive, whose address is the login name:
	 * the list the users sitemap above withholds. One of them even sends the
	 * core address on to its own. Each is judged by what that plugin itself
	 * routes on, and answered before any of them serves: the type the
	 * `sitemap` variable names (a slug one of them lets a site rename), a
	 * variable of its own, or the address itself, read the way the plugin
	 * that routes on it reads it. One also has a stylesheet that replays a
	 * cached sitemap named by the address the request says it came from,
	 * which a visitor writes for themselves.
	 *
	 * @param mixed $wp
	 */
	public function refuse_author_sitemaps( $wp ): void {
		if ( ! $wp instanceof \WP || ! self::asks_for_an_author_sitemap( $wp ) ) {
			return;
		}

		status_header( 404 );
		nocache_headers();

		wp_die(
			esc_html__( 'This page is not available.', 'bettershield' ),
			esc_html__( 'Not found', 'bettershield' ),
			array( 'response' => 404 )
		);
	}

	/**
	 * Whether a parsed request is for an author sitemap, however the plugin
	 * that would serve it routes one. Wider than any one of them, never
	 * narrower: a type in capitals, a paged or compressed copy.
	 */
	private static function asks_for_an_author_sitemap( \WP $wp ): bool {
		$vars = is_array( $wp->query_vars ) ? $wp->query_vars : array();
		$type = isset( $vars['sitemap'] ) && is_string( $vars['sitemap'] ) ? strtolower( $vars['sitemap'] ) : '';
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- the slug another plugin gives its author sitemap, asked of that plugin's own filter.
		$slug = strtolower( (string) apply_filters( 'rank_math/sitemap/author/slug', 'author' ) );

		if ( '' !== $type && in_array( $type, array( 'author', $slug ), true ) ) {
			return true;
		}

		if ( ! empty( $vars['seopress_author'] ) ) {
			return true;
		}

		$path = '' !== (string) $wp->request
			? (string) $wp->request
			: (string) wp_parse_url( isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '', PHP_URL_PATH ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- only the path is compared; nothing is stored or printed.

		/*
		 * And the core users sitemap's own address, which an SEO plugin that
		 * switches the core sitemaps off sends on to its author sitemap
		 * rather than leaving it to the route above.
		 */
		if ( self::names_an_author_sitemap( $path ) || 1 === preg_match( '#(?:^|/)wp-sitemap-users-\d+\.xml/?$#i', $path ) ) {
			return true;
		}

		// The stylesheet, replaying whichever sitemap the referring address names.
		if ( 1 === preg_match( '#(?:^|/)default-sitemap\.xsl$#i', $path ) ) {
			$referer = wp_get_referer();

			return false !== $referer && self::names_an_author_sitemap( (string) wp_parse_url( $referer, PHP_URL_PATH ) );
		}

		return false;
	}

	/**
	 * Whether an address is an author sitemap's: any page, compressed or not,
	 * under the file name the one plugin that lets a site rename it uses.
	 * Trailing slashes are dropped first, as that plugin drops them.
	 */
	private static function names_an_author_sitemap( string $path ): bool {
		$path  = rtrim( $path, '/\\' );
		$names = array( 'sitemap' );

		if ( function_exists( 'aioseo' ) && 1 === preg_match( '#\.xml(?:\.gz)?$#i', $path ) ) {
			try {
				$names[] = (string) aioseo()->sitemap->helpers->filename( 'general' );
			} catch ( \Throwable $e ) {
				unset( $e );
			}
		}

		$names = implode( '|', array_map( static fn( string $name ): string => preg_quote( $name, '#' ), array_filter( array_unique( $names ) ) ) );

		return 1 === preg_match( '#(?:^|/)author-(?:' . $names . ')\d*\.xml(?:\.gz)?$#i', $path );
	}

	/**
	 * No author archives in a list an SEO plugin builds into another sitemap.
	 *
	 * @param mixed $entries
	 * @return array<int, mixed>
	 */
	public function list_no_authors( $entries ): array {
		unset( $entries );

		return array();
	}

	/**
	 * And no authors in the query another builds its author lists from,
	 * including the one on an HTML sitemap page.
	 *
	 * @param mixed $args
	 * @return mixed
	 */
	public function query_no_authors( $args ) {
		return is_array( $args ) ? array_merge( $args, array( 'include' => array( 0 ) ) ) : $args;
	}

	/**
	 * The error codes this replaces, and nothing else.
	 *
	 * Each one differs from the others only in whether the account exists,
	 * which is the whole of the leak.
	 */
	private const NAMING_ERRORS = array( 'invalid_username', 'invalid_email', 'incorrect_password' );

	/**
	 * Answer a wrong password and an unknown account with the same sentence.
	 *
	 * This item closed four routes to a site's usernames and left open the one
	 * an attacker actually uses. WordPress tells a visitor which of two things
	 * went wrong — "the password you entered for the username editor is
	 * incorrect" against "the username totallyfakeuser999 is not registered on
	 * this site" — so a list of candidate names can be sorted into real and
	 * not real, one request at a time, with the item fully applied. It also sat
	 * oddly beside two of this plugin's own findings, both of which exist
	 * because a known username is a risk.
	 *
	 * Replaced only when every code in the error is one of the three that leak.
	 * A refusal this plugin raised itself — a lockout, an unsolved puzzle, a
	 * second factor — carries its own code and its own instructions, and those
	 * are messages somebody needs in order to get in.
	 *
	 * @param mixed $user
	 * @return mixed
	 */
	public function generic_sign_in_error( $user ) {
		if ( ! is_wp_error( $user ) ) {
			return $user;
		}

		$codes = $user->get_error_codes();

		if ( array() === $codes || array() !== array_diff( $codes, self::NAMING_ERRORS ) ) {
			return $user;
		}

		return new \WP_Error(
			'bettershield_invalid_credentials',
			__( '<strong>Error:</strong> The username or password you entered is incorrect.', 'bettershield' )
		);
	}

	/**
	 * Keep the sign-in form's own feedback.
	 *
	 * Core shakes the form for each of the codes replaced above and would not
	 * recognize the one that replaced them, so a person who mistyped their
	 * password would have got a quieter refusal than before — a hardening item
	 * that makes the site feel broken is one people turn off.
	 *
	 * @param mixed $codes
	 * @return mixed
	 */
	public function shake_on_generic_error( $codes ) {
		if ( ! is_array( $codes ) ) {
			return $codes;
		}

		$codes[] = 'bettershield_invalid_credentials';

		return $codes;
	}

	/**
	 * The code WordPress has already raised, by the time this filter runs, for
	 * no reason but that no account matched.
	 *
	 * Only one, because core reaches that conclusion in two places at two
	 * times: an address that matches nothing gets `invalid_email` before the
	 * filter, and a username that matches nothing gets `invalidcombo` after
	 * it. The second is never visible here — it is pre-empted instead, by
	 * leaving before core can add it.
	 */
	private const LOST_PASSWORD_NAMING_ERRORS = array( 'invalid_email' );

	/**
	 * Answer a lost-password request the same way whether the account exists.
	 *
	 * With the sign-in form saying one sentence either way, this was the last
	 * form on the site that still sorted a list of guesses into real and not
	 * real — and easier to script than the one it replaced, because the two
	 * answers differ by more than a sentence. An account that exists gets a
	 * redirect to the confirmation page; one that does not gets an error page.
	 * Rewriting the sentence would leave the status code, so this sends the
	 * unknown-account case to the confirmation the known one reaches.
	 *
	 * What that costs is real and worth naming: somebody who mistypes their
	 * address is told a link is on its way and then no email arrives. That is
	 * the standard trade, and it is made here rather than by default — the
	 * item is opt-in and its undo removes this with the rest.
	 *
	 * Replaced only when every code present is one of the two that mean "no
	 * such account". An empty username, or a refusal another plugin added, is
	 * something the person needs to read.
	 *
	 * One thing this does not equalize: the known-account path sends an email
	 * before redirecting, so it takes longer. Closing that would mean holding
	 * the unknown case for a made-up interval, which is a guess about somebody
	 * else's mail server rather than a measurement.
	 *
	 * @param mixed $errors
	 * @param mixed $user_data
	 * @return mixed
	 */
	public function generic_lost_password( $errors, $user_data = null ) {
		// Emptiness is core's own test for "no account matched", and a filter
		// on `lostpassword_user_data` can put something there that is not a
		// WP_User; whatever core would email, this leaves alone.
		if ( ! empty( $user_data ) || ! is_wp_error( $errors ) ) {
			return $errors;
		}

		$codes = $errors->get_error_codes();

		if ( array() !== array_diff( $codes, self::LOST_PASSWORD_NAMING_ERRORS ) ) {
			/*
			 * Another refusal is something the person needs to read, so it
			 * stands, but without core's "no such account" beside it. An
			 * account that exists never gets that sentence, so the pair was
			 * an answer of its own.
			 */
			foreach ( self::LOST_PASSWORD_NAMING_ERRORS as $naming ) {
				$errors->remove( $naming );
			}

			return $errors;
		}

		/*
		 * On wp-login.php itself, exactly what its success path hands
		 * wp_safe_redirect() for an account that exists: the caller's
		 * redirect_to read the way it reads it, or the relative literal it
		 * falls back to. The same value in is the same Location out, byte for
		 * byte, whatever directory WordPress sits in, whatever the sign-in
		 * address is called, and whatever filters the redirect on its way.
		 * The same page spelled another way was still a second answer.
		 */
		if ( 'wp-login.php' === ( $GLOBALS['pagenow'] ?? '' ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput -- read exactly as wp-login.php reads it, so the two answers match; wp_safe_redirect refuses anything off this site.
			wp_safe_redirect( ! empty( $_REQUEST['redirect_to'] ) ? $_REQUEST['redirect_to'] : 'wp-login.php?checkemail=confirm' );
			exit;
		}

		/*
		 * Anywhere else, a form another plugin or a theme puts on a page of
		 * its own: the same destination wp-login.php sends a successful
		 * request to, including the caller's own redirect_to when there is
		 * one, because the success path honors it, and a request that did
		 * not would be distinguishable again by where it landed.
		 */
		$requested = isset( $_REQUEST['redirect_to'] ) ? wp_unslash( $_REQUEST['redirect_to'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- read only to mirror the success path; wp_safe_redirect refuses anything off this site.

		/*
		 * Built absolutely, from the helper core's own wp_lostpassword_url()
		 * uses. A relative Location resolves against the directory of the
		 * request, and this fires from whatever handler called the action —
		 * so the bare literal is the confirmation page only when the caller
		 * happens to sit at the site root, and a 404 anywhere else.
		 */
		$default = add_query_arg( 'checkemail', 'confirm', network_site_url( 'wp-login.php', 'login' ) );

		wp_safe_redirect( '' !== (string) $requested ? (string) $requested : $default );
		exit;
	}

	/** The account a lost-password request named, once nothing refused it. */
	private int $lost_password_account = 0;

	/**
	 * Note that a lost-password request named an account that exists and that
	 * nothing refused, so whatever goes wrong after this is core's answer to
	 * a real account alone.
	 *
	 * @param mixed $errors
	 * @param mixed $user_data
	 * @return mixed
	 */
	public function note_lost_password_account( $errors, $user_data = null ) {
		$this->lost_password_account = $user_data instanceof \WP_User && is_wp_error( $errors ) && ! $errors->has_errors() ? (int) $user_data->ID : 0;

		return $errors;
	}

	/**
	 * Answer a reset that failed for an account that exists the way one that
	 * worked is answered.
	 *
	 * After every check has passed, core can still fail a real account: the
	 * site refuses it a reset, the reset key cannot be stored, or the email
	 * cannot be sent. Each comes back as a sentence only an account that
	 * exists could get, on the page where an unknown one is redirected to the
	 * confirmation, so a site whose mail is broken answered "this account is
	 * real" to every request. It gets the redirect a sent email gets, exactly
	 * as wp-login.php builds it, and the failure is recorded for the owner,
	 * who is the one able to fix it. Fires on wp-login.php alone, before it
	 * prints anything.
	 *
	 * @param mixed $errors
	 */
	public function generic_lost_password_failure( $errors ): void {
		$account                     = $this->lost_password_account;
		$this->lost_password_account = 0;

		if ( 0 === $account || ! $errors instanceof \WP_Error || ! $errors->has_errors() || 'wp-login.php' !== ( $GLOBALS['pagenow'] ?? '' ) ) {
			return;
		}

		// One row a while per account, however often somebody asks.
		$suppressed = \BetterShield\Events\Coalescer::admit( 'bettershield_reset_unsent-' . $account, 5 * MINUTE_IN_SECONDS );

		if ( null !== $suppressed ) {
			Writer::instance()->record(
				'password_reset_unsent',
				Writer::SEVERITY_MEDIUM,
				array(
					'actor_type'  => 'anonymous',
					'object_type' => 'user',
					'object_id'   => (string) $account,
					'context'     => array_filter(
						array(
							'reason'            => (string) $errors->get_error_code(),
							'unlogged_attempts' => $suppressed,
						)
					),
				)
			);
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput -- read exactly as wp-login.php reads it, so the two answers match; wp_safe_redirect refuses anything off this site.
		wp_safe_redirect( ! empty( $_REQUEST['redirect_to'] ) ? $_REQUEST['redirect_to'] : 'wp-login.php?checkemail=confirm' );
		exit;
	}

	/**
	 * Add response headers, never replace one already set.
	 *
	 * A site that already sends these — at the server, or through another
	 * plugin — has made a choice, and silently overriding it would be a change
	 * this plugin never announced.
	 *
	 * WordPress's post-embed page exists to be framed by other sites, the
	 * embed of a post somebody pasted on theirs. A frame header there blanked
	 * every such embed, so it is left off that page. The query has not run
	 * yet when these headers are sent; the parsed request says it is an
	 * embed already.
	 *
	 * @param array<string, string> $headers
	 * @param mixed                 $wp      The request WordPress parsed.
	 * @return array<string, string>
	 */
	public function add_security_headers( array $headers, $wp = null ): array {
		if ( $this->is_header_probe() ) {
			return $headers;
		}

		$embed = $wp instanceof \WP && ! empty( $wp->query_vars['embed'] );

		/*
		 * "Already set" means set anywhere, compared without regard to case
		 * (#2238). An exact-key lookup missed a lowercase `permissions-policy`
		 * another filter added, and a header() call made earlier in the
		 * request, which WordPress's own header() then replaced: DENY became
		 * SAMEORIGIN and no-referrer a weaker policy.
		 */
		$present = array_map( 'strtolower', array_map( 'strval', array_keys( $headers ) ) );

		foreach ( $this->headers_to_send() as $name => $value ) {
			if ( $embed && 'x-frame-options' === strtolower( $name ) ) {
				continue;
			}

			if ( ! in_array( strtolower( $name ), $present, true ) && ! SentHeaders::carries( $name ) ) {
				$headers[ $name ] = $value;
			}
		}

		return $headers;
	}

	/**
	 * The same headers on a surface that does not run `wp_headers`.
	 *
	 * Sent rather than filtered, and never overwriting one the server or core
	 * already set — the same rule the filter follows, for the same reason: a
	 * header somebody chose deliberately is not this plugin's to replace.
	 */
	public function send_security_headers(): void {
		if ( headers_sent() || $this->is_header_probe() ) {
			return;
		}

		$already = array();
		foreach ( headers_list() as $header ) {
			$already[] = strtolower( trim( (string) strtok( $header, ':' ) ) );
		}

		foreach ( $this->headers_to_send() as $name => $value ) {
			if ( ! in_array( strtolower( $name ), $already, true ) ) {
				header( $name . ': ' . $value );
			}
		}
	}

	/**
	 * The token the probe carries: a keyed hash of the current minute, so
	 * nothing is stored that could be lost. A token kept in a transient and
	 * evicted before the answer came back would have made this plugin send
	 * its own headers on the probe's response, and the item would then have
	 * learned that the server sends all four and stood aside for every one
	 * of them. The receiving request accepts this minute's and the last.
	 */
	private static function header_probe_token( int $minute ): string {
		return wp_hash( 'bettershield_header_probe|' . $minute, 'auth' );
	}

	/**
	 * Which of the four headers this site's server already sends.
	 *
	 * The send path defers to a header PHP can see, and a header the web
	 * server adds after PHP has answered is one it cannot: on a host whose
	 * nginx adds X-Frame-Options itself, visitors got that header twice. So
	 * the site is asked — one request to its own front page carrying a
	 * token that makes this plugin's send path stand aside for that one
	 * response — and whatever of the four came back was the server's. Those
	 * names are kept on the item's state and left to the server until the
	 * next asking. Asked from the daily task rather than from the apply,
	 * because the everyday path opens no connection: applying a protection
	 * is a click on an admin page, and this is a request to the web server
	 * with a length nothing here controls. A probe that fails, on a host
	 * that refuses loopback requests, learns nothing and the item sends
	 * everything as it always did.
	 */
	public function learn_server_headers(): void {
		// HSTS asks the same question: a Strict-Transport-Security the web
		// server adds is just as invisible from here, and a second one with a
		// shorter max-age can win in the browser.
		$headers_on = $this->is_active( 'security_headers' );
		$hsts_on    = $this->is_active( 'hsts' );

		/*
		 * Asked with both items off as well: the headers finding reads the
		 * answer, and a server that sends all four already does what the
		 * item would. Nothing is sent by this plugin on that answer, so what
		 * came back is the server's (or another plugin's), as a visitor
		 * gets it.
		 */
		$token = self::header_probe_token( (int) floor( time() / MINUTE_IN_SECONDS ) );

		/*
		 * An address no page cache holds. The plain front page is the one
		 * every page cache answers from a copy rendered while this item was
		 * on, with its own headers replayed in it; read as the server's, they
		 * stopped the item sending any of the four on the sign-in page, the
		 * dashboard and REST, which no page cache serves.
		 */
		$response = \BetterShield\Support\Http::same_site(
			'/?bettershield_probe=' . md5( $token ),
			array(
				'headers' => array( 'X-BetterShield-Probe' => $token ),
				'timeout' => 5,
			)
		);

		if ( is_wp_error( $response ) ) {
			// Nothing learned, so nothing is credited to the server.
			update_option(
				self::SERVER_HEADERS_OPTION,
				array(
					'checked_at' => gmdate( 'c' ),
					'reliable'   => false,
					'sends'      => array(),
				),
				false
			);

			return;
		}

		$names = array_map( 'strtolower', array_keys( Items::headers() ) );
		$sent  = array();
		$hsts  = false;

		/*
		 * And an answer that still says a cache served it may be this item's
		 * own output, replayed, so none of its headers count as the server's.
		 * What an earlier, cached answer left on record is dropped too rather
		 * than kept: on a cache that answers every asking, it would withhold
		 * the headers for good. A header sent twice does no harm; one sent by
		 * nobody does.
		 */
		if ( array() === \BetterShield\Audit\SignInCache::signals( $response ) ) {
			foreach ( wp_remote_retrieve_headers( $response ) as $name => $value ) {
				$name = strtolower( (string) $name );

				if ( in_array( $name, $names, true ) && ! in_array( $name, $sent, true ) ) {
					$sent[] = $name;
				}

				$hsts = $hsts || 'strict-transport-security' === $name;
			}
		}

		// A cached answer leaves $sent empty, so it earns nothing here either.
		update_option(
			self::SERVER_HEADERS_OPTION,
			array(
				'checked_at' => gmdate( 'c' ),
				'reliable'   => true,
				'sends'      => $sent,
			),
			false
		);

		if ( ! $headers_on && ! $hsts_on ) {
			return;
		}

		$state = get_option( self::OPTION, array() );

		if ( ! is_array( $state ) ) {
			return;
		}

		if ( $headers_on && isset( $state['security_headers'] ) && is_array( $state['security_headers'] ) ) {
			$state['security_headers']['server_sends'] = $sent;
		}

		if ( $hsts_on && isset( $state['hsts'] ) && is_array( $state['hsts'] ) ) {
			$state['hsts']['server_sends'] = $hsts;
		}

		update_option( self::OPTION, $state, true );
	}

	/**
	 * Which of the four headers the server was last seen sending on its own,
	 * lowercase; none when it was never asked or the asking failed.
	 *
	 * @return string[]
	 */
	public static function server_sends_headers(): array {
		$stored = get_option( self::SERVER_HEADERS_OPTION, null );

		if ( ! is_array( $stored ) || empty( $stored['reliable'] ) ) {
			return array();
		}

		return array_values( array_map( 'strtolower', array_map( 'strval', (array) ( $stored['sends'] ?? array() ) ) ) );
	}

	/**
	 * Whether this request is the probe above, which the send path stands
	 * aside for. Only a request carrying the token the probe was sent with,
	 * while it is out, is: a header alone is not a way to switch the
	 * headers off. Public because the page-view sampler stands aside for it
	 * too: its page leaves the headers off on purpose.
	 */
	public function is_header_probe(): bool {
		if ( empty( $_SERVER['HTTP_X_BETTERSHIELD_PROBE'] ) ) {
			return false;
		}

		$carried = sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_X_BETTERSHIELD_PROBE'] ) );
		$minute  = (int) floor( time() / MINUTE_IN_SECONDS );

		return hash_equals( self::header_probe_token( $minute ), $carried )
			|| hash_equals( self::header_probe_token( $minute - 1 ), $carried );
	}

	/**
	 * The four headers, less any the server was seen sending.
	 *
	 * @return array<string, string>
	 */
	private function headers_to_send(): array {
		$left = array_map( 'strtolower', (array) ( $this->item_state( 'security_headers' )['server_sends'] ?? array() ) );
		$send = array();

		foreach ( Items::headers() as $name => $value ) {
			if ( ! in_array( strtolower( $name ), $left, true ) ) {
				$send[ $name ] = $value;
			}
		}

		return $send;
	}

	/**
	 * REST responses, which bypass `wp_headers` entirely.
	 *
	 * @param bool $served Whether the request has already been served.
	 * @return bool
	 */
	public function send_security_headers_for_rest( $served ) {
		$this->send_security_headers();

		return $served;
	}
}
