<?php
/** Confirmed access and emergency actions, shared by the native registry and MCP. @package BetterShield */
declare( strict_types=1 );
namespace BetterShield\Abilities;
use BetterShield\Agents\Capture;
use BetterShield\Login\Sessions;
use BetterShield\Mcp\OAuth;
use BetterShield\Mcp\Server;
use BetterShield\Recovery\Lockdown;
use BetterShield\Recovery\SafeMode;
if ( ! defined( 'ABSPATH' ) ) { exit; }
final class WriteAccess {
	public const PAIRS = array( 'propose-session-end' => 'end-sessions', 'propose-app-revoke' => 'revoke-app', 'propose-lockdown' => 'enter-lockdown' );
	/** Each action in the owner's words, keyed by its short name. */
	public static function labels(): array {
		return array( 'end-sessions' => __( 'End sessions', 'bettershield' ), 'revoke-app' => __( 'Revoke app access', 'bettershield' ), 'enter-lockdown' => __( 'Enter lockdown', 'bettershield' ) );
	}
	public static function definitions( callable $execute, array $plan_meta, array $act_meta, array $plan_fields, array $plan_required ): array {
		$act_meta['meta']['annotations']['idempotent'] = false;
		$id = array( 'type' => 'integer', 'minimum' => 1 ); $integer = array( 'type' => 'integer', 'minimum' => 0 ); $string = array( 'type' => 'string' ); $boolean = array( 'type' => 'boolean' );
		$confirmation = array( 'proposal_id' => $id, 'confirmation' => $string );
		$targets = array( 'end-sessions' => array( 'user_id' => $id, 'scope' => array( 'type' => 'string', 'enum' => array( 'site' ) ) ), 'revoke-app' => array( 'app_id' => $string ), 'enter-lockdown' => array() );
		$labels = self::labels();
		$details = array(
			'end-sessions' => __( 'Ends sessions for one user_id or scope site, only for accounts this administrator may edit. The plan names the reach, skipped accounts, network-wide effects and the administrator’s own browser sessions. Ended sessions cannot be restored.', 'bettershield' ),
			'revoke-app' => __( 'Revokes another connected app’s access and refresh credentials. Refuses the calling app. Reconnecting needs a new approval on the site; revoked credentials cannot be restored.', 'bettershield' ),
			'enter-lockdown' => __( 'Pauses every assistant connection, including the caller, ends dashboard-capable sessions within the stated bound, and leaves the front end and checkout untouched. Lift lockdown only on the site. No undo token is returned.', 'bettershield' ),
		);
		$out = array();
		foreach ( self::PAIRS as $propose => $act ) {
			foreach ( array( $propose, $act ) as $name ) {
				$plan = $name === $propose;
				$fields = 'end-sessions' === $act ? array( 'scope' => array( 'type' => 'string', 'enum' => array( 'site', 'user' ) ), 'user_id' => $id, 'user_name' => $string, 'ended' => $integer, 'skipped' => $integer, 'surplus' => $integer, 'network_wide' => $boolean, 'ended_own' => $boolean ) : ( 'revoke-app' === $act ? array( 'app_id' => $string, 'app_name' => $string ) : array( 'active' => $boolean, 'since' => $integer, 'by' => $id ) );
				$required = 'end-sessions' === $act ? ( $plan ? array( 'scope' ) : array( 'scope', 'ended', 'skipped', 'surplus', 'network_wide', 'ended_own' ) ) : ( 'revoke-app' === $act ? array( 'app_id', 'app_name' ) : ( $plan ? array() : array( 'active' ) ) );
				$out[ 'bettershield/' . $name ] = ( $plan ? $plan_meta : $act_meta ) + array(
					'label' => $plan ? sprintf( /* translators: %s: the action being suggested. */ __( 'Suggest: %s', 'bettershield' ), $labels[ $act ] ) : $labels[ $act ],
					'description' => $details[ $act ] . ' ' . ( $plan ? __( 'Show this plan to the person. Execute only after they agree, using the returned proposal and confirmation.', 'bettershield' ) : __( 'Requires the proposal and its single-use confirmation after the person agrees. There is no direct execution path.', 'bettershield' ) ),
					'input_schema' => array( 'type' => 'object', 'properties' => $plan ? $targets[ $act ] : $confirmation, 'required' => $plan ? ( 'revoke-app' === $act ? array( 'app_id' ) : array() ) : array_keys( $confirmation ) ),
					'output_schema' => array( 'type' => 'object', 'properties' => ( $plan ? $plan_fields : array( 'applied' => $boolean ) ) + $fields, 'required' => array_merge( $plan ? $plan_required : array( 'applied' ), $required ) ),
					'execute_callback' => static function ( $input ) use ( $execute, $name ) { return $execute( $name, $input ); },
				);
			}
		}
		return $out;
	}
	/** Core does not enforce exclusive input alternatives, so callbacks do too. */
	public static function valid_input( string $name, array $input ): bool {
		if ( ! isset( self::PAIRS[ $name ] ) ) {
			return in_array( $name, self::PAIRS, true ) && count( $input ) === 2 && is_int( $input['proposal_id'] ?? null ) && $input['proposal_id'] > 0 && is_string( $input['confirmation'] ?? null ) && '' !== $input['confirmation'];
		}
		if ( 'propose-lockdown' === $name ) { return array() === $input; }
		if ( count( $input ) !== 1 ) { return false; }
		if ( 'propose-app-revoke' === $name ) { return is_string( $input['app_id'] ?? null ) && 1 === preg_match( '/^[a-zA-Z0-9_-]{1,100}$/D', $input['app_id'] ); }
		return ( 'site' === ( $input['scope'] ?? null ) ) || ( is_int( $input['user_id'] ?? null ) && $input['user_id'] > 0 );
	}
	/** Only counts and target labels enter the plan; the live identity is digested in memory. */
	public static function snapshot( string $act, array $input ) {
		$target = array(); $effect = array(); $state = array( 'actor' => get_current_user_id(), 'site' => get_current_blog_id() );
		if ( 'end-sessions' === $act ) {
			if ( 'site' === ( $input['scope'] ?? null ) ) {
				$preview = Sessions::instance()->ending_preview();
				$target = array( 'scope' => 'site' ); $state['preview'] = $preview;
				// Counted in words that agree with the number, and what is left out only when something is (#2142).
				$sessions = (int) $preview['reach']['reaches']; $accounts = count( $preview['accounts'] ); $outside = (int) ( $preview['skipped'] + $preview['surplus'] );
				$effect[] = sprintf( /* translators: 1: reachable sessions, 2: a count of accounts, e.g. "3 accounts". */ _n( 'Ends up to %1$d session across %2$s in reach.', 'Ends up to %1$d sessions across %2$s in reach.', $sessions, 'bettershield' ), $sessions, sprintf( /* translators: %d: number of accounts. */ _n( '%d account', '%d accounts', $accounts, 'bettershield' ), $accounts ) );
				if ( $outside > 0 ) { $effect[] = sprintf( /* translators: %d: accounts outside the bound or authority. */ _n( '%d account is outside this request’s authority or limit.', '%d accounts are outside this request’s authority or limit.', $outside, 'bettershield' ), $outside ); }
				$own = isset( $preview['accounts'][ get_current_user_id() ] );
			} else {
				$id = (int) ( $input['user_id'] ?? 0 ); $user = get_userdata( $id );
				if ( ! $user || ! current_user_can( 'edit_user', $id ) ) { return WriteTriage::error( 'bettershield_session_forbidden', __( 'This account is not available to the granting administrator.', 'bettershield' ), 403 ); }
				// Named as every agent read names an account, never by its login (#1822).
				$name   = ReadSurface::account_label( $id );
				$target = array( 'scope' => 'user', 'user_id' => $id, 'user_name' => $name );
				$state['sessions'] = count( \WP_Session_Tokens::get_instance( $id )->get_all() );
				$effect[] = sprintf( /* translators: 1: session count, 2: account name. */ _n( 'Ends %1$d session for %2$s.', 'Ends %1$d sessions for %2$s.', $state['sessions'], 'bettershield' ), $state['sessions'], $name );
				$own = $id === get_current_user_id();
			}
			if ( $own ) { $effect[] = __( 'Includes the granting administrator’s own browser sessions.', 'bettershield' ); }
			if ( is_multisite() ) { $effect[] = __( 'Sessions are shared across the network: each ending signs that account out of every site.', 'bettershield' ); }
			$effect[] = __( 'Ended sessions cannot be restored. People can sign in again.', 'bettershield' );
		} elseif ( 'revoke-app' === $act ) {
			$id = (string) ( $input['app_id'] ?? '' );
			if ( Server::current_credential() === 'app:' . $id ) { return WriteTriage::error( 'bettershield_calling_app', __( 'This is the calling app. Disconnect this connection through its revocation endpoint or on the site.', 'bettershield' ), 403 ); }
			$found = null;
			foreach ( OAuth::connected_apps() as $app ) { if ( $app['id'] === $id ) { $found = $app; break; } }
			if ( null === $found ) { return WriteTriage::error( 'bettershield_unknown_app', __( 'That app no longer holds access on this site.', 'bettershield' ), 404 ); }
			unset( $found['last_used'] ); $state['app'] = $found;
			$state['grants'] = OAuth::client_grants_digest( $id );
			$target = array( 'app_id' => $id, 'app_name' => $found['name'] );
			$effect[] = sprintf( /* translators: %s: connected app name. */ __( 'Revokes %s and its access and refresh credentials. Other applications keep their access.', 'bettershield' ), $found['name'] );
			$effect[] = 'read write' === $found['scope'] ? __( 'The app currently has read and write access.', 'bettershield' ) : __( 'The app currently has read-only access.', 'bettershield' );
			$effect[] = __( 'This cannot be undone. Reconnecting the app requires a new approval on the site.', 'bettershield' );
		} else {
			if ( Lockdown::state()['active'] || SafeMode::is_active() ) { return WriteTriage::error( 'bettershield_lockdown_unavailable', __( 'The site is already locked down or in safe mode. Review its recovery state on the site.', 'bettershield' ), 409 ); }
			$preview = Lockdown::eviction_preview( get_current_user_id() ); $state['preview'] = $preview;
			$accounts = count( $preview['accounts'] );
			$effect[] = sprintf( /* translators: 1: account count, 2: sweep limit. */ _n( 'Signs out up to %1$d dashboard-capable account, within a limit of %2$d.', 'Signs out up to %1$d dashboard-capable accounts, within a limit of %2$d.', $accounts, 'bettershield' ), $accounts, Lockdown::MAX_EVICTIONS );
			// A lower bound: the count stops one past the limit.
			if ( $preview['skipped'] > 0 ) { $effect[] = sprintf( /* translators: %d: accounts past the limit, at least. */ _n( 'At least %d more account is outside this request.', 'At least %d more accounts are outside this request.', $preview['skipped'], 'bettershield' ), $preview['skipped'] ); }
			$effect[] = __( 'Includes the granting administrator’s browser sessions.', 'bettershield' );
			$effect[] = __( 'Pauses every assistant connection, including this Hub or assistant, until someone lifts lockdown on the site. There is no remote undo.', 'bettershield' );
			$effect[] = __( 'The front end, customer sessions and checkout are untouched. Dashboard code installation and updates are frozen; removing code remains available.', 'bettershield' );
			if ( is_multisite() ) { $effect[] = __( 'Ended sessions sign the affected accounts out across the network. Lockdown itself applies to this site.', 'bettershield' ); }
		}
		return array( 'target' => $target, 'effect' => $effect, 'digest' => (string) Capture::digest( $state + $target ), 'grants' => $state['grants'] ?? null );
	}
	public static function execute( string $act, array $target, ?string $grants = null ) {
		if ( 'enter-lockdown' === $act ) {
			$result = Lockdown::enter( get_current_user_id() );
			if ( is_wp_error( $result ) ) { return $result; }
			return ! empty( $result['active'] ) ? array( 'applied' => true ) + $result : WriteTriage::error( 'bettershield_lockdown_busy', __( 'Lockdown did not start. Read the site’s state before trying again.', 'bettershield' ), 409 );
		}
		if ( 'revoke-app' === $act ) {
			if ( ! OAuth::revoke_client( $target['app_id'], $grants ) ) { return WriteTriage::error( 'bettershield_app_revoke_failed', __( 'The app’s revocation could not be confirmed. Read its access on the site.', 'bettershield' ), 503 ); }
			\BetterShield\Events\Writer::instance()->record( 'mcp_app_revoked', \BetterShield\Events\Writer::SEVERITY_INFO, array( 'object_type' => 'mcp_app', 'object_id' => $target['app_id'] ) );
			return array( 'applied' => true ) + $target;
		}
		$result = 'site' === $target['scope'] ? Sessions::instance()->end_all() : Sessions::instance()->end_for_user( $target['user_id'] ) + array( 'ended' => 1, 'skipped' => 0, 'surplus' => 0 );
		return array( 'applied' => true ) + $target + $result;
	}
}
