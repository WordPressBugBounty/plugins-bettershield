<?php
/**
 * Hardening item definitions.
 *
 * Most items are applied through runtime filters and plugin-owned state.
 * The few that write a file do so through Files\Guarded — a marked block
 * they own, or a whole file they create — and never rewrite anything
 * outside it. Each item declares what it changes in plain language and a
 * conflict probe that runs BEFORE applying, so warnings appear next to the
 * toggle instead of after a failure.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Items {

	/**
	 * Items that change the site's own address or how it is reached. A
	 * certificate that fails afterwards can take the dashboard with it, so
	 * each waits for a proved way back in, as a sign-in change does, and an
	 * assistant asks for it rather than applying it (#1289).
	 */
	public const ADDRESS_ITEMS = array( 'https_address', 'https_redirect' );

	/**
	 * Item identifiers only, translation-free: safe to call before init,
	 * where building the full definitions would trigger premature
	 * textdomain loading.
	 *
	 * @return string[]
	 */
	public static function ids(): array {
		return array(
			'xmlrpc',
			'file_editor',
			'user_enumeration',
			'security_headers',
			'uploads_php',
			'directory_browsing',
			'sensitive_files',
			'login_url',
			'application_passwords',
			'breached_passwords',
			'reset_link_lifetime',
			'email_change_confirm',
			'admin_gate',
			'version_disclosure',
			'auth_keys',
			'hsts',
			'csp_report_only',
			'admin_area_access',
			'cloud_metadata',
			'https_address',
			'https_redirect',
			'registration_role',
			'unfiltered_code',
			'script_uploads',
			'php_error_display',
			'ajax_origins',
			'ability_access',
			'own_auto_updates',
			'takeover_settings',
			'sign_in_no_cache',
		);
	}

	/**
	 * Whether undoing an item takes back everything it did, for the options
	 * it is (or would be) applied with.
	 *
	 * Read off the item: an item whose way back depends on how it is applied
	 * declares a callable. One that says nothing is treated as reversible,
	 * which every item was before any of them said anything.
	 *
	 * @param array<string, mixed> $options
	 */
	public static function is_reversible( string $item, array $options = array() ): bool {
		$definition = self::all()[ $item ] ?? array();

		if ( ! isset( $definition['reversible'] ) ) {
			return true;
		}

		if ( $definition['reversible'] instanceof \Closure ) {
			return (bool) ( $definition['reversible'] )( $options );
		}

		return (bool) $definition['reversible'];
	}

	/**
	 * Whether one of an item's extra actions puts protection on rather than
	 * taking it off, as the item answers. The password gate asks before a
	 * protection comes down and never before one goes up; an action no item
	 * vouches for is read as one that comes down.
	 */
	public static function adds_protection( string $item, string $action ): bool {
		$handler = self::handlers()[ $item ] ?? null;

		return null !== $handler && method_exists( $handler, 'adds_protection' ) && (bool) $handler::adds_protection( $action );
	}

	/**
	 * Items with behavior beyond runtime filters: a class the manager calls
	 * for apply-time work, revert, availability, options and extra actions.
	 * Translation-free and safe before init.
	 *
	 * @return array<string, class-string>
	 */
	public static function handlers(): array {
		return array(
			'xmlrpc'             => Item\XmlRpc::class,
			'uploads_php'        => Item\UploadsPhp::class,
			'directory_browsing' => Item\DirectoryBrowsing::class,
			'sensitive_files'    => Item\SensitiveFiles::class,
			'login_url'          => Item\LoginUrl::class,
			'application_passwords' => Item\ApplicationPasswords::class,
			'breached_passwords' => Item\BreachedPasswords::class,
			'reset_link_lifetime' => Item\ResetLinks::class,
			'email_change_confirm' => Item\EmailChange::class,
			'hsts'               => Item\Hsts::class,
			'csp_report_only'    => Item\ContentSecurityPolicy::class,
			'admin_area_access'  => Item\AdminAreaAccess::class,
			'admin_gate'         => Item\AdminGate::class,
			'version_disclosure' => Item\VersionDisclosure::class,
			'auth_keys'          => Item\AuthKeys::class,
			'cloud_metadata'     => Item\CloudMetadata::class,
			'https_address'      => Item\HttpsAddress::class,
			'https_redirect'     => Item\HttpsRedirect::class,
			'registration_role'  => Item\RegistrationRole::class,
			'unfiltered_code'    => Item\UnfilteredCode::class,
			'script_uploads'     => Item\ScriptUploads::class,
			'php_error_display'  => Item\PhpErrorDisplay::class,
			'ajax_origins'       => Item\AjaxOrigins::class,
			'ability_access'     => Item\AbilityAccess::class,
			'own_auto_updates'   => Item\OwnAutoUpdates::class,
			'takeover_settings'  => Item\TakeoverSettings::class,
			'sign_in_no_cache'   => Item\SignInNoCache::class,
		);
	}

	/**
	 * Response headers the security_headers item adds.
	 *
	 * Deliberately the four that change no behavior a normal site relies on.
	 * Strict-Transport-Security is not among them: it is the one header here
	 * that can make a site unreachable, because a browser that has seen it
	 * refuses plain HTTP for the whole max-age whatever the site does next.
	 * That belongs behind its own explicit choice, not inside a general item.
	 *
	 * @return array<string, string>
	 */
	public static function headers(): array {
		return array(
			// Stops a browser second-guessing a declared content type, which is
			// how an uploaded file gets executed as script.
			'X-Content-Type-Options'  => 'nosniff',
			// Framing by another origin is how clickjacking is staged.
			'X-Frame-Options'         => 'SAMEORIGIN',
			// Full URLs stop leaking to third parties, including any token that
			// happens to be in a path.
			'Referrer-Policy'         => 'strict-origin-when-cross-origin',
			// Opts the site out of the Topics API. Named explicitly because the
			// default is to participate.
			'Permissions-Policy'      => 'browsing-topics=()',
		);
	}

	/**
	 * Whether something other than this plugin's version item filters the
	 * generator tag.
	 */
	private static function generator_filtered_elsewhere(): bool {
		global $wp_filter;

		if ( empty( $wp_filter['the_generator'] ) || ! $wp_filter['the_generator'] instanceof \WP_Hook ) {
			return false;
		}

		foreach ( $wp_filter['the_generator']->callbacks as $callbacks ) {
			foreach ( $callbacks as $callback ) {
				$function = $callback['function'] ?? null;

				if ( ! ( is_array( $function ) && Item\VersionDisclosure::class === ( is_object( $function[0] ) ? get_class( $function[0] ) : $function[0] ) && 'blank_generator' === ( $function[1] ?? '' ) ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * The groups the items are read in, and which screen shows each one.
	 *
	 * A flat list of eleven switches asked the reader to work out what each one
	 * protected. Grouping states it, and the group is also where the item is
	 * shown: everything about the sign-in door belongs on Login & Access beside
	 * the lockouts and the sessions, not in a list the reader has to know to
	 * look in.
	 *
	 * `screen` names a tab in the admin app. An item's mechanism does not
	 * change with its group — the same apply, the same undo through the ledger,
	 * the same preview and conflict probe wherever it is drawn.
	 *
	 * @return array<string, array{title: string, screen: string}>
	 */
	public static function groups(): array {
		return array(
			'sign_in'   => array(
				'title'  => __( 'Signing in', 'bettershield' ),
				'screen' => 'login',
			),
			// What an account below administrator is given, which is not how
			// anybody signs in: drawn on Hardening, with no recovery pre-flight.
			'accounts'  => array(
				'title'  => __( 'User roles and uploads', 'bettershield' ),
				'screen' => 'hardening',
			),
			'exposure'  => array(
				'title'  => __( 'Hide site details', 'bettershield' ),
				'screen' => 'hardening',
			),
			'execution' => array(
				'title'  => __( 'Code and settings changes', 'bettershield' ),
				'screen' => 'hardening',
			),
			'browser'   => array(
				'title'  => __( 'HTTPS and browser security', 'bettershield' ),
				'screen' => 'hardening',
			),
		);
	}

	/**
	 * Each item declares `effect`: the exact runtime changes applying it would
	 * make, in the order they happen. This is what the dry run shows, so it
	 * must describe what the code actually does rather than what it is for.
	 * Items may also declare `fields` (owner input taken before applying) and
	 * `actions` (extra operations on an applied item); both are callables so
	 * their strings translate lazily like everything else here.
	 *
	 * An item may declare `detail`: the why behind its one-line description,
	 * forty words at most, shown behind an ⓘ beside its title. What a person
	 * must see to stay safe stays in the description.
	 *
	 * Each item declares `reverts` as well: what taking it off does, in the
	 * direction that runs — what stops and what comes back. A plan to take a
	 * protection off read its `effect` instead, and promised to add the very
	 * headers it was about to stop sending.
	 *
	 * Each item also declares `reversible`: whether undoing it puts the site
	 * back where it was, entirely, by construction. True for everything whose
	 * effect lives in this plugin's own runtime, and false where the change
	 * escapes into something this site does not control afterwards. It is a
	 * per-item answer rather than a list kept somewhere else, so an item added
	 * later has to state it rather than inherit somebody's assumption.
	 *
	 * @return array<string, array<string, callable|string|bool>>
	 */
	public static function all(): array {
		return array(

			'xmlrpc'           => array(
				'group'       => 'execution',
				'reversible'  => true,
				'title'       => __( 'Remote publishing block (XML-RPC)', 'bettershield' ),
				'description' => __( 'Turns off XML-RPC, or only its pingbacks. No files change.', 'bettershield' ),
				'detail'      => __( 'An old remote-publishing interface that attackers use to try many passwords in one request. Most sites no longer need it.', 'bettershield' ),
				'fields'      => static function (): array {
					return Item\XmlRpc::fields();
				},
				'reverts'     => static function ( array $options = array() ): array {
					if ( Item\XmlRpc::jetpack_only( $options ) ) {
						return array(
							__( 'xmlrpc.php answers everyone again, pingbacks included.', 'bettershield' ),
							__( 'The pingback header, RSD link and pingback address come back.', 'bettershield' ),
						);
					}

					if ( Item\XmlRpc::pingbacks_only( $options ) ) {
						return array(
							__( 'Other sites can ping this one again.', 'bettershield' ),
							__( 'The pingback header and pingback address come back.', 'bettershield' ),
						);
					}

					return array(
						__( 'xmlrpc.php works again, pingbacks included.', 'bettershield' ),
						__( 'The pingback header, RSD link and pingback address come back.', 'bettershield' ),
					);
				},
				'effect'      => static function ( array $options = array() ): array {
					if ( Item\XmlRpc::jetpack_only( $options ) ) {
						return array(
							__( 'Blocks all access to xmlrpc.php, except from Jetpack’s published server addresses.', 'bettershield' ),
							__( 'Jetpack is recognized by its published server addresses.', 'bettershield' ),
							__( 'Removes the pingback methods for Jetpack too, and the X-Pingback header and RSD link for everyone.', 'bettershield' ),
							__( 'The WordPress mobile apps can no longer sign in through XML-RPC.', 'bettershield' ),
							__( 'If Jetpack adds a server before BetterShield’s next update, its requests are refused until then. Pingbacks only is the way out.', 'bettershield' ),
						);
					}

					if ( Item\XmlRpc::pingbacks_only( $options ) ) {
						return array(
							__( 'Removes the pingback methods from XML-RPC, so other sites can no longer ping this one.', 'bettershield' ),
							__( 'Removes the X-Pingback header and blanks the pingback address. Themes that print it themselves still show it.', 'bettershield' ),
							__( 'Leaves the rest of XML-RPC alone, so Jetpack and the mobile apps keep working.', 'bettershield' ),
							__( 'Leaves trackbacks and the REST API untouched.', 'bettershield' ),
						);
					}

					return array(
						__( 'Blocks all access to xmlrpc.php.', 'bettershield' ),
						__( 'Removes every XML-RPC method too, so nothing works even if the endpoint is reached another way.', 'bettershield' ),
						__( 'Tells WordPress XML-RPC is off, so sign-in methods are refused too.', 'bettershield' ),
						__( 'Removes the hidden links that advertise XML-RPC to other sites, and blanks the pingback address. Themes that print it themselves still show it.', 'bettershield' ),
						__( 'Leaves trackbacks and the REST API untouched.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					if ( class_exists( 'Jetpack' ) || defined( 'JETPACK__VERSION' ) ) {
						return __( 'Jetpack uses XML-RPC. Choose all except Jetpack, or Jetpack stops connecting.', 'bettershield' );
					}

					return null;
				},
			),

			'file_editor'      => array(
				'group'       => 'execution',
				'reversible'  => true,
				'title'       => __( 'File editor lock', 'bettershield' ),
				'description' => __( 'Removes the plugin and theme code editors.', 'bettershield' ),
				'detail'      => __( 'Someone who gets into an administrator account could use the editors to put code on your site. Without them, changing code needs access to the files.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'The file editors come back for accounts allowed to use them, unless wp-config.php turns them off.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					return array(
						__( 'Removes the plugin and theme file editors for everyone, administrators included.', 'bettershield' ),
						__( 'Still lets you install and update plugins and themes.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					if ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) {
						return __( 'wp-config.php already disables the file editor, so this changes nothing unless that line is removed.', 'bettershield' );
					}

					/*
					 * The three capabilities this item denies belong to a
					 * network's own administrators, and a site administrator
					 * on a network never holds them — so applying it here is
					 * true and changes nothing anybody can see. Said plainly,
					 * because a switch that reports success and alters nothing
					 * is how somebody comes to believe a site is protected by
					 * a control that was never doing anything for it.
					 *
					 * The main site is the exception: Network Admin runs as
					 * the main site and reads its state, so applied there it
					 * takes the editors away from every network administrator.
					 */
					if ( is_multisite() && is_main_site() ) {
						return __( 'This also removes the file editors from Network Admin for every network administrator.', 'bettershield' );
					}

					if ( is_multisite() ) {
						return __( 'Only network administrators have the file editors, so this changes nothing here unless site administrators get them.', 'bettershield' );
					}

					return null;
				},
			),

			'user_enumeration' => array(
				'group'       => 'exposure',
				'reversible'  => true,
				'title'       => __( 'Username privacy', 'bettershield' ),
				'description' => __( 'Closes the ways visitors can find your usernames, including the sign-in form.', 'bettershield' ),
				'detail'      => __( 'Someone who knows a username only has to guess the password. Hiding usernames takes away half of what they need.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'Signed-out visitors can list users through the REST API again, and ?author= works as usual.', 'bettershield' ),
						__( 'Author sitemaps and author names in embeds come back.', 'bettershield' ),
						__( 'The sign-in and lost-password forms again reveal whether a username exists.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					$lines = array(
						__( 'Hides the list of usernames from visitors who aren’t signed in, including in author links and sitemaps. Author pages stay public.', 'bettershield' ),
						__( 'Removes the author name and link from embeds of your posts.', 'bettershield' ),
						__( 'Shows one message on the sign-in form for a wrong password or unknown username, so guessed names cannot be confirmed.', 'bettershield' ),
						__( 'Answers lost-password requests the same way whether or not the account exists. Someone who mistypes is still told a link is coming, but none arrives.', 'bettershield' ),
					);

					/*
					 * An SEO plugin serving its own sitemaps: what this does
					 * to them, and what it leaves. Said here, as what the
					 * item does, and not as a conflict: a conflict holds the
					 * fix back in Quick Setup, and this was the one fix that
					 * closes username discovery.
					 */
					if ( defined( 'WPSEO_VERSION' ) || defined( 'RANK_MATH_VERSION' ) || defined( 'AIOSEO_VERSION' ) || defined( 'SEOPRESS_VERSION' ) ) {
						array_splice( $lines, -1, 0, array( __( 'Your SEO plugin’s sitemap index may still list its author sitemap until you turn that off in the plugin.', 'bettershield' ) ) );
					}

					return $lines;
				},
				'conflict'    => static function (): ?string {
					/*
					 * On plain permalinks WordPress links every author archive
					 * as ?author=<id>, which is exactly what this sends home:
					 * no author archive opens for a signed-out visitor. Said
					 * first, because it is the one thing here a visitor sees,
					 * and as a conflict, so the setup asks before applying it.
					 */
					if ( '' === (string) get_option( 'permalink_structure' ) ) {
						return __( 'With plain permalinks, signed-out visitors who follow an author link are sent to the home page.', 'bettershield' );
					}

					// Anything already filtering the REST user route is doing
					// part of this item's job, and doing it first.
					if ( has_filter( 'rest_endpoints' ) && class_exists( 'WP_Rest_Api_Log' ) ) {
						return __( 'Another plugin already filters the REST API routes. Using both is safe; removing either keeps the other.', 'bettershield' );
					}

					return null;
				},
			),

			'own_auto_updates' => array(
				'group'       => 'execution',
				'reversible'  => true,
				'title'       => __( 'BetterShield auto-updates', 'bettershield' ),
				'description' => sprintf(
					/* translators: %s: the plugin's name. */
					__( 'Turns on auto-updates for %s only.', 'bettershield' ),
					\BetterShield\Support\Branding::name()
				),
				'detail'      => __( 'Each release, and the fixes in it, then arrives without waiting for someone to press Update.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'BetterShield waits for someone to press Update again, unless its auto-updates were switched off since.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					return array(
						__( 'Uses the same switch as “Enable auto-updates” on its row under Plugins.', 'bettershield' ),
						__( 'Leaves every other plugin’s auto-updates as they are.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					return null;
				},
			),

			'takeover_settings' => array(
				'group'       => 'execution',
				'reversible'  => true,
				'title'       => __( 'Admin-only key settings', 'bettershield' ),
				'description' => __( 'Stops plugins and themes changing the site address, admin email or sign-up settings.', 'bettershield' ),
				'detail'      => __( 'A faulty plugin can let strangers change these settings and make themselves an admin. This blocks that.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'Any code can change the site address, administrator email and registration settings again.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					$lines = array(
						__( 'Keeps the site and home address, administrator email, open registration and the role new accounts get as they are, unless an administrator is changing them.', 'bettershield' ),
						__( 'Still lets WP-CLI, installs and site moves change them.', 'bettershield' ),
						__( 'Logs each blocked change as critical, with the plugin or theme that tried it.', 'bettershield' ),
					);

					if ( is_multisite() ) {
						array_splice( $lines, 1, 0, array( __( 'On this network, the network’s registration, email and super administrator list change only for a network administrator.', 'bettershield' ) ) );
					}

					return $lines;
				},
				'conflict'    => static function (): ?string {
					return null;
				},
			),

			'uploads_php'      => array(
				'group'       => 'execution',
				'reversible'  => true,
				// Writes a file through Files\Guarded, which keeps the old copy for undo.
				'writes_files' => true,
				'title'       => __( 'Uploads code block', 'bettershield' ),
				'description' => __( 'Stops uploaded files from running as code.', 'bettershield' ),
				'detail'      => __( 'If a code file ever gets into your uploads, this stops it from running, so it stays a harmless file.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'Removes only its own block from the uploads .htaccess file.', 'bettershield' ),
						__( 'PHP-like files under uploads are no longer refused by that rule.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					$lines = array(
						__( 'Adds its own block to the uploads .htaccess file (created if missing). Undo removes only that block.', 'bettershield' ),
						__( 'Stops code files in your uploads folder from running. Images and documents work as before.', 'bettershield' ),
						// Permalinks prove the rewrite module, not the alias
						// module these rules need.
						__( 'Works on Apache and LiteSpeed Enterprise servers. BetterShield checks from outside that it works.', 'bettershield' ),
					);

					// An .htaccess rule reaches every directory below it, and
					// every site's uploads directory sits inside the main
					// site's — so the main site's block covers the network and
					// a subsite's covers itself. Except on a network still on
					// the old layout (`ms_files_rewriting`, set up before
					// WordPress 3.5 and never moved), where each site's uploads
					// are under blogs.dir, outside the main site's.
					if ( is_multisite() && get_site_option( 'ms_files_rewriting' ) ) {
						$lines[] = __( 'On this network, each site’s uploads are separate, so apply it on each site.', 'bettershield' );
					} elseif ( is_multisite() ) {
						$lines[] = is_main_site()
							? __( 'On this network, applying it here covers every site, because their uploads sit inside this site’s.', 'bettershield' )
							: __( 'On this network, this covers only this site’s uploads. Applied from the main site, it covers every site.', 'bettershield' );
					}

					return $lines;
				},
				'conflict'    => static function (): ?string {
					return Item\UploadsPhp::conflict();
				},
			),

			'directory_browsing' => array(
				'group'       => 'exposure',
				'reversible'  => true,
				// Writes a file through Files\Guarded, which keeps the old copy for undo.
				'writes_files' => true,
				'title'       => __( 'Folder listing protection', 'bettershield' ),
				'description' => __( 'Stops visitors browsing a list of every file in your uploads folder.', 'bettershield' ),
				'detail'      => __( 'Some servers list every file in a folder that has no index page, which shows visitors everything you have uploaded.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'Removes the blank index.php files it placed, if still unchanged.', 'bettershield' ),
						__( 'Uploads directories without their own index file can be listed again, where the server allows.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					$lines = array(
						__( 'Adds an empty page to your uploads folders so their file lists can’t be seen. Nothing is overwritten, and undo removes them.', 'bettershield' ),
						__( 'Works on every web server; no server configuration needed.', 'bettershield' ),
					);

					// Unlike an .htaccess rule, a guard file protects one
					// directory; the walk stops at its depth, and the other
					// sites' directories sit below it — so each site places
					// its own.
					if ( is_multisite() ) {
						$lines[] = __( 'On this network, it covers only this site’s uploads, so apply it on each site.', 'bettershield' );
					}

					return $lines;
				},
				/*
				 * Nothing to warn about, on any server.
				 *
				 * This carried the .htaccess-compatibility check the two items
				 * that genuinely write .htaccess rules carry, and it does not
				 * write one — it places blank index.php guard files, which was
				 * chosen precisely so it would not depend on server
				 * configuration. So on nginx it told the owner the rule "would
				 * be written and ignored" directly beside its own effect line
				 * saying it works on every web server, and talked them out of a
				 * fix that works there perfectly.
				 */
				'conflict'    => static function (): ?string {
					return null;
				},
			),

			'sensitive_files'  => array(
				'group'       => 'exposure',
				'reversible'  => true,
				// Writes a file through Files\Guarded, which keeps the old copy for undo.
				'writes_files' => true,
				'title'       => __( 'Private file protection', 'bettershield' ),
				'description' => __( 'Shows “not found” for log files, settings backups and other files that shouldn’t be public.', 'bettershield' ),
				'detail'      => __( 'Backups and logs left in public folders can hold passwords and private details that anyone could download.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'Removes only its own block from the site’s .htaccess file.', 'bettershield' ),
						__( 'Log files, wp-config backups, readme.html, license.txt and paths like .git and .env are no longer refused by that rule.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					return array(
						__( 'Adds its own block to the site’s .htaccess file. Undo removes only that block.', 'bettershield' ),
						__( 'Shows “not found” for log files, settings backups and other private files.', 'bettershield' ),
						__( 'Shows “not found”, so nobody can tell the file exists.', 'bettershield' ),
						// Permalinks prove the rewrite module, not the alias
						// module these rules need.
						__( 'Works on Apache and LiteSpeed Enterprise servers. BetterShield checks from outside that it works.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					return Item\SensitiveFiles::conflict();
				},
			),

			'login_url'        => array(
				'group'       => 'sign_in',
				'reversible'  => true,
				'title'       => __( 'Custom sign-in address', 'bettershield' ),
				'description' => __( 'Reduces automated sign-in attempts, but does not stop a targeted attacker.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'The sign-in page and all sign-in links go back to wp-login.php.', 'bettershield' ),
						__( 'The address this put in place stops answering.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					return array(
						__( 'Serves sign-in, sign-out and password resets at your chosen address.', 'bettershield' ),
						__( 'The usual sign-in page (wp-login.php) shows “page not found”, except for signing out.', 'bettershield' ),
						__( 'Updates every sign-in link WordPress builds, including in emails.', 'bettershield' ),
						__( 'Writes no files or rewrite rules, so undo is instant.', 'bettershield' ),
						__( 'If the address is lost, the recovery link restores the standard sign-in page.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					return Item\LoginUrl::conflict();
				},
				'fields'      => static function (): array {
					return Item\LoginUrl::fields();
				},
			),

			'application_passwords' => array(
				'group'       => 'sign_in',
				'reversible'  => true,
				'title'       => __( 'App password block', 'bettershield' ),
				'description' => __( 'Turns off the passwords that apps and tools use to reach your site. They don’t ask for a two-factor code. Nothing is deleted.', 'bettershield' ),
				'detail'      => __( 'Application passwords skip the second factor by design. Undo makes them work again.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'Application passwords work again, and the profile section that issues them comes back.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					return array(
						__( 'A request using an application password is treated as signed out.', 'bettershield' ),
						__( 'Hides the profile section that issues them, for the accounts this covers.', 'bettershield' ),
						__( 'Deletes nothing: existing passwords are refused, not removed.', 'bettershield' ),
						__( 'Leaves the REST API, WP-CLI and normal sign-in unchanged.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					return Item\ApplicationPasswords::conflict();
				},
				'fields'      => static function (): array {
					return Item\ApplicationPasswords::fields();
				},
			),

			'breached_passwords' => array(
				'group'       => 'sign_in',
				// Only adds a check and never stands between anyone and
				// signing in, so it doesn't wait for a way back in.
				'way_back'    => false,
				'reversible'  => true,
				'title'       => __( 'Leaked password check', 'bettershield' ),
				'description' => __( 'When someone sets a new password, checks it against known leaks. The password itself is never sent.', 'bettershield' ),
				'detail'      => __( 'A strong-looking password can still be on a published list. Existing passwords keep working.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'New passwords are no longer checked against breach lists.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					return array(
						__( 'Checks new passwords set while signed in (profile, store account page, REST API). Signed-out forms are never checked.', 'bettershield' ),
						__( 'Sends only the first five characters of a scrambled copy of the password, which can’t be turned back into it. Nothing else is sent.', 'bettershield' ),
						__( 'Refuses a listed password with a short message, and says nothing otherwise.', 'bettershield' ),
						__( 'Never affects signing in or any password an account already has.', 'bettershield' ),
						__( 'If the service cannot be reached, allows the password and records that the check did not run.', 'bettershield' ),
						__( 'Leaves WP-CLI and importers alone, so scripts never wait on an outside service.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					return Item\BreachedPasswords::conflict();
				},
			),

			'reset_link_lifetime' => array(
				'group'       => 'sign_in',
				// Only adds a check and never stands between anyone and
				// signing in, so it doesn't wait for a way back in.
				'way_back'    => false,
				'reversible'  => true,
				'title'       => __( 'Short reset links for admins and editors', 'bettershield' ),
				'description' => __( 'Password-reset links for administrators and editors expire sooner than the usual 24 hours.', 'bettershield' ),
				'detail'      => __( 'A reset link left in a mailbox is a way into the account for anyone who reads it.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'Reset links for privileged accounts work for 24 hours again.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					return array(
						__( 'Privileged accounts’ reset links stop working after the time you choose: 15 minutes, 1 hour or 4 hours.', 'bettershield' ),
						__( 'Everyone else keeps the usual 24 hours.', 'bettershield' ),
						__( 'An expired link gets the usual expired message and a form to request a new one.', 'bettershield' ),
						__( 'Never affects the recovery link, safe mode or signing in.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					return null;
				},
				'fields'      => static function (): array {
					return Item\ResetLinks::fields();
				},
			),

			'email_change_confirm' => array(
				'group'       => 'sign_in',
				'reversible'  => true,
				'title'       => __( 'Email change confirmation for admins and editors', 'bettershield' ),
				'description' => __( 'A new email address on these accounts only takes effect once it is confirmed from that inbox.', 'bettershield' ),
				'detail'      => __( 'Password resets go to this address, so one request from a stolen session could redirect them.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'Privileged accounts’ addresses change at once again, except on the profile screen.', 'bettershield' ),
						__( 'Changes already waiting stay waiting until confirmed or canceled.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					return array(
						__( 'Holds a change to a privileged account’s address made from the REST API, another account or a front-end form.', 'bettershield' ),
						__( 'Mails a confirmation link to the new address and a notice to the old one, and shows the pending change on the profile.', 'bettershield' ),
						__( 'Changes the address once the account holder, signed in, opens the link.', 'bettershield' ),
						__( 'Leaves WP-CLI, store checkout and other accounts alone.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					return null;
				},
			),

			'admin_area_access' => array(
				'group'       => 'sign_in',
				'reversible'  => true,
				'title'       => __( 'Dashboard lock for customers and subscribers', 'bettershield' ),
				'description' => __( 'Sends chosen roles to the front page instead of the dashboard.', 'bettershield' ),
				'detail'      => __( 'These accounts can still sign in, use the site, and manage their password, two-factor and signed-in devices from their profile.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'The roles it kept out can reach the dashboard and see the admin bar again.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					return array(
						__( 'Sends the roles you choose to the front page when they open a dashboard screen.', 'bettershield' ),
						__( 'Leaves their profile reachable, so they can still manage their password, two-factor and sign-ins.', 'bettershield' ),
						__( 'Keeps admin-ajax.php and admin-post.php working for front-end features while signed in.', 'bettershield' ),
						__( 'Hides the front-end admin bar for those accounts.', 'bettershield' ),
						__( 'Never applies to accounts that can manage this site or plugin, checked on every request.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					return Item\AdminAreaAccess::conflict();
				},
				'fields'      => static function (): array {
					return Item\AdminAreaAccess::fields();
				},
			),

			'registration_role' => array(
				'group'       => 'accounts',
				'reversible'  => true,
				'title'       => __( 'Subscriber role for new sign-ups', 'bettershield' ),
				'description' => __( 'New accounts start as Subscriber. Existing accounts keep their roles.', 'bettershield' ),
				'detail'      => __( 'If anyone can register, a higher default role lets strangers post on your site.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'New accounts get the role they got before, unless someone changed it since.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					return array(
						__( 'Sets the role new accounts get to Subscriber, the setting under Settings › General.', 'bettershield' ),
						__( 'Keeps the role it replaced, so undo can put it back. A role someone chooses in the meantime is left alone.', 'bettershield' ),
						__( 'Leaves existing accounts and whether anyone can register as they are. Store customers get the store’s own role.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					return Item\RegistrationRole::conflict();
				},
			),

			'unfiltered_code'  => array(
				'group'       => 'accounts',
				'reversible'  => true,
				'title'       => __( 'Admin-only script and file uploads', 'bettershield' ),
				'description' => __( 'Non-admins can no longer add scripts to posts or upload any file type. No role is changed.', 'bettershield' ),
				'detail'      => __( 'Script in a post runs in the browser of whoever views it, administrators included.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'Roles given unfiltered HTML or unfiltered uploads have them again.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					return array(
						__( 'Treats everyone below administrator as not allowed to add raw HTML or upload any file type.', 'bettershield' ),
						__( 'Lets Editors keep adding HTML, as WordPress allows, but no longer upload any file type.', 'bettershield' ),
						__( 'Changes no role in the database, so undo is instant.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					return Item\UnfilteredCode::conflict();
				},
			),

			'script_uploads'   => array(
				'group'       => 'accounts',
				'reversible'  => true,
				'title'       => __( 'Admin-only SVG and code uploads', 'bettershield' ),
				'description' => __( 'Accounts below administrator can no longer upload SVG, HTML, JavaScript or PHP-type files.', 'bettershield' ),
				'detail'      => __( 'An uploaded SVG or HTML file is served from your own address, so script in it runs as part of your site.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'Accounts below administrator can upload every type the site allows again.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					return array(
						__( 'Removes SVG, HTML, JavaScript and PHP-type files from the upload list for accounts below administrator.', 'bettershield' ),
						__( 'Leaves HTML and JavaScript to accounts that may publish unfiltered HTML, as WordPress does. Their SVG and PHP-type uploads go.', 'bettershield' ),
						__( 'Administrators keep every type. Files already uploaded stay where they are.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					return Item\ScriptUploads::conflict();
				},
			),

			'ability_access'   => array(
				'group'       => 'accounts',
				'reversible'  => true,
				'title'       => __( 'Admin-only plugin actions', 'bettershield' ),
				'description' => __( 'Some plugins let any signed-in user run actions that change the site, for example through an AI assistant. This limits them to administrators.', 'bettershield' ),
				'detail'      => __( 'If a plugin lets non-admins change the site, this keeps those actions to admins.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'The abilities it covered answer to their own plugin’s check again.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					return array(
						__( 'Limits these actions to administrators, including when an AI assistant asks.', 'bettershield' ),
						__( 'Administrators keep them. Every other ability is left alone.', 'bettershield' ),
						__( 'An ability a plugin adds later is not covered until you apply this again.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					return Item\AbilityAccess::conflict();
				},
			),

			'admin_gate'       => array(
				'group'       => 'sign_in',
				'reversible'  => true,
				'title'       => __( 'Dashboard privacy for visitors', 'bettershield' ),
				'description' => __( 'Visitors who aren’t signed in see a “page not found” instead of the sign-in page. Signed-in people notice nothing.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'Signed-out visitors who open the dashboard are sent to the sign-in page again.', 'bettershield' ),
					);
				},
				'effect'      => static function ( array $options = array() ): array {
					return array(
						empty( $options['destination'] )
							? __( 'Answers 404 when a signed-out visitor requests a dashboard page.', 'bettershield' )
							/* translators: %s: the address on this site that visitors are sent to. */
							: sprintf( __( 'Sends a signed-out visitor who requests a dashboard page to %s.', 'bettershield' ), home_url( '/' . (string) $options['destination'] . '/' ) ),
						__( 'Keeps admin-ajax.php and admin-post.php working for front-end features while signed out.', 'bettershield' ),
						__( 'Keeps the dashboard address, which plugins rely on. Signed-in users reach it as before.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					return Item\AdminGate::conflict();
				},
				'fields'      => static function (): array {
					return Item\AdminGate::fields();
				},
			),

			'php_error_display' => array(
				'group'       => 'exposure',
				'reversible'  => true,
				'title'       => __( 'Error message privacy', 'bettershield' ),
				'description' => __( 'Hides error details from pages; your error log still records them.', 'bettershield' ),
				'detail'      => __( 'A PHP error printed into a page shows file paths, and sometimes queries or credentials, to whoever loaded it.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'PHP errors show in pages again wherever the server or wp-config.php has them on.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					return array(
						sprintf(
							/* translators: %s: the plugin's name. */
							__( 'Hides error messages from pages as soon as %s loads.', 'bettershield' ),
							\BetterShield\Support\Branding::name()
						),
						__( 'Leaves wp-config.php untouched. Errors are still written to the log where logging is on.', 'bettershield' ),
						__( 'Errors raised before this plugin loads, by wp-config.php, must-use plugins or plugins loaded earlier, can still print.', 'bettershield' ),
						__( 'Checks first that the server lets it change the setting, and changes nothing if not.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					return null;
				},
			),

			'version_disclosure' => array(
				'group'       => 'exposure',
				'reversible'  => true,
				'title'       => __( 'WordPress version privacy', 'bettershield' ),
				'description' => __( 'Hides the WordPress version from pages, feeds and asset addresses.', 'bettershield' ),
				'detail'      => __( 'Automated scanners read the version to pick attacks that work on it. Updating matters more, but this gives them less to go on.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'The WordPress version shows again in pages, feeds and asset addresses.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					return array(
						__( 'Removes the WordPress version from your pages, feeds and file links.', 'bettershield' ),
						__( 'Leaves plugin and theme versions alone.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					// A theme that prints its own generator tag will keep doing
					// so: this removes WordPress's, not the theme's. Only another
					// filter counts: once applied, this item's own is on the hook.
					if ( has_action( 'wp_head', 'wp_generator' ) && self::generator_filtered_elsewhere() ) {
						return __( 'Something else already filters the version tag, so it may already be hidden. Applying this is still safe.', 'bettershield' );
					}

					return null;
				},
			),

			'cloud_metadata'   => array(
				'group'       => 'exposure',
				'reversible'  => true,
				'title'       => __( 'Server detail protection', 'bettershield' ),
				'description' => __( 'Stops plugins reading your cloud server’s private details, like access keys.', 'bettershield' ),
				'detail'      => __( 'If a plugin needs one of these addresses, switch this off, add it under “Addresses to allow”, then switch it back on.', 'bettershield' ),
				'fields'      => static function (): array {
					return Item\CloudMetadata::fields();
				},
				'reverts'     => static function (): array {
					return array(
						__( 'Requests to cloud-metadata addresses go out again, and internal-network requests are no longer logged.', 'bettershield' ),
					);
				},
				'effect'      => static function ( array $options = array() ): array {
					$lines = array(
						__( 'Stops any plugin reaching your cloud server’s private address, however the address is written.', 'bettershield' ),
						__( 'Covers the private addresses used by Amazon, Google, Azure and Alibaba Cloud.', 'bettershield' ),
						__( 'Refuses a redirect that leads to one of them.', 'bettershield' ),
						__( 'Other private-network requests still work and are logged once a day.', 'bettershield' ),
						__( 'Tells the refused plugin why, and names it in the activity log.', 'bettershield' ),
						__( 'Skips the store’s cart and checkout, and safe mode.', 'bettershield' ),
						__( 'Only covers requests made the standard WordPress way.', 'bettershield' ),
					);

					$allow = isset( $options['allow'] ) && is_array( $options['allow'] ) ? $options['allow'] : array();

					if ( array() !== $allow ) {
						$lines[] = sprintf(
							/* translators: %s: comma-separated host names, addresses and ranges. */
							__( 'Lets these through, neither refused nor noted: %s.', 'bettershield' ),
							implode( ', ', array_map( 'strval', $allow ) )
						);
					}

					return $lines;
				},
				'conflict'    => static function (): ?string {
					return null;
				},
			),

			'auth_keys'        => array(
				'group'       => 'sign_in',
				'reversible'  => true,
				'title'       => __( 'Sign everyone out on demand', 'bettershield' ),
				'description' => __( 'Adds a button that ends every sign-in at once.', 'bettershield' ),
				'detail'      => __( 'From the dashboard, your current session is kept. From an assistant or the command line, it ends too.', 'bettershield' ),
				/*
				 * The effect and the conflict are read for the request that
				 * asks — the screen, an assistant's plan, the command line —
				 * and say what happens to that caller's own session. Only a
				 * change made from a signed-in browser has one to carry over.
				 */
				'reverts'     => static function (): array {
					return array(
						__( 'WordPress goes back to using only the keys in wp-config.php.', 'bettershield' ),
						__( 'That signs every other session out; from the dashboard, yours is kept. Passwords don’t change.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					return array(
						__( 'Adds a second secret to how WordPress keeps people signed in. Your wp-config.php file isn’t changed.', 'bettershield' ),
						Item\AuthKeys::carries_session()
							? __( 'Signs every other session out the moment it is applied, and keeps yours. Passwords don’t change.', 'bettershield' )
							: __( 'Signs every session out the moment it is applied, yours included. Passwords don’t change.', 'bettershield' ),
						__( 'Adds a “Sign Out All Devices” button for when you think an account was misused.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					$kept = Item\AuthKeys::carries_session();

					// Rotating keys ends everybody else's session, which is
					// worth saying plainly on a site where that costs more
					// than usual.
					if ( defined( 'WP_CACHE' ) && WP_CACHE ) {
						return $kept
							? __( 'Applying, rotating or undoing signs out everyone else, including your other devices. A page cache may serve signed-out pages until it clears. Passwords don’t change.', 'bettershield' )
							: __( 'Applying, rotating or undoing signs out every account, yours included. A page cache may serve signed-out pages until it clears. Passwords don’t change.', 'bettershield' );
					}

					return $kept
						? __( 'Applying, rotating or undoing signs out everyone else, including your other devices. Passwords don’t change.', 'bettershield' )
						: __( 'Applying, rotating or undoing signs out every account, yours included. Passwords don’t change.', 'bettershield' );
				},
				'actions'     => static function (): array {
					return Item\AuthKeys::actions();
				},
			),

			'sign_in_no_cache' => array(
				'group'       => 'browser',
				'reversible'  => true,
				'title'       => __( 'Sign-in page cache protection', 'bettershield' ),
				'description' => __( 'Tells caching plugins, server caches and CDNs not to keep a copy of the sign-in page. No files change.', 'bettershield' ),
				'detail'      => __( 'A cached sign-in page can reject a correct password or show one visitor’s lockout to another.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'The sign-in page is sent with WordPress’s own caching headers only, as before.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					return array(
						__( 'Tells caching plugins, server caches and CDNs to skip the sign-in page, wherever it has moved.', 'bettershield' ),
						__( 'A copy a cache already holds stays until that cache is cleared.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					return null;
				},
			),

			'https_address'    => array(
				'group'       => 'browser',
				'title'       => __( 'HTTPS site address', 'bettershield' ),
				'description' => __( 'Checks the certificate first. Goes back to http on its own unless you press Keep HTTPS within 5 minutes.', 'bettershield' ),
				'detail'      => __( 'Uses WordPress’s own HTTPS switch. If HTTPS fails, the site switches back on its own, so you can’t be locked out.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'Both addresses go back to what they were, and so does WordPress’s note to rewrite old http links.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					return array(
						__( 'Asks this site for its front page over HTTPS, checking the certificate, and stops if that fails.', 'bettershield' ),
						__( 'Switches the site and WordPress addresses to https with WordPress’s own function.', 'bettershield' ),
						__( 'Puts both back on the next request after 5 minutes, unless Keep HTTPS is pressed on a dashboard opened over HTTPS.', 'bettershield' ),
						__( 'Single site only. Not offered when wp-config.php sets WP_HOME or WP_SITEURL.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					return null;
				},
				'actions'     => static function (): array {
					return Item\HttpsAddress::actions();
				},
			),

			'https_redirect'   => array(
				'group'       => 'browser',
				'title'       => __( 'HTTPS redirect', 'bettershield' ),
				'description' => __( 'Visitors who open an http:// link are sent to your https:// address.', 'bettershield' ),
				'detail'      => __( 'WordPress itself never moves http:// visitors to the HTTPS address. This does, for pages, sign-in, the dashboard and the REST API.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'Plain HTTP is answered again instead of redirected.', 'bettershield' ),
						__( 'Browsers that saw the permanent redirect keep going to HTTPS until they forget it.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					return array(
						__( 'Sends visitors who open an http:// address to the https:// one. Forms sent over http:// are left alone.', 'bettershield' ),
						__( 'Uses a temporary redirect for the first day, then a permanent one.', 'bettershield' ),
						__( 'Checks right away that http:// leads once to an HTTPS page that loads, and undoes itself if not.', 'bettershield' ),
						__( 'Never redirects the recovery link. Only offered once the site address is HTTPS.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					return Item\HttpsRedirect::conflict();
				},
			),

			'ajax_origins'     => array(
				'group'       => 'browser',
				'reversible'  => true,
				'title'       => __( 'Cross-site data protection', 'bettershield' ),
				'description' => __( 'Stops other websites reading data meant for your signed-in visitors.', 'bettershield' ),
				'detail'      => __( 'Only needed if a plugin lets other websites read your site’s data.', 'bettershield' ),
				'fields'      => static function (): array {
					return Item\AjaxOrigins::fields();
				},
				'reverts'     => static function (): array {
					return array(
						__( 'admin-ajax answers every address other code allows again.', 'bettershield' ),
					);
				},
				'effect'      => static function ( array $options = array() ): array {
					$lines = array(
						__( 'Lets only your own site’s addresses read signed-in data.', 'bettershield' ),
						__( 'Leaves the REST API’s own policy and every other request alone.', 'bettershield' ),
						__( 'Checks again in the background, and the finding updates.', 'bettershield' ),
					);

					if ( array() !== (array) ( $options['origins'] ?? array() ) ) {
						array_splice(
							$lines,
							1,
							0,
							array(
								sprintf(
									/* translators: %s: a list of web addresses. */
									__( 'Also answers: %s.', 'bettershield' ),
									implode( ', ', array_map( 'strval', (array) $options['origins'] ) )
								),
							)
						);
					}

					return $lines;
				},
				'conflict'    => static function (): ?string {
					return Item\AjaxOrigins::conflict();
				},
			),

			'hsts'             => array(
				'group'       => 'browser',
				/*
				 * Reversible by the clock, and only at five minutes without
				 * subdomains: a browser forgets the short header as fast as it
				 * learned it, so the ledger's way back is real. Six months
				 * outlives any undo made here, and widening the header to every
				 * subdomain rests on a precondition nothing in code can check —
				 * both wait for a person. Declared as a callable because the
				 * answer depends on how the item is applied.
				 */
				'reversible'  => static function ( array $options ): bool {
					return Item\Hsts::is_short( $options );
				},
				'title'       => __( 'Strict HTTPS (HSTS)', 'bettershield' ),
				'description' => __( 'Browsers remember to use your secure address. Try 5 minutes first: Undo can’t reach browsers that already saw it.', 'bettershield' ),
				'detail'      => __( 'If HTTPS later fails, visitors can’t reach the site until it is fixed. AI assistants can only turn on the 5-minute setting.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'Strict-Transport-Security is no longer sent by this site.', 'bettershield' ),
						__( 'Browsers that already saw it keep refusing plain HTTP until their copy expires.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					return array(
						__( 'Tells browsers to always use HTTPS for your site.', 'bettershield' ),
						__( 'Leaves an existing header alone: one set by WordPress or another plugin, or one your web server adds once the daily check has seen it.', 'bettershield' ),
						__( 'Never adds your site to the browsers’ built-in HTTPS list, which takes months to leave.', 'bettershield' ),
						__( 'Only offered when the site address is already HTTPS.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					return Item\Hsts::conflict();
				},
				'fields'      => static function (): array {
					return Item\Hsts::fields();
				},
			),

			'csp_report_only'  => array(
				'group'       => 'browser',
				// Its conflict line is the next step, not a warning (#2575).
				'conflict_tone' => 'info',
				'reversible'  => true,
				'title'       => __( 'Script-blocking policy', 'bettershield' ),
				'description' => __( 'Lists the scripts and files a stricter browser policy would block, without blocking anything yet.', 'bettershield' ),
				'detail'      => __( 'Visitors’ browsers report what the policy would block, so you see the cost before you turn on blocking.', 'bettershield' ),
				'reverts'     => static function (): array {
					return array(
						__( 'The report-only policy stops, and no new reports are collected.', 'bettershield' ),
						__( 'Sources you allowed are forgotten; switching it on again starts fresh.', 'bettershield' ),
					);
				},
				'effect'      => static function (): array {
					return array(
						__( 'Asks visitors’ browsers to report what a stricter policy would block.', 'bettershield' ),
						__( 'Collects browser reports, grouped by what was blocked and its source. Keeps only the website name, never the full address.', 'bettershield' ),
						__( 'Caps and rate-limits reports, since browsers send them without signing in.', 'bettershield' ),
						__( 'Lets you allow a reported source, take one back, or clear the list. Never allows code written into a page, or allow-all rules. Each change restarts the week.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					return Item\ContentSecurityPolicy::conflict();
				},
				'actions'     => static function (): array {
					return Item\ContentSecurityPolicy::actions();
				},
			),

			'security_headers' => array(
				'group'       => 'browser',
				'reversible'  => true,
				'title'       => __( 'Browser protections', 'bettershield' ),
				'description' => __( 'Adds missing security headers. Skips any your server already sends.', 'bettershield' ),
				'detail'      => __( 'These headers tell browsers to refuse common tricks, such as showing your pages inside another site or guessing what a file is.', 'bettershield' ),
				'reverts'     => static function (): array {
					$lines = array(
						sprintf(
							/* translators: %s: comma-separated list of HTTP header names. */
							__( 'This site stops sending %s. Headers your server adds itself continue.', 'bettershield' ),
							implode( ', ', array_keys( self::headers() ) )
						),
					);

					// The daily look at the front page also tells whether the
					// server sends HSTS itself, and goes on while that is on.
					if ( ! \BetterShield\Hardening\Manager::instance()->is_active( 'hsts' ) ) {
						$lines[] = __( 'The daily check of your front page stops.', 'bettershield' );
					}

					return $lines;
				},
				'effect'      => static function (): array {
					return array(
						__( 'Turns on four browser protections: no framing by other sites, no file-type guessing, shorter referrer details, and no ad-interest tracking.', 'bettershield' ),
						__( 'Covers pages, sign-in, the REST API and the dashboard, where it adds the two headers WordPress does not send.', 'bettershield' ),
						__( 'Still lets other sites embed your posts.', 'bettershield' ),
						__( 'Never overwrites any of these headers that are already set.', 'bettershield' ),
						__( 'Checks your front page daily for headers your web server already sends, and leaves those to it.', 'bettershield' ),
						__( 'The stricter HTTPS setting is separate, because a mistake with it can make the site unreachable.', 'bettershield' ),
					);
				},
				'conflict'    => static function (): ?string {
					// Once applied, the item knows which of the four the server
					// was seen sending, and says so: those are its, not ours.
					//
					// Until then there is nothing to say. The headers PHP has
					// queued for this request are not the server's: this is
					// read on a REST response, where WordPress has already
					// queued one of the four itself, and a header the web
					// server adds is never among them.
					$left = array_map( 'strtolower', (array) ( \BetterShield\Hardening\Manager::instance()->item_state( 'security_headers' )['server_sends'] ?? array() ) );

					if ( array() !== $left ) {
						$named = array();

						foreach ( array_keys( self::headers() ) as $name ) {
							if ( in_array( strtolower( $name ), $left, true ) ) {
								$named[] = $name;
							}
						}

						return sprintf(
							/* translators: %s: comma-separated list of HTTP header names. */
							__( 'Your server already sends %s. This sends the rest.', 'bettershield' ),
							implode( ', ', $named )
						);
					}

					return null;
				},
			),
		);
	}

	/**
	 * What taking one item off does: its `reverts` lines, in the words of the
	 * choice it was applied with where it took one.
	 *
	 * @param array<string, mixed> $options The options the item was applied with.
	 * @return string[]
	 */
	public static function reverts( string $item, array $options = array() ): array {
		$all = self::all();

		return isset( $all[ $item ]['reverts'] ) && is_callable( $all[ $item ]['reverts'] ) ? array_values( array_map( 'strval', (array) ( $all[ $item ]['reverts'] )( $options ) ) ) : array();
	}
}
