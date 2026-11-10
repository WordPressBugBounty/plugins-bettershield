<?php
/**
 * The base words the most-guessed passwords are built from.
 *
 * Deliberately short and auditable rather than a bundled corpus: candidates
 * are compared after lowercasing and stripping the decorating digits and
 * punctuation people add, so one entry here covers its whole family —
 * one entry such as "password" also refuses its decorated forms. A breached-
 * corpus check is the real extension and belongs with the plugin's first
 * disclosed external call, not here.
 *
 * Sources: the perennial top of every published breach-frequency list.
 * Entries shorter than any permitted minimum length still matter, because
 * they are cores, not full passwords.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Password;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class CommonWords {

	public const LIST = array(
		'password',
		'passwort',
		'motdepasse',
		'contrasena',
		'qwerty',
		'qwertyuiop',
		'azerty',
		'asdfgh',
		'asdfghjkl',
		'zxcvbnm',
		'letmein',
		'welcome',
		'monkey',
		'dragon',
		'master',
		'shadow',
		'superman',
		'batman',
		'trustno',
		'iloveyou',
		'sunshine',
		'princess',
		'flower',
		'butterfly',
		'freedom',
		'whatever',
		'secret',
		'admin',
		'administrator',
		'login',
		'root',
		'toor',
		'user',
		'guest',
		'test',
		'demo',
		'temp',
		'changeme',
		'default',
		'wordpress',
		'football',
		'baseball',
		'soccer',
		'hockey',
		'jordan',
		'harley',
		'ranger',
		'hunter',
		'buster',
		'thomas',
		'robert',
		'jennifer',
		'michelle',
		'charlie',
		'andrew',
		'michael',
		'jessica',
		'daniel',
		'starwars',
		'pokemon',
		'ninja',
		'abc',
		'aaa',
		'xxx',
	);
}
