/**
 * Post-build.
 *
 * Every generated *.asset.php must carry the same direct file access guard
 * every shipped PHP file has. And the widget entry exists only for its
 * stylesheet, so the empty script it also produces is removed rather than
 * shipped.
 */
const fs = require( 'fs' );
const path = require( 'path' );

const dir = 'assets/build';
const guard = "<?php if ( ! defined( 'ABSPATH' ) ) { exit; }";

for ( const name of [ 'widget.js', 'widget.asset.php' ] ) {
	const file = path.join( dir, name );
	if ( fs.existsSync( file ) ) {
		fs.unlinkSync( file );
	}
}

for ( const name of fs.readdirSync( dir ) ) {
	if ( ! name.endsWith( '.asset.php' ) ) {
		continue;
	}

	const file = path.join( dir, name );
	const contents = fs.readFileSync( file, 'utf8' );

	if ( ! contents.includes( 'ABSPATH' ) ) {
		fs.writeFileSync( file, contents.replace( '<?php', guard ) );
	}
}
