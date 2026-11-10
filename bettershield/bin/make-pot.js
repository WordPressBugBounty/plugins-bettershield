/**
 * Regenerates the translation template.
 *
 * make-pot stamps the time of the run into POT-Creation-Date, so every run
 * would change the file even when no string did. The template is written only
 * when something other than that line differs, which leaves the date as the
 * time the template last really changed.
 */
const fs = require( 'fs' );
const os = require( 'os' );
const path = require( 'path' );
const { execSync } = require( 'child_process' );

const template = 'languages/bettershield.pot';
const stamp = /^"POT-Creation-Date: .*$/m;

const withoutStamp = ( contents ) => contents.replace( stamp, '' );

// Written outside the plugin so that the run never scans its own output.
const dir = fs.mkdtempSync( path.join( os.tmpdir(), 'bettershield-pot-' ) );

try {
	const generated = path.join( dir, 'bettershield.pot' );

	execSync(
		`php -d memory_limit=1G "$(command -v wp)" i18n make-pot . "${ generated }" --domain=bettershield --include=bettershield.php,src,assets/js,assets/build --exclude=release,docs,tests,vendor,node_modules`,
		{ stdio: 'inherit' }
	);

	const next = fs.readFileSync( generated, 'utf8' );
	const current = fs.existsSync( template )
		? fs.readFileSync( template, 'utf8' )
		: null;

	if (
		null === current ||
		withoutStamp( current ) !== withoutStamp( next )
	) {
		fs.writeFileSync( template, next );
	}
} finally {
	fs.rmSync( dir, { recursive: true, force: true } );
}
