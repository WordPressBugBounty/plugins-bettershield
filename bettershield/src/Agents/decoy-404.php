<?php
/** Inert fallback when the active theme has no 404 template. @package BetterShield */
if ( ! defined( 'ABSPATH' ) ) { exit; }
?>
<!doctype html><html><head><meta charset="utf-8"><title><?php esc_html_e( 'Not found', 'bettershield' ); ?></title></head><body><h1><?php esc_html_e( 'Not found', 'bettershield' ); ?></h1></body></html>
