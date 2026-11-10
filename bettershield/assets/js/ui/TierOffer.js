/**
 * The one quiet way a screen may mention a paid tier, as the server states it.
 *
 * Nothing unless the server named an offer — which it does not while there is
 * nothing to point at, and never once the site is on that tier. Where it may
 * appear is a product rule, not a screen's choice: at the foot of a settings
 * card on this plugin's own screens, and nowhere near a finding, an alert or a
 * warning. The words come from the server too, so this bundle carries no
 * promise of its own.
 */

const model = window.bettershield || {};

/** {name, url, summary, adds} when the server named one; null otherwise. */
export const offer = model.offer && model.offer.name && model.offer.url ? model.offer : null;

/** The limits the tier sets, as the server states them for this request. */
export const limits = {
	retentionDays: model.limits && model.limits.retention_days ? Number( model.limits.retention_days ) : 30,
};
