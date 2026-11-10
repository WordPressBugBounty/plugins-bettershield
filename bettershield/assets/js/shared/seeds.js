/*
 * The one brand seed: the green of the product mark. ThemeProvider generates
 * the whole ramp from it, and decides light or dark from the background seed
 * — which `Root()` sets from the scheme the reader chose, rather than
 * leaving unset for the surface to inherit whatever wp-admin is using. That
 * changed when the app grew a light/dark control of its own: a scheme the
 * reader picks here has to paint the page here, and inheriting the admin's
 * would have left the two disagreeing. Every color in admin.css resolves
 * through the ramp, so between this object and that seed is where every
 * color is chosen.
 *
 * This is the mark's hue and saturation exactly, darkened until the button
 * label clears AA in every state. It is not the mark's own green, and the
 * gap is not an approximation to be tightened later:
 *
 * The seed passes through unchanged as the primary fill, and the ramp picks
 * the label that goes on it. Above roughly #008766 it stops being able to
 * reach contrast with white, and either forces white anyway — which it
 * reports as a warning — or, brighter still, flips the label to near-black.
 * A dark label is where this breaks, because core's primary Button darkens
 * on hover and again on press: at the mark's own green the resting button
 * measures 5.2:1 and the pressed one 3.4:1. #008766 is the brightest seed
 * the ramp takes unchanged and unwarned, and it holds 4.5:1 at rest, 5.5:1
 * hovered and 6.5:1 pressed.
 *
 * Moving the seed moves the literal fallbacks in tokens.css too; they are
 * that ramp's light values, and the two are meant to agree.
 */
export const BRAND_SEEDS = { primary: '#008766' };
