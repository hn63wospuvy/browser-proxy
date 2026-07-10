"use strict";

/**
 * Turn user input into a fully-qualified URL.
 *
 * - Already a valid URL (has a scheme)      → used as-is.
 * - Looks like a bare host ("example.com")  → prefixed with https://.
 * - Anything else                           → treated as a search query.
 *
 * @param {string} input
 * @param {string} template Search template with a `%s` placeholder.
 * @returns {string} Fully-qualified URL.
 */
function search(input, template) {
  try {
    return new URL(input).toString();
  } catch (_) {
    /* not a full URL */
  }

  try {
    const url = new URL(`https://${input}`);
    if (url.hostname.includes(".")) return url.toString();
  } catch (_) {
    /* not a bare host either */
  }

  return template.replace("%s", encodeURIComponent(input));
}
