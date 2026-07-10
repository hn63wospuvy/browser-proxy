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
    const u = new URL(input);
    // Only accept a real web URL. "example.com:8080" also parses as a URL whose scheme is
    // "example.com:", so gate on http/https to avoid passing that through unproxied.
    if (u.protocol === "http:" || u.protocol === "https:") return u.toString();
  } catch (_) {
    /* not a full URL */
  }

  try {
    const url = new URL(`https://${input}`);
    // A bare host, with or without a port: "example.com", "localhost:3000".
    if (url.hostname.includes(".") || url.port) return url.toString();
  } catch (_) {
    /* not a bare host either */
  }

  return template.replace("%s", encodeURIComponent(input));
}
