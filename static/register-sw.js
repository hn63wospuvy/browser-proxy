"use strict";

// The service worker is served from the site root, so its scope is "/" and it can
// intercept every request the proxied page makes.
const SW_PATH = "/sw.js";

// Service workers require a secure context. Browsers make an exception for localhost.
const swAllowedHostnames = ["localhost", "127.0.0.1"];

/**
 * Register the Scramjet service worker. Exposed globally; called from index.js on submit.
 */
async function registerSW() {
  if (!navigator.serviceWorker) {
    if (
      location.protocol !== "https:" &&
      !swAllowedHostnames.includes(location.hostname)
    ) {
      throw new Error(
        "Service workers require HTTPS. Open this page via https:// or on localhost."
      );
    }
    throw new Error("This browser does not support service workers.");
  }

  await navigator.serviceWorker.register(SW_PATH);
}
