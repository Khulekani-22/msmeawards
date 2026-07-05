/*
 * Contact form handler
 * ---------------------------------------------------------------------------
 * Validates the form and POSTs it to the server-side endpoint (api/contact.php),
 * which relays the message as an email through the Resend API.
 *
 * All secrets (Resend API key, sender address) live server-side in .env —
 * never in this file.
 * ---------------------------------------------------------------------------
 */
(function () {
  "use strict";

  var form = document.getElementById("contactForm");
  if (!form) return;

  // Endpoints resolved relative to this page so they work from any base path.
  var ENDPOINT = "api/contact.php";
  var CSRF_ENDPOINT = "api/csrf.php";

  // Optional Cloudflare Turnstile site key. Set window.CONTACT_TURNSTILE_SITEKEY
  // in the page to enable bot verification. Empty string = disabled.
  var TURNSTILE_SITEKEY = (window.CONTACT_TURNSTILE_SITEKEY || "")
    .toString()
    .trim();

  var statusEl = document.getElementById("contactStatus");
  var submitBtn = document.getElementById("contactSubmit");
  var submitDefaultLabel = submitBtn ? submitBtn.innerHTML : "Send Message";

  var csrfToken = "";
  var turnstileToken = "";
  var turnstileWidgetId = null;

  /**
   * Send the message to the server-side Resend relay.
   * @param {{name:string,email:string,subject:string,message:string,website:string,csrf_token:string,turnstile_token:string}} payload
   * @returns {Promise<{ok:boolean, id?:string}>}
   */
  function sendContactMessage(payload) {
    return fetch(ENDPOINT, {
      method: "POST",
      credentials: "same-origin", // send the session cookie for CSRF validation
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(payload),
    }).then(function (res) {
      return res
        .json()
        .catch(function () {
          return {};
        })
        .then(function (data) {
          if (!res.ok || !data || data.ok !== true) {
            var message =
              data && data.error
                ? data.error
                : "Request failed (" + res.status + ").";
            throw new Error(message);
          }
          return data;
        });
    });
  }

  function value(id) {
    var el = document.getElementById(id);
    return el ? el.value.trim() : "";
  }

  function setStatus(message, type) {
    if (!statusEl) return;
    statusEl.textContent = message || "";
    statusEl.className = "contact-status" + (type ? " contact-status--" + type : "");
    statusEl.hidden = !message;
  }

  function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  // Fetch (and cache) a CSRF token tied to the server session.
  function getCsrfToken() {
    if (csrfToken) return Promise.resolve(csrfToken);
    return fetch(CSRF_ENDPOINT, {
      method: "GET",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    })
      .then(function (res) {
        return res.json();
      })
      .then(function (data) {
        csrfToken = (data && data.token) || "";
        return csrfToken;
      });
  }

  // Load + render the Turnstile widget when a site key is configured.
  function initTurnstile() {
    if (!TURNSTILE_SITEKEY) return;
    var container = document.getElementById("contactTurnstile");
    if (!container) return;

    window.__contactTurnstileReady = function () {
      if (!window.turnstile) return;
      turnstileWidgetId = window.turnstile.render(container, {
        sitekey: TURNSTILE_SITEKEY,
        callback: function (token) {
          turnstileToken = token;
        },
        "error-callback": function () {
          turnstileToken = "";
        },
        "expired-callback": function () {
          turnstileToken = "";
        },
      });
    };

    var s = document.createElement("script");
    s.src =
      "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=__contactTurnstileReady";
    s.async = true;
    s.defer = true;
    document.head.appendChild(s);
  }

  // Clear the token and reset the widget (after a submit attempt).
  function resetTurnstile() {
    turnstileToken = "";
    if (turnstileWidgetId !== null && window.turnstile) {
      try {
        window.turnstile.reset(turnstileWidgetId);
      } catch (e) {
        /* ignore */
      }
    }
  }

  initTurnstile();

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    setStatus("", null);

    var payload = {
      name: value("contactName"),
      email: value("contactEmail"),
      subject: value("contactSubject"),
      message: value("contactMessage"),
      website: value("contactWebsite"), // honeypot (kept empty by real users)
    };

    // Basic client-side validation
    if (!payload.name || !payload.email || !payload.message) {
      setStatus("Please complete your name, email and message.", "error");
      return;
    }
    if (!isValidEmail(payload.email)) {
      setStatus("Please enter a valid email address.", "error");
      return;
    }

    // Require the Turnstile challenge to be completed when it is enabled.
    if (TURNSTILE_SITEKEY && !turnstileToken) {
      setStatus("Please complete the verification challenge below.", "error");
      return;
    }

    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.innerHTML = "Sending\u2026";
    }
    setStatus("Sending your message\u2026", "info");

    getCsrfToken()
      .then(function (token) {
        payload.csrf_token = token;
        payload.turnstile_token = turnstileToken;
        return sendContactMessage(payload);
      })
      .then(function () {
        form.reset();
        resetTurnstile();
        setStatus(
          "Thanks! Your message has been sent \u2014 we'll be in touch soon.",
          "success"
        );
      })
      .catch(function (err) {
        // eslint-disable-next-line no-console
        console.error("[contact] send failed:", err);
        resetTurnstile();
        setStatus(
          (err && err.message) ||
            "Sorry, something went wrong while sending. Please try again later.",
          "error"
        );
      })
      .then(function () {
        // finally (broad browser support)
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.innerHTML = submitDefaultLabel;
        }
      });
  });
})();
