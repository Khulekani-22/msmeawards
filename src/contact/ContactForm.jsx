import React, { useEffect, useRef, useState, useCallback } from 'react';
import axios from 'axios';

// Same-origin API (Vercel serves the site and functions together).
const api = axios.create({ baseURL: '/api', timeout: 20000 });

// Public Turnstile site key (safe to embed). Runtime global wins so the
// committed bundle stays configurable; build-time env is the fallback.
const TURNSTILE_SITEKEY =
  (typeof window !== 'undefined' && window.CONTACT_TURNSTILE_SITEKEY) ||
  import.meta.env.VITE_TURNSTILE_SITEKEY ||
  '';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const initialForm = { name: '', email: '', subject: '', message: '', website: '' };

export default function ContactForm() {
  const [form, setForm] = useState(initialForm);
  const [status, setStatus] = useState({ type: null, message: '' });
  const [submitting, setSubmitting] = useState(false);

  const csrfRef = useRef('');
  const turnstileTokenRef = useRef('');
  const turnstileElRef = useRef(null);
  const turnstileWidgetId = useRef(null);

  /* Fetch a stateless CSRF token up front (and refresh lazily on submit). */
  const fetchCsrf = useCallback(async () => {
    try {
      const { data } = await api.get('/csrf', { headers: { Accept: 'application/json' } });
      csrfRef.current = data?.token || '';
    } catch {
      csrfRef.current = '';
    }
    return csrfRef.current;
  }, []);

  useEffect(() => {
    fetchCsrf();
  }, [fetchCsrf]);

  /* Optional Cloudflare Turnstile — load + render when a site key is set. */
  useEffect(() => {
    if (!TURNSTILE_SITEKEY || !turnstileElRef.current) return undefined;

    const render = () => {
      if (!window.turnstile || turnstileWidgetId.current !== null) return;
      turnstileWidgetId.current = window.turnstile.render(turnstileElRef.current, {
        sitekey: TURNSTILE_SITEKEY,
        callback: (token) => {
          turnstileTokenRef.current = token;
        },
        'error-callback': () => {
          turnstileTokenRef.current = '';
        },
        'expired-callback': () => {
          turnstileTokenRef.current = '';
        },
      });
    };

    if (window.turnstile) {
      render();
      return undefined;
    }

    const existing = document.querySelector('script[data-turnstile]');
    if (!existing) {
      const s = document.createElement('script');
      s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      s.async = true;
      s.defer = true;
      s.setAttribute('data-turnstile', '');
      s.onload = render;
      document.head.appendChild(s);
    } else {
      existing.addEventListener('load', render);
    }
    return undefined;
  }, []);

  const resetTurnstile = () => {
    turnstileTokenRef.current = '';
    if (turnstileWidgetId.current !== null && window.turnstile) {
      try {
        window.turnstile.reset(turnstileWidgetId.current);
      } catch {
        /* ignore */
      }
    }
  };

  const onChange = (e) => {
    const { name, value } = e.target;
    setForm((f) => ({ ...f, [name]: value }));
  };

  const setError = (message) => setStatus({ type: 'error', message });

  const onSubmit = async (e) => {
    e.preventDefault();
    setStatus({ type: null, message: '' });

    const name = form.name.trim();
    const email = form.email.trim();
    const message = form.message.trim();

    if (!name || !email || !message) {
      return setError('Please complete your name, email and message.');
    }
    if (!EMAIL_RE.test(email)) {
      return setError('Please enter a valid email address.');
    }
    if (TURNSTILE_SITEKEY && !turnstileTokenRef.current) {
      return setError('Please complete the verification challenge below.');
    }

    setSubmitting(true);
    setStatus({ type: 'info', message: 'Sending your message…' });

    try {
      const token = csrfRef.current || (await fetchCsrf());
      const { data } = await api.post('/contact', {
        ...form,
        name,
        email,
        message,
        csrf_token: token,
        turnstile_token: turnstileTokenRef.current,
      });

      if (data?.ok) {
        setForm(initialForm);
        resetTurnstile();
        csrfRef.current = '';
        fetchCsrf();
        setStatus({
          type: 'success',
          message: "Thanks! Your message has been sent — we'll be in touch soon.",
        });
      } else {
        setError(data?.error || 'Something went wrong. Please try again later.');
      }
    } catch (err) {
      resetTurnstile();
      csrfRef.current = '';
      fetchCsrf();
      const apiError = err?.response?.data?.error;
      setError(apiError || 'Sorry, something went wrong while sending. Please try again later.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form id="contactForm" onSubmit={onSubmit} noValidate>
      <div className="row g-3">
        {/* Honeypot: hidden from humans, tempts bots. */}
        <div className="d-none" aria-hidden="true">
          <label htmlFor="contactWebsite">Website</label>
          <input
            className="form-control"
            id="contactWebsite"
            name="website"
            type="text"
            tabIndex={-1}
            autoComplete="off"
            value={form.website}
            onChange={onChange}
          />
        </div>

        <div className="col-md-6">
          <label className="form-label" htmlFor="contactName">
            Name <span aria-hidden="true">*</span>
          </label>
          <input
            className="form-control"
            id="contactName"
            name="name"
            type="text"
            autoComplete="name"
            placeholder="Your full name"
            required
            value={form.name}
            onChange={onChange}
          />
        </div>

        <div className="col-md-6">
          <label className="form-label" htmlFor="contactEmail">
            Email <span aria-hidden="true">*</span>
          </label>
          <input
            className="form-control"
            id="contactEmail"
            name="email"
            type="email"
            autoComplete="email"
            placeholder="you@example.com"
            required
            value={form.email}
            onChange={onChange}
          />
        </div>

        <div className="col-12">
          <label className="form-label" htmlFor="contactSubject">
            Subject
          </label>
          <input
            className="form-control"
            id="contactSubject"
            name="subject"
            type="text"
            placeholder="How can we help?"
            value={form.subject}
            onChange={onChange}
          />
        </div>

        <div className="col-12">
          <label className="form-label" htmlFor="contactMessage">
            Message <span aria-hidden="true">*</span>
          </label>
          <textarea
            className="form-control"
            id="contactMessage"
            name="message"
            rows={5}
            placeholder="Write your message…"
            required
            value={form.message}
            onChange={onChange}
          />
        </div>

        {TURNSTILE_SITEKEY ? (
          <div className="col-12">
            <div ref={turnstileElRef} className="contact-turnstile" />
          </div>
        ) : null}

        <div className="col-12 d-flex align-items-center gap-3 flex-wrap">
          <button className="contact-submit" id="contactSubmit" type="submit" disabled={submitting}>
            {submitting ? 'Sending…' : 'Send Message'}
          </button>
          {status.message ? (
            <p
              className={
                'contact-status' + (status.type ? ` contact-status--${status.type}` : '')
              }
              role="status"
              aria-live="polite"
            >
              {status.message}
            </p>
          ) : null}
        </div>

        <div className="col-12">
          <p className="contact-note">
            We typically respond within 2&ndash;3 business days. Your details are used only to
            respond to your enquiry.
          </p>
        </div>
      </div>
    </form>
  );
}
