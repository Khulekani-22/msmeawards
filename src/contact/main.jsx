// Entry point for the contact form React island. Mounts into #contact-widget
// on contact.html; a no-op on pages that don't include that element.
import React from 'react';
import { createRoot } from 'react-dom/client';
import ContactForm from './ContactForm.jsx';

const mountEl = document.getElementById('contact-widget');
if (mountEl) {
  createRoot(mountEl).render(
    <React.StrictMode>
      <ContactForm />
    </React.StrictMode>
  );
}
