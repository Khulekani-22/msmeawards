// Hide/reveal Bootstrap navbar on scroll direction
(function(){
  const nav = document.querySelector('nav.navbar');
  if (!nav) return;

  let lastY = window.scrollY || window.pageYOffset;
  let ticking = false;
  const delta = 6; // minimum scroll delta to toggle

  const shouldIgnore = () => {
    // Do not hide when at top, or when mobile menu is open
    const collapsed = document.querySelector('.navbar-collapse');
    const menuOpen = collapsed && collapsed.classList.contains('show');
    return window.scrollY <= 0 || menuOpen;
  };

  const update = () => {
    ticking = false;
    if (shouldIgnore()) {
      nav.classList.remove('navbar-hidden');
      lastY = window.scrollY;
      return;
    }

    const currentY = window.scrollY;
    const diff = currentY - lastY;

    if (diff > delta && currentY > 64) {
      // scrolling down
      nav.classList.add('navbar-hidden');
    } else if (diff < -delta) {
      // scrolling up
      nav.classList.remove('navbar-hidden');
    }
    lastY = currentY;
  };

  window.addEventListener('scroll', function(){
    if (!ticking) {
      window.requestAnimationFrame(update);
      ticking = true;
    }
  }, { passive: true });

  // Ensure shown on load and when navbar collapse toggles
  document.addEventListener('DOMContentLoaded', () => {
    nav.classList.remove('navbar-hidden');
  });

  document.addEventListener('shown.bs.collapse', (e) => {
    if (e.target && e.target.classList.contains('navbar-collapse')) {
      nav.classList.remove('navbar-hidden');
    }
  });
  document.addEventListener('hidden.bs.collapse', (e) => {
    if (e.target && e.target.classList.contains('navbar-collapse')) {
      // reset lastY so next scroll direction is computed correctly
      lastY = window.scrollY;
    }
  });
})();

