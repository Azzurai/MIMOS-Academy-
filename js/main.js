/* ============================================
   MIMOS Academy — Main JavaScript
   ============================================ */

document.addEventListener('DOMContentLoaded', () => {

  // --- Navbar Scroll Effect ---
  const navbar = document.querySelector('.navbar');
  if (navbar) {
    window.addEventListener('scroll', () => {
      if (window.scrollY > 10) {
        navbar.classList.add('scrolled');
      } else {
        navbar.classList.remove('scrolled');
      }
    });
  }

  // --- Mobile Menu Toggle ---
  const toggle = document.querySelector('.navbar__toggle');
  const navLinks = document.querySelector('.navbar__links');
  if (toggle && navLinks) {
    toggle.addEventListener('click', () => {
      navLinks.classList.toggle('open');
      toggle.classList.toggle('active');
    });

    // Close menu when clicking a link
    navLinks.querySelectorAll('.navbar__link').forEach(link => {
      link.addEventListener('click', () => {
        navLinks.classList.remove('open');
        toggle.classList.remove('active');
      });
    });
  }

  // --- Scroll Animations ---
  const animatedElements = document.querySelectorAll('.animate-on-scroll');
  if (animatedElements.length > 0) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('visible');
          observer.unobserve(entry.target);
        }
      });
    }, {
      threshold: 0.1,
      rootMargin: '0px 0px -50px 0px'
    });

    animatedElements.forEach(el => observer.observe(el));
  }

  // --- Filter Tabs (Programs Page) ---
  const filterTabs = document.querySelectorAll('.course-filters__tab');
  filterTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      filterTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
    });
  });

  // --- Contact Form Handling ---
  const contactForm = document.querySelector('#contactForm');
  if (contactForm) {
    contactForm.addEventListener('submit', (e) => {
      e.preventDefault();

      const fullName = document.querySelector('#fullName').value.trim();
      const email = document.querySelector('#email').value.trim();
      const message = document.querySelector('#message').value.trim();

      if (!fullName || !email || !message) {
        showNotification('Please fill in all required fields.', 'error');
        return;
      }

      // Email validation
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        showNotification('Please enter a valid email address.', 'error');
        return;
      }

      // Simulate form submission
      const submitBtn = contactForm.querySelector('.form-submit');
      submitBtn.textContent = 'Sending...';
      submitBtn.disabled = true;

      setTimeout(() => {
        showNotification('Your message has been sent successfully!', 'success');
        contactForm.reset();
        submitBtn.innerHTML = 'Send Enquiry <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>';
        submitBtn.disabled = false;
      }, 1500);
    });
  }

  // --- Notification System ---
  function showNotification(message, type = 'success') {
    // Remove existing notification
    const existing = document.querySelector('.notification');
    if (existing) existing.remove();

    const notification = document.createElement('div');
    notification.className = `notification notification--${type}`;
    notification.innerHTML = `
      <span>${message}</span>
      <button onclick="this.parentElement.remove()" style="background:none;border:none;color:inherit;cursor:pointer;font-size:18px;padding:0 0 0 12px;">&times;</button>
    `;

    // Style the notification
    Object.assign(notification.style, {
      position: 'fixed',
      top: '90px',
      right: '20px',
      padding: '14px 20px',
      borderRadius: '10px',
      color: '#fff',
      fontWeight: '500',
      fontSize: '14px',
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      zIndex: '9999',
      animation: 'fadeInUp 0.3s ease',
      boxShadow: '0 4px 20px rgba(0,0,0,0.15)',
      background: type === 'success' ? '#059669' : '#dc2626',
    });

    document.body.appendChild(notification);

    // Auto-remove after 4 seconds
    setTimeout(() => {
      if (notification.parentElement) {
        notification.style.opacity = '0';
        notification.style.transform = 'translateY(-10px)';
        notification.style.transition = 'all 0.3s ease';
        setTimeout(() => notification.remove(), 300);
      }
    }, 4000);
  }

  // --- Smooth scroll for anchor links ---
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });

  // --- Dynamic Navbar Auth Status ---
  updateNavbarAuth();

  function updateNavbarAuth() {
    // Avoid running this on the login/register/auth pages themselves
    if (document.querySelector('.auth-page')) return;

    const navbarActions = document.querySelector('.navbar__actions');
    if (!navbarActions) return;

    fetch('auth.php?action=check-session')
      .then(r => {
        if (!r.ok) throw new Error('Network response was not ok');
        return r.json();
      })
      .then(data => {
        if (data.logged_in) {
          const userName = data.user.name;
          const userAvatar = data.user.avatar;
          
          let avatarHtml = '';
          if (userAvatar) {
            avatarHtml = `<img src="${userAvatar}" alt="${userName}" class="navbar__avatar">`;
          } else {
            const initials = userName.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase();
            avatarHtml = `<div class="navbar__avatar-placeholder">${initials}</div>`;
          }

          navbarActions.innerHTML = `
            <button class="navbar__search" aria-label="Search">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
            </button>
            <div class="navbar__user-menu">
              <button class="navbar__user-btn" aria-label="User menu">
                ${avatarHtml}
                <span class="navbar__user-name">${userName.split(' ')[0]}</span>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m6 9 6 6 6-6"/></svg>
              </button>
              <div class="navbar__dropdown">
                <div class="navbar__dropdown-header">
                  <strong>${userName}</strong>
                  <span>${data.user.email}</span>
                </div>
                <hr>
                <button type="button" class="navbar__dropdown-item navbar__dropdown-item--devices" id="showDevicesBtn">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                  Active Devices
                </button>
                <a href="auth.php?action=logout" class="navbar__dropdown-item navbar__dropdown-item--logout">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg>
                  Sign Out
                </a>
              </div>
            </div>
          `;

          const userBtn = navbarActions.querySelector('.navbar__user-btn');
          const dropdown = navbarActions.querySelector('.navbar__dropdown');
          if (userBtn && dropdown) {
            userBtn.addEventListener('click', (e) => {
              e.stopPropagation();
              dropdown.classList.toggle('show');
            });
            document.addEventListener('click', () => {
              dropdown.classList.remove('show');
            });
          }

          const showDevicesBtn = navbarActions.querySelector('#showDevicesBtn');
          if (showDevicesBtn) {
            showDevicesBtn.addEventListener('click', (e) => {
              e.stopPropagation();
              dropdown.classList.remove('show');
              renderDevicesModal(data);
            });
          }
        } else {
          navbarActions.innerHTML = `
            <button class="navbar__search" aria-label="Search">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
            </button>
            <a href="auth.php" class="navbar__link-signin" style="font-size: var(--font-size-sm); font-weight: 600; color: var(--color-dark-text); margin-right: 15px; transition: color var(--transition-fast); display: inline-block;">Sign In</a>
            <a href="auth.php?action=register" class="navbar__cta">
              Register Now
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
            </a>
          `;

          const signInLink = navbarActions.querySelector('.navbar__link-signin');
          if (signInLink) {
            signInLink.addEventListener('mouseenter', () => signInLink.style.color = 'var(--color-primary)');
            signInLink.addEventListener('mouseleave', () => signInLink.style.color = 'var(--color-dark-text)');
          }
        }
      })
      .catch(err => {
        console.error('Session status fetch failed', err);
      });
  }

  function renderDevicesModal(data) {
    // Remove existing modal if any
    const existing = document.querySelector('.devices-modal-overlay');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.className = 'devices-modal-overlay';
    
    const sessions = data.sessions || [];
    
    overlay.innerHTML = `
      <div class="devices-modal">
        <div class="devices-modal__header">
          <h3>Active Devices</h3>
          <button class="devices-modal__close" aria-label="Close">&times;</button>
        </div>
        <div class="devices-modal__body">
          <p class="devices-modal__subtitle">Manage the devices currently logged in to your account. You can revoke access for any remote session here.</p>
          <div class="devices-modal__list">
            ${sessions.map(sess => `
              <div class="device-item ${sess.is_current ? 'device-item--current' : ''}">
                <div class="device-item__icon">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    ${sess.device.includes('Windows') || sess.device.includes('macOS') || sess.device.includes('Linux')
                      ? '<rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>'
                      : '<rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12" y2="18"/>'
                    }
                  </svg>
                </div>
                <div class="device-item__details">
                  <div class="device-item__name">
                    ${sess.device}
                    ${sess.is_current ? '<span class="device-badge device-badge--current">This Device</span>' : ''}
                  </div>
                  <div class="device-item__meta">
                    IP: ${sess.ip} &bull; Created: ${sess.created_at}
                  </div>
                </div>
                ${sess.is_current ? '' : `
                  <button class="device-logout-btn" data-id="${sess.id}">
                    Log Out
                  </button>
                `}
              </div>
            `).join('')}
          </div>
          ${sessions.length > 1 ? `
            <button class="devices-logout-others-btn" id="logoutOthersBtn">
              Log Out of All Other Devices
            </button>
          ` : ''}
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    // Trigger animate-in
    setTimeout(() => overlay.classList.add('show'), 10);

    // Close handlers
    const closeBtn = overlay.querySelector('.devices-modal__close');
    const closeModal = () => {
      overlay.classList.remove('show');
      setTimeout(() => overlay.remove(), 250);
    };
    
    closeBtn.addEventListener('click', closeModal);
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) closeModal();
    });

    // Revoke single device handler
    overlay.querySelectorAll('.device-logout-btn').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const sessionId = e.target.getAttribute('data-id');
        if (!confirm('Are you sure you want to log out this device? The device will be disconnected instantly.')) {
          return;
        }

        e.target.disabled = true;
        e.target.textContent = 'Logging out...';

        try {
          const res = await fetch('auth.php?action=logout-device', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              session_id: sessionId,
              csrf_token: data.csrf_token
            })
          });
          const result = await res.json();
          if (result.success) {
            updateNavbarAuth();
            closeModal();
            alert(result.message);
          } else {
            alert(result.message || 'Failed to log out device.');
            e.target.disabled = false;
            e.target.textContent = 'Log Out';
          }
        } catch (err) {
          alert('Network error. Please try again.');
          e.target.disabled = false;
          e.target.textContent = 'Log Out';
        }
      });
    });

    // Revoke other devices handler
    const logoutOthersBtn = overlay.querySelector('#logoutOthersBtn');
    if (logoutOthersBtn) {
      logoutOthersBtn.addEventListener('click', async () => {
        if (!confirm('Are you sure you want to log out of all other devices? This will disconnect every session except this browser.')) {
          return;
        }

        logoutOthersBtn.disabled = true;
        logoutOthersBtn.textContent = 'Revoking...';

        try {
          const res = await fetch('auth.php?action=logout-others', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              csrf_token: data.csrf_token
            })
          });
          const result = await res.json();
          if (result.success) {
            updateNavbarAuth();
            closeModal();
            alert(result.message);
          } else {
            alert(result.message || 'Failed to log out other devices.');
            logoutOthersBtn.disabled = false;
            logoutOthersBtn.textContent = 'Log Out of All Other Devices';
          }
        } catch (err) {
          alert('Network error. Please try again.');
          logoutOthersBtn.disabled = false;
          logoutOthersBtn.textContent = 'Log Out of All Other Devices';
        }
      });
    }
  }

});
