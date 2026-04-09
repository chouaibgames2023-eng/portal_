/**
 * Lab44 — Shared JavaScript Utilities
 * Common functions used across all pages
 */

// ── API Configuration ──────────────────────────────────────────────────────────
const Lab44Config = {
  baseUrl: window.location.origin,
  api: window.location.origin + '/api',
  guacUrl: '',
  
  async load() {
    try {
      const res = await fetch(this.baseUrl + '/api/config');
      const config = await res.json();
      this.api = config.student_api ? config.student_api + '/api' : this.api;
      this.guacUrl = config.guacamole_url || '';
      return config;
    } catch (err) {
      console.warn('Failed to load config:', err);
      return null;
    }
  }
};

// ── Authentication Helpers ─────────────────────────────────────────────────────
const Lab44Auth = {
  getRole() {
    return sessionStorage.getItem('lab44_role');
  },
  
  getStudent() {
    const data = sessionStorage.getItem('lab44_student');
    return data ? JSON.parse(data) : null;
  },
  
  isAdmin() {
    return this.getRole() === 'admin';
  },
  
  isStudent() {
    return this.getRole() === 'student';
  },
  
  requireStudent(redirectUrl = 'index.html') {
    if (!this.isStudent()) {
      window.location.replace(redirectUrl);
      return false;
    }
    return true;
  },
  
  requireAdmin(redirectUrl = 'admin.html') {
    if (!this.isAdmin()) {
      window.location.replace(redirectUrl);
      return false;
    }
    return true;
  },
  
  logout(redirectUrl = 'index.html') {
    sessionStorage.removeItem('lab44_role');
    sessionStorage.removeItem('lab44_student');
    window.location.href = redirectUrl;
  }
};

// ── UI Helpers ─────────────────────────────────────────────────────────────────
const Lab44UI = {
  // Escape HTML to prevent XSS
  esc(s) {
    return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
                          .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  },
  
  // Escape for JavaScript string literals in onclick handlers
  escAttr(s) {
    return String(s ?? '').replace(/'/g, "\\'").replace(/"/g, '&quot;');
  },
  
  // Show alert message
  showAlert(elementId, message, type = 'error') {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.className = `alert alert-${type} show`;
    el.textContent = message;
  },
  
  // Clear alert message
  clearAlert(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.className = 'alert';
    el.textContent = '';
  },
  
  // Field error handling
  fieldError(fieldId, message) {
    const el = document.getElementById(fieldId);
    if (!el) return;
    el.textContent = message;
    el.style.display = message ? 'flex' : 'none';
  },
  
  // Input state marking
  markInput(inputId, state) {
    const el = document.getElementById(inputId);
    if (!el) return;
    el.classList.remove('err', 'ok');
    if (state) el.classList.add(state);
  },
  
  // Show modal
  showModal(modalId, html) {
    const overlay = document.getElementById(modalId);
    if (!overlay) return;
    overlay.style.display = 'flex';
    overlay.innerHTML = `<div class="modal-overlay" onclick="if(event.target===this)this.style.display='none'">${html}</div>`;
  },
  
  // Hide modal
  hideModal(modalId) {
    const overlay = document.getElementById(modalId);
    if (overlay) overlay.style.display = 'none';
  },
  
  // Format date
  formatDate(dateStr) {
    if (!dateStr) return '';
    const d = new Date(dateStr.replace(' ', 'T'));
    if (isNaN(d)) return dateStr.split(' ')[0];
    return d.toLocaleDateString();
  },
  
  // Format time
  formatTime(dateStr) {
    if (!dateStr) return '';
    const d = new Date(dateStr.replace(' ', 'T'));
    if (isNaN(d)) return '';
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
};

// ── Form Validation ────────────────────────────────────────────────────────────
const Lab44Validation = {
  validateName(value, minLen = 2) {
    const v = value.trim();
    if (!v || v.length < minLen) {
      return { valid: false, message: `Minimum ${minLen} characters.` };
    }
    return { valid: true };
  },
  
  validateStudentId(value, minLen = 3) {
    const v = value.trim();
    if (!v || v.length < minLen) {
      return { valid: false, message: `Minimum ${minLen} characters.` };
    }
    return { valid: true };
  },
  
  validatePassword(value, minLen = 1) {
    if (!value || value.length < minLen) {
      return { valid: false, message: 'Password is required.' };
    }
    return { valid: true };
  },
  
  // Attach live validation to inputs
  attachLiveValidation(inputIds, onError, onClear) {
    inputIds.forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      el.addEventListener('input', () => {
        if (onClear) onClear(id);
      });
    });
  }
};

// ── Guacamole URL Builder ──────────────────────────────────────────────────────
const Lab44Guac = {
  buildUrl(protocol, host, port = null) {
    if (!Lab44Config.guacUrl || !host) return null;
    const defaultPort = protocol === 'rdp' ? '3389' : '22';
    const connStr = `${protocol}://admin:000000@${host}:${port || defaultPort}/?security=any&ignore-cert=true`;
    const b64 = btoa(connStr);
    return `${Lab44Config.guacUrl.replace(/\/$/, '')}/#/client/${b64}`;
  },
  
  openSSH(host) {
    const url = this.buildUrl('ssh', host);
    if (url) window.open(url, '_blank', 'noopener');
  },
  
  openRDP(host) {
    const url = this.buildUrl('rdp', host);
    if (url) window.open(url, '_blank', 'noopener');
  }
};

// ── API Request Helpers ────────────────────────────────────────────────────────
const Lab44API = {
  async request(endpoint, options = {}) {
    const url = Lab44Config.api + endpoint;
    const defaults = {
      headers: {
        'Content-Type': 'application/json'
      }
    };
    
    const config = { ...defaults, ...options };
    if (options.body && typeof options.body === 'object') {
      config.body = JSON.stringify(options.body);
    }
    
    try {
      const res = await fetch(url, config);
      const data = await res.json();
      return { ok: res.ok, status: res.status, data };
    } catch (err) {
      return { ok: false, status: 0, error: err.message };
    }
  },
  
  get(endpoint) {
    return this.request(endpoint, { method: 'GET' });
  },
  
  post(endpoint, body) {
    return this.request(endpoint, { method: 'POST', body });
  },
  
  put(endpoint, body) {
    return this.request(endpoint, { method: 'PUT', body });
  },
  
  patch(endpoint, body) {
    return this.request(endpoint, { method: 'PATCH', body });
  },
  
  delete(endpoint) {
    return this.request(endpoint, { method: 'DELETE' });
  }
};

// ── Polling Utility ────────────────────────────────────────────────────────────
class Lab44Poller {
  constructor(callback, interval = 5000) {
    this.callback = callback;
    this.interval = interval;
    this.timer = null;
    this.running = false;
  }
  
  start() {
    if (this.running) return;
    this.running = true;
    this.callback();
    this.timer = setInterval(() => this.callback(), this.interval);
  }
  
  stop() {
    if (!this.running) return;
    this.running = false;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }
  
  setCallback(callback) {
    this.callback = callback;
  }
  
  setInterval(interval) {
    this.interval = interval;
    if (this.running) {
      this.stop();
      this.start();
    }
  }
}

// Export for use in modules (if needed in future)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    Lab44Config,
    Lab44Auth,
    Lab44UI,
    Lab44Validation,
    Lab44Guac,
    Lab44API,
    Lab44Poller
  };
}
