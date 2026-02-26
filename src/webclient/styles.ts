export const WEB_CLIENT_STYLES = `
:root {
      --bg: #F3F5F8;
      --panel: #FFFFFF;
      --line: #DEE2E6;
      --text-primary: #212529;
      --text-secondary: #6C757D;
      --primary: #175DDC;
      --primary-hover: #144eb8;
      --danger: #DC3545;
      --danger-hover: #C82333;
      --danger-bg: #F8D7DA;
      --success: #198754;
      --success-bg: #D1E7DD;
      --border-color: #DEE2E6;
      --radius: 6px;
      --radius-sm: 4px;
      --shadow-sm: 0 1px 2px rgba(0,0,0,0.05);
      --shadow: 0 4px 12px rgba(0,0,0,0.08);
      --shadow-lg: 0 8px 24px rgba(0,0,0,0.12);
      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }
    * { box-sizing: border-box; }
    html, body { height: 100%; margin: 0; }
    body {
      color: var(--text-primary);
      font-family: var(--font-sans);
      background-color: var(--bg);
      -webkit-font-smoothing: antialiased;
    }
    #app { height: 100%; display: flex; flex-direction: column; }
    
    /* Auth Pages */
    .auth-page {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 20px;
      position: relative;
    }
    .lang-switch {
      position: absolute;
      top: 24px;
      right: 24px;
      cursor: pointer;
      color: var(--text-secondary);
      font-size: 14px;
      font-weight: 500;
    }
    .lang-switch:hover { color: var(--primary); }
    .auth-card {
      width: 100%;
      max-width: 420px;
      background: var(--panel);
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
      padding: 40px;
      box-shadow: var(--shadow);
    }
    .auth-header {
      text-align: center;
      margin-bottom: 32px;
    }
    .auth-logo {
      width: 48px;
      height: 48px;
      background: var(--primary);
      border-radius: 12px;
      margin: 0 auto 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: white;
      font-weight: bold;
      font-size: 24px;
    }
    .auth-logo::after { content: "NW"; }
    .auth-title {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
      margin-bottom: 8px;
    }
    .auth-subtitle {
      color: var(--text-secondary);
      font-size: 15px;
    }
    .auth-footer {
      margin-top: 24px;
      text-align: center;
      font-size: 14px;
    }
    .auth-footer a {
      color: var(--primary);
      text-decoration: none;
      font-weight: 500;
    }
    .auth-footer a:hover { text-decoration: underline; }

    /* Forms */
    .form-group { margin-bottom: 20px; }
    .form-label {
      display: block;
      margin-bottom: 8px;
      font-size: 14px;
      font-weight: 600;
      color: var(--text-primary);
    }
    .form-input {
      width: 100%;
      height: 42px;
      padding: 8px 12px;
      font-size: 15px;
      border: 1px solid var(--border-color);
      border-radius: var(--radius-sm);
      background: #fff;
      color: var(--text-primary);
      transition: border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out;
    }
    .form-input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(23, 93, 220, 0.15);
    }
    
    /* Buttons */
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      height: 42px;
      padding: 0 20px;
      font-size: 15px;
      font-weight: 600;
      border-radius: var(--radius-sm);
      border: 1px solid transparent;
      cursor: pointer;
      transition: all 0.15s ease-in-out;
    }
    .btn-primary {
      background: var(--primary);
      color: #fff;
    }
    .btn-primary:hover { background: var(--primary-hover); }
    .btn-secondary {
      background: #fff;
      border-color: var(--border-color);
      color: var(--text-primary);
    }
    .btn-secondary:hover { background: #F8F9FA; }
    .btn-danger {
      background: var(--danger);
      color: #fff;
    }
    .btn-danger:hover { background: var(--danger-hover); }
    
    /* Alerts */
    .alert {
      padding: 12px 16px;
      border-radius: var(--radius-sm);
      font-size: 14px;
      margin-bottom: 24px;
      border: 1px solid transparent;
    }
    .alert-success { background: var(--success-bg); color: var(--success); border-color: #BADBCC; }
    .alert-danger { background: var(--danger-bg); color: var(--danger); border-color: #F5C2C7; }
    
    /* App Layout */
    .navbar {
      height: 64px;
      background: var(--primary);
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 24px;
      flex-shrink: 0;
    }
    .nav-brand {
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 20px;
      font-weight: 700;
    }
    .nav-logo {
      width: 32px;
      height: 32px;
      background: #fff;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--primary);
      font-weight: bold;
      font-size: 16px;
    }
    .nav-logo::after { content: "NW"; }
    .nav-links {
      display: flex;
      gap: 8px;
    }
    .nav-link {
      color: rgba(255,255,255,0.8);
      text-decoration: none;
      padding: 8px 16px;
      border-radius: var(--radius-sm);
      font-weight: 500;
      font-size: 15px;
      transition: all 0.15s;
    }
    .nav-link:hover { color: #fff; background: rgba(255,255,255,0.1); }
    .nav-link.active { color: #fff; background: rgba(255,255,255,0.2); }
    .nav-user {
      display: flex;
      align-items: center;
    }
    .nav-user .lang-switch {
      color: rgba(255,255,255,0.8);
    }
    .nav-user .lang-switch:hover { color: #fff; }
    .nav-user .btn-secondary {
      height: 32px;
      padding: 0 12px;
      font-size: 13px;
      background: rgba(255,255,255,0.1);
      border-color: transparent;
      color: #fff;
    }
    .nav-user .btn-secondary:hover { background: rgba(255,255,255,0.2); }
    
    .app-body {
      display: flex;
      flex: 1;
      overflow: hidden;
    }
    .sidebar {
      width: 260px;
      background: #fff;
      border-right: 1px solid var(--border-color);
      display: flex;
      flex-direction: column;
      padding: 24px 16px;
      overflow-y: auto;
    }
    .sidebar-title {
      font-size: 12px;
      font-weight: 700;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 12px;
      padding: 0 12px;
    }
    .folder-btn {
      width: 100%;
      text-align: left;
      padding: 10px 12px;
      background: transparent;
      border: none;
      color: var(--text-primary);
      font-size: 14px;
      font-weight: 500;
      border-radius: var(--radius-sm);
      cursor: pointer;
      margin-bottom: 4px;
    }
    .folder-btn:hover { background: var(--bg); }
    .folder-btn.active { background: #E7F1FF; color: var(--primary); font-weight: 600; }
    
    .content {
      flex: 1;
      padding: 32px;
      overflow-y: auto;
    }
    
    /* Vault Grid */
    .vault-grid {
      display: grid;
      grid-template-columns: 350px 1fr;
      gap: 24px;
      height: calc(100vh - 180px);
    }
    .list {
      background: #fff;
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
      overflow-y: auto;
    }
    .item {
      padding: 16px;
      border-bottom: 1px solid var(--border-color);
      display: flex;
      align-items: center;
      gap: 12px;
      cursor: pointer;
    }
    .item:hover { background: var(--bg); }
    .item.active { background: #E7F1FF; }
    .item:last-child { border-bottom: none; }
    
    /* Common Components */
    .panel {
      background: #fff;
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
      padding: 24px;
      margin-bottom: 24px;
      box-shadow: var(--shadow-sm);
    }
    .panel h3 { margin: 0 0 20px 0; font-size: 18px; font-weight: 600; border-bottom: 1px solid var(--border-color); padding-bottom: 16px; }
    
    .table { width: 100%; border-collapse: collapse; font-size: 14px; }
    .table th, .table td { padding: 12px 16px; border-bottom: 1px solid var(--border-color); text-align: left; }
    .table th { font-weight: 600; color: var(--text-secondary); background: var(--bg); }
    
    .badge {
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 600;
      background: var(--bg);
      color: var(--text-secondary);
    }
    .badge.success { background: var(--success-bg); color: var(--success); }
    .badge.danger { background: var(--danger-bg); color: var(--danger); }
    
    .kv { margin-bottom: 12px; font-size: 14px; line-height: 1.5; display: flex; }
    .kv b { color: var(--text-secondary); font-weight: 600; width: 120px; flex-shrink: 0; }
    
    .totp-mask {
      position: fixed;
      inset: 0;
      background: rgba(0,0,0,0.5);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
    }
    .totp-box {
      width: 100%;
      max-width: 400px;
      background: #fff;
      border-radius: var(--radius);
      padding: 32px;
      box-shadow: var(--shadow-lg);
    }

`;

