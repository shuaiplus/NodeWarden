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
      width: min(1520px, calc(100vw - 40px));
      margin: 14px auto 16px;
      border: 1px solid var(--border-color);
      border-radius: 12px;
      background: #fff;
      box-shadow: var(--shadow);
      height: calc(100vh - 64px - 30px);
    }
    .sidebar {
      width: 300px;
      background: #fff;
      border-right: 1px solid var(--border-color);
      padding: 14px;
      overflow-y: auto;
    }
    .sidebar-block {
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
      padding: 10px;
      background: #fff;
      margin-bottom: 12px;
    }
    .sidebar-title {
      font-size: 12px;
      font-weight: 700;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 8px;
    }
    .search-input {
      width: 100%;
      height: 38px;
      border: 1px solid #2f6fec;
      border-radius: 9px;
      padding: 0 12px;
      font-size: 15px;
      outline: none;
    }
    .tree-btn {
      width: 100%;
      text-align: left;
      padding: 8px 10px;
      background: transparent;
      border: none;
      color: var(--text-primary);
      font-size: 14px;
      font-weight: 500;
      border-radius: var(--radius-sm);
      cursor: pointer;
      margin-bottom: 2px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .tree-btn:hover { background: var(--bg); }
    .tree-btn.active { color: var(--primary); font-weight: 700; background: #eef4ff; }
    
    .content {
      flex: 1;
      padding: 16px 18px;
      overflow-y: auto;
      background: #F8FAFC;
    }
    
    /* Vault Grid */
    .vault-grid {
      display: grid;
      grid-template-columns: minmax(380px, 44%) 1fr;
      gap: 16px;
      height: calc(100vh - 145px);
    }
    .vault-list-col { min-width: 0; display:flex; flex-direction:column; }
    .vault-list-head {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 8px;
      justify-content: flex-start;
      align-items: center;
    }
    .vault-list {
      background: #fff;
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
      overflow-y: auto;
      flex: 1;
    }
    .vault-item {
      padding: 13px 14px;
      border-bottom: 1px solid var(--border-color);
      display: flex;
      align-items: center;
      gap: 10px;
      cursor: pointer;
      background: #fff;
    }
    .vault-item:hover { background: #f6f9ff; }
    .vault-item.active { background: #ecf3ff; }
    .vault-item:last-child { border-bottom: none; }
    .vault-item-check { width:18px; height:18px; }
    .vault-item-main { display:flex; align-items:center; gap:12px; min-width:0; }
    .vault-item-icon {
      width: 24px;
      height: 24px;
      border-radius: 5px;
      object-fit: contain;
      flex-shrink: 0;
      border: 1px solid #d9dfe8;
      background: #fff;
    }
    .vault-item-icon-wrap { width:24px; height:24px; position:relative; flex-shrink:0; display:inline-flex; align-items:center; justify-content:center; }
    .vault-item-icon-fallback {
      display:inline-flex;
      align-items:center;
      justify-content:center;
      font-size: 24px;
      color: #6b7a90;
      border: none;
      background: transparent;
    }
    .vault-item-text { min-width:0; }
    .vault-item-title {
      color: #1457d6;
      font-size: 16px;
      font-weight: 700;
      line-height: 1.1;
      white-space: nowrap;
      text-overflow: ellipsis;
      overflow: hidden;
    }
    .vault-item-sub {
      color: #64748b;
      font-size: 13px;
      margin-top: 4px;
      white-space: nowrap;
      text-overflow: ellipsis;
      overflow: hidden;
    }
    .vault-detail {
      overflow-y: auto;
      padding-right: 2px;
    }
    .card {
      background: #fff;
      border: 1px solid var(--border-color);
      border-radius: 14px;
      padding: 16px 18px;
      margin-bottom: 14px;
      box-shadow: var(--shadow-sm);
    }
    .vault-detail-head .vault-detail-title { font-size: 24px; font-weight: 700; margin-bottom: 8px; }
    .vault-detail-folder { color: #334155; font-size: 14px; }
    .card-title {
      font-size: 15px;
      font-weight: 700;
      color: #334155;
      margin-bottom: 10px;
    }
    .field-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
      padding: 10px 0;
      border-bottom: 1px solid #e8edf4;
    }
    .field-row:last-child { border-bottom: none; }
    .field-label { color: #64748b; font-size: 13px; margin-bottom: 3px; }
    .field-value { color: #0f172a; font-size: 17px; word-break: break-all; }
    .field-sub { color: #64748b; font-size: 12px; margin-top: 2px; }
    .icon-btn {
      border: 1px solid var(--border-color);
      background: #fff;
      border-radius: 8px;
      height: 30px;
      padding: 0 10px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      margin-left: 6px;
    }
    .icon-btn:hover { background: #f8fafc; }
    .link-btn {
      border: none;
      background: transparent;
      color: #1457d6;
      font-weight: 700;
      font-size: 16px;
      cursor: pointer;
      padding: 2px 0;
    }
    .link-btn:hover { text-decoration: underline; }
    .create-menu-wrap { position: relative; }
    .create-menu {
      position: absolute;
      top: calc(100% + 4px);
      left: 0;
      min-width: 180px;
      background: #fff;
      border: 1px solid var(--border-color);
      border-radius: 10px;
      box-shadow: var(--shadow);
      z-index: 30;
      padding: 6px;
    }
    .create-menu-item {
      width: 100%;
      text-align: left;
      border: none;
      background: transparent;
      padding: 8px 10px;
      border-radius: 8px;
      font-size: 15px;
      cursor: pointer;
    }
    .create-menu-item:hover { background: #eff5ff; }
    .field-modal { max-width: 560px; }
    .field-modal-head { display:flex; justify-content:space-between; align-items:center; margin-bottom: 8px; }
    .field-modal-head h3 { margin: 0; }
    .history-line { color: #64748b; font-size: 13px; line-height: 1.8; }
    .detail-input {
      width: 100%;
      min-height: 36px;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 7px 10px;
      font-size: 14px;
      background: #fff;
      color: #0f172a;
    }
    .detail-input:focus { outline: none; border-color: #2f6fec; box-shadow: 0 0 0 3px rgba(47,111,236,0.12); }
    .detail-textarea { min-height: 100px; resize: vertical; }
    .detail-actions {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 8px;
      gap: 8px;
    }
    .detail-actions .btn { margin-right: 8px; }
    .detail-actions .btn:last-child { margin-right: 0; }
    .vault-empty {
      min-height: 120px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--text-secondary);
      padding: 20px;
      text-align: center;
      background: #fff;
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
    }
    
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
    @media (max-width: 980px) {
      .app-body {
        width: calc(100vw - 16px);
        margin: 8px auto;
        border-radius: 10px;
      }
      .sidebar { width: 280px; }
    }
    @media (max-width: 760px) {
      .app-body {
        width: 100%;
        margin: 0;
        border: none;
        border-radius: 0;
        box-shadow: none;
        height: calc(100vh - 64px);
      }
      .sidebar {
        width: 100%;
        border-right: none;
        border-bottom: 1px solid var(--border-color);
      }
      .vault-grid { grid-template-columns: 1fr; }
    }

`;

