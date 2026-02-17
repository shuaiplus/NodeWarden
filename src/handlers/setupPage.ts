import { Env } from '../types';
import { StorageService } from '../services/storage';
import { htmlResponse } from '../utils/response';

type JwtSecretState = 'missing' | 'default' | 'too_short';

function renderRegisterPageHTML(jwtState: JwtSecretState | null): string {
  const jwtStateJson = JSON.stringify(jwtState);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NodeWarden</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f3f4f6;
      --card: #ffffff;
      --border: #d0d5dd;
      --text: #101828;
      --muted: #475467;
      --muted2: #667085;
      --danger: #b42318;
      --ok: #027a48;
      --shadow: 0 16px 44px rgba(16, 24, 40, 0.08);
      --radius: 20px;
      --radius2: 16px;
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    }
    * { box-sizing: border-box; }
    html, body { height: 100%; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 40px 24px;
    }

    .shell { width: min(900px, 100%); }

    .panel {
      padding: 40px;
      border: 1px solid var(--border);
      background: var(--card);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      display: flex;
      flex-direction: column;
      position: relative;
    }

    .lang-toggle {
      position: absolute;
      top: 14px;
      right: 14px;
      height: 32px;
      min-width: 62px;
      padding: 0 10px;
      border-radius: 10px;
      border: 1px solid #d5dae1;
      background: #ffffff;
      color: #111418;
      font-size: 13px;
      font-weight: 700;
      line-height: 1;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
    }
    .lang-toggle:hover { background: #f8fafc; }

    .top {
      display: flex;
      gap: 14px;
      align-items: center;
      margin-bottom: 14px;
    }

    .mark {
      width: 60px;
      height: 60px;
      border-radius: 16px;
      background: #111418;
      border: 1px solid #111418;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 24px;
      font-weight: 800;
      letter-spacing: 0.6px;
      line-height: 1;
      color: #ffffff;
      text-transform: uppercase;
      user-select: none;
    }

    .title { display: flex; flex-direction: column; gap: 4px; }
    .title h1 { font-size: 30px; margin: 0; letter-spacing: -0.6px; }
    .title p { margin: 0; color: var(--muted); font-size: 15px; line-height: 1.6; }

    h2 { font-size: 22px; margin: 10px 0 14px 0; letter-spacing: -0.3px; }
    h3 { font-size: 17px; margin: 0 0 10px 0; color: #1d2939; }
    .lead { margin: 0; color: #344054; font-size: 16px; line-height: 1.75; }

    .step-container {
      position: relative;
      height: 442px;
      overflow: hidden;
    }
    .step {
      position: absolute;
      inset: 0;
      opacity: 0;
      transform: translateX(10px);
      pointer-events: none;
      transition: opacity 170ms ease, transform 170ms ease;
      overflow-y: auto;
      padding-right: 4px;
    }
    .step.active {
      opacity: 1;
      transform: translateX(0);
      pointer-events: auto;
    }

    .message {
      display: none;
      border-radius: 12px;
      padding: 14px;
      margin: 0 0 12px 0;
      font-size: 15px;
      line-height: 1.45;
      border: 1px solid var(--border);
      background: #fafbfc;
    }
    .message.error {
      display: block;
      border-color: #fecdca;
      background: #fff6f5;
      color: var(--danger);
    }
    .message.success {
      display: block;
      border-color: #abefc6;
      background: #f0fdf4;
      color: var(--ok);
    }

    .kv {
      border-radius: var(--radius2);
      border: 1px solid var(--border);
      background: #fafbfc;
      padding: 18px;
      margin-bottom: 14px;
    }
    .kv p { margin: 0; font-size: 15px; line-height: 1.65; color: var(--muted); }
    .kv ul, .kv ol { margin: 8px 0 0 18px; padding: 0; color: var(--muted); line-height: 1.7; }

    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
    @media (max-width: 760px) { .grid { grid-template-columns: 1fr; } }

    .field { display: flex; flex-direction: column; gap: 7px; }
    label { font-size: 14px; color: var(--muted); letter-spacing: 0.1px; }
    input {
      height: 50px;
      padding: 0 14px;
      border-radius: 14px;
      border: 1px solid #d5dae1;
      background: #ffffff;
      color: var(--text);
      outline: none;
      font-size: 16px;
      transition: border-color 160ms ease, box-shadow 160ms ease;
    }
    input::placeholder { color: #98a2b3; }
    input:focus {
      border-color: #111418;
      box-shadow: 0 0 0 5px rgba(17, 20, 24, 0.08);
    }

    .hint { margin: 0; color: var(--muted2); font-size: 14px; line-height: 1.6; }
    .muted { color: var(--muted); }

    .compat-wrap {
      margin-top: 12px;
      border: 1px solid var(--border);
      border-radius: 12px;
      background: #ffffff;
      padding: 10px 12px;
    }
    .compat-title {
      margin: 0 0 8px 0;
      font-size: 13px;
      font-weight: 700;
      color: #344054;
      letter-spacing: 0.1px;
    }
    .compat-grid {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }
    .compat-chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      height: 30px;
      padding: 0 10px;
      border-radius: 999px;
      border: 1px solid #d5dae1;
      background: #f8fafc;
      font-size: 13px;
      color: #1d2939;
      line-height: 1;
      white-space: nowrap;
    }
    .compat-chip.ok {
      border-color: #abefc6;
      background: #f0fdf4;
      color: #027a48;
    }
    .compat-chip.na {
      border-color: #e4e7ec;
      background: #f9fafb;
      color: #667085;
    }
    .compat-dot {
      width: 8px;
      height: 8px;
      border-radius: 999px;
      background: currentColor;
      opacity: 0.9;
    }

    .btn {
      height: 46px;
      padding: 0 16px;
      border-radius: 14px;
      border: 1px solid #d5dae1;
      background: #ffffff;
      color: #111418;
      font-weight: 700;
      font-size: 15px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      text-align: center;
      cursor: pointer;
      white-space: nowrap;
    }
    .btn.primary {
      border-color: #111418;
      background: #111418;
      color: #ffffff;
    }
    .btn:disabled { opacity: 0.55; cursor: not-allowed; }

    .mode-tabs { display: inline-flex; border: 1px solid #d5dae1; border-radius: 12px; overflow: hidden; }
    .mode-tab {
      border: none;
      background: #fff;
      color: #111418;
      padding: 9px 12px;
      cursor: pointer;
      font-weight: 700;
      font-size: 14px;
    }
    .mode-tab.active { background: #111418; color: #fff; }

    .mode-panel { display: none; margin-top: 12px; }
    .mode-panel.active { display: block; }

    .server {
      margin-top: 10px;
      font-family: var(--mono);
      font-size: 14px;
      padding: 12px 14px;
      border-radius: 14px;
      background: #ffffff;
      border: 1px solid #d5dae1;
      word-break: break-all;
      color: #111418;
    }

    .var-chip-wrap {
      display: inline-flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-left: 6px;
      vertical-align: middle;
    }
    .var-chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 8px;
      border: 1px solid #d5dae1;
      border-radius: 999px;
      background: #ffffff;
      line-height: 1;
    }
    .var-chip code {
      font-family: var(--mono);
      font-size: 12px;
      color: #111418;
    }
    .icon-copy-btn {
      width: 22px;
      height: 22px;
      border-radius: 6px;
      border: 1px solid #d5dae1;
      background: #fff;
      color: #344054;
      font-size: 12px;
      line-height: 1;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      padding: 0;
    }
    .icon-copy-btn:hover { background: #f8fafc; }

    .flow-bottom {
      margin-top: 14px;
      padding: 0 8px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }
    .flow-actions { display: flex; align-items: center; gap: 8px; width: 132px; }
    .flow-actions .btn { width: 120px; padding: 0; }

    .dots {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      min-height: 26px;
    }
    .dot {
      width: 9px;
      height: 9px;
      border-radius: 999px;
      background: #cfd5de;
      transition: all 120ms ease;
    }
    .dot.active {
      width: 24px;
      height: 10px;
      border-radius: 999px;
      background: #111418;
    }

    a { color: #175cd3; text-decoration: none; }
    a:hover { text-decoration: underline; }

    .footer {
      margin-top: 15px;
      padding-top: 10px;
      border-top: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
      font-size: 14px;
      color: var(--muted2);
    }

    .modal-mask {
      position: fixed;
      inset: 0;
      background: rgba(16, 24, 40, 0.45);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 9999;
      padding: 20px;
    }
    .modal-mask.show { display: flex; }
    .modal {
      width: min(520px, 100%);
      border-radius: 16px;
      border: 1px solid var(--border);
      background: #ffffff;
      box-shadow: 0 24px 56px rgba(16, 24, 40, 0.18);
      padding: 20px;
    }
    .modal h3 {
      margin: 0 0 8px 0;
      font-size: 18px;
      color: #101828;
    }
    .modal p {
      margin: 0;
      font-size: 15px;
      line-height: 1.7;
      color: #475467;
    }
    .modal-warn {
      margin-top: 10px;
      border: 1px solid #fecdca;
      background: #fff6f5;
      color: #b42318;
      border-radius: 12px;
      padding: 10px 12px;
      font-size: 14px;
      line-height: 1.6;
    }
    .modal-actions {
      margin-top: 16px;
      display: flex;
      justify-content: flex-end;
      gap: 8px;
    }
  </style>
</head>
<body>
  <div class="shell">
    <aside class="panel">
      <button id="langToggle" class="lang-toggle" type="button" onclick="toggleLanguage()">EN</button>

      <div class="top">
        <div class="mark" aria-label="NodeWarden">NW</div>
        <div class="title">
          <h1 id="t_app">NodeWarden</h1>
          <p id="t_tag">Minimal Bitwarden-compatible server on Cloudflare Workers.</p>
        </div>
      </div>

      <div id="message" class="message"></div>

      <div class="step-container">
      <section id="step1" class="step active">
        <h2 id="t_s1_title">Welcome</h2>
        <p class="lead" id="t_s1_desc"></p>
        <div class="kv" style="margin-top:14px;">
          <h3 id="t_s1_adv_title">Why NodeWarden</h3>
          <ul>
            <li id="t_s1_adv_1"></li>
            <li id="t_s1_adv_2"></li>
            <li id="t_s1_adv_3"></li>
          </ul>
        </div>

        <div class="kv">
          <h3 id="t_s1_compat_title"></h3>
          <div class="compat-grid">
            <span class="compat-chip ok"><span class="compat-dot"></span><span id="t_s1_compat_win"></span></span>
            <span class="compat-chip ok"><span class="compat-dot"></span><span id="t_s1_compat_android"></span></span>
            <span class="compat-chip ok"><span class="compat-dot"></span><span id="t_s1_compat_ios"></span></span>
            <span class="compat-chip ok"><span class="compat-dot"></span><span id="t_s1_compat_ext"></span></span>
            <span class="compat-chip na"><span class="compat-dot"></span><span id="t_s1_compat_other"></span></span>
          </div>
        </div>
      </section>

      <section id="step2" class="step">
        <h2 id="t_s2_title">JWT secret check</h2>

        <div style="margin-top:14px;display:flex;flex-direction:column;gap:14px;">
          <div class="kv">
            <h3 id="t_s2_fix_title">Fix steps</h3>
            <div id="t_s2_fix_text"></div>

            <div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border);">
            <h3 id="t_s2_gen_title">Random JWT_SECRET</h3>
            <div class="server" id="secret"></div>
            <div style="height:10px"></div>
            <div style="display:flex; gap:8px; flex-wrap:wrap;">
              <button class="btn primary" type="button" id="refreshSecretBtn" onclick="refreshSecret()">Refresh</button>
              <button class="btn" type="button" id="copySecretBtn" onclick="copySecret()">Copy</button>
            </div>
            </div>
          </div>
        </div>
      </section>

      <section id="step3" class="step">
        <h2 id="t_s3_title">Sync setup</h2>
        <p class="lead" id="t_s3_desc"></p>

        <div class="kv" style="margin-top:14px;">
          <h3 id="t_s3_common_title">Common required steps</h3>
          <ol>
            <li id="t_s3_common_1"></li>
            <li id="t_s3_common_2"></li>
            <li id="t_s3_common_3"></li>
          </ol>
        </div>

        <div class="kv">
          <div class="mode-tabs">
            <button class="mode-tab active" id="manualTab" onclick="setSyncMode('manual')">Manual sync</button>
            <button class="mode-tab" id="autoTab" onclick="setSyncMode('auto')">Auto sync</button>
          </div>

          <div id="manualPanel" class="mode-panel active">
            <p id="t_s3_manual_text"></p>
            <ol>
              <li id="t_s3_manual_step1"></li>
              <li id="t_s3_manual_step2"></li>
            </ol>
          </div>

          <div id="autoPanel" class="mode-panel">
            <p id="t_s3_auto_text"></p>
            <ol>
              <li id="t_s3_auto_step1"></li>
              <li id="t_s3_auto_step2"></li>
              <li id="t_s3_auto_step3"></li>
            </ol>
          </div>
        </div>
      </section>

      <section id="step4" class="step">
        <h2 id="t_s4_title">Backup strategy</h2>
        <p class="lead" id="t_s4_desc"></p>

        <div class="kv" style="margin-top:14px;">
          <h3 id="t_s4_how_title">How to enable</h3>
          <ol>
            <li id="t_s4_how_1"></li>
            <li id="t_s4_how_2"></li>
            <li id="t_s4_how_3"></li>
            <li id="t_s4_how_4"></li>
          </ol>
        </div>
      </section>

      <section id="step5" class="step">
        <h2 id="t_s5_title">Final step</h2>
        <p class="lead" id="t_s5_desc"></p>

        <div id="setup-form">
          <form id="form" onsubmit="handleSubmit(event)">
            <div class="grid">
              <div class="field">
                <label for="name" id="t_name_label">Name</label>
                <input type="text" id="name" name="name" required placeholder="Your name">
              </div>
              <div class="field">
                <label for="email" id="t_email_label">Email</label>
                <input type="email" id="email" name="email" required placeholder="you@example.com" autocomplete="email">
              </div>
            </div>

            <div style="height: 10px"></div>
            <div class="field">
              <label for="password" id="t_pw_label">Master password</label>
              <input type="password" id="password" name="password" required minlength="12" placeholder="At least 12 characters" autocomplete="new-password">
              <p class="hint" id="t_pw_hint">Choose a strong password you can remember. The server cannot recover it.</p>
            </div>

            <div style="height: 10px"></div>
            <div class="field">
              <label for="confirmPassword" id="t_pw2_label">Confirm password</label>
              <input type="password" id="confirmPassword" name="confirmPassword" required placeholder="Confirm password" autocomplete="new-password">
            </div>

            <div style="height:12px"></div>
            <button type="submit" id="submitBtn" class="btn primary" style="width:100%;height:52px;">Create account</button>
          </form>
        </div>

        <div id="registered-view" style="display:none;">
          <div class="kv">
            <h3 id="t_done_title">Setup complete</h3>
            <p id="t_done_desc">Your server is ready. Configure your Bitwarden client with this server URL:</p>
            <div class="server" id="serverUrl"></div>
          </div>
          <div class="kv">
            <h3 id="t_hide_title">Hide setup page</h3>
            <p id="t_hide_desc"></p>
            <div style="margin-top:10px;">
              <button type="button" id="hideBtn" class="btn primary" onclick="openHideConfirmModal()">Hide setup page</button>
            </div>
          </div>
        </div>
      </section>
      </div>

      <div class="footer">
        <div><span class="muted" id="t_by">By</span> <a href="https://shuai.plus" target="_blank" rel="noreferrer">shuaiplus</a></div>
        <div><a href="https://github.com/shuaiplus/nodewarden" target="_blank" rel="noreferrer">GitHub</a></div>
      </div>
    </aside>

    <div class="flow-bottom">
      <div class="flow-actions">
        <button id="prevBtn" class="btn" type="button">Previous</button>
      </div>
      <div class="dots" id="dots">
        <span class="dot active" data-step="1"></span>
        <span class="dot" data-step="2"></span>
        <span class="dot" data-step="3"></span>
        <span class="dot" data-step="4"></span>
        <span class="dot" data-step="5"></span>
      </div>
      <div class="flow-actions" style="justify-content:flex-end;">
        <button id="nextBtn" class="btn primary" type="button">Next</button>
      </div>
    </div>
  </div>

  <div id="hideModal" class="modal-mask" role="dialog" aria-modal="true" aria-labelledby="hideModalTitle" aria-describedby="hideModalDesc">
    <div class="modal">
      <h3 id="hideModalTitle"></h3>
      <p id="hideModalDesc"></p>
      <div class="modal-warn" id="hideModalWarn"></div>
      <div class="modal-actions">
        <button id="hideModalCancel" class="btn" type="button" onclick="closeHideConfirmModal()"></button>
        <button id="hideModalConfirm" class="btn primary" type="button" onclick="disableSetupPage()"></button>
      </div>
    </div>
  </div>

  <script>
    const JWT_STATE = ${jwtStateJson};

    let isRegistered = false;
    let currentStep = 1;
    let currentLang = ((navigator.language || '').toLowerCase().startsWith('zh')) ? 'zh' : 'en';

    function isChinese() {
      return currentLang === 'zh';
    }

    function toggleLanguage() {
      currentLang = isChinese() ? 'en' : 'zh';
      applyI18n();
    }

    function t(key) {
      const zh = {
        app: 'NodeWarden',
        tag: '部署在 Cloudflare Workers 上的最小 Bitwarden 兼容服务。',
        by: '作者',

        s1Title: '欢迎使用 NodeWarden',
        s1Desc: '无需自建 VPS 的 Bitwarden 兼容服务：部署简单、维护成本低、可直接连接官方客户端。点击下一步开始检查。',
        s1AdvTitle: '为什么选择 NodeWarden',
        s1Adv1: '无需 VPS，直接运行在 Cloudflare Workers',
        s1Adv2: '兼容 Bitwarden 官方客户端（桌面端 / 移动端 / 浏览器扩展）',
        s1Adv3: '面向单用户场景，稳定且易维护',
        s1CompatTitle: '兼容性',
        s1CompatWin: 'Windows 客户端',
        s1CompatAndroid: 'Android 客户端',
        s1CompatIos: 'iOS 客户端',
        s1CompatExt: '浏览器扩展',
        s1CompatOther: '其他：未测试',

        s2Title: '环境检查：JWT_SECRET',
        s2DescGood: 'JWT_SECRET 检查通过。',
        s2DescMissing: '检测到 JWT_SECRET 未配置，请先配置后继续。',
        s2DescDefault: '检测到 JWT_SECRET 为默认值，请先替换后继续。',
        s2DescShort: '检测到 JWT_SECRET 长度小于 32，请先替换后继续。',
        s2FixTitle: '处理步骤（新增 / 替换）',
        s2FixAddTitle: '当前为“未配置”，请新增：',
        s2FixReplaceTitle: '当前为“默认值或长度不足”，请替换：',
        s2FixStep1: '进入 Cloudflare 控制台 -> Workers 和 Pages -> 你的 nodewarden 服务。',
        s2FixStep2Add: '打开 设置 -> 变量和机密，新增 JWT_SECRET（类型选择 Secret）。',
        s2FixStep2Replace: '打开 设置 -> 变量和机密，找到 JWT_SECRET 并修改为新值。',
        s2FixStep3: '保存并等待重新部署完成。',
        s2FixStep4: '设置完成后返回本页，刷新页面继续。',
        s2FixStep5: '如需新密钥，可在下方生成并复制到 JWT_SECRET。',
        s2GenTitle: '随机密钥生成器',
        refresh: '刷新',
        copy: '复制',
        copied: '已复制',

        s3Title: '同步策略（可跳过）',
        s3CommonTitle: '通用前置步骤',
        s3Common1: '如果还未 fork，请先将本项目 fork 到你自己的 GitHub。',
        s3Common2: 'Cloudflare 控制台 -> Workers 和 Pages -> 你的服务 -> 设置 -> 构建和部署 -> 源代码，解绑当前仓库。',
        s3Common3: '在同一位置重新绑定你的 fork 仓库。',
        manualSync: '手动同步',
        autoSync: '自动同步',
        s3ManualText: '手动同步：在 GitHub 网页端一键完成。',
        s3ManualStep1: '打开你的 fork 仓库主页，看到可同步提示时点击 Sync fork。',
        s3ManualStep2: '点击 Update branch 完成同步。',
        s3AutoText: '自动同步：fork 已包含工作流文件，你只需要开启 Actions。',
        s3AutoStep1: '进入你的 fork 仓库 -> Actions。',
        s3AutoStep2: '点击 I understand my workflows, go ahead and enable them。',
        s3AutoStep3: '默认每天凌晨 3 点自动同步，也可手动点击 Run workflow。',
        s4BackupTitle: '备份策略（推荐）',
        s4BackupDesc: '开启后会将明文 JSON 和附件导出到加密压缩包并保存到 R2。',
        s4HowTitle: '如何开启',
        s4How1: 'Cloudflare 控制台 -> Workers 和 Pages -> NodeWarden -> 设置 -> 变量和机密。',
        s4How2: '新增密钥：',
        s4How2Hint: '（该值是备份压缩包的解压密码，建议使用强密码）',
        s4How3: '可选变量：',
        s4How4: '完成变量设置后，在当前 Worker 的「触发事件」中点击「添加 Cron 触发器」，再按你的备份频率设置执行周期。',
        s5Title: '最终：创建账号',
        s5Desc: '填写信息并创建你的唯一账号，完成初始化。',
        nameLabel: '名称',
        emailLabel: '邮箱',
        pwLabel: '主密码',
        pwHint: '请选择你能记住的强密码。服务器无法帮你找回主密码。',
        pw2Label: '确认主密码',
        create: '创建账号',
        creating: '正在创建…',
        doneTitle: '初始化完成',
        doneDesc: '服务已就绪。请在 Bitwarden 客户端中填写以下服务器地址：',
        important: '重要提示',
        limitations: '本项目仅支持单用户：不能添加新用户，也不支持修改主密码；若忘记主密码，只能重新部署并重新注册。',
        hideTitle: '隐藏初始化页面',
        hideDesc: '隐藏后，初始化页面会对所有人返回 404。你的密码库仍可正常使用。',
        hideBtn: '隐藏初始化页面',
        hideWorking: '正在隐藏…',
        hideDone: '已隐藏，此页面将返回 404。',
        hideFailed: '隐藏失败',
        hideConfirm: '确认隐藏初始化页面？隐藏后页面将不可访问，但密码库不受影响。',
        hideModalTitle: '确认隐藏初始化页面',
        hideModalDesc: '隐藏后，初始化页面将被永久关闭（返回 404）。你的密码库可继续使用。',
        hideModalWarn: '此操作不可恢复。若要重新进入初始化流程，只能重新部署。',
        cancel: '取消',
        confirmHide: '确认隐藏',

        prev: '上一步',
        next: '下一步',
        done: '完成',
        keyWaitRefresh: '设置后请刷新',

        errPwNotMatch: '两次输入的密码不一致',
        errPwTooShort: '密码长度至少 12 位',
        errGeneric: '发生错误：',
        errRegisterFailed: '注册失败',
      };

      const en = {
        app: 'NodeWarden',
        tag: 'Minimal Bitwarden-compatible server on Cloudflare Workers.',
        by: 'By',

        s1Title: 'NodeWarden deployed successfully',
        s1Desc: 'A Bitwarden-compatible server without managing your own VPS: simple deployment, low maintenance, and official client compatibility. Click Next to start checks.',
        s1AdvTitle: 'Highlights',
        s1Adv1: 'No VPS required, runs on Cloudflare Workers',
        s1Adv2: 'Works with official Bitwarden clients',
        s1Adv3: 'Simple and stable for single-user setup',
        s1CompatTitle: 'Fully compatible',
        s1CompatWin: 'Windows client',
        s1CompatAndroid: 'Android client',
        s1CompatIos: 'iOS client',
        s1CompatExt: 'Browser extension',
        s1CompatOther: 'Others: not tested',

        s2Title: 'Environment check: JWT_SECRET',
        s2DescGood: 'JWT_SECRET check passed.',
        s2DescMissing: 'JWT_SECRET is missing. Add it before continuing.',
        s2DescDefault: 'JWT_SECRET is default/sample. Replace it before continuing.',
        s2DescShort: 'JWT_SECRET is shorter than 32 chars. Replace it before continuing.',
        s2FixTitle: 'Fix steps (add / replace)',
        s2FixAddTitle: 'Current state is "missing", add it:',
        s2FixReplaceTitle: 'Current state is "default or too short", replace it:',
        s2FixStep1: 'Open Cloudflare Dashboard -> Workers & Pages -> your nodewarden service.',
        s2FixStep2Add: 'Go to Settings -> Variables and Secrets, add JWT_SECRET (Secret type).',
        s2FixStep2Replace: 'Go to Settings -> Variables and Secrets, edit JWT_SECRET with a new value.',
        s2FixStep3: 'Save and wait for redeploy to complete.',
        s2FixStep4: 'After setting it, come back and refresh this page to continue.',
        s2FixStep5: 'If needed, generate a new secret in the section below, then copy and paste it into JWT_SECRET.',
        s2GenTitle: 'Random secret generator',
        refresh: 'Refresh',
        copy: 'Copy',
        copied: 'Copied',

        s3Title: 'Sync strategy (optional)',
        s3CommonTitle: 'Common prerequisites',
        s3Common1: 'If you have not forked yet, fork this project to your own GitHub first.',
        s3Common2: 'Cloudflare Dashboard -> Workers & Pages -> NodeWarden -> Settings -> Builds and deployments -> Source code, unbind the current one-click-deploy repo.',
        s3Common3: 'In the same place, bind your own fork repository.',
        manualSync: 'Manual sync',
        autoSync: 'Auto sync',
        s3ManualText: 'Manual sync: one click in GitHub web UI.',
        s3ManualStep1: 'Open your fork repo home page. When you see update hint like "This branch is behind", click "Sync fork".',
        s3ManualStep2: 'Click "Update branch" to finish sync.',
        s3AutoText: 'Auto sync: your fork already includes the workflow file; you only need to enable Actions.',
        s3AutoStep1: 'Go to your fork repository -> Actions.',
        s3AutoStep2: 'Click "I understand my workflows, go ahead and enable them".',
        s3AutoStep3: 'It runs daily at 03:00 by default; you can also click "Run workflow".',
        s4BackupTitle: 'Backup strategy (recommended)',
        s4BackupDesc: 'Backups export plaintext JSON and attachments into an encrypted archive stored in R2.',
        s4HowTitle: 'How to enable',
        s4How1: 'Cloudflare Dashboard -> Workers & Pages -> NodeWarden -> Settings -> Variables and Secrets.',
        s4How2: 'Add Secret:',
        s4How2Hint: '(this value is the extraction password for backup archives; use a strong password)',
        s4How3: 'Optional vars:',
        s4How4: 'After finishing variables, open Triggers in the same Worker settings, click Add Cron Trigger, then set a schedule that matches your backup cadence.',

        s5Title: 'Final: create account',
        s5Desc: 'Create your single user account to finish setup.',
        nameLabel: 'Name',
        emailLabel: 'Email',
        pwLabel: 'Master password',
        pwHint: 'Choose a strong password you can remember. The server cannot recover it.',
        pw2Label: 'Confirm password',
        create: 'Create account',
        creating: 'Creating…',
        doneTitle: 'Setup complete',
        doneDesc: 'Your server is ready. Use this URL in Bitwarden clients:',
        important: 'Important',
        limitations: 'Single user only: no additional users, no master password change. If forgotten, redeploy and register again.',
        hideTitle: 'Hide setup page',
        hideDesc: 'After hiding, this page returns 404 for everyone. Vault still works.',
        hideBtn: 'Hide setup page',
        hideWorking: 'Hiding…',
        hideDone: 'Hidden. This page will now return 404.',
        hideFailed: 'Failed to hide setup page',
        hideConfirm: 'Hide setup page? It will no longer be accessible, but vault keeps working.',
        hideModalTitle: 'Confirm hide setup page',
        hideModalDesc: 'After hiding, this setup page is permanently closed (returns 404). Your vault keeps working.',
        hideModalWarn: 'This action cannot be undone. Re-entering setup requires redeploy.',
        cancel: 'Cancel',
        confirmHide: 'Confirm hide',

        prev: 'Previous',
        next: 'Next',
        done: 'Done',
        keyWaitRefresh: 'After setting it, refresh this page',

        errPwNotMatch: 'Passwords do not match',
        errPwTooShort: 'Password must be at least 12 characters',
        errGeneric: 'An error occurred: ',
        errRegisterFailed: 'Registration failed',
      };

      if (isChinese()) return zh[key] || en[key] || key;
      return en[key] || zh[key] || key;
    }

    function setText(id, value) {
      const el = document.getElementById(id);
      if (el) el.textContent = value;
    }

    function renderBackupSecretChip() {
      const el = document.getElementById('t_s4_how_2');
      if (!el) return;
      const value = 'BACKUP_PASSWORD';
      const chip = '<span class="var-chip"><code>' + value + '</code>'
        + '<button type="button" class="icon-copy-btn" data-copy="' + value + '" onclick="copyBackupPreset(this)" aria-label="' + t('copy') + '" title="' + t('copy') + '">⧉</button></span>';
      el.innerHTML = t('s4How2') + '<span class="var-chip-wrap">' + chip + '</span> ' + t('s4How2Hint');
    }

    function renderBackupVarChips() {
      const el = document.getElementById('t_s4_how_3');
      if (!el) return;
      const vars = [
        'BACKUP_ENABLED=true',
        'BACKUP_KEEP_LAST=30',
        'BACKUP_R2_PREFIX=backups/',
        'BACKUP_INCLUDE_ATTACHMENTS=true'
      ];
      const chips = vars.map((value) =>
        '<span class="var-chip"><code>' + value + '</code>'
        + '<button type="button" class="icon-copy-btn" data-copy="' + value + '" onclick="copyBackupPreset(this)" aria-label="' + t('copy') + '" title="' + t('copy') + '">⧉</button></span>'
      ).join('');
      el.innerHTML = t('s4How3') + '<span class="var-chip-wrap">' + chips + '</span>';
    }

    function renderJwtFixSteps() {
      const el = document.getElementById('t_s2_fix_text');
      if (!el) return;
      if (!JWT_STATE) {
        el.innerHTML = isChinese()
          ? '<ol><li>你可以直接继续下一步，不影响使用。</li><li>如果当前密钥不是强随机值，建议复制下方生成器生成的 64 位密钥。</li><li>前往 Cloudflare 控制台 -> Workers 和 Pages -> 你的服务 -> 设置 -> 变量和机密，更新 JWT_SECRET。</li><li>保存并等待重新部署完成，然后刷新本页确认。</li></ol>'
          : '<ol><li>You can continue directly.</li><li>If your current secret is not a strong random one, copy a 64-char secret from the generator below.</li><li>Go to Cloudflare Dashboard -> Workers & Pages -> NodeWarden -> Settings -> Variables and Secrets, then update JWT_SECRET.</li><li>Save, wait for redeploy, and refresh this page to confirm.</li></ol>';
        return;
      }
      const isAdd = JWT_STATE === 'missing';
      const step2 = isAdd ? t('s2FixStep2Add') : t('s2FixStep2Replace');
      el.innerHTML = '<ol>'
        + '<li>' + t('s2FixStep1') + '</li>'
        + '<li>' + step2 + '</li>'
        + '<li>' + t('s2FixStep3') + '</li>'
        + '<li>' + t('s2FixStep4') + '</li>'
        + '<li>' + t('s2FixStep5') + '</li>'
        + '</ol>';
    }

    function applyI18n() {
      document.documentElement.lang = isChinese() ? 'zh-CN' : 'en';
      setText('t_app', t('app'));
      setText('t_tag', t('tag'));
      setText('t_by', t('by'));

      setText('t_s1_title', t('s1Title'));
      setText('t_s1_desc', t('s1Desc'));
      setText('t_s1_adv_title', t('s1AdvTitle'));
      setText('t_s1_adv_1', t('s1Adv1'));
      setText('t_s1_adv_2', t('s1Adv2'));
      setText('t_s1_adv_3', t('s1Adv3'));
      setText('t_s1_compat_title', t('s1CompatTitle'));
      setText('t_s1_compat_win', t('s1CompatWin'));
      setText('t_s1_compat_android', t('s1CompatAndroid'));
      setText('t_s1_compat_ios', t('s1CompatIos'));
      setText('t_s1_compat_ext', t('s1CompatExt'));
      setText('t_s1_compat_other', t('s1CompatOther'));

      setText('t_s2_title', t('s2Title'));
      setText('t_s2_fix_title', t('s2FixTitle'));
      renderJwtFixSteps();
      setText('t_s2_gen_title', t('s2GenTitle'));
      setText('refreshSecretBtn', t('refresh'));
      setText('copySecretBtn', t('copy'));

      setText('t_s3_title', t('s3Title'));
      setText('t_s3_common_title', t('s3CommonTitle'));
      setText('t_s3_common_1', t('s3Common1'));
      setText('t_s3_common_2', t('s3Common2'));
      setText('t_s3_common_3', t('s3Common3'));
      setText('manualTab', t('manualSync'));
      setText('autoTab', t('autoSync'));
      setText('t_s3_manual_text', t('s3ManualText'));
      setText('t_s3_manual_step1', t('s3ManualStep1'));
      setText('t_s3_manual_step2', t('s3ManualStep2'));
      setText('t_s3_auto_text', t('s3AutoText'));
      setText('t_s3_auto_step1', t('s3AutoStep1'));
      setText('t_s3_auto_step2', t('s3AutoStep2'));
      setText('t_s3_auto_step3', t('s3AutoStep3'));

      setText('t_s4_title', t('s4BackupTitle'));
      setText('t_s4_desc', t('s4BackupDesc'));
      setText('t_s4_how_title', t('s4HowTitle'));
      setText('t_s4_how_1', t('s4How1'));
      renderBackupSecretChip();
      renderBackupVarChips();
      setText('t_s4_how_4', t('s4How4'));

      setText('t_s5_title', t('s5Title'));
      setText('t_s5_desc', t('s5Desc'));
      setText('t_name_label', t('nameLabel'));
      setText('t_email_label', t('emailLabel'));
      setText('t_pw_label', t('pwLabel'));
      setText('t_pw_hint', t('pwHint'));
      setText('t_pw2_label', t('pw2Label'));
      setText('submitBtn', t('create'));
      setText('t_done_title', t('doneTitle'));
      setText('t_done_desc', t('doneDesc'));
      setText('t_important', t('important'));
      setText('t_limitations', t('limitations'));
      setText('t_hide_title', t('hideTitle'));
      setText('t_hide_desc', t('hideDesc'));
      setText('hideBtn', t('hideBtn'));
      setText('hideModalTitle', t('hideModalTitle'));
      setText('hideModalDesc', t('hideModalDesc'));
      setText('hideModalWarn', t('hideModalWarn'));
      setText('hideModalCancel', t('cancel'));
      setText('hideModalConfirm', t('confirmHide'));

      setText('prevBtn', t('prev'));
      setText('nextBtn', t('next'));
      setText('langToggle', isChinese() ? 'EN' : '中文');

      const title = document.getElementById('t_s2_title');
      if (title) {
        if (!JWT_STATE) title.textContent = t('s2DescGood');
        else if (JWT_STATE === 'missing') title.textContent = t('s2DescMissing');
        else if (JWT_STATE === 'default') title.textContent = t('s2DescDefault');
        else title.textContent = t('s2DescShort');
      }
    }

    function setSyncMode(mode) {
      const manualTab = document.getElementById('manualTab');
      const autoTab = document.getElementById('autoTab');
      const manualPanel = document.getElementById('manualPanel');
      const autoPanel = document.getElementById('autoPanel');
      if (!manualTab || !autoTab || !manualPanel || !autoPanel) return;
      const isManual = mode === 'manual';
      manualTab.classList.toggle('active', isManual);
      autoTab.classList.toggle('active', !isManual);
      manualPanel.classList.toggle('active', isManual);
      autoPanel.classList.toggle('active', !isManual);
    }

    function refreshSecret() {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
      const bytes = new Uint8Array(64);
      crypto.getRandomValues(bytes);
      let out = '';
      for (let i = 0; i < bytes.length; i++) out += chars[bytes[i] % chars.length];
      const el = document.getElementById('secret');
      if (el) el.textContent = out;
    }

    async function copySecret() {
      const el = document.getElementById('secret');
      if (!el) return;
      const s = el.textContent || '';
      try {
        await navigator.clipboard.writeText(s);
      } catch {
        const ta = document.createElement('textarea');
        ta.value = s;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.remove();
      }
      const btn = document.getElementById('copySecretBtn');
      if (btn) {
        const old = btn.textContent;
        btn.textContent = t('copied');
        setTimeout(() => { btn.textContent = old; }, 1000);
      }
    }

    async function copyBackupPreset(btn) {
      if (!btn) return;
      const value = btn.getAttribute('data-copy') || '';
      if (!value) return;
      const old = btn.textContent;
      try {
        await navigator.clipboard.writeText(value);
      } catch {
        const ta = document.createElement('textarea');
        ta.value = value;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.remove();
      }
      btn.textContent = '✓';
      setTimeout(() => { btn.textContent = old || '⧉'; }, 1000);
    }

    function goToStep(targetStep) {
      // 瀹夊叏闄愬埗锛欽WT_SECRET 涓嶅悎瑙勬椂锛屽彧鍏佽璁块棶绗?1/2 姝ャ€?
      const maxStep = JWT_STATE ? 2 : 5;
      currentStep = Math.max(1, Math.min(maxStep, targetStep));

      for (let i = 1; i <= 5; i++) {
        const el = document.getElementById('step' + i);
        if (el) el.classList.toggle('active', i === currentStep);
      }

      const dots = document.querySelectorAll('.dot');
      dots.forEach((dot) => {
        const step = Number(dot.getAttribute('data-step'));
        dot.classList.toggle('active', step === currentStep);
      });

      const prevBtn = document.getElementById('prevBtn');
      if (prevBtn) prevBtn.style.display = currentStep <= 1 ? 'none' : 'inline-flex';

      const nextBtn = document.getElementById('nextBtn');
      if (nextBtn) {
        nextBtn.style.display = currentStep >= 5 ? 'none' : 'inline-flex';
        if (currentStep === 2 && !!JWT_STATE) {
          nextBtn.disabled = true;
          nextBtn.textContent = t('keyWaitRefresh');
        } else {
          nextBtn.disabled = false;
          nextBtn.textContent = t('next');
        }
      }
    }

    function showMessage(text, type) {
      const msg = document.getElementById('message');
      if (!msg) return;
      msg.textContent = text;
      msg.className = 'message ' + type;
    }

    async function checkStatus() {
      try {
        const res = await fetch('/setup/status');
        const data = await res.json();
        isRegistered = !!data.registered;
        if (isRegistered) {
          if (JWT_STATE) {
            // 宸叉敞鍐屼絾瀵嗛挜涓嶅畨鍏細鍙兘鍋滅暀鍦ㄩ椤?瀵嗛挜椤碉紝涓嶈兘鐩存帴杩涘叆鍚庣画椤甸潰銆?
            goToStep(2);
          } else {
            goToStep(5);
            showRegisteredView();
          }
        }
      } catch (e) {
        console.error('Failed to check status:', e);
      }
    }

    function showRegisteredView() {
      isRegistered = true;
      const setupForm = document.getElementById('setup-form');
      const registeredView = document.getElementById('registered-view');
      const serverUrl = document.getElementById('serverUrl');
      if (setupForm) setupForm.style.display = 'none';
      if (registeredView) registeredView.style.display = 'block';
      if (serverUrl) serverUrl.textContent = window.location.origin;
      showMessage(t('doneTitle'), 'success');
    }

    function openHideConfirmModal() {
      const modal = document.getElementById('hideModal');
      if (modal) modal.classList.add('show');
    }

    function closeHideConfirmModal() {
      const modal = document.getElementById('hideModal');
      if (modal) modal.classList.remove('show');
    }

    async function disableSetupPage() {
      if (!isRegistered) return;
      closeHideConfirmModal();
      const btn = document.getElementById('hideBtn');
      if (btn) {
        btn.disabled = true;
        btn.textContent = t('hideWorking');
      }
      try {
        const res = await fetch('/setup/disable', { method: 'POST' });
        const data = await res.json();
        if (res.ok && data.success) {
          showMessage(t('hideDone'), 'success');
          setTimeout(() => window.location.reload(), 650);
          return;
        }
        showMessage(data.error || t('hideFailed'), 'error');
      } catch {
        showMessage(t('hideFailed'), 'error');
      }
      if (btn) {
        btn.disabled = false;
        btn.textContent = t('hideBtn');
      }
    }

    async function pbkdf2(password, salt, iterations, keyLen) {
      const encoder = new TextEncoder();
      const passwordBytes = (password instanceof Uint8Array) ? password : encoder.encode(password);
      const saltBytes = (salt instanceof Uint8Array) ? salt : encoder.encode(salt);
      const keyMaterial = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits']);
      const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations: iterations, hash: 'SHA-256' }, keyMaterial, keyLen * 8);
      return new Uint8Array(derivedBits);
    }

    async function hkdfExpand(prk, info, length) {
      const encoder = new TextEncoder();
      const key = await crypto.subtle.importKey('raw', prk, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const infoBytes = encoder.encode(info);
      const result = new Uint8Array(length);
      let prev = new Uint8Array(0);
      let offset = 0;
      let counter = 1;
      while (offset < length) {
        const input = new Uint8Array(prev.length + infoBytes.length + 1);
        input.set(prev);
        input.set(infoBytes, prev.length);
        input[input.length - 1] = counter;
        const signature = await crypto.subtle.sign('HMAC', key, input);
        prev = new Uint8Array(signature);
        const toCopy = Math.min(prev.length, length - offset);
        result.set(prev.slice(0, toCopy), offset);
        offset += toCopy;
        counter++;
      }
      return result;
    }

    function generateSymmetricKey() {
      return crypto.getRandomValues(new Uint8Array(64));
    }

    async function encryptAesCbc(data, key, iv) {
      const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['encrypt']);
      const encrypted = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: iv }, cryptoKey, data);
      return new Uint8Array(encrypted);
    }

    async function hmacSha256(key, data) {
      const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const signature = await crypto.subtle.sign('HMAC', cryptoKey, data);
      return new Uint8Array(signature);
    }

    function base64Encode(bytes) {
      return btoa(String.fromCharCode.apply(null, bytes));
    }

    async function encryptToBitwardenFormat(data, encKey, macKey) {
      const iv = crypto.getRandomValues(new Uint8Array(16));
      const encrypted = await encryptAesCbc(data, encKey, iv);
      const macData = new Uint8Array(iv.length + encrypted.length);
      macData.set(iv);
      macData.set(encrypted, iv.length);
      const mac = await hmacSha256(macKey, macData);
      return '2.' + base64Encode(iv) + '|' + base64Encode(encrypted) + '|' + base64Encode(mac);
    }

    async function generateRsaKeyPair() {
      const keyPair = await crypto.subtle.generateKey(
        { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' },
        true,
        ['encrypt', 'decrypt']
      );
      const publicKeySpki = await crypto.subtle.exportKey('spki', keyPair.publicKey);
      const publicKeyB64 = base64Encode(new Uint8Array(publicKeySpki));
      const privateKeyPkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
      return { publicKey: publicKeyB64, privateKey: new Uint8Array(privateKeyPkcs8) };
    }

    async function handleSubmit(event) {
      event.preventDefault();
      if (isRegistered) {
        showRegisteredView();
        return;
      }

      const nameInput = document.getElementById('name');
      const emailInput = document.getElementById('email');
      const passwordInput = document.getElementById('password');
      const confirmInput = document.getElementById('confirmPassword');
      const name = nameInput ? nameInput.value : '';
      const email = emailInput ? emailInput.value.toLowerCase() : '';
      const password = passwordInput ? passwordInput.value : '';
      const confirmPassword = confirmInput ? confirmInput.value : '';

      if (password !== confirmPassword) {
        showMessage(t('errPwNotMatch'), 'error');
        return;
      }
      if (password.length < 12) {
        showMessage(t('errPwTooShort'), 'error');
        return;
      }

      const btn = document.getElementById('submitBtn');
      if (btn) {
        btn.disabled = true;
        btn.textContent = t('creating');
      }

      try {
        const iterations = 600000;
        const masterKey = await pbkdf2(password, email, iterations, 32);
        const masterPasswordHash = await pbkdf2(masterKey, password, 1, 32);
        const masterPasswordHashB64 = base64Encode(masterPasswordHash);

        const stretchedKey = await hkdfExpand(masterKey, 'enc', 32);
        const stretchedMacKey = await hkdfExpand(masterKey, 'mac', 32);
        const symmetricKey = generateSymmetricKey();

        const encryptedKey = await encryptToBitwardenFormat(symmetricKey, stretchedKey, stretchedMacKey);
        const rsaKeys = await generateRsaKeyPair();
        const encryptedPrivateKey = await encryptToBitwardenFormat(
          rsaKeys.privateKey,
          symmetricKey.slice(0, 32),
          symmetricKey.slice(32, 64)
        );

        const response = await fetch('/api/accounts/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: email,
            name: name,
            masterPasswordHash: masterPasswordHashB64,
            key: encryptedKey,
            kdf: 0,
            kdfIterations: iterations,
            keys: {
              publicKey: rsaKeys.publicKey,
              encryptedPrivateKey: encryptedPrivateKey
            }
          })
        });

        const result = await response.json();
        if (response.ok && result.success) {
          showRegisteredView();
        } else {
          showMessage(result.error || (result.ErrorModel && result.ErrorModel.Message) || t('errRegisterFailed'), 'error');
          if (btn) {
            btn.disabled = false;
            btn.textContent = t('create');
          }
        }
      } catch (error) {
        console.error('Registration error:', error);
        showMessage(t('errGeneric') + (error && error.message ? error.message : String(error)), 'error');
        if (btn) {
          btn.disabled = false;
          btn.textContent = t('create');
        }
      }
    }

    function init() {
      applyI18n();
      refreshSecret();
      setSyncMode('manual');
      goToStep(1);
      checkStatus();

      const prevBtn = document.getElementById('prevBtn');
      if (prevBtn) {
        prevBtn.addEventListener('click', () => {
          if (currentStep <= 1) return;
          goToStep(currentStep - 1);
        });
      }

      const nextBtn = document.getElementById('nextBtn');
      if (nextBtn) {
        nextBtn.addEventListener('click', () => {
          if (currentStep === 1) goToStep(2);
          else if (currentStep === 2) goToStep(3);
          else if (currentStep === 3) goToStep(4);
          else if (currentStep === 4) goToStep(5);
        });
      }

      const hideModal = document.getElementById('hideModal');
      if (hideModal) {
        hideModal.addEventListener('click', (e) => {
          if (e.target === hideModal) closeHideConfirmModal();
        });
      }

      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeHideConfirmModal();
      });
    }

    init();
  </script>
</body>
</html>`;
}

export async function handleRegisterPage(request: Request, env: Env, jwtState: JwtSecretState | null): Promise<Response> {
  const storage = new StorageService(env.DB);
  const disabled = await storage.isSetupDisabled();
  if (disabled) {
    return new Response(null, { status: 404 });
  }
  return htmlResponse(renderRegisterPageHTML(jwtState));
}




