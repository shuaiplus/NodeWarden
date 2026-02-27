import { Env } from '../types';
import { htmlResponse } from '../utils/response';

function renderPublicSendPage(accessId: string, urlB64Key: string | null): string {
  const accessIdJson = JSON.stringify(accessId);
  const urlB64KeyJson = JSON.stringify(urlB64Key);

  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Bitwarden Send</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f3f5f8;
      --card: #ffffff;
      --text: #0f172a;
      --muted: #64748b;
      --border: #d9e0ea;
      --primary: #2563eb;
      --danger: #b91c1c;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .card {
      width: min(760px, 100%);
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 14px;
      box-shadow: 0 12px 28px rgba(15, 23, 42, 0.09);
      padding: 24px;
    }
    h1 {
      margin: 0;
      font-size: 24px;
      font-weight: 700;
      letter-spacing: -0.2px;
    }
    .meta {
      margin-top: 8px;
      color: var(--muted);
      font-size: 14px;
      line-height: 1.6;
    }
    .status {
      margin-top: 16px;
      min-height: 22px;
      color: var(--muted);
      font-size: 14px;
    }
    .status.error { color: var(--danger); }
    .section {
      margin-top: 18px;
      padding: 16px;
      border: 1px solid var(--border);
      border-radius: 12px;
      background: #fcfdff;
      display: none;
    }
    .section h2 {
      margin: 0 0 12px 0;
      font-size: 16px;
    }
    .text-box {
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
      line-height: 1.7;
      font-size: 15px;
    }
    .hidden-mask {
      filter: blur(7px);
      user-select: none;
    }
    .row {
      display: flex;
      gap: 10px;
      align-items: center;
      flex-wrap: wrap;
    }
    .field {
      width: 100%;
      margin-top: 8px;
    }
    input[type="password"], input[type="text"] {
      width: 100%;
      height: 42px;
      border-radius: 10px;
      border: 1px solid var(--border);
      padding: 0 12px;
      font-size: 14px;
      outline: none;
      background: #fff;
    }
    input[type="password"]:focus, input[type="text"]:focus {
      border-color: #93c5fd;
      box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15);
    }
    button {
      height: 40px;
      padding: 0 14px;
      border-radius: 10px;
      border: 1px solid #c6d0de;
      background: #eef2ff;
      color: #1e3a8a;
      font-weight: 600;
      cursor: pointer;
    }
    button.primary {
      background: var(--primary);
      border-color: var(--primary);
      color: white;
    }
    button:disabled {
      opacity: 0.65;
      cursor: not-allowed;
    }
    .small {
      margin-top: 8px;
      color: var(--muted);
      font-size: 13px;
    }
  </style>
</head>
<body>
  <div class="card">
    <h1 id="sendName">加载中...</h1>
    <div class="meta" id="sendMeta"></div>
    <div class="status" id="status"></div>

    <section class="section" id="keySection">
      <h2>需要解密密钥</h2>
      <form id="keyForm">
        <div class="field">
          <input id="keyInput" type="text" placeholder="粘贴链接中的 key（/#/send/{id}/{key} 的最后一段）" autocomplete="off" spellcheck="false" />
        </div>
        <div class="row" style="margin-top: 10px;">
          <button class="primary" id="keySubmit" type="submit">继续</button>
        </div>
      </form>
      <div class="small">如果你打开的是 <code>/#/send/{id}</code>，请补全 key 后再解锁。</div>
    </section>

    <section class="section" id="passwordSection">
      <h2>此 Send 需要密码</h2>
      <form id="passwordForm">
        <div class="field">
          <input id="passwordInput" type="password" placeholder="输入 Send 密码" autocomplete="current-password" />
        </div>
        <div class="row" style="margin-top: 10px;">
          <button class="primary" id="passwordSubmit" type="submit">解锁</button>
        </div>
      </form>
      <div class="small" id="passwordHint">密码仅用于当前会话，不会保存。</div>
    </section>

    <section class="section" id="textSection">
      <h2>文本内容</h2>
      <p id="textContent" class="text-box"></p>
      <div class="row" style="margin-top: 10px;">
        <button id="toggleTextBtn" type="button" style="display:none;">显示内容</button>
      </div>
    </section>

    <section class="section" id="fileSection">
      <h2>文件内容</h2>
      <div class="meta" id="fileMeta"></div>
      <div class="row" style="margin-top: 10px;">
        <button class="primary" id="downloadFileBtn" type="button">下载并解密文件</button>
      </div>
    </section>
  </div>

  <script>
    const ACCESS_ID = ${accessIdJson};
    const URL_B64_KEY = ${urlB64KeyJson};

    const SEND_TYPE_TEXT = 0;
    const SEND_TYPE_FILE = 1;
    const SEND_PASSWORD_ITERATIONS = 100000;
    const SEND_KEY_SALT = 'bitwarden-send';
    const SEND_KEY_INFO = 'send';

    const textEncoder = new TextEncoder();
    const textDecoder = new TextDecoder();

    let keyMaterialBytes = null;
    let encKeyBytes = null;
    let macKeyBytes = null;
    let derivedKeySource = null;
    let currentUrlB64Key = typeof URL_B64_KEY === 'string' ? URL_B64_KEY : '';
    let sendPasswordHash = null;
    let activeSend = null;

    function getProp(obj, keys) {
      if (!obj || typeof obj !== 'object') return undefined;
      for (const key of keys) {
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
          return obj[key];
        }
      }
      return undefined;
    }

    function byId(id) {
      return document.getElementById(id);
    }

    function setStatus(message, isError) {
      const el = byId('status');
      el.textContent = message || '';
      el.classList.toggle('error', !!isError);
    }

    function show(el, visible) {
      el.style.display = visible ? 'block' : 'none';
    }

    function bytesToBase64(bytes) {
      let binary = '';
      for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary);
    }

    function base64ToBytes(base64) {
      const normalized = base64.replace(/\\s/g, '');
      const binary = atob(normalized);
      const out = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        out[i] = binary.charCodeAt(i);
      }
      return out;
    }

    function urlB64ToBytes(urlB64) {
      let base64 = (urlB64 || '').replace(/-/g, '+').replace(/_/g, '/');
      while (base64.length % 4 !== 0) base64 += '=';
      return base64ToBytes(base64);
    }

    function normalizeUrlB64Key(value) {
      if (typeof value !== 'string') return '';
      const trimmed = value.trim().replace(/^\\/+|\\/+$/g, '');
      return trimmed;
    }

    function syncPathWithResolvedKey() {
      if (!currentUrlB64Key) return;
      const nextPath = '/send/' + encodeURIComponent(ACCESS_ID) + '/' + encodeURIComponent(currentUrlB64Key);
      if (window.location.pathname !== nextPath) {
        history.replaceState(null, '', nextPath);
      }
    }

    function constantTimeEqual(a, b) {
      if (a.length !== b.length) return false;
      let diff = 0;
      for (let i = 0; i < a.length; i++) {
        diff |= a[i] ^ b[i];
      }
      return diff === 0;
    }

    function parseEncString(value) {
      if (typeof value !== 'string' || !value) {
        throw new Error('Invalid encrypted string');
      }

      const dot = value.indexOf('.');
      let encType = 0;
      let payload = value;
      if (dot >= 0) {
        encType = Number(value.slice(0, dot));
        payload = value.slice(dot + 1);
      }

      const parts = payload.split('|');
      if (encType === 2 && parts.length === 3) {
        return {
          encType,
          iv: base64ToBytes(parts[0]),
          data: base64ToBytes(parts[1]),
          mac: base64ToBytes(parts[2]),
        };
      }
      if (encType === 0 && parts.length === 2) {
        return {
          encType,
          iv: base64ToBytes(parts[0]),
          data: base64ToBytes(parts[1]),
          mac: null,
        };
      }

      throw new Error('Unsupported encrypted format');
    }

    async function verifyMac(ivBytes, dataBytes, expectedMac) {
      const macInput = new Uint8Array(ivBytes.length + dataBytes.length);
      macInput.set(ivBytes, 0);
      macInput.set(dataBytes, ivBytes.length);

      const hmacKey = await crypto.subtle.importKey(
        'raw',
        macKeyBytes,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      );
      const signature = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, macInput));
      return constantTimeEqual(signature, expectedMac);
    }

    async function aesCbcDecrypt(ivBytes, dataBytes) {
      const aesKey = await crypto.subtle.importKey(
        'raw',
        encKeyBytes,
        { name: 'AES-CBC' },
        false,
        ['decrypt']
      );
      const plain = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: ivBytes }, aesKey, dataBytes);
      return new Uint8Array(plain);
    }

    async function decryptEncString(value) {
      const parsed = parseEncString(value);
      if (parsed.encType === 2) {
        const macOk = await verifyMac(parsed.iv, parsed.data, parsed.mac);
        if (!macOk) throw new Error('Invalid MAC');
      }
      const plainBytes = await aesCbcDecrypt(parsed.iv, parsed.data);
      return textDecoder.decode(plainBytes);
    }

    async function decryptEncArrayBuffer(bufferBytes) {
      if (!bufferBytes || bufferBytes.length < 18) {
        throw new Error('Invalid encrypted file data');
      }

      const encType = bufferBytes[0];
      if (encType === 2) {
        if (bufferBytes.length < 50) throw new Error('Invalid encrypted file data');
        const iv = bufferBytes.slice(1, 17);
        const mac = bufferBytes.slice(17, 49);
        const data = bufferBytes.slice(49);
        const macOk = await verifyMac(iv, data, mac);
        if (!macOk) throw new Error('Invalid file MAC');
        return await aesCbcDecrypt(iv, data);
      }

      if (encType === 0) {
        const iv = bufferBytes.slice(1, 17);
        const data = bufferBytes.slice(17);
        return await aesCbcDecrypt(iv, data);
      }

      throw new Error('Unsupported encrypted file type');
    }

    async function ensureDerivedSendKeys() {
      const normalizedKey = normalizeUrlB64Key(currentUrlB64Key);
      if (!normalizedKey) {
        throw new Error('MISSING_KEY');
      }

      currentUrlB64Key = normalizedKey;
      if (derivedKeySource === currentUrlB64Key && keyMaterialBytes && encKeyBytes && macKeyBytes) {
        return;
      }

      keyMaterialBytes = urlB64ToBytes(currentUrlB64Key);
      const hkdfKey = await crypto.subtle.importKey('raw', keyMaterialBytes, 'HKDF', false, ['deriveBits']);
      const bits = await crypto.subtle.deriveBits(
        {
          name: 'HKDF',
          hash: 'SHA-256',
          salt: textEncoder.encode(SEND_KEY_SALT),
          info: textEncoder.encode(SEND_KEY_INFO),
        },
        hkdfKey,
        512
      );
      const keyBytes = new Uint8Array(bits);
      encKeyBytes = keyBytes.slice(0, 32);
      macKeyBytes = keyBytes.slice(32, 64);
      derivedKeySource = currentUrlB64Key;
    }

    async function hashSendPassword(rawPassword) {
      const pwKey = await crypto.subtle.importKey('raw', textEncoder.encode(rawPassword), 'PBKDF2', false, ['deriveBits']);
      const bits = await crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          salt: keyMaterialBytes,
          iterations: SEND_PASSWORD_ITERATIONS,
          hash: 'SHA-256',
        },
        pwKey,
        256
      );
      return bytesToBase64(new Uint8Array(bits));
    }

    function renderMeta(send) {
      const creator = send.creatorIdentifier ? ('创建者: ' + send.creatorIdentifier) : '创建者已隐藏';
      const exp = send.expirationDate ? ('到期时间: ' + new Date(send.expirationDate).toLocaleString()) : '到期时间: 未设置';
      byId('sendMeta').textContent = creator + ' · ' + exp;
    }

    function clearSections() {
      show(byId('keySection'), false);
      show(byId('passwordSection'), false);
      show(byId('textSection'), false);
      show(byId('fileSection'), false);
    }

    async function loadSend() {
      clearSections();

      currentUrlB64Key = normalizeUrlB64Key(currentUrlB64Key);
      if (!currentUrlB64Key) {
        show(byId('keySection'), true);
        setStatus('链接缺少解密 key，请补全后再继续。', true);
        return;
      }

      try {
        await ensureDerivedSendKeys();
        syncPathWithResolvedKey();
      } catch (error) {
        console.error(error);
        show(byId('keySection'), true);
        setStatus('解密 key 无效，请检查链接是否完整。', true);
        return;
      }

      setStatus('正在加载 Send ...', false);

      const requestBody = sendPasswordHash ? { password: sendPasswordHash } : {};
      const response = await fetch('/api/sends/access/' + encodeURIComponent(ACCESS_ID), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
      });

      let payload = null;
      try {
        payload = await response.json();
      } catch {
        payload = null;
      }

      if (response.status === 401) {
        show(byId('passwordSection'), true);
        if (sendPasswordHash) {
          setStatus('密码无效，请重新输入。', true);
        } else {
          setStatus('需要密码才能访问该 Send。', true);
        }
        return;
      }
      if (response.status === 400) {
        sendPasswordHash = null;
        show(byId('passwordSection'), true);
        setStatus('密码错误，请重试。', true);
        return;
      }
      if (response.status === 404) {
        setStatus('Send 不存在或已失效。', true);
        byId('sendName').textContent = 'Send 不可用';
        return;
      }
      if (!response.ok || !payload) {
        setStatus('加载失败，请稍后重试。', true);
        return;
      }

      const sendType = Number(getProp(payload, ['type', 'Type']));
      const encryptedName = getProp(payload, ['name', 'Name']);
      const creatorIdentifier = getProp(payload, ['creatorIdentifier', 'CreatorIdentifier']) || null;
      const expirationDate = getProp(payload, ['expirationDate', 'ExpirationDate']) || null;
      const sendId = getProp(payload, ['id', 'Id']);

      const decryptedName = await decryptEncString(encryptedName);
      byId('sendName').textContent = decryptedName || 'Untitled Send';

      activeSend = {
        id: sendId,
        type: sendType,
        creatorIdentifier,
        expirationDate,
      };

      renderMeta(activeSend);

      if (sendType === SEND_TYPE_TEXT) {
        const textObj = getProp(payload, ['text', 'Text']) || {};
        const encryptedText = getProp(textObj, ['text', 'Text']);
        const hidden = !!getProp(textObj, ['hidden', 'Hidden']);
        const decryptedText = await decryptEncString(encryptedText);

        activeSend.text = {
          text: decryptedText,
          hidden,
        };

        const textEl = byId('textContent');
        textEl.textContent = decryptedText;
        textEl.classList.toggle('hidden-mask', hidden);

        const toggleBtn = byId('toggleTextBtn');
        if (hidden) {
          toggleBtn.style.display = 'inline-flex';
          toggleBtn.textContent = '显示内容';
        } else {
          toggleBtn.style.display = 'none';
        }

        show(byId('textSection'), true);
      } else if (sendType === SEND_TYPE_FILE) {
        const fileObj = getProp(payload, ['file', 'File']) || {};
        const fileId = getProp(fileObj, ['id', 'Id']);
        const encryptedFileName = getProp(fileObj, ['fileName', 'FileName']);
        const fileSize = getProp(fileObj, ['size', 'Size']) || '';
        const fileSizeName = getProp(fileObj, ['sizeName', 'SizeName']) || '';

        const decryptedFileName = await decryptEncString(encryptedFileName);
        activeSend.file = {
          id: fileId,
          fileName: decryptedFileName,
          size: fileSize,
          sizeName: fileSizeName,
        };

        byId('fileMeta').textContent = '文件名: ' + decryptedFileName + (fileSizeName ? (' · 大小: ' + fileSizeName) : '');
        show(byId('fileSection'), true);
      }

      show(byId('passwordSection'), false);
      const passwordInput = byId('passwordInput');
      if (passwordInput) passwordInput.value = '';
      setStatus('Send 已解锁。', false);
    }

    async function downloadFile() {
      if (!activeSend || activeSend.type !== SEND_TYPE_FILE || !activeSend.file || !activeSend.file.id) {
        setStatus('当前 Send 不是文件类型。', true);
        return;
      }

      setStatus('正在获取下载链接...', false);

      const requestBody = sendPasswordHash ? { password: sendPasswordHash } : {};
      const response = await fetch(
        '/api/sends/' + encodeURIComponent(activeSend.id) + '/access/file/' + encodeURIComponent(activeSend.file.id),
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(requestBody),
        }
      );

      let payload = null;
      try {
        payload = await response.json();
      } catch {
        payload = null;
      }

      if (response.status === 401) {
        show(byId('passwordSection'), true);
        setStatus('需要密码才能下载文件。', true);
        return;
      }
      if (response.status === 400) {
        sendPasswordHash = null;
        show(byId('passwordSection'), true);
        setStatus('密码错误，无法下载文件。', true);
        return;
      }
      if (!response.ok || !payload || !getProp(payload, ['url', 'Url'])) {
        setStatus('无法获取下载链接。', true);
        return;
      }

      const downloadUrl = getProp(payload, ['url', 'Url']);
      setStatus('正在下载并解密文件...', false);

      const fileResponse = await fetch(downloadUrl);
      if (!fileResponse.ok) {
        setStatus('下载文件失败。', true);
        return;
      }

      const encryptedBytes = new Uint8Array(await fileResponse.arrayBuffer());
      const plainBytes = await decryptEncArrayBuffer(encryptedBytes);
      const blob = new Blob([plainBytes], { type: 'application/octet-stream' });
      const objectUrl = URL.createObjectURL(blob);

      const anchor = document.createElement('a');
      anchor.href = objectUrl;
      anchor.download = activeSend.file.fileName || 'send-file';
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(objectUrl), 3000);

      setStatus('下载完成。', false);
    }

    byId('keyForm').addEventListener('submit', async function (event) {
      event.preventDefault();
      const submitBtn = byId('keySubmit');
      const input = byId('keyInput');
      const keyValue = normalizeUrlB64Key((input.value || '').trim());
      if (!keyValue) {
        setStatus('请输入解密 key。', true);
        return;
      }

      submitBtn.disabled = true;
      try {
        currentUrlB64Key = keyValue;
        derivedKeySource = null;
        keyMaterialBytes = null;
        encKeyBytes = null;
        macKeyBytes = null;
        sendPasswordHash = null;
        const passwordInput = byId('passwordInput');
        if (passwordInput) passwordInput.value = '';
        await loadSend();
      } catch (error) {
        console.error(error);
        setStatus('解锁失败，请检查 key。', true);
      } finally {
        submitBtn.disabled = false;
      }
    });

    byId('passwordForm').addEventListener('submit', async function (event) {
      event.preventDefault();
      const submitBtn = byId('passwordSubmit');
      const input = byId('passwordInput');
      const rawPassword = (input.value || '').trim();
      if (!rawPassword) {
        setStatus('请输入密码。', true);
        return;
      }

      submitBtn.disabled = true;
      try {
        sendPasswordHash = await hashSendPassword(rawPassword);
        await loadSend();
      } catch (error) {
        console.error(error);
        setStatus('解锁失败，请重试。', true);
      } finally {
        submitBtn.disabled = false;
      }
    });

    byId('toggleTextBtn').addEventListener('click', function () {
      if (!activeSend || !activeSend.text) return;
      const textEl = byId('textContent');
      const hidden = textEl.classList.contains('hidden-mask');
      if (hidden) {
        textEl.classList.remove('hidden-mask');
        this.textContent = '隐藏内容';
      } else {
        textEl.classList.add('hidden-mask');
        this.textContent = '显示内容';
      }
    });

    byId('downloadFileBtn').addEventListener('click', async function () {
      this.disabled = true;
      try {
        await downloadFile();
      } catch (error) {
        console.error(error);
        setStatus('下载或解密失败。', true);
      } finally {
        this.disabled = false;
      }
    });

    (async function init() {
      try {
        currentUrlB64Key = normalizeUrlB64Key(currentUrlB64Key);
        const keyInput = byId('keyInput');
        if (keyInput && currentUrlB64Key) {
          keyInput.value = currentUrlB64Key;
        }

        if (!currentUrlB64Key) {
          show(byId('keySection'), true);
          byId('sendName').textContent = '需要解密 key';
          setStatus('链接不完整：缺少解密 key。', true);
          return;
        }

        await loadSend();
      } catch (error) {
        console.error(error);
        setStatus('页面初始化失败。', true);
        byId('sendName').textContent = 'Send 加载失败';
      }
    })();
  </script>
</body>
</html>`;
}

// GET /send/:accessId/:urlB64Key?
export async function handlePublicSendPage(
  request: Request,
  env: Env,
  accessId: string,
  urlB64Key?: string | null
): Promise<Response> {
  void request;
  void env;

  if (!accessId) {
    return htmlResponse('Invalid Send URL', 400);
  }

  return htmlResponse(renderPublicSendPage(accessId, urlB64Key ?? null));
}
