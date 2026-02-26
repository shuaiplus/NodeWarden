export function renderWebClientScript(defaultKdfIterations: number): string {
  return `
(function () {
      var app = document.getElementById('app');
      var defaultKdfIterations = ${defaultKdfIterations};
      var state = {
        phase: 'loading',
        lang: (navigator.language || '').toLowerCase().startsWith('zh') ? 'zh' : 'en',
        msg: '',
        msgType: 'ok',
        inviteCode: '',
        registerName: '',
        registerEmail: '',
        registerPassword: '',
        registerPassword2: '',
        session: null,
        profile: null,
        tab: 'vault',
        ciphers: [],
        folders: [],
        folderFilterId: '',
        selectedCipherId: '',
        selectedMap: {},
        users: [],
        invites: [],
        loginEmail: '',
        loginPassword: '',
        loginTotpToken: '',
        loginTotpError: '',
        pendingLogin: null,
        totpSetupSecret: '',
        totpSetupToken: '',
        totpDisableOpen: false,
        totpDisablePassword: '',
        totpDisableError: ''
      };
      var NO_FOLDER_FILTER = '__none__';

      var i18n = {
        en: {
          brand: 'NodeWarden',
          subtitle: 'Open Source Password Manager',
          login: 'Log In',
          register: 'Create Account',
          email: 'Email Address',
          masterPwd: 'Master Password',
          confirmPwd: 'Confirm Master Password',
          name: 'Name',
          inviteCode: 'Invite Code (Optional)',
          loginBtn: 'Log In',
          registerBtn: 'Create Account',
          backToLogin: 'Back to Log In',
          vault: 'Vault',
          settings: 'Settings',
          admin: 'Admin',
          help: 'Help',
          logout: 'Log Out',
          folders: 'Folders',
          allItems: 'All Items',
          noFolder: 'No Folder',
          refresh: 'Refresh',
          move: 'Move',
          delete: 'Delete',
          selectAll: 'Select All',
          clear: 'Clear',
          noItems: 'There are no items to list.',
          selectItem: 'Select an item to view details.',
          profile: 'Profile',
          saveProfile: 'Save Profile',
          changePwd: 'Change Master Password',
          currentPwd: 'Current Master Password',
          newPwd: 'New Master Password',
          totpSetup: 'Two-Step Login (TOTP)',
          enableTotp: 'Enable TOTP',
          disableTotp: 'Disable TOTP',
          secret: 'Authenticator Key',
          verifyCode: 'Verification Code',
          users: 'Users',
          invites: 'Invites',
          createInvite: 'Create Invite',
          expiresIn: 'Expires in (hours)',
          copyLink: 'Copy Link',
          revoke: 'Revoke',
          ban: 'Ban',
          unban: 'Unban',
          status: 'Status',
          role: 'Role',
          action: 'Options',
          loading: 'Loading NodeWarden...',
          totpVerify: 'Two-step verification',
          totpVerifySub: 'Password is already verified.',
          totpCode: 'TOTP Code',
          verify: 'Verify',
          cancel: 'Cancel',
          totpDisableSub: 'Enter master password to disable two-step verification.',
          helpSync: 'Upstream Sync',
          helpSync1: 'Track upstream with a fork and scheduled sync workflow (recommended).',
          helpSync2: 'Before merge: compare API routes, migration files, and auth logic changes.',
          helpSync3: 'After merge: run local dev migration tests, then deploy Worker after validation.',
          helpErr: 'Common Errors',
          helpErr1: '401 Unauthorized: token expired or revoked, login again.',
          helpErr2: '403 Account disabled: admin must unban user in User Management.',
          helpErr3: '403 Invite invalid: invite expired/used/revoked, create a new invite.',
          helpErr4: '429 Too many requests: wait retry seconds and avoid burst writes.',
          helpTb: 'Troubleshooting',
          helpTb1: 'Login OK but encrypted values shown: verify profile key and KDF settings are consistent.',
          helpTb2: 'TOTP fails repeatedly: sync device time and re-scan QR using latest secret.',
          helpTb3: 'Password change failed: ensure current password is correct and new password has at least 12 chars.',
          helpTb4: 'Sync conflicts: refresh vault and retry one operation at a time.',
          langSwitch: '中文'
        },
        zh: {
          brand: 'NodeWarden',
          subtitle: '开源密码管理器',
          login: '登录',
          register: '创建账号',
          email: '电子邮件地址',
          masterPwd: '主密码',
          confirmPwd: '确认主密码',
          name: '姓名',
          inviteCode: '邀请码 (可选)',
          loginBtn: '登录',
          registerBtn: '创建账号',
          backToLogin: '返回登录',
          vault: '密码库',
          settings: '设置',
          admin: '管理',
          help: '帮助',
          logout: '退出登录',
          folders: '文件夹',
          allItems: '所有项目',
          noFolder: '无文件夹',
          refresh: '刷新',
          move: '移动',
          delete: '删除',
          selectAll: '全选',
          clear: '清除',
          noItems: '没有可列出的项目。',
          selectItem: '选择一个项目以查看详细信息。',
          profile: '个人资料',
          saveProfile: '保存个人资料',
          changePwd: '更改主密码',
          currentPwd: '当前主密码',
          newPwd: '新主密码',
          totpSetup: '两步登录 (TOTP)',
          enableTotp: '启用 TOTP',
          disableTotp: '禁用 TOTP',
          secret: '身份验证器密钥',
          verifyCode: '验证码',
          users: '用户',
          invites: '邀请',
          createInvite: '创建邀请',
          expiresIn: '过期时间 (小时)',
          copyLink: '复制链接',
          revoke: '撤销',
          ban: '封禁',
          unban: '解封',
          status: '状态',
          role: '角色',
          action: '选项',
          loading: '正在加载 NodeWarden...',
          totpVerify: '两步验证',
          totpVerifySub: '密码已验证。',
          totpCode: 'TOTP 验证码',
          verify: '验证',
          cancel: '取消',
          totpDisableSub: '输入主密码以禁用两步验证。',
          helpSync: '上游同步',
          helpSync1: '建议通过 fork 和定时同步工作流跟踪上游。',
          helpSync2: '合并前：比较 API 路由、迁移文件和认证逻辑的更改。',
          helpSync3: '合并后：运行本地开发迁移测试，验证后部署 Worker。',
          helpErr: '常见错误',
          helpErr1: '401 未授权：令牌过期或被撤销，请重新登录。',
          helpErr2: '403 账号被禁用：管理员必须在用户管理中解封用户。',
          helpErr3: '403 邀请无效：邀请已过期/已使用/被撤销，请创建新邀请。',
          helpErr4: '429 请求过多：等待重试时间，避免突发写入。',
          helpTb: '故障排除',
          helpTb1: '登录成功但显示加密值：验证个人资料密钥和 KDF 设置是否一致。',
          helpTb2: 'TOTP 反复失败：同步设备时间并使用最新密钥重新扫描二维码。',
          helpTb3: '密码更改失败：确保当前密码正确且新密码至少 12 个字符。',
          helpTb4: '同步冲突：刷新密码库并一次重试一个操作。',
          langSwitch: 'English'
        }
      };

      function t(key) { return i18n[state.lang][key] || key; }

      function esc(v) {
        return String(v == null ? '' : v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
      }
      function sessionKey() { return 'nodewarden.web.session.v2'; }
      function setMsg(t, ty) { state.msg = t || ''; state.msgType = ty || 'ok'; render(); }
      function clearMsg() { state.msg = ''; }
      function renderMsg() { return state.msg ? '<div class="alert alert-' + (state.msgType === 'err' ? 'danger' : 'success') + '">' + esc(state.msg) + '</div>' : ''; }
      function saveSession() { if (state.session) localStorage.setItem(sessionKey(), JSON.stringify(state.session)); else localStorage.removeItem(sessionKey()); }
      function loadSession() { try { var r = localStorage.getItem(sessionKey()); if (!r) return null; var p = JSON.parse(r); if (!p || !p.accessToken || !p.refreshToken) return null; return p; } catch (e) { return null; } }
      function bytesToBase64(bytes) { var s=''; for (var i=0;i<bytes.length;i++) s += String.fromCharCode(bytes[i]); return btoa(s); }
      function concatBytes(a,b){ var o=new Uint8Array(a.length+b.length); o.set(a,0); o.set(b,a.length); return o; }
      async function pbkdf2(passwordOrBytes, saltOrBytes, iterations, keyLen){
        var enc=new TextEncoder();
        var pass=(passwordOrBytes instanceof Uint8Array)?passwordOrBytes:enc.encode(String(passwordOrBytes));
        var salt=(saltOrBytes instanceof Uint8Array)?saltOrBytes:enc.encode(String(saltOrBytes));
        var keyMaterial=await crypto.subtle.importKey('raw', pass, 'PBKDF2', false, ['deriveBits']);
        var bits=await crypto.subtle.deriveBits({name:'PBKDF2', salt:salt, iterations:iterations, hash:'SHA-256'}, keyMaterial, keyLen*8);
        return new Uint8Array(bits);
      }
      async function hkdfExpand(prk, info, length){
        var enc=new TextEncoder();
        var key=await crypto.subtle.importKey('raw', prk, {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
        var infoBytes=enc.encode(info); var result=new Uint8Array(length); var prev=new Uint8Array(0); var off=0; var cnt=1;
        while(off<length){ var inp=new Uint8Array(prev.length+infoBytes.length+1); inp.set(prev,0); inp.set(infoBytes,prev.length); inp[inp.length-1]=cnt; var sig=new Uint8Array(await crypto.subtle.sign('HMAC', key, inp)); prev=sig; var c=Math.min(prev.length, length-off); result.set(prev.slice(0,c), off); off+=c; cnt++; }
        return result;
      }
      async function hmacSha256(keyBytes, dataBytes){ var key=await crypto.subtle.importKey('raw', keyBytes, {name:'HMAC', hash:'SHA-256'}, false, ['sign']); return new Uint8Array(await crypto.subtle.sign('HMAC', key, dataBytes)); }
      async function encryptAesCbc(data,key,iv){ var ck=await crypto.subtle.importKey('raw', key, {name:'AES-CBC'}, false, ['encrypt']); return new Uint8Array(await crypto.subtle.encrypt({name:'AES-CBC', iv:iv}, ck, data)); }
      async function encryptBw(data, encKey, macKey){ var iv=crypto.getRandomValues(new Uint8Array(16)); var cipher=await encryptAesCbc(data,encKey,iv); var mac=await hmacSha256(macKey, concatBytes(iv,cipher)); return '2.'+bytesToBase64(iv)+'|'+bytesToBase64(cipher)+'|'+bytesToBase64(mac); }
      async function jsonOrNull(resp){ var t=await resp.text(); if(!t) return null; try{ return JSON.parse(t);} catch(e){ return null; } }

      function base64ToBytes(b64){ var bin=atob(b64); var bytes=new Uint8Array(bin.length); for(var i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i); return bytes; }
      function parseCipherString(s){
        if(!s||typeof s!=='string') return null;
        var type,rest,dotIdx=s.indexOf('.');
        if(dotIdx>=0){ type=parseInt(s.substring(0,dotIdx),10); rest=s.substring(dotIdx+1); }
        else{ var pp=s.split('|'); type=(pp.length===3)?2:0; rest=s; }
        var parts=rest.split('|');
        if(type===2&&parts.length===3) return {type:2,iv:base64ToBytes(parts[0]),ct:base64ToBytes(parts[1]),mac:base64ToBytes(parts[2])};
        if((type===0||type===1||type===4)&&parts.length>=2) return {type:type,iv:base64ToBytes(parts[0]),ct:base64ToBytes(parts[1]),mac:null};
        return null;
      }
      async function decryptAesCbc(data,key,iv){ var ck=await crypto.subtle.importKey('raw',key,{name:'AES-CBC'},false,['decrypt']); return new Uint8Array(await crypto.subtle.decrypt({name:'AES-CBC',iv:iv},ck,data)); }
      async function decryptBw(cipherString,encKey,macKey){
        var parsed=parseCipherString(cipherString); if(!parsed) return null;
        if(parsed.type===2&&macKey&&parsed.mac){
          var macData=concatBytes(parsed.iv,parsed.ct); var computedMac=await hmacSha256(macKey,macData);
          var match=true; if(computedMac.length!==parsed.mac.length) match=false;
          else{ for(var i=0;i<computedMac.length;i++){if(computedMac[i]!==parsed.mac[i]){match=false;break;}} }
          if(!match) throw new Error('MAC mismatch');
        }
        return await decryptAesCbc(parsed.ct,encKey,parsed.iv);
      }
      async function decryptStr(cipherString,encKey,macKey){
        if(!cipherString) return '';
        try{ var bytes=await decryptBw(cipherString,encKey,macKey); if(!bytes) return String(cipherString); return new TextDecoder().decode(bytes); }
        catch(e){ return String(cipherString); }
      }
      async function decryptVault(){
        if(!state.session||!state.session.symEncKey||!state.session.symMacKey) return;
        var encKey=base64ToBytes(state.session.symEncKey); var macKey=base64ToBytes(state.session.symMacKey);
        for(var i=0;i<state.folders.length;i++){ state.folders[i].decName=await decryptStr(state.folders[i].name,encKey,macKey); }
        for(var i=0;i<state.ciphers.length;i++){
          var c=state.ciphers[i]; var ek=encKey,mk=macKey;
          if(c.key){ try{ var ikb=await decryptBw(c.key,encKey,macKey); if(ikb){ek=ikb.slice(0,32);mk=ikb.slice(32,64);} }catch(e){} }
          c.decName=await decryptStr(c.name,ek,mk); c.decNotes=await decryptStr(c.notes,ek,mk);
          if(c.login){
            c.login.decUsername=await decryptStr(c.login.username,ek,mk); c.login.decPassword=await decryptStr(c.login.password,ek,mk); c.login.decTotp=await decryptStr(c.login.totp,ek,mk);
            if(c.login.uris){for(var j=0;j<c.login.uris.length;j++){if(c.login.uris[j].uri) c.login.uris[j].decUri=await decryptStr(c.login.uris[j].uri,ek,mk);}}
          }
          if(c.card){
            c.card.decCardholderName=await decryptStr(c.card.cardholderName,ek,mk); c.card.decNumber=await decryptStr(c.card.number,ek,mk);
            c.card.decBrand=await decryptStr(c.card.brand,ek,mk); c.card.decExpMonth=await decryptStr(c.card.expMonth,ek,mk);
            c.card.decExpYear=await decryptStr(c.card.expYear,ek,mk); c.card.decCode=await decryptStr(c.card.code,ek,mk);
          }
          if(c.identity){
            c.identity.decFirstName=await decryptStr(c.identity.firstName,ek,mk); c.identity.decLastName=await decryptStr(c.identity.lastName,ek,mk);
            c.identity.decEmail=await decryptStr(c.identity.email,ek,mk); c.identity.decPhone=await decryptStr(c.identity.phone,ek,mk);
            c.identity.decCompany=await decryptStr(c.identity.company,ek,mk); c.identity.decUsername=await decryptStr(c.identity.username,ek,mk);
          }
          if(c.fields){ for(var j=0;j<c.fields.length;j++){ c.fields[j].decName=await decryptStr(c.fields[j].name,ek,mk); c.fields[j].decValue=await decryptStr(c.fields[j].value,ek,mk); } }
        }
      }

      async function deriveLoginHash(email,password){
        var pre=await fetch('/identity/accounts/prelogin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:email.toLowerCase()})});
        if(!pre.ok) throw new Error('prelogin failed');
        var d=await pre.json();
        var it=Number(d.kdfIterations||defaultKdfIterations);
        var mk=await pbkdf2(password,email.toLowerCase(),it,32);
        var h=await pbkdf2(mk,password,1,32);
        return { hash: bytesToBase64(h), masterKey: mk, kdfIterations: it };
      }

      function logout(){
        state.session=null; state.profile=null; state.ciphers=[]; state.folders=[]; state.users=[]; state.invites=[]; state.folderFilterId=''; state.selectedCipherId=''; state.selectedMap={}; state.pendingLogin=null; state.loginTotpToken=''; state.loginTotpError=''; state.totpDisableOpen=false; state.totpDisablePassword=''; state.totpDisableError=''; state.phase='login'; saveSession(); clearMsg(); render();
      }

      async function authFetch(path, options){
        var opts=options||{}; if(!state.session||!state.session.accessToken) throw new Error('unauthorized');
        var h=opts.headers?Object.assign({},opts.headers):{}; h.Authorization='Bearer '+state.session.accessToken;
        var r=await fetch(path,Object.assign({},opts,{headers:h})); if(r.status!==401) return r; if(!state.session.refreshToken) return r;
        var f=new URLSearchParams(); f.set('grant_type','refresh_token'); f.set('refresh_token',state.session.refreshToken);
        var rr=await fetch('/identity/connect/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:f.toString()});
        if(!rr.ok){ logout(); return r; }
        var tj=await rr.json(); state.session.accessToken=tj.access_token; state.session.refreshToken=tj.refresh_token||state.session.refreshToken; saveSession();
        h.Authorization='Bearer '+state.session.accessToken; return fetch(path,Object.assign({},opts,{headers:h}));
      }

      async function loadProfile(){ var r=await authFetch('/api/accounts/profile',{method:'GET'}); if(!r.ok) throw new Error('profile'); state.profile=await r.json(); }
      async function loadVault(){ var cr=await authFetch('/api/ciphers',{method:'GET'}); var fr=await authFetch('/api/folders',{method:'GET'}); if(!cr.ok||!fr.ok) throw new Error('vault'); var cj=await cr.json(); var fj=await fr.json(); state.ciphers=cj.data||[]; state.folders=fj.data||[]; if(!state.selectedCipherId&&state.ciphers.length>0) state.selectedCipherId=state.ciphers[0].id; await decryptVault(); }
      async function loadAdminData(){ if(!state.profile||state.profile.role!=='admin') return; var u=await authFetch('/api/admin/users',{method:'GET'}); if(u.ok){ var uj=await u.json(); state.users=uj.data||[]; } var i=await authFetch('/api/admin/invites?includeInactive=true',{method:'GET'}); if(i.ok){ var ij=await i.json(); state.invites=ij.data||[]; } }

      function selectedCount(){ var n=0; for(var k in state.selectedMap){ if(state.selectedMap[k]) n++; } return n; }
      function filteredCiphers(){ var out=[]; for(var i=0;i<state.ciphers.length;i++){ var c=state.ciphers[i]; if(!state.folderFilterId) out.push(c); else if(state.folderFilterId===NO_FOLDER_FILTER&&(!c.folderId||c.folderId==='')) out.push(c); else if(c.folderId===state.folderFilterId) out.push(c);} return out; }
      function selectedCipher(){ if(!state.selectedCipherId) return null; var list=filteredCiphers(); for(var i=0;i<list.length;i++){ if(list[i].id===state.selectedCipherId) return list[i]; } return null; }
      function randomBase32Secret(len){ var a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; var b=crypto.getRandomValues(new Uint8Array(len)); var o=''; for(var i=0;i<b.length;i++) o+=a[b[i]%a.length]; return o; }
      function currentTotpSecret(){ if(!state.totpSetupSecret) state.totpSetupSecret=randomBase32Secret(32); return state.totpSetupSecret; }
      function buildTotpUri(secret){ var issuer='NodeWarden'; var account=state.profile&&state.profile.email?state.profile.email:'account'; return 'otpauth://totp/'+encodeURIComponent(issuer+':'+account)+'?secret='+encodeURIComponent(secret)+'&issuer='+encodeURIComponent(issuer)+'&algorithm=SHA1&digits=6&period=30'; }
      function buildSymmetricKeyBytes(){
        if(!state.session||!state.session.symEncKey||!state.session.symMacKey) return null;
        try{
          var enc=base64ToBytes(state.session.symEncKey);
          var mac=base64ToBytes(state.session.symMacKey);
          if(enc.length!==32||mac.length!==32) return null;
          var out=new Uint8Array(64);
          out.set(enc,0);
          out.set(mac,32);
          return out;
        }catch(e){
          return null;
        }
      }
      function renderLoginScreen(){
        return ''
          + '<div class="auth-page">'
          + '  <div class="lang-switch" data-action="toggle-lang">'+t('langSwitch')+'</div>'
          + '  <div class="auth-card">'
          + '    <div class="auth-header">'
          + '      <div class="auth-logo"></div>'
          + '      <div class="auth-title">'+t('brand')+'</div>'
          + '      <div class="auth-subtitle">'+t('subtitle')+'</div>'
          + '    </div>'
          +      renderMsg()
          + '    <form id="loginForm">'
          + '      <div class="form-group"><label class="form-label">'+t('email')+'</label><input class="form-input" type="email" name="email" value="'+esc(state.loginEmail)+'" required autofocus /></div>'
          + '      <div class="form-group"><label class="form-label">'+t('masterPwd')+'</label><input class="form-input" type="password" name="password" value="'+esc(state.loginPassword)+'" required /></div>'
          + '      <button class="btn btn-primary" type="submit" style="width:100%; margin-top:16px;">'+t('loginBtn')+'</button>'
          + '    </form>'
          + '    <div class="auth-footer">'
          + '      <a href="#" data-action="goto-register">'+t('registerBtn')+'</a>'
          + '    </div>'
          + (state.pendingLogin ? ''
            + '<div class="totp-mask"><div class="totp-box"><h3 style="margin-top:0;">'+t('totpVerify')+'</h3><div class="tiny" style="margin-bottom:16px;">'+t('totpVerifySub')+'</div>'
            + (state.loginTotpError?'<div class="alert alert-danger" style="margin-bottom:16px;">'+esc(state.loginTotpError)+'</div>':'')
            + '<form id="loginTotpForm"><div class="form-group"><label class="form-label">'+t('totpCode')+'</label><input class="form-input" name="totpToken" maxlength="6" value="'+esc(state.loginTotpToken)+'" required autofocus /></div><div style="display:flex; gap:8px; margin-top:16px;"><button class="btn btn-primary" type="submit" style="flex:1;">'+t('verify')+'</button><button class="btn btn-secondary" type="button" data-action="totp-cancel" style="flex:1;">'+t('cancel')+'</button></div></form>'
            + '</div></div>'
            : '')
          + '  </div>'
          + '</div>';
      }

      function renderRegisterScreen(){
        return ''
          + '<div class="auth-page">'
          + '  <div class="lang-switch" data-action="toggle-lang">'+t('langSwitch')+'</div>'
          + '  <div class="auth-card">'
          + '    <div class="auth-header">'
          + '      <div class="auth-logo"></div>'
          + '      <div class="auth-title">'+t('register')+'</div>'
          + '      <div class="auth-subtitle">'+t('brand')+'</div>'
          + '    </div>'
          +      renderMsg()
          + '    <form id="registerForm">'
          + '      <div class="form-group"><label class="form-label">'+t('name')+'</label><input class="form-input" name="name" value="'+esc(state.registerName)+'" required autofocus /></div>'
          + '      <div class="form-group"><label class="form-label">'+t('email')+'</label><input class="form-input" type="email" name="email" value="'+esc(state.registerEmail)+'" required /></div>'
          + '      <div class="form-group"><label class="form-label">'+t('masterPwd')+'</label><input class="form-input" type="password" name="password" value="'+esc(state.registerPassword)+'" minlength="12" required /></div>'
          + '      <div class="form-group"><label class="form-label">'+t('confirmPwd')+'</label><input class="form-input" type="password" name="password2" value="'+esc(state.registerPassword2)+'" minlength="12" required /></div>'
          + '      <div class="form-group"><label class="form-label">'+t('inviteCode')+'</label><input class="form-input" name="inviteCode" value="'+esc(state.inviteCode)+'" /></div>'
          + '      <button class="btn btn-primary" type="submit" style="width:100%; margin-top:16px;">'+t('registerBtn')+'</button>'
          + '    </form>'
          + '    <div class="auth-footer">'
          + '      <a href="#" data-action="goto-login">'+t('backToLogin')+'</a>'
          + '    </div>'
          + '  </div>'
          + '</div>';
      }

      function renderVaultTab(){
        var list=filteredCiphers();
        var rows='';
        for(var i=0;i<list.length;i++){
          var c=list[i];
          var nameText=(c.decName||c.name||c.id);
          rows += '<div class="item '+(c.id===state.selectedCipherId?'active':'')+'" data-action="pick-cipher" data-id="'+esc(c.id)+'"><input type="checkbox" data-action="toggle-select" data-id="'+esc(c.id)+'"'+(state.selectedMap[c.id]?' checked':'')+' /><div><div style="font-weight:600;font-size:14px;color:var(--text-primary);">'+esc(nameText)+'</div><div class="tiny" style="color:var(--text-secondary);">'+esc(c.id)+'</div></div></div>';
        }
        if(!rows) rows='<div class="item" style="justify-content:center; color:var(--text-secondary);">'+t('noItems')+'</div>';

        var c0=selectedCipher();
        var detail='<div class="tiny" style="text-align:center; padding:40px; color:var(--text-secondary);">'+t('selectItem')+'</div>';
        if(c0){
          var login = c0.login||{};
          var fields=Array.isArray(c0.fields)?c0.fields:[];
          var fh='';
          for(var j=0;j<fields.length;j++) fh += '<div class="kv"><b>'+(esc(fields[j].decName||fields[j].name||'Field '+(j+1)))+':</b> '+esc(fields[j].decValue||fields[j].value||'')+'</div>';
          var uriHtml=''; if(login.uris){for(var j=0;j<login.uris.length;j++){var u=login.uris[j]; uriHtml+='<div class="kv"><b>URI '+(j+1)+':</b> '+esc(u.decUri||u.uri||'')+'</div>';}}
          var cardHtml=''; if(c0.card){var cd=c0.card; cardHtml='<div class="kv"><b>Cardholder:</b> '+esc(cd.decCardholderName||cd.cardholderName||'')+'</div><div class="kv"><b>Number:</b> '+esc(cd.decNumber||cd.number||'')+'</div><div class="kv"><b>Brand:</b> '+esc(cd.decBrand||cd.brand||'')+'</div><div class="kv"><b>Exp:</b> '+esc(cd.decExpMonth||cd.expMonth||'')+'/'+esc(cd.decExpYear||cd.expYear||'')+'</div><div class="kv"><b>CVV:</b> '+esc(cd.decCode||cd.code||'')+'</div>';}
          var identHtml=''; if(c0.identity){var id=c0.identity; identHtml='<div class="kv"><b>Name:</b> '+esc((id.decFirstName||id.firstName||'')+' '+(id.decLastName||id.lastName||''))+'</div><div class="kv"><b>Email:</b> '+esc(id.decEmail||id.email||'')+'</div><div class="kv"><b>Phone:</b> '+esc(id.decPhone||id.phone||'')+'</div><div class="kv"><b>Company:</b> '+esc(id.decCompany||id.company||'')+'</div><div class="kv"><b>Username:</b> '+esc(id.decUsername||id.username||'')+'</div>';}
          detail=''
            + '<div class="kv"><b>Name:</b> '+esc(c0.decName||c0.name||'')+'</div>'
            + '<div class="kv"><b>Notes:</b> '+esc(c0.decNotes||c0.notes||'')+'</div>'
            + (c0.login?('<div class="kv"><b>Username:</b> '+esc(login.decUsername||login.username||'')+'</div>'
            + '<div class="kv"><b>Password:</b> '+esc(login.decPassword||login.password||'')+'</div>'
            + '<div class="kv"><b>TOTP:</b> '+esc(login.decTotp||login.totp||'')+'</div>'+uriHtml):''
            ) + cardHtml + identHtml + fh;
        }

        return ''
          + renderMsg()
          + '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:24px; flex-wrap:wrap; gap:16px;">'
          + '<h2 style="margin:0; font-size:24px; font-weight:600; color:var(--text-primary);">'+t('vault')+'</h2>'
          + '<div style="display:flex; gap:8px;"><button class="btn btn-secondary" data-action="vault-refresh">'+t('refresh')+'</button><button class="btn btn-secondary" data-action="bulk-move">'+t('move')+'</button><button class="btn btn-danger" data-action="bulk-delete">'+t('delete')+' ('+selectedCount()+')</button><button class="btn btn-secondary" data-action="select-all">'+t('selectAll')+'</button><button class="btn btn-secondary" data-action="select-none">'+t('clear')+'</button></div>'
          + '</div>'
          + '<div class="vault-grid"><div class="list">'+rows+'</div><div class="panel" style="margin:0; overflow:auto;">'+detail+'</div></div>';
      }

      function renderSettingsTab(){
        var p=state.profile||{};
        var secret=currentTotpSecret();
        var qr='https://api.qrserver.com/v1/create-qr-code/?size=180x180&data='+encodeURIComponent(buildTotpUri(secret));
        return ''
          + renderMsg()
          + '<h2 style="margin:0 0 24px 0; font-size:24px; font-weight:600; color:var(--text-primary);">'+t('settings')+'</h2>'
          + '<div class="panel"><h3 style="margin-top:0;">'+t('profile')+'</h3><form id="profileForm"><div style="display:flex; gap:16px; margin-bottom:16px;"><div class="form-group" style="flex:1;"><label class="form-label">'+t('name')+'</label><input class="form-input" name="name" value="'+esc(p.name||'')+'" /></div><div class="form-group" style="flex:1;"><label class="form-label">'+t('email')+'</label><input class="form-input" type="email" name="email" value="'+esc(p.email||'')+'" required /></div></div><button class="btn btn-primary" type="submit">'+t('saveProfile')+'</button></form></div>'
          + '<div class="panel"><h3 style="margin-top:0;">'+t('changePwd')+'</h3><form id="passwordForm"><div class="form-group"><label class="form-label">'+t('currentPwd')+'</label><input class="form-input" type="password" name="currentPassword" required /></div><div style="display:flex; gap:16px; margin-bottom:16px;"><div class="form-group" style="flex:1;"><label class="form-label">'+t('newPwd')+'</label><input class="form-input" type="password" name="newPassword" minlength="12" required /></div><div class="form-group" style="flex:1;"><label class="form-label">'+t('confirmPwd')+'</label><input class="form-input" type="password" name="newPassword2" minlength="12" required /></div></div><button class="btn btn-danger" type="submit">'+t('changePwd')+'</button><div class="tiny" style="margin-top:8px;">After success, current sessions are revoked and you must log in again.</div></form></div>'
          + '<div class="panel"><h3 style="margin-top:0;">'+t('totpSetup')+'</h3><div style="display:flex; gap:24px; margin-bottom:24px; flex-wrap:wrap;"><div style="background:#fff; padding:16px; border:1px solid var(--border-color); border-radius:8px;"><img src="'+esc(qr)+'" alt="TOTP QR" style="display:block;" /></div><div style="flex:1; min-width:250px;"><form id="totpEnableForm"><div class="form-group"><label class="form-label">'+t('secret')+'</label><input class="form-input" name="secret" value="'+esc(secret)+'" /></div><div class="form-group"><label class="form-label">'+t('verifyCode')+'</label><input class="form-input" name="token" maxlength="6" value="'+esc(state.totpSetupToken)+'" /></div><div style="display:flex; gap:8px;"><button class="btn btn-primary" type="submit">'+t('enableTotp')+'</button><button class="btn btn-secondary" type="button" data-action="totp-secret-refresh">Regenerate</button><button class="btn btn-secondary" type="button" data-action="totp-secret-copy">Copy Secret</button></div></form></div></div><button class="btn btn-danger" type="button" data-action="totp-disable">'+t('disableTotp')+'</button><div class="tiny" style="margin-top:8px;">Disable action prompts for master password.</div></div>';
      }
      function renderTotpDisableModal(){
        if(!state.totpDisableOpen) return '';
        return ''
          + '<div class="totp-mask"><div class="totp-box"><h3 style="margin-top:0;">'+t('disableTotp')+'</h3><div class="tiny" style="margin-bottom:16px;">'+t('totpDisableSub')+'</div>'
          + (state.totpDisableError?'<div class="alert alert-danger" style="margin-bottom:16px;">'+esc(state.totpDisableError)+'</div>':'')
          + '<form id="totpDisableForm"><div class="form-group"><label class="form-label">'+t('masterPwd')+'</label><input class="form-input" type="password" name="masterPassword" value="'+esc(state.totpDisablePassword)+'" required autofocus /></div><div style="display:flex; gap:8px; margin-top:16px;"><button class="btn btn-danger" type="submit" style="flex:1;">'+t('disableTotp')+'</button><button class="btn btn-secondary" type="button" data-action="totp-disable-cancel" style="flex:1;">'+t('cancel')+'</button></div></form>'
          + '</div></div>';
      }

      function renderHelpTab(){
        return ''
          + '<h2 style="margin:0 0 24px 0; font-size:24px; font-weight:600; color:var(--text-primary);">'+t('help')+'</h2>'
          + '<div class="panel"><h3 style="margin-top:0;">'+t('helpSync')+'</h3><ul style="margin:0; padding-left:20px; color:var(--text-secondary); line-height:1.6;"><li>'+t('helpSync1')+'</li><li>'+t('helpSync2')+'</li><li>'+t('helpSync3')+'</li></ul></div>'
          + '<div class="panel"><h3 style="margin-top:0;">'+t('helpErr')+'</h3><ul style="margin:0; padding-left:20px; color:var(--text-secondary); line-height:1.6;"><li>'+t('helpErr1')+'</li><li>'+t('helpErr2')+'</li><li>'+t('helpErr3')+'</li><li>'+t('helpErr4')+'</li></ul></div>'
          + '<div class="panel"><h3 style="margin-top:0;">'+t('helpTb')+'</h3><ul style="margin:0; padding-left:20px; color:var(--text-secondary); line-height:1.6;"><li>'+t('helpTb1')+'</li><li>'+t('helpTb2')+'</li><li>'+t('helpTb3')+'</li><li>'+t('helpTb4')+'</li></ul></div>';
      }

      function renderAdminTab(){
        var usersRows='';
        for(var i=0;i<state.users.length;i++){
          var u=state.users[i]; var canAct=state.profile&&u.id!==state.profile.id;
          usersRows += '<tr><td>'+esc(u.email)+'</td><td>'+esc(u.name||'')+'</td><td><span class="badge">'+esc(u.role)+'</span></td><td><span class="badge '+(u.status==='active'?'success':'danger')+'">'+esc(u.status)+'</span></td><td>'
            + (canAct?'<button class="btn btn-secondary" data-action="user-toggle" data-id="'+esc(u.id)+'" data-status="'+esc(u.status)+'">'+(u.status==='active'?t('ban'):t('unban'))+'</button>':'')
            + (canAct?' <button class="btn btn-danger" data-action="user-delete" data-id="'+esc(u.id)+'">'+t('delete')+'</button>':'')
            + '</td></tr>';
        }
        if(!usersRows) usersRows='<tr><td colspan="5" style="text-align:center; color:var(--text-secondary); padding:24px;">No users found.</td></tr>';

        var inviteRows='';
        for(var j=0;j<state.invites.length;j++){
          var inv=state.invites[j];
          inviteRows += '<tr><td><code style="background:var(--bg-secondary); padding:4px 8px; border-radius:6px; font-size:13px;">'+esc(inv.code)+'</code></td><td><span class="badge '+(inv.status==='active'?'success':'danger')+'">'+esc(inv.status)+'</span></td><td>'+esc(inv.expiresAt)+'</td><td>'
            + '<button class="btn btn-secondary" data-action="invite-copy" data-link="'+esc(inv.inviteLink||'')+'">'+t('copyLink')+'</button>'
            + (inv.status==='active'?' <button class="btn btn-danger" data-action="invite-revoke" data-code="'+esc(inv.code)+'">'+t('revoke')+'</button>':'')
            + '</td></tr>';
        }
        if(!inviteRows) inviteRows='<tr><td colspan="4" style="text-align:center; color:var(--text-secondary); padding:24px;">No invites found.</td></tr>';

        return ''
          + renderMsg()
          + '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:24px;">'
          + '<h2 style="margin:0; font-size:24px; font-weight:600; color:var(--text-primary);">'+t('admin')+'</h2>'
          + '<button class="btn btn-secondary" data-action="admin-refresh">'+t('refresh')+'</button>'
          + '</div>'
          + '<div class="panel"><h3 style="margin-top:0;">'+t('createInvite')+'</h3><form id="inviteForm"><div class="form-group"><label class="form-label">'+t('expiresIn')+'</label><input class="form-input" name="hours" type="number" min="1" max="720" value="168" /></div><button class="btn btn-primary" type="submit">'+t('createInvite')+'</button></form></div>'
          + '<div class="panel"><h3 style="margin-top:0;">'+t('users')+'</h3><div style="overflow-x:auto;"><table class="table"><thead><tr><th>'+t('email')+'</th><th>'+t('name')+'</th><th>'+t('role')+'</th><th>'+t('status')+'</th><th>'+t('action')+'</th></tr></thead><tbody>'+usersRows+'</tbody></table></div></div>'
          + '<div class="panel"><h3 style="margin-top:0;">'+t('invites')+'</h3><div style="overflow-x:auto;"><table class="table"><thead><tr><th>Code</th><th>'+t('status')+'</th><th>Expires At</th><th>'+t('action')+'</th></tr></thead><tbody>'+inviteRows+'</tbody></table></div></div>';
      }

      function renderApp(){
        var isAdmin=state.profile&&state.profile.role==='admin';
        var showFolders=state.tab==='vault';
        var folders='<button class="btn folder-btn '+(!state.folderFilterId?'active':'')+'" data-action="folder-filter" data-folder="">'+t('allItems')+'</button>'
          + '<button class="btn folder-btn '+(state.folderFilterId===NO_FOLDER_FILTER?'active':'')+'" data-action="folder-filter" data-folder="'+NO_FOLDER_FILTER+'">'+t('noFolder')+'</button>';
        for(var i=0;i<state.folders.length;i++){ var f=state.folders[i]; var folderName=(f.decName||f.name||f.id); folders += '<button class="btn folder-btn '+(state.folderFilterId===f.id?'active':'')+' " data-action="folder-filter" data-folder="'+esc(f.id)+'">'+esc(folderName)+'</button>'; }
        var content = state.tab==='vault'?renderVaultTab():state.tab==='settings'?renderSettingsTab():(state.tab==='admin'&&isAdmin)?renderAdminTab():renderHelpTab();
        
        return ''
          + '<div class="navbar">'
          + '  <div class="nav-brand"><div class="nav-logo"></div>'+t('brand')+'</div>'
          + '  <div class="nav-links">'
          + '    <a href="#" class="nav-link '+(state.tab==='vault'?'active':'')+'" data-action="tab" data-tab="vault">'+t('vault')+'</a>'
          + '    <a href="#" class="nav-link '+(state.tab==='settings'?'active':'')+'" data-action="tab" data-tab="settings">'+t('settings')+'</a>'
          + (isAdmin?'<a href="#" class="nav-link '+(state.tab==='admin'?'active':'')+'" data-action="tab" data-tab="admin">'+t('admin')+'</a>':'')
          + '    <a href="#" class="nav-link '+(state.tab==='help'?'active':'')+'" data-action="tab" data-tab="help">'+t('help')+'</a>'
          + '  </div>'
          + '  <div class="nav-user">'
          + '    <div class="lang-switch" data-action="toggle-lang" style="position:static; margin-right:16px;">'+t('langSwitch')+'</div>'
          + '    <span style="margin-right:16px; color:var(--text-secondary);">'+esc(state.profile&&state.profile.email?state.profile.email:'')+'</span>'
          + '    <button class="btn btn-secondary" data-action="logout">'+t('logout')+'</button>'
          + '  </div>'
          + '</div>'
          + '<div class="app-body">'
          + (showFolders?('  <aside class="sidebar"><div class="sidebar-title">'+t('folders')+'</div><div style="display:flex; flex-direction:column; gap:4px;">'+folders+'</div></aside>'):'')
          + '  <main class="content">'+content+'</main>'
          + '</div>'+renderTotpDisableModal();
      }

      function render(){
        if(state.phase==='loading'){ app.innerHTML='<div class="auth-page" style="align-items:center; justify-content:center;"><div style="display:flex; flex-direction:column; align-items:center; gap:16px;"><div class="auth-logo" style="margin:0;"></div><div style="color:var(--text-secondary); font-weight:500;">'+t('loading')+'</div></div></div>'; return; }
        if(state.phase==='register'){ app.innerHTML=renderRegisterScreen(); return; }
        if(state.phase==='login'){ app.innerHTML=renderLoginScreen(); return; }
        app.innerHTML=renderApp();
      }

      async function init(){
        var url=new URL(window.location.href); state.inviteCode=(url.searchParams.get('invite')||'').trim(); state.session=loadSession();
        var st=await fetch('/setup/status'); var setup=await jsonOrNull(st); var registered=!!(setup&&setup.registered);
        if(state.session){
          try{ await loadProfile(); await loadVault(); await loadAdminData(); state.phase='app'; state.tab='vault'; render(); return; } catch(e){ state.session=null; saveSession(); }
        }
        state.phase=registered?'login':'register'; render();
      }

      async function onRegister(form){
        clearMsg();
        var fd=new FormData(form); var name=String(fd.get('name')||'').trim(); var email=String(fd.get('email')||'').trim().toLowerCase(); var p=String(fd.get('password')||''); var p2=String(fd.get('password2')||''); var invite=String(fd.get('inviteCode')||'').trim();
        state.registerName=name; state.registerEmail=email; state.registerPassword=p; state.registerPassword2=p2; state.inviteCode=invite;
        if(!email||!p) return setMsg('Please input email and password.', 'err');
        if(p.length<12) return setMsg('Master password must be at least 12 chars.', 'err');
        if(p!==p2) return setMsg('Passwords do not match.', 'err');
        try{
          var it=defaultKdfIterations; var mk=await pbkdf2(p,email,it,32); var hash=await pbkdf2(mk,p,1,32); var ek=await hkdfExpand(mk,'enc',32); var em=await hkdfExpand(mk,'mac',32); var sym=crypto.getRandomValues(new Uint8Array(64)); var encKey=await encryptBw(sym,ek,em);
          var kp=await crypto.subtle.generateKey({name:'RSA-OAEP', modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-1'}, true, ['encrypt','decrypt']);
          var pub=new Uint8Array(await crypto.subtle.exportKey('spki',kp.publicKey)); var prv=new Uint8Array(await crypto.subtle.exportKey('pkcs8',kp.privateKey)); var encPrv=await encryptBw(prv,sym.slice(0,32),sym.slice(32,64));
          var resp=await fetch('/api/accounts/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:email,name:name,masterPasswordHash:bytesToBase64(hash),key:encKey,kdf:0,kdfIterations:it,inviteCode:invite||undefined,keys:{publicKey:bytesToBase64(pub),encryptedPrivateKey:encPrv}})});
          var j=await jsonOrNull(resp); if(!resp.ok) return setMsg((j&&(j.error||j.error_description))||'Register failed.', 'err');
          state.registerName=''; state.registerEmail=''; state.registerPassword=''; state.registerPassword2=''; state.inviteCode='';
          state.phase='login'; state.loginEmail=email; state.loginPassword=''; setMsg('Registration succeeded. Please sign in.', 'ok');
        }catch(e){ setMsg(e&&e.message?e.message:String(e), 'err'); }
      }

      async function onLoginPassword(form){
        clearMsg();
        var fd=new FormData(form); state.loginEmail=String(fd.get('email')||'').trim().toLowerCase(); state.loginPassword=String(fd.get('password')||'');
        if(!state.loginEmail||!state.loginPassword) return setMsg('Please input email and password.', 'err');
        try{
          var d=await deriveLoginHash(state.loginEmail,state.loginPassword);
          var body=new URLSearchParams(); body.set('grant_type','password'); body.set('username',state.loginEmail); body.set('password',d.hash); body.set('scope','api offline_access');
          var resp=await fetch('/identity/connect/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body.toString()});
          var j=await jsonOrNull(resp);
          if(!resp.ok){
            if(j&&j.TwoFactorProviders){ state.pendingLogin={email:state.loginEmail,passwordHash:d.hash,masterKey:d.masterKey}; state.loginTotpToken=''; state.loginTotpError=''; clearMsg(); render(); return; }
            return setMsg((j&&(j.error_description||j.error))||'Login failed.', 'err');
          }
          await onLoginSuccess(j,d.masterKey,state.loginEmail,state.loginPassword);
        }catch(e){ setMsg(e&&e.message?e.message:String(e), 'err'); }
      }

      async function onLoginTotp(form){
        if(!state.pendingLogin) return setMsg('TOTP flow is not ready.', 'err');
        var fd=new FormData(form); state.loginTotpToken=String(fd.get('totpToken')||'').trim(); if(!state.loginTotpToken){ state.loginTotpError='Please input TOTP code.'; render(); return; }
        var b=new URLSearchParams(); b.set('grant_type','password'); b.set('username',state.pendingLogin.email); b.set('password',state.pendingLogin.passwordHash); b.set('scope','api offline_access'); b.set('twoFactorProvider','0'); b.set('twoFactorToken',state.loginTotpToken);
        var resp=await fetch('/identity/connect/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b.toString()});
        var j=await jsonOrNull(resp); if(!resp.ok){ state.loginTotpError=(j&&(j.error_description||j.error))||'TOTP verification failed.'; render(); return; }
        state.loginTotpError='';
        await onLoginSuccess(j,state.pendingLogin.masterKey,state.pendingLogin.email,state.loginPassword);
      }

      async function onLoginSuccess(tokenJson, masterKey, email, password){
        state.session={accessToken:tokenJson.access_token,refreshToken:tokenJson.refresh_token,email:email}; saveSession(); state.pendingLogin=null; state.loginTotpToken=''; state.loginTotpError='';
        await loadProfile();
        try{
          var ek=await hkdfExpand(masterKey,'enc',32); var em=await hkdfExpand(masterKey,'mac',32);
          var symKeyBytes=await decryptBw(state.profile.key,ek,em);
          if(symKeyBytes){ state.session.symEncKey=bytesToBase64(symKeyBytes.slice(0,32)); state.session.symMacKey=bytesToBase64(symKeyBytes.slice(32,64)); saveSession(); }
        }catch(e){ console.warn('Key derivation failed:',e); }
        await loadVault(); await loadAdminData(); state.phase='app'; state.tab='vault';
        setMsg('Login success.', 'ok');
      }
      async function onSaveProfile(form){ var fd=new FormData(form); var n=String(fd.get('name')||'').trim(); var em=String(fd.get('email')||'').trim().toLowerCase(); var r=await authFetch('/api/accounts/profile',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:n,email:em})}); var j=await jsonOrNull(r); if(!r.ok) return setMsg((j&&(j.error||j.error_description))||'Save profile failed.', 'err'); state.profile=j; render(); setMsg('Profile updated.', 'ok'); }
      async function onChangePassword(form){
        var fd=new FormData(form);
        var currentPassword=String(fd.get('currentPassword')||'');
        var newPassword=String(fd.get('newPassword')||'');
        var newPassword2=String(fd.get('newPassword2')||'');
        if(!currentPassword||!newPassword) return setMsg('Current/new password is required.', 'err');
        if(newPassword.length<12) return setMsg('New master password must be at least 12 chars.', 'err');
        if(newPassword!==newPassword2) return setMsg('New passwords do not match.', 'err');
        if(newPassword===currentPassword) return setMsg('New password must be different.', 'err');
        var email=String(state.profile&&state.profile.email?state.profile.email:'').toLowerCase();
        if(!email) return setMsg('Profile email missing.', 'err');
        try{
          var current=await deriveLoginHash(email,currentPassword);
          var userSym=buildSymmetricKeyBytes();
          if(!userSym){
            var oldEk=await hkdfExpand(current.masterKey,'enc',32);
            var oldEm=await hkdfExpand(current.masterKey,'mac',32);
            userSym=await decryptBw(state.profile.key,oldEk,oldEm);
          }
          if(!userSym||userSym.length<64) return setMsg('Unable to load vault key for password rotation.', 'err');
          var nextMasterKey=await pbkdf2(newPassword,email,current.kdfIterations,32);
          var nextHash=await pbkdf2(nextMasterKey,newPassword,1,32);
          var nextEk=await hkdfExpand(nextMasterKey,'enc',32);
          var nextEm=await hkdfExpand(nextMasterKey,'mac',32);
          var newKey=await encryptBw(userSym.slice(0,64),nextEk,nextEm);
          var r=await authFetch('/api/accounts/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({currentPasswordHash:current.hash,newMasterPasswordHash:bytesToBase64(nextHash),newKey:newKey,kdf:0,kdfIterations:current.kdfIterations})});
          var j=await jsonOrNull(r);
          if(!r.ok) return setMsg((j&&(j.error||j.error_description))||'Change master password failed.', 'err');
          logout();
          setMsg('Master password changed. Please log in again.', 'ok');
        }catch(e){
          setMsg('Change master password failed: '+(e&&e.message?e.message:String(e)), 'err');
        }
      }
      async function onEnableTotp(form){ var fd=new FormData(form); state.totpSetupSecret=String(fd.get('secret')||'').toUpperCase().replace(/[\\s-]/g,'').replace(/=+$/g,''); state.totpSetupToken=String(fd.get('token')||'').trim(); if(!state.totpSetupSecret) return setMsg('TOTP secret is required.', 'err'); if(!state.totpSetupToken) return setMsg('TOTP token is required.', 'err'); var r=await authFetch('/api/accounts/totp',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:true,secret:state.totpSetupSecret,token:state.totpSetupToken})}); var j=await jsonOrNull(r); if(!r.ok) return setMsg((j&&(j.error||j.error_description))||'Enable TOTP failed.', 'err'); state.totpSetupToken=''; render(); setMsg('TOTP enabled.', 'ok'); }
      function onDisableTotp(){ state.totpDisableOpen=true; state.totpDisablePassword=''; state.totpDisableError=''; render(); }
      async function onDisableTotpSubmit(form){
        var fd=new FormData(form); state.totpDisablePassword=String(fd.get('masterPassword')||'');
        if(!state.totpDisablePassword){ state.totpDisableError='Please input master password.'; render(); return; }
        try{
          var d=await deriveLoginHash(state.profile.email,state.totpDisablePassword);
          var r=await authFetch('/api/accounts/totp',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:false,masterPasswordHash:d.hash})});
          var j=await jsonOrNull(r);
          if(!r.ok){ state.totpDisableError=(j&&(j.error||j.error_description))||'Disable TOTP failed.'; render(); return; }
          state.totpDisableOpen=false; state.totpDisablePassword=''; state.totpDisableError='';
          render(); setMsg('TOTP disabled.', 'ok');
        }catch(e){
          state.totpDisableError='Disable TOTP failed: '+(e&&e.message?e.message:String(e));
          render();
        }
      }

      async function onBulkDelete(){ var ids=[]; for(var k in state.selectedMap){ if(state.selectedMap[k]) ids.push(k);} if(ids.length===0) return setMsg('Select items first.', 'err'); if(!window.confirm('Delete selected '+ids.length+' items?')) return; for(var i=0;i<ids.length;i++) await authFetch('/api/ciphers/'+encodeURIComponent(ids[i]),{method:'DELETE'}); state.selectedMap={}; await loadVault(); render(); setMsg('Deleted selected items.', 'ok'); }
      async function onBulkMove(){ var ids=[]; for(var k in state.selectedMap){ if(state.selectedMap[k]) ids.push(k);} if(ids.length===0) return setMsg('Select items first.', 'err'); var opts=['0) No folder']; for(var i=0;i<state.folders.length;i++){ var f=state.folders[i]; var label=(f.decName||f.name||f.id); opts.push(String(i+1)+') '+String(label)); } var pick=window.prompt('Move selected items to:\\n'+opts.join('\\n')+'\\n\\nInput number (empty to cancel):','0'); if(pick===null) return; pick=String(pick).trim(); if(!pick) return; var idx=Number(pick); if(!Number.isInteger(idx)||idx<0||idx>state.folders.length) return setMsg('Invalid folder selection.', 'err'); var folderId=idx===0?null:state.folders[idx-1].id; var r=await authFetch('/api/ciphers/move',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids:ids,folderId:folderId})}); var j=await jsonOrNull(r); if(!r.ok) return setMsg((j&&(j.error||j.error_description))||'Bulk move failed.', 'err'); await loadVault(); render(); setMsg('Moved selected items.', 'ok'); }

      async function onCreateInvite(form){ var fd=new FormData(form); var h=Number(fd.get('hours')||168); var r=await authFetch('/api/admin/invites',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({expiresInHours:h})}); var j=await jsonOrNull(r); if(!r.ok) return setMsg((j&&(j.error||j.error_description))||'Create invite failed.', 'err'); await loadAdminData(); render(); setMsg('Invite created.', 'ok'); }
      async function onToggleUserStatus(id,status){ var n=status==='active'?'banned':'active'; var r=await authFetch('/api/admin/users/'+encodeURIComponent(id)+'/status',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:n})}); var j=await jsonOrNull(r); if(!r.ok) return setMsg((j&&(j.error||j.error_description))||'Update user status failed.', 'err'); await loadAdminData(); render(); setMsg('User status updated.', 'ok'); }
      async function onDeleteUser(id){ if(!window.confirm('Delete this user and all user data?')) return; var r=await authFetch('/api/admin/users/'+encodeURIComponent(id),{method:'DELETE'}); var j=await jsonOrNull(r); if(!r.ok) return setMsg((j&&(j.error||j.error_description))||'Delete user failed.', 'err'); await loadAdminData(); render(); setMsg('User deleted.', 'ok'); }
      async function onRevokeInvite(code){ var r=await authFetch('/api/admin/invites/'+encodeURIComponent(code),{method:'DELETE'}); var j=await jsonOrNull(r); if(!r.ok) return setMsg((j&&(j.error||j.error_description))||'Revoke invite failed.', 'err'); await loadAdminData(); render(); setMsg('Invite revoked.', 'ok'); }

      app.addEventListener('submit', function(ev){
        var form=ev.target; if(!(form instanceof HTMLFormElement)) return; ev.preventDefault();
        if(form.id==='registerForm') return void onRegister(form);
        if(form.id==='loginForm') return void onLoginPassword(form);
        if(form.id==='loginTotpForm') return void onLoginTotp(form);
        if(form.id==='profileForm') return void onSaveProfile(form);
        if(form.id==='passwordForm') return void onChangePassword(form);
        if(form.id==='totpEnableForm') return void onEnableTotp(form);
        if(form.id==='totpDisableForm') return void onDisableTotpSubmit(form);
        if(form.id==='inviteForm') return void onCreateInvite(form);
      });

      app.addEventListener('click', function(ev){
        var n=ev.target; while(n&&n!==app&&!n.getAttribute('data-action')) n=n.parentElement; if(!n||n===app) return; var a=n.getAttribute('data-action'); if(!a) return;
        if(a==='toggle-lang'){ state.lang = state.lang === 'zh' ? 'en' : 'zh'; render(); return; }
        if(a==='goto-login'){ state.phase='login'; clearMsg(); render(); return; }
        if(a==='goto-register'){ state.phase='register'; clearMsg(); render(); return; }
        if(a==='logout'){ if(window.confirm('Log out now?')) logout(); return; }
        if(a==='totp-cancel'){ state.pendingLogin=null; state.loginTotpToken=''; state.loginTotpError=''; render(); return; }
        if(a==='totp-disable-cancel'){ state.totpDisableOpen=false; state.totpDisablePassword=''; state.totpDisableError=''; render(); return; }
        if(a==='tab'){ state.tab=n.getAttribute('data-tab')||'vault'; clearMsg(); render(); return; }
        if(a==='folder-filter'){ state.folderFilterId=n.getAttribute('data-folder')||''; var filtered=filteredCiphers(); state.selectedCipherId=filtered.length?filtered[0].id:''; render(); return; }
        if(a==='pick-cipher'){ state.selectedCipherId=n.getAttribute('data-id')||''; render(); return; }
        if(a==='toggle-select'){ ev.stopPropagation(); state.selectedMap[n.getAttribute('data-id')]=!!n.checked; render(); return; }
        if(a==='select-all'){ var list=filteredCiphers(); state.selectedMap={}; for(var i=0;i<list.length;i++) state.selectedMap[list[i].id]=true; render(); return; }
        if(a==='select-none'){ state.selectedMap={}; render(); return; }
        if(a==='bulk-delete') return void onBulkDelete();
        if(a==='bulk-move') return void onBulkMove();
        if(a==='vault-refresh'){ loadVault().then(function(){ render(); setMsg('Vault refreshed.', 'ok'); }).catch(function(e){ setMsg('Refresh failed: '+(e&&e.message?e.message:String(e)), 'err'); }); return; }
        if(a==='totp-secret-refresh'){ state.totpSetupSecret=randomBase32Secret(32); render(); return; }
        if(a==='totp-secret-copy'){ navigator.clipboard.writeText(currentTotpSecret()).then(function(){ setMsg('TOTP secret copied.', 'ok'); }).catch(function(){ setMsg('Copy failed.', 'err'); }); return; }
        if(a==='totp-disable'){ onDisableTotp(); return; }
        if(a==='admin-refresh'){ loadAdminData().then(function(){ render(); setMsg('Admin data refreshed.', 'ok'); }).catch(function(e){ setMsg('Refresh failed: '+(e&&e.message?e.message:String(e)), 'err'); }); return; }
        if(a==='user-toggle') return void onToggleUserStatus(n.getAttribute('data-id'),n.getAttribute('data-status'));
        if(a==='user-delete') return void onDeleteUser(n.getAttribute('data-id'));
        if(a==='invite-revoke') return void onRevokeInvite(n.getAttribute('data-code'));
        if(a==='invite-copy'){ var link=n.getAttribute('data-link')||''; navigator.clipboard.writeText(link).then(function(){ setMsg('Invite link copied.', 'ok'); }).catch(function(){ setMsg('Copy failed.', 'err'); }); return; }
      });

      init();
    })();

`;
}

