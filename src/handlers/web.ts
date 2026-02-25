import { Env } from '../types';
import { htmlResponse } from '../utils/response';
import { LIMITS } from '../config/limits';

function renderWebClientHTML(): string {
  const defaultKdfIterations = LIMITS.auth.defaultKdfIterations;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>NodeWarden Web</title>
  <style>
    :root {
      --bg: #f4f0e7;
      --bg2: #e9f1ec;
      --panel: #fffdf8;
      --line: #d7ccbb;
      --text: #1f1710;
      --muted: #6a5f52;
      --primary: #a63c2b;
      --primary2: #1f6b5a;
      --danger: #a53024;
      --ok: #0f7a3d;
    }
    * { box-sizing: border-box; }
    html, body { height: 100%; }
    body {
      margin: 0;
      color: var(--text);
      font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
      background:
        radial-gradient(circle at 12% 14%, #f6ddaf 0%, transparent 35%),
        radial-gradient(circle at 84% 20%, #d5efe4 0%, transparent 33%),
        linear-gradient(155deg, var(--bg) 0%, var(--bg2) 100%);
    }
    #app { min-height: 100%; }
    .shell { min-height: 100%; padding: 10px; }
    .auth {
      min-height: calc(100vh - 20px);
      border: 1px solid var(--line);
      border-radius: 18px;
      background: var(--panel);
      box-shadow: 0 20px 46px rgba(26, 18, 12, 0.12);
      display: grid;
      grid-template-columns: 360px 1fr;
      overflow: hidden;
    }
    .auth-left {
      border-right: 1px solid var(--line);
      padding: 24px;
      background: #fff8eb;
    }
    .brand {
      width: 58px;
      height: 58px;
      border-radius: 13px;
      background: #111;
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      margin-bottom: 14px;
      user-select: none;
    }
    .auth-left h1 { margin: 0; font-size: 30px; }
    .auth-left p { margin: 10px 0 0 0; color: var(--muted); line-height: 1.7; font-size: 14px; }
    .auth-right { padding: 24px; position: relative; }
    .section-title { margin: 0 0 12px 0; font-size: 28px; }
    .msg {
      margin-bottom: 12px;
      border-radius: 10px;
      border: 1px solid var(--line);
      padding: 10px 12px;
      font-size: 13px;
      background: #fff;
    }
    .msg.ok { color: var(--ok); border-color: #9dd2b6; background: #f0fbf4; }
    .msg.err { color: var(--danger); border-color: #f2b4a9; background: #fff5f2; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .field { margin-bottom: 10px; }
    .field label { display: block; margin-bottom: 6px; color: var(--muted); font-size: 13px; }
    .field input, .field select, .field textarea {
      width: 100%;
      min-height: 44px;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #fffdf8;
      color: var(--text);
      padding: 0 12px;
      font-size: 14px;
    }
    .field textarea {
      min-height: 90px;
      padding-top: 10px;
      padding-bottom: 10px;
      resize: vertical;
    }
    .actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
    .btn {
      border: 1px solid #b8ad9c;
      background: #f4ede3;
      color: var(--text);
      border-radius: 10px;
      min-height: 40px;
      padding: 0 12px;
      font-weight: 700;
      cursor: pointer;
    }
    .btn.primary { border-color: #8f3124; background: var(--primary); color: #fff; }
    .btn.secondary { border-color: #1b594c; background: var(--primary2); color: #fff; }
    .btn.danger { border-color: #7f261d; background: var(--danger); color: #fff; }
    .tiny { font-size: 12px; color: var(--muted); }
    .totp-mask {
      position: absolute;
      inset: 0;
      background: rgba(22, 17, 12, 0.48);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 16px;
    }
    .totp-box {
      width: min(460px, 100%);
      border: 1px solid var(--line);
      border-radius: 14px;
      background: #fff;
      padding: 16px;
      box-shadow: 0 18px 30px rgba(0, 0, 0, 0.2);
    }
    .totp-box h3 { margin: 0 0 8px 0; font-size: 20px; }
    .app-layout {
      min-height: calc(100vh - 20px);
      border: 1px solid var(--line);
      border-radius: 18px;
      background: var(--panel);
      box-shadow: 0 16px 40px rgba(26, 18, 12, 0.12);
      overflow: hidden;
      display: grid;
    }
    .app-layout.normal-layout { grid-template-columns: 250px 1fr; }
    .app-layout.vault-layout { grid-template-columns: 250px 260px 1fr; }
    .sidebar, .folderbar {
      border-right: 1px solid var(--line);
      padding: 14px;
      background: #fff8eb;
      min-width: 0;
    }
    .folderbar { background: #fffaf1; }
    .sidebar .brand { width: 50px; height: 50px; margin-bottom: 8px; }
    .sidebar .mail { font-size: 12px; color: var(--muted); margin-bottom: 10px; word-break: break-all; }
    .nav-btn, .folder-btn { width: 100%; text-align: left; margin-bottom: 8px; }
    .nav-btn.active { border-color: #8f3124; background: #fff2ea; color: #7f271c; }
    .folder-btn { margin-bottom: 6px; font-size: 13px; }
    .folder-btn.active { border-color: #1b594c; background: #e9f6f0; color: #184f43; }
    .content { padding: 12px; min-width: 0; overflow: auto; }
    .panel {
      border: 1px solid var(--line);
      border-radius: 12px;
      background: #fff;
      padding: 12px;
      margin-bottom: 12px;
    }
    .panel h3 { margin: 0 0 10px 0; font-size: 18px; }
    .vault-grid { display: grid; grid-template-columns: 1.1fr 1fr; gap: 12px; }
    .list {
      border: 1px solid var(--line);
      border-radius: 10px;
      max-height: calc(100vh - 280px);
      overflow: auto;
      background: #fff;
    }
    .item {
      border-bottom: 1px solid var(--line);
      padding: 9px 10px;
      display: grid;
      grid-template-columns: 26px 1fr;
      gap: 8px;
      align-items: center;
      cursor: pointer;
    }
    .item:last-child { border-bottom: none; }
    .item.active { background: #fff2ea; }
    .kv {
      margin-bottom: 7px;
      font-size: 13px;
      line-height: 1.55;
      word-break: break-word;
    }
    .kv b { color: var(--muted); margin-right: 6px; }
    .table {
      width: 100%;
      border-collapse: collapse;
      border: 1px solid var(--line);
      border-radius: 10px;
      overflow: hidden;
      font-size: 13px;
      background: #fff;
    }
    .table th, .table td {
      border-bottom: 1px solid var(--line);
      padding: 8px;
      text-align: left;
      vertical-align: middle;
    }
    .table tr:last-child td { border-bottom: none; }
    .qr-row { display: grid; grid-template-columns: 190px 1fr; gap: 12px; align-items: start; }
    .qr-box { border: 1px solid var(--line); border-radius: 10px; padding: 8px; background: #fff; }
    .qr-box img { width: 170px; height: 170px; display: block; object-fit: contain; background: #fff; }
    .help-box { border: 1px solid var(--line); border-radius: 10px; background: #fff; padding: 12px; margin-bottom: 10px; }
    .help-box h4 { margin: 0 0 8px 0; font-size: 15px; }
    .help-box ul { margin: 0; padding-left: 18px; line-height: 1.65; font-size: 13px; color: #3f352c; }
    @media (max-width: 1080px) {
      .auth { grid-template-columns: 1fr; }
      .auth-left { border-right: none; border-bottom: 1px solid var(--line); }
      .app-layout { grid-template-columns: 1fr; }
      .sidebar, .folderbar { border-right: none; border-bottom: 1px solid var(--line); }
      .vault-grid { grid-template-columns: 1fr; }
      .row { grid-template-columns: 1fr; }
      .qr-row { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div id="app"></div>
  <script>
    (function () {
      var app = document.getElementById('app');
      var defaultKdfIterations = ${defaultKdfIterations};
      var state = {
        phase: 'loading',
        msg: '',
        msgType: 'ok',
        inviteCode: '',
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

      function esc(v) {
        return String(v == null ? '' : v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
      }
      function sessionKey() { return 'nodewarden.web.session.v2'; }
      function setMsg(t, ty) { state.msg = t || ''; state.msgType = ty || 'ok'; render(); }
      function clearMsg() { state.msg = ''; }
      function renderMsg() { return state.msg ? '<div class="msg ' + (state.msgType === 'err' ? 'err' : 'ok') + '">' + esc(state.msg) + '</div>' : ''; }
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
        return { hash: bytesToBase64(h), masterKey: mk };
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
      function renderLoginScreen(){
        return ''
          + '<div class="shell"><div class="auth">'
          + '  <aside class="auth-left"><div class="brand">NW</div><h1>NodeWarden Web</h1><p>Password errors keep email/password fields. If 2FA is enabled, password step is done once and TOTP is entered in modal only.</p></aside>'
          + '  <main class="auth-right"><h2 class="section-title">Sign In</h2>'
          +      renderMsg()
          + '    <form id="loginForm">'
          + '      <div class="field"><label>Email</label><input type="email" name="email" value="'+esc(state.loginEmail)+'" required /></div>'
          + '      <div class="field"><label>Master Password</label><input type="password" name="password" value="'+esc(state.loginPassword)+'" required /></div>'
          + '      <div class="actions"><button class="btn primary" type="submit">Login</button><button class="btn" type="button" data-action="goto-register">Register</button></div>'
          + '    </form>'
          + (state.pendingLogin ? ''
            + '<div class="totp-mask"><div class="totp-box"><h3>Two-step verification</h3><div class="tiny">Password is already verified.</div>'
            + (state.loginTotpError?'<div class="msg err" style="margin-top:8px;">'+esc(state.loginTotpError)+'</div>':'')
            + '<form id="loginTotpForm"><div class="field"><label>TOTP Code</label><input name="totpToken" maxlength="6" value="'+esc(state.loginTotpToken)+'" required /></div><div class="actions"><button class="btn primary" type="submit">Verify</button><button class="btn" type="button" data-action="totp-cancel">Cancel</button></div></form>'
            + '</div></div>'
            : '')
          + '  </main>'
          + '</div></div>';
      }

      function renderRegisterScreen(){
        return ''
          + '<div class="shell"><div class="auth">'
          + '  <aside class="auth-left"><div class="brand">NW</div><h1>NodeWarden Web</h1><p>First account becomes admin. Later accounts require invite code.</p></aside>'
          + '  <main class="auth-right"><h2 class="section-title">Register</h2>'
          +      renderMsg()
          + '    <form id="registerForm">'
          + '      <div class="row"><div class="field"><label>Name</label><input name="name" required /></div><div class="field"><label>Email</label><input type="email" name="email" required /></div></div>'
          + '      <div class="field"><label>Master Password</label><input type="password" name="password" minlength="12" required /></div>'
          + '      <div class="field"><label>Confirm Password</label><input type="password" name="password2" minlength="12" required /></div>'
          + '      <div class="field"><label>Invite Code</label><input name="inviteCode" value="'+esc(state.inviteCode)+'" /></div>'
          + '      <div class="actions"><button class="btn primary" type="submit">Create Account</button><button class="btn" type="button" data-action="goto-login">Back to Login</button></div>'
          + '    </form>'
          + '  </main>'
          + '</div></div>';
      }

      function renderVaultTab(){
        var list=filteredCiphers();
        var rows='';
        for(var i=0;i<list.length;i++){
          var c=list[i];
          var nameText=(c.decName||c.name||c.id);
          rows += '<div class="item '+(c.id===state.selectedCipherId?'active':'')+'" data-action="pick-cipher" data-id="'+esc(c.id)+'"><input type="checkbox" data-action="toggle-select" data-id="'+esc(c.id)+'"'+(state.selectedMap[c.id]?' checked':'')+' /><div><div style="font-weight:700;font-size:14px;">'+esc(nameText)+'</div><div class="tiny">'+esc(c.id)+'</div></div></div>';
        }
        if(!rows) rows='<div class="item"><div></div><div class="tiny">No items in this folder.</div></div>';

        var c0=selectedCipher();
        var detail='<div class="tiny">Select an item to view details.</div>';
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
          + '<div class="panel"><h3>Vault</h3>'
          + '<div class="actions"><button class="btn" data-action="vault-refresh">Refresh</button><button class="btn" data-action="bulk-move">Move Selected</button><button class="btn danger" data-action="bulk-delete">Delete Selected ('+selectedCount()+')</button><button class="btn" data-action="select-all">Select all</button><button class="btn" data-action="select-none">Clear</button></div>'
          + '<div class="vault-grid" style="margin-top:10px;"><div class="list">'+rows+'</div><div class="panel" style="margin:0;">'+detail+'</div></div>'
          + '</div>';
      }

      function renderSettingsTab(){
        var p=state.profile||{};
        var secret=currentTotpSecret();
        var qr='https://api.qrserver.com/v1/create-qr-code/?size=180x180&data='+encodeURIComponent(buildTotpUri(secret));
        return ''
          + renderMsg()
          + '<div class="panel"><h3>Profile</h3><form id="profileForm"><div class="row"><div class="field"><label>Name</label><input name="name" value="'+esc(p.name||'')+'" /></div><div class="field"><label>Email</label><input type="email" name="email" value="'+esc(p.email||'')+'" required /></div></div><div class="actions"><button class="btn primary" type="submit">Save Profile</button></div></form></div>'
          + '<div class="panel"><h3>TOTP Setup</h3><div class="qr-row"><div class="qr-box"><img src="'+esc(qr)+'" alt="TOTP QR" /></div><div><form id="totpEnableForm"><div class="field"><label>Secret (Base32)</label><input name="secret" value="'+esc(secret)+'" /></div><div class="field"><label>Verification Code</label><input name="token" maxlength="6" value="'+esc(state.totpSetupToken)+'" /></div><div class="actions"><button class="btn secondary" type="submit">Enable TOTP</button><button class="btn" type="button" data-action="totp-secret-refresh">Regenerate</button><button class="btn" type="button" data-action="totp-secret-copy">Copy Secret</button></div></form></div></div><div class="actions"><button class="btn danger" type="button" data-action="totp-disable">Disable TOTP</button></div><div class="tiny">Disable action prompts for master password.</div></div>';
      }
      function renderTotpDisableModal(){
        if(!state.totpDisableOpen) return '';
        return ''
          + '<div class="totp-mask"><div class="totp-box"><h3>Disable TOTP</h3><div class="tiny">Enter master password to disable two-step verification.</div>'
          + (state.totpDisableError?'<div class="msg err" style="margin-top:8px;">'+esc(state.totpDisableError)+'</div>':'')
          + '<form id="totpDisableForm"><div class="field"><label>Master Password</label><input type="password" name="masterPassword" value="'+esc(state.totpDisablePassword)+'" required /></div><div class="actions"><button class="btn danger" type="submit">Disable</button><button class="btn" type="button" data-action="totp-disable-cancel">Cancel</button></div></form>'
          + '</div></div>';
      }

      function renderHelpTab(){
        return ''
          + '<div class="help-box"><h4>Upstream Sync</h4><ul><li>Use fork + GitHub Actions scheduled sync.</li><li>Or use manual Sync fork from repository page.</li><li>Deploy updated branch in Cloudflare Worker after sync.</li></ul></div>'
          + '<div class="help-box"><h4>Common Errors</h4><ul><li>401 Unauthorized: login again.</li><li>429 Too many requests: wait and retry.</li><li>403 Invite invalid: check invite status and expiry.</li><li>Disabled user cannot login.</li></ul></div>';
      }

      function renderAdminTab(){
        var usersRows='';
        for(var i=0;i<state.users.length;i++){
          var u=state.users[i]; var canAct=state.profile&&u.id!==state.profile.id;
          usersRows += '<tr><td>'+esc(u.email)+'</td><td>'+esc(u.name||'')+'</td><td>'+esc(u.role)+'</td><td>'+esc(u.status)+'</td><td>'
            + (canAct?'<button class="btn" data-action="user-toggle" data-id="'+esc(u.id)+'" data-status="'+esc(u.status)+'">'+(u.status==='active'?'Ban':'Unban')+'</button>':'')
            + (canAct?' <button class="btn danger" data-action="user-delete" data-id="'+esc(u.id)+'">Delete</button>':'')
            + '</td></tr>';
        }
        if(!usersRows) usersRows='<tr><td colspan="5">No users.</td></tr>';

        var inviteRows='';
        for(var j=0;j<state.invites.length;j++){
          var inv=state.invites[j];
          inviteRows += '<tr><td>'+esc(inv.code)+'</td><td>'+esc(inv.status)+'</td><td>'+esc(inv.expiresAt)+'</td><td>'
            + '<button class="btn" data-action="invite-copy" data-link="'+esc(inv.inviteLink||'')+'">Copy link</button>'
            + (inv.status==='active'?' <button class="btn danger" data-action="invite-revoke" data-code="'+esc(inv.code)+'">Revoke</button>':'')
            + '</td></tr>';
        }
        if(!inviteRows) inviteRows='<tr><td colspan="4">No invites.</td></tr>';

        return ''
          + renderMsg()
          + '<div class="panel"><h3>Create Invite</h3><form id="inviteForm"><div class="field"><label>Expires in hours</label><input name="hours" type="number" min="1" max="720" value="168" /></div><div class="actions"><button class="btn primary" type="submit">Create Invite</button><button class="btn" type="button" data-action="admin-refresh">Refresh</button></div></form></div>'
          + '<div class="panel"><h3>Users</h3><table class="table"><thead><tr><th>Email</th><th>Name</th><th>Role</th><th>Status</th><th>Action</th></tr></thead><tbody>'+usersRows+'</tbody></table></div>'
          + '<div class="panel"><h3>Invites</h3><table class="table"><thead><tr><th>Code</th><th>Status</th><th>Expires At</th><th>Action</th></tr></thead><tbody>'+inviteRows+'</tbody></table></div>';
      }

      function renderApp(){
        var isAdmin=state.profile&&state.profile.role==='admin';
        var showFolders=state.tab==='vault';
        var folders='<button class="btn folder-btn '+(!state.folderFilterId?'active':'')+'" data-action="folder-filter" data-folder="">All items</button>'
          + '<button class="btn folder-btn '+(state.folderFilterId===NO_FOLDER_FILTER?'active':'')+'" data-action="folder-filter" data-folder="'+NO_FOLDER_FILTER+'">无文件夹</button>';
        for(var i=0;i<state.folders.length;i++){ var f=state.folders[i]; var folderName=(f.decName||f.name||f.id); folders += '<button class="btn folder-btn '+(state.folderFilterId===f.id?'active':'')+' " data-action="folder-filter" data-folder="'+esc(f.id)+'">'+esc(folderName)+'</button>'; }
        var content = state.tab==='vault'?renderVaultTab():state.tab==='settings'?renderSettingsTab():(state.tab==='admin'&&isAdmin)?renderAdminTab():renderHelpTab();
        var layoutClass=showFolders?'vault-layout':'normal-layout';
        return ''
          + '<div class="shell"><div class="app-layout '+layoutClass+'">'
          + '  <aside class="sidebar"><div class="brand">NW</div><div class="mail">'+esc(state.profile&&state.profile.email?state.profile.email:'')+'</div>'
          + '    <button class="btn nav-btn '+(state.tab==='vault'?'active':'')+'" data-action="tab" data-tab="vault">Vault</button>'
          + '    <button class="btn nav-btn '+(state.tab==='settings'?'active':'')+'" data-action="tab" data-tab="settings">Settings</button>'
          + (isAdmin?'<button class="btn nav-btn '+(state.tab==='admin'?'active':'')+'" data-action="tab" data-tab="admin">User Management</button>':'')
          + '    <button class="btn nav-btn '+(state.tab==='help'?'active':'')+'" data-action="tab" data-tab="help">Help</button>'
          + '    <button class="btn nav-btn" data-action="logout">Logout</button></aside>'
          + (showFolders?('  <aside class="folderbar"><h3 style="margin:0 0 10px 0;">Folders</h3>'+folders+'</aside>'):'')
          + '  <main class="content">'+content+'</main>'
          + '</div>'+renderTotpDisableModal()+'</div>';
      }

      function render(){
        if(state.phase==='loading'){ app.innerHTML='<div class="shell"><div class="panel"><h3>Loading...</h3></div></div>'; return; }
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
        if(!email||!p) return setMsg('Please input email and password.', 'err');
        if(p.length<12) return setMsg('Master password must be at least 12 chars.', 'err');
        if(p!==p2) return setMsg('Passwords do not match.', 'err');
        try{
          var it=defaultKdfIterations; var mk=await pbkdf2(p,email,it,32); var hash=await pbkdf2(mk,p,1,32); var ek=await hkdfExpand(mk,'enc',32); var em=await hkdfExpand(mk,'mac',32); var sym=crypto.getRandomValues(new Uint8Array(64)); var encKey=await encryptBw(sym,ek,em);
          var kp=await crypto.subtle.generateKey({name:'RSA-OAEP', modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-1'}, true, ['encrypt','decrypt']);
          var pub=new Uint8Array(await crypto.subtle.exportKey('spki',kp.publicKey)); var prv=new Uint8Array(await crypto.subtle.exportKey('pkcs8',kp.privateKey)); var encPrv=await encryptBw(prv,sym.slice(0,32),sym.slice(32,64));
          var resp=await fetch('/api/accounts/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:email,name:name,masterPasswordHash:bytesToBase64(hash),key:encKey,kdf:0,kdfIterations:it,inviteCode:invite||undefined,keys:{publicKey:bytesToBase64(pub),encryptedPrivateKey:encPrv}})});
          var j=await jsonOrNull(resp); if(!resp.ok) return setMsg((j&&(j.error||j.error_description))||'Register failed.', 'err');
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
        if(form.id==='totpEnableForm') return void onEnableTotp(form);
        if(form.id==='totpDisableForm') return void onDisableTotpSubmit(form);
        if(form.id==='inviteForm') return void onCreateInvite(form);
      });

      app.addEventListener('click', function(ev){
        var n=ev.target; while(n&&n!==app&&!n.getAttribute('data-action')) n=n.parentElement; if(!n||n===app) return; var a=n.getAttribute('data-action'); if(!a) return;
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
  </script>
</body>
</html>`;
}

export async function handleWebClientPage(request: Request, env: Env): Promise<Response> {
  void request;
  void env;
  return htmlResponse(renderWebClientHTML());
}
