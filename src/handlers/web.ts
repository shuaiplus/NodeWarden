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
      --bg: #f8fafc;
      --bg2: #f1f5f9;
      --panel: #ffffff;
      --line: #e2e8f0;
      --text: #0f172a;
      --muted: #64748b;
      --primary: #0f172a;
      --primary-hover: #334155;
      --primary2: #3b82f6;
      --primary2-hover: #2563eb;
      --danger: #ef4444;
      --danger-hover: #dc2626;
      --danger-bg: #fef2f2;
      --ok: #10b981;
      --ok-bg: #ecfdf5;
      --radius: 16px;
      --radius-sm: 10px;
      --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
      --shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
      --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
      --shadow-xl: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1);
      --font-sans: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }
    * { box-sizing: border-box; }
    html, body { height: 100%; }
    body {
      margin: 0;
      color: var(--text);
      font-family: var(--font-sans);
      background-color: var(--bg);
      background-image:
        radial-gradient(at 0% 0%, hsla(253,16%,7%,0.05) 0, transparent 50%),
        radial-gradient(at 50% 0%, hsla(225,39%,30%,0.05) 0, transparent 50%),
        radial-gradient(at 100% 0%, hsla(339,49%,30%,0.05) 0, transparent 50%);
      background-attachment: fixed;
      -webkit-font-smoothing: antialiased;
    }
    #app { min-height: 100%; display: flex; flex-direction: column; }
    .shell { flex: 1; padding: 20px; display: flex; flex-direction: column; }
    .auth {
      width: 100%;
      max-width: 900px;
      min-height: 600px;
      margin: auto;
      border: 1px solid var(--line);
      border-radius: 24px;
      background: var(--panel);
      box-shadow: var(--shadow-lg);
      display: grid;
      grid-template-columns: 360px 1fr;
      overflow: hidden;
    }
    .auth-left {
      border-right: 1px solid var(--line);
      padding: 40px;
      background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
      display: flex;
      flex-direction: column;
      justify-content: center;
    }
    .brand {
      width: 64px;
      height: 64px;
      border-radius: 16px;
      background: linear-gradient(135deg, #0f172a, #334155);
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 24px;
      margin-bottom: 24px;
      user-select: none;
      box-shadow: var(--shadow);
    }
    .auth-left h1 { margin: 0; font-size: 32px; font-weight: 700; letter-spacing: -0.02em; }
    .auth-left p { margin: 16px 0 0 0; color: var(--muted); line-height: 1.6; font-size: 15px; }
    .auth-right { padding: 40px; position: relative; display: flex; flex-direction: column; justify-content: center; }
    .section-title { margin: 0 0 24px 0; font-size: 28px; font-weight: 700; letter-spacing: -0.02em; }
    .msg {
      margin-bottom: 20px;
      border-radius: var(--radius-sm);
      border: 1px solid var(--line);
      padding: 12px 16px;
      font-size: 14px;
      background: #fff;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .msg.ok { color: var(--ok); border-color: #a7f3d0; background: var(--ok-bg); }
    .msg.err { color: var(--danger); border-color: #fecaca; background: var(--danger-bg); }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    .field { margin-bottom: 16px; }
    .field label { display: block; margin-bottom: 8px; color: var(--text); font-size: 14px; font-weight: 500; }
    .field input, .field select, .field textarea {
      width: 100%;
      min-height: 48px;
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
      background: #fff;
      color: var(--text);
      padding: 0 16px;
      font-size: 15px;
      transition: all 0.2s ease;
      box-shadow: var(--shadow-sm);
    }
    .field input:focus, .field select:focus, .field textarea:focus {
      outline: none;
      border-color: var(--primary2);
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
    }
    .field textarea {
      min-height: 100px;
      padding-top: 12px;
      padding-bottom: 12px;
      resize: vertical;
    }
    .actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 24px; }
    .btn {
      border: 1px solid var(--line);
      background: #fff;
      color: var(--text);
      border-radius: var(--radius-sm);
      min-height: 44px;
      padding: 0 20px;
      font-weight: 600;
      font-size: 14px;
      cursor: pointer;
      transition: all 0.2s ease;
      box-shadow: var(--shadow-sm);
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }
    .btn:hover { background: #f8fafc; border-color: #cbd5e1; }
    .btn.primary { border-color: var(--primary); background: var(--primary); color: #fff; }
    .btn.primary:hover { background: var(--primary-hover); border-color: var(--primary-hover); }
    .btn.secondary { border-color: var(--primary2); background: var(--primary2); color: #fff; }
    .btn.secondary:hover { background: var(--primary2-hover); border-color: var(--primary2-hover); }
    .btn.danger { border-color: var(--danger); background: var(--danger); color: #fff; }
    .btn.danger:hover { background: var(--danger-hover); border-color: var(--danger-hover); }
    .tiny { font-size: 13px; color: var(--muted); margin-top: 8px; line-height: 1.5; }
    .totp-mask {
      position: absolute;
      inset: 0;
      background: rgba(15, 23, 42, 0.6);
      backdrop-filter: blur(4px);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      z-index: 50;
      border-radius: 24px;
    }
    .totp-box {
      width: min(400px, 100%);
      border: 1px solid var(--line);
      border-radius: 20px;
      background: #fff;
      padding: 32px;
      box-shadow: var(--shadow-xl);
    }
    .totp-box h3 { margin: 0 0 12px 0; font-size: 22px; font-weight: 700; letter-spacing: -0.01em; }
    .app-layout {
      width: 100%;
      max-width: 1400px;
      height: calc(100vh - 40px);
      margin: auto;
      border: 1px solid var(--line);
      border-radius: 24px;
      background: var(--panel);
      box-shadow: var(--shadow-lg);
      overflow: hidden;
      display: grid;
    }
    .app-layout.normal-layout { grid-template-columns: 260px 1fr; }
    .app-layout.vault-layout { grid-template-columns: 260px 300px 1fr; }
    .sidebar, .folderbar {
      border-right: 1px solid var(--line);
      padding: 20px;
      background: #f8fafc;
      min-width: 0;
      display: flex;
      flex-direction: column;
    }
    .folderbar { background: #ffffff; }
    .sidebar .brand { width: 48px; height: 48px; margin-bottom: 16px; font-size: 18px; border-radius: 12px; }
    .sidebar .mail { font-size: 13px; color: var(--muted); margin-bottom: 24px; word-break: break-all; font-weight: 500; }
    .nav-btn, .folder-btn { 
      width: 100%; 
      text-align: left; 
      margin-bottom: 8px; 
      justify-content: flex-start;
      border: none;
      box-shadow: none;
      background: transparent;
      color: var(--muted);
      font-weight: 500;
    }
    .nav-btn:hover, .folder-btn:hover { background: #f1f5f9; color: var(--text); }
    .nav-btn.active { background: #e2e8f0; color: var(--text); font-weight: 600; }
    .folder-btn { margin-bottom: 4px; font-size: 14px; min-height: 36px; padding: 0 12px; }
    .folder-btn.active { background: #eff6ff; color: var(--primary2); font-weight: 600; }
    .content { padding: 24px; min-width: 0; overflow: auto; background: #ffffff; }
    .panel {
      border: 1px solid var(--line);
      border-radius: 16px;
      background: #fff;
      padding: 24px;
      margin-bottom: 24px;
      box-shadow: var(--shadow-sm);
    }
    .panel h3 { margin: 0 0 16px 0; font-size: 20px; font-weight: 600; letter-spacing: -0.01em; }
    .vault-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; height: calc(100vh - 220px); }
    .list {
      border: 1px solid var(--line);
      border-radius: 12px;
      overflow: auto;
      background: #fff;
      box-shadow: var(--shadow-sm);
    }
    .item {
      border-bottom: 1px solid var(--line);
      padding: 12px 16px;
      display: grid;
      grid-template-columns: 24px 1fr;
      gap: 12px;
      align-items: center;
      cursor: pointer;
      transition: background 0.2s ease;
    }
    .item:hover { background: #f8fafc; }
    .item:last-child { border-bottom: none; }
    .item.active { background: #eff6ff; }
    .item input[type="checkbox"] { width: 16px; height: 16px; cursor: pointer; accent-color: var(--primary2); }
    .kv {
      margin-bottom: 12px;
      font-size: 14px;
      line-height: 1.6;
      word-break: break-word;
      display: flex;
      flex-direction: column;
    }
    .kv b { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 2px; }
    .table {
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      border: 1px solid var(--line);
      border-radius: 12px;
      overflow: hidden;
      font-size: 14px;
      background: #fff;
      box-shadow: var(--shadow-sm);
    }
    .table th { background: #f8fafc; font-weight: 600; color: var(--muted); text-transform: uppercase; font-size: 12px; letter-spacing: 0.05em; }
    .table th, .table td {
      border-bottom: 1px solid var(--line);
      padding: 12px 16px;
      text-align: left;
      vertical-align: middle;
    }
    .table tr:last-child td { border-bottom: none; }
    .badge {
      display: inline-flex;
      align-items: center;
      padding: 2px 8px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 600;
      background: #f1f5f9;
      color: #475569;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .badge.success { background: #dcfce7; color: #166534; }
    .badge.danger { background: #fee2e2; color: #991b1b; }
    .qr-row { display: grid; grid-template-columns: 200px 1fr; gap: 24px; align-items: start; }
    .qr-box { border: 1px solid var(--line); border-radius: 16px; padding: 16px; background: #fff; box-shadow: var(--shadow-sm); }
    .qr-box img { width: 100%; height: auto; display: block; object-fit: contain; border-radius: 8px; }
    @media (max-width: 1080px) {
      .auth { grid-template-columns: 1fr; min-height: auto; }
      .auth-left { border-right: none; border-bottom: 1px solid var(--line); padding: 32px; }
      .auth-right { padding: 32px; }
      .app-layout { grid-template-columns: 1fr; height: auto; min-height: calc(100vh - 40px); }
      .sidebar, .folderbar { border-right: none; border-bottom: 1px solid var(--line); padding: 16px; }
      .vault-grid { grid-template-columns: 1fr; height: auto; }
      .list { max-height: 400px; }
      .row { grid-template-columns: 1fr; }
      .qr-row { grid-template-columns: 1fr; }
      .totp-mask { border-radius: 0; }
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
          + '<div class="shell"><div class="auth">'
          + '  <aside class="auth-left"><div class="brand">NW</div><h1>NodeWarden Web</h1><p>Password errors keep email/password fields. If 2FA is enabled, password step is done once and TOTP is entered in modal only.</p></aside>'
          + '  <main class="auth-right"><h2 class="section-title">Sign In</h2>'
          +      renderMsg()
          + '    <form id="loginForm">'
          + '      <div class="field"><label>Email</label><input type="email" name="email" value="'+esc(state.loginEmail)+'" required /></div>'
          + '      <div class="field"><label>Master Password</label><input type="password" name="password" value="'+esc(state.loginPassword)+'" required /></div>'
          + '      <div class="actions"><button class="btn primary" type="submit">Login</button><button class="btn secondary" type="button" data-action="goto-register">Register</button></div>'
          + '    </form>'
          + (state.pendingLogin ? ''
            + '<div class="totp-mask"><div class="totp-box"><h3>Two-step verification</h3><div class="tiny">Password is already verified.</div>'
            + (state.loginTotpError?'<div class="msg err" style="margin-top:8px;">'+esc(state.loginTotpError)+'</div>':'')
            + '<form id="loginTotpForm"><div class="field"><label>TOTP Code</label><input name="totpToken" maxlength="6" value="'+esc(state.loginTotpToken)+'" required /></div><div class="actions"><button class="btn primary" type="submit">Verify</button><button class="btn secondary" type="button" data-action="totp-cancel">Cancel</button></div></form>'
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
          + '      <div class="row"><div class="field"><label>Name</label><input name="name" value="'+esc(state.registerName)+'" required /></div><div class="field"><label>Email</label><input type="email" name="email" value="'+esc(state.registerEmail)+'" required /></div></div>'
          + '      <div class="field"><label>Master Password</label><input type="password" name="password" value="'+esc(state.registerPassword)+'" minlength="12" required /></div>'
          + '      <div class="field"><label>Confirm Password</label><input type="password" name="password2" value="'+esc(state.registerPassword2)+'" minlength="12" required /></div>'
          + '      <div class="field"><label>Invite Code</label><input name="inviteCode" value="'+esc(state.inviteCode)+'" /></div>'
          + '      <div class="actions"><button class="btn primary" type="submit">Create Account</button><button class="btn secondary" type="button" data-action="goto-login">Back to Login</button></div>'
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
          rows += '<div class="item '+(c.id===state.selectedCipherId?'active':'')+'" data-action="pick-cipher" data-id="'+esc(c.id)+'"><input type="checkbox" data-action="toggle-select" data-id="'+esc(c.id)+'"'+(state.selectedMap[c.id]?' checked':'')+' /><div><div style="font-weight:600;font-size:14px;color:var(--text-primary);">'+esc(nameText)+'</div><div class="tiny" style="color:var(--text-secondary);">'+esc(c.id)+'</div></div></div>';
        }
        if(!rows) rows='<div class="item" style="justify-content:center; color:var(--text-secondary);">No items in this folder.</div>';

        var c0=selectedCipher();
        var detail='<div class="tiny" style="text-align:center; padding:40px; color:var(--text-secondary);">Select an item to view details.</div>';
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
          + '<h2 style="margin:0; font-size:24px; font-weight:700; letter-spacing:-0.02em;">Vault</h2>'
          + '<div class="actions" style="margin:0;"><button class="btn secondary" data-action="vault-refresh">Refresh</button><button class="btn secondary" data-action="bulk-move">Move</button><button class="btn danger" data-action="bulk-delete">Delete ('+selectedCount()+')</button><button class="btn secondary" data-action="select-all">All</button><button class="btn secondary" data-action="select-none">Clear</button></div>'
          + '</div>'
          + '<div class="vault-grid"><div class="list">'+rows+'</div><div class="panel" style="margin:0; overflow:auto;">'+detail+'</div></div>';
      }

      function renderSettingsTab(){
        var p=state.profile||{};
        var secret=currentTotpSecret();
        var qr='https://api.qrserver.com/v1/create-qr-code/?size=180x180&data='+encodeURIComponent(buildTotpUri(secret));
        return ''
          + renderMsg()
          + '<h2 style="margin:0 0 24px 0; font-size:24px; font-weight:700; letter-spacing:-0.02em;">Settings</h2>'
          + '<div class="panel"><h3>Profile</h3><form id="profileForm"><div class="row"><div class="field"><label>Name</label><input name="name" value="'+esc(p.name||'')+'" /></div><div class="field"><label>Email</label><input type="email" name="email" value="'+esc(p.email||'')+'" required /></div></div><div class="actions"><button class="btn primary" type="submit">Save Profile</button></div></form></div>'
          + '<div class="panel"><h3>Master Password</h3><form id="passwordForm"><div class="field"><label>Current Master Password</label><input type="password" name="currentPassword" required /></div><div class="row"><div class="field"><label>New Master Password</label><input type="password" name="newPassword" minlength="12" required /></div><div class="field"><label>Confirm New Password</label><input type="password" name="newPassword2" minlength="12" required /></div></div><div class="actions"><button class="btn danger" type="submit">Change Master Password</button></div><div class="tiny">After success, current sessions are revoked and you must log in again.</div></form></div>'
          + '<div class="panel"><h3>TOTP Setup</h3><div class="qr-row"><div class="qr-box"><img src="'+esc(qr)+'" alt="TOTP QR" /></div><div><form id="totpEnableForm"><div class="field"><label>Secret (Base32)</label><input name="secret" value="'+esc(secret)+'" /></div><div class="field"><label>Verification Code</label><input name="token" maxlength="6" value="'+esc(state.totpSetupToken)+'" /></div><div class="actions"><button class="btn primary" type="submit">Enable TOTP</button><button class="btn secondary" type="button" data-action="totp-secret-refresh">Regenerate</button><button class="btn secondary" type="button" data-action="totp-secret-copy">Copy Secret</button></div></form></div></div><div class="actions"><button class="btn danger" type="button" data-action="totp-disable">Disable TOTP</button></div><div class="tiny">Disable action prompts for master password.</div></div>';
      }
      function renderTotpDisableModal(){
        if(!state.totpDisableOpen) return '';
        return ''
          + '<div class="totp-mask"><div class="totp-box"><h3 style="margin:0 0 8px 0; font-size:20px;">Disable TOTP</h3><div class="tiny" style="margin-bottom:16px;">Enter master password to disable two-step verification.</div>'
          + (state.totpDisableError?'<div class="msg err" style="margin-bottom:16px;">'+esc(state.totpDisableError)+'</div>':'')
          + '<form id="totpDisableForm"><div class="field"><label>Master Password</label><input type="password" name="masterPassword" value="'+esc(state.totpDisablePassword)+'" required /></div><div class="actions"><button class="btn danger" type="submit">Disable</button><button class="btn secondary" type="button" data-action="totp-disable-cancel">Cancel</button></div></form>'
          + '</div></div>';
      }

      function renderHelpTab(){
        return ''
          + '<h2 style="margin:0 0 24px 0; font-size:24px; font-weight:700; letter-spacing:-0.02em;">Help & Support</h2>'
          + '<div class="panel"><h3>Upstream Sync</h3><ul style="margin:0; padding-left:20px; color:var(--text-secondary); line-height:1.6;"><li>Track upstream with a fork and scheduled sync workflow (recommended).</li><li>Before merge: compare API routes, migration files, and auth logic changes.</li><li>After merge: run local dev migration tests, then deploy Worker after validation.</li></ul></div>'
          + '<div class="panel"><h3>Common Errors</h3><ul style="margin:0; padding-left:20px; color:var(--text-secondary); line-height:1.6;"><li>401 Unauthorized: token expired or revoked, login again.</li><li>403 Account disabled: admin must unban user in User Management.</li><li>403 Invite invalid: invite expired/used/revoked, create a new invite.</li><li>429 Too many requests: wait retry seconds and avoid burst writes.</li></ul></div>'
          + '<div class="panel"><h3>Troubleshooting</h3><ul style="margin:0; padding-left:20px; color:var(--text-secondary); line-height:1.6;"><li>Login OK but encrypted values shown: verify profile key and KDF settings are consistent.</li><li>TOTP fails repeatedly: sync device time and re-scan QR using latest secret.</li><li>Password change failed: ensure current password is correct and new password has at least 12 chars.</li><li>Sync conflicts: refresh vault and retry one operation at a time.</li></ul></div>';
      }

      function renderAdminTab(){
        var usersRows='';
        for(var i=0;i<state.users.length;i++){
          var u=state.users[i]; var canAct=state.profile&&u.id!==state.profile.id;
          usersRows += '<tr><td>'+esc(u.email)+'</td><td>'+esc(u.name||'')+'</td><td><span class="badge">'+esc(u.role)+'</span></td><td><span class="badge '+(u.status==='active'?'success':'danger')+'">'+esc(u.status)+'</span></td><td>'
            + (canAct?'<button class="btn secondary" data-action="user-toggle" data-id="'+esc(u.id)+'" data-status="'+esc(u.status)+'">'+(u.status==='active'?'Ban':'Unban')+'</button>':'')
            + (canAct?' <button class="btn danger" data-action="user-delete" data-id="'+esc(u.id)+'">Delete</button>':'')
            + '</td></tr>';
        }
        if(!usersRows) usersRows='<tr><td colspan="5" style="text-align:center; color:var(--text-secondary); padding:24px;">No users found.</td></tr>';

        var inviteRows='';
        for(var j=0;j<state.invites.length;j++){
          var inv=state.invites[j];
          inviteRows += '<tr><td><code style="background:var(--bg-secondary); padding:4px 8px; border-radius:6px; font-size:13px;">'+esc(inv.code)+'</code></td><td><span class="badge '+(inv.status==='active'?'success':'danger')+'">'+esc(inv.status)+'</span></td><td>'+esc(inv.expiresAt)+'</td><td>'
            + '<button class="btn secondary" data-action="invite-copy" data-link="'+esc(inv.inviteLink||'')+'">Copy link</button>'
            + (inv.status==='active'?' <button class="btn danger" data-action="invite-revoke" data-code="'+esc(inv.code)+'">Revoke</button>':'')
            + '</td></tr>';
        }
        if(!inviteRows) inviteRows='<tr><td colspan="4" style="text-align:center; color:var(--text-secondary); padding:24px;">No invites found.</td></tr>';

        return ''
          + renderMsg()
          + '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:24px;">'
          + '<h2 style="margin:0; font-size:24px; font-weight:700; letter-spacing:-0.02em;">User Management</h2>'
          + '<button class="btn secondary" data-action="admin-refresh">Refresh Data</button>'
          + '</div>'
          + '<div class="panel"><h3>Create Invite</h3><form id="inviteForm"><div class="field"><label>Expires in hours</label><input name="hours" type="number" min="1" max="720" value="168" /></div><div class="actions"><button class="btn primary" type="submit">Create Invite</button></div></form></div>'
          + '<div class="panel"><h3>Users</h3><div style="overflow-x:auto;"><table class="table"><thead><tr><th>Email</th><th>Name</th><th>Role</th><th>Status</th><th>Action</th></tr></thead><tbody>'+usersRows+'</tbody></table></div></div>'
          + '<div class="panel"><h3>Invites</h3><div style="overflow-x:auto;"><table class="table"><thead><tr><th>Code</th><th>Status</th><th>Expires At</th><th>Action</th></tr></thead><tbody>'+inviteRows+'</tbody></table></div></div>';
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
          + '    <div style="flex:1; display:flex; flex-direction:column; gap:4px;">'
          + '      <button class="btn nav-btn '+(state.tab==='vault'?'active':'')+'" data-action="tab" data-tab="vault">Vault</button>'
          + '      <button class="btn nav-btn '+(state.tab==='settings'?'active':'')+'" data-action="tab" data-tab="settings">Settings</button>'
          + (isAdmin?'<button class="btn nav-btn '+(state.tab==='admin'?'active':'')+'" data-action="tab" data-tab="admin">User Management</button>':'')
          + '      <button class="btn nav-btn '+(state.tab==='help'?'active':'')+'" data-action="tab" data-tab="help">Help</button>'
          + '    </div>'
          + '    <button class="btn nav-btn" style="margin-top:auto; color:var(--danger);" data-action="logout">Logout</button></aside>'
          + (showFolders?('  <aside class="folderbar"><h3 style="margin:0 0 16px 0; font-size:14px; text-transform:uppercase; letter-spacing:0.05em; color:var(--text-secondary);">Folders</h3><div style="display:flex; flex-direction:column; gap:4px;">'+folders+'</div></aside>'):'')
          + '  <main class="content">'+content+'</main>'
          + '</div>'+renderTotpDisableModal()+'</div>';
      }

      function render(){
        if(state.phase==='loading'){ app.innerHTML='<div class="shell" style="align-items:center; justify-content:center;"><div style="display:flex; flex-direction:column; align-items:center; gap:16px;"><div class="brand" style="margin:0;">NW</div><div style="color:var(--text-secondary); font-weight:500;">Loading NodeWarden...</div></div></div>'; return; }
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
