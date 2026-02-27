import { I18N } from './i18n.js';
import { bytesToBase64, base64ToBytes, concatBytes, pbkdf2, hkdfExpand, encryptBw, decryptBw, decryptStr, extractTotpSecret, calcTotpNow } from './crypto.js';
import { parseFieldType as parseFieldTypeUtil, selectedCount as selectedCountUtil, cipherTypeKey as cipherTypeKeyUtil, firstCipherUri as firstCipherUriUtil, hostFromUri as hostFromUriUtil } from './vault-utils.js';

export function startNodewardenApp(runtimeConfig) {
      var app = document.getElementById('app');
      var defaultKdfIterations = Number(runtimeConfig && runtimeConfig.defaultKdfIterations) || 600000;
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
        vaultQuery: '',
        vaultType: 'all',
        showSelectedPassword: false,
        vaultSearchComposing: false,
        vaultSearchTimer: 0,
        totpTicking: false,
        totpTickBusy: false,
        detailMode: 'view',
        detailDraft: null,
        createMenuOpen: false,
        fieldModalOpen: false,
        fieldModalType: 'text',
        fieldModalLabel: '',
        fieldModalValue: '',
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
        totpDisableError: '',
        unlockPassword: '',
        unlockError: '',
        lockTimeoutMinutes: 15,
        lockLastActiveTs: Date.now(),
        lockCheckTimer: 0,
        lockChannel: null
      };
      var NO_FOLDER_FILTER = '__none__';
      var i18n = I18N;

      function t(key) { return i18n[state.lang][key] || key; }

      function esc(v) {
        return String(v == null ? '' : v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
      }
      function sessionKey() { return 'nodewarden.web.session.v2'; }
      function lockSettingsKey() { return 'nodewarden.web.lock.v1'; }
      function setMsg(t, ty) { state.msg = t || ''; state.msgType = ty || 'ok'; render(); }
      function clearMsg() { state.msg = ''; }
      function renderMsg() { return state.msg ? '<div class="alert alert-' + (state.msgType === 'err' ? 'danger' : 'success') + '">' + esc(state.msg) + '</div>' : ''; }
      function saveSession() {
        if (!state.session) { localStorage.removeItem(sessionKey()); return; }
        var persisted = {
          accessToken: state.session.accessToken || '',
          refreshToken: state.session.refreshToken || '',
          email: state.session.email || ''
        };
        localStorage.setItem(sessionKey(), JSON.stringify(persisted));
      }
      function loadSession() {
        try {
          var r = localStorage.getItem(sessionKey());
          if (!r) return null;
          var p = JSON.parse(r);
          if (!p || !p.accessToken || !p.refreshToken) return null;
          return { accessToken: p.accessToken, refreshToken: p.refreshToken, email: p.email || '' };
        } catch (e) { return null; }
      }
      function saveLockSettings() {
        localStorage.setItem(lockSettingsKey(), JSON.stringify({ lockTimeoutMinutes: Number(state.lockTimeoutMinutes) || 0 }));
      }
      function loadLockSettings() {
        try {
          var r = localStorage.getItem(lockSettingsKey());
          if (!r) return;
          var p = JSON.parse(r);
          var mins = Number(p && p.lockTimeoutMinutes);
          if (Number.isFinite(mins) && mins >= 0) state.lockTimeoutMinutes = mins;
        } catch (_) {}
      }
      async function jsonOrNull(resp){ var t=await resp.text(); if(!t) return null; try{ return JSON.parse(t);} catch(e){ return null; } }
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
            c.identity.decTitle=await decryptStr(c.identity.title,ek,mk); c.identity.decMiddleName=await decryptStr(c.identity.middleName,ek,mk);
            c.identity.decSsn=await decryptStr(c.identity.ssn,ek,mk); c.identity.decPassportNumber=await decryptStr(c.identity.passportNumber,ek,mk);
            c.identity.decLicenseNumber=await decryptStr(c.identity.licenseNumber,ek,mk); c.identity.decAddress1=await decryptStr(c.identity.address1,ek,mk);
            c.identity.decAddress2=await decryptStr(c.identity.address2,ek,mk); c.identity.decAddress3=await decryptStr(c.identity.address3,ek,mk);
            c.identity.decCity=await decryptStr(c.identity.city,ek,mk); c.identity.decState=await decryptStr(c.identity.state,ek,mk);
            c.identity.decPostalCode=await decryptStr(c.identity.postalCode,ek,mk); c.identity.decCountry=await decryptStr(c.identity.country,ek,mk);
          }
          if(c.sshKey){
            c.sshKey.decPrivateKey=await decryptStr(c.sshKey.privateKey,ek,mk);
            c.sshKey.decPublicKey=await decryptStr(c.sshKey.publicKey,ek,mk);
            c.sshKey.decFingerprint=await decryptStr(c.sshKey.fingerprint,ek,mk);
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

      function clearVaultMemory() {
        state.ciphers = [];
        state.folders = [];
        state.folderFilterId = '';
        state.selectedCipherId = '';
        state.selectedMap = {};
        state.detailMode = 'view';
        state.detailDraft = null;
        state.showSelectedPassword = false;
      }

      function markUserActivity() {
        if (state.phase === 'app') state.lockLastActiveTs = Date.now();
      }

      function ensureLockChannel() {
        if (state.lockChannel || typeof BroadcastChannel === 'undefined') return;
        try {
          state.lockChannel = new BroadcastChannel('nodewarden-lock-v1');
          state.lockChannel.onmessage = function (ev) {
            var msg = ev && ev.data;
            if (!msg || msg.type !== 'lock') return;
            if (state.phase === 'app') lockVault(false, false);
          };
        } catch (_) {}
      }

      function ensureAutoLockTicker() {
        if (state.lockCheckTimer) return;
        state.lockCheckTimer = setInterval(function () {
          if (state.phase !== 'app') return;
          var mins = Number(state.lockTimeoutMinutes) || 0;
          if (mins <= 0) return;
          if ((Date.now() - state.lockLastActiveTs) >= mins * 60 * 1000) {
            lockVault(true, true);
          }
        }, 5000);
      }

      function lockVault(showMsg, broadcast) {
        if (state.session) {
          delete state.session.symEncKey;
          delete state.session.symMacKey;
        }
        clearVaultMemory();
        state.pendingLogin = null;
        state.loginTotpToken = '';
        state.loginTotpError = '';
        state.unlockPassword = '';
        state.unlockError = '';
        state.phase = 'locked';
        if (broadcast !== false && state.lockChannel) {
          try { state.lockChannel.postMessage({ type: 'lock', at: Date.now() }); } catch (_) {}
        }
        if (showMsg) setMsg('Vault locked.', 'ok');
        else render();
      }

      async function onUnlock(form) {
        clearMsg();
        state.unlockError = '';
        var fd = new FormData(form);
        state.unlockPassword = String(fd.get('password') || '');
        if (!state.unlockPassword) {
          state.unlockError = 'Please input master password.';
          render();
          return;
        }
        try {
          var email = String(state.profile && state.profile.email ? state.profile.email : state.session && state.session.email ? state.session.email : '').toLowerCase();
          if (!email) throw new Error('email missing');
          var d = await deriveLoginHash(email, state.unlockPassword);
          var ek = await hkdfExpand(d.masterKey, 'enc', 32);
          var em = await hkdfExpand(d.masterKey, 'mac', 32);
          var symKeyBytes = await decryptBw(state.profile.key, ek, em);
          if (!symKeyBytes || symKeyBytes.length < 64) throw new Error('invalid key');
          state.session.symEncKey = bytesToBase64(symKeyBytes.slice(0, 32));
          state.session.symMacKey = bytesToBase64(symKeyBytes.slice(32, 64));
          state.unlockPassword = '';
          state.unlockError = '';
          await loadVault();
          await loadAdminData();
          state.phase = 'app';
          state.tab = 'vault';
          state.lockLastActiveTs = Date.now();
          render();
          setMsg('Unlocked.', 'ok');
        } catch (e) {
          state.unlockError = 'Unlock failed. Master password is incorrect.';
          render();
        }
      }

      function logout(){
        state.session=null; state.profile=null; state.ciphers=[]; state.folders=[]; state.users=[]; state.invites=[]; state.folderFilterId=''; state.selectedCipherId=''; state.selectedMap={}; state.pendingLogin=null; state.loginTotpToken=''; state.loginTotpError=''; state.totpDisableOpen=false; state.totpDisablePassword=''; state.totpDisableError=''; state.unlockPassword=''; state.unlockError=''; state.phase='login'; saveSession(); clearMsg(); render();
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

      function selectedCount(){ return selectedCountUtil(state.selectedMap); }
      function cipherTypeKey(c){ return cipherTypeKeyUtil(c); }
      function cipherTypeLabel(c){
        var k=cipherTypeKey(c);
        if(k==='login') return t('typeLogin');
        if(k==='card') return t('typeCard');
        if(k==='identity') return t('typeIdentity');
        if(k==='note') return t('typeNote');
        return t('typeOther');
      }
      function folderNameById(id){
        for(var i=0;i<state.folders.length;i++){
          var f=state.folders[i];
          if(f.id===id) return f.decName||f.name||f.id;
        }
        return '';
      }
      function firstCipherUri(c){ return firstCipherUriUtil(c); }
      function hostFromUri(uri){ return hostFromUriUtil(uri); }
      function listSubtitle(c){
        if(c&&c.login){
          return c.login.decUsername||c.login.username||firstCipherUri(c)||'';
        }
        return cipherTypeLabel(c);
      }
      function syncSelectedWithFilter(){
        var filtered=filteredCiphers();
        if(state.selectedCipherId){
          var found=false;
          for(var i=0;i<filtered.length;i++){ if(filtered[i].id===state.selectedCipherId){ found=true; break; } }
          if(!found) state.selectedCipherId=filtered.length?filtered[0].id:'';
        }else{
          state.selectedCipherId=filtered.length?filtered[0].id:'';
        }
      }
      async function updateLiveTotpDisplay(){
        if(state.phase!=='app'||state.tab!=='vault') return;
        if(state.totpTickBusy) return;
        var vEl=document.getElementById('totp-live-value');
        var rEl=document.getElementById('totp-live-remain');
        if(!vEl||!rEl) return;
        var c=selectedCipher(); if(!c||!c.login) return;
        var raw=(c.login.decTotp||c.login.totp||'').trim();
        if(!raw){ vEl.textContent=''; rEl.textContent=''; return; }
        state.totpTickBusy=true;
        try{
          var x=await calcTotpNow(raw);
          if(!x){ vEl.textContent='N/A'; rEl.textContent=''; return; }
          vEl.textContent=x.code;
          rEl.textContent=t('totpLiveIn')+': '+x.remain+'s';
        }catch(e){
          vEl.textContent='N/A';
          rEl.textContent='';
        }finally{
          state.totpTickBusy=false;
        }
      }
      function ensureTotpTicker(){
        if(state.totpTicking) return;
        state.totpTicking=true;
        setInterval(function(){ updateLiveTotpDisplay(); }, 1000);
      }
      function filteredCiphers(){
        var out=[]; var q=String(state.vaultQuery||'').toLowerCase();
        for(var i=0;i<state.ciphers.length;i++){
          var c=state.ciphers[i];
          if(state.folderFilterId){
            if(state.folderFilterId===NO_FOLDER_FILTER){ if(c.folderId&&c.folderId!=='') continue; }
            else if(c.folderId!==state.folderFilterId) continue;
          }
          if(state.vaultType!=='all'&&cipherTypeKey(c)!==state.vaultType) continue;
          if(q){
            var text=(String(c.decName||c.name||'')+' '+String(listSubtitle(c)||'')+' '+String(firstCipherUri(c)||'')).toLowerCase();
            if(text.indexOf(q)===-1) continue;
          }
          out.push(c);
        }
        return out;
      }
      function selectedCipher(){ if(!state.selectedCipherId) return null; var list=filteredCiphers(); for(var i=0;i<list.length;i++){ if(list[i].id===state.selectedCipherId) return list[i]; } return null; }
      function randomBase32Secret(len){ var a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; var b=crypto.getRandomValues(new Uint8Array(len)); var o=''; for(var i=0;i<b.length;i++) o+=a[b[i]%a.length]; return o; }
      function currentTotpSecret(){ if(!state.totpSetupSecret) state.totpSetupSecret=randomBase32Secret(32); return state.totpSetupSecret; }
      function buildTotpUri(secret){ var issuer='NodeWarden'; var account=state.profile&&state.profile.email?state.profile.email:'account'; return 'otpauth://totp/'+encodeURIComponent(issuer+':'+account)+'?secret='+encodeURIComponent(secret)+'&issuer='+encodeURIComponent(issuer)+'&algorithm=SHA1&digits=6&period=30'; }
      function renderTotpSetupQr(){
        if(state.phase!=='app'||state.tab!=='settings') return;
        var box=document.getElementById('totp-qr-box');
        if(!box) return;
        var secret=currentTotpSecret();
        var otpUri=buildTotpUri(secret);
        try{
          var qrf=window.qrcode;
          if(typeof qrf!=='function') throw new Error('qrcode-generator unavailable');
          var qr=qrf(0,'M');
          qr.addData(otpUri);
          qr.make();
          var dataUrl=qr.createDataURL(4,2);
          if(!dataUrl) throw new Error('qrcode data url unavailable');
          box.innerHTML='<img src="'+esc(dataUrl)+'" alt="TOTP QR" width="180" height="180" style="display:block; width:180px; height:180px;" />';
        }catch(_){
          box.innerHTML='<div class="totp-qr-fallback"><div>QR unavailable</div><div class="tiny">Use secret key below</div></div>';
        }
      }
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
      function getUserCryptoKeys(){
        var sym=buildSymmetricKeyBytes();
        if(!sym||sym.length<64) return null;
        return { enc: sym.slice(0,32), mac: sym.slice(32,64) };
      }
      async function getCipherCryptoKeys(cipher){
        var user=getUserCryptoKeys();
        if(!user) return null;
        if(cipher&&cipher.key){
          try{
            var raw=await decryptBw(cipher.key,user.enc,user.mac);
            if(raw&&raw.length>=64) return { enc: raw.slice(0,32), mac: raw.slice(32,64), key: cipher.key };
          }catch(e){}
        }
        return { enc: user.enc, mac: user.mac, key: null };
      }
      async function encryptTextValue(v, enc, mac){
        var s=String(v==null?'':v);
        if(!s) return null;
        return encryptBw(new TextEncoder().encode(s), enc, mac);
      }
      function openCreateDraft(){
        state.detailMode='create';
        state.showSelectedPassword=true;
        state.createMenuOpen=false;
        state.detailDraft={
          id: '',
          type: 1,
          name: '',
          folderId: state.folderFilterId&&state.folderFilterId!==NO_FOLDER_FILTER?state.folderFilterId:'',
          reprompt: false,
          loginUsername: '',
          loginPassword: '',
          loginTotp: '',
          websites: [''],
          cardholderName: '',
          cardNumber: '',
          cardBrand: '',
          cardExpMonth: '',
          cardExpYear: '',
          cardCode: '',
          identTitle: '',
          identFirstName: '',
          identMiddleName: '',
          identLastName: '',
          identUsername: '',
          identCompany: '',
          identSsn: '',
          identPassportNumber: '',
          identLicenseNumber: '',
          identEmail: '',
          identPhone: '',
          identAddress1: '',
          identAddress2: '',
          identAddress3: '',
          identCity: '',
          identState: '',
          identPostalCode: '',
          identCountry: '',
          sshPrivateKey: '',
          sshPublicKey: '',
          sshFingerprint: '',
          customFields: [],
          notes: ''
        };
      }
      function openEditDraft(cipher){
        if(!cipher) return;
        var login=cipher.login||{};
        var uris=Array.isArray(login.uris)?login.uris:[];
        var ws=[]; for(var i=0;i<uris.length;i++){ var u=String(uris[i]&&(uris[i].decUri||uris[i].uri)||'').trim(); if(u) ws.push(u); }
        if(!ws.length) ws.push('');
        var cfs=[]; var fs=Array.isArray(cipher.fields)?cipher.fields:[];
        for(var j=0;j<fs.length;j++) cfs.push({ type: parseFieldType(fs[j].type), label: fs[j].decName||fs[j].name||'', value: fs[j].decValue||fs[j].value||'' });
        state.detailMode='edit';
        state.showSelectedPassword=true;
        state.detailDraft={
          id: cipher.id,
          type: Number(cipher.type)||1,
          name: cipher.decName||cipher.name||'',
          folderId: cipher.folderId||'',
          reprompt: !!cipher.reprompt,
          loginUsername: login.decUsername||login.username||'',
          loginPassword: login.decPassword||login.password||'',
          loginTotp: login.decTotp||login.totp||'',
          websites: ws,
          cardholderName: (cipher.card&&(cipher.card.decCardholderName||cipher.card.cardholderName))||'',
          cardNumber: (cipher.card&&(cipher.card.decNumber||cipher.card.number))||'',
          cardBrand: (cipher.card&&(cipher.card.decBrand||cipher.card.brand))||'',
          cardExpMonth: (cipher.card&&(cipher.card.decExpMonth||cipher.card.expMonth))||'',
          cardExpYear: (cipher.card&&(cipher.card.decExpYear||cipher.card.expYear))||'',
          cardCode: (cipher.card&&(cipher.card.decCode||cipher.card.code))||'',
          identTitle: (cipher.identity&&(cipher.identity.decTitle||cipher.identity.title))||'',
          identFirstName: (cipher.identity&&(cipher.identity.decFirstName||cipher.identity.firstName))||'',
          identMiddleName: (cipher.identity&&(cipher.identity.decMiddleName||cipher.identity.middleName))||'',
          identLastName: (cipher.identity&&(cipher.identity.decLastName||cipher.identity.lastName))||'',
          identUsername: (cipher.identity&&(cipher.identity.decUsername||cipher.identity.username))||'',
          identCompany: (cipher.identity&&(cipher.identity.decCompany||cipher.identity.company))||'',
          identSsn: (cipher.identity&&(cipher.identity.decSsn||cipher.identity.ssn))||'',
          identPassportNumber: (cipher.identity&&(cipher.identity.decPassportNumber||cipher.identity.passportNumber))||'',
          identLicenseNumber: (cipher.identity&&(cipher.identity.decLicenseNumber||cipher.identity.licenseNumber))||'',
          identEmail: (cipher.identity&&(cipher.identity.decEmail||cipher.identity.email))||'',
          identPhone: (cipher.identity&&(cipher.identity.decPhone||cipher.identity.phone))||'',
          identAddress1: (cipher.identity&&(cipher.identity.decAddress1||cipher.identity.address1))||'',
          identAddress2: (cipher.identity&&(cipher.identity.decAddress2||cipher.identity.address2))||'',
          identAddress3: (cipher.identity&&(cipher.identity.decAddress3||cipher.identity.address3))||'',
          identCity: (cipher.identity&&(cipher.identity.decCity||cipher.identity.city))||'',
          identState: (cipher.identity&&(cipher.identity.decState||cipher.identity.state))||'',
          identPostalCode: (cipher.identity&&(cipher.identity.decPostalCode||cipher.identity.postalCode))||'',
          identCountry: (cipher.identity&&(cipher.identity.decCountry||cipher.identity.country))||'',
          sshPrivateKey: (cipher.sshKey&&(cipher.sshKey.decPrivateKey||cipher.sshKey.privateKey))||'',
          sshPublicKey: (cipher.sshKey&&(cipher.sshKey.decPublicKey||cipher.sshKey.publicKey))||'',
          sshFingerprint: (cipher.sshKey&&(cipher.sshKey.decFingerprint||cipher.sshKey.fingerprint))||'',
          customFields: cfs,
          notes: cipher.decNotes||cipher.notes||''
        };
      }
      function closeDetailEdit(){
        state.detailMode='view';
        state.detailDraft=null;
        state.createMenuOpen=false;
        state.fieldModalOpen=false;
        state.showSelectedPassword=false;
      }
      async function saveDetailDraft(){
        var d=state.detailDraft||{};
        var name=String(d.name||'').trim();
        if(!name) return setMsg('Name is required.', 'err');
        var typeNum=Number(d.type)||1;
        function basePayloadCommon(){
          return {
            type: typeNum,
            folderId: d.folderId||null,
            notes: d.notes
          };
        }
        try{
          if(state.detailMode==='create'){
            var user=getUserCryptoKeys(); if(!user) return setMsg('Vault key unavailable.', 'err');
            var createUris=[]; var cws=Array.isArray(d.websites)?d.websites:[];
            for(var wi=0;wi<cws.length;wi++){ var u=String(cws[wi]||'').trim(); if(!u) continue; createUris.push({ uri: await encryptTextValue(u,user.enc,user.mac), match: null }); }
            var createFields=[]; var cfs=Array.isArray(d.customFields)?d.customFields:[];
            for(var fi=0;fi<cfs.length;fi++){
              var f=cfs[fi]||{}; var fl=String(f.label||'').trim(); if(!fl) continue;
              createFields.push({ type: parseFieldType(f.type), name: await encryptTextValue(fl,user.enc,user.mac), value: await encryptTextValue(String(f.value||''),user.enc,user.mac) });
            }
            var payload={
              type: typeNum,
              name: await encryptTextValue(name,user.enc,user.mac),
              notes: await encryptTextValue(d.notes,user.enc,user.mac),
              folderId: d.folderId||null,
              reprompt: d.reprompt?1:0,
              login: null,
              card: null,
              identity: null,
              secureNote: null,
              sshKey: null,
              fields: createFields
            };
            if(typeNum===1){
              payload.login={ username: await encryptTextValue(d.loginUsername,user.enc,user.mac), password: await encryptTextValue(d.loginPassword,user.enc,user.mac), totp: await encryptTextValue(d.loginTotp,user.enc,user.mac), uris: createUris };
            } else if(typeNum===3){
              payload.card={ cardholderName: await encryptTextValue(d.cardholderName,user.enc,user.mac), number: await encryptTextValue(d.cardNumber,user.enc,user.mac), brand: await encryptTextValue(d.cardBrand,user.enc,user.mac), expMonth: await encryptTextValue(d.cardExpMonth,user.enc,user.mac), expYear: await encryptTextValue(d.cardExpYear,user.enc,user.mac), code: await encryptTextValue(d.cardCode,user.enc,user.mac) };
            } else if(typeNum===4){
              payload.identity={ title: await encryptTextValue(d.identTitle,user.enc,user.mac), firstName: await encryptTextValue(d.identFirstName,user.enc,user.mac), middleName: await encryptTextValue(d.identMiddleName,user.enc,user.mac), lastName: await encryptTextValue(d.identLastName,user.enc,user.mac), username: await encryptTextValue(d.identUsername,user.enc,user.mac), company: await encryptTextValue(d.identCompany,user.enc,user.mac), ssn: await encryptTextValue(d.identSsn,user.enc,user.mac), passportNumber: await encryptTextValue(d.identPassportNumber,user.enc,user.mac), licenseNumber: await encryptTextValue(d.identLicenseNumber,user.enc,user.mac), email: await encryptTextValue(d.identEmail,user.enc,user.mac), phone: await encryptTextValue(d.identPhone,user.enc,user.mac), address1: await encryptTextValue(d.identAddress1,user.enc,user.mac), address2: await encryptTextValue(d.identAddress2,user.enc,user.mac), address3: await encryptTextValue(d.identAddress3,user.enc,user.mac), city: await encryptTextValue(d.identCity,user.enc,user.mac), state: await encryptTextValue(d.identState,user.enc,user.mac), postalCode: await encryptTextValue(d.identPostalCode,user.enc,user.mac), country: await encryptTextValue(d.identCountry,user.enc,user.mac) };
            } else if(typeNum===5){
              payload.sshKey={ privateKey: await encryptTextValue(d.sshPrivateKey,user.enc,user.mac), publicKey: await encryptTextValue(d.sshPublicKey,user.enc,user.mac), fingerprint: await encryptTextValue(d.sshFingerprint,user.enc,user.mac) };
            } else if(typeNum===2){
              payload.secureNote={ type: 0 };
            }
            var rc=await authFetch('/api/ciphers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
            var jc=await jsonOrNull(rc); if(!rc.ok) return setMsg((jc&&(jc.error||jc.error_description))||'Create failed.', 'err');
            await loadVault();
            state.selectedCipherId=jc&&jc.id?jc.id:(state.ciphers.length?state.ciphers[0].id:'');
            closeDetailEdit();
            render(); setMsg('Item created.', 'ok');
            return;
          }
          var c=selectedCipher(); if(!c) return setMsg('No item selected.', 'err');
          var keys=await getCipherCryptoKeys(c); if(!keys) return setMsg('Vault key unavailable.', 'err');
          var editUris=[]; var ews=Array.isArray(d.websites)?d.websites:[];
          for(var wi2=0;wi2<ews.length;wi2++){ var u2=String(ews[wi2]||'').trim(); if(!u2) continue; editUris.push({ uri: await encryptTextValue(u2,keys.enc,keys.mac), match: null }); }
          var editFields=[]; var efs=Array.isArray(d.customFields)?d.customFields:[];
          for(var fi2=0;fi2<efs.length;fi2++){
            var f2=efs[fi2]||{}; var fl2=String(f2.label||'').trim(); if(!fl2) continue;
            editFields.push({ type: parseFieldType(f2.type), name: await encryptTextValue(fl2,keys.enc,keys.mac), value: await encryptTextValue(String(f2.value||''),keys.enc,keys.mac) });
          }
          var payload={
            id: c.id,
            type: typeNum,
            key: keys.key||null,
            folderId: d.folderId||null,
            favorite: !!c.favorite,
            name: await encryptTextValue(name,keys.enc,keys.mac),
            notes: await encryptTextValue(d.notes,keys.enc,keys.mac),
            reprompt: d.reprompt?1:0,
            login: null,
            card: null,
            identity: null,
            secureNote: null,
            sshKey: null,
            fields: editFields
          };
          if(typeNum===1){
            payload.login={ username: await encryptTextValue(d.loginUsername,keys.enc,keys.mac), password: await encryptTextValue(d.loginPassword,keys.enc,keys.mac), totp: await encryptTextValue(d.loginTotp,keys.enc,keys.mac), uris: editUris };
          } else if(typeNum===3){
            payload.card={ cardholderName: await encryptTextValue(d.cardholderName,keys.enc,keys.mac), number: await encryptTextValue(d.cardNumber,keys.enc,keys.mac), brand: await encryptTextValue(d.cardBrand,keys.enc,keys.mac), expMonth: await encryptTextValue(d.cardExpMonth,keys.enc,keys.mac), expYear: await encryptTextValue(d.cardExpYear,keys.enc,keys.mac), code: await encryptTextValue(d.cardCode,keys.enc,keys.mac) };
          } else if(typeNum===4){
            payload.identity={ title: await encryptTextValue(d.identTitle,keys.enc,keys.mac), firstName: await encryptTextValue(d.identFirstName,keys.enc,keys.mac), middleName: await encryptTextValue(d.identMiddleName,keys.enc,keys.mac), lastName: await encryptTextValue(d.identLastName,keys.enc,keys.mac), username: await encryptTextValue(d.identUsername,keys.enc,keys.mac), company: await encryptTextValue(d.identCompany,keys.enc,keys.mac), ssn: await encryptTextValue(d.identSsn,keys.enc,keys.mac), passportNumber: await encryptTextValue(d.identPassportNumber,keys.enc,keys.mac), licenseNumber: await encryptTextValue(d.identLicenseNumber,keys.enc,keys.mac), email: await encryptTextValue(d.identEmail,keys.enc,keys.mac), phone: await encryptTextValue(d.identPhone,keys.enc,keys.mac), address1: await encryptTextValue(d.identAddress1,keys.enc,keys.mac), address2: await encryptTextValue(d.identAddress2,keys.enc,keys.mac), address3: await encryptTextValue(d.identAddress3,keys.enc,keys.mac), city: await encryptTextValue(d.identCity,keys.enc,keys.mac), state: await encryptTextValue(d.identState,keys.enc,keys.mac), postalCode: await encryptTextValue(d.identPostalCode,keys.enc,keys.mac), country: await encryptTextValue(d.identCountry,keys.enc,keys.mac) };
          } else if(typeNum===5){
            payload.sshKey={ privateKey: await encryptTextValue(d.sshPrivateKey,keys.enc,keys.mac), publicKey: await encryptTextValue(d.sshPublicKey,keys.enc,keys.mac), fingerprint: await encryptTextValue(d.sshFingerprint,keys.enc,keys.mac) };
          } else if(typeNum===2){
            payload.secureNote={ type: 0 };
          }
          var ru=await authFetch('/api/ciphers/'+encodeURIComponent(c.id),{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
          var ju=await jsonOrNull(ru); if(!ru.ok) return setMsg((ju&&(ju.error||ju.error_description))||'Update failed.', 'err');
          await loadVault();
          closeDetailEdit();
          render(); setMsg('Item updated.', 'ok');
        }catch(e){
          setMsg('Save failed: '+(e&&e.message?e.message:String(e)), 'err');
        }
      }
      async function deleteSelectedCipher(){
        var c=selectedCipher(); if(!c) return;
        if(!window.confirm('Delete this item? This operation cannot be undone.')) return;
        var r=await authFetch('/api/ciphers/'+encodeURIComponent(c.id),{method:'DELETE'});
        var j=await jsonOrNull(r); if(!r.ok) return setMsg((j&&(j.error||j.error_description))||'Delete failed.', 'err');
        closeDetailEdit();
        await loadVault();
        syncSelectedWithFilter();
        render();
        setMsg('Item deleted.', 'ok');
      }
      function parseFieldType(v){ return parseFieldTypeUtil(v); }
      function fieldTypeSelectKey(v){
        var n=parseFieldType(v);
        if(n===1) return 'hidden';
        if(n===2) return 'boolean';
        if(n===3) return 'linked';
        return 'text';
      }
      function renderFieldTypeOptions(selected){
        var s=fieldTypeSelectKey(selected);
        function opt(v,l){ return '<option value="'+v+'"'+(s===v?' selected':'')+'>'+l+'</option>'; }
        return opt('text',t('fieldText'))+opt('hidden',t('fieldHidden'))+opt('boolean',t('fieldBoolean'))+opt('linked',t('fieldLinked'));
      }
      function renderCreateMenu(){
        if(!state.createMenuOpen) return '';
        return '<div class="create-menu"><button class="create-menu-item" data-action="detail-create-type" data-type="1">'+t('newTypeLogin')+'</button><button class="create-menu-item" data-action="detail-create-type" data-type="3">'+t('newTypeCard')+'</button><button class="create-menu-item" data-action="detail-create-type" data-type="4">'+t('newTypeIdentity')+'</button><button class="create-menu-item" data-action="detail-create-type" data-type="2">'+t('newTypeNote')+'</button><button class="create-menu-item" data-action="detail-create-type" data-type="5">'+t('newTypeSsh')+'</button></div>';
      }
      function renderFieldModal(){
        if(!state.fieldModalOpen) return '';
        return ''
          + '<div class="totp-mask"><div class="totp-box field-modal"><div class="field-modal-head"><h3>'+t('addField')+'</h3><button class="icon-btn" data-action="field-modal-close">✕</button></div>'
          + '<div class="form-group"><label class="form-label">'+t('fieldType')+'</label><select class="detail-input" data-action="field-modal-type">'+renderFieldTypeOptions(state.fieldModalType)+'</select></div>'
          + '<div class="form-group"><label class="form-label">'+t('fieldLabel')+'</label><input class="detail-input" data-action="field-modal-label" value="'+esc(state.fieldModalLabel)+'" /></div>'
          + '<div class="form-group"><label class="form-label">'+t('fieldValue')+'</label><input class="detail-input" data-action="field-modal-value" value="'+esc(state.fieldModalValue)+'" /></div>'
          + '<div class="detail-actions"><div><button class="btn btn-primary" data-action="field-modal-add">'+t('add')+'</button><button class="btn btn-secondary" data-action="field-modal-close">'+t('cancel')+'</button></div><div></div></div>'
          + '</div></div>';
      }
      function fieldTypeTextByNum(n){
        var x=parseFieldType(n);
        if(x===1) return t('fieldHidden');
        if(x===2) return t('fieldBoolean');
        if(x===3) return t('fieldLinked');
        return t('fieldText');
      }
      function renderCardBrandOptions(selected){
        var s=String(selected||'').toLowerCase();
        var brands=['','visa','mastercard','amex','discover','jcb','unionpay','dinersclub','maestro'];
        var labels={ '':'-- Select --', visa:'Visa', mastercard:'Mastercard', amex:'American Express', discover:'Discover', jcb:'JCB', unionpay:'UnionPay', dinersclub:'Diners Club', maestro:'Maestro' };
        var out='';
        for(var i=0;i<brands.length;i++){
          var b=brands[i];
          out += '<option value="'+b+'"'+(s===b?' selected':'')+'>'+labels[b]+'</option>';
        }
        return out;
      }
      function renderMonthOptions(selected){
        var s=String(selected||'');
        var out='<option value="">-- Select --</option>';
        for(var m=1;m<=12;m++){
          var mm=m<10?('0'+m):String(m);
          out += '<option value="'+mm+'"'+(s===mm?' selected':'')+'>'+mm+'</option>';
        }
        return out;
      }
      function renderDraftTypeCards(d){
        var typeNum=Number(d&&d.type||1);
        if(typeNum===3){
          return ''
            + '<div class="card"><div class="card-title">Card details</div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">Cardholder name</div><input class="detail-input" data-action="draft-change" data-field="cardholderName" value="'+esc(d.cardholderName||'')+'" /></div></div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">Number</div><input class="detail-input" data-action="draft-change" data-field="cardNumber" value="'+esc(d.cardNumber||'')+'" /></div></div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">Brand</div><select class="detail-input" data-action="draft-change" data-field="cardBrand">'+renderCardBrandOptions(d.cardBrand||'')+'</select></div></div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">Exp month</div><select class="detail-input" data-action="draft-change" data-field="cardExpMonth">'+renderMonthOptions(d.cardExpMonth||'')+'</select></div><div style="flex:1;"><div class="field-label">Exp year</div><input class="detail-input" type="number" min="2000" max="2999" data-action="draft-change" data-field="cardExpYear" value="'+esc(d.cardExpYear||'')+'" /></div></div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">Security code (CVV)</div><input class="detail-input" data-action="draft-change" data-field="cardCode" value="'+esc(d.cardCode||'')+'" /></div></div>'
            + '</div>';
        }
        if(typeNum===4){
          return ''
            + '<div class="card"><div class="card-title">Personal details</div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">Title</div><input class="detail-input" data-action="draft-change" data-field="identTitle" value="'+esc(d.identTitle||'')+'" /></div></div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">First name</div><input class="detail-input" data-action="draft-change" data-field="identFirstName" value="'+esc(d.identFirstName||'')+'" /></div></div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">Middle name</div><input class="detail-input" data-action="draft-change" data-field="identMiddleName" value="'+esc(d.identMiddleName||'')+'" /></div></div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">Last name</div><input class="detail-input" data-action="draft-change" data-field="identLastName" value="'+esc(d.identLastName||'')+'" /></div></div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">Username</div><input class="detail-input" data-action="draft-change" data-field="identUsername" value="'+esc(d.identUsername||'')+'" /></div></div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">Company</div><input class="detail-input" data-action="draft-change" data-field="identCompany" value="'+esc(d.identCompany||'')+'" /></div></div>'
            + '</div>'
            + '<div class="card"><div class="card-title">Identity</div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">SSN</div><input class="detail-input" data-action="draft-change" data-field="identSsn" value="'+esc(d.identSsn||'')+'" /></div></div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">Passport number</div><input class="detail-input" data-action="draft-change" data-field="identPassportNumber" value="'+esc(d.identPassportNumber||'')+'" /></div></div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">License number</div><input class="detail-input" data-action="draft-change" data-field="identLicenseNumber" value="'+esc(d.identLicenseNumber||'')+'" /></div></div>'
            + '</div>'
            + '<div class="card"><div class="card-title">Contact information</div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">Email</div><input class="detail-input" data-action="draft-change" data-field="identEmail" value="'+esc(d.identEmail||'')+'" /></div></div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">Phone</div><input class="detail-input" data-action="draft-change" data-field="identPhone" value="'+esc(d.identPhone||'')+'" /></div></div>'
            + '</div>'
            + '<div class="card"><div class="card-title">Address</div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">Address 1</div><input class="detail-input" data-action="draft-change" data-field="identAddress1" value="'+esc(d.identAddress1||'')+'" /></div></div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">Address 2</div><input class="detail-input" data-action="draft-change" data-field="identAddress2" value="'+esc(d.identAddress2||'')+'" /></div></div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">Address 3</div><input class="detail-input" data-action="draft-change" data-field="identAddress3" value="'+esc(d.identAddress3||'')+'" /></div></div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">City / Town</div><input class="detail-input" data-action="draft-change" data-field="identCity" value="'+esc(d.identCity||'')+'" /></div></div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">State / Province</div><input class="detail-input" data-action="draft-change" data-field="identState" value="'+esc(d.identState||'')+'" /></div></div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">ZIP / Postal code</div><input class="detail-input" data-action="draft-change" data-field="identPostalCode" value="'+esc(d.identPostalCode||'')+'" /></div></div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">Country</div><input class="detail-input" data-action="draft-change" data-field="identCountry" value="'+esc(d.identCountry||'')+'" /></div></div>'
            + '</div>';
        }
        if(typeNum===5){
          return ''
            + '<div class="card"><div class="card-title">SSH key</div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">Private key</div><textarea class="detail-input detail-textarea" data-action="draft-change" data-field="sshPrivateKey">'+esc(d.sshPrivateKey||'')+'</textarea></div></div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">Public key</div><textarea class="detail-input detail-textarea" data-action="draft-change" data-field="sshPublicKey">'+esc(d.sshPublicKey||'')+'</textarea></div></div>'
            + '<div class="field-row"><div style="flex:1;"><div class="field-label">Fingerprint</div><input class="detail-input" data-action="draft-change" data-field="sshFingerprint" value="'+esc(d.sshFingerprint||'')+'" /></div></div>'
            + '</div>';
        }
        if(typeNum===2){
          return '';
        }
        return ''
          + '<div class="card"><div class="card-title">'+t('credentials')+'</div>'
          +   '<div class="field-row"><div style="flex:1;"><div class="field-label">Username</div><input class="detail-input" data-action="draft-change" data-field="loginUsername" value="'+esc(d.loginUsername||'')+'" /></div></div>'
          +   '<div class="field-row"><div style="flex:1;"><div class="field-label">Password</div><input class="detail-input" data-action="draft-change" data-field="loginPassword" value="'+esc(d.loginPassword||'')+'" /></div></div>'
          +   '<div class="field-row"><div style="flex:1;"><div class="field-label">TOTP Secret</div><input class="detail-input" data-action="draft-change" data-field="loginTotp" value="'+esc(d.loginTotp||'')+'" /></div></div>'
          + '</div>';
      }
      function renderReadOnlyCustomFields(cipher){
        var fs=Array.isArray(cipher&&cipher.fields)?cipher.fields:[];
        if(!fs.length) return '';
        var rows='';
        for(var i=0;i<fs.length;i++){
          var f=fs[i]||{};
          var name=f.decName||f.name||'';
          var value=f.decValue||f.value||'';
          var typeNum=parseFieldType(f.type);
          if(typeNum===1 && value) value=new Array(Math.max(String(value).length,8)+1).join('•');
          rows += '<div class="field-row"><div><div class="field-label">'+esc(name)+' ('+esc(fieldTypeTextByNum(typeNum))+')</div><div class="field-value">'+esc(value||'')+'</div></div></div>';
        }
        return '<div class="card"><div class="card-title">Fields</div>'+rows+'</div>';
      }
      function renderReadOnlyTypeDetails(c0, folderLabel, created, updated){
        var typeNum=Number(c0&&c0.type||1);
        var notes=c0&&((c0.decNotes||c0.notes)||'');
        var baseHead=''
          + '<div class="vault-detail-head card">'
          +   '<div class="vault-detail-title">'+esc(c0.decName||c0.name||'')+'</div>'
          +   '<div class="vault-detail-folder">'+t('folder')+': '+esc(folderLabel||t('noFolder'))+'</div>'
          + '</div>';
        var history=''
          + '<div class="card"><div class="card-title">'+t('itemHistory')+'</div>'
          +   '<div class="history-line">'+t('updatedAt')+': '+esc(updated)+'</div>'
          +   '<div class="history-line">'+t('createdAt')+': '+esc(created)+'</div>'
          + '</div>';
        if(typeNum===3){
          var c=c0.card||{};
          return baseHead
            + '<div class="card"><div class="card-title">Card details</div>'
            + '<div class="field-row"><div><div class="field-label">Cardholder name</div><div class="field-value">'+esc(c.decCardholderName||c.cardholderName||'')+'</div></div></div>'
            + '<div class="field-row"><div><div class="field-label">Number</div><div class="field-value">'+esc(c.decNumber||c.number||'')+'</div></div></div>'
            + '<div class="field-row"><div><div class="field-label">Brand</div><div class="field-value">'+esc(c.decBrand||c.brand||'')+'</div></div></div>'
            + '<div class="field-row"><div><div class="field-label">Exp month/year</div><div class="field-value">'+esc((c.decExpMonth||c.expMonth||'')+' / '+(c.decExpYear||c.expYear||''))+'</div></div></div>'
            + '<div class="field-row"><div><div class="field-label">Security code (CVV)</div><div class="field-value">'+esc(c.decCode||c.code||'')+'</div></div></div>'
            + '</div>'
            + '<div class="card"><div class="card-title">Additional options</div><div class="field-row"><div><div class="field-label">Notes</div><div class="field-value">'+esc(notes)+'</div></div></div></div>'
            + renderReadOnlyCustomFields(c0)
            + history;
        }
        if(typeNum===4){
          var id=c0.identity||{};
          return baseHead
            + '<div class="card"><div class="card-title">Personal details</div>'
            + '<div class="field-row"><div><div class="field-label">Title</div><div class="field-value">'+esc(id.decTitle||id.title||'')+'</div></div></div>'
            + '<div class="field-row"><div><div class="field-label">First name</div><div class="field-value">'+esc(id.decFirstName||id.firstName||'')+'</div></div></div>'
            + '<div class="field-row"><div><div class="field-label">Middle name</div><div class="field-value">'+esc(id.decMiddleName||id.middleName||'')+'</div></div></div>'
            + '<div class="field-row"><div><div class="field-label">Last name</div><div class="field-value">'+esc(id.decLastName||id.lastName||'')+'</div></div></div>'
            + '<div class="field-row"><div><div class="field-label">Username</div><div class="field-value">'+esc(id.decUsername||id.username||'')+'</div></div></div>'
            + '<div class="field-row"><div><div class="field-label">Company</div><div class="field-value">'+esc(id.decCompany||id.company||'')+'</div></div></div>'
            + '</div>'
            + '<div class="card"><div class="card-title">Identity</div>'
            + '<div class="field-row"><div><div class="field-label">SSN</div><div class="field-value">'+esc(id.decSsn||id.ssn||'')+'</div></div></div>'
            + '<div class="field-row"><div><div class="field-label">Passport number</div><div class="field-value">'+esc(id.decPassportNumber||id.passportNumber||'')+'</div></div></div>'
            + '<div class="field-row"><div><div class="field-label">License number</div><div class="field-value">'+esc(id.decLicenseNumber||id.licenseNumber||'')+'</div></div></div>'
            + '</div>'
            + '<div class="card"><div class="card-title">Contact information</div>'
            + '<div class="field-row"><div><div class="field-label">Email</div><div class="field-value">'+esc(id.decEmail||id.email||'')+'</div></div></div>'
            + '<div class="field-row"><div><div class="field-label">Phone</div><div class="field-value">'+esc(id.decPhone||id.phone||'')+'</div></div></div>'
            + '</div>'
            + '<div class="card"><div class="card-title">Address</div>'
            + '<div class="field-row"><div><div class="field-label">Address 1</div><div class="field-value">'+esc(id.decAddress1||id.address1||'')+'</div></div></div>'
            + '<div class="field-row"><div><div class="field-label">Address 2</div><div class="field-value">'+esc(id.decAddress2||id.address2||'')+'</div></div></div>'
            + '<div class="field-row"><div><div class="field-label">Address 3</div><div class="field-value">'+esc(id.decAddress3||id.address3||'')+'</div></div></div>'
            + '<div class="field-row"><div><div class="field-label">City / Town</div><div class="field-value">'+esc(id.decCity||id.city||'')+'</div></div></div>'
            + '<div class="field-row"><div><div class="field-label">State / Province</div><div class="field-value">'+esc(id.decState||id.state||'')+'</div></div></div>'
            + '<div class="field-row"><div><div class="field-label">ZIP / Postal code</div><div class="field-value">'+esc(id.decPostalCode||id.postalCode||'')+'</div></div></div>'
            + '<div class="field-row"><div><div class="field-label">Country</div><div class="field-value">'+esc(id.decCountry||id.country||'')+'</div></div></div>'
            + '</div>'
            + '<div class="card"><div class="card-title">Additional options</div><div class="field-row"><div><div class="field-label">Notes</div><div class="field-value">'+esc(notes)+'</div></div></div></div>'
            + renderReadOnlyCustomFields(c0)
            + history;
        }
        if(typeNum===5){
          var ssh=c0.sshKey||{};
          var privateKey=ssh.decPrivateKey||ssh.privateKey||'';
          return baseHead
            + '<div class="card"><div class="card-title">SSH key</div>'
            + '<div class="field-row"><div><div class="field-label">Private key</div><div class="field-value">'+esc(privateKey?new Array(Math.max(String(privateKey).length,12)+1).join('•'):'')+'</div></div></div>'
            + '<div class="field-row"><div><div class="field-label">Public key</div><div class="field-value">'+esc(ssh.decPublicKey||ssh.publicKey||'')+'</div></div></div>'
            + '<div class="field-row"><div><div class="field-label">Fingerprint</div><div class="field-value">'+esc(ssh.decFingerprint||ssh.fingerprint||'')+'</div></div></div>'
            + '</div>'
            + '<div class="card"><div class="card-title">Additional options</div><div class="field-row"><div><div class="field-label">Notes</div><div class="field-value">'+esc(notes)+'</div></div></div></div>'
            + renderReadOnlyCustomFields(c0)
            + history;
        }
        if(typeNum===2){
          return baseHead
            + '<div class="card"><div class="card-title">Additional options</div><div class="field-row"><div><div class="field-label">Notes</div><div class="field-value">'+esc(notes)+'</div></div></div></div>'
            + renderReadOnlyCustomFields(c0)
            + history;
        }
        var login=c0.login||{};
        var username=login.decUsername||login.username||'';
        var rawPwd=login.decPassword||login.password||'';
        var masked=rawPwd?new Array(Math.max(rawPwd.length,12)+1).join('•'):'';
        var pwdText=state.showSelectedPassword?rawPwd:masked;
        var totp=login.decTotp||login.totp||'';
        var uri0=firstCipherUri(c0);
        return baseHead
          + '<div class="card"><div class="card-title">'+t('credentials')+'</div>'
          +   '<div class="field-row"><div><div class="field-label">Username</div><div class="field-value">'+esc(username)+'</div></div><button class="icon-btn" data-action="copy-field" data-value="'+esc(username)+'">'+t('copy')+'</button></div>'
          +   '<div class="field-row"><div><div class="field-label">Password</div><div class="field-value">'+esc(pwdText)+'</div></div><div><button class="icon-btn" data-action="toggle-password">'+(state.showSelectedPassword?t('hide'):t('reveal'))+'</button><button class="icon-btn" data-action="copy-field" data-value="'+esc(rawPwd)+'">'+t('copy')+'</button></div></div>'
          +   (totp?('<div class="field-row"><div><div class="field-label">TOTP</div><div class="field-value" id="totp-live-value">...</div><div class="field-sub" id="totp-live-remain"></div></div><button class="icon-btn" data-action="copy-totp-current">'+t('copy')+'</button></div>'):'')
          + '</div>'
          + '<div class="card"><div class="card-title">'+t('autofillOptions')+'</div>'
          +   '<div class="field-row"><div><div class="field-label">'+t('website')+'</div><div class="field-value">'+esc(uri0||'')+'</div></div><div>'+(uri0?('<button class="icon-btn" data-action="open-uri" data-value="'+esc(uri0)+'">'+t('open')+'</button>'):'')+(uri0?('<button class="icon-btn" data-action="copy-field" data-value="'+esc(uri0)+'">'+t('copy')+'</button>'):'')+'</div></div>'
          + '</div>'
          + renderReadOnlyCustomFields(c0)
          + history;
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

      function renderLockedScreen(){
        var email = String(state.profile && state.profile.email ? state.profile.email : state.session && state.session.email ? state.session.email : '');
        return ''
          + '<div class="auth-page">'
          + '  <div class="lang-switch" data-action="toggle-lang">'+t('langSwitch')+'</div>'
          + '  <div class="auth-card">'
          + '    <div class="auth-header">'
          + '      <div class="auth-logo"></div>'
          + '      <div class="auth-title">Unlock Vault</div>'
          + '      <div class="auth-subtitle">'+esc(email)+'</div>'
          + '    </div>'
          +      renderMsg()
          + (state.unlockError?('<div class="alert alert-danger">'+esc(state.unlockError)+'</div>'):'')
          + '    <form id="unlockForm">'
          + '      <div class="form-group"><label class="form-label">'+t('masterPwd')+'</label><input class="form-input" type="password" name="password" value="'+esc(state.unlockPassword)+'" required autofocus /></div>'
          + '      <button class="btn btn-primary" type="submit" style="width:100%; margin-top:16px;">Unlock</button>'
          + '    </form>'
          + '    <div style="display:flex; gap:8px; margin-top:16px;">'
          + '      <button class="btn btn-secondary" style="flex:1;" data-action="logout">Log Out</button>'
          + '    </div>'
          + '  </div>'
          + '</div>';
      }

      function renderVaultTab(){
        var list=filteredCiphers();
        function renderFolderOptions(selectedId){
          var html='<option value=""'+(!selectedId?' selected':'')+'>'+t('noFolder')+'</option>';
          for(var fi=0;fi<state.folders.length;fi++){
            var ff=state.folders[fi];
            var sid=String(selectedId||'')===String(ff.id)?' selected':'';
            html += '<option value="'+esc(ff.id)+'"'+sid+'>'+esc(ff.decName||ff.name||ff.id)+'</option>';
          }
          return html;
        }
        var rows='';
        for(var i=0;i<list.length;i++){
          var c=list[i];
          var nameText=(c.decName||c.name||c.id);
          var subtitle=listSubtitle(c);
          var uri=firstCipherUri(c);
          var host=hostFromUri(uri);
          var icon=host
            ? ('<span class="vault-item-icon-wrap"><img class="vault-item-icon" src="/icons/'+esc(host)+'/icon.png" alt="" onerror="this.style.display=\'none\';this.nextElementSibling.style.display=\'inline-flex\';"><span class="vault-item-icon vault-item-icon-fallback" style="display:none;">🌐</span></span>')
            : '<span class="vault-item-icon vault-item-icon-fallback">🌐</span>';
          rows += ''
            + '<div class="vault-item '+(c.id===state.selectedCipherId?'active':'')+'" data-action="pick-cipher" data-id="'+esc(c.id)+'">'
            +   '<input type="checkbox" class="vault-item-check" data-action="toggle-select" data-id="'+esc(c.id)+'"'+(state.selectedMap[c.id]?' checked':'')+' />'
            +   '<div class="vault-item-main">'+icon+'<div class="vault-item-text"><div class="vault-item-title">'+esc(nameText)+'</div><div class="vault-item-sub">'+esc(subtitle||'')+'</div></div></div>'
            + '</div>';
        }
        if(!rows) rows='<div class="vault-empty">'+t('noItems')+'</div>';

        var c0=selectedCipher();
        var detail='<div class="vault-empty" style="height:100%;">'+t('selectItem')+'</div>';
        if(state.detailMode==='create'){
          var dc=state.detailDraft||{};
          var wsHtml=''; var cws=Array.isArray(dc.websites)?dc.websites:[''];
          for(var wci=0;wci<cws.length;wci++){
            wsHtml += '<div class="field-row"><div style="flex:1;"><div class="field-label">'+t('website')+' (URI)</div><input class="detail-input" data-action="draft-website-change" data-index="'+wci+'" value="'+esc(cws[wci]||'')+'" /></div>'+(cws.length>1?'<button class="icon-btn" data-action="draft-website-remove" data-index="'+wci+'">✕</button>':'')+'</div>';
          }
          var cfHtml=''; var cfs=Array.isArray(dc.customFields)?dc.customFields:[];
          for(var cfi=0;cfi<cfs.length;cfi++){
            var cf=cfs[cfi]||{};
            cfHtml += '<div class="field-row"><div style="flex:1;"><div class="field-label">'+esc(cf.label||'')+' ('+esc(fieldTypeTextByNum(cf.type))+')</div><div class="field-value">'+esc(cf.value||'')+'</div></div><button class="icon-btn" data-action="draft-field-remove" data-index="'+cfi+'">✕</button></div>';
          }
          detail=''
            + '<div class="vault-detail-head card"><div class="vault-detail-title"><input class="detail-input" data-action="draft-change" data-field="name" placeholder="Name" value="'+esc(dc.name||'')+'" /></div><div class="vault-detail-folder">'+t('folder')+': <select class="detail-input" data-action="draft-change" data-field="folderId">'+renderFolderOptions(dc.folderId||'')+'</select></div></div>'
            + renderDraftTypeCards(dc)
            + (Number(dc.type||1)===1?('<div class="card"><div class="card-title">'+t('autofillOptions')+'</div>'+wsHtml+'<button class="link-btn" data-action="draft-website-add">'+t('addWebsite')+'</button>'
            + '</div>'):'')
            + '<div class="card"><div class="card-title">Additional options</div>'
            + '<textarea class="detail-input detail-textarea" data-action="draft-change" data-field="notes">'+esc(dc.notes||'')+'</textarea>'
            + '<div style="margin-top:10px;"><label><input type="checkbox" data-action="draft-change" data-field="reprompt" '+(dc.reprompt?'checked':'')+' /> Master password reprompt</label></div>'
            + '</div>'
            + '<div class="card"><div class="card-title">Fields</div>'+cfHtml+'<button class="link-btn" data-action="draft-field-open">'+t('addField')+'</button></div>'
            + '<div class="detail-actions"><div><button class="btn btn-primary" data-action="detail-save">Confirm</button><button class="btn btn-secondary" data-action="detail-cancel">Cancel</button></div><div></div></div>';
        } else if(c0){
          var folderLabel=c0.folderId?folderNameById(c0.folderId):t('noFolder');
          var updated=c0.revisionDate||c0.updatedAt||'';
          var created=c0.creationDate||c0.createdAt||'';
          if(state.detailMode==='edit'){
            var de=state.detailDraft||{};
            var ewsHtml=''; var ews=Array.isArray(de.websites)?de.websites:[''];
            for(var wei=0;wei<ews.length;wei++){
              ewsHtml += '<div class="field-row"><div style="flex:1;"><div class="field-label">'+t('website')+' (URI)</div><input class="detail-input" data-action="draft-website-change" data-index="'+wei+'" value="'+esc(ews[wei]||'')+'" /></div>'+(ews.length>1?'<button class="icon-btn" data-action="draft-website-remove" data-index="'+wei+'">✕</button>':'')+'</div>';
            }
            var efsHtml=''; var efs=Array.isArray(de.customFields)?de.customFields:[];
            for(var efi=0;efi<efs.length;efi++){
              var ef=efs[efi]||{};
              efsHtml += '<div class="field-row"><div style="flex:1;"><div class="field-label">'+esc(ef.label||'')+' ('+esc(fieldTypeTextByNum(ef.type))+')</div><div class="field-value">'+esc(ef.value||'')+'</div></div><button class="icon-btn" data-action="draft-field-remove" data-index="'+efi+'">✕</button></div>';
            }
            detail=''
            + '<div class="vault-detail-head card"><div class="vault-detail-title"><input class="detail-input" data-action="draft-change" data-field="name" value="'+esc(de.name||'')+'" /></div><div class="vault-detail-folder">'+t('folder')+': <select class="detail-input" data-action="draft-change" data-field="folderId">'+renderFolderOptions(de.folderId||'')+'</select></div></div>'
            + renderDraftTypeCards(de)
            + (Number(de.type||1)===1?('<div class="card"><div class="card-title">'+t('autofillOptions')+'</div>'+ewsHtml+'<button class="link-btn" data-action="draft-website-add">'+t('addWebsite')+'</button>'
            + '</div>'):'')
            + '<div class="card"><div class="card-title">Additional options</div>'
            + '<textarea class="detail-input detail-textarea" data-action="draft-change" data-field="notes">'+esc(de.notes||'')+'</textarea>'
            + '<div style="margin-top:10px;"><label><input type="checkbox" data-action="draft-change" data-field="reprompt" '+(de.reprompt?'checked':'')+' /> Master password reprompt</label></div>'
            + '</div>'
            + '<div class="card"><div class="card-title">Fields</div>'+efsHtml+'<button class="link-btn" data-action="draft-field-open">'+t('addField')+'</button></div>'
            + '<div class="detail-actions"><div><button class="btn btn-primary" data-action="detail-save">Confirm</button><button class="btn btn-secondary" data-action="detail-cancel">Cancel</button></div><button class="btn btn-danger" data-action="detail-delete">🗑</button></div>';
          } else detail=renderReadOnlyTypeDetails(c0, folderLabel, created, updated)
            + '<div class="detail-actions"><div><button class="btn btn-secondary" data-action="detail-edit">Edit</button></div><button class="btn btn-danger" data-action="detail-delete">🗑</button></div>';
        }

        return ''
          + renderMsg()
          + '<div class="vault-grid"><div class="vault-list-col"><div class="vault-list-head"><button class="btn btn-secondary" data-action="vault-refresh">'+t('refresh')+'</button><button class="btn btn-secondary" data-action="bulk-move">'+t('move')+'</button><button class="btn btn-danger" data-action="bulk-delete">'+t('delete')+' ('+selectedCount()+')</button><button class="btn btn-secondary" data-action="select-all">'+t('selectAll')+'</button><button class="btn btn-secondary" data-action="select-none">'+t('clear')+'</button><div class="create-menu-wrap"><button class="btn btn-primary" data-action="detail-create-toggle">+ New</button>'+renderCreateMenu()+'</div></div><div class="vault-list">'+rows+'</div></div><div class="vault-detail">'+detail+renderFieldModal()+'</div></div>';
      }

      function renderSettingsTab(){
        var p=state.profile||{};
        var secret=currentTotpSecret();
        var lockMins = Number(state.lockTimeoutMinutes)||0;
        return ''
          + renderMsg()
          + '<h2 style="margin:0 0 24px 0; font-size:24px; font-weight:600; color:var(--text-primary);">'+t('settings')+'</h2>'
          + '<div class="panel"><h3 style="margin-top:0;">Vault Lock</h3><form id="lockForm"><div class="form-group"><label class="form-label">Auto-lock timeout</label><select class="form-input" name="lockTimeoutMinutes"><option value="0"'+(lockMins===0?' selected':'')+'>Never</option><option value="1"'+(lockMins===1?' selected':'')+'>1 minute</option><option value="5"'+(lockMins===5?' selected':'')+'>5 minutes</option><option value="15"'+(lockMins===15?' selected':'')+'>15 minutes</option><option value="30"'+(lockMins===30?' selected':'')+'>30 minutes</option><option value="60"'+(lockMins===60?' selected':'')+'>60 minutes</option></select></div><button class="btn btn-primary" type="submit">Save Lock Settings</button></form></div>'
          + '<div class="panel"><h3 style="margin-top:0;">'+t('profile')+'</h3><form id="profileForm"><div style="display:flex; gap:16px; margin-bottom:16px;"><div class="form-group" style="flex:1;"><label class="form-label">'+t('name')+'</label><input class="form-input" name="name" value="'+esc(p.name||'')+'" /></div><div class="form-group" style="flex:1;"><label class="form-label">'+t('email')+'</label><input class="form-input" type="email" name="email" value="'+esc(p.email||'')+'" required /></div></div><button class="btn btn-primary" type="submit">'+t('saveProfile')+'</button></form></div>'
          + '<div class="panel"><h3 style="margin-top:0;">'+t('changePwd')+'</h3><form id="passwordForm"><div class="form-group"><label class="form-label">'+t('currentPwd')+'</label><input class="form-input" type="password" name="currentPassword" required /></div><div style="display:flex; gap:16px; margin-bottom:16px;"><div class="form-group" style="flex:1;"><label class="form-label">'+t('newPwd')+'</label><input class="form-input" type="password" name="newPassword" minlength="12" required /></div><div class="form-group" style="flex:1;"><label class="form-label">'+t('confirmPwd')+'</label><input class="form-input" type="password" name="newPassword2" minlength="12" required /></div></div><button class="btn btn-danger" type="submit">'+t('changePwd')+'</button><div class="tiny" style="margin-top:8px;">After success, current sessions are revoked and you must log in again.</div></form></div>'
          + '<div class="panel"><h3 style="margin-top:0;">'+t('totpSetup')+'</h3><div style="display:flex; gap:24px; margin-bottom:24px; flex-wrap:wrap;"><div class="totp-qr-card"><div id="totp-qr-box"><div class="totp-qr-fallback"><div>QR loading...</div><div class="tiny">Use secret key below</div></div></div></div><div style="flex:1; min-width:250px;"><form id="totpEnableForm"><div class="form-group"><label class="form-label">'+t('secret')+'</label><input class="form-input" name="secret" value="'+esc(secret)+'" /></div><div class="form-group"><label class="form-label">'+t('verifyCode')+'</label><input class="form-input" name="token" maxlength="6" value="'+esc(state.totpSetupToken)+'" /></div><div style="display:flex; gap:8px;"><button class="btn btn-primary" type="submit">'+t('enableTotp')+'</button><button class="btn btn-secondary" type="button" data-action="totp-secret-refresh">Regenerate</button><button class="btn btn-secondary" type="button" data-action="totp-secret-copy">Copy Secret</button></div></form></div></div><button class="btn btn-danger" type="button" data-action="totp-disable">'+t('disableTotp')+'</button><div class="tiny" style="margin-top:8px;">Disable action prompts for master password.</div></div>';
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
        var folders=''
          + '<button class="tree-btn '+(!state.folderFilterId?'active':'')+'" data-action="folder-filter" data-folder=""><span>▾</span><span>'+t('allItems')+'</span></button>'
          + '<button class="tree-btn '+(state.folderFilterId===NO_FOLDER_FILTER?'active':'')+'" data-action="folder-filter" data-folder="'+NO_FOLDER_FILTER+'"><span>📁</span><span>'+t('noFolder')+'</span></button>';
        for(var i=0;i<state.folders.length;i++){ var f=state.folders[i]; var folderName=(f.decName||f.name||f.id); folders += '<button class="tree-btn '+(state.folderFilterId===f.id?'active':'')+'" data-action="folder-filter" data-folder="'+esc(f.id)+'"><span>📁</span><span>'+esc(folderName)+'</span></button>'; }
        var typeTree=''
          + '<button class="tree-btn '+(state.vaultType==='all'?'active':'')+'" data-action="type-filter" data-type="all"><span>◉</span><span>'+t('typeAll')+'</span></button>'
          + '<button class="tree-btn '+(state.vaultType==='login'?'active':'')+'" data-action="type-filter" data-type="login"><span>⊕</span><span>'+t('typeLogin')+'</span></button>'
          + '<button class="tree-btn '+(state.vaultType==='card'?'active':'')+'" data-action="type-filter" data-type="card"><span>◧</span><span>'+t('typeCard')+'</span></button>'
          + '<button class="tree-btn '+(state.vaultType==='identity'?'active':'')+'" data-action="type-filter" data-type="identity"><span>◫</span><span>'+t('typeIdentity')+'</span></button>'
          + '<button class="tree-btn '+(state.vaultType==='note'?'active':'')+'" data-action="type-filter" data-type="note"><span>☰</span><span>'+t('typeNote')+'</span></button>'
          + '<button class="tree-btn '+(state.vaultType==='other'?'active':'')+'" data-action="type-filter" data-type="other"><span>•</span><span>'+t('typeOther')+'</span></button>';
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
          + '    <button class="btn btn-secondary" data-action="lock" style="margin-right:8px;">Lock</button>'
          + '    <button class="btn btn-secondary" data-action="logout">'+t('logout')+'</button>'
          + '  </div>'
          + '</div>'
          + '<div class="app-body">'
          + (showFolders?('  <aside class="sidebar">'
            + '<div class="sidebar-block"><div class="sidebar-title">'+t('filter')+'</div><input class="search-input" data-action="vault-search" placeholder="'+t('searchVault')+'" value="'+esc(state.vaultQuery)+'" /></div>'
            + '<div class="sidebar-block"><div class="sidebar-title">'+t('allItems')+'</div>'+typeTree+'</div>'
            + '<div class="sidebar-block"><div class="sidebar-title">'+t('folders')+'</div>'+folders+'</div>'
            + '</aside>'):'')
          + '  <main class="content">'+content+'</main>'
          + '</div>'+renderTotpDisableModal();
      }

      function render(){
        if(state.phase==='loading'){ app.innerHTML='<div class="auth-page" style="align-items:center; justify-content:center;"><div style="display:flex; flex-direction:column; align-items:center; gap:16px;"><div class="auth-logo" style="margin:0;"></div><div style="color:var(--text-secondary); font-weight:500;">'+t('loading')+'</div></div></div>'; return; }
        if(state.phase==='register'){ app.innerHTML=renderRegisterScreen(); return; }
        if(state.phase==='login'){ app.innerHTML=renderLoginScreen(); return; }
        if(state.phase==='locked'){ app.innerHTML=renderLockedScreen(); return; }
        app.innerHTML=renderApp();
        updateLiveTotpDisplay();
        renderTotpSetupQr();
      }

      async function init(){
        var url=new URL(window.location.href); state.inviteCode=(url.searchParams.get('invite')||'').trim(); state.session=loadSession();
        loadLockSettings();
        ensureTotpTicker();
        ensureLockChannel();
        ensureAutoLockTicker();
        var st=await fetch('/setup/status'); var setup=await jsonOrNull(st); var registered=!!(setup&&setup.registered);
        if(state.session){
          try{ await loadProfile(); state.phase='locked'; state.tab='vault'; render(); return; } catch(e){ state.session=null; saveSession(); }
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
          if(symKeyBytes){ state.session.symEncKey=bytesToBase64(symKeyBytes.slice(0,32)); state.session.symMacKey=bytesToBase64(symKeyBytes.slice(32,64)); }
        }catch(e){ console.warn('Key derivation failed:',e); }
        await loadVault(); await loadAdminData(); state.phase='app'; state.tab='vault'; state.lockLastActiveTs=Date.now();
        setMsg('Login success.', 'ok');
      }
      async function onSaveLockSettings(form){
        var fd=new FormData(form);
        var mins=Number(fd.get('lockTimeoutMinutes')||0);
        if(!Number.isFinite(mins)||mins<0) mins=15;
        state.lockTimeoutMinutes=mins;
        saveLockSettings();
        state.lockLastActiveTs=Date.now();
        setMsg('Lock settings saved.', 'ok');
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
      async function onEnableTotp(form){ var fd=new FormData(form); state.totpSetupSecret=String(fd.get('secret')||'').toUpperCase().replace(/[\s-]/g,'').replace(/=+$/g,''); state.totpSetupToken=String(fd.get('token')||'').trim(); if(!state.totpSetupSecret) return setMsg('TOTP secret is required.', 'err'); if(!state.totpSetupToken) return setMsg('TOTP token is required.', 'err'); var r=await authFetch('/api/accounts/totp',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:true,secret:state.totpSetupSecret,token:state.totpSetupToken})}); var j=await jsonOrNull(r); if(!r.ok) return setMsg((j&&(j.error||j.error_description))||'Enable TOTP failed.', 'err'); state.totpSetupToken=''; render(); setMsg('TOTP enabled.', 'ok'); }
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
      async function onBulkMove(){ var ids=[]; for(var k in state.selectedMap){ if(state.selectedMap[k]) ids.push(k);} if(ids.length===0) return setMsg('Select items first.', 'err'); var opts=['0) No folder']; for(var i=0;i<state.folders.length;i++){ var f=state.folders[i]; var label=(f.decName||f.name||f.id); opts.push(String(i+1)+') '+String(label)); } var pick=window.prompt('Move selected items to:\n'+opts.join('\n')+'\n\nInput number (empty to cancel):','0'); if(pick===null) return; pick=String(pick).trim(); if(!pick) return; var idx=Number(pick); if(!Number.isInteger(idx)||idx<0||idx>state.folders.length) return setMsg('Invalid folder selection.', 'err'); var folderId=idx===0?null:state.folders[idx-1].id; var r=await authFetch('/api/ciphers/move',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids:ids,folderId:folderId})}); var j=await jsonOrNull(r); if(!r.ok) return setMsg((j&&(j.error||j.error_description))||'Bulk move failed.', 'err'); await loadVault(); render(); setMsg('Moved selected items.', 'ok'); }

      async function onCreateInvite(form){ var fd=new FormData(form); var h=Number(fd.get('hours')||168); var r=await authFetch('/api/admin/invites',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({expiresInHours:h})}); var j=await jsonOrNull(r); if(!r.ok) return setMsg((j&&(j.error||j.error_description))||'Create invite failed.', 'err'); await loadAdminData(); render(); setMsg('Invite created.', 'ok'); }
      async function onToggleUserStatus(id,status){ var n=status==='active'?'banned':'active'; var r=await authFetch('/api/admin/users/'+encodeURIComponent(id)+'/status',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:n})}); var j=await jsonOrNull(r); if(!r.ok) return setMsg((j&&(j.error||j.error_description))||'Update user status failed.', 'err'); await loadAdminData(); render(); setMsg('User status updated.', 'ok'); }
      async function onDeleteUser(id){ if(!window.confirm('Delete this user and all user data?')) return; var r=await authFetch('/api/admin/users/'+encodeURIComponent(id),{method:'DELETE'}); var j=await jsonOrNull(r); if(!r.ok) return setMsg((j&&(j.error||j.error_description))||'Delete user failed.', 'err'); await loadAdminData(); render(); setMsg('User deleted.', 'ok'); }
      async function onRevokeInvite(code){ var r=await authFetch('/api/admin/invites/'+encodeURIComponent(code),{method:'DELETE'}); var j=await jsonOrNull(r); if(!r.ok) return setMsg((j&&(j.error||j.error_description))||'Revoke invite failed.', 'err'); await loadAdminData(); render(); setMsg('Invite revoked.', 'ok'); }

      app.addEventListener('submit', function(ev){
        var form=ev.target; if(!(form instanceof HTMLFormElement)) return; ev.preventDefault();
        if(form.id==='registerForm') return void onRegister(form);
        if(form.id==='loginForm') return void onLoginPassword(form);
        if(form.id==='loginTotpForm') return void onLoginTotp(form);
        if(form.id==='unlockForm') return void onUnlock(form);
        if(form.id==='lockForm') return void onSaveLockSettings(form);
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
        if(a==='lock'){ lockVault(true, true); return; }
        if(a==='totp-cancel'){ state.pendingLogin=null; state.loginTotpToken=''; state.loginTotpError=''; render(); return; }
        if(a==='totp-disable-cancel'){ state.totpDisableOpen=false; state.totpDisablePassword=''; state.totpDisableError=''; render(); return; }
        if(a==='tab'){ state.tab=n.getAttribute('data-tab')||'vault'; clearMsg(); render(); return; }
        if(a==='folder-filter'){ state.folderFilterId=n.getAttribute('data-folder')||''; syncSelectedWithFilter(); state.showSelectedPassword=false; render(); return; }
        if(a==='type-filter'){ state.vaultType=n.getAttribute('data-type')||'all'; syncSelectedWithFilter(); state.showSelectedPassword=false; render(); return; }
        if(a==='pick-cipher'){ state.selectedCipherId=n.getAttribute('data-id')||''; state.showSelectedPassword=false; render(); return; }
        if(a==='detail-create-toggle'){ state.createMenuOpen=!state.createMenuOpen; render(); return; }
        if(a==='detail-create-type'){ openCreateDraft(); if(state.detailDraft) state.detailDraft.type=Number(n.getAttribute('data-type')||1); render(); return; }
        if(a==='detail-edit'){ openEditDraft(selectedCipher()); render(); return; }
        if(a==='detail-cancel'){ closeDetailEdit(); render(); return; }
        if(a==='detail-save'){ return void saveDetailDraft(); }
        if(a==='detail-delete'){ return void deleteSelectedCipher(); }
        if(a==='draft-website-add'){ if(state.detailDraft){ if(!Array.isArray(state.detailDraft.websites)) state.detailDraft.websites=[]; state.detailDraft.websites.push(''); render(); } return; }
        if(a==='draft-website-remove'){ if(state.detailDraft&&Array.isArray(state.detailDraft.websites)){ var wi=Number(n.getAttribute('data-index')||-1); if(wi>=0&&wi<state.detailDraft.websites.length){ state.detailDraft.websites.splice(wi,1); if(!state.detailDraft.websites.length) state.detailDraft.websites.push(''); render(); } } return; }
        if(a==='draft-field-open'){ state.fieldModalOpen=true; state.fieldModalType='text'; state.fieldModalLabel=''; state.fieldModalValue=''; render(); return; }
        if(a==='field-modal-close'){ state.fieldModalOpen=false; render(); return; }
        if(a==='field-modal-add'){
          if(!state.detailDraft) return;
          var label=String(state.fieldModalLabel||'').trim(); if(!label) return setMsg('Field label is required.', 'err');
          if(!Array.isArray(state.detailDraft.customFields)) state.detailDraft.customFields=[];
          var typ=parseFieldType(state.fieldModalType);
          state.detailDraft.customFields.push({ type: typ, label: label, value: String(state.fieldModalValue||'') });
          state.fieldModalOpen=false; state.fieldModalLabel=''; state.fieldModalValue=''; render(); return;
        }
        if(a==='draft-field-remove'){ if(state.detailDraft&&Array.isArray(state.detailDraft.customFields)){ var fi=Number(n.getAttribute('data-index')||-1); if(fi>=0&&fi<state.detailDraft.customFields.length){ state.detailDraft.customFields.splice(fi,1); render(); } } return; }
        if(a==='toggle-select'){ ev.stopPropagation(); state.selectedMap[n.getAttribute('data-id')]=!!n.checked; render(); return; }
        if(a==='select-all'){ var list=filteredCiphers(); state.selectedMap={}; for(var i=0;i<list.length;i++) state.selectedMap[list[i].id]=true; render(); return; }
        if(a==='select-none'){ state.selectedMap={}; render(); return; }
        if(a==='toggle-password'){ state.showSelectedPassword=!state.showSelectedPassword; render(); return; }
        if(a==='copy-totp-current'){ var tv=document.getElementById('totp-live-value'); var txt=tv?String(tv.textContent||'').replace(/\s+/g,''):''; if(!txt) return setMsg('No current TOTP code.', 'err'); navigator.clipboard.writeText(txt).then(function(){ setMsg('Copied to clipboard.', 'ok'); }).catch(function(){ setMsg('Copy failed.', 'err'); }); return; }
        if(a==='copy-field'){ var val=n.getAttribute('data-value')||''; navigator.clipboard.writeText(val).then(function(){ setMsg('Copied to clipboard.', 'ok'); }).catch(function(){ setMsg('Copy failed.', 'err'); }); return; }
        if(a==='open-uri'){ var v=n.getAttribute('data-value')||''; if(!v) return; if(!/^https?:\/\//i.test(v)) v='https://'+v; window.open(v, '_blank', 'noopener'); return; }
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

      app.addEventListener('input', function(ev){
        var n=ev.target;
        if(!(n instanceof HTMLInputElement) && !(n instanceof HTMLTextAreaElement) && !(n instanceof HTMLSelectElement)) return;
        var a=n.getAttribute('data-action');
        if(a==='vault-search'){
          state.vaultQuery=String(n.value||'');
          if(ev.isComposing||state.vaultSearchComposing) return;
          if(state.vaultSearchTimer) clearTimeout(state.vaultSearchTimer);
          state.vaultSearchTimer=setTimeout(function(){ syncSelectedWithFilter(); render(); }, 120);
          return;
        }
        if(a==='draft-change'&&state.detailDraft){
          var field=n.getAttribute('data-field')||'';
          if(field){
            if(n instanceof HTMLInputElement && n.type==='checkbox') state.detailDraft[field]=!!n.checked;
            else state.detailDraft[field]=String(n.value||'');
          }
          return;
        }
        if(a==='draft-website-change'&&state.detailDraft){
          var wi=Number(n.getAttribute('data-index')||-1);
          if(!Array.isArray(state.detailDraft.websites)) state.detailDraft.websites=[];
          if(wi>=0&&wi<state.detailDraft.websites.length) state.detailDraft.websites[wi]=String(n.value||'');
          return;
        }
        if(a==='field-modal-label'){ state.fieldModalLabel=String(n.value||''); return; }
        if(a==='field-modal-value'){ state.fieldModalValue=String(n.value||''); return; }
      });

      app.addEventListener('change', function(ev){
        var n=ev.target;
        if(!(n instanceof HTMLSelectElement)) return;
        var a=n.getAttribute('data-action');
        if(a==='field-modal-type'){ state.fieldModalType=String(n.value||'text'); return; }
      });

      app.addEventListener('compositionstart', function(ev){
        var n=ev.target;
        if(n instanceof HTMLInputElement && n.getAttribute('data-action')==='vault-search') state.vaultSearchComposing=true;
      });
      app.addEventListener('compositionend', function(ev){
        var n=ev.target;
        if(n instanceof HTMLInputElement && n.getAttribute('data-action')==='vault-search'){
          state.vaultSearchComposing=false;
          state.vaultQuery=String(n.value||'');
          if(state.vaultSearchTimer) clearTimeout(state.vaultSearchTimer);
          state.vaultSearchTimer=setTimeout(function(){ syncSelectedWithFilter(); render(); }, 60);
        }
      });

      ['click','keydown','mousemove','touchstart','scroll'].forEach(function(evt){
        window.addEventListener(evt, markUserActivity, { passive: true });
      });

      init();
    }
