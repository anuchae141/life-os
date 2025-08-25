
// Life OS — Secure + Biometric (AES-GCM + PBKDF2) • PWA
(function(){
  const QS = (s, r=document)=>r.querySelector(s);
  const QSA = (s, r=document)=>Array.from(r.querySelectorAll(s));
  const prefix = 'lo-';
  const SEC_KEY = 'lo-sec-v1';
  const WA_ID_KEY = 'lo-wa-id';
  const THEME_KEY = prefix+'theme';
  let state = {};
  let cryptoKey = null;
  let saveTimer = null;
  let inactivityTimer = null;
  const INACT_MS = 5*60*1000;

  if ('serviceWorker' in navigator) { navigator.serviceWorker.register('./service-worker.js').catch(()=>{}); }

  const setTheme = (dark)=>{
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    localStorage.setItem(THEME_KEY, dark? 'dark':'light');
    const t = QS('#lo-theme'); if (t) t.checked = dark;
  };
  function applyThemeFromStorage(){
    const t = localStorage.getItem(THEME_KEY);
    setTheme( t ? (t==='dark') : window.matchMedia('(prefers-color-scheme: dark)').matches );
    const themeToggle = QS('#lo-theme');
    if(themeToggle) themeToggle.addEventListener('change', e=> setTheme(e.target.checked));
    const themeLock = QS('#lo-theme-lock'); if(themeLock) themeLock.addEventListener('change', e=> setTheme(e.target.checked));
  }

  const te = new TextEncoder(), td = new TextDecoder();
  const b64 = {
    enc: (buf)=> btoa(String.fromCharCode(...new Uint8Array(buf))),
    dec: (b64)=>{ const bin=atob(b64); const u=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) u[i]=bin.charCodeAt(i); return u.buffer; }
  };
  const b64url = {
    enc: (buf)=>{ let s = btoa(String.fromCharCode(...new Uint8Array(buf))); return s.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); },
    dec: (s)=>{ s=s.replace(/-/g,'+').replace(/_/g,'/'); const pad=s.length%4; if(pad) s+='='.repeat(4-pad); const bin = atob(s); const u = new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) u[i]=bin.charCodeAt(i); return u.buffer; }
  };

  async function deriveKey(pass, saltB){
    const mat = await crypto.subtle.importKey('raw', te.encode(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({name:'PBKDF2', salt:saltB, iterations:200000, hash:'SHA-256'}, mat, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
  }
  async function encryptJSON(obj){
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = te.encode(JSON.stringify(obj));
    const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, cryptoKey, data);
    return { iv: b64.enc(iv), ct: b64.enc(ct) };
  }
  async function decryptJSON(payload){
    const iv = new Uint8Array(b64.dec(payload.iv));
    const ct = b64.dec(payload.ct);
    const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv}, cryptoKey, ct);
    return JSON.parse(td.decode(pt));
  }

  function pulseSaved(){
    const btn = QS('#btn-save');
    btn.textContent = 'บันทึกแล้ว • เข้ารหัส';
    btn.style.transform = 'scale(1.02)';
    setTimeout(()=>{ btn.style.transform='scale(1)'; }, 120);
  }
  function scheduleSave(){ clearTimeout(saveTimer); saveTimer = setTimeout(saveEncrypted, 400); }
  function resetInactivity(){ clearTimeout(inactivityTimer); inactivityTimer = setTimeout(()=> lockNow(), INACT_MS); }

  async function saveEncrypted(){
    if(!cryptoKey) return;
    const payload = await encryptJSON(state);
    let meta = localStorage.getItem(SEC_KEY);
    if(meta){ meta = JSON.parse(meta); meta.data = payload; }
    else { const salt = crypto.getRandomValues(new Uint8Array(16)); meta = { salt: b64.enc(salt), data: payload }; }
    localStorage.setItem(SEC_KEY, JSON.stringify(meta));
    pulseSaved();
  }

  function collectInputs(){
    const fields = QSA('#app input, #app textarea').filter(el=>el.id && el.id.startsWith(prefix));
    fields.forEach(el=>{
      if(el.type==='checkbox'){
        el.checked = !!state[el.id];
        el.addEventListener('input', ()=>{ state[el.id] = el.checked ? 1 : 0; scheduleSave(); resetInactivity(); });
      }else{
        el.value = state[el.id] ?? '';
        el.addEventListener('input', ()=>{ state[el.id] = el.value; scheduleSave(); resetInactivity(); });
      }
    });
  }

  function resetDay(){
    ['breaks','water','sun','done','stuck','next'].forEach(k=> delete state[prefix+k]);
    Object.keys(state).forEach(k=>{ if(k.includes('-sleep-')||k.includes('-water-')||k.includes('-sun-')||k.includes('-ex-')||k.includes('-walk-')) delete state[k]; });
    QSA('#daily input, #daily textarea').forEach(el=>{ if(el.type==='checkbox'){ el.checked=false; } if(el.tagName==='TEXTAREA'){ el.value=''; } });
    QSA('#habits input[type="checkbox"]').forEach(el=> el.checked=false);
    scheduleSave();
  }
  function resetWeek(){
    ['b1','b1def','b2','b2def','b3','b3def','wipA','wipB','rel','ex1','ex2','win','block','energy','nb1','nb2','nb3','r1','r2','r3','r4','r5','r6','r7']
      .forEach(id=> delete state[prefix+id]);
    QSA('#weekly input').forEach(el=> el.value='');
    QSA('#review input').forEach(el=> el.value='');
    QSA('#review textarea').forEach(el=> el.value='');
    QSA('#reset7 input[type="checkbox"]').forEach(el=> el.checked=false);
    QSA('#habits input[type="checkbox"]').forEach(el=> el.checked=false);
    scheduleSave();
  }

  function isWebAuthnAvail(){ return window.PublicKeyCredential && (window.isSecureContext || location.hostname==='localhost'); }
  async function enableBio(){
    if(!isWebAuthnAvail()){ alert('ต้องใช้งานบน HTTPS หรือ localhost เท่านั้น'); return; }
    const userId = crypto.getRandomValues(new Uint8Array(16));
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    try{
      const cred = await navigator.credentials.create({
        publicKey: {
          challenge,
          rp: { name: 'Life OS', id: location.hostname },
          user: { id: userId, name: 'user@lifeos', displayName: 'Life OS User' },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
          authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required' },
          timeout: 60000,
          attestation: 'none'
        }
      });
      const id = btoa(String.fromCharCode(...new Uint8Array(cred.rawId))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
      localStorage.setItem('lo-wa-id', id);
      alert('เปิดใช้ Face/Touch ID เรียบร้อย');
    }catch(e){ console.error(e); alert('ไม่สามารถเปิดใช้งานได้'); }
  }
  async function maybeRequireWebAuthn(){
    const id = localStorage.getItem('lo-wa-id');
    if(!id) return true;
    try{
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge,
          allowCredentials: [{ id: (function(){ const s=id.replace(/-/g,'+').replace(/_/g,'/'); const pad=s.length%4; const b=s + (pad? '='.repeat(4-pad):''); const bin=atob(b); const u=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) u[i]=bin.charCodeAt(i); return u.buffer; })(), type: 'public-key' }],
          userVerification: 'required',
          timeout: 60000
        }
      });
      return !!assertion;
    }catch(e){ console.error(e); alert('ยืนยันตัวตนด้วย Face/Touch ID ไม่สำเร็จ'); return false; }
  }
  async function biometricOnly(){ if(await maybeRequireWebAuthn()) alert('ยืนยันตัวตนสำเร็จ — โปรดกรอกรหัสผ่านเพื่อถอดรหัสข้อมูล'); }

  async function doUnlockOrSetup(){
    const meta = localStorage.getItem(SEC_KEY);
    const pass1 = QS('#pass1').value;
    const pass2 = QS('#pass2').value;
    if(meta){
      if(await maybeRequireWebAuthn() === false) return;
      if(pass1.length<1){ alert('กรอกรหัสผ่าน'); return; }
      const {salt, data} = JSON.parse(meta);
      const saltB = (function(b64){ const bin=atob(b64); const u=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) u[i]=bin.charCodeAt(i); return u.buffer; })(salt);
      try{
        cryptoKey = await deriveKey(pass1, new Uint8Array(saltB));
        state = await decryptJSON(data);
      }catch(e){ alert('รหัสผ่านไม่ถูกต้อง'); return; }
    }else{
      if(pass1.length<8){ alert('ตั้งรหัสอย่างน้อย 8 ตัวอักษร'); return; }
      if(pass1!==pass2){ alert('รหัสผ่านไม่ตรงกัน'); return; }
      const saltB = crypto.getRandomValues(new Uint8Array(16));
      cryptoKey = await deriveKey(pass1, saltB);
      state = {};
      const payload = await encryptJSON(state);
      const metaNew = { salt: btoa(String.fromCharCode(...new Uint8Array(saltB))), data: payload };
      localStorage.setItem(SEC_KEY, JSON.stringify(metaNew));
    }
    QS('#lock').style.display = 'none';
    QS('#app').style.visibility = 'visible';
    applyThemeFromStorage();
    collectInputs();
    pulseSaved();
    resetInactivity();
  }

  async function exportEncrypted(){
    const meta = localStorage.getItem(SEC_KEY) || '{}';
    const blob = new Blob([meta], {type:'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href=url; a.download='life-os-secure-backup.json'; a.click();
    setTimeout(()=>URL.revokeObjectURL(url), 1000);
  }
  function importEncrypted(){
    const i = document.createElement('input'); i.type='file'; i.accept='application/json';
    i.onchange = ()=>{
      const f = i.files[0]; if(!f) return;
      const fr = new FileReader();
      fr.onload = ()=>{
        try{
          const data = JSON.parse(fr.result);
          if(!data.salt || !data.data){ alert('ไฟล์ไม่ถูกต้อง'); return; }
          localStorage.setItem(SEC_KEY, JSON.stringify(data));
          alert('นำเข้าข้อมูลแล้ว — กรุณาปลดล็อกอีกครั้ง'); lockNow();
        }catch(e){ alert('ไฟล์ไม่ถูกต้อง'); }
      };
      fr.readAsText(f);
    };
    i.click();
  }
  async function changePassword(){
    const oldPass = prompt('กรอกรหัสผ่านเดิม'); if(oldPass===null) return;
    const meta = JSON.parse(localStorage.getItem(SEC_KEY) || '{}');
    if(!meta.salt || !meta.data){ alert('ยังไม่มีข้อมูลให้เปลี่ยนรหัส'); return; }
    try{
      const saltB = (function(b64){ const bin=atob(b64); const u=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) u[i]=bin.charCodeAt(i); return u.buffer; })(meta.salt);
      const oldKey = await deriveKey(oldPass, new Uint8Array(saltB));
      await crypto.subtle.decrypt({name:'AES-GCM', iv:new Uint8Array((function(b64){ const bin=atob(b64); const u=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) u[i]=bin.charCodeAt(i); return u.buffer; })(meta.data.iv))}, oldKey, (function(b64){ const bin=atob(b64); const u=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) u[i]=bin.charCodeAt(i); return u.buffer; })(meta.data.ct));
    }catch(e){ alert('รหัสเดิมไม่ถูกต้อง'); return; }
    const newPass = prompt('ตั้งรหัสผ่านใหม่ (≥ 8 ตัว)'); if(!newPass || newPass.length<8){ alert('รหัสใหม่สั้นเกินไป'); return; }
    const newSalt = crypto.getRandomValues(new Uint8Array(16));
    const newKey = await deriveKey(newPass, newSalt);
    const prevKey = cryptoKey;
    cryptoKey = newKey;
    const payload = await encryptJSON(state);
    const metaNew = { salt: btoa(String.fromCharCode(...new Uint8Array(newSalt))), data: payload };
    localStorage.setItem(SEC_KEY, JSON.stringify(metaNew));
    cryptoKey = prevKey;
    alert('เปลี่ยนรหัสผ่านเรียบร้อย');
  }

  function lockNow(){
    cryptoKey = null; state = {};
    QS('#app').style.visibility = 'hidden';
    const has = localStorage.getItem(SEC_KEY);
    if(has){
      QS('#lock-title').textContent = 'ปลดล็อก Life OS';
      QS('#lock-desc').textContent = 'กรอกรหัสผ่าน (หรือใช้ Face/Touch ID หากเปิดใช้งาน)';
      QS('#pass2').style.display = 'none';
      QS('#btn-only-bio').style.display = localStorage.getItem(WA_ID_KEY) ? '' : 'none';
    }else{
      QS('#lock-title').textContent = 'ตั้งรหัสผ่าน Life OS';
      QS('#lock-desc').textContent = 'รหัสนี้ใช้เข้ารหัสข้อมูลทั้งหมดในเครื่อง (หากลืมจะกู้ไม่ได้)';
      QS('#pass2').style.display = '';
      QS('#btn-only-bio').style.display = 'none';
    }
    QS('#pass1').value = ''; QS('#pass2').value = '';
    QS('#lock').style.display = 'flex';
  }

  document.addEventListener('visibilitychange', ()=>{ if(document.hidden) lockNow(); });
  ['click','keydown','touchstart'].forEach(ev=> document.addEventListener(ev, resetInactivity, {passive:true}));
  QS('#btn-unlock').addEventListener('click', doUnlockOrSetup);
  QS('#btn-only-bio').addEventListener('click', biometricOnly);
  QS('#btn-enable-bio').addEventListener('click', enableBio);
  QS('#btn-revoke-bio').addEventListener('click', ()=>{ localStorage.removeItem(WA_ID_KEY); alert('ปิดการใช้ Face/Touch ID แล้ว'); });
  QS('#btn-reset-day').addEventListener('click', ()=>{ if(confirm('ล้างข้อมูลประจำวัน?')) resetDay(); });
  QS('#btn-reset-week').addEventListener('click', ()=>{ if(confirm('ล้างข้อมูลรายสัปดาห์/นิสัย?')) resetWeek(); });
  QS('#btn-export').addEventListener('click', exportEncrypted);
  QS('#btn-import').addEventListener('click', importEncrypted);
  QS('#btn-change-pass').addEventListener('click', changePassword);

  setTheme( (localStorage.getItem(THEME_KEY) || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark':'light')) === 'dark' );
  applyThemeFromStorage();
  lockNow();
})();
