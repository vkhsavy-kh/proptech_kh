import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { html } from 'hono/html';
import { setCookie, getCookie } from 'hono/cookie';

interface Env {
  DB: D1Database;
  MEDIA?: R2Bucket;
  SESSIONS: KVNamespace;
  NOTIFICATIONS: Queue;
  APP_NAME: string;
  APP_URL: string;
  TELEGRAM_REDIRECT_URI: string;
  TELEGRAM_CLIENT_ID?: string;
  TELEGRAM_CLIENT_SECRET?: string;
  BOOTSTRAP_ADMIN_KEY?: string;
}

type Variables = { user: any | null };
const app = new Hono<{ Bindings: Env; Variables: Variables }>();
app.use('*', cors());

const page = (title:string, body:any) => html`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} — PropTech</title><script src="https://cdn.tailwindcss.com"></script></head><body class="bg-slate-50 text-slate-900"><nav class="bg-white border-b"><div class="max-w-7xl mx-auto px-6 py-4 flex justify-between"><a href="/" class="font-bold text-2xl">Prop<span class="text-emerald-600">Tech</span></a><div class="space-x-5"><a href="/properties">Properties</a><a href="/login">Login</a></div></div></nav>${body}</body></html>`;

// --- password hashing -------------------------------------------------------
// PBKDF2-HMAC-SHA256 with a per-password random salt. Stored format:
//   pbkdf2_sha256$<iterations>$<salt-b64>$<hash-b64>
// The iteration count lives in the stored value so it can be raised later
// and existing hashes upgraded on the next successful login.
//
// 100k is the hard ceiling: the Workers runtime rejects deriveBits above it
// with "iteration counts above 100000 are not supported" (NotSupportedError).
// Node's Web Crypto has no such cap, so verify against workerd, not node, when
// changing this value.
const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_SCHEME = 'pbkdf2_sha256';

const b64 = (bytes:Uint8Array) => { let s=''; for(const b of bytes) s+=String.fromCharCode(b); return btoa(s); };
const unb64 = (s:string) => { const bin=atob(s); const out=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i); return out; };

async function pbkdf2(password:string, salt:Uint8Array, iterations:number){
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name:'PBKDF2', salt: salt as unknown as BufferSource, iterations, hash:'SHA-256' }, key, 256);
  return new Uint8Array(bits);
}

// Constant-time compare: avoids leaking the match position via timing.
function safeEqual(a:Uint8Array, b:Uint8Array){
  if(a.length !== b.length) return false;
  let diff = 0;
  for(let i=0;i<a.length;i++) diff |= a[i]^b[i];
  return diff === 0;
}

async function hashPassword(password:string){
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return `${PBKDF2_SCHEME}$${PBKDF2_ITERATIONS}$${b64(salt)}$${b64(hash)}`;
}

// Verifies against either the new PBKDF2 scheme or the original unsalted
// SHA-256 helper. Legacy hashes still validate but are flagged for rehashing.
async function verifyPassword(password:string, stored:string){
  if(/^[0-9a-f]{64}$/i.test(stored)){
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password)));
    let hex=''; for(const b of digest) hex += b.toString(16).padStart(2,'0');
    const ok = safeEqual(new TextEncoder().encode(hex), new TextEncoder().encode(stored.toLowerCase()));
    return { ok, needsRehash: ok };
  }
  const parts = stored.split('$');
  if(parts.length !== 4 || parts[0] !== PBKDF2_SCHEME) return { ok:false, needsRehash:false };
  const iterations = Number(parts[1]);
  if(!Number.isFinite(iterations) || iterations < 1) return { ok:false, needsRehash:false };
  const actual = await pbkdf2(password, unb64(parts[2]), iterations);
  return { ok: safeEqual(actual, unb64(parts[3])), needsRehash: iterations < PBKDF2_ITERATIONS };
}
async function sessionUser(c:any){ const sid=getCookie(c,'proptech_session'); if(!sid) return null; const raw=await c.env.SESSIONS.get(`session:${sid}`); if(!raw) return null; const u=JSON.parse(raw); if(!u?.id) return null; // a session minted before a password change carries a stale epoch
  const row:any=await c.env.DB.prepare('SELECT session_epoch FROM users WHERE id=? AND status=?').bind(u.id,'active').first();
  if(!row) return null;
  if(Number(u.epoch||0) !== Number(row.session_epoch||0)){ await c.env.SESSIONS.delete(`session:${sid}`); return null; }
  return u;
}
async function requireAuth(c:any,next:any){ const u=await sessionUser(c); if(!u) return c.json({error:'Unauthorized'},401); c.set('user',u); await next(); }

// Mints a session stamped with the user's current session_epoch. Reading the
// value from the database (rather than the caller's copy of the user row)
// keeps a session valid across a password change for the acting browser only.
async function issueSession(c:any, u:any){
  const row:any = await c.env.DB.prepare('SELECT session_epoch FROM users WHERE id=?').bind(u.id).first();
  const payload = { ...u, epoch: Number(row?.session_epoch || 0) };
  const sid = crypto.randomUUID();
  await c.env.SESSIONS.put(`session:${sid}`, JSON.stringify(payload), { expirationTtl: 604800 });
  setCookie(c,'proptech_session',sid,{httpOnly:true,secure:true,sameSite:'Lax',path:'/',maxAge:604800});
  return sid;
}
async function requirePermission(c:any, code:string){ const u=c.get('user'); if(!u) return false; const row=await c.env.DB.prepare('SELECT 1 FROM role_permissions rp JOIN permissions p ON p.id=rp.permission_id WHERE rp.role_id=? AND p.code=?').bind(u.role_id,code).first(); return !!row; }

app.get('/', c => c.html(page('Home', html`<main class="max-w-7xl mx-auto px-6 py-16"><div class="rounded-3xl bg-slate-900 text-white p-10 md:p-16"><p class="text-emerald-300 font-semibold">CAMBODIA REAL ESTATE PLATFORM</p><h1 class="text-5xl font-bold mt-3">Find your next property with PropTech.</h1><p class="text-slate-300 mt-5 max-w-2xl">Buy, rent and manage property listings with a professional agency CRM built for Cambodia.</p><a href="/properties" class="inline-block mt-8 bg-emerald-500 px-6 py-3 rounded-xl font-semibold">Explore Properties</a></div><section class="mt-12"><h2 class="text-2xl font-bold">Featured Properties</h2><div id="featured" class="grid md:grid-cols-3 gap-5 mt-5"></div></section></main><script>fetch('/api/properties?limit=6').then(r=>r.json()).then(d=>{document.getElementById('featured').innerHTML=d.data.map(p=>\`<a href="/properties/\${p.id}" class="bg-white rounded-2xl overflow-hidden border"><div class="h-44 bg-slate-200"></div><div class="p-5"><div class="font-bold">\${p.title}</div><div class="text-sm text-slate-500 mt-2">\${p.property_type} · \${p.province||''}</div><div class="font-semibold mt-3">\${p.sale_price? '$'+Number(p.sale_price).toLocaleString():p.rent_price? '$'+Number(p.rent_price).toLocaleString()+'/mo':'Contact for price'}</div></div></a>\`).join('')})</script>`)));

// Search state lives entirely in the query string so any result set can be
// linked, bookmarked or shared, and the back button behaves as expected.
const clientScript = (mediaOn:boolean) => html`
<script>
const MEDIA = '${mediaOn ? 'true' : 'false'}' === 'true';
const DEFAULTS = { q:'', status:'published', listing_type:'', property_type:'', province:'', min_beds:'', min_price:'', max_price:'', sort:'newest', page:'1' };
let S = Object.assign({}, DEFAULTS);
const esc = s => String(s==null?'':s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const usd = n => n==null||n===''?'' : Number(n).toLocaleString('en-US',{maximumFractionDigits:0});
// Rebuild S from scratch rather than merging, so filters absent from the URL
// are actually cleared when navigating back or forward.
function readUrl(){ const p=new URLSearchParams(location.search); S=Object.assign({}, DEFAULTS); for(const k in S) if(p.get(k)) S[k]=p.get(k); }
function writeUrl(replace){ const p=new URLSearchParams(); for(const k in S) if(S[k]) p.set(k,S[k]); const u=p.toString()?'?'+p.toString():location.pathname; history[replace?'replaceState':'pushState']({},'',u); }
function qs(){ const p=new URLSearchParams(); for(const k in S) if(S[k]) p.set(k,S[k]); return p.toString(); }
const money = p => p.listing_type==='rent' && p.rent_price ? '$'+usd(p.rent_price)+'/mo' : p.sale_price ? '$'+usd(p.sale_price) : 'Price on request';
const where = p => [p.street,p.village,p.sangkat,p.district,p.province].filter(Boolean).join(', ') || 'Location not specified';

function card(p){
  const img = MEDIA
    ? (p.image_key ? '<img src="/media/'+encodeURIComponent(p.image_key)+'" alt="" loading="lazy" class="w-full h-52 object-cover">' : fallback(p))
    : fallback(p);
  return '<a href="/properties/'+p.id+'" class="group bg-white rounded-2xl border border-slate-200 overflow-hidden hover:shadow-lg hover:border-slate-300 transition flex flex-col">'
    + '<div class="relative">'+img
    + '<span class="absolute top-3 left-3 bg-slate-900/85 text-white text-[11px] font-semibold uppercase tracking-wide px-2.5 py-1 rounded-full">'+esc(p.listing_type==='rent'?'For Rent':'For Sale')+'</span>'
    + (p.image_count>1?'<span class="absolute bottom-3 right-3 bg-white/90 text-slate-700 text-[11px] font-semibold px-2 py-1 rounded-full">'+p.image_count+' photos</span>':'')
    + '</div>'
    + '<div class="p-4 flex flex-col flex-1">'
    + '<p class="text-xl font-bold text-slate-900">'+money(p)+'</p>'
    + '<p class="text-sm text-slate-600 mt-1.5 flex items-center gap-1.5 flex-wrap">'
      + '<span>'+esc(p.bedrooms??'—')+' bed</span><span class="text-slate-300">|</span>'
      + '<span>'+esc(p.bathrooms??'—')+' bath</span><span class="text-slate-300">|</span>'
      + '<span>'+esc(p.property_type||'Property')+'</span></p>'
    + '<h3 class="font-semibold mt-2.5 group-hover:text-emerald-700 transition line-clamp-2">'+esc(p.title)+'</h3>'
    + '<p class="text-xs text-slate-400 mt-1 truncate">'+esc(where(p))+'</p>'
    + '</div></a>';
}
function fallback(p){
  const t = esc((p.property_type||'Home').charAt(0).toUpperCase());
  return '<div class="w-full h-52 bg-gradient-to-br from-slate-100 to-slate-200 flex items-center justify-center text-slate-400 text-4xl font-light">'+t+'</div>';
}
function skeleton(){ let o=''; for(let i=0;i<6;i++) o+='<div class="bg-white rounded-2xl border border-slate-200 overflow-hidden"><div class="h-52 bg-slate-100 animate-pulse"></div><div class="p-4"><div class="h-6 bg-slate-100 rounded animate-pulse w-2/3"></div><div class="h-4 bg-slate-100 rounded animate-pulse w-1/2 mt-3"></div><div class="h-4 bg-slate-100 rounded animate-pulse w-3/4 mt-2"></div></div></div>'; return o; }

function activeChips(){
  const labels={listing_type:{sale:'For sale',rent:'For rent'},property_type:{},province:{},min_beds:{},min_price:{},max_price:{}};
  const out=[];
  if(S.listing_type) out.push(['listing_type', labels.listing_type[S.listing_type]||S.listing_type]);
  if(S.property_type) out.push(['property_type', S.property_type]);
  if(S.province) out.push(['province', S.province]);
  if(S.min_beds) out.push(['min_beds', S.min_beds+'+ beds']);
  if(S.min_price||S.max_price){
    const lo=S.min_price?'$'+usd(S.min_price):'Any';
    const hi=S.max_price?'$'+usd(S.max_price):'Any';
    out.push(['price', (S.min_price&&S.max_price)?lo+' – '+hi : S.min_price?'From '+lo : 'Up to '+hi]);
  }
  if(!out.length) return '';
  return '<div class="flex flex-wrap gap-2 mb-4">'+out.map(([k,l])=>'<button data-clear="'+k+'" class="inline-flex items-center gap-1.5 bg-slate-900 text-white text-xs font-medium px-3 py-1.5 rounded-full hover:bg-slate-700">'+esc(l)+' <span aria-hidden="true">&times;</span></button>').join('')+'<button data-clear="all" class="text-xs text-slate-500 underline hover:text-slate-900 px-2">Clear all</button></div>';
}

function facetRow(label, field, facets){
  const keys=Object.keys(facets||{}).sort();
  if(!keys.length) return '';
  return '<div><h3 class="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-2.5">'+label+'</h3><div class="space-y-1.5">'
    + keys.map(k=>'<label class="flex items-center gap-2.5 cursor-pointer group py-0.5"><input type="radio" name="'+field+'" data-f="'+field+'" value="'+esc(k)+'" '+(S[field]===k?'checked':'')+' class="accent-emerald-600 w-4 h-4"><span class="text-sm group-hover:text-emerald-700 flex-1 '+(S[field]===k?'font-semibold text-slate-900':'text-slate-600')+'">'+esc(k)+'</span><span class="text-xs text-slate-400 tabular-nums">'+facets[k]+'</span></label>').join('')
    + (S[field]?'<label class="flex items-center gap-2.5 cursor-pointer pt-1"><input type="radio" name="'+field+'" data-f="'+field+'" value="" class="accent-emerald-600 w-4 h-4"><span class="text-sm text-slate-500">Any</span></label>':'')
    + '</div></div>';
}
function bedRow(facets){
  const opts=[['','Any'],[1,'1+'],[2,'2+'],[3,'3+'],[4,'4+'],[5,'5+']];
  return '<div><h3 class="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-2.5">Bedrooms</h3><div class="flex flex-wrap gap-1.5">'
    + opts.map(([v,l])=>'<button data-f="min_beds" data-v="'+v+'" class="px-3 py-1.5 text-sm rounded-lg border '+(S.min_beds===v?'bg-slate-900 text-white border-slate-900':'border-slate-200 hover:border-slate-400')+'">'+l+'</button>').join('')
    + '</div></div>';
}

async function load(push){
  document.getElementById('grid').innerHTML = skeleton();
  document.getElementById('count').textContent = 'Loading…';
  writeUrl(push);
  const [res, fac] = await Promise.all([
    fetch('/api/properties?'+qs()).then(r=>r.json()),
    fetch('/api/properties/facets?'+qs()).then(r=>r.json()),
  ]);
  document.getElementById('chips').innerHTML = activeChips();
  document.getElementById('rail').innerHTML =
      bedRow(fac.beds)
    + '<div><h3 class="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-2.5">Price (USD)</h3>'
    + '<div class="flex items-center gap-2"><input id="minp" type="number" min="0" placeholder="Min" value="'+esc(S.min_price)+'" class="w-full p-2 text-sm border rounded-lg"><span class="text-slate-400">–</span><input id="maxp" type="number" min="0" placeholder="Max" value="'+esc(S.max_price)+'" class="w-full p-2 text-sm border rounded-lg"></div>'
    + '<button id="applyPrice" class="mt-2 w-full text-sm border border-slate-200 rounded-lg py-2 hover:border-slate-400">Apply price</button></div>'
    + facetRow('Property type','property_type',fac.types)
    + facetRow('Province','province',fac.provinces);
  document.getElementById('applyPrice').onclick = () => { S.min_price=document.getElementById('minp').value; S.max_price=document.getElementById('maxp').value; S.page='1'; load(true); };

  const total = res.total||0;
  document.getElementById('count').innerHTML = total
    ? '<span class="font-semibold text-slate-900">'+total+' propert'+(total===1?'y':'ies')+'</span>'
    : '<span class="text-slate-500">No matches</span>';
  document.getElementById('grid').innerHTML = total
    ? res.data.map(card).join('')
    : '<div class="col-span-full py-20 text-center"><div class="text-4xl mb-3">🏠</div><p class="font-semibold">No properties match these filters</p><p class="text-slate-500 text-sm mt-1.5">Try widening the price range or clearing a filter.</p><button id="resetInline" class="mt-5 bg-slate-900 text-white px-5 py-2.5 rounded-xl text-sm">Reset filters</button></div>';
  const reset = document.getElementById('resetInline');
  if(reset) reset.onclick = resetAll;

  let pg='';
  if(res.pages>1){
    const cur=res.page, last=res.pages;
    const btn=(p,label,dis,on)=>'<button data-page="'+p+'" '+(on?'class="bg-slate-900 text-white border-slate-900"':'class="border-slate-200 hover:border-slate-400"')+' '+(dis?'opacity-40 pointer-events-none':'')+' px-3.5 py-2 text-sm rounded-lg border">'+label+'</button>';
    const nums=[]; for(let i=Math.max(1,cur-2);i<=Math.min(last,cur+2);i++) nums.push('<button data-page="'+i+'" class="'+(i===cur?'bg-slate-900 text-white border-slate-900':'border-slate-200 hover:border-slate-400')+' px-3.5 py-2 text-sm rounded-lg border tabular-nums">'+i+'</button>');
    pg='<div class="col-span-full flex items-center justify-center gap-1.5 pt-6">'+btn(cur-1,'Prev',cur===1,false)+nums.join('')+btn(cur+1,'Next',cur===last,false)+'</div>';
  }
  document.getElementById('grid').insertAdjacentHTML('beforeend', pg);
}

document.addEventListener('click', e => {
  const f = e.target.closest('[data-f]');
  if(f){ const k=f.dataset.f; const v=(f.dataset.v!==undefined?f.dataset.v:f.value); S[k]=(S[k]===v?'':v); S.page='1'; load(true); return; }
  const c = e.target.closest('[data-clear]');
  if(c){ const k=c.dataset.clear;
    if(k==='all'){ S.property_type='';S.province='';S.min_beds='';S.min_price='';S.max_price='';S.q='';document.getElementById('q').value=''; }
    else if(k==='price'){ S.min_price='';S.max_price=''; }
    else S[k]='';
    S.page='1'; load(true); return; }
  const p = e.target.closest('[data-page]');
  if(p){ S.page=p.dataset.page; load(true); window.scrollTo({top:0,behavior:'smooth'}); }
});
document.getElementById('q').addEventListener('input', e => { S.q=e.target.value; S.page='1'; clearTimeout(window.__t); window.__t=setTimeout(()=>load(true),320); });
document.getElementById('sort').addEventListener('change', e => { S.sort=e.target.value; S.page='1'; load(true); });
for(const b of document.querySelectorAll('[data-lt]')) b.addEventListener('click', () => { S.listing_type=b.dataset.lt; S.page='1'; load(true); });
function resetAll(){ S.property_type='';S.province='';S.min_beds='';S.min_price='';S.max_price='';S.q='';S.listing_type='';document.getElementById('q').value='';S.page='1';load(true); }
document.getElementById('resetTop').onclick = resetAll;
window.addEventListener('popstate', () => { readUrl(); document.getElementById('q').value=S.q; document.getElementById('sort').value=S.sort; load(false); });
readUrl();
document.getElementById('q').value = S.q;
document.getElementById('sort').value = S.sort;
load(false);
</script>`;

app.get('/properties', c => {
  const mediaOn = !!c.env.MEDIA;
  return c.html(page('Properties', html`
<main class="max-w-7xl mx-auto px-4 sm:px-6 py-6">
  <div class="bg-white border border-slate-200 rounded-2xl p-3 sm:p-4 flex flex-col sm:flex-row gap-3 mb-6">
    <div class="flex rounded-xl bg-slate-100 p-1 shrink-0">
      <button data-lt="sale" class="flex-1 sm:flex-none px-4 py-2 text-sm font-semibold rounded-lg bg-white shadow-sm">Buy</button>
      <button data-lt="rent" class="flex-1 sm:flex-none px-4 py-2 text-sm font-semibold rounded-lg text-slate-500">Rent</button>
    </div>
    <div class="flex-1 relative">
      <input id="q" placeholder="Search by title, district, sangkat or street…" class="w-full p-2.5 pl-9 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-emerald-500/30">
      <svg class="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
    </div>
    <select id="sort" class="p-2.5 border border-slate-200 rounded-xl text-sm bg-white">
      <option value="newest">Newest first</option>
      <option value="price_asc">Price: low to high</option>
      <option value="price_desc">Price: high to low</option>
      <option value="beds">Most bedrooms</option>
    </select>
  </div>

  <div class="flex gap-6">
    <aside class="hidden lg:block w-60 shrink-0">
      <div class="flex items-center justify-between mb-4">
        <h2 class="font-bold">Filters</h2>
        <button id="resetTop" class="text-xs text-slate-500 hover:text-slate-900 underline">Reset</button>
      </div>
      <div id="rail" class="space-y-6"></div>
    </aside>

    <div class="flex-1 min-w-0">
      <div id="chips"></div>
      <div id="count" class="text-sm text-slate-500 mb-4">Loading…</div>
      <div id="grid" class="grid sm:grid-cols-2 xl:grid-cols-3 gap-5"></div>
    </div>
  </div>
</main>
${clientScript(mediaOn)}`));
});

app.get('/properties/:id', async c => { const p=await c.env.DB.prepare('SELECT * FROM properties WHERE id=?').bind(c.req.param('id')).first(); if(!p) return c.notFound(); return c.html(page(String((p as any).title), html`<main class="max-w-5xl mx-auto px-6 py-10"><div class="h-80 bg-slate-200 rounded-3xl"></div><div class="bg-white p-8 rounded-3xl mt-5"><p class="text-emerald-600 font-semibold">${(p as any).property_type}</p><h1 class="text-4xl font-bold mt-2">${(p as any).title}</h1><p class="text-slate-500 mt-2">${(p as any).province||''} ${(p as any).district||''} ${(p as any).sangkat||''}</p><div class="grid grid-cols-2 md:grid-cols-4 gap-4 mt-8"><div><b>${(p as any).bedrooms||'-'}</b><br>Bedrooms</div><div><b>${(p as any).bathrooms||'-'}</b><br>Bathrooms</div><div><b>${(p as any).land_area||'-'}</b><br>Land m²</div><div><b>${(p as any).building_area||'-'}</b><br>Building m²</div></div><p class="mt-8 whitespace-pre-line">${(p as any).description||''}</p><button class="mt-8 bg-emerald-600 text-white px-6 py-3 rounded-xl">Contact Agent</button></div></main>`)); });

app.get('/login', c => { const tg = !!(c.env.TELEGRAM_CLIENT_ID && c.env.TELEGRAM_CLIENT_SECRET && c.env.TELEGRAM_REDIRECT_URI && !c.env.TELEGRAM_REDIRECT_URI.includes('YOUR-DOMAIN')); return c.html(page('Login', html`<main class="max-w-md mx-auto px-6 py-16"><div class="bg-white border rounded-3xl p-8"><h1 class="text-3xl font-bold">Welcome to PropTech</h1><p class="text-slate-500 mt-2">Sign in with your phone/email and password${tg?', or Telegram.':'.'}</p><form id="login" class="space-y-4 mt-7"><input name="login" class="w-full p-3 border rounded-xl" placeholder="Email or phone" required><input name="password" type="password" class="w-full p-3 border rounded-xl" placeholder="Password" required><button class="w-full bg-slate-900 text-white p-3 rounded-xl">Login</button></form>${tg ? html`<div class="text-center my-5 text-slate-400">OR</div><a href="/auth/telegram" class="block text-center bg-sky-500 text-white p-3 rounded-xl">Continue with Telegram</a>` : ''}<p id="msg" class="text-sm mt-4 text-red-600"></p></div></main><script>document.getElementById('login').onsubmit=async e=>{e.preventDefault();let d=Object.fromEntries(new FormData(e.target));let r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});let j=await r.json().catch(()=>({error:'Login failed'}));if(r.ok)location='/dashboard';else document.getElementById('msg').textContent=j.error||'Login failed'}</script>`)); });

app.get('/dashboard', async c => { const u=await sessionUser(c); if(!u) return c.redirect('/login'); return c.html(page('Dashboard', html`<main class="max-w-7xl mx-auto px-6 py-10"><div class="flex justify-between"><div><p class="text-slate-500">Welcome</p><h1 class="text-4xl font-bold">${u.name}</h1><p class="text-sm text-slate-500 mt-1">Role: ${u.role}</p></div><a href="/admin/properties/new" class="bg-emerald-600 text-white px-5 py-3 rounded-xl">+ Add Property</a></div><div id="stats" class="grid md:grid-cols-4 gap-5 mt-8"></div><div class="bg-white border rounded-2xl p-6 mt-8"><h2 class="font-bold text-xl">Recent Properties</h2><div id="recent" class="mt-4"></div></div></main><script>fetch('/api/dashboard').then(r=>r.json()).then(d=>{document.getElementById('stats').innerHTML=[['Properties',d.properties],['Owners',d.owners],['Customers',d.customers],['Leads',d.leads]].map(x=>\`<div class="bg-white border rounded-2xl p-6"><div class="text-slate-500">\${x[0]}</div><div class="text-3xl font-bold mt-2">\${x[1]}</div></div>\`).join('');document.getElementById('recent').innerHTML=d.recent.map(p=>\`<div class="py-3 border-b flex justify-between"><span>\${p.title}</span><span class="text-sm text-slate-500">\${p.status}</span></div>\`).join('')})</script>`)); });

app.get('/admin/properties/new', async c => { const u=await sessionUser(c); if(!u) return c.redirect('/login'); return c.html(page('Add Property', html`<main class="max-w-4xl mx-auto px-6 py-10"><h1 class="text-4xl font-bold">Add Property</h1><p class="text-slate-500 mt-2">Five-step agency listing workflow.</p><form id="f" class="bg-white border rounded-3xl p-8 mt-8 space-y-5"><div class="grid md:grid-cols-2 gap-4"><input name="title" class="p-3 border rounded-xl" placeholder="Property title" required><select name="listing_type" class="p-3 border rounded-xl"><option value="sale">For Sale</option><option value="rent">For Rent</option><option value="sale_rent">Sale + Rent</option></select><select name="property_type" class="p-3 border rounded-xl"><option>Villa</option><option>Condo</option><option>House</option><option>Land</option><option>Shophouse</option><option>Apartment</option><option>Commercial</option></select><input name="sale_price" type="number" class="p-3 border rounded-xl" placeholder="Sale price USD"><input name="rent_price" type="number" class="p-3 border rounded-xl" placeholder="Rent/month USD"><input name="bedrooms" type="number" class="p-3 border rounded-xl" placeholder="Bedrooms"><input name="bathrooms" type="number" class="p-3 border rounded-xl" placeholder="Bathrooms"><input name="land_area" type="number" class="p-3 border rounded-xl" placeholder="Land area m²"><input name="building_area" type="number" class="p-3 border rounded-xl" placeholder="Building area m²"><input name="province" class="p-3 border rounded-xl" placeholder="Province"><input name="district" class="p-3 border rounded-xl" placeholder="Khan / District"><input name="sangkat" class="p-3 border rounded-xl" placeholder="Sangkat / Commune"><input name="village" class="p-3 border rounded-xl" placeholder="Village"><input name="street" class="p-3 border rounded-xl" placeholder="Street / Road"><input name="landmark" class="p-3 border rounded-xl" placeholder="Nearby landmark"><input name="latitude" type="number" step="any" class="p-3 border rounded-xl" placeholder="Latitude"><input name="longitude" type="number" step="any" class="p-3 border rounded-xl" placeholder="Longitude"></div><textarea name="description" class="w-full p-3 border rounded-xl" rows="6" placeholder="Description"></textarea><div class="border-2 border-dashed rounded-2xl p-8 text-center"><input id="photos" type="file" multiple accept="image/*"><p class="text-sm text-slate-500 mt-2">Photos are uploaded to Cloudflare R2 after the property is created.</p></div><button class="bg-emerald-600 text-white px-7 py-3 rounded-xl">Save Draft</button><p id="msg"></p></form></main><script>document.getElementById('f').onsubmit=async e=>{e.preventDefault();let data=Object.fromEntries(new FormData(e.target));for(let k of ['sale_price','rent_price','bedrooms','bathrooms','land_area','building_area','latitude','longitude'])if(data[k]==='')delete data[k];let r=await fetch('/api/properties',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});let j=await r.json();document.getElementById('msg').textContent=r.ok?'Saved property #'+j.id:(j.error||'Error');}</script>`)); });

app.post('/api/auth/login', async c => { let body:any; try { body=await c.req.json(); } catch { return c.json({error:'Invalid request body'},400); } const login=typeof body?.login==='string'?body.login.trim():''; const password=typeof body?.password==='string'?body.password:''; if(!login||!password) return c.json({error:'Invalid login'},401); const u:any=await c.env.DB.prepare('SELECT u.*,r.name role FROM users u JOIN roles r ON r.id=u.role_id WHERE (u.email=? OR u.phone=?) AND u.status="active"').bind(login,login).first(); if(!u){ // verify against a throwaway hash so a missing account costs the same as a wrong password and cannot be distinguished by timing
    await pbkdf2(password, crypto.getRandomValues(new Uint8Array(16)), PBKDF2_ITERATIONS); return c.json({error:'Invalid login'},401); }
  if(!u.password_hash){ await pbkdf2(password, crypto.getRandomValues(new Uint8Array(16)), PBKDF2_ITERATIONS); return c.json({error:'Invalid login'},401); }
  const check = await verifyPassword(password, u.password_hash);
  if(!check.ok) return c.json({error:'Invalid login'},401);
  if(check.needsRehash){ // transparently upgrade legacy/undersized hashes on successful login
    const upgraded = await hashPassword(password);
    await c.env.DB.prepare('UPDATE users SET password_hash=?, updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(upgraded, u.id).run();
    u.password_hash = upgraded;
  }
  await issueSession(c,u);
  return c.json({ok:true}); });

// Password strength is deliberately modest but explicit. The 12-character
// floor matches the bootstrap rule, and rejecting a reuse of the current
// password stops a "change" that silently leaves the old secret in place.
const PASSWORD_MIN = 12;
function passwordProblem(next:string, current:string){
  if(typeof next!=='string' || !next) return 'Enter a new password';
  if(next.length < PASSWORD_MIN) return `New password must be at least ${PASSWORD_MIN} characters`;
  if(next.length > 200) return 'New password is too long';
  if(typeof current==='string' && current && next===current) return 'New password must be different from your current one';
  return null;
}

app.post('/api/auth/password', requireAuth, async c => {
  const u = c.get('user');
  let body:any; try { body = await c.req.json(); } catch { return c.json({error:'Invalid request body'},400); }
  const current = typeof body?.current === 'string' ? body.current : '';
  const next = typeof body?.next === 'string' ? body.next : '';
  const problem = passwordProblem(next, current);
  if(problem) return c.json({ error: problem }, 400);
  if(!current) return c.json({ error: 'Enter your current password' }, 400);

  // Always read the stored hash from the database. The value cached in the
  // session payload can be a legacy SHA-256 digest that an earlier login
  // already upgraded, so trusting it could reject the correct password.
  const row:any = await c.env.DB.prepare('SELECT id, password_hash, role_id, name, email, phone, session_epoch FROM users WHERE id=? AND status=?').bind(u.id,'active').first();
  if(!row) return c.json({ error: 'Account not found' }, 404 );
  if(!row.password_hash){
    // No password set (for example a Telegram-only account): require the
    // bootstrap flow rather than letting anyone claim the account.
    return c.json({ error: 'This account has no password set. Use the Telegram login or contact an administrator.' }, 400 );
  }
  const check = await verifyPassword(current, row.password_hash);
  if(!check.ok) return c.json({ error: 'Current password is incorrect' }, 403 );

  const updated = await hashPassword(next);
  // Bumping the epoch retires every session issued under the old password,
  // including any an attacker may hold.
  await c.env.DB.prepare('UPDATE users SET password_hash=?, session_epoch=session_epoch+1, updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(updated, u.id).run();
  await c.env.DB.prepare('INSERT INTO audit_logs(actor_id,action,entity_type,entity_id,metadata) VALUES(?,?,?,?,?)').bind(u.id,'password_change','user',u.id,JSON.stringify({ invalidated_sessions: true })).run();
  // Reissue for this browser so the person who just changed it stays signed in.
  await issueSession(c, { ...row, epoch: Number(row.session_epoch||0) + 1 });
  return c.json({ ok: true, message: 'Password updated. Other devices have been signed out.' });
});

app.get('/account/password', async c => { const u=await sessionUser(c); if(!u) return c.redirect('/login'); return c.html(page('Change password', html`
<main class="max-w-lg mx-auto px-6 py-14">
  <a href="/dashboard" class="text-sm text-slate-500 hover:text-slate-900">&larr; Back to dashboard</a>
  <div class="bg-white border rounded-3xl p-8 mt-4">
    <h1 class="text-2xl font-bold">Change password</h1>
    <p class="text-slate-500 text-sm mt-1.5">Changing your password signs out every other device.</p>
    <form id="form" class="space-y-4 mt-7">
      <div><label class="block text-sm font-medium mb-1.5">Current password</label><input name="current" type="password" autocomplete="current-password" class="w-full p-3 border rounded-xl" required></div>
      <div><label class="block text-sm font-medium mb-1.5">New password</label><input name="next" type="password" autocomplete="new-password" minlength="12" class="w-full p-3 border rounded-xl" required><p class="text-xs text-slate-400 mt-1.5">At least 12 characters. Avoid passwords you use elsewhere.</p></div>
      <div><label class="block text-sm font-medium mb-1.5">Confirm new password</label><input name="confirm" type="password" autocomplete="new-password" minlength="12" class="w-full p-3 border rounded-xl" required></div>
      <div id="strength" class="h-1.5 rounded-full bg-slate-100 overflow-hidden"><div id="bar" class="h-full w-0 bg-rose-400 transition-all"></div></div>
      <button class="w-full bg-slate-900 text-white p-3 rounded-xl disabled:opacity-50" id="submit">Update password</button>
      <p id="msg" class="text-sm"></p>
    </form>
  </div>
</main>
<script>
const form=document.getElementById('form'), msg=document.getElementById('msg'), btn=document.getElementById('submit');
const bar=document.getElementById('bar'), nextEl=form.next, confirmEl=form.confirm;
// Cheap client-side length feedback only. The server owns the real check.
function score(){ const v=nextEl.value; let s=0; if(v.length>=12)s+=40; if(v.length>=16)s+=20; if(/[a-z]/.test(v)&&/[A-Z]/.test(v))s+=15; if(/[0-9]/.test(v))s+=15; if(/[^A-Za-z0-9]/.test(v))s+=10;
  bar.style.width=Math.min(100,s)+'%'; bar.className='h-full transition-all '+(s<40?'bg-rose-400':s<75?'bg-amber-400':'bg-emerald-500');
  btn.disabled = confirmEl.value!==v || v.length<12; }
nextEl.addEventListener('input',score); confirmEl.addEventListener('input',score);
form.onsubmit=async e=>{ e.preventDefault(); msg.textContent=''; msg.className='text-sm';
  if(nextEl.value!==confirmEl.value){ msg.textContent='The two new passwords do not match'; msg.className='text-sm text-red-600'; return; }
  btn.disabled=true;
  let r; try { r=await fetch('/api/auth/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current:form.current.value,next:nextEl.value})}); }
  catch { msg.textContent='Network error, try again'; msg.className='text-sm text-red-600'; btn.disabled=false; return; }
  const j=await r.json().catch(()=>({error:'Unexpected response'}));
  if(r.ok){ form.reset(); bar.style.width='0'; msg.textContent=j.message||'Password updated'; msg.className='text-sm text-emerald-700'; }
  else { msg.textContent=j.error||'Could not update password'; msg.className='text-sm text-red-600'; }
  btn.disabled=false; };
</script>`)); });

function b64url(bytes:ArrayBuffer|Uint8Array){ const a=bytes instanceof Uint8Array?bytes:new Uint8Array(bytes); let s=''; for(const b of a)s+=String.fromCharCode(b); return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }

const notice = (title:string, detail:string) => html`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} — PropTech</title><script src="https://cdn.tailwindcss.com"></script></head><body class="bg-slate-50 text-slate-900"><nav class="bg-white border-b"><div class="max-w-7xl mx-auto px-6 py-4 flex justify-between"><a href="/" class="font-bold text-2xl">Prop<span class="text-emerald-600">Tech</span></a><div class="space-x-5"><a href="/properties">Properties</a><a href="/login">Login</a></div></div></nav><main class="max-w-lg mx-auto px-6 py-20 text-center"><div class="bg-white border rounded-3xl p-10"><div class="w-14 h-14 rounded-2xl bg-amber-100 text-amber-700 flex items-center justify-center text-2xl mx-auto">!</div><h1 class="text-2xl font-bold mt-5">${title}</h1><p class="text-slate-500 mt-3">${detail}</p><div class="flex gap-3 justify-center mt-8"><a href="/login" class="px-5 py-2.5 rounded-xl bg-slate-900 text-white">Back to login</a><a href="/properties" class="px-5 py-2.5 rounded-xl border">Browse properties</a></div></div></main></body></html>`;
async function sha256Text(v:string){ return new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(v))); }
async function verifyTelegramJwt(token:string, clientId:string){
  const [h,p,s]=token.split('.'); if(!h||!p||!s) throw new Error('Invalid token');
  const header=JSON.parse(atob(h.replace(/-/g,'+').replace(/_/g,'/'))); const payload=JSON.parse(atob(p.replace(/-/g,'+').replace(/_/g,'/')));
  if(payload.iss!=='https://oauth.telegram.org' || String(payload.aud)!==String(clientId) || Number(payload.exp)<=Math.floor(Date.now()/1000)) throw new Error('Invalid claims');
  const jwks:any=await fetch('https://oauth.telegram.org/.well-known/jwks.json').then(r=>r.json());
  const jwk=jwks.keys.find((k:any)=>k.kid===header.kid); if(!jwk) throw new Error('Unknown signing key');
  const key=await crypto.subtle.importKey('jwk',jwk,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
  const data=new TextEncoder().encode(`${h}.${p}`); const sig=Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),x=>x.charCodeAt(0));
  if(!(await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,sig,data))) throw new Error('Invalid signature'); return payload;
}
app.get('/auth/telegram', async c => { const id=c.env.TELEGRAM_CLIENT_ID; if(!id||!c.env.TELEGRAM_CLIENT_SECRET) return c.html(notice('Telegram login is not available','Telegram sign-in has not been configured on this deployment yet. Use your email and password to sign in.'),503); if(!c.env.TELEGRAM_REDIRECT_URI||c.env.TELEGRAM_REDIRECT_URI.includes('YOUR-DOMAIN')) return c.html(notice('Telegram login is misconfigured','The Telegram redirect URI has not been set for this deployment. Use your email and password to sign in.'),503); const state=crypto.randomUUID(); const verifier=b64url(crypto.getRandomValues(new Uint8Array(32))); const challenge=b64url(await sha256Text(verifier)); await c.env.SESSIONS.put(`oauth:${state}`,verifier,{expirationTtl:600}); const url=new URL('https://oauth.telegram.org/auth'); url.searchParams.set('client_id',id); url.searchParams.set('redirect_uri',c.env.TELEGRAM_REDIRECT_URI); url.searchParams.set('response_type','code'); url.searchParams.set('scope','openid profile phone'); url.searchParams.set('state',state); url.searchParams.set('code_challenge',challenge); url.searchParams.set('code_challenge_method','S256'); return c.redirect(url.toString()); });
app.get('/auth/telegram/callback', async c => { try { const code=c.req.query('code'),state=c.req.query('state'); if(!code||!state) return c.html(notice('Sign-in failed','Telegram did not return an authorization code. Please try again.'),400); const verifier=await c.env.SESSIONS.get(`oauth:${state}`); await c.env.SESSIONS.delete(`oauth:${state}`); if(!verifier) return c.html(notice('Sign-in expired','This sign-in link was already used or took too long. Please try again.'),400); const basic=btoa(`${c.env.TELEGRAM_CLIENT_ID}:${c.env.TELEGRAM_CLIENT_SECRET}`); const form=new URLSearchParams({grant_type:'authorization_code',code,redirect_uri:c.env.TELEGRAM_REDIRECT_URI,client_id:c.env.TELEGRAM_CLIENT_ID!,code_verifier:verifier}); const tr=await fetch('https://oauth.telegram.org/token',{method:'POST',headers:{Authorization:`Basic ${basic}`,'Content-Type':'application/x-www-form-urlencoded'},body:form}); const tj:any=await tr.json(); if(!tr.ok||!tj.id_token) return c.html(notice('Telegram sign-in failed','Telegram rejected the sign-in request. Please try again.'),401); const claims:any=await verifyTelegramJwt(tj.id_token,c.env.TELEGRAM_CLIENT_ID!); const role:any=await c.env.DB.prepare('SELECT id FROM roles WHERE name=?').bind('customer').first(); if(!role) return c.html(notice('Sign-in unavailable','The customer role is missing from the database. Run the migrations again.'),500); const existing:any=await c.env.DB.prepare('SELECT u.*,r.name role FROM users u JOIN roles r ON r.id=u.role_id WHERE u.telegram_id=?').bind(String(claims.sub)).first(); let u:any=existing; if(!u){ if(!c.env.DB) return c.html(notice('Sign-in unavailable','Database binding is missing.'),500); const ins=await c.env.DB.prepare('INSERT INTO users(name,phone,telegram_id,telegram_username,role_id) VALUES(?,?,?,?,?)').bind(claims.name||claims.preferred_username||'Telegram User',claims.phone_number||null,String(claims.sub),claims.preferred_username||null,(role as any).id).run(); u=await c.env.DB.prepare('SELECT u.*,r.name role FROM users u JOIN roles r ON r.id=u.role_id WHERE u.id=?').bind(ins.meta.last_row_id).first(); } await issueSession(c,u); return c.redirect('/dashboard'); } catch(e){ console.error('telegram callback error', e); return c.html(notice('Sign-in failed','We could not complete Telegram sign-in. Please try again or use your email and password.'),401); } });

// Builds the shared WHERE clause used by both the search endpoint and the
// facet endpoint, so the counts in the filter rail can never disagree with
// the results they label.
type Facets = { types:Record<string,number>, provinces:Record<string,number>, beds:Record<string,number>, total:number };

function buildWhere(q:any){
  const where:string[] = ['1=1']; const args:any[] = [];
  const status = q.get('status');
  if(status){ where.push('status=?'); args.push(status); }
  const listing = q.get('listing_type');
  if(listing==='sale'||listing==='rent'){ where.push('listing_type=?'); args.push(listing); }
  const type = q.get('property_type');
  if(type){ where.push('property_type=?'); args.push(type); }
  const province = q.get('province');
  if(province){ where.push('province=?'); args.push(province); }
  const minBeds = Number(q.get('min_beds'));
  if(Number.isFinite(minBeds) && minBeds>0){ where.push('bedrooms>=?'); args.push(minBeds); }
  const min = Number(q.get('min_price')), max = Number(q.get('max_price'));
  if(Number.isFinite(min)&&min>0){ where.push('COALESCE(CASE WHEN listing_type=\'rent\' THEN rent_price ELSE sale_price END,0)>=?'); args.push(min); }
  if(Number.isFinite(max)&&max>0){ where.push('COALESCE(CASE WHEN listing_type=\'rent\' THEN rent_price ELSE sale_price END,0)<=?'); args.push(max); }
  const qy = (q.get('q')||'').trim();
  if(qy){ where.push('(title LIKE ? OR description LIKE ? OR province LIKE ? OR district LIKE ? OR sangkat LIKE ? OR village LIKE ? OR street LIKE ?)'); const x=`%${qy}%`; for(let i=0;i<7;i++) args.push(x); }
  return { sql: where.join(' AND '), args };
}

function tally<T extends string>(rows:any[], field:string):Record<string,number>{
  const out:Record<string,number> = {};
  for(const r of rows) if(r[field]!=null) out[String(r[field])]=(out[String(r[field])]||0)+1;
  return out;
}

app.get('/api/properties/facets', async c => {
  const { sql, args } = buildWhere(new URL(c.req.url).searchParams);
  const base = `SELECT property_type, province, bedrooms FROM properties WHERE ${sql}`;
  const { results } = await c.env.DB.prepare(base).bind(...args).all();
  const beds:Record<string,number> = {};
  for(const r of results as any[]){ const k = r.bedrooms==null?'any':String(r.bedrooms); beds[k]=(beds[k]||0)+1; }
  const f:Facets = { total:(results as any[]).length, types:tally(results as any[],'property_type'), provinces:tally(results as any[],'province'), beds };
  return c.json(f);
});

app.get('/api/properties', async c => {
  const q = new URL(c.req.url).searchParams;
  const { sql, args } = buildWhere(q);
  const page = Math.max(1, Number(q.get('page')||1) || 1);
  const perPage = Math.min(24, Math.max(1, Number(q.get('per_page')||12) || 12));
  const sorts:Record<string,string> = {
    newest: 'created_at DESC, id DESC',
    price_asc: 'eff_price ASC, id DESC',
    price_desc: 'eff_price DESC, id DESC',
    beds: 'bedrooms DESC, id DESC',
  };
  const sort = q.get('sort')||'newest';
  const order = sorts[sort] || sorts.newest;
  const total = await c.env.DB.prepare(`SELECT COUNT(*) AS n FROM properties WHERE ${sql}`).bind(...args).first<{n:number}>();
  const rows = await c.env.DB.prepare(`
    SELECT p.*, (SELECT object_key FROM property_images i WHERE i.property_id=p.id ORDER BY i.id LIMIT 1) AS image_key,
           (SELECT COUNT(*) FROM property_images i WHERE i.property_id=p.id) AS image_count
    FROM properties p
    WHERE ${sql.replace(/\b(status|property_type|province|bedrooms|listing_type|description|title|sale_price|rent_price|sangkat|village|street)\b/g,'p.$1')}
    ORDER BY ${order.replace(/eff_price/g,'COALESCE(CASE WHEN p.listing_type=\'rent\' THEN p.rent_price ELSE p.sale_price END,0)').replace(/created_at/g,'p.created_at')}
    LIMIT ? OFFSET ?`).bind(...args, perPage, (page-1)*perPage).all();
  const n = total?.n ?? 0;
  return c.json({ data: rows.results, page, per_page: perPage, total: n, pages: Math.max(1, Math.ceil(n/perPage)) });
});

app.post('/api/properties', requireAuth, async c => { if(!(await requirePermission(c,'property.create'))) return c.json({error:'Forbidden'},403); const u=c.get('user'); const p=await c.req.json(); const r=await c.env.DB.prepare(`INSERT INTO properties(title,description,listing_type,property_type,sale_price,rent_price,bedrooms,bathrooms,land_area,building_area,province,district,sangkat,village,street,landmark,latitude,longitude,agent_id,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(p.title,p.description||null,p.listing_type,p.property_type,p.sale_price||null,p.rent_price||null,p.bedrooms||null,p.bathrooms||null,p.land_area||null,p.building_area||null,p.province||null,p.district||null,p.sangkat||null,p.village||null,p.street||null,p.landmark||null,p.latitude||null,p.longitude||null,u.id,u.id).run(); await c.env.DB.prepare('INSERT INTO audit_logs(actor_id,action,entity_type,entity_id) VALUES(?,?,?,?)').bind(u.id,'create','property',r.meta.last_row_id).run(); return c.json({ok:true,id:r.meta.last_row_id}); });

app.get('/api/dashboard', requireAuth, async c => { const [p,o,cu,l,recent]=await Promise.all([c.env.DB.prepare('SELECT COUNT(*) n FROM properties').first(),c.env.DB.prepare('SELECT COUNT(*) n FROM owners').first(),c.env.DB.prepare('SELECT COUNT(*) n FROM customers').first(),c.env.DB.prepare('SELECT COUNT(*) n FROM leads').first(),c.env.DB.prepare('SELECT id,title,status FROM properties ORDER BY created_at DESC LIMIT 10').all()]); return c.json({properties:(p as any)?.n||0,owners:(o as any)?.n||0,customers:(cu as any)?.n||0,leads:(l as any)?.n||0,recent:recent.results}); });

app.post('/api/media/upload-url', requireAuth, async c => { if(!(await requirePermission(c,'property.edit'))) return c.json({error:'Forbidden'},403); return c.json({error:'Use R2 direct Worker upload route in production; this endpoint is reserved for signed-upload integration.'},501); });


app.post('/api/setup/bootstrap-admin', async c => { const key=c.req.header('x-bootstrap-key'); if(!c.env.BOOTSTRAP_ADMIN_KEY || key!==c.env.BOOTSTRAP_ADMIN_KEY) return c.json({error:'Forbidden'},403); let body:any; try { body=await c.req.json(); } catch { return c.json({error:'Invalid request body'},400); } const name=typeof body?.name==='string'?body.name.trim():''; const email=typeof body?.email==='string'?body.email.trim():''; const password=typeof body?.password==='string'?body.password:''; if(!name||!email||!password||password.length<12) return c.json({error:'name, email and a password of at least 12 characters are required'},400); const role:any=await c.env.DB.prepare('SELECT id FROM roles WHERE name=?').bind('super_admin').first(); if(!role) return c.json({error:'super_admin role missing; run migrations first'},500); const exists:any=await c.env.DB.prepare('SELECT id FROM users WHERE role_id=? LIMIT 1').bind(role.id).first(); if(exists) return c.json({error:'A super admin already exists'},409); const hash=await hashPassword(password); const r=await c.env.DB.prepare('INSERT INTO users(name,email,phone,password_hash,role_id) VALUES(?,?,?,?,?)').bind(name,email,typeof body?.phone==='string'?body.phone:null,hash,role.id).run(); return c.json({ok:true,id:r.meta.last_row_id}); });

app.post('/api/properties/:id/status', requireAuth, async c => { const u=c.get('user'); const body=await c.req.json(); const target=body.status; const allowed=['draft','pending_review','approved','published','under_offer','sold','rented','archived']; if(!allowed.includes(target)) return c.json({error:'Invalid status'},400); const perm=target==='published'?'property.publish':target==='approved'?'property.approve':'property.edit'; if(!(await requirePermission(c,perm))) return c.json({error:'Forbidden'},403); await c.env.DB.prepare('UPDATE properties SET status=?,published_at=CASE WHEN ?="published" THEN CURRENT_TIMESTAMP ELSE published_at END,updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(target,target,c.req.param('id')).run(); await c.env.DB.prepare('INSERT INTO audit_logs(actor_id,action,entity_type,entity_id,metadata) VALUES(?,?,?,?,?)').bind(u.id,'status_change','property',c.req.param('id'),JSON.stringify({status:target})).run(); return c.json({ok:true}); });

app.post('/api/properties/:id/images', requireAuth, async c => { if(!(await requirePermission(c,'property.edit'))) return c.json({error:'Forbidden'},403); if(!c.env.MEDIA) return c.json({error:'Media storage is not enabled on this deployment'},501); const form=await c.req.formData(); const file=form.get('file'); if(!(file instanceof File)) return c.json({error:'file is required'},400); if(file.size>15*1024*1024) return c.json({error:'Max 15MB'},413); if(!file.type.startsWith('image/')) return c.json({error:'Image only'},415); const key=`properties/${c.req.param('id')}/${crypto.randomUUID()}-${file.name.replace(/[^a-zA-Z0-9._-]/g,'_')}`; await c.env.MEDIA.put(key,file.stream(),{httpMetadata:{contentType:file.type}}); const r=await c.env.DB.prepare('INSERT INTO property_images(property_id,object_key,caption) VALUES(?,?,?)').bind(c.req.param('id'),key,String(form.get('caption')||'')).run(); return c.json({ok:true,id:r.meta.last_row_id,key}); });

app.get('/media/*', async c => { if(!c.env.MEDIA) return c.json({error:'Media storage is not enabled on this deployment'},501); const key=c.req.path.replace('/media/',''); const obj=await c.env.MEDIA.get(key); if(!obj) return c.notFound(); return new Response(obj.body,{headers:{'Content-Type':obj.httpMetadata?.contentType||'application/octet-stream','Cache-Control':'public, max-age=31536000, immutable'}}); });

app.get('/api/health', c=>c.json({ok:true,app:'PropTech',time:new Date().toISOString()}));

export default app;
