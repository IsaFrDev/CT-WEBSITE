/**
 * CT Cyber Team — Website Interactive Logic
 * Handles scanner, dashboard, animations, and navigation.
 */

function resolveApiBase() {
    if (typeof window === 'undefined') return 'http://localhost:5000/api';
    if (typeof window.__CT_API_BASE__ === 'string' && window.__CT_API_BASE__.trim())
        return window.__CT_API_BASE__.trim();
    const h = window.location.hostname;
    if (h === 'localhost' || h === '127.0.0.1') return 'http://localhost:5000/api';
    return '';
}
const API_BASE = resolveApiBase();

/** Supabase Email: Providers → Email (yoqiq).
 *  Authentication → URL configuration: Site URL ham, Redirect URLs ham `getRedirectForSupabaseMagicLink()` chiqqan manzil bilan bir xil (masalan prod Vercel). */
const CT_SUPABASE = {
    url: 'https://iwtkibrjkyunvebvdceq.supabase.co',
    anonKey:
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Iml3dGtpYnJqa3l1bnZlYnZkY2VxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Nzc3MDM4NTksImV4cCI6MjA5MzI3OTg1OX0.H06pXAyKgKxIackBSKl2tM91HPvpuzR3ly7jNqyqhVc',
};
if (typeof window !== 'undefined' && window.__CT_SUPABASE__) {
    Object.assign(CT_SUPABASE, window.__CT_SUPABASE__);
}
const SUPABASE_URL = String(CT_SUPABASE.url || '').trim();
const SUPABASE_ANON_KEY = String(CT_SUPABASE.anonKey || '').trim();

/** Ishlab chiqish uchun hozirgi sahifa URL; email havolasida KO‘PINCHA prod kerak → CT_EMAIL_AFTER_AUTH_REDIRECT. */
function getSiteUrlForAuthRedirect() {
    let path = window.location.pathname || '/';
    path = path.replace(/\/(?:index)?\.html?$/i, '');
    if (path !== '/' && !path.endsWith('/')) path += '/';
    if (path === '') path = '/';
    return window.location.origin + path;
}

/** Emaildagi «Verify» havolasi mana shu adresga boshlaydi (localhost emas!).
 *  Lokal tekshirish: brauzerda `window.__CT_AUTH_REDIRECT_URL__ = 'http://localhost:3000/'` yozing (OTP yuborishdan OLDIN sahifani yangilang). */
const CT_EMAIL_AFTER_AUTH_REDIRECT =
    typeof window !== 'undefined' && window.__CT_EMAIL_AFTER_AUTH__
        ? String(window.__CT_EMAIL_AFTER_AUTH__).trim()
        : 'https://ct-website-red.vercel.app/';

function normalizeAuthRedirectTarget(urlString) {
    try {
        const url = new URL(urlString.trim());
        let path = url.pathname || '/';
        path = path.replace(/\/(?:index)?\.html?$/i, '');
        if (path !== '/' && !path.endsWith('/')) path += '/';
        if (path === '') path = '/';
        return url.origin + path;
    } catch {
        const s = String(urlString).trim();
        return s.endsWith('/') ? s : `${s}/`;
    }
}

function getRedirectForSupabaseMagicLink() {
    const a =
        typeof window.__CT_AUTH_REDIRECT_URL__ === 'string' && window.__CT_AUTH_REDIRECT_URL__.trim()
            ? window.__CT_AUTH_REDIRECT_URL__.trim()
            : '';
    if (a) return normalizeAuthRedirectTarget(a);

    const legacy =
        typeof window.__CT_GOOGLE_REDIRECT_URI__ === 'string' && window.__CT_GOOGLE_REDIRECT_URI__.trim()
            ? window.__CT_GOOGLE_REDIRECT_URI__.trim()
            : '';
    if (legacy) return normalizeAuthRedirectTarget(legacy);

    if (CT_EMAIL_AFTER_AUTH_REDIRECT) return normalizeAuthRedirectTarget(CT_EMAIL_AFTER_AUTH_REDIRECT);

    return getSiteUrlForAuthRedirect();
}

function stripOAuthFragmentFromBar() {
    if (!window.location.hash || !/#access_token=/.test(window.location.hash)) return;
    const clean = `${window.location.pathname}${window.location.search || ''}`;
    window.history.replaceState({}, document.title, clean);
}

let sbAuth = null;
let shownEmailBannerFor = '';

function showEmailSignedInBanner(email) {
    if (!email || shownEmailBannerFor === email) return;
    shownEmailBannerFor = email;
    const gmailOutput = document.getElementById('gmailOutput');
    const hint = document.getElementById('authEmailHint');
    if (hint) hint.textContent = '';
    if (gmailOutput) {
        gmailOutput.style.display = 'block';
        gmailOutput.innerHTML = `<div style="background:rgba(0,230,119,0.12);border:1px solid rgba(0,230,119,0.35);padding:14px;border-radius:10px">
            <p style="color:var(--success);font-weight:700;margin-bottom:8px">✅ Ulandi: <span style="color:var(--text-primary)">${email}</span></p>
            <p style="color:var(--text-secondary);font-size:0.9rem">Phishing uchun yuqoridagi maydonga shubhali havolani qo'yib sinab koʻring.</p>
        </div>`;
        document.getElementById('try-now')?.scrollIntoView({ behavior: 'smooth' });
    }
}

if (SUPABASE_URL && SUPABASE_ANON_KEY && typeof window.supabase !== 'undefined' && window.supabase.createClient) {
    sbAuth = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
        auth: { detectSessionInUrl: true },
    });

    sbAuth.auth.onAuthStateChange((event, session) => {
        if ((event === 'SIGNED_IN' || event === 'INITIAL_SESSION') && session?.user?.email) {
            stripOAuthFragmentFromBar();
            showEmailSignedInBanner(session.user.email);
        }
        if (event === 'SIGNED_OUT') shownEmailBannerFor = '';
    });
}

// ============================================================
//  PHISHING ANALYZER (Client-side fallback)
// ============================================================
const PHISHING_KEYWORDS = [
    'urgent','click now','verify account','suspended','blocked',
    'confirm identity','update payment','security alert','unusual activity',
    'account locked','reset password','expire','immediately',
    'kartangiz bloklandi','hisobingiz','tasdiqlang','shoshilinch',
];
const SUSPICIOUS_TLDS = ['.xyz','.top','.club','.online','.site','.tk','.ml','.ga','.cf','.gq','.work','.click','.link','.win','.bid'];
const LEGIT_DOMAINS = ['google.com','facebook.com','twitter.com','instagram.com','github.com','microsoft.com','apple.com','amazon.com','paypal.com','netflix.com','telegram.org','youtube.com','payme.uz','click.uz','uzcard.uz'];
const BRANDS = {paypal:'paypal.com',google:'google.com',facebook:'facebook.com',microsoft:'microsoft.com',apple:'apple.com',amazon:'amazon.com',netflix:'netflix.com',instagram:'instagram.com',telegram:'telegram.org',payme:'payme.uz',click:'click.uz',uzcard:'uzcard.uz'};
const HOMOGLYPHS = {'0':'o','1':'l','3':'e','4':'a','5':'s','7':'t','8':'b','|':'l','!':'i'};

function analyzeUrl(url) {
    if (!url) return {result:'invalid',confidence:0,findings:['Empty URL'],risk_score:0};
    if (!url.startsWith('http')) url = 'http://' + url;
    let findings = [], risk = 0;
    try {
        const u = new URL(url);
        const domain = u.hostname.toLowerCase();
        const path = u.pathname.toLowerCase();
        // Whitelist
        if (LEGIT_DOMAINS.some(d => domain.endsWith(d))) {
            return {result:'safe',confidence:0.95,findings:['✅ Verified legitimate domain'],risk_score:0,domain};
        }
        // IP address
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) { risk+=30; findings.push('⚠️ URL uses IP address'); }
        // Suspicious TLD
        for (const t of SUSPICIOUS_TLDS) { if (domain.endsWith(t)) { risk+=20; findings.push('⚠️ Suspicious TLD: '+t); break; } }
        // Long domain
        if (domain.length > 30) { risk+=15; findings.push('⚠️ Unusually long domain'); }
        // Subdomains
        if (domain.split('.').length > 4) { risk+=20; findings.push('⚠️ Excessive subdomains'); }
        // Brand impersonation
        const dp = domain.replace(/[.\-]/g,' ');
        for (const [b,ld] of Object.entries(BRANDS)) {
            if (dp.includes(b) && !domain.endsWith(ld)) { risk+=40; findings.push('🔴 Brand impersonation: '+b); break; }
        }
        // Homoglyph
        let base = domain.split('.')[0], norm = '', hasSub = false;
        for (const c of base) { if (HOMOGLYPHS[c]) { norm += HOMOGLYPHS[c]; hasSub = true; } else norm += c; }
        if (hasSub) { for (const b of Object.keys(BRANDS)) { if (norm === b) { risk+=35; findings.push('🔴 Homoglyph: "'+base+'" → "'+b+'"'); break; } } }
        // No HTTPS
        if (u.protocol === 'http:') { risk+=10; findings.push('⚠️ No HTTPS'); }
        // Path keywords
        for (const sp of ['login','signin','verify','secure','account','update','confirm']) {
            if (path.includes(sp)) { risk+=10; findings.push('⚠️ Suspicious path: '+sp); break; }
        }
        // @ in URL
        if (u.username || domain.includes('@')) { risk+=30; findings.push('🔴 @ in URL'); }
        // Dashes
        if ((domain.match(/-/g)||[]).length > 2) { risk+=15; findings.push('⚠️ Excessive dashes'); }

        risk = Math.min(risk, 100);
        const result = risk >= 60 ? 'phishing' : risk >= 30 ? 'suspicious' : 'safe';
        if (!findings.length) findings.push('✅ No threats detected');
        return {result, confidence: +(risk/100).toFixed(2), findings, risk_score: risk, domain};
    } catch(e) {
        return {result:'error',confidence:0,findings:['❌ Invalid URL format'],risk_score:0};
    }
}

// ============================================================
//  NAVIGATION
// ============================================================
const navbar = document.getElementById('navbar');
const navToggle = document.getElementById('navToggle');
const navLinks = document.getElementById('navLinks');

window.addEventListener('scroll', () => {
    navbar.classList.toggle('scrolled', window.scrollY > 50);
});

navToggle?.addEventListener('click', () => {
    navLinks.classList.toggle('open');
});

document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', () => navLinks.classList.remove('open'));
});

// Active nav on scroll
const sections = document.querySelectorAll('section[id]');
window.addEventListener('scroll', () => {
    const y = window.scrollY + 100;
    sections.forEach(s => {
        const top = s.offsetTop, h = s.offsetHeight, id = s.id;
        const link = document.querySelector(`.nav-link[href="#${id}"]`);
        if (link) link.classList.toggle('active', y >= top && y < top + h);
    });
});

// ============================================================
//  COUNTER ANIMATION
// ============================================================
function animateCounters() {
    document.querySelectorAll('[data-count]').forEach(el => {
        const target = +el.dataset.count;
        const duration = 2000;
        const start = performance.now();
        function tick(now) {
            const p = Math.min((now - start) / duration, 1);
            const ease = 1 - Math.pow(1 - p, 3);
            el.textContent = Math.floor(ease * target).toLocaleString();
            if (p < 1) requestAnimationFrame(tick);
            else el.textContent = target.toLocaleString();
        }
        requestAnimationFrame(tick);
    });
}

// ============================================================
//  SCROLL ANIMATIONS
// ============================================================
const observer = new IntersectionObserver((entries) => {
    entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('visible'); observer.unobserve(e.target); } });
}, {threshold: 0.1});

document.querySelectorAll('.about-card, .feature-category, .step-card, .dash-card, .ai-item, .dl-card, .chart-card').forEach(el => {
    el.classList.add('fade-in');
    observer.observe(el);
});

// Animate hero stats when visible
const heroObserver = new IntersectionObserver((entries) => {
    entries.forEach(e => { if (e.isIntersecting) { animateCounters(); heroObserver.unobserve(e.target); } });
}, {threshold: 0.3});
const heroSection = document.getElementById('home');
if (heroSection) heroObserver.observe(heroSection);

// ============================================================
//  DEMO SCANNER (Hero)
// ============================================================
const demoScan = document.getElementById('demoScan');
const demoInput = document.getElementById('demoInput');
const scanResult = document.getElementById('scanResult');

demoScan?.addEventListener('click', () => {
    const url = demoInput.value.trim();
    if (!url) return;
    const r = analyzeUrl(url);
    const emoji = r.result === 'phishing' ? '🔴' : r.result === 'suspicious' ? '🟡' : '🟢';
    const color = r.result === 'phishing' ? '#ff4757' : r.result === 'suspicious' ? '#ffa502' : '#2ed573';
    const label = r.result === 'phishing' ? 'PHISHING DETECTED!' : r.result === 'suspicious' ? 'SUSPICIOUS LINK' : 'LINK IS SAFE';
    scanResult.style.borderColor = color + '33';
    scanResult.style.background = color + '0d';
    scanResult.innerHTML = `
        <div class="result-icon">${emoji}</div>
        <div class="result-text">
            <strong style="color:${color}">${label}</strong>
            <p>Risk Score: ${r.risk_score}/100 | Confidence: ${(r.confidence*100).toFixed(0)}%</p>
            <p>${r.findings[0] || ''}</p>
        </div>`;
});

// ============================================================
//  LIVE SCANNER (Try Now)
// ============================================================
const liveScan = document.getElementById('liveScan');
const liveInput = document.getElementById('liveInput');
const liveOutput = document.getElementById('liveOutput');

liveScan?.addEventListener('click', async () => {
    const url = liveInput.value.trim();
    if (!url) { liveOutput.innerHTML = '<p style="color:var(--warning)">⚠️ URL kiriting!</p>'; return; }

    liveOutput.innerHTML = '<p style="color:var(--accent);animation:pulse 1s infinite">🔍 Tekshirilmoqda...</p>';

    // Try backend first, fallback to client-side
    let result;
    try {
        const resp = await fetch(`${API_BASE}/scan/url`, {
            method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({url})
        });
        if (resp.ok) result = await resp.json();
        else throw new Error('API error');
    } catch(e) {
        result = analyzeUrl(url);
    }

    const emoji = result.result === 'phishing' ? '🔴' : result.result === 'suspicious' ? '🟡' : '🟢';
    const cls = result.result === 'phishing' ? 'result-phishing' : result.result === 'suspicious' ? 'result-suspicious' : 'result-safe';
    const label = result.result === 'phishing' ? 'XAVFLI — PHISHING!' : result.result === 'suspicious' ? 'SHUBHALI LINK' : 'XAVFSIZ ✅';

    let html = `<p class="${cls}" style="font-size:1.1rem;font-weight:700;margin-bottom:12px">${emoji} ${label}</p>`;
    html += `<p>📊 Risk Score: <strong>${result.risk_score}/100</strong></p>`;
    html += `<p>🎯 Confidence: <strong>${(result.confidence*100).toFixed(0)}%</strong></p>`;
    html += `<p>🌐 URL: ${url.substring(0,60)}${url.length>60?'...':''}</p>`;
    html += '<hr style="border-color:var(--border);margin:12px 0">';
    html += '<p style="margin-bottom:8px;font-weight:600">📋 Findings:</p>';
    (result.findings || []).forEach(f => { html += `<p style="padding:2px 0">${f}</p>`; });

    if (result.result === 'phishing') {
        html += '<hr style="border-color:var(--border);margin:12px 0">';
        html += '<p style="color:var(--danger);font-weight:700">⚠️ Bu linkni BOSMANG!</p>';
    }
    liveOutput.innerHTML = html;
});

liveInput?.addEventListener('keydown', e => { if (e.key === 'Enter') liveScan.click(); });

// ============================================================
//  DASHBOARD DATA
// ============================================================
async function loadDashboard() {
    // Default demo data
    let stats = {total_scans:1247,phishing_detected:287,total_users:843,suspicious_detected:156,daily_stats:[]};
    try {
        const r = await fetch(`${API_BASE}/stats`);
        if (r.ok) stats = await r.json();
    } catch(e) {}

    // Animate dashboard values
    animateValue('dashScans', stats.total_scans);
    animateValue('dashPhishing', stats.phishing_detected);
    animateValue('dashUsers', stats.total_users);
    animateValue('dashSuspicious', stats.suspicious_detected);

    // Chart bars
    const chartBars = document.getElementById('chartBars');
    if (chartBars) {
        const days = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
        const values = stats.daily_stats?.length ? stats.daily_stats.map(d=>d.scans) : [18,24,12,32,28,15,22];
        const max = Math.max(...values, 1);
        chartBars.innerHTML = '';
        values.forEach((v,i) => {
            const pct = (v/max*100);
            const wrap = document.createElement('div');
            wrap.className = 'chart-bar-wrap';
            wrap.innerHTML = `<div class="chart-bar" style="height:0%"><div class="chart-bar-value">${v}</div></div><div class="chart-bar-label">${days[i]||''}</div>`;
            chartBars.appendChild(wrap);
            setTimeout(() => { wrap.querySelector('.chart-bar').style.height = pct + '%'; }, 200 + i * 100);
        });
    }
}

function animateValue(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    const dur = 1500, start = performance.now();
    function tick(now) {
        const p = Math.min((now-start)/dur,1);
        const ease = 1 - Math.pow(1-p,3);
        el.textContent = Math.floor(ease*target).toLocaleString();
        if (p<1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
}

// Dashboard observer
const dashSection = document.getElementById('dashboard');
if (dashSection) {
    const dObs = new IntersectionObserver((entries) => {
        entries.forEach(e => { if (e.isIntersecting) { loadDashboard(); dObs.unobserve(e.target); } });
    }, {threshold: 0.2});
    dObs.observe(dashSection);
}

// ============================================================
//  INIT
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    console.log('🛡️ CT Cyber Team website loaded');

    // Language Switcher Logic
    const langSelect = document.getElementById('langSelect');
    
    function setLanguage(lang) {
        const t = translations[lang];
        if (!t) return;
        
        document.querySelectorAll('[data-i18n]').forEach(el => {
            const key = el.getAttribute('data-i18n');
            if (t[key]) {
                el.innerHTML = t[key];
            }
        });

        // Update placeholder if it exists
        const demoInput = document.getElementById('demoInput');
        if (demoInput && t.scan_placeholder) demoInput.placeholder = t.scan_placeholder;
        
        const demoScanBtn = document.getElementById('demoScan');
        if (demoScanBtn && t.scan_btn) demoScanBtn.textContent = t.scan_btn;

        // Save preference
        localStorage.setItem('ct_lang', lang);
    }

    langSelect?.addEventListener('change', (e) => {
        setLanguage(e.target.value);
    });

    // Load saved language
    const savedLang = localStorage.getItem('ct_lang') || 'uz';
    if (langSelect) langSelect.value = savedLang;
    setLanguage(savedLang);

    // ============================================================
    //  Supabase: email OTP / magic link (Google provider kerak emas)
    // ============================================================
    const authEmailInput = document.getElementById('authEmailInput');
    const authOtpInput = document.getElementById('authOtpInput');
    const btnEmailSendOtp = document.getElementById('btnEmailSendOtp');
    const btnEmailVerifyOtp = document.getElementById('btnEmailVerifyOtp');
    const authEmailHint = document.getElementById('authEmailHint');

    /** Supabase OTP endpoint 429 bermasligi uchun mijozdan keyingi yuborish oralig'i (ms). */
    const OTP_SEND_MIN_GAP_MS = 45000;
    let otpSendCooldownUntil = 0;
    let otpSendLabelOriginal = btnEmailSendOtp?.textContent || 'Kod yuborish';

    function otpSendCooldownLeftSec() {
        return Math.max(0, Math.ceil((otpSendCooldownUntil - Date.now()) / 1000));
    }

    function isAuthRateLimited(err) {
        if (!err) return false;
        const st = err.status ?? err.code;
        if (st === 429 || String(st) === '429') return true;
        const msg = `${err.message || ''}`.toLowerCase();
        return /429|too many|rate.?limit|throttl|bir necha martta/i.test(msg);
    }

    const otpTick = setInterval(() => {
        const left = otpSendCooldownLeftSec();
        if (!btnEmailSendOtp) return;
        if (left > 0) {
            btnEmailSendOtp.disabled = true;
            btnEmailSendOtp.textContent = `Kutasiz (${left}s)`;
        } else {
            btnEmailSendOtp.disabled = false;
            btnEmailSendOtp.textContent = otpSendLabelOriginal;
        }
    }, 1000);

    btnEmailSendOtp?.addEventListener('click', async () => {
        if (window.location.protocol === 'file:') {
            alert('HTTP server orqali oching (`file://`da email auth ishlamaydi).');
            return;
        }
        if (!sbAuth) {
            alert(
                'Supabase sozlanmagan. script.js ichida CT_SUPABASE.anonKey ni tekshiring yoki window.__CT_SUPABASE__.'
            );
            return;
        }
        const left = otpSendCooldownLeftSec();
        if (left > 0 && authEmailHint) {
            authEmailHint.textContent = `Biroz kutib turing (${left}s). Keyingi OTP xavfsizlik uchun oralig'i kerak.`;
            return;
        }
        const email = String(authEmailInput?.value || '')
            .trim()
            .toLowerCase();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            alert('Yaroqli email kiriting.');
            return;
        }
        if (typeof sessionStorage !== 'undefined') sessionStorage.setItem('ct_otp_email', email);
        if (authEmailHint) authEmailHint.textContent = 'Yuborilmoqda…';
        btnEmailSendOtp && (btnEmailSendOtp.disabled = true);

        const { error } = await sbAuth.auth.signInWithOtp({
            email,
            options: {
                emailRedirectTo: getRedirectForSupabaseMagicLink(),
                shouldCreateUser: true,
            },
        });

        if (authEmailHint) {
            if (error) {
                if (isAuthRateLimited(error)) {
                    otpSendCooldownUntil = Date.now() + 120000;
                    authEmailHint.textContent =
                        'Supabase chegarasi (429): juda tez‑tez yuborgan yoki kunlik limit toʻlgan. 2–5 daqiqa kuting, boshqa email bilan sinamasdan bitta akkauntni ishlating. Dashboard da Email rate limit rejasi tekshiring.';
                } else {
                    authEmailHint.textContent = `Xato: ${error.message}`;
                }
            } else {
                otpSendCooldownUntil = Date.now() + OTP_SEND_MIN_GAP_MS;
                authEmailHint.textContent =
                    'Email tekshiring. Kod kelgan boʻlsa quyidagi maydonga yozing — yoki xabardagi havolani oching (magic link).';
            }
        }
        if (btnEmailSendOtp)
            btnEmailSendOtp.disabled = otpSendCooldownLeftSec() > 0;
        if (error && typeof sessionStorage !== 'undefined') sessionStorage.removeItem('ct_otp_email');
    });

    window.addEventListener('beforeunload', () => clearInterval(otpTick));

    btnEmailVerifyOtp?.addEventListener('click', async () => {
        if (!sbAuth) return;
        const email =
            String(authEmailInput?.value || '')
                .trim()
                .toLowerCase() ||
            (typeof sessionStorage !== 'undefined' ? sessionStorage.getItem('ct_otp_email') || '' : '');
        const raw = String(authOtpInput?.value || '').trim().replace(/\s+/g, '');
        if (!email || !raw) {
            alert('Email va kodni kiriting.');
            return;
        }
        if (authEmailHint) authEmailHint.textContent = 'Tekshirilmoqda…';

        let res = await sbAuth.auth.verifyOtp({ email, token: raw, type: 'email' });
        if (res.error) res = await sbAuth.auth.verifyOtp({ email, token: raw, type: 'signup' });
        if (res.error) {
            if (authEmailHint) authEmailHint.textContent = `Kod toʻgʻri emas yoki muddat tugagan: ${res.error.message}`;
            return;
        }
        if (authEmailHint) authEmailHint.textContent = '';
        authOtpInput.value = '';
    });

    void (async () => {
        if (!sbAuth) return;
        const {
            data: { session },
        } = await sbAuth.auth.getSession();
        if (session?.user?.email) showEmailSignedInBanner(session.user.email);
    })();
});
