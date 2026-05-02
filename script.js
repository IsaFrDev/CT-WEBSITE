/**
 * CT Cyber Team — Website Interactive Logic
 * Handles scanner, dashboard, animations, and navigation.
 */

const API_BASE = 'http://localhost:5000/api';

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
    //  GMAIL OAUTH & SCANNER
    // ============================================================
    const CLIENT_ID = '47473682665-l0od8aalgp6doikk0bpu347nhup46jao.apps.googleusercontent.com';
    const REDIRECT_URI = window.location.origin + window.location.pathname;

    const btnGmailScan = document.getElementById('btnGmailScan');
    const gmailOutput = document.getElementById('gmailOutput');

    btnGmailScan?.addEventListener('click', () => {
        if (window.location.protocol === 'file:') {
            alert("Xatolik: Google orqali kirish uchun saytni Live Server (yoki HTTP server) orqali ochishingiz kerak. 'file://' manzilida Google ruxsat bermaydi!");
            return;
        }

        const oauth2Endpoint = 'https://accounts.google.com/o/oauth2/v2/auth';
        const form = document.createElement('form');
        form.setAttribute('method', 'GET');
        form.setAttribute('action', oauth2Endpoint);

        const params = {
            'client_id': CLIENT_ID,
            'redirect_uri': REDIRECT_URI,
            'response_type': 'token',
            'scope': 'https://www.googleapis.com/auth/gmail.readonly',
            'include_granted_scopes': 'true',
            'state': 'gmail_auth'
        };

        for (let p in params) {
            let input = document.createElement('input');
            input.setAttribute('type', 'hidden');
            input.setAttribute('name', p);
            input.setAttribute('value', params[p]);
            form.appendChild(input);
        }
        document.body.appendChild(form);
        form.submit();
    });

    // Check if returned from Google Auth
    const fragmentString = location.hash.substring(1);
    const params = {};
    const regex = /([^&=]+)=([^&]*)/g;
    let m;
    while (m = regex.exec(fragmentString)) {
        params[decodeURIComponent(m[1])] = decodeURIComponent(m[2]);
    }
    
    if (Object.keys(params).length > 0 && params['access_token']) {
        // Clear hash to prevent accidental re-fetches
        window.history.replaceState({}, document.title, window.location.pathname);
        
        if (gmailOutput) {
            gmailOutput.style.display = 'block';
            gmailOutput.innerHTML = '<p style="color:var(--accent);animation:pulse 1s infinite">📧 Gmaildan xabarlar olinmoqda va AI tekshirmoqda...</p>';
            
            // Scroll down to the Try Now section automatically
            setTimeout(() => {
                document.getElementById('try-now')?.scrollIntoView({behavior:'smooth'});
            }, 300);

            fetch(`${API_BASE}/gmail/fetch`, {
                method: 'POST',
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify({token: params['access_token']})
            })
            .then(res => res.json())
            .then(data => {
                if (data.error) throw new Error(data.error);
                let html = '<h4 style="margin-bottom:10px; color:#fff;">Oxirgi Xabarlar:</h4>';
                data.forEach(msg => {
                    const color = msg.result === 'phishing' ? '#ff4757' : msg.result === 'suspicious' ? '#ffa502' : '#2ed573';
                    const emoji = msg.result === 'phishing' ? '🔴' : msg.result === 'suspicious' ? '🟡' : '🟢';
                    html += `
                        <div style="background:rgba(255,255,255,0.05); padding:12px; border-radius:8px; margin-bottom:10px; border-left:4px solid ${color}">
                            <div style="display:flex; justify-content:space-between; margin-bottom:5px;">
                                <strong style="color:#fff; font-size:0.95rem;">${msg.sender.substring(0, 35)}</strong>
                                <span style="color:#888; font-size:0.8rem;">${msg.time}</span>
                            </div>
                            <p style="font-size:0.9rem; margin-bottom:8px; color:#ddd; line-height:1.4;">${msg.text.substring(0, 100)}...</p>
                            <div style="font-size:0.85rem; color:${color}; font-weight:600; padding:6px; background:rgba(0,0,0,0.2); border-radius:4px;">
                                ${emoji} AI Xulosasi: ${msg.reason}
                            </div>
                        </div>
                    `;
                });
                gmailOutput.innerHTML = html;
            })
            .catch(err => {
                gmailOutput.innerHTML = `<p style="color:var(--danger)">❌ Xatolik yuz berdi: ${err.message}</p>`;
            });
        }
    }
});
