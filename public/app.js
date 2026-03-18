// ============================================================
// STATE
// ============================================================
const state = {
    token: localStorage.getItem('pob_token') || null,
    user: (() => { try { return JSON.parse(localStorage.getItem('pob_user')); } catch { return null; } })(),
    projectId: null,
    projectName: '',
    siteId: null,
    siteName: '',
    session: 'AM',
    scanCount: 0,
    totalEmployees: 0,
    scanner: null,
    scanning: false
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

function esc(s) {
    const d = document.createElement('div');
    d.textContent = s ?? '';
    return d.innerHTML;
}

// ============================================================
// API HELPER (attaches auth token)
// ============================================================
async function api(path, opts = {}) {
    const headers = { 'Content-Type': 'application/json', ...opts.headers };
    if (state.token) headers['Authorization'] = `Bearer ${state.token}`;

    const res = await fetch(`/api${path}`, { ...opts, headers });

    if (res.status === 401) {
        const body = await res.json();
        if (body.auth_required) {
            doLogout(true);
            return body;
        }
    }
    return res.json();
}

function toast(msg, type = 'info') {
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = msg;
    $('#toast-container').appendChild(el);
    setTimeout(() => el.remove(), 3000);
}

function timeStr() {
    return new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

const SESSION_LABELS = { AM: '9 AM', PM: '2 PM', EV: '6 PM' };
function sessionByHour() {
    const h = new Date().getHours();
    if (h < 12) return 'AM';
    if (h < 18) return 'PM';
    return 'EV';
}
function updateClock() {
    const now = new Date();
    $('#live-clock').textContent = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    const s = sessionByHour();
    $('#session-badge').textContent = SESSION_LABELS[s] || s;
    $('#session-badge').className = `badge badge-${s.toLowerCase()}`;
}

// ============================================================
// AUTH: LOGIN / LOGOUT
// ============================================================
function hideAllScreens() {
    $('#login-screen').style.display = 'none';
    $('#change-pin-screen').style.display = 'none';
    $('#totp-screen').style.display = 'none';
    $('header.topbar').style.display = 'none';
    $('#main-content').style.display = 'none';
    $('#setup-overlay').classList.add('hidden');
    $('#totp-setup-modal').classList.add('hidden');
}

function showLogin() {
    hideAllScreens();
    $('#login-screen').style.display = 'flex';
}

function showApp() {
    hideAllScreens();
    $('header.topbar').style.display = 'flex';
    $('#user-badge').textContent = state.user.display_name;
    $('#admin-tab').style.display = (state.user.role === 'admin' || state.user.role === 'executive') ? '' : 'none';
    const scannerTab = document.querySelector('.tab[data-tab="scanner"]');
    if (scannerTab) scannerTab.style.display = (state.user.role === 'focal_point') ? 'none' : '';
    $('#setup-overlay').classList.remove('hidden');
}

function doLogout(expired = false) {
    if (state.token && !expired) {
        fetch('/api/auth/logout', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${state.token}`, 'Content-Type': 'application/json' }
        }).catch(() => {});
    }
    state.token = null;
    state.user = null;
    localStorage.removeItem('pob_token');
    localStorage.removeItem('pob_user');
    localStorage.removeItem('pob_setup');
    if (state.scanner) { try { state.scanner.stop(); } catch(e) {} state.scanning = false; }
    showLogin();
    if (expired) toast('Session expired, please login again', 'error');
}

function initLogin() {
    const loginBtn = $('#login-btn');
    const usernameInput = $('#login-username');
    const totpInput = $('#login-totp');
    const errorDiv = $('#login-error');

    async function doLogin() {
        errorDiv.textContent = '';
        const username = usernameInput.value.trim();
        const totp_code = totpInput.value.trim();
        if (!username || !totp_code) { errorDiv.textContent = 'Enter username and 2FA code'; return; }
        if (totp_code.length !== 6 || !/^\d+$/.test(totp_code)) { errorDiv.textContent = 'Enter the 6-digit code from your authenticator app'; return; }

        loginBtn.disabled = true;
        loginBtn.textContent = 'Signing in...';

        try {
            const res = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, totp_code })
            });
            const data = await res.json();

            if (data.success) {
                state.token = data.token;
                state.user = data.user;
                localStorage.setItem('pob_token', data.token);
                localStorage.setItem('pob_user', JSON.stringify(data.user));
                totpInput.value = '';
                showApp();
                toast(`Welcome, ${data.user.display_name}`, 'success');
            } else {
                errorDiv.textContent = data.message;
                totpInput.value = '';
                totpInput.focus();
            }
        } catch (e) {
            errorDiv.textContent = 'Connection error. Is the server running?';
        }
        loginBtn.disabled = false;
        loginBtn.textContent = 'Sign in';
    }

    loginBtn.addEventListener('click', doLogin);
    totpInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') doLogin(); });
    usernameInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') totpInput.focus(); });

    $('#user-badge').addEventListener('click', () => {
        if (confirm('Logout?')) doLogout();
    });
}

function showChangePinScreen() {
    $('#login-screen').style.display = 'none';
    $('#change-pin-screen').style.display = 'flex';

    $('#change-pin-btn').onclick = async () => {
        const newPin = $('#new-pin').value.trim();
        const confirmPin = $('#confirm-pin').value.trim();
        const err = $('#pin-error');
        err.textContent = '';

        if (!newPin || newPin.length < 4) { err.textContent = 'PIN must be at least 4 digits'; return; }
        if (!/^\d+$/.test(newPin)) { err.textContent = 'PIN must be numbers only'; return; }
        if (newPin !== confirmPin) { err.textContent = 'PINs do not match'; return; }

        const res = await api('/auth/change-pin', {
            method: 'POST',
            body: JSON.stringify({ new_pin: newPin })
        });
        if (res.success) {
            state.user.must_change_pin = false;
            localStorage.setItem('pob_user', JSON.stringify(state.user));
            toast('PIN changed successfully', 'success');
            showApp();
        } else {
            err.textContent = res.message || 'Failed';
        }
    };
}

// ============================================================
// 2FA VERIFICATION (login step 2)
// ============================================================
function show2FAScreen(pendingToken) {
    hideAllScreens();
    $('#totp-screen').style.display = 'flex';
    const codeInput = $('#totp-code');
    const errorDiv = $('#totp-error');
    const verifyBtn = $('#totp-verify-btn');
    codeInput.value = '';
    errorDiv.textContent = '';
    codeInput.focus();

    const doVerify = async () => {
        const code = codeInput.value.trim();
        if (!code || code.length < 6) { errorDiv.textContent = 'Enter the 6-digit code'; return; }

        verifyBtn.disabled = true;
        verifyBtn.textContent = 'Verifying...';

        try {
            const res = await fetch('/api/auth/verify-2fa', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pending_token: pendingToken, totp_code: code })
            });
            const data = await res.json();

            if (data.success) {
                state.token = data.token;
                state.user = data.user;
                localStorage.setItem('pob_token', data.token);
                localStorage.setItem('pob_user', JSON.stringify(data.user));

                if (data.user.must_change_pin) showChangePinScreen();
                else { showApp(); toast(`Welcome, ${data.user.display_name}`, 'success'); }
            } else {
                errorDiv.textContent = data.message;
                codeInput.value = '';
                codeInput.focus();
            }
        } catch (e) {
            errorDiv.textContent = 'Connection error';
        }
        verifyBtn.disabled = false;
        verifyBtn.textContent = 'Verify';
    };

    verifyBtn.onclick = doVerify;
    codeInput.onkeypress = (e) => { if (e.key === 'Enter') doVerify(); };
    $('#totp-back-btn').onclick = showLogin;
}

// ============================================================
// 2FA SETUP
// ============================================================
async function open2FASetup() {
    $('#totp-setup-modal').classList.remove('hidden');
    $('#totp-setup-error').textContent = '';
    $('#totp-setup-code').value = '';

    const res = await api('/auth/2fa/setup', { method: 'POST' });
    if (!res.success) {
        $('#totp-setup-error').textContent = res.message || 'Failed';
        return;
    }

    $('#totp-setup-qr').src = `data:image/png;base64,${res.qr_code}`;
    $('#totp-setup-secret').textContent = res.secret;

    $('#totp-setup-confirm').onclick = async () => {
        const code = $('#totp-setup-code').value.trim();
        if (!code || code.length < 6) { $('#totp-setup-error').textContent = 'Enter the 6-digit code'; return; }

        const r = await api('/auth/2fa/confirm', { method: 'POST', body: JSON.stringify({ totp_code: code }) });
        if (r.success) {
            toast('2FA enabled!', 'success');
            state.user.totp_enabled = true;
            localStorage.setItem('pob_user', JSON.stringify(state.user));
            $('#totp-setup-modal').classList.add('hidden');
            if (typeof loadAdmin === 'function') loadAdmin();
        } else {
            $('#totp-setup-error').textContent = r.message || 'Invalid code';
        }
    };

    $('#totp-setup-cancel').onclick = () => $('#totp-setup-modal').classList.add('hidden');
}

async function disable2FA() {
    const totp_code = prompt('Enter your current 6-digit 2FA code to disable 2FA:');
    if (!totp_code || totp_code.length !== 6) return;
    const res = await api('/auth/2fa/disable', { method: 'POST', body: JSON.stringify({ totp_code: totp_code.trim() }) });
    if (res.success) {
        toast('2FA disabled. You will need to set it up again to sign in.', 'success');
        state.user.totp_enabled = false;
        localStorage.setItem('pob_user', JSON.stringify(state.user));
        if (typeof loadAdmin === 'function') loadAdmin();
    } else {
        toast(res.message || 'Failed', 'error');
    }
}

// ============================================================
// SETUP OVERLAY
// ============================================================
async function loadProjects(selectEl, includeAll = false) {
    const projects = await api('/projects');
    if (!Array.isArray(projects)) return [];
    selectEl.innerHTML = includeAll
        ? '<option value="">All Projects</option>'
        : '<option value="">-- Select Project --</option>';
    projects.forEach(p => {
        const opt = document.createElement('option');
        opt.value = p.id;
        opt.textContent = `${p.name} (${p.employee_count} workers)`;
        opt.dataset.name = p.name;
        selectEl.appendChild(opt);
    });
    return projects;
}

async function loadSitesForProject(selectEl, projectId) {
    if (!projectId) {
        selectEl.innerHTML = '<option value="">Select project first</option>';
        selectEl.disabled = true;
        return [];
    }
    const sites = await api(`/sites?project_id=${projectId}`);
    if (!Array.isArray(sites)) return [];
    selectEl.innerHTML = '<option value="">-- Select Site --</option>';
    sites.forEach(s => {
        const opt = document.createElement('option');
        opt.value = s.id;
        opt.textContent = s.name;
        selectEl.appendChild(opt);
    });
    selectEl.disabled = false;
    return sites;
}

function initSetup() {
    const projectSelect = $('#setup-project');
    const siteSelect = $('#setup-site');

    loadProjects(projectSelect);
    projectSelect.addEventListener('change', () => loadSitesForProject(siteSelect, projectSelect.value));

    const auto = sessionByHour();
    $$('.btn-session').forEach(btn => btn.classList.toggle('active', btn.dataset.session === auto));
    state.session = auto;

    $$('.btn-session').forEach(btn => {
        btn.addEventListener('click', () => {
            $$('.btn-session').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            state.session = btn.dataset.session;
        });
    });

    $('#setup-confirm').addEventListener('click', () => {
        if (!projectSelect.value) return toast('Select a project', 'error');
        if (!siteSelect.value) return toast('Select a site', 'error');

        state.projectId = projectSelect.value;
        state.projectName = projectSelect.options[projectSelect.selectedIndex].dataset.name;
        state.siteId = siteSelect.value;
        state.siteName = siteSelect.options[siteSelect.selectedIndex].text;

        localStorage.setItem('pob_setup', JSON.stringify({
            projectId: state.projectId, projectName: state.projectName,
            siteId: state.siteId, siteName: state.siteName, session: state.session
        }));

        $('#setup-overlay').classList.add('hidden');
        $('#main-content').style.display = 'block';
        updateScannerHeader();
        startScanner();
        loadTodayCount();
    });

    const saved = localStorage.getItem('pob_setup');
    if (saved) {
        try {
            const s = JSON.parse(saved);
            state.projectId = s.projectId;
            state.projectName = s.projectName;
            state.siteId = s.siteId;
            state.siteName = s.siteName;
            state.session = (s.session && ['AM','PM','EV'].includes(s.session)) ? s.session : auto;
            setTimeout(() => {
                projectSelect.value = s.projectId;
                loadSitesForProject(siteSelect, s.projectId).then(() => siteSelect.value = s.siteId);
                $$('.btn-session').forEach(btn => btn.classList.toggle('active', btn.dataset.session === state.session));
            }, 500);
        } catch { /* corrupted data */ }
    }
}

function updateScannerHeader() {
    $('#current-project-name').textContent = state.projectName;
    $('#current-site-name').textContent = state.siteName;
    const lbl = $('#current-session-label');
    lbl.textContent = SESSION_LABELS[state.session] || state.session;
    lbl.className = `badge badge-${(state.session || 'am').toLowerCase()}`;
}

// ============================================================
// IMPORT MODAL
// ============================================================
function initImportModal() {
    $('#import-cancel').addEventListener('click', () => $('#import-modal').classList.add('hidden'));
    $('#import-confirm').addEventListener('click', async () => {
        const file = $('#import-file').files[0];
        if (!file) return toast('Select a CSV file', 'error');
        const projectName = $('#import-project-name').value.trim();
        const status = $('#import-status');
        status.textContent = 'Importing...';

        const form = new FormData();
        form.append('file', file);
        if (projectName) form.append('project_name', projectName);

        try {
            const res = await fetch('/api/import-csv', {
                method: 'POST', body: form,
                headers: { 'Authorization': `Bearer ${state.token}` }
            });
            const result = await res.json();
            status.textContent = result.message || result.error;
            if (result.success) {
                toast(result.message, 'success');
                setTimeout(() => { $('#import-modal').classList.add('hidden'); status.textContent = ''; }, 1500);
            }
        } catch (e) {
            status.textContent = 'Upload failed';
        }
    });

    $('#btn-open-import-excel')?.addEventListener('click', () => {
        $('#import-modal').classList.remove('hidden');
        $('#import-excel-file').focus?.();
    });

    $('#import-excel-btn')?.addEventListener('click', async () => {
        const file = $('#import-excel-file')?.files?.[0];
        if (!file) return toast('Select an Excel (.xlsx) file', 'error');
        const status = $('#import-status');
        status.textContent = 'Importing Excel...';
        const form = new FormData();
        form.append('file', file);
        form.append('region', 'P&C BAB/NEB');
        try {
            const res = await fetch('/api/import-excel', {
                method: 'POST', body: form,
                headers: { 'Authorization': `Bearer ${state.token}` }
            });
            const result = await res.json();
            status.textContent = result.message || result.error || 'Done';
            if (result.success) {
                toast(result.message, 'success');
                $('#import-excel-file').value = '';
                setTimeout(() => { $('#import-modal').classList.add('hidden'); status.textContent = ''; }, 2000);
            }
        } catch (e) {
            status.textContent = 'Upload failed';
        }
    });
}

// ============================================================
// QR SCANNER
// ============================================================
async function startScanner() {
    if (state.scanner) { try { await state.scanner.stop(); } catch(e) {} }
    const container = $('#qr-reader');
    container.innerHTML = '';

    state.scanner = new Html5Qrcode('qr-reader');
    try {
        await state.scanner.start(
            { facingMode: 'environment' },
            { fps: 15, qrbox: { width: 250, height: 250 }, aspectRatio: 1.0,
              formatsToSupport: [Html5QrcodeSupportedFormats.QR_CODE] },
            onScanSuccess, () => {}
        );
        state.scanning = true;
    } catch (err) {
        container.innerHTML = '<div class="empty-state" style="padding:40px 20px"><p>Camera not available</p><p style="font-size:0.8rem;margin-top:8px">Use manual entry below</p></div>';
    }
}

let lastScanTime = 0;
async function onScanSuccess(decodedText) {
    if (Date.now() - lastScanTime < 2000) return;
    lastScanTime = Date.now();
    if (navigator.vibrate) navigator.vibrate(100);
    await processScan(decodedText.trim());
}

async function processScan(decodedText) {
    let employeeNo = decodedText && decodedText.trim();
    if (!employeeNo) return;

    // Unique QR format: "project_id|employee_no" — switch project/site when scanned
    const projectSelect = $('#setup-project');
    const siteSelect = $('#setup-site');
    if (employeeNo.includes('|')) {
        const [pid, empNo] = employeeNo.split('|').map(s => s.trim());
        if (pid && empNo) {
            employeeNo = empNo;
            const projects = await api('/projects');
            const proj = Array.isArray(projects) && projects.find(p => String(p.id) === String(pid));
            if (proj) {
                state.projectId = String(pid);
                state.projectName = proj.name || '';
                const sites = await api(`/sites?project_id=${pid}`);
                if (Array.isArray(sites) && sites.length) {
                    state.siteId = String(sites[0].id);
                    state.siteName = sites[0].name || '';
                    projectSelect.value = state.projectId;
                    await loadSitesForProject(siteSelect, state.projectId);
                    siteSelect.value = state.siteId;
                    const opt = siteSelect.querySelector(`option[value="${state.siteId}"]`);
                    if (opt) state.siteName = opt.textContent;
                    updateScannerHeader();
                    try {
                        const saved = JSON.parse(localStorage.getItem('pob_setup') || '{}');
                        saved.projectId = state.projectId;
                        saved.projectName = state.projectName;
                        saved.siteId = state.siteId;
                        saved.siteName = state.siteName;
                        localStorage.setItem('pob_setup', JSON.stringify(saved));
                    } catch (e) {}
                }
            }
        }
    }

    if (!state.projectId || !state.siteId) return;

    const resultDiv = $('#scan-result');
    resultDiv.style.display = 'block';
    resultDiv.className = 'scan-result';
    resultDiv.innerHTML = '<div class="spinner"></div>';

    try {
        const result = await api('/scan', {
            method: 'POST',
            body: JSON.stringify({
                employee_no: employeeNo, project_id: state.projectId,
                site_id: state.siteId, session: state.session
            })
        });

        if (result.success) {
            resultDiv.className = 'scan-result success';
            resultDiv.innerHTML = `<div class="result-name">${esc(result.employee.name)}</div>
                <div class="result-detail">${esc(result.employee.designation)} | ${esc(result.employee.discipline)} | ${esc(result.employee.employee_no)}</div>`;
            state.scanCount = result.site_count;
            state.totalEmployees = result.site_total;
            $('#scan-count').textContent = state.scanCount;
            $('#scan-total').textContent = `/ ${state.totalEmployees}`;
            addRecentScan(result.employee);
            playSound('success');
        } else if (result.duplicate) {
            resultDiv.className = 'scan-result duplicate';
            resultDiv.innerHTML = `<div class="result-name">${esc(result.employee.name)}</div>
                <div class="result-detail">Already scanned for ${esc(state.session)}</div>`;
            playSound('duplicate');
        } else {
            resultDiv.className = 'scan-result error';
            resultDiv.innerHTML = `<div class="result-name">${esc(result.message)}</div>`;
            playSound('error');
        }
    } catch (e) {
        resultDiv.className = 'scan-result error';
        resultDiv.innerHTML = '<div class="result-name">Scan failed - check connection</div>';
    }
    setTimeout(() => { resultDiv.style.display = 'none'; }, 4000);
}

function addRecentScan(emp) {
    const list = $('#recent-scans-list');
    const item = document.createElement('div');
    item.className = 'scan-item';
    item.innerHTML = `<div><div class="scan-item-name">${esc(emp.name)}</div>
        <div class="scan-item-sub">${esc(emp.designation)} | ${esc(emp.employee_no)}</div></div>
        <div class="scan-item-time">${timeStr()}</div>`;
    list.prepend(item);
    while (list.children.length > 30) list.lastChild.remove();
}

async function loadTodayCount() {
    try {
        const data = await api(`/headcount?project_id=${state.projectId}&site_id=${state.siteId}&session=${state.session}`);
        if (data.sites && data.sites.length > 0) {
            state.scanCount = (data.sites && data.sites[0]) ? (data.sites[0][state.session] ?? 0) : 0;
            state.totalEmployees = data.sites[0].total_employees || 0;
        } else {
            state.scanCount = 0;
            const stats = await api(`/stats?project_id=${state.projectId}`);
            state.totalEmployees = stats.total_employees || 0;
        }
        $('#scan-count').textContent = state.scanCount;
        $('#scan-total').textContent = `/ ${state.totalEmployees}`;
    } catch (e) {}
}

function playSound(type) {
    try {
        const ctx = new (window.AudioContext || window.webkitAudioContext)();
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.connect(gain); gain.connect(ctx.destination); gain.gain.value = 0.3;
        osc.frequency.value = type === 'success' ? 800 : type === 'duplicate' ? 400 : 200;
        osc.type = type === 'success' ? 'sine' : type === 'duplicate' ? 'triangle' : 'sawtooth';
        osc.start(); osc.stop(ctx.currentTime + 0.15);
    } catch (e) {}
}

// ============================================================
// DASHBOARD
// ============================================================
async function loadDashboard() {
    const d = $('#dash-date'), p = $('#dash-project'), s = $('#dash-site');
    if (!d.value) d.value = new Date().toISOString().split('T')[0];

    let url = `/headcount?date=${d.value}`;
    if (p.value) url += `&project_id=${p.value}`;
    if (s.value) url += `&site_id=${s.value}`;
    let su = '/stats';
    if (p.value) su += `?project_id=${p.value}`;

    const [hc, stats] = await Promise.all([api(url), api(su)]);
    if (!stats.total_employees && stats.total_employees !== 0) return;

    const headcountDate = d.value || hc.date || new Date().toISOString().split('T')[0];
    const dateLabel = formatHeadcountDate(headcountDate);
    const dateEl = $('#headcount-date-label');
    if (dateEl) dateEl.textContent = dateLabel ? ` — ${dateLabel}` : '';

    const amP = stats.total_employees > 0 ? Math.round(((stats.today_am || 0) / stats.total_employees) * 100) : 0;
    const pmP = stats.total_employees > 0 ? Math.round(((stats.today_pm || 0) / stats.total_employees) * 100) : 0;
    const evP = stats.total_employees > 0 ? Math.round(((stats.today_ev || 0) / stats.total_employees) * 100) : 0;
    $('#stats-cards').innerHTML = `
        <div class="stat-card"><div class="stat-value blue">${esc(String(stats.total_employees))}</div><div class="stat-label">Total Workforce</div></div>
        <div class="stat-card"><div class="stat-value green">${esc(String(stats.today_am ?? 0))} <small style="font-size:0.7em;opacity:0.7">(${amP}%)</small></div><div class="stat-label">9 AM Present</div></div>
        <div class="stat-card"><div class="stat-value purple">${esc(String(stats.today_pm ?? 0))} <small style="font-size:0.7em;opacity:0.7">(${pmP}%)</small></div><div class="stat-label">2 PM Present</div></div>
        <div class="stat-card"><div class="stat-value teal">${esc(String(stats.today_ev ?? 0))} <small style="font-size:0.7em;opacity:0.7">(${evP}%)</small></div><div class="stat-label">6 PM Present</div></div>
        <div class="stat-card"><div class="stat-value orange">${esc(String(stats.total_projects))}</div><div class="stat-label">Projects</div></div>`;

    const tw = $('#headcount-table-wrap');
    if (!hc.sites || hc.sites.length === 0) {
        tw.innerHTML = `<div class="empty-state">No attendance data for ${dateLabel || headcountDate}</div>`;
    } else {
        let h = `<div class="text-dim" style="font-size:0.85rem;margin-bottom:6px">Date: ${dateLabel || headcountDate}</div><table><thead><tr><th>Project</th><th>Site</th><th>Total</th><th>9 AM</th><th>2 PM</th><th>6 PM</th><th>9 AM %</th></tr></thead><tbody>`;
        hc.sites.forEach(r => {
            const am = r.AM ?? 0, pm = r.PM ?? 0, ev = r.EV ?? 0;
            const pct = r.total_employees > 0 ? Math.round((am / r.total_employees) * 100) : 0;
            const c = pct >= 80 ? 'var(--success)' : pct >= 50 ? 'var(--warning)' : 'var(--danger)';
            h += `<tr><td>${esc(r.project)}</td><td>${esc(r.site)}</td><td>${r.total_employees}</td><td><strong>${am}</strong></td><td><strong>${pm}</strong></td><td><strong>${ev}</strong></td>
                <td><div style="display:flex;align-items:center;gap:6px"><div class="progress-bar"><div class="progress-fill" style="width:${pct}%;background:${c}"></div></div><span style="font-size:0.8rem">${pct}%</span></div></td></tr>`;
        });
        tw.innerHTML = h + '</tbody></table>';
    }
}

function formatHeadcountDate(iso) {
    if (!iso) return '';
    const [y, m, day] = iso.split('-');
    const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    return `${day} ${months[parseInt(m,10)-1]} ${y}`;
}

async function loadPersonnel(view = 'present') {
    const d = $('#dash-date').value || new Date().toISOString().split('T')[0];
    const p = $('#dash-project').value, s = $('#dash-site').value;
    const personnelDateEl = $('#personnel-date-label');
    if (personnelDateEl) personnelDateEl.textContent = formatHeadcountDate(d) ? ` (${formatHeadcountDate(d)})` : '';
    const list = $('#personnel-list');
    list.innerHTML = '<div class="spinner"></div>';

    const sess = $('#dash-session')?.value || 'AM';
    let url = `${view === 'present' ? '/headcount/detail' : '/headcount/missing'}?date=${d}&session=${sess}`;
    if (p) url += `&project_id=${p}`;
    if (s) url += `&site_id=${s}`;

    const data = await api(url);
    if (!Array.isArray(data) || data.length === 0) {
        list.innerHTML = `<div class="empty-state">No ${view === 'present' ? 'scanned' : 'missing'} personnel</div>`;
        return;
    }
    list.innerHTML = data.slice(0, 200).map(r => {
        const by = r.supervisor_name ? (r.scanner_designation ? `by ${esc(r.supervisor_name)} (${esc(r.scanner_designation)})` : `by ${esc(r.supervisor_name)}`) : '';
        return `<div class="person-item"><div>
        <div class="person-name">${esc(r.name)}</div>
        <div class="person-detail">${esc(r.designation || '')} | ${esc(r.discipline || '')} | ${esc(r.employee_no)}${by ? ' | ' + by : ''}</div>
        </div>${r.scanned_at ? `<div class="person-detail">${new Date(r.scanned_at).toLocaleTimeString()}</div>` : ''}</div>`;
    }).join('');
}

// ============================================================
// QR CODES
// ============================================================
async function loadQRCodes() {
    const grid = $('#qr-grid');
    const pf = $('#qr-project-filter').value, search = $('#qr-search').value;
    grid.innerHTML = '<div class="spinner"></div>';

    let url = '/qrcodes/batch';
    if (pf) url += `?project_id=${pf}`;
    const data = await api(url);
    if (!Array.isArray(data)) { grid.innerHTML = '<div class="empty-state">Error loading</div>'; return; }

    let filtered = data;
    if (search) {
        const s = search.toLowerCase();
        filtered = data.filter(e => e.name.toLowerCase().includes(s) || e.employee_no.toLowerCase().includes(s));
    }
    if (filtered.length === 0) { grid.innerHTML = '<div class="empty-state">No employees found</div>'; return; }

    grid.innerHTML = filtered.map(e => `<div class="qr-card" data-emp="${esc(e.employee_no)}">
        <img src="data:image/png;base64,${e.qr_base64}" alt="QR ${esc(e.employee_no)}">
        <div class="qr-name">${esc(e.name)}</div>
        <div class="qr-id">${esc(e.employee_no)}</div>
        <div class="qr-role">${esc(e.designation || '')}${e.designation && e.discipline ? ' | ' : ''}${esc(e.discipline || '')}</div>
        ${e.project_name ? `<div class="qr-project">${esc(e.project_name)}</div>` : ''}
        <div class="qr-handout">POB Tracker — present at site</div>
        </div>`).join('');
}

// ============================================================
// ADMIN PANEL
// ============================================================
let _adminUsers = [];

async function loadAdmin() {
    const users = await api('/users');
    if (!Array.isArray(users)) return;
    _adminUsers = users;

    const ul = $('#users-list');
    const roleBadge = (role) => {
        const cls = { executive: 'badge-exec', admin: 'badge-danger', manager: 'badge-pm', project_manager: 'badge-pm', focal_point: 'badge-warning', scanner: 'badge-am', supervisor: 'badge-am', viewer: 'badge-warning' };
        return `<span class="badge ${cls[role] || 'badge-warning'}">${esc(String(role).replace('_', ' '))}</span>`;
    };
    ul.innerHTML = users.map((u, idx) => {
        const projAccess = (u.role === 'executive' || u.role === 'admin' || u.role === 'manager')
            ? '<em style="opacity:0.6">All areas</em>'
            : (u.projects && u.projects.length ? u.projects.map(p => esc(p.name)).join(', ') : '<em style="color:var(--danger)">No areas assigned</em>');
        const contact = [u.email, u.designation].filter(Boolean).map(esc).join(' · ') || '';
        return `<div class="scan-item">
        <div>
            <div class="scan-item-name">${esc(u.display_name)} ${roleBadge(u.role)}
                ${u.totp_enabled ? '<span class="badge badge-2fa">2FA</span>' : ''}</div>
            <div class="scan-item-sub">@${esc(u.username)}${contact ? ' | ' + contact : ''} | ${projAccess} | Last: ${u.last_login ? new Date(u.last_login).toLocaleDateString() : 'never'}</div>
        </div>
        <div style="display:flex;gap:4px;flex-wrap:wrap">
            <button class="btn btn-sm btn-outline" data-action="access" data-idx="${idx}">Access</button>
            <button class="btn btn-sm btn-outline" data-action="resetpin" data-id="${u.id}">Reset PIN</button>
            ${u.totp_enabled ? `<button class="btn btn-sm btn-outline" data-action="reset2fa" data-id="${u.id}">Reset 2FA</button>` : ''}
        </div>
    </div>`}).join('');

    ul.onclick = async (e) => {
        const btn = e.target.closest('[data-action]');
        if (!btn) return;
        const action = btn.dataset.action;
        const id = parseInt(btn.dataset.id);
        if (action === 'access') {
            const idx = parseInt(btn.dataset.idx);
            const u = _adminUsers[idx];
            editUserAccess(u.id, u.display_name, u.role);
        } else if (action === 'resetpin') {
            resetUserPin(id);
        } else if (action === 'reset2fa') {
            adminReset2FA(id);
        }
    };

    const my2fa = $('#my-2fa-status');
    if (state.user && state.user.totp_enabled) {
        my2fa.innerHTML = `<div class="settings-item"><div><strong>2FA is ACTIVE</strong>
            <p>Your account is protected with authenticator app</p></div>
            <button class="btn btn-sm btn-danger" onclick="disable2FA()">Disable 2FA</button></div>`;
    } else {
        my2fa.innerHTML = `<div class="settings-item"><div><strong>2FA is not enabled</strong>
            <p>Add an extra layer of security with an authenticator app</p></div>
            <button class="btn btn-sm btn-success" onclick="open2FASetup()">Enable 2FA</button></div>`;
    }

    const projects = await api('/projects');
    if (Array.isArray(projects)) {
        $('#projects-list').innerHTML = projects.map(p => `<div class="scan-item"><div>
            <div class="scan-item-name">${esc(p.name)}${p.region ? ' <span style="opacity:0.6;font-size:0.85em">(' + esc(p.region) + ')</span>' : ''}</div>
            <div class="scan-item-sub">${p.employee_count} employees | ${p.site_count} sites</div>
        </div></div>`).join('') || '<div class="empty-state">No areas</div>';
        const areaWrap = $('#new-user-areas');
        if (areaWrap) {
            areaWrap.innerHTML = projects.map(p => `<label class="area-check"><input type="checkbox" value="${p.id}"> ${esc(p.name)}</label>`).join('');
        }
    }

    const audit = await api('/audit');
    if (Array.isArray(audit)) {
        $('#audit-log').innerHTML = audit.slice(0, 100).map(a => `<div class="scan-item" style="padding:6px 10px">
            <div>
                <div class="scan-item-sub">${esc(a.user_name || 'system')} - <strong>${esc(a.action)}</strong> ${esc(a.detail || '')}</div>
            </div>
            <div class="scan-item-time">${new Date(a.created_at).toLocaleString()}</div>
        </div>`).join('') || '<div class="empty-state">No audit entries</div>';
    }
}

async function resetUserPin(userId) {
    const pin = prompt('Enter new PIN for user (4+ digits):');
    if (!pin || pin.length < 4 || !/^\d+$/.test(pin)) { toast('Invalid PIN', 'error'); return; }
    const res = await api(`/users/${userId}/reset-pin`, { method: 'POST', body: JSON.stringify({ pin }) });
    toast(res.message || 'Done', res.success ? 'success' : 'error');
    loadAdmin();
}

async function adminReset2FA(userId) {
    if (!confirm('Generate a new 2FA secret for this user? They will need to add it to their authenticator app to sign in.')) return;
    const res = await api(`/users/${userId}/reset-2fa`, { method: 'POST' });
    if (res.success && res.totp_setup) {
        showTotpGiveModal(res.totp_setup.secret, res.totp_setup.uri);
        toast(res.message, 'success');
    } else {
        toast(res.message || 'Done', res.success ? 'success' : 'error');
    }
    loadAdmin();
}

function showTotpGiveModal(secret, uri) {
    const modal = $('#totp-give-modal');
    $('#totp-give-secret').textContent = secret;
    $('#totp-give-qr').src = 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' + encodeURIComponent(uri);
    modal.classList.remove('hidden');
    $('#totp-give-close').onclick = () => modal.classList.add('hidden');
}

async function editUserAccess(userId, name, role) {
    const projects = await api('/projects');
    if (!Array.isArray(projects) || projects.length === 0) {
        toast('No areas yet', 'error');
        return;
    }
    const user = _adminUsers.find(u => u.id === userId);
    const currentIds = new Set((user?.projects || []).map(p => p.id));
    const userEmail = (user && user.email) ? esc(user.email) : '';
    const userDesignation = (user && user.designation) ? esc(user.designation) : '';

    const modal = document.createElement('div');
    modal.className = 'overlay';
    const safeName = esc(name);
    modal.innerHTML = `<div class="overlay-content" style="max-width:420px">
        <h2>Area access: ${safeName}</h2>
        <p style="color:var(--text-dim);margin-bottom:12px;font-size:0.85rem">
            ${(role === 'executive' || role === 'admin' || role === 'manager') ? 'This role sees all areas.' : 'Select areas this user can access:'}
        </p>
        <div class="form-group">
            <label>Email</label>
            <input type="email" id="edit-email" class="input" value="${userEmail}" placeholder="Scanner/Focal Point email">
        </div>
        <div class="form-group">
            <label>Designation</label>
            <input type="text" id="edit-designation" class="input" value="${userDesignation}" placeholder="e.g. Site Supervisor">
        </div>
        <div class="form-group">
            <label>Role</label>
            <select id="edit-role" class="input">
                <option value="scanner" ${role === 'scanner' ? 'selected' : ''}>Scanner</option>
                <option value="focal_point" ${role === 'focal_point' ? 'selected' : ''}>Focal Point (view only)</option>
                <option value="supervisor" ${role === 'supervisor' ? 'selected' : ''}>Supervisor</option>
                <option value="manager" ${role === 'manager' ? 'selected' : ''}>Manager (view all)</option>
                <option value="project_manager" ${role === 'project_manager' ? 'selected' : ''}>Project Manager</option>
                <option value="viewer" ${role === 'viewer' ? 'selected' : ''}>Viewer</option>
                <option value="admin" ${role === 'admin' ? 'selected' : ''}>Admin</option>
                <option value="executive" ${role === 'executive' ? 'selected' : ''}>Executive</option>
            </select>
        </div>
        <div id="project-checkboxes" style="max-height:200px;overflow-y:auto;margin-bottom:16px">
            ${projects.map(p => `<label style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border)">
                <input type="checkbox" value="${p.id}" ${currentIds.has(p.id) ? 'checked' : ''}>
                <span>${esc(p.name)} <span style="opacity:0.5">(${p.employee_count})</span></span>
            </label>`).join('')}
        </div>
        <div style="display:flex;gap:8px">
            <button class="btn btn-outline" style="flex:1" id="access-cancel">Cancel</button>
            <button id="save-access-btn" class="btn btn-primary" style="flex:1">Save</button>
        </div>
    </div>`;
    document.body.appendChild(modal);

    modal.querySelector('#access-cancel').addEventListener('click', () => modal.remove());
    modal.querySelector('#save-access-btn').addEventListener('click', async () => {
        const newRole = modal.querySelector('#edit-role').value;
        const email = modal.querySelector('#edit-email').value.trim();
        const designation = modal.querySelector('#edit-designation').value.trim();
        const checked = [...modal.querySelectorAll('#project-checkboxes input:checked')].map(cb => parseInt(cb.value));
        await api(`/users/${userId}`, {
            method: 'PUT',
            body: JSON.stringify({ role: newRole, email, designation, project_ids: checked })
        });
        modal.remove();
        toast('User access updated', 'success');
        loadAdmin();
    });
}

function initAdmin() {
    loadAdmin();

    const roleSelect = $('#new-userrole');
    const areaWrap = $('#new-user-areas');
    function toggleAreaAssign() {
        const r = roleSelect.value;
        if (areaWrap) areaWrap.style.display = (r === 'scanner' || r === 'focal_point') ? 'block' : 'none';
    }
    roleSelect.addEventListener('change', toggleAreaAssign);
    toggleAreaAssign();

    $('#btn-add-user').addEventListener('click', async () => {
        const username = $('#new-username').value.trim().toLowerCase();
        const display_name = $('#new-displayname').value.trim();
        const email = $('#new-useremail').value.trim();
        const designation = $('#new-userdesignation').value.trim();
        const pin = ($('#new-userpin') && $('#new-userpin').value) ? $('#new-userpin').value.trim() : '';
        const role = $('#new-userrole').value;
        if (!username || !display_name) { toast('Username and name required', 'error'); return; }
        if ((role === 'scanner' || role === 'focal_point') && !email) { toast('Email required for Scanner/Focal Point', 'error'); return; }
        if ((role === 'scanner' || role === 'focal_point') && !designation) { toast('Designation required for Scanner/Focal Point', 'error'); return; }
        let project_ids = [];
        if (role === 'scanner' || role === 'focal_point') {
            project_ids = Array.from(document.querySelectorAll('#new-user-areas input:checked')).map(cb => parseInt(cb.value));
            if (!project_ids.length) { toast('Select at least one area for Scanner/Focal Point', 'error'); return; }
        }
        const res = await api('/users', { method: 'POST', body: JSON.stringify({ username, display_name, email, designation, pin: pin || '1234', role, project_ids }) });
        if (res.success) {
            if (res.totp_setup) showTotpGiveModal(res.totp_setup.secret, res.totp_setup.uri);
            toast(res.message, 'success');
            $('#new-username').value = ''; $('#new-displayname').value = ''; $('#new-useremail').value = ''; $('#new-userdesignation').value = '';
            if ($('#new-userpin')) $('#new-userpin').value = '';
            if (areaWrap) areaWrap.querySelectorAll('input').forEach(cb => cb.checked = false);
            loadAdmin();
        } else {
            toast(res.message || 'Failed', 'error');
        }
    });

    $('#btn-add-project').addEventListener('click', async () => {
        const name = $('#new-project-name').value.trim();
        if (!name) return;
        const res = await api('/projects', { method: 'POST', body: JSON.stringify({ name }) });
        toast(res.success ? 'Project added' : (res.message || 'Failed'), res.success ? 'success' : 'error');
        if (res.success) { $('#new-project-name').value = ''; loadAdmin(); }
    });

    $('#btn-open-import').addEventListener('click', () => $('#import-modal').classList.remove('hidden'));
    $('#btn-reimport').addEventListener('click', async () => {
        const res = await api('/import-roster', { method: 'POST' });
        toast(res.message || 'Done', res.success ? 'success' : 'error');
        loadAdmin();
    });
}

// ============================================================
// TABS
// ============================================================
function initTabs() {
    let adminInit = false;
    $$('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            $$('.tab').forEach(t => t.classList.remove('active'));
            $$('.tab-content').forEach(c => c.classList.remove('active'));
            tab.classList.add('active');
            const target = tab.dataset.tab;
            $(`#tab-${target}`).classList.add('active');

            if (target === 'dashboard') { loadProjects($('#dash-project'), true); loadDashboard(); loadPersonnel('present'); }
            else if (target === 'qrcodes') { loadProjects($('#qr-project-filter'), true); loadQRCodes(); }
            else if (target === 'admin') { if (!adminInit) { initAdmin(); adminInit = true; } else loadAdmin(); }
            else if (target === 'scanner' && !state.scanning) startScanner();
        });
    });

    const rd = () => { loadDashboard(); loadPersonnel('present'); };
    $('#dash-date').addEventListener('change', rd);
    $('#dash-project').addEventListener('change', () => {
        const pid = $('#dash-project').value;
        if (pid) loadSitesForProject($('#dash-site'), pid);
        else $('#dash-site').innerHTML = '<option value="">All Sites</option>';
        rd();
    });
    $('#dash-site').addEventListener('change', rd);
    $('#dash-session')?.addEventListener('change', () => {
        const view = document.querySelector('.btn-toggle.active')?.dataset?.view || 'present';
        loadPersonnel(view);
    });

    $$('.btn-toggle').forEach(btn => {
        btn.addEventListener('click', () => {
            $$('.btn-toggle').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            loadPersonnel(btn.dataset.view);
        });
    });

    let qrT;
    $('#qr-search').addEventListener('input', () => { clearTimeout(qrT); qrT = setTimeout(loadQRCodes, 300); });
    $('#qr-project-filter').addEventListener('change', loadQRCodes);
    $('#btn-print-qr').addEventListener('click', () => window.print());

    $('#btn-export').addEventListener('click', async () => {
        const d = $('#dash-date').value || new Date().toISOString().split('T')[0];
        try {
            const { token: dlToken } = await api('/export/download-token', { method: 'POST' });
            let url = `/api/export/attendance?date=${d}&dl_token=${dlToken}`;
            if ($('#dash-project').value) url += `&project_id=${$('#dash-project').value}`;
            if ($('#dash-site').value) url += `&site_id=${$('#dash-site').value}`;
            window.open(url, '_blank');
        } catch (e) {
            toast('Export failed', 'error');
        }
    });
    $('#btn-export-roster')?.addEventListener('click', async () => {
        try {
            const { token: dlToken } = await api('/export/download-token', { method: 'POST' });
            let url = `/api/export/roster?dl_token=${dlToken}`;
            if ($('#dash-project').value) url += `&project_id=${$('#dash-project').value}`;
            window.open(url, '_blank');
        } catch (e) {
            toast('Export failed', 'error');
        }
    });

    $('#btn-manual-scan').addEventListener('click', () => {
        const v = $('#manual-emp-no').value.trim();
        if (v) { processScan(v); $('#manual-emp-no').value = ''; }
    });
    $('#manual-emp-no').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') { const v = $('#manual-emp-no').value.trim(); if (v) { processScan(v); $('#manual-emp-no').value = ''; } }
    });

    $('#btn-change-setup').addEventListener('click', () => {
        $('#setup-overlay').classList.remove('hidden');
        $('#main-content').style.display = 'none';
        if (state.scanner) { try { state.scanner.stop(); } catch(e) {} state.scanning = false; }
    });
}

// ============================================================
// BOOT
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    updateClock();
    setInterval(updateClock, 30000);
    initLogin();
    initImportModal();
    initSetup();
    initTabs();
    $('#dash-date').value = new Date().toISOString().split('T')[0];

    if (state.token && state.user) {
        if (state.user.must_change_pin) showChangePinScreen();
        else showApp();
    } else {
        showLogin();
    }
});

if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
