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

    let res;
    try {
        res = await fetch(`/api${path}`, { ...opts, headers });
    } catch (e) {
        return { success: false, message: 'Network error contacting server' };
    }

    let body;
    try {
        body = await res.json();
    } catch (e) {
        const text = await res.text().catch(() => '');
        return { success: false, message: `Server returned non-JSON (${res.status})`, detail: text.slice(0, 2000) };
    }

    if (res.status === 401 && body && body.auth_required) {
        doLogout(true);
        return body;
    }
    return body;
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

const SESSION_LABELS = { AM: '9 AM', EV: '7 PM' };
function sessionByHour() {
    const h = new Date().getHours();
    if (h < 16) return 'AM';
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
    $('header.topbar').style.display = 'none';
    $('#main-content').style.display = 'none';
    $('#setup-overlay').classList.add('hidden');
    try { $('#totp-setup-modal').classList.add('hidden'); } catch {}
}

function showLogin() {
    hideAllScreens();
    $('#login-screen').style.display = 'flex';
}

const isAdminRole = (role) => ['executive', 'admin', 'manager', 'focal_point'].includes(role);

function showApp() {
    hideAllScreens();
    $('header.topbar').style.display = 'flex';
    $('#user-badge').textContent = state.user.display_name;
    const role = state.user.role;
    const admin = isAdminRole(role);
    $('#admin-tab').style.display = (role === 'admin' || role === 'executive') ? '' : 'none';
    $('#trends-tab').style.display = admin ? '' : 'none';
    $('#health-tab').style.display = admin ? '' : 'none';
    $('#twl-tab').style.display = admin ? '' : 'none';
    $('#oi-tab').style.display = admin ? '' : 'none';
    $('#risk-tab').style.display = admin ? '' : 'none';
    $('#workforce-tab').style.display = admin ? '' : 'none';
    const scannerTab = document.querySelector('.tab[data-tab="scanner"]');
    const dashTab = document.querySelector('.tab[data-tab="dashboard"]');

    if (role === 'scanner') {
        if (scannerTab) scannerTab.style.display = '';
        if (dashTab) dashTab.style.display = 'none';
        $('#setup-overlay').classList.remove('hidden');
    } else {
        if (scannerTab) scannerTab.style.display = 'none';
        if (dashTab) dashTab.style.display = '';
        $('#main-content').style.display = 'block';
        if (dashTab) dashTab.click();
    }
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
    const errorDiv = $('#login-error');
    const backMainBtn = $('#login-back-main');
    let loginMode = 'scanner';

    const scannerFields = $('#login-scanner-fields');
    const adminFields = $('#login-admin-fields');
    const modeScanner = $('#login-mode-scanner');
    const modeAdmin = $('#login-mode-admin');

    function setError(message) {
        errorDiv.textContent = message || '';
        if (backMainBtn) backMainBtn.style.display = message ? '' : 'none';
    }

    function resetToMain() {
        setError('');
        ['#login-username', '#login-pin', '#login-admin-username', '#login-totp'].forEach(sel => {
            const el = $(sel);
            if (el) el.value = '';
        });
        const dv = $('#login-division'); if (dv) dv.value = '';
        const ar = $('#login-area');
        if (ar) { ar.innerHTML = '<option value="">Select division first</option>'; ar.disabled = true; }
        const pr = $('#login-project');
        if (pr) { pr.innerHTML = '<option value="">Select area first</option>'; pr.disabled = true; }
        setMode('scanner');
        const u = $('#login-username');
        if (u) u.focus();
    }

    function setMode(mode) {
        loginMode = mode;
        setError('');
        if (mode === 'scanner') {
            scannerFields.style.display = '';
            adminFields.style.display = 'none';
            modeScanner.classList.add('active');
            modeAdmin.classList.remove('active');
        } else {
            scannerFields.style.display = 'none';
            adminFields.style.display = '';
            modeScanner.classList.remove('active');
            modeAdmin.classList.add('active');
        }
    }
    modeScanner.addEventListener('click', () => setMode('scanner'));
    modeAdmin.addEventListener('click', () => setMode('admin'));
    if (backMainBtn) backMainBtn.addEventListener('click', resetToMain);

    const divisionSelect = $('#login-division');
    const areaSelect = $('#login-area');
    const projectSelect = $('#login-project');
    let _locations = null;

    async function loadLoginLocations() {
        if (_locations || !divisionSelect) return;
        try {
            const res = await fetch('/api/public/locations');
            const data = await res.json();
            if (!data || !data.success) return;
            _locations = data;
            divisionSelect.innerHTML = '<option value="">-- Select Division --</option>' +
                data.divisions.map(d => `<option value="${d.id}">${esc(d.name)}</option>`).join('');
        } catch (_) { /* offline / will retry on submit */ }
    }
    loadLoginLocations();

    function repopulateAreas(divisionId) {
        if (!areaSelect) return;
        if (!divisionId || !_locations) {
            areaSelect.innerHTML = '<option value="">Select division first</option>';
            areaSelect.disabled = true;
            return;
        }
        const filtered = _locations.areas.filter(a => String(a.division_id) === String(divisionId));
        areaSelect.innerHTML = '<option value="">-- Select Area --</option>' +
            filtered.map(a => `<option value="${a.id}">${esc(a.name)}</option>`).join('');
        areaSelect.disabled = false;
    }
    function repopulateProjects(areaId) {
        if (!projectSelect) return;
        if (!areaId || !_locations) {
            projectSelect.innerHTML = '<option value="">Select area first</option>';
            projectSelect.disabled = true;
            return;
        }
        const filtered = _locations.projects.filter(p => String(p.area_id) === String(areaId));
        projectSelect.innerHTML = '<option value="">-- Select Project --</option>' +
            filtered.map(p => `<option value="${p.id}" data-name="${esc(p.name)}">${esc(p.name)}</option>`).join('');
        projectSelect.disabled = false;
    }

    divisionSelect?.addEventListener('change', () => {
        repopulateAreas(divisionSelect.value);
        repopulateProjects('');
    });
    areaSelect?.addEventListener('change', () => repopulateProjects(areaSelect.value));

    async function doLogin() {
        setError('');
        let body;
        let scannerSetup = null;
        if (loginMode === 'scanner') {
            const username = $('#login-username').value.trim();
            const pin = $('#login-pin').value.trim();
            if (!username || !pin) { setError('Enter username and PIN'); return; }
            const divisionId = divisionSelect ? divisionSelect.value : '';
            const areaId = areaSelect ? areaSelect.value : '';
            const projectId = projectSelect ? projectSelect.value : '';
            const projectName = projectSelect && projectSelect.selectedIndex >= 0
                ? (projectSelect.options[projectSelect.selectedIndex]?.dataset?.name || '')
                : '';
            if (!divisionId) { setError('Select a Division'); return; }
            if (!areaId) { setError('Select an Area'); return; }
            if (!projectId) { setError('Select a Project'); return; }
            scannerSetup = { divisionId, areaId, projectId, projectName };
            body = { username, pin, login_mode: 'scanner' };
        } else {
            const username = $('#login-admin-username').value.trim();
            const totp_code = $('#login-totp').value.trim();
            if (!username || !totp_code) { setError('Enter username and 2FA code'); return; }
            if (totp_code.length !== 6 || !/^\d+$/.test(totp_code)) { setError('Enter the 6-digit code from your authenticator app'); return; }
            body = { username, totp_code, login_mode: 'admin' };
        }

        loginBtn.disabled = true;
        loginBtn.textContent = 'Signing in...';

        try {
            const res = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            const data = await res.json();

            if (data.success) {
                state.token = data.token;
                state.user = data.user;
                localStorage.setItem('pob_token', data.token);
                localStorage.setItem('pob_user', JSON.stringify(data.user));
                if (scannerSetup) {
                    state.divisionId = scannerSetup.divisionId;
                    state.areaId = scannerSetup.areaId;
                    state.projectId = scannerSetup.projectId;
                    state.projectName = scannerSetup.projectName;
                    localStorage.setItem('pob_setup', JSON.stringify({
                        projectId: scannerSetup.projectId,
                        projectName: scannerSetup.projectName,
                        divisionId: scannerSetup.divisionId,
                        areaId: scannerSetup.areaId,
                        siteId: null, siteName: '',
                        session: sessionByHour()
                    }));
                }
                $('#login-pin').value = '';
                $('#login-totp').value = '';
                showApp();
                toast(`Welcome, ${data.user.display_name}`, 'success');
            } else {
                setError(data.message || 'Sign-in failed');
            }
        } catch (e) {
            setError('Connection error. Is the server running?');
        }
        loginBtn.disabled = false;
        loginBtn.textContent = 'Sign in';
    }

    loginBtn.addEventListener('click', doLogin);
    $('#login-pin')?.addEventListener('keypress', (e) => { if (e.key === 'Enter') doLogin(); });
    $('#login-totp')?.addEventListener('keypress', (e) => { if (e.key === 'Enter') doLogin(); });
    $('#login-username')?.addEventListener('keypress', (e) => { if (e.key === 'Enter') $('#login-pin')?.focus(); });
    $('#login-admin-username')?.addEventListener('keypress', (e) => { if (e.key === 'Enter') $('#login-totp')?.focus(); });

    $('#btn-logout').addEventListener('click', () => {
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
// SETUP OVERLAY (Division -> Area -> Project -> Site)
// ============================================================
async function loadDivisions(selectEl) {
    const list = await api('/divisions');
    if (!Array.isArray(list)) {
        selectEl.innerHTML = `<option value="">${esc(list?.message || 'Failed to load divisions')}</option>`;
        return [];
    }
    selectEl.innerHTML = '<option value="">-- Select Division --</option>';
    list.forEach(d => {
        const opt = document.createElement('option');
        opt.value = d.id;
        opt.textContent = d.name;
        selectEl.appendChild(opt);
    });
    return list;
}

async function loadAreas(selectEl, divisionId) {
    if (!divisionId) {
        selectEl.innerHTML = '<option value="">Select division first</option>';
        selectEl.disabled = true;
        return [];
    }
    const list = await api(`/areas?division_id=${divisionId}`);
    if (!Array.isArray(list)) {
        selectEl.innerHTML = '<option value="">Failed to load areas</option>';
        return [];
    }
    selectEl.innerHTML = '<option value="">-- Select Area --</option>';
    list.forEach(a => {
        const opt = document.createElement('option');
        opt.value = a.id;
        opt.textContent = a.name;
        selectEl.appendChild(opt);
    });
    selectEl.disabled = false;
    return list;
}

async function loadProjects(selectEl, includeAll = false, areaId = null, divisionId = null) {
    selectEl.innerHTML = '<option value="">Loading...</option>';
    let url = '/projects';
    if (areaId) url += `?area_id=${areaId}`;
    else if (divisionId) url += `?division_id=${divisionId}`;
    const projects = await api(url);
    if (!Array.isArray(projects)) {
        const msg = projects?.message || projects?.error || 'Failed to load projects';
        selectEl.innerHTML = `<option value="">${esc(msg)}</option>`;
        toast(msg, 'error');
        return [];
    }
    selectEl.innerHTML = includeAll
        ? '<option value="">All Projects</option>'
        : '<option value="">-- Select Project --</option>';
    projects.forEach(p => {
        const opt = document.createElement('option');
        opt.value = p.id;
        let label = p.name;
        if (p.contractor_company) label += ` — ${p.contractor_company}`;
        if (p.employee_count) label += ` (${p.employee_count})`;
        opt.textContent = label;
        opt.dataset.name = p.name;
        opt.dataset.contractor = p.contractor_company || '';
        selectEl.appendChild(opt);
    });
    selectEl.disabled = false;
    return projects;
}

async function resolveProjectSite(projectId) {
    if (!projectId) return null;
    const sites = await api(`/sites?project_id=${projectId}`);
    if (!Array.isArray(sites) || !sites.length) return null;
    return { id: String(sites[0].id), name: sites[0].name || '' };
}

function initSetup() {
    const legacySite = document.getElementById('setup-site');
    if (legacySite) {
        const legacyGroup = legacySite.closest('.form-group');
        if (legacyGroup) legacyGroup.remove(); else legacySite.remove();
    }
    const setupOverlayDesc = document.querySelector('#setup-overlay .overlay-content > p');
    if (setupOverlayDesc && /site/i.test(setupOverlayDesc.textContent)) {
        setupOverlayDesc.textContent = 'Select division, then area, then project and session (all required)';
    }

    const divisionSelect = $('#setup-division');
    const areaSelect = $('#setup-area');
    const projectSelect = $('#setup-project');

    if (!document.getElementById('setup-back')) {
        const confirmBtn = document.getElementById('setup-confirm');
        if (confirmBtn && confirmBtn.parentNode) {
            const backBtn = document.createElement('button');
            backBtn.id = 'setup-back';
            backBtn.className = 'btn btn-outline';
            backBtn.style.marginTop = '8px';
            backBtn.style.width = '100%';
            backBtn.textContent = 'Back to Main Page';
            confirmBtn.parentNode.insertBefore(backBtn, confirmBtn.nextSibling);
        }
    }
    // Keep label in sync if older HTML cached
    const existingBack = document.getElementById('setup-back');
    if (existingBack && existingBack.textContent.trim() !== 'Back to Main Page') {
        existingBack.textContent = 'Back to Main Page';
    }

    function updateSetupConfirmState() {
        const btn = $('#setup-confirm');
        if (!btn) return;
        const ok = divisionSelect.value && areaSelect.value && projectSelect.value;
        btn.disabled = !ok;
    }
    (async () => {
        await loadDivisions(divisionSelect);
        updateSetupConfirmState();
        if (state.user && state.user.role === 'scanner' && state.user.allowed_projects && state.user.allowed_projects.length === 1) {
            const projects = await api('/projects');
            if (Array.isArray(projects) && projects.length === 1) {
                const p = projects[0];
                if (p.division_id && p.area_id) {
                    await loadAreas(areaSelect, p.division_id);
                    divisionSelect.value = p.division_id;
                    areaSelect.value = p.area_id;
                    await loadProjects(projectSelect, false, p.area_id, null);
                } else {
                    await loadProjects(projectSelect);
                }
                projectSelect.value = p.id;
                const site = await resolveProjectSite(p.id);
                if (site) { state.siteId = site.id; state.siteName = site.name; }
                updateSetupConfirmState();
            }
        }
    })();
    divisionSelect.addEventListener('change', async () => {
        const divId = divisionSelect.value;
        await loadAreas(areaSelect, divId);
        areaSelect.value = '';
        projectSelect.innerHTML = '<option value="">Select area first</option>';
        projectSelect.disabled = true;
        state.siteId = null;
        state.siteName = '';
    });
    areaSelect.addEventListener('change', async () => {
        const areaId = areaSelect.value;
        await loadProjects(projectSelect, false, areaId || null, null);
        if (!areaId) projectSelect.disabled = true;
        state.siteId = null;
        state.siteName = '';
    });
    projectSelect.addEventListener('change', async () => {
        const site = await resolveProjectSite(projectSelect.value);
        state.siteId = site ? site.id : null;
        state.siteName = site ? site.name : '';
        updateSetupConfirmState();
    });
    divisionSelect.addEventListener('change', () => setTimeout(updateSetupConfirmState, 0));
    areaSelect.addEventListener('change', () => setTimeout(updateSetupConfirmState, 0));

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

    $('#setup-back')?.addEventListener('click', () => {
        if (state.scanner) { try { state.scanner.stop(); } catch (e) {} state.scanning = false; }
        doLogout();
    });

    $('#setup-confirm').addEventListener('click', async () => {
        if (!divisionSelect.value) return toast('Select a division', 'error');
        if (!areaSelect.value) return toast('Select an area', 'error');
        if (!projectSelect.value) return toast('Select a project', 'error');

        state.projectId = projectSelect.value;
        state.projectName = projectSelect.options[projectSelect.selectedIndex].dataset.name;

        // Site is hidden from scanner UI; resolve quietly. If none exists, the server will
        // auto-provision a default site at scan-time, so don't block sign-in.
        if (!state.siteId) {
            try {
                const site = await resolveProjectSite(state.projectId);
                if (site) { state.siteId = site.id; state.siteName = site.name; }
            } catch (_) { /* ignore — server handles fallback */ }
        }

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
            state.session = (s.session && ['AM','EV'].includes(s.session)) ? s.session : auto;
            $$('.btn-session').forEach(btn => btn.classList.toggle('active', btn.dataset.session === state.session));
            (async () => {
                const projects = await api('/projects');
                if (Array.isArray(projects)) {
                    const proj = projects.find(p => String(p.id) === String(s.projectId));
                    if (proj && proj.division_id && proj.area_id) {
                        await loadAreas(areaSelect, proj.division_id);
                        divisionSelect.value = proj.division_id;
                        areaSelect.value = proj.area_id;
                        await loadProjects(projectSelect, false, proj.area_id, null);
                    } else {
                        await loadProjects(projectSelect);
                    }
                    projectSelect.value = s.projectId;
                    if (!state.siteId) {
                        const site = await resolveProjectSite(s.projectId);
                        if (site) { state.siteId = site.id; state.siteName = site.name; }
                    }
                }
                updateSetupConfirmState();
            })();
        } catch { /* corrupted data */ }
    }
}

function updateScannerHeader() {
    $('#current-project-name').textContent = state.projectName;
    // Site is hidden from the scanner UI now (auto-resolved on the server). Only show the label
    // if there are actually multiple distinct sites worth disambiguating per project.
    const siteEl = $('#current-site-name');
    if (siteEl) {
        const isDefault = !state.siteName || /^main$/i.test(state.siteName);
        siteEl.textContent = isDefault ? '' : state.siteName;
        siteEl.style.display = isDefault ? 'none' : '';
    }
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

    document.getElementById('btn-open-import-excel')?.addEventListener('click', async () => {
        $('#import-modal').classList.remove('hidden');
        await loadImportExcelDivisionArea();
        $('#import-excel-file').focus?.();
    });

    const importDivisionSelect = $('#import-excel-division');
    const importAreaSelect = $('#import-excel-area');
    if (importDivisionSelect) {
        importDivisionSelect.addEventListener('change', async () => {
            const divId = importDivisionSelect.value;
            importAreaSelect.disabled = true;
            importAreaSelect.innerHTML = '<option value="">Loading...</option>';
            if (!divId) {
                importAreaSelect.innerHTML = '<option value="">Select division first</option>';
                return;
            }
            const areas = await api(`/areas?division_id=${divId}`);
            importAreaSelect.innerHTML = '<option value="">-- Select Area --</option>' +
                (Array.isArray(areas) ? areas.map(a => `<option value="${a.id}">${esc(a.name)}</option>`).join('') : '');
            importAreaSelect.disabled = false;
        });
    }

    async function loadImportExcelDivisionArea() {
        const divs = await api('/divisions');
        const list = Array.isArray(divs) ? divs : [];
        if (importDivisionSelect) {
            importDivisionSelect.innerHTML = '<option value="">-- Select Division --</option>' +
                list.map(d => `<option value="${d.id}">${esc(d.name)}</option>`).join('');
        }
        importAreaSelect.innerHTML = '<option value="">Select division first</option>';
        importAreaSelect.disabled = true;
    }

    $('#import-excel-btn')?.addEventListener('click', async () => {
        const file = $('#import-excel-file')?.files?.[0];
        if (!file) return toast('Select an Excel (.xlsx) file', 'error');
        const areaId = importAreaSelect?.value;
        if (!areaId) return toast('Select a division and area for the import', 'error');
        const status = $('#import-status');
        status.textContent = 'Importing Excel...';
        const form = new FormData();
        form.append('file', file);
        form.append('area_id', areaId);
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
    if (employeeNo.includes('|')) {
        const [pid, empNo] = employeeNo.split('|').map(s => s.trim());
        if (pid && empNo) {
            employeeNo = empNo;
            const projects = await api('/projects');
            const proj = Array.isArray(projects) && projects.find(p => String(p.id) === String(pid));
            if (proj) {
                state.projectId = String(pid);
                state.projectName = proj.name || '';
                const site = await resolveProjectSite(pid);
                if (site) {
                    state.siteId = site.id;
                    state.siteName = site.name;
                    if (projectSelect) projectSelect.value = state.projectId;
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

    if (!state.projectId) return;

    const resultDiv = $('#scan-result');
    resultDiv.style.display = 'block';
    resultDiv.className = 'scan-result';
    resultDiv.innerHTML = '<div class="spinner"></div>';

    try {
        const result = await api('/scan', {
            method: 'POST',
            body: JSON.stringify({
                employee_no: employeeNo, project_id: state.projectId,
                site_id: state.siteId || null, session: state.session
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
        const siteParam = state.siteId ? `&site_id=${state.siteId}` : '';
        const data = await api(`/headcount?project_id=${state.projectId}${siteParam}&session=${state.session}`);
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
let _dashWorkers = [];
let _sliderDates = [];
let _sliderSession = 'AM';

function buildSliderDates(mode) {
    const dates = [];
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    if (mode === 'month') {
        // 24 months back; each entry = last day of that month, capped at today
        for (let i = 23; i >= 0; i--) {
            const monthAnchor = new Date(today.getFullYear(), today.getMonth() - i, 1);
            const lastDayOfMonth = new Date(monthAnchor.getFullYear(), monthAnchor.getMonth() + 1, 0);
            const use = lastDayOfMonth > today ? today : lastDayOfMonth;
            dates.push(use.toISOString().split('T')[0]);
        }
    } else if (mode === 'week') {
        for (let i = 12; i >= 0; i--) {
            const d = new Date(today);
            d.setDate(d.getDate() - i * 7);
            dates.push(d.toISOString().split('T')[0]);
        }
    } else {
        for (let i = 59; i >= 0; i--) {
            const d = new Date(today);
            d.setDate(d.getDate() - i);
            dates.push(d.toISOString().split('T')[0]);
        }
    }
    return dates;
}

function getSliderDate() {
    const slider = $('#dash-slider-range');
    if (!slider || !_sliderDates.length) return new Date().toISOString().split('T')[0];
    return _sliderDates[parseInt(slider.value)] || _sliderDates[_sliderDates.length - 1];
}

function formatSliderLabel(dateStr, mode) {
    const d = new Date(dateStr + 'T00:00:00');
    const opts = { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric' };
    if (mode === 'month') {
        return d.toLocaleDateString('en-GB', { month: 'long', year: 'numeric' });
    }
    if (mode === 'week') {
        const end = new Date(d);
        end.setDate(end.getDate() + 6);
        return `Week of ${d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })} – ${end.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })}`;
    }
    return d.toLocaleDateString('en-GB', opts);
}

const _tabSliders = {};

function initTabSlider(containerEl, refreshFn) {
    if (!containerEl) return null;
    const slider = containerEl.querySelector('.tab-slider-range');
    const label = containerEl.querySelector('.tab-slider-label');
    const modeSelect = containerEl.querySelector('.tab-slider-mode');
    const prevBtn = containerEl.querySelector('.tab-slider-prev');
    const nextBtn = containerEl.querySelector('.tab-slider-next');
    const todayBtn = containerEl.querySelector('.tab-slider-today');
    const sessionBtns = containerEl.querySelectorAll('.tab-session-btn');
    if (!slider) return null;

    const state = { dates: [], session: 'AM' };

    function rebuild() {
        const mode = modeSelect?.value || 'day';
        state.dates = buildSliderDates(mode);
        slider.max = state.dates.length - 1;
        slider.value = state.dates.length - 1;
        updateLabel();
    }

    function updateLabel() {
        const mode = modeSelect?.value || 'day';
        const ds = getDate();
        if (label) label.textContent = formatSliderLabel(ds, mode);
    }

    function getDate() {
        if (!state.dates.length) return new Date().toISOString().split('T')[0];
        return state.dates[parseInt(slider.value)] || state.dates[state.dates.length - 1];
    }

    slider.addEventListener('input', () => { updateLabel(); refreshFn(); });
    prevBtn?.addEventListener('click', () => { slider.value = Math.max(0, parseInt(slider.value) - 1); updateLabel(); refreshFn(); });
    nextBtn?.addEventListener('click', () => { slider.value = Math.min(parseInt(slider.max), parseInt(slider.value) + 1); updateLabel(); refreshFn(); });
    todayBtn?.addEventListener('click', () => { slider.value = state.dates.length - 1; updateLabel(); refreshFn(); });
    modeSelect?.addEventListener('change', () => { rebuild(); refreshFn(); });
    sessionBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            sessionBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            state.session = btn.dataset.session;
            refreshFn();
        });
    });

    rebuild();
    return { getDate, getSession: () => state.session };
}

function initDateSlider() {
    const slider = $('#dash-slider-range');
    const label = $('#dash-slider-date-label');
    const modeSelect = $('#dash-slider-mode');
    const prevBtn = $('#dash-slider-prev');
    const nextBtn = $('#dash-slider-next');
    const todayBtn = $('#dash-slider-today');
    if (!slider) return;

    function rebuildSlider() {
        const mode = modeSelect?.value || 'day';
        _sliderDates = buildSliderDates(mode);
        slider.max = _sliderDates.length - 1;
        slider.value = _sliderDates.length - 1;
        updateSliderLabel();
    }

    function updateSliderLabel() {
        const mode = modeSelect?.value || 'day';
        const dateStr = getSliderDate();
        if (label) label.textContent = formatSliderLabel(dateStr, mode);
    }

    slider.addEventListener('input', () => {
        updateSliderLabel();
        refreshDashboard();
    });

    if (prevBtn) prevBtn.addEventListener('click', () => {
        slider.value = Math.max(0, parseInt(slider.value) - 1);
        updateSliderLabel();
        refreshDashboard();
    });

    if (nextBtn) nextBtn.addEventListener('click', () => {
        slider.value = Math.min(parseInt(slider.max), parseInt(slider.value) + 1);
        updateSliderLabel();
        refreshDashboard();
    });

    if (todayBtn) todayBtn.addEventListener('click', () => {
        slider.value = _sliderDates.length - 1;
        updateSliderLabel();
        refreshDashboard();
    });

    if (modeSelect) modeSelect.addEventListener('change', () => {
        rebuildSlider();
        refreshDashboard();
    });

    document.querySelectorAll('#tab-dashboard .dash-session-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('#tab-dashboard .dash-session-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            _sliderSession = btn.dataset.session;
            refreshDashboard();
        });
    });

    rebuildSlider();
}

// ===========================================================
// Dashboard Filter Shell — drag-drop palette + active chips + popover
// ===========================================================

const FILTER_CATEGORIES = [
    { key: 'division',          label: 'Division',          source: 'divisions',     valueField: 'id',  labelField: 'name' },
    { key: 'area',              label: 'Area',              source: 'areas',         valueField: 'id',  labelField: 'name' },
    { key: 'project',           label: 'Project',           source: 'projects',      valueField: 'id',  labelField: 'name' },
    { key: 'subcontractor',     label: 'Contractor',        source: 'contractors',   simple: true },
    { key: 'camp',              label: 'Camp',              source: 'camps',         simple: true },
    { key: 'fieldglass_status', label: 'Fieldglass Status', source: 'fieldglass',    simple: true },
    { key: 'discipline',        label: 'Discipline',        source: 'disciplines',   simple: true },
    { key: 'nationality',       label: 'Nationality',       source: 'nationalities', simple: true },
    { key: 'age',               label: 'Age Range',         range: true },
    { key: 'chronic',           label: 'Chronic Condition', source: 'chronic',       simple: true, hasAny: true },
];

// Multi-value filter state. age is special: { from, to }.
let _filterState = {};
let _filterOptions = null; // cached payload from /api/filter-options
let _filterDebounce = null;
let _activePopoverCat = null;

function _emptyFilterValue(cat) {
    return cat.range ? null : [];
}

function _filterChipIcon(catKey) {
    const map = {
        division: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M8 7V5a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>',
        area: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="3 6 9 3 15 6 21 3 21 18 15 21 9 18 3 21 3 6"/><line x1="9" y1="3" x2="9" y2="18"/><line x1="15" y1="6" x2="15" y2="21"/></svg>',
        project: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 7h6l2 3h10v10H3z"/></svg>',
        subcontractor: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="9" cy="7" r="4"/><path d="M3 21v-2a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v2"/><circle cx="17" cy="7" r="3"/></svg>',
        twl_zone: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 14V4a2 2 0 1 0-4 0v10a4 4 0 1 0 4 0z"/></svg>',
        camp: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 21h18L12 4 3 21z"/></svg>',
        fieldglass_status: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="9 12 11 14 15 10"/></svg>',
        discipline: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.7-3.7a6 6 0 0 1-7.9 7.9l-6.9 6.9a2.1 2.1 0 0 1-3-3l6.9-6.9a6 6 0 0 1 7.9-7.9l-3.7 3.7z"/></svg>',
        nationality: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20"/></svg>',
        age: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
        chronic: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 1 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>',
    };
    return map[catKey] || '';
}

function _renderPalette() {
    const palette = $('#filter-palette-chips');
    if (!palette) return;
    palette.innerHTML = FILTER_CATEGORIES.map(cat => {
        const isActive = _filterState[cat.key] !== undefined;
        return `<button class="fchip ${isActive ? 'disabled' : ''}" draggable="${isActive ? 'false' : 'true'}" data-cat="${cat.key}" type="button" title="${esc(cat.label)}">
            <span class="fchip-icon">${_filterChipIcon(cat.key)}</span>
            <span>${esc(cat.label)}</span>
        </button>`;
    }).join('');
    palette.querySelectorAll('.fchip').forEach(chip => {
        chip.addEventListener('dragstart', e => {
            chip.classList.add('dragging');
            e.dataTransfer.setData('text/plain', chip.dataset.cat);
            e.dataTransfer.effectAllowed = 'copy';
        });
        chip.addEventListener('dragend', () => chip.classList.remove('dragging'));
        chip.addEventListener('click', () => _addFilterCategory(chip.dataset.cat, chip));
    });
}

function _renderActiveChips() {
    const zone = $('#filter-active-chips');
    const dropzone = $('#filter-dropzone');
    const badge = $('#filter-count-badge');
    if (!zone || !dropzone) return;

    const activeKeys = Object.keys(_filterState);
    if (activeKeys.length === 0) {
        zone.innerHTML = '';
        dropzone.classList.remove('has-chips');
        if (badge) badge.style.display = 'none';
        _renderPalette();
        return;
    }

    dropzone.classList.add('has-chips');
    if (badge) { badge.style.display = ''; badge.textContent = String(activeKeys.length); }

    zone.innerHTML = activeKeys.map(key => {
        const cat = FILTER_CATEGORIES.find(c => c.key === key);
        if (!cat) return '';
        const valStr = _formatActiveValue(cat, _filterState[key]);
        const placeholder = !valStr;
        return `<div class="fchip-active" data-cat="${cat.key}" draggable="true">
            <span class="fchip-active-cat">${esc(cat.label)}</span>
            <span class="fchip-active-sep">›</span>
            <span class="fchip-active-vals ${placeholder ? 'placeholder' : ''}">${esc(valStr || 'select…')}</span>
            <button class="fchip-active-edit" type="button" title="Edit values" data-action="edit">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/></svg>
            </button>
            <button class="fchip-active-remove" type="button" title="Remove" data-action="remove">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
        </div>`;
    }).join('');

    zone.querySelectorAll('.fchip-active').forEach(chip => {
        const cat = chip.dataset.cat;
        chip.querySelector('[data-action="remove"]').addEventListener('click', e => {
            e.stopPropagation();
            _removeFilterCategory(cat);
        });
        chip.querySelector('[data-action="edit"]').addEventListener('click', e => {
            e.stopPropagation();
            _openPopover(cat, chip);
        });
        chip.querySelector('.fchip-active-vals').addEventListener('click', () => _openPopover(cat, chip));
        chip.addEventListener('dragstart', e => {
            chip.classList.add('dragging');
            e.dataTransfer.setData('text/plain', `__active:${cat}`);
            e.dataTransfer.effectAllowed = 'move';
        });
        chip.addEventListener('dragend', () => chip.classList.remove('dragging'));
    });

    _renderPalette();
}

function _formatActiveValue(cat, val) {
    if (cat.range) {
        if (!val) return '';
        const f = (val.from !== '' && val.from != null) ? val.from : '';
        const t = (val.to   !== '' && val.to   != null) ? val.to   : '';
        if (!f && !t) return '';
        if (f && t) return `${f} – ${t}`;
        if (f) return `≥ ${f}`;
        return `≤ ${t}`;
    }
    if (!Array.isArray(val) || val.length === 0) return '';
    const labels = val.map(v => v.label);
    if (labels.length <= 2) return labels.join(', ');
    return `${labels[0]}, ${labels[1]} +${labels.length - 2}`;
}

function _addFilterCategory(catKey, anchorEl) {
    if (_filterState[catKey] !== undefined) return;
    const cat = FILTER_CATEGORIES.find(c => c.key === catKey);
    if (!cat) return;
    _filterState[catKey] = _emptyFilterValue(cat);
    _renderActiveChips();
    requestAnimationFrame(() => {
        const newChip = document.querySelector(`.fchip-active[data-cat="${catKey}"]`);
        if (newChip) _openPopover(catKey, newChip);
    });
}

function _removeFilterCategory(catKey) {
    delete _filterState[catKey];
    _closePopover();
    _renderActiveChips();
    _scheduleDashboardRefresh();
}

function _scheduleDashboardRefresh() {
    if (_filterDebounce) clearTimeout(_filterDebounce);
    _filterDebounce = setTimeout(() => {
        if (typeof refreshDashboard === 'function') refreshDashboard();
    }, 220);
}

// ----- Popover -----

function _openPopover(catKey, anchorEl) {
    const cat = FILTER_CATEGORIES.find(c => c.key === catKey);
    if (!cat) return;
    const popover = $('#filter-popover');
    const title = $('#filter-popover-title');
    const body = $('#filter-popover-body');
    const search = $('#filter-popover-search');
    if (!popover || !body) return;

    _activePopoverCat = catKey;
    title.textContent = cat.label;

    popover.classList.remove('hidden');
    const dropzone = $('#filter-dropzone');
    if (dropzone) dropzone.classList.add('picker-open');
    requestAnimationFrame(() => {
        if (popover.scrollIntoView) popover.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    });

    if (cat.range) {
        search.classList.add('hidden');
        const cur = _filterState[catKey] || {};
        const minDef = (_filterOptions && _filterOptions.age_min) || 18;
        const maxDef = (_filterOptions && _filterOptions.age_max) || 70;
        body.innerHTML = `<div class="filter-age-range">
            <div class="filter-age-row">
                <label for="age-from-input">From</label>
                <input id="age-from-input" type="number" class="input" min="0" max="120" placeholder="${minDef}" value="${cur.from ?? ''}">
            </div>
            <div class="filter-age-row">
                <label for="age-to-input">To</label>
                <input id="age-to-input" type="number" class="input" min="0" max="120" placeholder="${maxDef}" value="${cur.to ?? ''}">
            </div>
            <div class="filter-age-summary">Workforce range: ${minDef} – ${maxDef}</div>
        </div>`;
    } else {
        search.classList.remove('hidden');
        search.value = '';
        _renderPopoverOptions(cat, '');
        search.oninput = () => _renderPopoverOptions(cat, search.value);
    }
}

function _renderPopoverOptions(cat, q) {
    const body = $('#filter-popover-body');
    const opts = _getOptionsFor(cat) || [];
    const cur = _filterState[cat.key] || [];
    const curIds = new Set(cur.map(v => String(v.id)));
    const ql = (q || '').trim().toLowerCase();
    const filtered = ql ? opts.filter(o => String(o.label).toLowerCase().includes(ql)) : opts;

    let html = '';
    if (cat.hasAny) {
        const isAny = cur.some(v => String(v.id) === 'any');
        html += `<label class="filter-popover-opt"><input type="checkbox" data-id="any" ${isAny ? 'checked' : ''}> <span><strong>Any condition</strong> (excludes "none")</span></label>`;
    }
    if (!filtered.length) {
        html += `<div class="filter-popover-opt empty">No options found.</div>`;
    } else {
        html += filtered.map(o => {
            const checked = curIds.has(String(o.id)) ? 'checked' : '';
            const sub = o.sub ? ` <small style="color:var(--text-mute)">${esc(o.sub)}</small>` : '';
            return `<label class="filter-popover-opt"><input type="checkbox" data-id="${esc(String(o.id))}" data-label="${esc(o.label)}" ${checked}> <span>${esc(o.label)}${sub}</span></label>`;
        }).join('');
    }
    body.innerHTML = html;
}

function _getOptionsFor(cat) {
    if (!_filterOptions || !cat.source) return [];
    const raw = _filterOptions[cat.source] || [];

    // Cascading filters: when division/area selected, narrow areas/projects.
    if (cat.key === 'area') {
        const divSel = (_filterState.division || []).map(v => String(v.id));
        const out = (_filterOptions.areas || []).filter(a => !divSel.length || divSel.includes(String(a.division_id)));
        return out.map(a => ({ id: a.id, label: a.name, sub: a.division_name }));
    }
    if (cat.key === 'project') {
        const divSel = (_filterState.division || []).map(v => String(v.id));
        const areaSel = (_filterState.area || []).map(v => String(v.id));
        const out = (_filterOptions.projects || []).filter(p =>
            (!divSel.length  || divSel.includes(String(p.division_id))) &&
            (!areaSel.length || areaSel.includes(String(p.area_id)))
        );
        return out.map(p => ({ id: p.id, label: p.name }));
    }
    if (cat.key === 'division') return raw.map(d => ({ id: d.id, label: d.name }));
    if (cat.key === 'twl_zone') return raw.map(z => ({ id: z.id, label: z.name }));
    if (cat.simple) return raw.map(v => ({ id: v, label: v }));
    return [];
}

function _closePopover() {
    const popover = $('#filter-popover');
    if (popover) popover.classList.add('hidden');
    const dropzone = $('#filter-dropzone');
    if (dropzone) dropzone.classList.remove('picker-open');
    _activePopoverCat = null;
}

function _applyPopover() {
    if (!_activePopoverCat) { _closePopover(); return; }
    const cat = FILTER_CATEGORIES.find(c => c.key === _activePopoverCat);
    if (!cat) { _closePopover(); return; }

    if (cat.range) {
        const f = $('#age-from-input')?.value;
        const t = $('#age-to-input')?.value;
        const fv = (f !== '' && f != null) ? parseInt(f, 10) : '';
        const tv = (t !== '' && t != null) ? parseInt(t, 10) : '';
        if ((fv === '' || isNaN(fv)) && (tv === '' || isNaN(tv))) {
            _filterState[cat.key] = null;
        } else {
            _filterState[cat.key] = {
                from: (fv === '' || isNaN(fv)) ? '' : fv,
                to:   (tv === '' || isNaN(tv)) ? '' : tv,
            };
        }
    } else {
        const checks = Array.from($$('#filter-popover-body input[type="checkbox"]:checked'));
        _filterState[cat.key] = checks.map(c => ({ id: c.dataset.id, label: c.dataset.label || c.dataset.id }));

        // Cascade: when division values change, prune area/project selections that no longer match.
        if (cat.key === 'division') _pruneCascade('division');
        if (cat.key === 'area')     _pruneCascade('area');
    }

    _closePopover();
    _renderActiveChips();
    _scheduleDashboardRefresh();
}

function _pruneCascade(changedKey) {
    if (!_filterOptions) return;
    if (changedKey === 'division') {
        const divIds = (_filterState.division || []).map(v => String(v.id));
        if (divIds.length && _filterState.area) {
            _filterState.area = _filterState.area.filter(v => {
                const a = (_filterOptions.areas || []).find(x => String(x.id) === String(v.id));
                return a && divIds.includes(String(a.division_id));
            });
        }
        if (divIds.length && _filterState.project) {
            _filterState.project = _filterState.project.filter(v => {
                const p = (_filterOptions.projects || []).find(x => String(x.id) === String(v.id));
                return p && divIds.includes(String(p.division_id));
            });
        }
    }
    if (changedKey === 'area') {
        const areaIds = (_filterState.area || []).map(v => String(v.id));
        if (areaIds.length && _filterState.project) {
            _filterState.project = _filterState.project.filter(v => {
                const p = (_filterOptions.projects || []).find(x => String(x.id) === String(v.id));
                return p && areaIds.includes(String(p.area_id));
            });
        }
    }
}

function _clearPopover() {
    if (!_activePopoverCat) return;
    const cat = FILTER_CATEGORIES.find(c => c.key === _activePopoverCat);
    if (!cat) return;
    if (cat.range) {
        const f = $('#age-from-input'); if (f) f.value = '';
        const t = $('#age-to-input');   if (t) t.value = '';
    } else {
        $$('#filter-popover-body input[type="checkbox"]').forEach(c => c.checked = false);
    }
}

function _resetAllFilters() {
    _filterState = {};
    _closePopover();
    _renderActiveChips();
    _scheduleDashboardRefresh();
}

async function initDashFilters() {
    // Load distinct values once
    try {
        _filterOptions = await api('/filter-options');
    } catch (e) {
        _filterOptions = { divisions: [], areas: [], projects: [], contractors: [], camps: [], fieldglass: [], disciplines: [], nationalities: [], chronic: [], twl_zones: [], age_min: 18, age_max: 70 };
    }

    _renderPalette();
    _renderActiveChips();

    // Drop zone events
    const dropzone = $('#filter-dropzone');
    if (dropzone) {
        dropzone.addEventListener('dragover', e => {
            e.preventDefault();
            dropzone.classList.add('drag-over');
            if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
        });
        dropzone.addEventListener('dragleave', e => {
            if (e.target === dropzone) dropzone.classList.remove('drag-over');
        });
        dropzone.addEventListener('drop', e => {
            e.preventDefault();
            dropzone.classList.remove('drag-over');
            const data = e.dataTransfer.getData('text/plain');
            if (!data || data.startsWith('__active:')) return;
            const anchor = document.querySelector(`#filter-palette-chips .fchip[data-cat="${data}"]`);
            _addFilterCategory(data, anchor);
        });
    }

    // Popover wiring
    $('#filter-popover-close')?.addEventListener('click', _closePopover);
    $('#filter-popover-apply')?.addEventListener('click', _applyPopover);
    $('#filter-popover-clear')?.addEventListener('click', _clearPopover);
    $('#filter-reset')?.addEventListener('click', _resetAllFilters);

    // Click-outside dismiss
    document.addEventListener('mousedown', e => {
        const popover = $('#filter-popover');
        if (!popover || popover.classList.contains('hidden')) return;
        if (popover.contains(e.target)) return;
        if (e.target.closest('.fchip-active') || e.target.closest('.fchip')) return;
        _closePopover();
    });

    // Esc dismiss
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') _closePopover();
    });

    initDateSlider();
}

function refreshDashboard() {
    loadDashboard();
    loadDashCharts();
    loadPersonnel('present');
    loadAnomalies();
}

async function loadDashboard() {
    const selectedDate = getSliderDate();

    const filterParams = getDashFilterParams();
    let url = `/headcount?date=${selectedDate}` + (filterParams ? '&' + filterParams : '');
    let su = `/stats?date=${selectedDate}` + (filterParams ? '&' + filterParams : '');

    const [hc, stats] = await Promise.all([api(url), api(su)]);
    if (!stats.total_employees && stats.total_employees !== 0) return;

    const headcountDate = selectedDate || hc.date || new Date().toISOString().split('T')[0];
    const dateLabel = formatHeadcountDate(headcountDate);
    const dateEl = $('#headcount-date-label');
    if (dateEl) dateEl.textContent = dateLabel ? `${dateLabel} →` : '→';

    const amP = stats.total_employees > 0 ? Math.round(((stats.today_am || 0) / stats.total_employees) * 100) : 0;
    const evP = stats.total_employees > 0 ? Math.round(((stats.today_ev || 0) / stats.total_employees) * 100) : 0;
    $('#stats-cards').innerHTML = `
        <div class="stat-card clickable" data-navigate="workforce"><div class="stat-value blue">${esc(String(stats.total_employees))}</div><div class="stat-label">Total Workforce</div></div>
        <div class="stat-card clickable" data-navigate="trends"><div class="stat-value green">${esc(String(stats.today_am ?? 0))} <small style="font-size:0.7em;opacity:0.7">(${amP}%)</small></div><div class="stat-label">9 AM Present</div></div>
        <div class="stat-card clickable" data-navigate="trends"><div class="stat-value teal">${esc(String(stats.today_ev ?? 0))} <small style="font-size:0.7em;opacity:0.7">(${evP}%)</small></div><div class="stat-label">7 PM Present</div></div>
        <div class="stat-card clickable" data-navigate="workforce"><div class="stat-value orange">${esc(String(stats.total_projects))}</div><div class="stat-label">Projects</div></div>`;

    window._dashHC = hc;
    window._dashStats = stats;
    drawHeadcountChart(hc);
}

function getDashFilterParams() {
    const parts = [];
    const map = {
        division: 'division_id',
        area: 'area_id',
        project: 'project_id',
        subcontractor: 'subcontractor',
        twl_zone: 'twl_zone',
        camp: 'camp',
        fieldglass_status: 'fieldglass_status',
        discipline: 'discipline',
        nationality: 'nationality',
        chronic: 'chronic',
    };
    Object.keys(map).forEach(key => {
        const val = _filterState[key];
        if (!Array.isArray(val) || val.length === 0) return;
        const csv = val.map(v => v.id).join(',');
        parts.push(`${map[key]}=${encodeURIComponent(csv)}`);
    });
    if (_filterState.age && (_filterState.age.from !== '' || _filterState.age.to !== '')) {
        if (_filterState.age.from !== '' && _filterState.age.from != null) parts.push(`age_from=${_filterState.age.from}`);
        if (_filterState.age.to   !== '' && _filterState.age.to   != null) parts.push(`age_to=${_filterState.age.to}`);
    }
    return parts.join('&');
}

// Legacy no-op (the new filter shell handles contractor selection via /api/filter-options).
async function loadContractors() { return; }

function getWorkforceFilterParams() {
    const parts = [];
    const div = $('#wf-division')?.value;
    const area = $('#wf-filter-area')?.value;
    const proj = $('#wf-project')?.value;
    const ctr = $('#wf-contractor')?.value;
    if (proj) parts.push(`project_id=${proj}`);
    else if (area) parts.push(`area_id=${area}`);
    else if (div) parts.push(`division_id=${div}`);
    if (ctr) parts.push(`subcontractor=${encodeURIComponent(ctr)}`);
    return parts.join('&');
}

async function loadWorkerList() {
    const wrap = $('#worker-list');
    if (!wrap) return;
    wrap.innerHTML = '<div class="spinner"></div>';
    const params = getWorkforceFilterParams();
    let url = '/employees' + (params ? '?' + params : '');
    const data = await api(url);
    if (!Array.isArray(data)) { wrap.innerHTML = '<div class="empty-state">No workers</div>'; _dashWorkers = []; return; }
    _dashWorkers = data;
    renderWorkerTable(data);
}

function renderWorkerTable(data) {
    const wrap = $('#worker-list');
    const label = $('#worker-count-label');
    if (label) label.textContent = `${data.length} worker${data.length !== 1 ? 's' : ''}`;
    if (!data.length) { wrap.innerHTML = '<div class="empty-state">No workers found</div>'; return; }
    wrap.innerHTML = `<table class="worker-table"><thead><tr>
        <th>SL#</th><th>Agreement No.</th><th>Asset</th><th>Contractor</th><th>Project</th>
        <th>Name</th><th>Designation</th><th>Nationality</th><th>DOB</th><th>Age</th>
        <th>EID / Passport</th><th>Fieldglass</th><th>Work Location</th><th>Camp</th>
        <th>Employee No.</th><th>Qualification</th><th>Joining</th><th>Deployment</th>
        <th>Medical Date</th><th>Discipline</th><th>Sub-contractor</th>
        <th>Med Freq</th><th>Last Medical</th><th>Next Medical</th><th>Result</th>
        <th>Chronic</th><th>Treated?</th><th>Feeling</th><th>Remarks</th><th>QR</th>
        </tr></thead><tbody>` +
        data.slice(0, 500).map((w) => `<tr>
        <td>${esc(w.srl || '')}</td><td>${esc(w.agreement_no || '')}</td>
        <td>${esc(w.asset_name || '')}</td><td>${esc(w.contractor || '')}</td>
        <td>${esc(w.project_name || '')}</td><td>${esc(w.name)}</td>
        <td>${esc(w.designation || '')}</td><td>${esc(w.nationality || '')}</td>
        <td>${esc(w.dob || '')}</td><td>${esc(w.age || '')}</td>
        <td>${esc(w.eid_passport || '')}</td><td>${esc(w.fieldglass_status || '')}</td>
        <td>${esc(w.work_location || '')}</td><td>${esc(w.camp_name || '')}</td>
        <td>${esc(w.employee_no)}</td><td>${esc(w.qualification || '')}</td>
        <td>${esc(w.date_joining || '')}</td><td>${esc(w.date_deployment || '')}</td>
        <td>${esc(w.medical_date || '')}</td><td>${esc(w.discipline || '')}</td>
        <td>${esc(w.subcontractor || '')}</td>
        <td>${esc(w.medical_frequency || '')}</td><td>${esc(w.last_medical_date || '')}</td>
        <td>${esc(w.next_medical_due || '')}</td><td>${esc(w.medical_result || '')}</td>
        <td>${esc(w.chronic_condition || '')}</td><td>${esc(w.chronic_treated || '')}</td>
        <td>${esc(w.general_feeling || '')}</td><td>${esc(w.remarks || '')}</td>
        <td><button class="btn-qr-dl" data-empno="${esc(w.employee_no)}" data-pid="${w.project_id}" data-name="${esc(w.name)}">QR</button></td>
        </tr>`).join('') + '</tbody></table>';

    wrap.onclick = async (e) => {
        const btn = e.target.closest('.btn-qr-dl');
        if (!btn) return;
        const empNo = btn.dataset.empno, pid = btn.dataset.pid, name = btn.dataset.name;
        try {
            const res = await fetch(`/api/qrcodes/single?employee_no=${encodeURIComponent(empNo)}&project_id=${pid}`, {
                headers: { 'Authorization': `Bearer ${state.token}` }
            });
            const blob = await res.blob();
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `QR_${name.replace(/\s+/g, '_')}_${empNo}.png`;
            a.click();
            URL.revokeObjectURL(a.href);
        } catch { toast('Download failed', 'error'); }
    };
}

async function loadDashQRCodes() {
    const grid = $('#qr-grid');
    if (!grid) return;
    grid.innerHTML = '<div class="spinner"></div>';
    const search = ($('#qr-search')?.value || '').toLowerCase();
    const pf = $('#qr-project-filter')?.value;
    let url = '/qrcodes/batch';
    if (pf) url += `?project_id=${pf}`;
    else {
        const filterParams = getDashFilterParams();
        if (filterParams) url += '?' + filterParams;
    }
    const data = await api(url);
    if (!Array.isArray(data)) { grid.innerHTML = '<div class="empty-state">No QR codes</div>'; return; }
    let filtered = search ? data.filter(e => e.name.toLowerCase().includes(search) || e.employee_no.toLowerCase().includes(search)) : data;
    if (!filtered.length) { grid.innerHTML = '<div class="empty-state">No matching workers</div>'; return; }
    grid.innerHTML = filtered.map(e => `<div class="qr-card" data-emp="${esc(e.employee_no)}">
        <img src="data:image/png;base64,${e.qr_base64}" alt="QR ${esc(e.employee_no)}">
        <div class="qr-name">${esc(e.name)}</div>
        <div class="qr-id">${esc(e.employee_no)}</div>
        <div class="qr-role">${esc(e.designation || '')}${e.designation && e.discipline ? ' | ' : ''}${esc(e.discipline || '')}</div>
        ${e.project_name ? `<div class="qr-project">${esc(e.project_name)}</div>` : ''}
        <div class="qr-handout">Digital HSE & Welfare — present at site</div>
        </div>`).join('');
}

function formatHeadcountDate(iso) {
    if (!iso) return '';
    const [y, m, day] = iso.split('-');
    const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    return `${day} ${months[parseInt(m,10)-1]} ${y}`;
}

// ============================================================
// DASHBOARD CHARTS (overview only — click to navigate)
// ============================================================

function drawHeadcountChart(hc) {
    const canvas = $('#dash-headcount-chart');
    if (!canvas || !hc.sites || !hc.sites.length) {
        if (canvas) { const ctx = canvas.getContext('2d'); ctx.clearRect(0, 0, canvas.width, canvas.height); ctx.fillStyle = '#94a3b8'; ctx.font = '13px Inter, sans-serif'; ctx.fillText('No headcount data', 20, 90); }
        return;
    }
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth, h = canvas.clientHeight;
    canvas.width = w * dpr; canvas.height = h * dpr;
    ctx.scale(dpr, dpr); ctx.clearRect(0, 0, w, h);
    const sites = hc.sites.slice(0, 8);
    const pad = { top: 10, right: 16, bottom: 30, left: 100 };
    const ch = h - pad.top - pad.bottom;
    const barH = Math.min(20, ch / sites.length * 0.65);
    const gap = (ch - barH * sites.length) / (sites.length + 1);
    const maxV = Math.max(...sites.map(s => s.total_employees || 1), 1);

    sites.forEach((s, i) => {
        const y = pad.top + gap + i * (barH + gap);
        const am = s.AM ?? 0;
        const barW = (am / maxV) * (w - pad.left - pad.right);
        const totalW = (s.total_employees / maxV) * (w - pad.left - pad.right);
        ctx.fillStyle = 'rgba(148,163,184,0.1)';
        ctx.fillRect(pad.left, y, totalW, barH);
        const pct = s.total_employees > 0 ? am / s.total_employees : 0;
        ctx.fillStyle = pct >= 0.8 ? '#22c55e' : pct >= 0.5 ? '#f59e0b' : '#ef4444';
        ctx.beginPath();
        const r = 3;
        ctx.moveTo(pad.left + r, y); ctx.lineTo(pad.left + barW - r, y);
        ctx.quadraticCurveTo(pad.left + barW, y, pad.left + barW, y + r);
        ctx.lineTo(pad.left + barW, y + barH - r);
        ctx.quadraticCurveTo(pad.left + barW, y + barH, pad.left + barW - r, y + barH);
        ctx.lineTo(pad.left + r, y + barH);
        ctx.quadraticCurveTo(pad.left, y + barH, pad.left, y + barH - r);
        ctx.lineTo(pad.left, y + r);
        ctx.quadraticCurveTo(pad.left, y, pad.left + r, y);
        ctx.fill();

        ctx.fillStyle = '#e2e8f0'; ctx.font = '10px Inter, sans-serif'; ctx.textAlign = 'left';
        ctx.fillText(`${am}/${s.total_employees}`, pad.left + barW + 6, y + barH / 2 + 4);
        ctx.fillStyle = '#94a3b8'; ctx.font = '10px Inter, sans-serif'; ctx.textAlign = 'right';
        const label = (s.project || '').length > 14 ? (s.project || '').slice(0, 13) + '…' : (s.project || '');
        ctx.fillText(label, pad.left - 6, y + barH / 2 + 4);
    });
}

async function loadDashCharts() {
    loadDashAttendanceChart();
    loadDashMissingChart();
    loadDashTWLGauge();
    loadDashHealthChart();
    loadDashChronicChart();
    loadDashOIChart();
    loadDashDisciplineChart();
    loadDashWeatherSummary();
    loadDashNationalityChart();
}

async function loadDashAttendanceChart() {
    const canvas = $('#dash-attendance-chart');
    if (!canvas) return;
    const filterParams = getDashFilterParams();
    const params = new URLSearchParams();
    if (filterParams) filterParams.split('&').forEach(p => { const [k, v] = p.split('='); params.set(k, v); });
    const mode = $('#dash-slider-mode')?.value || 'day';
    params.set('days', mode === 'month' ? '30' : mode === 'week' ? '13' : '7');
    params.set('session', _sliderSession === 'PM' ? 'EV' : 'AM');
    const data = await api('/trends?' + params.toString());
    if (!data || !data.labels) return;
    drawLineChart(canvas, data.labels, data.values, data.total);
}

async function loadDashMissingChart() {
    const canvas = $('#dash-missing-chart');
    if (!canvas) return;
    const selectedDate = getSliderDate();
    const filterParams = getDashFilterParams();
    const sess = _sliderSession === 'PM' ? 'EV' : 'AM';
    const hcUrl = `/headcount?date=${selectedDate}` + (filterParams ? '&' + filterParams : '');
    const hc = await api(hcUrl);
    if (!hc || !hc.sites) return;

    const projects = {};
    hc.sites.forEach(s => {
        const key = s.project;
        if (!projects[key]) projects[key] = { present: 0, total: 0 };
        projects[key].present += (s[sess] || s['AM'] || 0);
        projects[key].total += (s.total_employees || 0);
    });

    const sorted = Object.entries(projects)
        .map(([name, d]) => ({ name, present: d.present, missing: Math.max(0, d.total - d.present), total: d.total }))
        .filter(d => d.total > 0)
        .sort((a, b) => b.missing - a.missing)
        .slice(0, 8);

    if (!sorted.length) {
        const ctx = canvas.getContext('2d');
        const dpr = window.devicePixelRatio || 1;
        const w = canvas.clientWidth, h = canvas.clientHeight;
        canvas.width = w * dpr; canvas.height = h * dpr;
        ctx.scale(dpr, dpr); ctx.clearRect(0, 0, w, h);
        ctx.fillStyle = '#94a3b8'; ctx.font = '13px Inter'; ctx.fillText('No attendance data', w / 2 - 55, h / 2);
        return;
    }

    drawStackedBarChart(canvas, sorted);
}

function drawStackedBarChart(canvas, data) {
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth, h = canvas.clientHeight;
    canvas.width = w * dpr; canvas.height = h * dpr;
    ctx.scale(dpr, dpr); ctx.clearRect(0, 0, w, h);
    if (!data.length) return;

    const pad = { top: 22, right: 50, bottom: 10, left: 100 };
    const barArea = h - pad.top - pad.bottom;
    const barH = Math.min(18, (barArea / data.length) - 4);
    const gap = Math.max(2, (barArea - barH * data.length) / Math.max(data.length - 1, 1));
    const maxVal = Math.max(...data.map(d => d.total), 1);
    const barWidth = w - pad.left - pad.right;

    const totalMissing = data.reduce((s, d) => s + d.missing, 0);
    const totalPresent = data.reduce((s, d) => s + d.present, 0);
    ctx.fillStyle = '#e2e8f0'; ctx.font = 'bold 11px Inter'; ctx.textAlign = 'left';
    ctx.fillText(`${totalMissing} missing`, pad.left, 14);
    ctx.fillStyle = '#94a3b8'; ctx.font = '10px Inter';
    ctx.fillText(`/ ${totalPresent + totalMissing} total`, pad.left + ctx.measureText(`${totalMissing} missing`).width + 4, 14);

    data.forEach((d, i) => {
        const y = pad.top + i * (barH + gap);
        const presentW = (d.present / maxVal) * barWidth;
        const missingW = (d.missing / maxVal) * barWidth;

        ctx.fillStyle = '#94a3b8'; ctx.font = '10px Inter'; ctx.textAlign = 'right';
        const label = d.name.length > 14 ? d.name.substring(0, 13) + '…' : d.name;
        ctx.fillText(label, pad.left - 6, y + barH / 2 + 3);

        const r = 3;
        if (presentW > 0) {
            ctx.fillStyle = '#22c55e';
            ctx.beginPath();
            ctx.moveTo(pad.left + r, y);
            ctx.lineTo(pad.left + presentW, y);
            ctx.lineTo(pad.left + presentW, y + barH);
            ctx.lineTo(pad.left + r, y + barH);
            ctx.quadraticCurveTo(pad.left, y + barH, pad.left, y + barH - r);
            ctx.lineTo(pad.left, y + r);
            ctx.quadraticCurveTo(pad.left, y, pad.left + r, y);
            ctx.fill();
        }

        if (missingW > 1) {
            ctx.fillStyle = '#ef4444';
            ctx.beginPath();
            const mx = pad.left + presentW;
            ctx.moveTo(mx, y);
            ctx.lineTo(mx + missingW - r, y);
            ctx.quadraticCurveTo(mx + missingW, y, mx + missingW, y + r);
            ctx.lineTo(mx + missingW, y + barH - r);
            ctx.quadraticCurveTo(mx + missingW, y + barH, mx + missingW - r, y + barH);
            ctx.lineTo(mx, y + barH);
            ctx.fill();
        }

        ctx.fillStyle = '#e2e8f0'; ctx.font = 'bold 9px Inter'; ctx.textAlign = 'left';
        ctx.fillText(`${d.missing}`, pad.left + presentW + missingW + 4, y + barH / 2 + 3);
    });
}

async function loadDashTWLGauge() {
    const el = $('#dash-twl-gauge');
    if (!el) return;
    const filterParams = getDashFilterParams();
    let qp = 'days=1';
    const area = $('#dash-area')?.value;
    if (area) qp += `&area_id=${area}`;
    const data = await api('/twl/summary?' + qp);
    if (!data || !data.today || data.today.length === 0) {
        el.innerHTML = `<div class="twl-gauge-wrap">
            <div class="twl-gauge-value" style="color:var(--text-dim)">—</div>
            <div class="twl-gauge-detail">No TWL readings today</div>
            <div class="twl-gauge-bar"><div class="twl-gauge-marker" style="left:50%"></div></div>
            <div class="twl-gauge-labels"><span>&lt;115</span><span>115</span><span>140</span><span>220+</span></div>
        </div>`;
        return;
    }
    const latest = data.today[0];
    const val = latest.twl_value;
    const zone = latest.risk_zone;
    const zoneColors = { low: '#22c55e', medium: '#f59e0b', high: '#ef4444' };
    const zoneLabels = { low: 'Low Risk', medium: 'Medium Risk', high: 'High Risk' };
    const zoneBg = { low: 'rgba(34,197,94,0.15)', medium: 'rgba(245,158,11,0.15)', high: 'rgba(239,68,68,0.15)' };
    const markerPct = Math.max(0, Math.min(100, ((val - 80) / (220 - 80)) * 100));

    el.innerHTML = `<div class="twl-gauge-wrap">
        <div class="twl-gauge-value" style="color:${zoneColors[zone]}">${val}</div>
        <div class="twl-gauge-zone" style="background:${zoneBg[zone]};color:${zoneColors[zone]}">${zoneLabels[zone]}</div>
        <div class="twl-gauge-bar"><div class="twl-gauge-marker" style="left:${markerPct}%"></div></div>
        <div class="twl-gauge-labels"><span>&lt;115</span><span>115</span><span>140</span><span>220+</span></div>
        <div class="twl-gauge-detail">${latest.area_name || ''} at ${latest.reading_time || ''}</div>
    </div>`;
}

async function loadDashHealthChart() {
    const canvas = $('#dash-health-chart');
    if (!canvas) return;
    const filterParams = getDashFilterParams();
    const data = await api('/health-trends' + (filterParams ? '?' + filterParams : ''));
    if (!data || data.success === false || !data.medical || !data.total) return;
    drawDonutChart(canvas, [
        { label: 'Fit', value: data.medical.fit, color: '#22c55e' },
        { label: 'Unfit', value: data.medical.unfit, color: '#ef4444' },
        { label: 'No Result', value: data.medical.no_result, color: '#94a3b8' },
    ], data.total);
}

async function loadDashChronicChart() {
    const canvas = $('#dash-chronic-chart');
    if (!canvas) return;
    const filterParams = getDashFilterParams();
    const data = await api('/health-trends' + (filterParams ? '?' + filterParams : ''));
    if (!data || !data.chronic_types || !data.chronic_types.length) {
        const ctx = canvas.getContext('2d');
        const dpr = window.devicePixelRatio || 1;
        const w = canvas.clientWidth, h = canvas.clientHeight;
        canvas.width = w * dpr; canvas.height = h * dpr;
        ctx.scale(dpr, dpr); ctx.clearRect(0, 0, w, h);
        ctx.fillStyle = '#94a3b8'; ctx.font = '13px Inter'; ctx.fillText('No chronic conditions recorded', w / 2 - 80, h / 2);
        return;
    }
    const types = data.chronic_types.slice(0, 8);
    const colors = ['#ef4444', '#f59e0b', '#8b5cf6', '#3b82f6', '#06b6d4', '#22c55e', '#ec4899', '#f97316'];
    drawHorizontalBarChart(canvas, types.map(t => t.label), types.map(t => t.count), colors, data.chronic.has_chronic);
}

function drawHorizontalBarChart(canvas, labels, values, colors, total) {
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth, h = canvas.clientHeight;
    canvas.width = w * dpr; canvas.height = h * dpr;
    ctx.scale(dpr, dpr); ctx.clearRect(0, 0, w, h);
    if (!values.length) return;

    const maxVal = Math.max(...values, 1);
    const pad = { top: 20, right: 16, bottom: 10, left: 100 };
    const barArea = h - pad.top - pad.bottom;
    const barH = Math.min(20, (barArea / values.length) - 4);
    const gap = (barArea - barH * values.length) / Math.max(values.length - 1, 1);

    ctx.fillStyle = '#e2e8f0'; ctx.font = 'bold 12px Inter'; ctx.textAlign = 'left';
    ctx.fillText(`${total || values.reduce((a, b) => a + b, 0)} total`, pad.left, 14);

    labels.forEach((label, i) => {
        const y = pad.top + i * (barH + gap);
        const barW = (values[i] / maxVal) * (w - pad.left - pad.right);

        ctx.fillStyle = '#94a3b8'; ctx.font = '10px Inter'; ctx.textAlign = 'right';
        const truncLabel = label.length > 14 ? label.substring(0, 13) + '…' : label;
        ctx.fillText(truncLabel, pad.left - 6, y + barH / 2 + 3);

        ctx.fillStyle = colors[i % colors.length];
        ctx.beginPath();
        const r = 3;
        ctx.moveTo(pad.left + r, y);
        ctx.lineTo(pad.left + barW - r, y);
        ctx.quadraticCurveTo(pad.left + barW, y, pad.left + barW, y + r);
        ctx.lineTo(pad.left + barW, y + barH - r);
        ctx.quadraticCurveTo(pad.left + barW, y + barH, pad.left + barW - r, y + barH);
        ctx.lineTo(pad.left + r, y + barH);
        ctx.quadraticCurveTo(pad.left, y + barH, pad.left, y + barH - r);
        ctx.lineTo(pad.left, y + r);
        ctx.quadraticCurveTo(pad.left, y, pad.left + r, y);
        ctx.fill();

        ctx.fillStyle = '#e2e8f0'; ctx.font = 'bold 10px Inter'; ctx.textAlign = 'left';
        ctx.fillText(values[i], pad.left + barW + 5, y + barH / 2 + 3);
    });
}

async function loadDashOIChart() {
    const canvas = $('#dash-oi-chart');
    if (!canvas) return;
    const selectedDate = getSliderDate();
    const filterParams = getDashFilterParams();
    let url = `/observations/summary?date=${selectedDate}`;
    if (filterParams) url += '&' + filterParams;
    const data = await api(url);
    if (!data || !data.total) {
        const ctx = canvas.getContext('2d');
        const dpr = window.devicePixelRatio || 1;
        const w = canvas.clientWidth, h = canvas.clientHeight;
        canvas.width = w * dpr; canvas.height = h * dpr;
        ctx.scale(dpr, dpr); ctx.clearRect(0, 0, w, h);
        ctx.fillStyle = '#94a3b8'; ctx.font = '13px Inter'; ctx.fillText('No observations for this day', w / 2 - 80, h / 2);
        return;
    }
    const groupColors = {
        'Safe Act': '#22c55e', 'Safe Condition': '#16a34a',
        'Unsafe Act': '#f59e0b', 'Unsafe Condition': '#ef4444',
        'Near Miss': '#f97316', 'HIPO': '#a855f7'
    };
    const segments = data.by_group.map(g => ({
        label: g.observation_group, value: g.c, color: groupColors[g.observation_group] || '#94a3b8'
    }));
    drawDonutChart(canvas, segments, data.total);
}

async function loadDashDisciplineChart() {
    const canvas = $('#dash-discipline-chart');
    if (!canvas) return;
    const filterParams = getDashFilterParams();
    const data = await api('/employees' + (filterParams ? '?' + filterParams : ''));
    if (!Array.isArray(data) || !data.length) return;
    const discCounts = {};
    data.forEach(w => { const d = w.discipline || 'Unknown'; discCounts[d] = (discCounts[d] || 0) + 1; });
    const sorted = Object.entries(discCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const colors = ['#3b82f6', '#22c55e', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4', '#ec4899', '#f97316'];
    drawHorizontalBarChart(canvas, sorted.map(s => s[0]), sorted.map(s => s[1]), colors, data.length);
}

async function loadDashWeatherSummary() {
    const el = $('#dash-weather-summary');
    if (!el) return;
    const coords = getWeatherCoords();
    const selectedDate = getSliderDate();
    try {
        const resp = await fetch(`https://historical-forecast-api.open-meteo.com/v1/forecast?latitude=${coords.lat}&longitude=${coords.lon}&start_date=${selectedDate}&end_date=${selectedDate}&daily=temperature_2m_max,temperature_2m_min,wind_speed_10m_max,relative_humidity_2m_max,precipitation_sum&timezone=Asia%2FDubai`);
        const w = await resp.json();
        if (!w.daily || !w.daily.time || !w.daily.time.length) throw new Error('No data');
        const d = w.daily;
        el.innerHTML = `<div class="dash-weather-row">
            <div class="dash-weather-item"><div class="dash-weather-val" style="color:#f59e0b">${(d.temperature_2m_max[0] ?? 0).toFixed(0)}°</div><div class="dash-weather-lbl">High</div></div>
            <div class="dash-weather-item"><div class="dash-weather-val" style="color:#38bdf8">${(d.temperature_2m_min[0] ?? 0).toFixed(0)}°</div><div class="dash-weather-lbl">Low</div></div>
            <div class="dash-weather-item"><div class="dash-weather-val" style="color:#06b6d4">${(d.relative_humidity_2m_max[0] ?? 0).toFixed(0)}%</div><div class="dash-weather-lbl">Humidity</div></div>
            <div class="dash-weather-item"><div class="dash-weather-val" style="color:#8b5cf6">${(d.wind_speed_10m_max[0] ?? 0).toFixed(0)}</div><div class="dash-weather-lbl">Wind km/h</div></div>
            <div class="dash-weather-item"><div class="dash-weather-val" style="color:#3b82f6">${(d.precipitation_sum[0] ?? 0).toFixed(1)}</div><div class="dash-weather-lbl">Rain mm</div></div>
        </div>`;
        if ((d.temperature_2m_max[0] || 0) > 45 || (d.wind_speed_10m_max[0] || 0) > 40) {
            el.innerHTML += '<div class="weather-warn" style="margin-top:8px;grid-column:1/-1">⚠ Extreme conditions — check TWL</div>';
        }
    } catch {
        el.innerHTML = '<div class="empty-state" style="padding:20px">Weather unavailable</div>';
    }
}

async function loadDashNationalityChart() {
    const canvas = $('#dash-nationality-chart');
    if (!canvas) return;
    const filterParams = getDashFilterParams();
    const data = await api('/employees' + (filterParams ? '?' + filterParams : ''));
    if (!Array.isArray(data) || !data.length) return;
    const natCounts = {};
    data.forEach(w => { const n = w.nationality || 'Unknown'; natCounts[n] = (natCounts[n] || 0) + 1; });
    const sorted = Object.entries(natCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const colors = ['#3b82f6', '#22c55e', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4'];
    drawDonutChart(canvas, sorted.map(([label, value], i) => ({ label, value, color: colors[i % colors.length] })), data.length);
}

function drawDonutChart(canvas, segments, total) {
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth, h = canvas.clientHeight;
    canvas.width = w * dpr; canvas.height = h * dpr;
    ctx.scale(dpr, dpr); ctx.clearRect(0, 0, w, h);
    if (!segments.length || total === 0) { ctx.fillStyle = '#94a3b8'; ctx.font = '13px Inter'; ctx.fillText('No data', w/2 - 25, h/2); return; }

    const cx = w * 0.35, cy = h / 2, radius = Math.min(cx - 10, cy - 10, 70);
    const inner = radius * 0.55;
    let startAngle = -Math.PI / 2;
    segments.forEach(seg => {
        const slice = (seg.value / total) * Math.PI * 2;
        ctx.beginPath(); ctx.moveTo(cx + inner * Math.cos(startAngle), cy + inner * Math.sin(startAngle));
        ctx.arc(cx, cy, radius, startAngle, startAngle + slice);
        ctx.arc(cx, cy, inner, startAngle + slice, startAngle, true);
        ctx.closePath(); ctx.fillStyle = seg.color; ctx.fill();
        startAngle += slice;
    });
    ctx.fillStyle = '#e2e8f0'; ctx.font = 'bold 16px Inter'; ctx.textAlign = 'center';
    ctx.fillText(total, cx, cy + 6);

    let ly = Math.max(16, cy - segments.length * 11);
    const lx = w * 0.7;
    ctx.textAlign = 'left'; ctx.font = '10px Inter';
    segments.forEach(seg => {
        ctx.fillStyle = seg.color; ctx.fillRect(lx, ly - 5, 8, 8);
        ctx.fillStyle = '#e2e8f0'; ctx.fillText(`${seg.label} (${seg.value})`, lx + 12, ly + 3);
        ly += 18;
    });
}

function navigateToTab(tabName) {
    const tab = document.querySelector(`.tab[data-tab="${tabName}"]`);
    if (tab && tab.style.display !== 'none') tab.click();
}

async function loadAnomalies() {
    const panel = $('#anomalies-panel');
    const list = $('#anomalies-list');
    const countBadge = $('#anomaly-count');
    if (!panel || !list) return;

    const selectedDate = getSliderDate();
    const filterParams = getDashFilterParams();
    let url = `/anomalies?date=${selectedDate}`;
    if (filterParams) url += '&' + filterParams;

    const data = await api(url);
    if (!data || !data.anomalies || data.anomalies.length === 0) {
        panel.style.display = 'none';
        return;
    }

    panel.style.display = '';
    if (countBadge) countBadge.textContent = data.count;

    const catIcons = {
        attendance: '👥', health: '🏥', safety: '⚠', twl: '🌡', cross: '🔗'
    };

    list.innerHTML = data.anomalies.map(a => `
        <div class="anomaly-card sev-${a.severity}">
            <div class="anomaly-icon cat-${a.category}">${catIcons[a.category] || '⚡'}</div>
            <div class="anomaly-body">
                <div class="anomaly-title">
                    <span><span class="anomaly-sev-tag sev-tag-${a.severity}">${a.severity}</span>${esc(a.title)}</span>
                    <span class="anomaly-metric">${esc(a.metric)}</span>
                </div>
                <div class="anomaly-detail">${esc(a.detail)}</div>
            </div>
        </div>
    `).join('');

    const toggleBtn = $('#anomalies-toggle');
    if (toggleBtn && !toggleBtn._bound) {
        toggleBtn._bound = true;
        toggleBtn.addEventListener('click', () => {
            const isHidden = list.style.display === 'none';
            list.style.display = isHidden ? '' : 'none';
            toggleBtn.textContent = isHidden ? 'Collapse' : 'Expand';
        });
    }
}

// ============================================================
// Risk Engine — independent date/scope, Live + Backtest sub-tabs
// ============================================================
const _riskState = {
    asOf: '',
    divisionId: '',
    areaId: '',
    projectId: '',
    subTab: 'live',
    backtestDays: 90,
    inited: false,
};

const RISK_DOMAIN_LABELS = {
    attendance: 'Attendance',
    health: 'Health',
    safety: 'Safety (O&I)',
    environmental: 'Environment (TWL)',
    cross_cutting: 'Cross-cutting',
};

function getRiskQueryParams() {
    const parts = [];
    if (_riskState.asOf) parts.push('date=' + encodeURIComponent(_riskState.asOf));
    if (_riskState.projectId) parts.push('project_id=' + encodeURIComponent(_riskState.projectId));
    else if (_riskState.areaId) parts.push('area_id=' + encodeURIComponent(_riskState.areaId));
    else if (_riskState.divisionId) parts.push('division_id=' + encodeURIComponent(_riskState.divisionId));
    return parts.join('&');
}

async function _populateRiskScopeSelects() {
    const divSel = $('#risk-division');
    const areaSel = $('#risk-area');
    const projSel = $('#risk-project');
    if (!divSel) return;

    const divs = await api('/divisions');
    if (Array.isArray(divs)) {
        divSel.innerHTML = '<option value="">All</option>' +
            divs.map(d => `<option value="${d.id}">${esc(d.name)}</option>`).join('');
    }
    areaSel.innerHTML = '<option value="">All</option>';
    projSel.innerHTML = '<option value="">All</option>';
}

async function _refreshRiskAreaOptions(divisionId) {
    const areaSel = $('#risk-area');
    if (!areaSel) return;
    if (!divisionId) {
        areaSel.innerHTML = '<option value="">All</option>';
        return;
    }
    const areas = await api(`/areas?division_id=${divisionId}`);
    areaSel.innerHTML = '<option value="">All</option>' +
        (Array.isArray(areas) ? areas.map(a => `<option value="${a.id}">${esc(a.name)}</option>`).join('') : '');
}

async function _refreshRiskProjectOptions(areaId, divisionId) {
    const projSel = $('#risk-project');
    if (!projSel) return;
    let url = '/projects';
    if (areaId) url += `?area_id=${areaId}`;
    else if (divisionId) url += `?division_id=${divisionId}`;
    const projs = await api(url);
    projSel.innerHTML = '<option value="">All</option>' +
        (Array.isArray(projs) ? projs.map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join('') : '');
}

function initRiskTab() {
    if (!_riskState.inited) {
        const today = new Date().toISOString().split('T')[0];
        _riskState.asOf = today;
        const asOfInput = $('#risk-asof');
        if (asOfInput) asOfInput.value = today;

        _populateRiskScopeSelects();

        $('#risk-asof')?.addEventListener('change', e => {
            _riskState.asOf = e.target.value || new Date().toISOString().split('T')[0];
            loadRiskEngine();
        });
        $('#risk-division')?.addEventListener('change', async e => {
            _riskState.divisionId = e.target.value;
            _riskState.areaId = '';
            _riskState.projectId = '';
            await _refreshRiskAreaOptions(_riskState.divisionId);
            await _refreshRiskProjectOptions('', _riskState.divisionId);
            _refreshRiskActiveSubTab();
        });
        $('#risk-area')?.addEventListener('change', async e => {
            _riskState.areaId = e.target.value;
            _riskState.projectId = '';
            await _refreshRiskProjectOptions(_riskState.areaId, _riskState.divisionId);
            _refreshRiskActiveSubTab();
        });
        $('#risk-project')?.addEventListener('change', e => {
            _riskState.projectId = e.target.value;
            _refreshRiskActiveSubTab();
        });

        $('#risk-use-dash')?.addEventListener('click', async () => {
            const dashDate = (typeof getSliderDate === 'function') ? getSliderDate() : new Date().toISOString().split('T')[0];
            _riskState.asOf = dashDate;
            $('#risk-asof').value = dashDate;
            const fs = (typeof _filterState !== 'undefined' && _filterState) ? _filterState : {};
            const div = (fs.division && fs.division[0]?.id) || '';
            const area = (fs.area && fs.area[0]?.id) || '';
            const proj = (fs.project && fs.project[0]?.id) || '';
            _riskState.divisionId = String(div || '');
            _riskState.areaId = String(area || '');
            _riskState.projectId = String(proj || '');
            await _refreshRiskAreaOptions(_riskState.divisionId);
            await _refreshRiskProjectOptions(_riskState.areaId, _riskState.divisionId);
            $('#risk-division').value = _riskState.divisionId;
            $('#risk-area').value = _riskState.areaId;
            $('#risk-project').value = _riskState.projectId;
            _refreshRiskActiveSubTab();
            toast('Risk Engine scope synced from Dashboard', 'success');
        });

        $('#risk-engine-refresh')?.addEventListener('click', () => _refreshRiskActiveSubTab());

        $$('.risk-subtab').forEach(btn => {
            btn.addEventListener('click', () => {
                $$('.risk-subtab').forEach(b => { b.classList.remove('active'); b.setAttribute('aria-selected', 'false'); });
                $$('.risk-subview').forEach(v => v.classList.remove('active'));
                btn.classList.add('active');
                btn.setAttribute('aria-selected', 'true');
                const target = btn.dataset.rsub;
                $(`#risk-sub-${target}`)?.classList.add('active');
                _riskState.subTab = target;
                _refreshRiskActiveSubTab();
            });
        });

        $('#risk-backtest-window')?.addEventListener('change', e => {
            _riskState.backtestDays = parseInt(e.target.value, 10) || 90;
            loadRiskBacktest();
        });

        _riskState.inited = true;
    }
    _refreshRiskActiveSubTab();
}

function _refreshRiskActiveSubTab() {
    if (_riskState.subTab === 'backtest') loadRiskBacktest();
    else loadRiskEngine();
}

async function loadRiskEngine() {
    const panel = $('#risk-engine-panel');
    const ring = $('#risk-gauge-ring');
    const idxEl = $('#risk-index-value');
    const levelEl = $('#risk-engine-level');
    const domainsEl = $('#risk-domains');
    const predEl = $('#risk-predictive-list');
    const prevEl = $('#risk-preventive-list');
    if (!panel || !ring || !idxEl) return;

    const qs = getRiskQueryParams();
    const url = '/risk-engine' + (qs ? '?' + qs : '');
    const data = await api(url);
    if (!data || data.risk_index === undefined) {
        panel.style.display = 'none';
        return;
    }
    panel.style.display = '';

    const ri = Math.min(100, Math.max(0, data.risk_index));
    ring.style.setProperty('--risk-pct', String(ri));
    idxEl.textContent = String(ri);

    const lvl = data.risk_level || 'low';
    if (levelEl) {
        levelEl.textContent = lvl.toUpperCase();
        levelEl.className = 'risk-level-badge risk-lvl-' + lvl;
    }

    if (domainsEl && data.domains) {
        const hr = data.domain_hit_rate || {};
        domainsEl.innerHTML = Object.entries(data.domains).map(([key, d]) => {
            const max = key === 'safety' ? 30 : key === 'attendance' ? 25 : key === 'health' ? 20 : key === 'environmental' ? 15 : 10;
            const pct = Math.min(100, ((d.score || 0) / max) * 100);
            const tr = d.trend || 'stable';
            const trIcon = tr === 'worsening' ? '↓' : tr === 'improving' ? '↑' : '→';
            const cal = hr[key];
            const calChip = (cal && cal.evaluated >= 3)
                ? ` <span class="risk-signal-conf-cal" title="Rolling 90d hit-rate from backtest">90d hit-rate ${cal.hits}/${cal.evaluated} (${Math.round(cal.hit_rate*100)}%)</span>`
                : '';
            return `<div class="risk-domain-row">
                <div class="risk-domain-name">${RISK_DOMAIN_LABELS[key] || key} <span class="risk-trend-${tr}">${trIcon} ${tr}</span>${calChip}</div>
                <div class="risk-domain-bar-wrap"><div class="risk-domain-bar" style="width:${pct}%"></div></div>
                <div class="risk-domain-meta">${d.score || 0}/${max} · ${esc(d.summary || '')}</div>
            </div>`;
        }).join('');
    }

    if (predEl) {
        const sigs = data.predictive_signals || [];
        if (!sigs.length) {
            predEl.innerHTML = '<div class="empty-state" style="padding:8px;font-size:0.85rem">No predictive signals for this scope — conditions appear stable on trend metrics.</div>';
        } else {
            predEl.innerHTML = sigs.map(s => {
                const conf = s.confidence != null ? Math.round(s.confidence * 100) : null;
                const rawConf = s.confidence_raw != null ? Math.round(s.confidence_raw * 100) : null;
                const calLabel = (rawConf != null && rawConf !== conf)
                    ? `<span class="risk-signal-conf-cal" title="Auto-calibrated from rolling 90d backtest hit rate">cal. from ${rawConf}%</span>`
                    : '';
                return `
                <div class="risk-signal-card sev-${s.severity || 'low'}">
                    <div class="risk-signal-top">
                        <span class="risk-signal-type">${esc(s.type || 'signal')}</span>
                        <span class="risk-signal-conf">${conf != null ? conf + '% conf.' : ''}</span>${calLabel}
                        <span class="risk-signal-horizon">${s.horizon_days != null ? '~' + s.horizon_days + 'd horizon' : ''}</span>
                    </div>
                    <div class="risk-signal-title">${esc(s.title)}</div>
                    <div class="risk-signal-detail">${esc(s.detail)}</div>
                </div>`;
            }).join('');
        }
    }

    if (prevEl) {
        const acts = data.preventive_recommendations || [];
        if (!acts.length) {
            prevEl.innerHTML = '<li class="empty-state" style="list-style:none">No extra preventive actions suggested beyond routine HSE cadence.</li>';
        } else {
            prevEl.innerHTML = acts.map(a => `<li><span class="risk-act-priority">P${a.priority}</span> <strong>${esc(a.domain)}</strong>: ${esc(a.action)} <span class="risk-act-rationale">— ${esc(a.rationale)}</span></li>`).join('');
        }
    }
}

async function loadRiskBacktest() {
    const summaryEl = $('#risk-backtest-summary');
    const domainsEl = $('#risk-backtest-domains');
    const confEl = $('#risk-backtest-confusion');
    const feedEl = $('#risk-backtest-feed');
    const badgeEl = $('#risk-backtest-badge');
    const calCanvas = $('#risk-calibration-chart');
    if (!domainsEl || !feedEl) return;

    const days = _riskState.backtestDays || 90;
    const parts = ['days=' + days];
    if (_riskState.projectId) parts.push('project_id=' + _riskState.projectId);
    else if (_riskState.areaId) parts.push('area_id=' + _riskState.areaId);
    else if (_riskState.divisionId) parts.push('division_id=' + _riskState.divisionId);
    const url = '/risk-engine/backtest?' + parts.join('&');

    feedEl.innerHTML = '<div class="spinner" style="margin:20px auto"></div>';
    const data = await api(url);
    if (!data) return;

    const totalEv = data.total_evaluated || 0;
    const totalSig = data.total_signals || 0;
    const hr = data.overall_hit_rate || 0;
    if (summaryEl) {
        summaryEl.innerHTML = `<strong>${totalSig}</strong> signal${totalSig === 1 ? '' : 's'} in last ${days} days · <strong>${totalEv}</strong> evaluated · overall hit rate <strong>${Math.round(hr * 100)}%</strong>`;
    }
    if (badgeEl) badgeEl.textContent = totalEv ? `${Math.round(hr * 100)}%` : '';

    const domainsMap = data.domains || {};
    const domainKeys = Object.keys(RISK_DOMAIN_LABELS);
    if (domainsEl) {
        domainsEl.innerHTML = domainKeys.map(key => {
            const d = domainsMap[key];
            if (!d || !d.evaluated) {
                return `<div class="risk-domain-row">
                    <div class="risk-domain-name">${RISK_DOMAIN_LABELS[key] || key}</div>
                    <div class="risk-domain-bar-wrap"><div class="risk-domain-bar" style="width:0%;background:#475569"></div></div>
                    <div class="risk-domain-meta">No evaluated signals in window</div>
                </div>`;
            }
            const pct = Math.round(d.hit_rate * 100);
            return `<div class="risk-domain-row">
                <div class="risk-domain-name">${RISK_DOMAIN_LABELS[key] || key}</div>
                <div class="risk-domain-bar-wrap"><div class="risk-domain-bar" style="width:${pct}%"></div></div>
                <div class="risk-domain-meta">${d.hits}/${d.evaluated} correct (${pct}%) · ${d.misses} false positive</div>
            </div>`;
        }).join('');
    }

    if (confEl) {
        const sevs = ['critical', 'high', 'medium', 'low'];
        const conf = data.severity_confusion || {};
        confEl.innerHTML = `<table class="risk-confusion-table">
            <thead><tr><th>Severity</th><th>True Pos.</th><th>False Pos.</th><th>Pending</th><th>Total</th><th>Hit rate</th></tr></thead>
            <tbody>${sevs.map(sv => {
                const c = conf[sv] || {tp:0,fp:0,pending:0,total:0};
                const rate = c.total - c.pending > 0 ? Math.round((c.tp / (c.total - c.pending)) * 100) : null;
                return `<tr>
                    <td><span class="risk-level-badge risk-lvl-${sv}">${sv.toUpperCase()}</span></td>
                    <td class="rc-tp">${c.tp}</td>
                    <td class="rc-fp">${c.fp}</td>
                    <td class="rc-pn">${c.pending}</td>
                    <td>${c.total}</td>
                    <td>${rate != null ? rate + '%' : '—'}</td>
                </tr>`;
            }).join('')}</tbody></table>`;
    }

    if (calCanvas) drawCalibrationChart(calCanvas, data.calibration_bins || []);

    if (feedEl) {
        const feed = data.feed || [];
        if (!feed.length) {
            feedEl.innerHTML = '<div class="empty-state" style="padding:14px;font-size:0.85rem">No persisted signals yet. Open the Live tab on different dates so the engine can record signals; they will appear here once their horizon has elapsed.</div>';
        } else {
            feedEl.innerHTML = `<table class="risk-feed-table"><thead><tr>
                <th>As of</th><th>Domain</th><th>Severity</th><th>Title</th><th>Horizon</th><th>Conf.</th><th>Verdict</th><th>Outcome</th>
            </tr></thead><tbody>${feed.map(s => {
                const verdict = s.verdict || 'pending';
                const conf = s.confidence != null ? Math.round(s.confidence * 100) + '%' : '—';
                return `<tr class="verdict-${verdict}">
                    <td>${esc(s.as_of_date || '')}</td>
                    <td>${esc(RISK_DOMAIN_LABELS[s.domain] || s.domain || '')}</td>
                    <td><span class="risk-level-badge risk-lvl-${s.severity || 'low'}">${(s.severity || 'low').toUpperCase()}</span></td>
                    <td>${esc(s.title || '')}</td>
                    <td>${s.horizon_days || '—'}d</td>
                    <td>${conf}</td>
                    <td><span class="risk-verdict-badge ${verdict}">${verdict.replace('_', ' ')}</span></td>
                    <td class="feed-detail">${esc(s.outcome_summary || '—')}</td>
                </tr>`;
            }).join('')}</tbody></table>`;
        }
    }
}

function drawCalibrationChart(canvas, bins) {
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const fixedH = 240;
    let w = canvas.clientWidth || canvas.parentElement?.clientWidth || 320;
    const h = fixedH;
    canvas.style.height = h + 'px';
    canvas.style.maxHeight = h + 'px';
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    const pad = { top: 18, right: 14, bottom: 30, left: 38 };
    const cw = w - pad.left - pad.right, ch = h - pad.top - pad.bottom;

    ctx.strokeStyle = 'rgba(148,163,184,0.12)'; ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
        const y = pad.top + ch - (ch * i / 4);
        ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(w - pad.right, y); ctx.stroke();
        ctx.fillStyle = '#94a3b8'; ctx.font = '10px Inter, sans-serif'; ctx.textAlign = 'right';
        ctx.fillText(`${(i*25)}%`, pad.left - 5, y + 3);
    }

    ctx.strokeStyle = 'rgba(148,163,184,0.45)'; ctx.lineWidth = 1; ctx.setLineDash([4, 3]);
    ctx.beginPath();
    ctx.moveTo(pad.left, pad.top + ch);
    ctx.lineTo(w - pad.right, pad.top);
    ctx.stroke();
    ctx.setLineDash([]);

    const points = bins.filter(b => b.observed != null && b.n > 0);
    points.forEach(b => {
        const x = pad.left + b.expected * cw;
        const y = pad.top + ch - b.observed * ch;
        const r = Math.min(11, 3 + Math.sqrt(b.n));
        ctx.fillStyle = 'rgba(168,85,247,0.85)';
        ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.fill();
        ctx.strokeStyle = 'rgba(168,85,247,0.4)';
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.fillStyle = '#e2e8f0';
        ctx.font = 'bold 10px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(String(b.n), x, y - r - 3);
    });

    ctx.fillStyle = '#94a3b8'; ctx.font = '11px Inter, sans-serif'; ctx.textAlign = 'center';
    ctx.fillText('Predicted confidence', pad.left + cw / 2, h - 8);
    ctx.save();
    ctx.translate(12, pad.top + ch / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText('Observed hit rate', 0, 0);
    ctx.restore();

    if (!points.length) {
        ctx.fillStyle = '#64748b'; ctx.font = '12px Inter, sans-serif'; ctx.textAlign = 'center';
        ctx.fillText('No evaluated signals yet — run the engine over time to populate.', pad.left + cw / 2, pad.top + ch / 2);
    }
}

async function loadPersonnel(view = 'present') {
    const d = getSliderDate();
    const personnelDateEl = $('#personnel-date-label');
    if (personnelDateEl) personnelDateEl.textContent = formatHeadcountDate(d) ? ` (${formatHeadcountDate(d)})` : '';
    const list = $('#personnel-list');
    list.innerHTML = '<div class="spinner"></div>';

    const sess = _sliderSession === 'PM' ? 'EV' : 'AM';
    const filterParams = getDashFilterParams();
    let url = `${view === 'present' ? '/headcount/detail' : '/headcount/missing'}?date=${d}&session=${sess}` + (filterParams ? '&' + filterParams : '');

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
// TRENDS (line chart + weather + insights)
// ============================================================
let _trendsInited = false;

const AREA_COORDS = {
    'BAB':              { lat: 23.67, lon: 54.07, label: 'Bab field' },
    'NEB':              { lat: 23.53, lon: 54.15, label: 'North-East Bab' },
    'BAB MP':           { lat: 23.65, lon: 54.10, label: 'Bab MP' },
    'Buhasa':           { lat: 23.45, lon: 53.52, label: 'Bu Hasa field' },
    'BUIFDP (Buhasa)':  { lat: 23.45, lon: 53.52, label: 'Bu Hasa IFDP' },
    'BUHASA MP':        { lat: 23.45, lon: 53.52, label: 'Bu Hasa MP' },
    'Asab/Sahil':       { lat: 23.32, lon: 53.77, label: 'Asab / Sahil field' },
    'SQM':              { lat: 23.83, lon: 53.68, label: 'Shah / Qusahwira / Mender' },
    'SHAH':             { lat: 23.83, lon: 53.55, label: 'Shah gas field' },
    'QW':               { lat: 23.88, lon: 53.65, label: 'Qusahwira' },
    'MN':               { lat: 23.78, lon: 53.70, label: 'Mender' },
    'GAS':              { lat: 24.08, lon: 53.75, label: 'ADNOC Gas fields' },
    'GAS (ASAB)':       { lat: 23.32, lon: 53.75, label: 'Gas – Asab' },
    'GAS (BAB)':        { lat: 23.67, lon: 54.05, label: 'Gas – Bab' },
    'TPO':              { lat: 24.18, lon: 52.58, label: 'Terminal & Pipeline Ops' },
    'GAS/TPO':          { lat: 24.10, lon: 53.10, label: 'Gas / TPO combined' },
    'WEP':              { lat: 24.05, lon: 53.20, label: 'West-to-East Pipeline' },
    'FUJ':              { lat: 25.13, lon: 56.33, label: 'Fujairah' },
    'IPS':              { lat: 24.45, lon: 54.65, label: 'Industrial Park – Abu Dhabi' },
    'JD':               { lat: 24.18, lon: 52.58, label: 'Jebel Dhanna' },
    'MPS':              { lat: 24.42, lon: 54.43, label: 'Musaffah' },
    '_default':         { lat: 23.65, lon: 54.35, label: 'Abu Dhabi onshore region' },
};

async function initTrends() {
    if (!_trendsInited) {
        _trendsInited = true;

    const td = $('#trend-division'), ta = $('#trend-area'), tp = $('#trend-project'), tc = $('#trend-contractor');
    const [divs, allAreas] = await Promise.all([api('/divisions'), api('/areas')]);
    if (Array.isArray(divs)) td.innerHTML = '<option value="">All Divisions</option>' + divs.map(d => `<option value="${d.id}">${esc(d.name)}</option>`).join('');
    if (Array.isArray(allAreas)) ta.innerHTML = '<option value="">All Areas</option>' + allAreas.map(a => `<option value="${a.id}" data-name="${esc(a.name)}">${esc(a.name)}</option>`).join('');

    td.addEventListener('change', async () => {
        ta.innerHTML = '<option value="">All Areas</option>';
        tp.innerHTML = '<option value="">All Projects</option>';
        tc.innerHTML = '<option value="">All Contractors</option>';
        if (td.value) {
            const areas = await api(`/areas?division_id=${td.value}`);
            if (Array.isArray(areas)) ta.innerHTML = '<option value="">All Areas</option>' + areas.map(a => `<option value="${a.id}" data-name="${esc(a.name)}">${esc(a.name)}</option>`).join('');
            const projs = await api(`/projects?division_id=${td.value}`);
            if (Array.isArray(projs)) tp.innerHTML = '<option value="">All Projects</option>' + projs.map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join('');
        } else if (Array.isArray(allAreas)) {
            ta.innerHTML = '<option value="">All Areas</option>' + allAreas.map(a => `<option value="${a.id}" data-name="${esc(a.name)}">${esc(a.name)}</option>`).join('');
        }
        loadTrends();
    });
    ta?.addEventListener('change', async () => {
        tc.innerHTML = '<option value="">All Contractors</option>';
        tp.innerHTML = '<option value="">All Projects</option>';
        if (ta.value) await loadProjects(tp, true, ta.value, null);
        const params = getTrendFilterParams();
        const ctrs = await api('/contractors' + (params ? '?' + params : ''));
        if (Array.isArray(ctrs)) tc.innerHTML = '<option value="">All Contractors</option>' + ctrs.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join('');
        loadTrends();
    });
    tp?.addEventListener('change', loadTrends);
    tc?.addEventListener('change', loadTrends);

    _tabSliders.trends = initTabSlider($('#trend-date-slider'), loadTrends);

    const changeEls = ['trend-designation', 'trend-nationality'];
    changeEls.forEach(id => $('#' + id)?.addEventListener('change', loadTrends));
    }
    await loadTrends();
}

function getTrendFilterParams() {
    const parts = [];
    const div = $('#trend-division')?.value;
    const area = $('#trend-area')?.value;
    const proj = $('#trend-project')?.value;
    const ctr = $('#trend-contractor')?.value;
    if (proj) parts.push(`project_id=${proj}`);
    else if (area) parts.push(`area_id=${area}`);
    else if (div) parts.push(`division_id=${div}`);
    if (ctr) parts.push(`subcontractor=${encodeURIComponent(ctr)}`);
    return parts.join('&');
}

function getSelectedAreaName() {
    const sel = $('#trend-area');
    if (!sel || !sel.value) return null;
    const opt = sel.options[sel.selectedIndex];
    return opt?.dataset?.name || opt?.textContent || null;
}

function generateDummyTrend(numDays) {
    const labels = [], values = [];
    const total = 350;
    const today = new Date();
    for (let i = numDays - 1; i >= 0; i--) {
        const d = new Date(today); d.setDate(d.getDate() - i);
        labels.push(d.toISOString().split('T')[0]);
        const base = 270 + Math.round(Math.random() * 60);
        const weekend = (d.getDay() === 5 || d.getDay() === 6) ? -Math.round(Math.random() * 80) : 0;
        const weather = Math.random() < 0.1 ? -Math.round(Math.random() * 100) : 0;
        values.push(Math.max(50, Math.min(total, base + weekend + weather)));
    }
    return {
        labels, values, total,
        designations: ['Engineer', 'Foreman', 'Technician', 'Welder', 'Electrician', 'Pipefitter', 'Rigger', 'Safety Officer'],
        nationalities: ['Indian', 'Pakistani', 'Filipino', 'Bangladeshi', 'Egyptian', 'Omani', 'Emirati']
    };
}

async function loadTrends() {
    const ts = _tabSliders.trends;
    const numDays = 30;
    const params = new URLSearchParams();
    const fp = getTrendFilterParams();
    if (fp) fp.split('&').forEach(p => { const [k, v] = p.split('='); params.set(k, v); });
    const sess = ts ? (ts.getSession() === 'PM' ? 'EV' : 'AM') : 'AM';
    const desig = $('#trend-designation')?.value;
    const nat = $('#trend-nationality')?.value;
    if (sess) params.set('session', sess);
    if (desig) params.set('designation', desig);
    if (nat) params.set('nationality', nat);
    params.set('days', numDays);
    const data = await api('/trends?' + params.toString());
    if (!data || !data.labels) return;

    const dSel = $('#trend-designation'), nSel = $('#trend-nationality');
    if (data.designations) { const c = dSel.value; dSel.innerHTML = '<option value="">All Designations</option>' + data.designations.map(d => `<option value="${esc(d)}">${esc(d)}</option>`).join(''); dSel.value = c; }
    if (data.nationalities) { const c = nSel.value; nSel.innerHTML = '<option value="">All Nationalities</option>' + data.nationalities.map(n => `<option value="${esc(n)}">${esc(n)}</option>`).join(''); nSel.value = c; }

    drawLineChart($('#trend-chart'), data.labels, data.values, data.total);
    renderInsights(data);
    renderBreakdown(data);
    loadWeather(data.labels);
}

function renderInsights(data) {
    const el = $('#trend-insights');
    if (!el || !data.labels.length) { if (el) el.innerHTML = ''; return; }
    const vals = data.values, total = data.total || 1, n = vals.length;
    const sum = vals.reduce((a, b) => a + b, 0);
    const avgAtt = n > 0 ? sum / n : 0;
    const avgPct = Math.round((avgAtt / total) * 100);
    const peakVal = Math.max(...vals);
    const peakIdx = vals.indexOf(peakVal);
    const lowVal = Math.min(...vals);
    const lowIdx = vals.indexOf(lowVal);
    const weekdayVals = [], weekendVals = [];
    data.labels.forEach((l, i) => { const dow = new Date(l).getDay(); (dow === 5 || dow === 6) ? weekendVals.push(vals[i]) : weekdayVals.push(vals[i]); });
    const avgWeekday = weekdayVals.length ? Math.round(weekdayVals.reduce((a, b) => a + b, 0) / weekdayVals.length) : 0;
    const avgWeekend = weekendVals.length ? Math.round(weekendVals.reduce((a, b) => a + b, 0) / weekendVals.length) : 0;
    const weekendDrop = avgWeekday > 0 ? Math.round(((avgWeekday - avgWeekend) / avgWeekday) * 100) : 0;
    const trend7 = n >= 7 ? vals.slice(-7) : vals;
    const recent = trend7.reduce((a, b) => a + b, 0) / trend7.length;
    const older = n > 7 ? vals.slice(0, -7).reduce((a, b) => a + b, 0) / (n - 7) : recent;
    const momentum = older > 0 ? Math.round(((recent - older) / older) * 100) : 0;

    el.innerHTML = `
        <div class="stat-card"><div class="stat-value green">${avgPct}%</div><div class="stat-label">Avg Attendance</div></div>
        <div class="stat-card"><div class="stat-value blue">${Math.round(avgAtt)}</div><div class="stat-label">Avg Present / Day</div></div>
        <div class="stat-card"><div class="stat-value teal">${peakVal}</div><div class="stat-label">Peak Day<br><small>${formatHeadcountDate(data.labels[peakIdx])}</small></div></div>
        <div class="stat-card"><div class="stat-value orange">${lowVal}</div><div class="stat-label">Lowest Day<br><small>${formatHeadcountDate(data.labels[lowIdx])}</small></div></div>
        <div class="stat-card"><div class="stat-value purple">${weekendDrop > 0 ? '-' : ''}${weekendDrop}%</div><div class="stat-label">Fri-Sat Drop</div></div>
        <div class="stat-card"><div class="stat-value" style="color:${momentum >= 0 ? '#22c55e' : '#ef4444'}">${momentum > 0 ? '+' : ''}${momentum}%</div><div class="stat-label">7-Day Momentum</div></div>`;
}

function renderBreakdown(data) {
    const bd = $('#trend-breakdown');
    if (!bd || !data.labels.length) return;
    bd.innerHTML = `<table class="worker-table"><thead><tr><th>Date</th><th>Day</th><th>Present</th><th>Total</th><th>%</th><th>Trend</th></tr></thead><tbody>` +
        data.labels.map((d, i) => {
            const v = data.values[i], total = data.total || 1;
            const pct = Math.round((v / total) * 100);
            const dow = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][new Date(d).getDay()];
            const isWE = new Date(d).getDay() === 5 || new Date(d).getDay() === 6;
            const prev = i > 0 ? data.values[i - 1] : v;
            const arrow = v > prev ? '↑' : v < prev ? '↓' : '→';
            const arrowColor = v > prev ? '#22c55e' : v < prev ? '#ef4444' : '#94a3b8';
            return `<tr style="${isWE ? 'background:rgba(234,179,8,0.05)' : ''}">
                <td>${formatHeadcountDate(d)}</td><td>${dow}</td><td><strong>${v}</strong></td><td>${total}</td><td>${pct}%</td>
                <td style="color:${arrowColor};font-weight:600">${arrow} ${v - prev >= 0 ? '+' : ''}${v - prev}</td></tr>`;
        }).join('') + '</tbody></table>';
}

function getWeatherCoords() {
    const areaName = getSelectedAreaName();
    if (areaName && AREA_COORDS[areaName]) return AREA_COORDS[areaName];
    return AREA_COORDS['_default'];
}

async function loadWeather(labels) {
    const cards = $('#weather-cards'), canvas = $('#weather-chart'), locLabel = $('#weather-location-label');
    if (!cards || !canvas || !labels || !labels.length) return;
    cards.innerHTML = '<div class="spinner"></div>';

    const coords = getWeatherCoords();
    if (locLabel) locLabel.textContent = `${coords.label} (${coords.lat.toFixed(2)}°N, ${coords.lon.toFixed(2)}°E) — Open-Meteo`;

    const start = labels[0], end = labels[labels.length - 1];
    const url = `https://historical-forecast-api.open-meteo.com/v1/forecast?latitude=${coords.lat}&longitude=${coords.lon}` +
        `&start_date=${start}&end_date=${end}` +
        `&daily=temperature_2m_max,temperature_2m_min,wind_speed_10m_max,precipitation_sum,relative_humidity_2m_max` +
        `&timezone=Asia%2FDubai`;

    try {
        const resp = await fetch(url);
        const w = await resp.json();
        if (!w.daily || !w.daily.time) throw new Error('No weather data');

        const d = w.daily;
        const temps = d.temperature_2m_max || [];
        const winds = d.wind_speed_10m_max || [];
        const humid = d.relative_humidity_2m_max || [];
        const rain = d.precipitation_sum || [];
        const minTemps = d.temperature_2m_min || [];

        const avg = arr => arr.filter(v => v != null).reduce((a, b) => a + b, 0) / (arr.filter(v => v != null).length || 1);
        const avgTemp = avg(temps), maxWind = Math.max(...winds.filter(v => v != null), 0);
        const avgHumid = avg(humid), totalRain = rain.reduce((a, b) => a + (b || 0), 0);
        const maxTemp = Math.max(...temps.filter(v => v != null), 0);
        const minTemp = Math.min(...minTemps.filter(v => v != null), 99);

        let warn = '';
        if (maxWind > 40) warn += `High wind: ${maxWind.toFixed(0)} km/h. `;
        if (maxTemp > 45) warn += `Extreme heat: ${maxTemp.toFixed(0)}°C. `;
        if (totalRain > 5) warn += `Rainfall: ${totalRain.toFixed(1)} mm. `;

        cards.innerHTML = (warn ? `<div class="weather-warn" style="grid-column:1/-1">⚠ ${warn}Possible work stoppages.</div>` : '') +
            `<div class="stat-card"><div class="stat-value" style="color:#f59e0b">${avgTemp.toFixed(1)}°C</div><div class="stat-label">Avg High</div></div>
            <div class="stat-card"><div class="stat-value" style="color:#38bdf8">${minTemp.toFixed(1)}°C</div><div class="stat-label">Min Low</div></div>
            <div class="stat-card"><div class="stat-value" style="color:#06b6d4">${avgHumid.toFixed(0)}%</div><div class="stat-label">Avg Humidity</div></div>
            <div class="stat-card"><div class="stat-value" style="color:#8b5cf6">${maxWind.toFixed(0)} km/h</div><div class="stat-label">Max Wind</div></div>
            <div class="stat-card"><div class="stat-value" style="color:#3b82f6">${totalRain.toFixed(1)} mm</div><div class="stat-label">Rainfall</div></div>
            <div class="stat-card"><div class="stat-value" style="color:#ef4444">${maxTemp.toFixed(0)}°C</div><div class="stat-label">Peak Temp</div></div>`;

        drawWeatherChart(canvas, d.time, temps, winds, humid);
    } catch (e) {
        cards.innerHTML = `<div class="empty-state">Weather unavailable (${e.message})</div>`;
        const ctx = canvas.getContext('2d'); ctx.clearRect(0, 0, canvas.width, canvas.height);
    }
}

function drawWeatherChart(canvas, dates, temps, winds, humidity) {
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth, h = canvas.clientHeight;
    canvas.width = w * dpr; canvas.height = h * dpr;
    ctx.scale(dpr, dpr); ctx.clearRect(0, 0, w, h);
    if (!dates || !dates.length) return;

    const pad = { top: 30, right: 50, bottom: 40, left: 50 };
    const cw = w - pad.left - pad.right, ch = h - pad.top - pad.bottom;
    const n = dates.length, stepX = n > 1 ? cw / (n - 1) : cw;
    const allVals = [...(temps || []), ...(winds || []), ...(humidity || [])].filter(v => v != null);
    const maxV = Math.max(...allVals, 1);

    ctx.strokeStyle = 'rgba(148,163,184,0.12)'; ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
        const y = pad.top + ch - (ch * i / 4);
        ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(w - pad.right, y); ctx.stroke();
        ctx.fillStyle = '#94a3b8'; ctx.font = '10px Inter, sans-serif'; ctx.textAlign = 'right';
        ctx.fillText(Math.round(maxV * i / 4), pad.left - 6, y + 3);
    }
    function drawLine(data, color, dash) {
        if (!data) return;
        ctx.setLineDash(dash || []); ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.lineJoin = 'round';
        ctx.beginPath();
        data.forEach((v, i) => { if (v == null) return; const x = pad.left + i * stepX, y = pad.top + ch - (ch * v / maxV); i === 0 || data[i - 1] == null ? ctx.moveTo(x, y) : ctx.lineTo(x, y); });
        ctx.stroke(); ctx.setLineDash([]);
    }
    drawLine(temps, '#f59e0b'); drawLine(winds, '#8b5cf6', [4, 3]); drawLine(humidity, '#06b6d4', [2, 2]);

    ctx.fillStyle = '#94a3b8'; ctx.font = '10px Inter, sans-serif'; ctx.textAlign = 'center';
    const step = Math.max(1, Math.floor(n / 7));
    dates.forEach((d, i) => { if (i % step === 0 || i === n - 1) { const x = pad.left + i * stepX; const parts = d.split('-'); ctx.fillText(`${parts[2]}/${parts[1]}`, x, h - pad.bottom + 14); } });

    const legend = [['Temp °C', '#f59e0b'], ['Wind km/h', '#8b5cf6'], ['Humidity %', '#06b6d4']];
    let lx = pad.left; ctx.font = '11px Inter, sans-serif';
    legend.forEach(([label, color]) => { ctx.fillStyle = color; ctx.fillRect(lx, 6, 14, 3); ctx.fillStyle = '#94a3b8'; ctx.textAlign = 'left'; ctx.fillText(label, lx + 18, 12); lx += ctx.measureText(label).width + 34; });
}

function drawLineChart(canvas, labels, values, total) {
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth, h = canvas.clientHeight;
    canvas.width = w * dpr; canvas.height = h * dpr;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    if (!values.length) { ctx.fillStyle = '#8b8aa6'; ctx.font = '14px Inter, sans-serif'; ctx.fillText('No data', w/2 - 25, h/2); return; }

    const pad = { top: 30, right: 20, bottom: 48, left: 50 };
    const cw = w - pad.left - pad.right, ch = h - pad.top - pad.bottom;
    const maxV = Math.max(...values, total || 1, 1);

    // Grid lines
    ctx.strokeStyle = 'rgba(148,163,184,0.15)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
        const y = pad.top + ch - (ch * i / 4);
        ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(w - pad.right, y); ctx.stroke();
        ctx.fillStyle = '#94a3b8'; ctx.font = '11px Inter, sans-serif'; ctx.textAlign = 'right';
        ctx.fillText(Math.round(maxV * i / 4), pad.left - 6, y + 4);
    }

    // Total line (dashed)
    if (total > 0) {
        const ty = pad.top + ch - (ch * total / maxV);
        ctx.setLineDash([4, 4]); ctx.strokeStyle = 'rgba(59,130,246,0.4)'; ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(pad.left, ty); ctx.lineTo(w - pad.right, ty); ctx.stroke();
        ctx.setLineDash([]); ctx.fillStyle = '#3b82f6'; ctx.font = '10px Inter, sans-serif'; ctx.textAlign = 'left';
        ctx.fillText(`Total: ${total}`, pad.left + 4, ty - 4);
    }

    // Line
    const stepX = values.length > 1 ? cw / (values.length - 1) : cw;
    ctx.strokeStyle = '#22c55e'; ctx.lineWidth = 2.5; ctx.lineJoin = 'round';
    ctx.beginPath();
    values.forEach((v, i) => {
        const x = pad.left + i * stepX;
        const y = pad.top + ch - (ch * v / maxV);
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();

    // Fill area
    const last = values.length - 1;
    ctx.lineTo(pad.left + last * stepX, pad.top + ch);
    ctx.lineTo(pad.left, pad.top + ch);
    ctx.closePath();
    ctx.fillStyle = 'rgba(34,197,94,0.1)'; ctx.fill();

    // Dots
    values.forEach((v, i) => {
        const x = pad.left + i * stepX;
        const y = pad.top + ch - (ch * v / maxV);
        ctx.beginPath(); ctx.arc(x, y, 3, 0, Math.PI * 2);
        ctx.fillStyle = '#22c55e'; ctx.fill();
    });

    // X labels — day number on top, month name as one word right below (less congestion)
    ctx.textAlign = 'center';
    const step = Math.max(1, Math.floor(labels.length / 7));
    const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    labels.forEach((l, i) => {
        if (i % step === 0 || i === labels.length - 1) {
            const x = pad.left + i * stepX;
            const parts = l.split('-');
            const day = parts[2] ? parseInt(parts[2], 10) : 0;
            const monthIdx = parts[1] ? parseInt(parts[1], 10) - 1 : 0;
            const monthName = MONTHS[Math.max(0, Math.min(11, monthIdx))] || '';
            ctx.fillStyle = '#cbcbe0';
            ctx.font = '600 11px Inter, sans-serif';
            ctx.fillText(String(day), x, h - pad.bottom + 14);
            ctx.fillStyle = '#8b8aa6';
            ctx.font = '10px Inter, sans-serif';
            ctx.fillText(monthName, x, h - pad.bottom + 28);
        }
    });
}

// ============================================================
// HEALTH TRENDS
// ============================================================

let _healthInited = false;

async function initHealthTrends() {
    if (!_healthInited) {
        _healthInited = true;

    const hd = $('#ht-division'), ha = $('#ht-area'), hp = $('#ht-project'), hc = $('#ht-contractor');
    const [divs, allAreas] = await Promise.all([api('/divisions'), api('/areas')]);
    if (Array.isArray(divs)) hd.innerHTML = '<option value="">All Divisions</option>' + divs.map(d => `<option value="${d.id}">${esc(d.name)}</option>`).join('');
    if (Array.isArray(allAreas)) ha.innerHTML = '<option value="">All Areas</option>' + allAreas.map(a => `<option value="${a.id}">${esc(a.name)}</option>`).join('');

    hd.addEventListener('change', async () => {
        ha.innerHTML = '<option value="">All Areas</option>';
        hp.innerHTML = '<option value="">All Projects</option>';
        hc.innerHTML = '<option value="">All Contractors</option>';
        if (hd.value) {
            const areas = await api(`/areas?division_id=${hd.value}`);
            if (Array.isArray(areas)) ha.innerHTML = '<option value="">All Areas</option>' + areas.map(a => `<option value="${a.id}">${esc(a.name)}</option>`).join('');
            const projs = await api(`/projects?division_id=${hd.value}`);
            if (Array.isArray(projs)) hp.innerHTML = '<option value="">All Projects</option>' + projs.map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join('');
        } else if (Array.isArray(allAreas)) {
            ha.innerHTML = '<option value="">All Areas</option>' + allAreas.map(a => `<option value="${a.id}">${esc(a.name)}</option>`).join('');
        }
        loadHealthTrends();
    });
    ha?.addEventListener('change', async () => {
        hc.innerHTML = '<option value="">All Contractors</option>';
        hp.innerHTML = '<option value="">All Projects</option>';
        if (ha.value) await loadProjects(hp, true, ha.value, null);
        const p = getHTFilterParams();
        const ctrs = await api('/contractors' + (p ? '?' + p : ''));
        if (Array.isArray(ctrs)) hc.innerHTML = '<option value="">All Contractors</option>' + ctrs.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join('');
        loadHealthTrends();
    });
    hp?.addEventListener('change', loadHealthTrends);
    hc?.addEventListener('change', loadHealthTrends);

    _tabSliders.health = initTabSlider($('#ht-date-slider'), loadHealthTrends);

    }
    await loadHealthTrends();
}

function getHTFilterParams() {
    const parts = [];
    const div = $('#ht-division')?.value;
    const area = $('#ht-area')?.value;
    const proj = $('#ht-project')?.value;
    const ctr = $('#ht-contractor')?.value;
    if (proj) parts.push(`project_id=${proj}`);
    else if (area) parts.push(`area_id=${area}`);
    else if (div) parts.push(`division_id=${div}`);
    if (ctr) parts.push(`subcontractor=${encodeURIComponent(ctr)}`);
    return parts.join('&');
}

function generateDemoHealth() {
    const total = 420;
    const fit = 310, unfit = 18, no_result = total - fit - unfit;
    const overdue = 34;
    const has_chronic = 47, treated = 38, untreated = 9;
    const good = 340, bad = 22, neutral = total - good - bad;
    return {
        total,
        medical: { fit, unfit, no_result, overdue },
        chronic: { has_chronic, treated, untreated },
        feeling: { good, bad, neutral },
        medical_freq: [
            { label: '1 Year', count: 180 }, { label: '2 Years', count: 140 }, { label: '3 Years', count: 65 }, { label: 'N/A', count: 35 }
        ],
        chronic_types: [
            { label: 'Diabetes', count: 18 }, { label: 'Hypertension', count: 12 },
            { label: 'Cholesterol', count: 8 }, { label: 'Asthma', count: 5 },
            { label: 'Back Pain (Chronic)', count: 4 }
        ],
        risk_people: [
            { name: 'Ali Ahmed Khan', employee_no: 'CTR-1042', designation: 'Welder', nationality: 'Pakistani', project_name: 'BFN P11643', medical_result: 'UNFIT', next_medical_due: '2025-11-30', chronic_condition: 'Diabetes', chronic_treated: 'Yes', general_feeling: 'Tired' },
            { name: 'Raju Sharma', employee_no: 'CTR-2108', designation: 'Pipefitter', nationality: 'Indian', project_name: 'Wave C3B', medical_result: 'Fit', next_medical_due: '2025-09-15', chronic_condition: '', chronic_treated: '', general_feeling: 'Poor' },
            { name: 'Mohammed Hasan', employee_no: 'CTR-3055', designation: 'Electrician', nationality: 'Bangladeshi', project_name: 'BFN P11643', medical_result: 'UNFIT', next_medical_due: '2026-04-01', chronic_condition: 'Hypertension', chronic_treated: 'No', general_feeling: 'Unwell' },
            { name: 'Jose Santos', employee_no: 'CTR-4221', designation: 'Rigger', nationality: 'Filipino', project_name: 'BFN P11643', medical_result: 'Fit', next_medical_due: '2025-12-10', chronic_condition: 'Cholesterol', chronic_treated: 'Yes - Under Control', general_feeling: 'Good' },
            { name: 'Ahmad Faisal', employee_no: 'CTR-5099', designation: 'Foreman', nationality: 'Egyptian', project_name: 'Wave C3B', medical_result: 'UNFIT', next_medical_due: '2026-01-20', chronic_condition: 'Asthma', chronic_treated: 'No', general_feeling: 'Sick' },
            { name: 'Suresh Patel', employee_no: 'CTR-6317', designation: 'Technician', nationality: 'Indian', project_name: 'BFN P11643', medical_result: 'Fit', next_medical_due: '2025-10-01', chronic_condition: 'Back Pain (Chronic)', chronic_treated: 'Yes', general_feeling: 'Fine' },
        ]
    };
}

function riskLevel(person) {
    const today = new Date().toISOString().split('T')[0];
    let score = 0;
    const mr = (person.medical_result || '').toLowerCase();
    if (mr.includes('unfit')) score += 3;
    if (person.next_medical_due && person.next_medical_due < today) score += 2;
    const cc = (person.chronic_condition || '').toLowerCase();
    if (cc && !cc.includes('nil') && !cc.includes('none') && cc !== 'no' && cc !== 'n/a') {
        score += 1;
        const ct = (person.chronic_treated || '').toLowerCase();
        if (!ct.includes('yes') && !ct.includes('control')) score += 2;
    }
    const gf = (person.general_feeling || '').toLowerCase();
    if (gf.includes('bad') || gf.includes('poor') || gf.includes('sick') || gf.includes('unwell') || gf.includes('tired')) score += 1;
    if (score >= 5) return { label: 'Critical', color: '#dc2626', bg: 'rgba(220,38,38,0.12)', cls: 'risk-critical' };
    if (score >= 3) return { label: 'High', color: '#ea580c', bg: 'rgba(234,88,12,0.10)', cls: 'risk-high' };
    if (score >= 2) return { label: 'Medium', color: '#d97706', bg: 'rgba(217,119,6,0.08)', cls: 'risk-medium' };
    return { label: 'Low', color: '#16a34a', bg: 'rgba(22,163,74,0.06)', cls: 'risk-low' };
}

async function loadHealthTrends() {
    const p = getHTFilterParams();
    const data = await api('/health-trends' + (p ? '?' + p : ''));
    if (!data || data.success === false || !data.medical) {
        if (data && data.message) {
            toast(data.message, 'error');
            console.error('health-trends error:', data);
        }
        return;
    }
    renderHealthOverview(data);
    renderMedicalSection(data);
    renderChronicSection(data);
    renderRiskTable(data);
}

function pct(n, t) { return t > 0 ? Math.round((n / t) * 100) : 0; }

function renderHealthOverview(data) {
    const el = $('#ht-risk-overview');
    if (!el) return;
    const t = data.total || 1;
    const m = data.medical, c = data.chronic, f = data.feeling;
    const fitPct = pct(m.fit, t), overduePct = pct(m.overdue, t);
    const chronicPct = pct(c.has_chronic, t), unfitPct = pct(m.unfit, t);
    const wellPct = pct(f.good, t), unwellPct = pct(f.bad, t);

    const riskScore = Math.min(100, Math.round((m.unfit * 4 + m.overdue * 2 + c.untreated * 3 + f.bad * 1.5) / Math.max(t, 1) * 100));
    let overallColor = '#16a34a', overallLabel = 'Low Risk';
    if (riskScore >= 15) { overallColor = '#dc2626'; overallLabel = 'Critical'; }
    else if (riskScore >= 8) { overallColor = '#ea580c'; overallLabel = 'High Risk'; }
    else if (riskScore >= 3) { overallColor = '#d97706'; overallLabel = 'Moderate'; }

    el.innerHTML = `
        <div class="stat-card risk-card" style="border-left:4px solid ${overallColor}">
            <div class="stat-value" style="color:${overallColor}">${overallLabel}</div>
            <div class="stat-label">Overall Health Risk<br><small>Score: ${riskScore}/100</small></div>
        </div>
        <div class="stat-card"><div class="stat-value" style="color:#16a34a">${fitPct}%</div><div class="stat-label">Medically Fit<br><small>${m.fit} / ${t}</small></div></div>
        <div class="stat-card"><div class="stat-value" style="color:#dc2626">${m.unfit}</div><div class="stat-label">Unfit Personnel<br><small>${unfitPct}%</small></div></div>
        <div class="stat-card"><div class="stat-value" style="color:#ea580c">${m.overdue}</div><div class="stat-label">Medical Overdue<br><small>${overduePct}%</small></div></div>
        <div class="stat-card"><div class="stat-value" style="color:#d97706">${c.has_chronic}</div><div class="stat-label">Chronic Conditions<br><small>${chronicPct}%</small></div></div>
        <div class="stat-card"><div class="stat-value" style="color:#3b82f6">${wellPct}%</div><div class="stat-label">Feeling Well<br><small>${f.good} / ${t}</small></div></div>`;
}

function renderMedicalSection(data) {
    const cards = $('#ht-medical-cards'), canvas = $('#ht-medical-chart');
    if (!cards) return;
    const m = data.medical, t = data.total || 1;

    cards.innerHTML = `
        <div class="stat-card"><div class="stat-value" style="color:#16a34a">${m.fit}</div><div class="stat-label">Fit to Work</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#dc2626">${m.unfit}</div><div class="stat-label">Unfit</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#94a3b8">${m.no_result}</div><div class="stat-label">No Result</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#ea580c">${m.overdue}</div><div class="stat-label">Overdue Medical</div></div>`;

    if (data.medical_freq && data.medical_freq.length) {
        cards.innerHTML += data.medical_freq.map(f =>
            `<div class="stat-card"><div class="stat-value" style="color:#6366f1">${f.count}</div><div class="stat-label">${esc(f.label)} Cycle</div></div>`
        ).join('');
    }

    if (canvas) {
        const tryDraw = (attempt = 0) => {
            if (canvas.clientWidth > 0 || attempt >= 12) drawMedicalChart(canvas, data);
            else requestAnimationFrame(() => tryDraw(attempt + 1));
        };
        requestAnimationFrame(() => tryDraw(0));
    }
}

function drawMedicalChart(canvas, data) {
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const fixedH = 260;
    let w = canvas.clientWidth;
    if (w <= 0) w = canvas.parentElement?.clientWidth || 480;
    const h = fixedH;
    canvas.style.height = h + 'px';
    canvas.style.maxHeight = h + 'px';
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    const m = data.medical, t = data.total || 1;
    const bars = [
        { label: 'Fit', value: m.fit, color: '#16a34a' },
        { label: 'Unfit', value: m.unfit, color: '#dc2626' },
        { label: 'No Result', value: m.no_result, color: '#94a3b8' },
        { label: 'Overdue', value: m.overdue, color: '#ea580c' },
    ];
    const pad = { top: 30, right: 20, bottom: 50, left: 60 };
    const cw = w - pad.left - pad.right, ch = h - pad.top - pad.bottom;
    const maxV = Math.max(...bars.map(b => b.value), 1);
    const barW = Math.min(60, cw / bars.length * 0.6);
    const gap = (cw - barW * bars.length) / (bars.length + 1);

    ctx.strokeStyle = 'rgba(148,163,184,0.12)'; ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
        const y = pad.top + ch - (ch * i / 4);
        ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(w - pad.right, y); ctx.stroke();
        ctx.fillStyle = '#94a3b8'; ctx.font = '11px Inter, sans-serif'; ctx.textAlign = 'right';
        ctx.fillText(Math.round(maxV * i / 4), pad.left - 8, y + 4);
    }

    bars.forEach((b, i) => {
        const x = pad.left + gap + i * (barW + gap);
        const barH = (b.value / maxV) * ch;
        const y = pad.top + ch - barH;
        ctx.fillStyle = b.color;
        ctx.beginPath();
        const r = 4;
        ctx.moveTo(x + r, y); ctx.lineTo(x + barW - r, y);
        ctx.quadraticCurveTo(x + barW, y, x + barW, y + r);
        ctx.lineTo(x + barW, pad.top + ch);
        ctx.lineTo(x, pad.top + ch);
        ctx.lineTo(x, y + r);
        ctx.quadraticCurveTo(x, y, x + r, y);
        ctx.fill();

        ctx.fillStyle = '#e2e8f0'; ctx.font = 'bold 12px Inter, sans-serif'; ctx.textAlign = 'center';
        ctx.fillText(b.value, x + barW / 2, y - 8);
        ctx.fillStyle = '#94a3b8'; ctx.font = '11px Inter, sans-serif';
        ctx.fillText(b.label, x + barW / 2, pad.top + ch + 18);
        ctx.fillStyle = '#64748b'; ctx.font = '10px Inter, sans-serif';
        ctx.fillText(`${pct(b.value, t)}%`, x + barW / 2, pad.top + ch + 34);
    });

    ctx.fillStyle = '#94a3b8'; ctx.font = '11px Inter, sans-serif'; ctx.textAlign = 'center';
    ctx.fillText('Medical Status Distribution', w / 2, 16);
}

function renderChronicSection(data) {
    const el = $('#ht-chronic-cards');
    if (!el) return;
    const c = data.chronic, f = data.feeling, t = data.total || 1;

    let html = `
        <div class="stat-card"><div class="stat-value" style="color:#d97706">${c.has_chronic}</div><div class="stat-label">With Chronic Condition</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#16a34a">${c.treated}</div><div class="stat-label">Treated / Controlled</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#dc2626">${c.untreated}</div><div class="stat-label">Untreated / Uncontrolled</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#22c55e">${f.good}</div><div class="stat-label">Feeling Good</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#ef4444">${f.bad}</div><div class="stat-label">Feeling Unwell</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#94a3b8">${f.neutral}</div><div class="stat-label">Not Reported</div></div>`;

    if (data.chronic_types && data.chronic_types.length) {
        html += '<div style="grid-column:1/-1;margin-top:8px"><h4 style="color:var(--text-dim);font-size:0.8rem;text-transform:uppercase;margin-bottom:8px">Top Conditions</h4><div class="ht-condition-list">';
        data.chronic_types.forEach(ct => {
            html += `<span class="ht-condition-tag">${esc(ct.label)} <strong>${ct.count}</strong></span>`;
        });
        html += '</div></div>';
    }
    el.innerHTML = html;
}

function renderRiskTable(data) {
    const el = $('#ht-risk-table');
    if (!el) return;
    const people = data.risk_people || [];
    if (!people.length) {
        el.innerHTML = '<div class="empty-state">No flagged personnel</div>';
        return;
    }
    const sorted = [...people].sort((a, b) => {
        const ra = riskLevel(a), rb = riskLevel(b);
        const order = { Critical: 0, High: 1, Medium: 2, Low: 3 };
        return (order[ra.label] ?? 9) - (order[rb.label] ?? 9);
    });
    el.innerHTML = `<table class="worker-table"><thead><tr>
        <th>Risk</th><th>Name</th><th>Employee No.</th><th>Designation</th><th>Nationality</th>
        <th>Project</th><th>Medical Result</th><th>Next Medical</th>
        <th>Chronic Condition</th><th>Treated?</th><th>Feeling</th>
        </tr></thead><tbody>` +
        sorted.map(p => {
            const r = riskLevel(p);
            const today = new Date().toISOString().split('T')[0];
            const overdue = p.next_medical_due && p.next_medical_due < today;
            return `<tr style="background:${r.bg}">
                <td><span class="risk-badge ${r.cls}">${r.label}</span></td>
                <td><strong>${esc(p.name)}</strong></td>
                <td>${esc(p.employee_no)}</td>
                <td>${esc(p.designation || '')}</td>
                <td>${esc(p.nationality || '')}</td>
                <td>${esc(p.project_name || '')}</td>
                <td style="color:${(p.medical_result||'').toLowerCase().includes('unfit') ? '#dc2626' : '#16a34a'};font-weight:600">${esc(p.medical_result || 'N/A')}</td>
                <td style="color:${overdue ? '#ea580c' : 'inherit'};font-weight:${overdue ? '600' : 'normal'}">${esc(p.next_medical_due || 'N/A')}${overdue ? ' ⚠' : ''}</td>
                <td>${esc(p.chronic_condition || '—')}</td>
                <td>${esc(p.chronic_treated || '—')}</td>
                <td>${esc(p.general_feeling || '—')}</td>
            </tr>`;
        }).join('') + '</tbody></table>';
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
    const roleLabels = { executive: 'Executive', admin: 'Admin', manager: 'HSE Manager', focal_point: 'Divisional Focal Point', scanner: 'Contractor Scanner' };
    const roleBadge = (role) => {
        const cls = { executive: 'badge-exec', admin: 'badge-danger', manager: 'badge-pm', project_manager: 'badge-pm', focal_point: 'badge-warning', scanner: 'badge-am', supervisor: 'badge-am', viewer: 'badge-warning' };
        const label = roleLabels[role] || String(role).replace('_', ' ');
        return `<span class="badge ${cls[role] || 'badge-warning'}">${esc(label)}</span>`;
    };
    ul.innerHTML = users.map((u, idx) => {
        const projAccess = (u.role === 'executive' || u.role === 'admin' || u.role === 'manager')
            ? '<em style="opacity:0.6">All</em>'
            : (u.role === 'focal_point')
                ? (u.divisions && u.divisions.length ? u.divisions.map(d => esc(d.name)).join(', ') : '<em style="color:var(--danger)">No division</em>')
                : (u.projects && u.projects.length ? u.projects.map(p => esc(p.name)).join(', ') : '<em style="color:var(--danger)">No project</em>');
        const contact = [u.email, u.designation].filter(Boolean).map(esc).join(' · ') || '';
        return `<div class="scan-item">
        <div>
            <div class="scan-item-name">${esc(u.display_name)} ${roleBadge(u.role)}
                ${u.totp_enabled ? '<span class="badge badge-2fa">2FA</span>' : ''}</div>
            <div class="scan-item-sub">@${esc(u.username)}${contact ? ' | ' + contact : ''} | ${projAccess} | Last: ${u.last_login ? new Date(u.last_login).toLocaleDateString() : 'never'}</div>
        </div>
        <div style="display:flex;gap:4px;flex-wrap:wrap">
            <button class="btn btn-sm btn-outline" data-action="access" data-idx="${idx}">Edit</button>
            <button class="btn btn-sm btn-outline" data-action="resetpin" data-id="${u.id}">Reset PIN</button>
            ${u.totp_enabled ? `<button class="btn btn-sm btn-outline" data-action="reset2fa" data-id="${u.id}">Reset 2FA</button>` : ''}
            <button class="btn btn-sm btn-danger" data-action="deleteuser" data-id="${u.id}" data-name="${esc(u.display_name)}">Delete</button>
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
        } else if (action === 'deleteuser') {
            const name = btn.dataset.name || '';
            if (!confirm(`Delete user "${name}"? This cannot be undone.`)) return;
            const res = await api(`/users/${id}`, { method: 'DELETE' });
            toast(res.success ? 'User deleted' : (res.message || 'Failed'), res.success ? 'success' : 'error');
            if (res.success) loadAdmin();
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

    const [divisions, projects] = await Promise.all([api('/divisions'), api('/projects')]);
    window._adminDivisions = Array.isArray(divisions) ? divisions : [];
    window._adminProjects = Array.isArray(projects) ? projects : [];
    const areaWrap = $('#new-user-areas');
    if (areaWrap && typeof fillNewUserAccess === 'function') fillNewUserAccess();

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

async function loadDivAreas() {
    const [divisions, areas] = await Promise.all([api('/divisions'), api('/areas')]);
    if (!Array.isArray(divisions)) return;
    const areasByDiv = {};
    (Array.isArray(areas) ? areas : []).forEach(a => {
        if (!areasByDiv[a.division_id]) areasByDiv[a.division_id] = [];
        areasByDiv[a.division_id].push(a);
    });

    const container = $('#div-area-list');
    if (!container) return;
    container.innerHTML = divisions.map(d => {
        const areasHtml = (areasByDiv[d.id] || []).map(a =>
            `<div class="da-area-row" style="display:flex;align-items:center;gap:6px;padding:4px 0 4px 24px;border-bottom:1px solid var(--border)">
                <span style="flex:1">${esc(a.name)}</span>
                <button class="btn btn-sm btn-outline" data-rename-area="${a.id}" data-current="${esc(a.name)}" title="Rename">Rename</button>
                <button class="btn btn-sm btn-danger" data-delete-area="${a.id}" data-name="${esc(a.name)}" title="Delete">×</button>
            </div>`).join('');
        return `<div class="da-div-block" style="margin-bottom:12px;border:1px solid var(--border);border-radius:var(--radius);overflow:hidden">
            <div style="display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--bg-card)">
                <strong style="flex:1">${esc(d.name)}</strong>
                <button class="btn btn-sm btn-outline" data-rename-div="${d.id}" data-current="${esc(d.name)}">Rename</button>
                <button class="btn btn-sm btn-danger" data-delete-div="${d.id}" data-name="${esc(d.name)}">×</button>
            </div>
            ${areasHtml || '<div style="padding:6px 12px 6px 24px;color:var(--text-dim);font-size:0.85rem">No areas</div>'}
        </div>`;
    }).join('') || '<div class="empty-state">No divisions</div>';

    container.onclick = async (e) => {
        const btn = e.target.closest('button');
        if (!btn) return;
        if (btn.dataset.renameDev || btn.dataset.renameDiv) {
            const id = btn.dataset.renameDiv;
            const cur = btn.dataset.current || '';
            const newName = prompt('Rename division:', cur);
            if (!newName || newName === cur) return;
            const res = await api(`/divisions/${id}`, { method: 'PUT', body: JSON.stringify({ name: newName }) });
            toast(res.success ? 'Division renamed' : (res.message || 'Failed'), res.success ? 'success' : 'error');
            if (res.success) loadDivAreas();
        } else if (btn.dataset.deleteDiv) {
            if (!confirm(`Delete division "${btn.dataset.name}"? Areas under it will also be hidden.`)) return;
            const res = await api(`/divisions/${btn.dataset.deleteDiv}`, { method: 'DELETE' });
            toast(res.success ? 'Division deleted' : (res.message || 'Failed'), res.success ? 'success' : 'error');
            if (res.success) loadDivAreas();
        } else if (btn.dataset.renameArea) {
            const id = btn.dataset.renameArea;
            const cur = btn.dataset.current || '';
            const newName = prompt('Rename area:', cur);
            if (!newName || newName === cur) return;
            const res = await api(`/areas/${id}`, { method: 'PUT', body: JSON.stringify({ name: newName }) });
            toast(res.success ? 'Area renamed' : (res.message || 'Failed'), res.success ? 'success' : 'error');
            if (res.success) loadDivAreas();
        } else if (btn.dataset.deleteArea) {
            if (!confirm(`Delete area "${btn.dataset.name}"?`)) return;
            const res = await api(`/areas/${btn.dataset.deleteArea}`, { method: 'DELETE' });
            toast(res.success ? 'Area deleted' : (res.message || 'Failed'), res.success ? 'success' : 'error');
            if (res.success) loadDivAreas();
        }
    };

    // Populate "Add Area" division dropdown
    const addAreaDiv = $('#new-area-div');
    if (addAreaDiv) {
        addAreaDiv.innerHTML = '<option value="">Select Division</option>' +
            divisions.map(d => `<option value="${d.id}">${esc(d.name)}</option>`).join('');
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
    const [divisions, projects] = await Promise.all([api('/divisions'), api('/projects')]);
    const user = _adminUsers.find(u => u.id === userId);
    const currentProjectIds = new Set((user?.projects || []).map(p => p.id));
    const currentDivisionIds = new Set((user?.divisions || []).map(d => d.id));
    const userEmail = (user && user.email) ? esc(user.email) : '';
    const userDesignation = (user && user.designation) ? esc(user.designation) : '';

    const isFocal = role === 'focal_point';
    const listHtml = isFocal && Array.isArray(divisions)
        ? divisions.map(d => `<label style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border)">
            <input type="checkbox" data-type="division" value="${d.id}" ${currentDivisionIds.has(d.id) ? 'checked' : ''}>
            <span>${esc(d.name)}</span></label>`).join('')
        : Array.isArray(projects)
            ? projects.map(p => `<label style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border)">
                <input type="checkbox" data-type="project" value="${p.id}" ${currentProjectIds.has(p.id) ? 'checked' : ''}>
                <span>${esc(p.name)} <span style="opacity:0.5">(${p.employee_count ?? 0})</span></span></label>`).join('')
            : '<p>No divisions/projects</p>';

    const modal = document.createElement('div');
    modal.className = 'overlay';
    const safeName = esc(name);
    modal.innerHTML = `<div class="overlay-content" style="max-width:420px">
        <h2>Access: ${safeName}</h2>
        <p style="color:var(--text-dim);margin-bottom:12px;font-size:0.85rem">
            ${(role === 'executive' || role === 'admin' || role === 'manager') ? 'This role sees all.' : (isFocal ? 'Select division(s) for Divisional Focal Point:' : 'Select project(s) for Contractor Scanner:')}
        </p>
        <div class="form-group">
            <label>Email</label>
            <input type="email" id="edit-email" class="input" value="${userEmail}" placeholder="Email">
        </div>
        <div class="form-group">
            <label>Designation</label>
            <input type="text" id="edit-designation" class="input" value="${userDesignation}" placeholder="e.g. Site Supervisor">
        </div>
        <div class="form-group">
            <label>Role</label>
            <select id="edit-role" class="input">
                <option value="scanner" ${role === 'scanner' ? 'selected' : ''}>Contractor Scanner</option>
                <option value="focal_point" ${role === 'focal_point' ? 'selected' : ''}>Divisional Focal Point</option>
                <option value="manager" ${role === 'manager' ? 'selected' : ''}>HSE Manager</option>
                <option value="admin" ${role === 'admin' ? 'selected' : ''}>Admin</option>
                <option value="executive" ${role === 'executive' ? 'selected' : ''}>Executive</option>
            </select>
        </div>
        <div id="access-checkboxes" style="max-height:200px;overflow-y:auto;margin-bottom:16px">${listHtml}</div>
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
        const projectCbs = modal.querySelectorAll('#access-checkboxes input[data-type="project"]:checked');
        const divisionCbs = modal.querySelectorAll('#access-checkboxes input[data-type="division"]:checked');
        const project_ids = [...projectCbs].map(cb => parseInt(cb.value));
        const division_ids = [...divisionCbs].map(cb => parseInt(cb.value));
        const body = { role: newRole, email, designation };
        if (newRole === 'focal_point') body.division_ids = division_ids;
        else body.project_ids = project_ids;
        await api(`/users/${userId}`, { method: 'PUT', body: JSON.stringify(body) });
        modal.remove();
        toast('User access updated', 'success');
        loadAdmin();
    });
}

function fillNewUserAccess() {
    const areaWrap = $('#new-user-areas');
    if (!areaWrap) return;
    const role = $('#new-userrole')?.value || 'scanner';
    const divisions = window._adminDivisions || [];
    const projects = window._adminProjects || [];
    if (role === 'focal_point' && divisions.length) {
        areaWrap.innerHTML = divisions.map(d => `<label class="area-check"><input type="checkbox" data-type="division" value="${d.id}"> ${esc(d.name)}</label>`).join('');
    } else if (role === 'scanner' && projects.length) {
        const grouped = {};
        projects.forEach(p => {
            const key = p.division_name ? `${p.division_name} / ${p.area_name || ''}` : (p.area_name || 'Other');
            if (!grouped[key]) grouped[key] = [];
            grouped[key].push(p);
        });
        areaWrap.innerHTML = Object.entries(grouped).map(([group, projs]) =>
            `<div style="margin-bottom:6px"><div style="font-weight:600;font-size:0.8rem;color:var(--text-dim);margin-bottom:2px">${esc(group)}</div>` +
            projs.map(p => `<label class="area-check" style="padding-left:12px"><input type="checkbox" data-type="project" value="${p.id}"> ${esc(p.name)} <span style="opacity:0.5">(${p.employee_count ?? 0})</span></label>`).join('') +
            '</div>'
        ).join('');
    }
}

async function loadScannerStatus() {
    const el = $('#scanner-status-list');
    if (!el) return;
    el.innerHTML = '<div class="spinner"></div>';
    const scanners = await api('/scanner-status');
    if (!Array.isArray(scanners) || !scanners.length) {
        el.innerHTML = '<div class="empty-state">No scanners registered yet</div>';
        return;
    }

    const today = new Date().toISOString().split('T')[0];
    const threeDaysAgo = new Date(Date.now() - 3 * 86400000).toISOString().split('T')[0];

    el.innerHTML = `<table class="scanner-status-table"><thead><tr>
        <th>Scanner</th><th>Email</th><th>Designation</th><th>Projects</th>
        <th>Approval</th><th>Scan Status</th><th>Security</th>
        <th>Today</th><th>Total</th><th>Days Active</th><th>Last Scan</th>
        </tr></thead><tbody>` +
        scanners.map(s => {
            const approvalOk = s.active === 1;
            const approvalBadge = approvalOk
                ? '<span class="scanner-badge sc-approved">Approved</span>'
                : '<span class="scanner-badge sc-suspended">Suspended</span>';

            let scanStatus, scanBadge;
            if (!s.last_scan) {
                scanStatus = 'never';
                scanBadge = '<span class="scanner-badge sc-inactive">Never Scanned</span>';
            } else if (s.last_scan.scan_date === today) {
                scanStatus = 'active';
                scanBadge = '<span class="scanner-badge sc-active">Active Today</span>';
            } else if (s.last_scan.scan_date >= threeDaysAgo) {
                scanStatus = 'recent';
                scanBadge = '<span class="scanner-badge sc-recent">Recent</span>';
            } else {
                scanStatus = 'idle';
                scanBadge = '<span class="scanner-badge sc-idle">Idle</span>';
            }

            let secBadge;
            if (s.locked_until) {
                secBadge = '<span class="scanner-badge sc-locked">Locked</span>';
            } else if (s.failed_attempts > 3) {
                secBadge = `<span class="scanner-badge sc-warning">Fails: ${s.failed_attempts}</span>`;
            } else {
                secBadge = '<span class="scanner-badge sc-secure">Secure</span>';
            }

            const projList = s.projects.map(p => `<span class="sc-proj-tag">${esc(p.area_name || '')} / ${esc(p.name)}</span>`).join(' ') || '<em style="opacity:0.5">None</em>';
            const lastScanStr = s.last_scan
                ? `${s.last_scan.scan_date} ${s.last_scan.session}`
                : '—';

            return `<tr>
                <td><strong>${esc(s.display_name)}</strong><br><small class="text-dim">${esc(s.username)}</small></td>
                <td>${esc(s.email || '—')}</td>
                <td>${esc(s.designation || '—')}</td>
                <td>${projList}</td>
                <td>${approvalBadge}</td>
                <td>${scanBadge}</td>
                <td>${secBadge}</td>
                <td style="text-align:center;font-weight:600">${s.today_scans}</td>
                <td style="text-align:center">${s.total_scans}</td>
                <td style="text-align:center">${s.days_active}</td>
                <td><small>${lastScanStr}</small></td>
            </tr>`;
        }).join('') + '</tbody></table>';
}

function initAdmin() {
    loadAdmin();
    loadDivAreas();
    loadScannerStatus();
    $('#btn-refresh-scanners')?.addEventListener('click', loadScannerStatus);

    const roleSelect = $('#new-userrole');
    const areaWrap = $('#new-user-areas');
    function toggleAreaAssign() {
        const r = roleSelect.value;
        if (areaWrap) {
            areaWrap.style.display = (r === 'scanner' || r === 'focal_point') ? 'block' : 'none';
            fillNewUserAccess();
        }
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
        if ((role === 'scanner' || role === 'focal_point') && !email) { toast('Email required for Contractor Scanner / Divisional Focal Point', 'error'); return; }
        if ((role === 'scanner' || role === 'focal_point') && !designation) { toast('Designation required for Contractor Scanner / Divisional Focal Point', 'error'); return; }
        let project_ids = [];
        let division_ids = [];
        if (role === 'scanner') {
            project_ids = Array.from(document.querySelectorAll('#new-user-areas input[data-type="project"]:checked')).map(cb => parseInt(cb.value));
            if (!project_ids.length) { toast('Select at least one project for Contractor Scanner', 'error'); return; }
        } else if (role === 'focal_point') {
            division_ids = Array.from(document.querySelectorAll('#new-user-areas input[data-type="division"]:checked')).map(cb => parseInt(cb.value));
            if (!division_ids.length) { toast('Select at least one division for Divisional Focal Point', 'error'); return; }
        }
        const res = await api('/users', { method: 'POST', body: JSON.stringify({ username, display_name, email, designation, pin: pin || '1234', role, project_ids, division_ids }) });
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

    // Add Division
    $('#btn-add-div')?.addEventListener('click', async () => {
        const name = $('#new-div-name')?.value.trim();
        if (!name) { toast('Enter a division name', 'error'); return; }
        const res = await api('/divisions', { method: 'POST', body: JSON.stringify({ name }) });
        toast(res.success ? 'Division added' : (res.message || 'Failed'), res.success ? 'success' : 'error');
        if (res.success) { $('#new-div-name').value = ''; loadDivAreas(); loadAdmin(); }
    });

    // Add Area
    $('#btn-add-area')?.addEventListener('click', async () => {
        const division_id = parseInt($('#new-area-div')?.value);
        const name = $('#new-area-name')?.value.trim();
        if (!division_id) { toast('Select a division first', 'error'); return; }
        if (!name) { toast('Enter an area name', 'error'); return; }
        const res = await api('/areas', { method: 'POST', body: JSON.stringify({ name, division_id }) });
        toast(res.success ? 'Area added' : (res.message || 'Failed'), res.success ? 'success' : 'error');
        if (res.success) { $('#new-area-name').value = ''; loadDivAreas(); }
    });
}

// ============================================================
// TABS
// ============================================================
let _dashInited = false;
let _workforceInited = false;
let _twlInited = false;

function initTabs() {
    let adminInit = false;
    $$('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            $$('.tab').forEach(t => t.classList.remove('active'));
            $$('.tab-content').forEach(c => c.classList.remove('active'));
            tab.classList.add('active');
            const target = tab.dataset.tab;
            $(`#tab-${target}`).classList.add('active');

            if (target === 'dashboard') {
                if (!_dashInited) { initDashFilters(); _dashInited = true; }
                refreshDashboard();
            }
            else if (target === 'workforce') { initWorkforceTab(); }
            else if (target === 'trends') { initTrends(); }
            else if (target === 'health') { initHealthTrends(); }
            else if (target === 'twl') { initTWLTab(); }
            else if (target === 'oi') { initOITab(); }
            else if (target === 'risk') { initRiskTab(); }
            else if (target === 'admin') { if (!adminInit) { initAdmin(); adminInit = true; } else loadAdmin(); }
            else if (target === 'scanner' && !state.scanning) startScanner();
        });
    });

    // Dashboard click-to-navigate on cards and charts
    document.addEventListener('click', (e) => {
        const card = e.target.closest('[data-navigate]');
        if (card) navigateToTab(card.dataset.navigate);
    });

    $('#dash-date')?.addEventListener('change', refreshDashboard);

    $$('.btn-toggle').forEach(btn => {
        btn.addEventListener('click', () => {
            $$('.btn-toggle').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            loadPersonnel(btn.dataset.view);
        });
    });

    let qrT;
    $('#qr-search')?.addEventListener('input', () => { clearTimeout(qrT); qrT = setTimeout(loadDashQRCodes, 300); });
    $('#btn-print-qr')?.addEventListener('click', () => window.print());
    $('#qr-project-filter')?.addEventListener('change', loadDashQRCodes);

    let workerT;
    $('#worker-search')?.addEventListener('input', () => {
        clearTimeout(workerT);
        workerT = setTimeout(() => {
            const s = ($('#worker-search').value || '').toLowerCase();
            const filtered = s ? _dashWorkers.filter(w => w.name.toLowerCase().includes(s) || w.employee_no.toLowerCase().includes(s)) : _dashWorkers;
            renderWorkerTable(filtered);
        }, 300);
    });

    $('#btn-export')?.addEventListener('click', async () => {
        const exportDate = getSliderDate();
        try {
            const { token: dlToken } = await api('/export/download-token', { method: 'POST' });
            let url = `/api/export/attendance?date=${exportDate}&dl_token=${dlToken}`;
            if ($('#dash-project')?.value) url += `&project_id=${$('#dash-project').value}`;
            window.open(url, '_blank');
        } catch (e) {
            toast('Export failed', 'error');
        }
    });
    $('#btn-export-roster')?.addEventListener('click', async () => {
        try {
            const { token: dlToken } = await api('/export/download-token', { method: 'POST' });
            let url = `/api/export/roster?dl_token=${dlToken}`;
            if ($('#dash-project')?.value) url += `&project_id=${$('#dash-project').value}`;
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

    $('#btn-scanner-back-main')?.addEventListener('click', () => {
        if (state.scanner) { try { state.scanner.stop(); } catch(e) {} state.scanning = false; }
        try { state.divisionId = null; state.areaId = null; state.projectId = null; state.siteId = null; state.session = null; } catch(e) {}
        const setupOverlay = document.getElementById('setup-overlay');
        if (setupOverlay) setupOverlay.classList.add('hidden');
        const mainContent = document.getElementById('main-content');
        if (mainContent) mainContent.style.display = 'none';
        doLogout();
    });
}

// ============================================================
// WORKFORCE TAB
// ============================================================

async function initWorkforceTab() {
    if (!_workforceInited) {
        _workforceInited = true;

        const wfDiv = $('#wf-division'), wfArea2 = $('#wf-filter-area'), wfProj = $('#wf-project'), wfCtr = $('#wf-contractor');
        const [divs, allAreas] = await Promise.all([api('/divisions'), api('/areas')]);
        if (wfDiv && Array.isArray(divs)) wfDiv.innerHTML = '<option value="">All Divisions</option>' + divs.map(d => `<option value="${d.id}">${esc(d.name)}</option>`).join('');
        if (wfArea2 && Array.isArray(allAreas)) wfArea2.innerHTML = '<option value="">All Areas</option>' + allAreas.map(a => `<option value="${a.id}">${esc(a.name)}</option>`).join('');

        wfDiv?.addEventListener('change', async () => {
            if (wfArea2) { wfArea2.innerHTML = '<option value="">All Areas</option>'; if (wfDiv.value) { const a2 = await api(`/areas?division_id=${wfDiv.value}`); if (Array.isArray(a2)) wfArea2.innerHTML = '<option value="">All Areas</option>' + a2.map(x => `<option value="${x.id}">${esc(x.name)}</option>`).join(''); } else if (Array.isArray(allAreas)) { wfArea2.innerHTML = '<option value="">All Areas</option>' + allAreas.map(a => `<option value="${a.id}">${esc(a.name)}</option>`).join(''); } }
            if (wfProj) wfProj.innerHTML = '<option value="">All Projects</option>';
            if (wfCtr) wfCtr.innerHTML = '<option value="">All Contractors</option>';
            loadWorkerList();
        });
        wfArea2?.addEventListener('change', async () => {
            if (wfProj) { wfProj.innerHTML = '<option value="">All Projects</option>'; if (wfArea2.value) await loadProjects(wfProj, true, wfArea2.value, null); }
            loadWorkerList();
        });
        wfProj?.addEventListener('change', loadWorkerList);
        wfCtr?.addEventListener('change', loadWorkerList);

        const wfArea = $('#wf-area');
        if (wfArea && Array.isArray(allAreas)) {
            wfArea.innerHTML = '<option value="">Select Area</option>' + allAreas.map(a => `<option value="${a.id}">${esc(a.name)}</option>`).join('');
        }
        $('#dash-import-btn')?.addEventListener('click', async () => {
            const file = $('#dash-import-file')?.files?.[0];
            if (!file) return toast('Select an Excel file', 'error');
            const areaId = $('#wf-area')?.value;
            if (!areaId) return toast('Select an area first', 'error');
            const status = $('#dash-import-status');
            status.textContent = 'Importing...';
            const form = new FormData();
            form.append('file', file); form.append('area_id', areaId);
            try {
                const res = await fetch('/api/import-excel', { method: 'POST', body: form, headers: { 'Authorization': `Bearer ${state.token}` } });
                const result = await res.json();
                status.textContent = result.message || 'Done';
                if (result.success) {
                    toast(result.message, 'success');
                    $('#dash-import-file').value = '';
                    loadWorkerList();
                    loadDashQRCodes();
                }
            } catch { status.textContent = 'Upload failed'; }
        });
    }
    loadWorkerList();
    loadDashQRCodes();
    loadProjects($('#qr-project-filter'), true);
}

// ============================================================
// TWL TAB
// ============================================================

async function initTWLTab() {
    if (!_twlInited) {
        _twlInited = true;
        const twlArea = $('#twl-area');
        const twlFilterDiv = $('#twl-filter-division');
        const twlFilterArea = $('#twl-filter-area');
        const twlFilterProj = $('#twl-filter-project');
        const twlFilterCtr = $('#twl-filter-contractor');

        const [divs, allAreas] = await Promise.all([api('/divisions'), api('/areas')]);
        if (twlArea && Array.isArray(allAreas)) {
            twlArea.innerHTML = '<option value="">Select Area</option>' + allAreas.map(a => `<option value="${a.id}">${esc(a.name)}</option>`).join('');
        }
        if (twlFilterDiv && Array.isArray(divs)) {
            twlFilterDiv.innerHTML = '<option value="">All Divisions</option>' + divs.map(d => `<option value="${d.id}">${esc(d.name)}</option>`).join('');
        }
        if (twlFilterArea && Array.isArray(allAreas)) {
            twlFilterArea.innerHTML = '<option value="">All Areas</option>' + allAreas.map(a => `<option value="${a.id}">${esc(a.name)}</option>`).join('');
        }

        twlFilterDiv?.addEventListener('change', async () => {
            twlFilterArea.innerHTML = '<option value="">All Areas</option>';
            if (twlFilterProj) twlFilterProj.innerHTML = '<option value="">All Projects</option>';
            if (twlFilterCtr) twlFilterCtr.innerHTML = '<option value="">All Contractors</option>';
            if (twlFilterDiv.value) {
                const areas = await api(`/areas?division_id=${twlFilterDiv.value}`);
                if (Array.isArray(areas)) twlFilterArea.innerHTML = '<option value="">All Areas</option>' + areas.map(a => `<option value="${a.id}">${esc(a.name)}</option>`).join('');
            }
            loadTWLData();
        });
        twlFilterArea?.addEventListener('change', async () => {
            if (twlFilterProj) {
                twlFilterProj.innerHTML = '<option value="">All Projects</option>';
                if (twlFilterArea.value) await loadProjects(twlFilterProj, true, twlFilterArea.value, null);
            }
            loadTWLData();
        });
        twlFilterProj?.addEventListener('change', loadTWLData);
        twlFilterCtr?.addEventListener('change', loadTWLData);

        _tabSliders.twl = initTabSlider($('#twl-date-slider'), loadTWLData);

        $('#btn-twl-submit')?.addEventListener('click', submitTWLReading);
    }
    loadTWLData();
}

async function submitTWLReading() {
    const twlValue = $('#twl-value')?.value;
    if (!twlValue) return toast('Enter TWL value', 'error');
    const body = {
        area_id: $('#twl-area')?.value || null,
        twl_value: parseFloat(twlValue),
        temperature: $('#twl-temp')?.value ? parseFloat($('#twl-temp').value) : null,
        humidity: $('#twl-humidity')?.value ? parseFloat($('#twl-humidity').value) : null,
        wind_speed: $('#twl-wind')?.value ? parseFloat($('#twl-wind').value) : null,
        work_type: $('#twl-work-type')?.value || 'light',
        notes: $('#twl-notes')?.value || '',
    };
    const res = await api('/twl', { method: 'POST', body: JSON.stringify(body) });
    const resultEl = $('#twl-result');
    if (res.success) {
        const zi = res.zone_info;
        const zoneColors = { low: '#22c55e', medium: '#f59e0b', high: '#ef4444' };
        resultEl.innerHTML = `<div style="padding:12px;border-radius:var(--radius);background:rgba(${res.risk_zone === 'high' ? '239,68,68' : res.risk_zone === 'medium' ? '245,158,11' : '34,197,94'},0.12);border:1px solid ${zoneColors[res.risk_zone]}30">
            <strong style="color:${zoneColors[res.risk_zone]}">${zi.label}</strong>
            <p style="margin-top:4px;font-size:0.85rem;color:var(--text-dim)">${zi.interventions}</p>
        </div>`;
        toast(res.message, 'success');
        $('#twl-value').value = '';
        $('#twl-temp').value = '';
        $('#twl-humidity').value = '';
        $('#twl-wind').value = '';
        $('#twl-notes').value = '';
        loadTWLData();
    } else {
        toast(res.message || 'Failed', 'error');
    }
}

async function loadTWLData() {
    const area = $('#twl-filter-area')?.value;
    const division = $('#twl-filter-division')?.value;
    let qp = `days=60`;
    if (area) qp += `&area_id=${area}`;
    else if (division) qp += `&division_id=${division}`;

    const [summary, readings] = await Promise.all([
        api('/twl/summary?' + qp),
        api('/twl?' + qp)
    ]);

    renderTWLSummary(summary);
    renderTWLTrendChart(summary);
    renderTWLReadings(readings);
}

function renderTWLSummary(data) {
    const el = $('#twl-summary-cards');
    if (!el || !data) return;
    const zones = data.zones || {};
    const highDays = data.high_risk_days || 0;
    const total = data.total_readings || 0;

    el.innerHTML = `
        <div class="stat-card"><div class="stat-value blue">${total}</div><div class="stat-label">Total Readings</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#f59e0b">${data.avg_twl}</div><div class="stat-label">Avg TWL</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#ef4444">${data.min_twl}</div><div class="stat-label">Min TWL</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#22c55e">${data.max_twl}</div><div class="stat-label">Max TWL</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#22c55e">${zones.low || 0}</div><div class="stat-label">Low Risk</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#f59e0b">${zones.medium || 0}</div><div class="stat-label">Medium Risk</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#ef4444">${zones.high || 0}</div><div class="stat-label">High Risk</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#ef4444">${highDays}</div><div class="stat-label">High Risk Days</div></div>`;
}

function renderTWLTrendChart(data) {
    const canvas = $('#twl-trend-chart');
    if (!canvas || !data || !data.trend || !data.trend.length) {
        if (canvas) { const ctx = canvas.getContext('2d'); ctx.clearRect(0, 0, canvas.width, canvas.height); ctx.fillStyle = '#94a3b8'; ctx.font = '14px Inter'; ctx.fillText('No TWL trend data yet', 20, 60); }
        return;
    }
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth, h = canvas.clientHeight;
    canvas.width = w * dpr; canvas.height = h * dpr;
    ctx.scale(dpr, dpr); ctx.clearRect(0, 0, w, h);

    const trend = data.trend;
    const pad = { top: 30, right: 20, bottom: 40, left: 50 };
    const cw = w - pad.left - pad.right, ch = h - pad.top - pad.bottom;
    const n = trend.length, stepX = n > 1 ? cw / (n - 1) : cw;
    const allVals = trend.flatMap(t => [t.avg_twl, t.min_twl, t.max_twl]).filter(v => v != null);
    const maxV = Math.max(...allVals, 220, 1);
    const minV = Math.min(...allVals, 80);
    const range = maxV - minV || 1;

    // Risk zone bands
    const y115 = pad.top + ch - (ch * (115 - minV) / range);
    const y140 = pad.top + ch - (ch * (140 - minV) / range);
    ctx.fillStyle = 'rgba(239,68,68,0.06)';
    ctx.fillRect(pad.left, y115, cw, pad.top + ch - y115);
    ctx.fillStyle = 'rgba(245,158,11,0.06)';
    ctx.fillRect(pad.left, y140, cw, y115 - y140);
    ctx.fillStyle = 'rgba(34,197,94,0.06)';
    ctx.fillRect(pad.left, pad.top, cw, y140 - pad.top);

    // Threshold lines
    [{ v: 115, c: '#ef4444', l: 'High Risk < 115' }, { v: 140, c: '#f59e0b', l: 'Medium < 140' }].forEach(th => {
        const y = pad.top + ch - (ch * (th.v - minV) / range);
        ctx.setLineDash([4, 4]); ctx.strokeStyle = th.c + '60'; ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(w - pad.right, y); ctx.stroke();
        ctx.setLineDash([]); ctx.fillStyle = th.c; ctx.font = '9px Inter'; ctx.textAlign = 'left';
        ctx.fillText(th.l, pad.left + 4, y - 3);
    });

    // Grid
    ctx.strokeStyle = 'rgba(148,163,184,0.12)'; ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
        const y = pad.top + ch - (ch * i / 4);
        ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(w - pad.right, y); ctx.stroke();
        ctx.fillStyle = '#94a3b8'; ctx.font = '10px Inter'; ctx.textAlign = 'right';
        ctx.fillText(Math.round(minV + range * i / 4), pad.left - 6, y + 3);
    }

    // Range fill (min to max)
    ctx.fillStyle = 'rgba(59,130,246,0.1)';
    ctx.beginPath();
    trend.forEach((t, i) => { const x = pad.left + i * stepX, y = pad.top + ch - (ch * (t.max_twl - minV) / range); i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y); });
    for (let i = n - 1; i >= 0; i--) { const x = pad.left + i * stepX, y = pad.top + ch - (ch * (trend[i].min_twl - minV) / range); ctx.lineTo(x, y); }
    ctx.closePath(); ctx.fill();

    // Avg line
    ctx.strokeStyle = '#3b82f6'; ctx.lineWidth = 2.5; ctx.lineJoin = 'round';
    ctx.beginPath();
    trend.forEach((t, i) => { const x = pad.left + i * stepX, y = pad.top + ch - (ch * (t.avg_twl - minV) / range); i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y); });
    ctx.stroke();

    // Dots colored by zone
    trend.forEach((t, i) => {
        const x = pad.left + i * stepX, y = pad.top + ch - (ch * (t.avg_twl - minV) / range);
        ctx.beginPath(); ctx.arc(x, y, 4, 0, Math.PI * 2);
        ctx.fillStyle = t.avg_twl < 115 ? '#ef4444' : t.avg_twl < 140 ? '#f59e0b' : '#22c55e';
        ctx.fill();
    });

    // X labels
    ctx.fillStyle = '#94a3b8'; ctx.font = '10px Inter'; ctx.textAlign = 'center';
    const step = Math.max(1, Math.floor(n / 7));
    trend.forEach((t, i) => { if (i % step === 0 || i === n - 1) { const x = pad.left + i * stepX; const parts = t.reading_date.split('-'); ctx.fillText(`${parts[2]}/${parts[1]}`, x, h - pad.bottom + 14); } });

    // Legend
    const legend = [['Avg TWL', '#3b82f6'], ['Range (min-max)', 'rgba(59,130,246,0.3)']];
    let lx = pad.left; ctx.font = '10px Inter';
    legend.forEach(([label, color]) => { ctx.fillStyle = color; ctx.fillRect(lx, 6, 14, 4); ctx.fillStyle = '#94a3b8'; ctx.textAlign = 'left'; ctx.fillText(label, lx + 18, 12); lx += ctx.measureText(label).width + 34; });
}

function renderTWLReadings(readings) {
    const el = $('#twl-readings-list');
    if (!el) return;
    if (!Array.isArray(readings) || !readings.length) {
        el.innerHTML = '<div class="empty-state">No TWL readings in this period</div>';
        return;
    }
    const zoneBadge = (z) => `<span class="twl-reading-badge twl-badge-${z}">${z}</span>`;
    el.innerHTML = `<table class="worker-table"><thead><tr>
        <th>Date</th><th>Time</th><th>Area</th><th>TWL</th><th>Zone</th>
        <th>Temp °C</th><th>Humidity %</th><th>Wind km/h</th><th>Work Type</th><th>Recorded By</th><th>Notes</th>
        </tr></thead><tbody>` +
        readings.slice(0, 200).map(r => `<tr>
            <td>${formatHeadcountDate(r.reading_date)}</td>
            <td>${esc(r.reading_time || '')}</td>
            <td>${esc(r.area_name || '—')}</td>
            <td><strong style="color:${r.risk_zone === 'high' ? '#ef4444' : r.risk_zone === 'medium' ? '#f59e0b' : '#22c55e'}">${r.twl_value}</strong></td>
            <td>${zoneBadge(r.risk_zone)}</td>
            <td>${r.temperature != null ? r.temperature : '—'}</td>
            <td>${r.humidity != null ? r.humidity : '—'}</td>
            <td>${r.wind_speed != null ? r.wind_speed : '—'}</td>
            <td>${esc(r.work_type || '')}</td>
            <td>${esc(r.recorded_by_name || '')}</td>
            <td>${esc(r.notes || '')}</td>
        </tr>`).join('') + '</tbody></table>';
}

// ============================================================
// O&I (Observation & Intervention)
// ============================================================
let _oiInited = false;

async function initOITab() {
    if (!_oiInited) {
        _oiInited = true;
        const meta = await api('/observations/meta');
        if (!meta) return;

        const oiGroup = $('#oi-group');
        const oiType = $('#oi-type');
        const oiSeverity = $('#oi-severity');
        const oiRisk = $('#oi-risk');
        const oiDisc = $('#oi-observer-disc');
        const oiEmpType = $('#oi-emp-type');
        const oiDiv = $('#oi-division');
        const oiArea = $('#oi-area');
        const oiProj = $('#oi-project');

        if (oiGroup) oiGroup.innerHTML = '<option value="">Select</option>' + meta.observation_groups.map(g => `<option value="${g}">${esc(g)}</option>`).join('');
        if (oiType) oiType.innerHTML = '<option value="">Select</option>' + meta.observation_types.map(t => `<option value="${t}">${esc(t)}</option>`).join('');
        if (oiEmpType) oiEmpType.innerHTML = '<option value="">Select</option>' + meta.employee_types.map(t => `<option value="${t}">${esc(t)}</option>`).join('');

        const disciplines = ['Civil', 'Mechanical', 'Electrical', 'Piping', 'Instrumentation', 'HSE', 'Structural', 'Welding', 'Painting', 'Insulation', 'Scaffolding', 'QA/QC', 'Rigging', 'Operations', 'Logistics'];
        if (oiDisc) oiDisc.innerHTML = '<option value="">Select</option>' + disciplines.map(d => `<option value="${d}">${d}</option>`).join('');

        oiGroup?.addEventListener('change', () => {
            const isSafe = oiGroup.value === 'Safe Act' || oiGroup.value === 'Safe Condition';
            const sevOpts = isSafe ? meta.severity_safe : meta.severity_unsafe;
            const riskOpts = isSafe ? meta.risk_safe : meta.risk_unsafe;
            if (oiSeverity) oiSeverity.innerHTML = '<option value="">Select</option>' + sevOpts.map(s => `<option value="${s}">${s}</option>`).join('');
            if (oiRisk) oiRisk.innerHTML = '<option value="">Select</option>' + riskOpts.map(r => `<option value="${r}">${r}</option>`).join('');
        });

        const [divs, areas] = await Promise.all([api('/divisions'), api('/areas')]);
        if (oiDiv && Array.isArray(divs)) oiDiv.innerHTML = '<option value="">Select</option>' + divs.map(d => `<option value="${d.id}">${esc(d.name)}</option>`).join('');
        if (oiArea && Array.isArray(areas)) oiArea.innerHTML = '<option value="">Select</option>' + areas.map(a => `<option value="${a.id}">${esc(a.name)}</option>`).join('');

        oiDiv?.addEventListener('change', async () => {
            oiArea.innerHTML = '<option value="">Select</option>';
            oiProj.innerHTML = '<option value="">Select</option>';
            if (oiDiv.value) {
                const a = await api(`/areas?division_id=${oiDiv.value}`);
                if (Array.isArray(a)) oiArea.innerHTML = '<option value="">Select</option>' + a.map(x => `<option value="${x.id}">${esc(x.name)}</option>`).join('');
            }
        });
        oiArea?.addEventListener('change', async () => {
            oiProj.innerHTML = '<option value="">Select</option>';
            if (oiArea.value) await loadProjects(oiProj, false, oiArea.value, null);
        });

        const oiFilterDiv = $('#oi-filter-division');
        const oiFilterArea2 = $('#oi-filter-area');
        const oiFilterProj2 = $('#oi-filter-project');
        const oiFilterCtr = $('#oi-filter-contractor');
        if (oiFilterDiv && Array.isArray(divs)) oiFilterDiv.innerHTML = '<option value="">All Divisions</option>' + divs.map(d => `<option value="${d.id}">${esc(d.name)}</option>`).join('');
        if (oiFilterArea2 && Array.isArray(areas)) oiFilterArea2.innerHTML = '<option value="">All Areas</option>' + areas.map(a => `<option value="${a.id}">${esc(a.name)}</option>`).join('');

        oiFilterDiv?.addEventListener('change', async () => {
            if (oiFilterArea2) {
                oiFilterArea2.innerHTML = '<option value="">All Areas</option>';
                if (oiFilterDiv.value) {
                    const a2 = await api(`/areas?division_id=${oiFilterDiv.value}`);
                    if (Array.isArray(a2)) oiFilterArea2.innerHTML = '<option value="">All Areas</option>' + a2.map(x => `<option value="${x.id}">${esc(x.name)}</option>`).join('');
                }
            }
            if (oiFilterProj2) oiFilterProj2.innerHTML = '<option value="">All Projects</option>';
            if (oiFilterCtr) oiFilterCtr.innerHTML = '<option value="">All Contractors</option>';
            loadOIData();
        });
        oiFilterArea2?.addEventListener('change', async () => {
            if (oiFilterProj2) {
                oiFilterProj2.innerHTML = '<option value="">All Projects</option>';
                if (oiFilterArea2.value) await loadProjects(oiFilterProj2, true, oiFilterArea2.value, null);
            }
            loadOIData();
        });
        oiFilterProj2?.addEventListener('change', loadOIData);
        oiFilterCtr?.addEventListener('change', loadOIData);

        _tabSliders.oi = initTabSlider($('#oi-date-slider'), loadOIData);

        $('#oi-date').value = new Date().toISOString().split('T')[0];
        $('#oi-entry-form')?.addEventListener('submit', submitObservation);
    }
    loadOIData();
}

async function submitObservation(e) {
    e.preventDefault();
    const group = $('#oi-group')?.value;
    if (!group) return toast('Select observation group', 'error');
    const body = {
        observation_date: $('#oi-date')?.value || new Date().toISOString().split('T')[0],
        division_id: $('#oi-division')?.value || null,
        area_id: $('#oi-area')?.value || null,
        project_id: $('#oi-project')?.value || null,
        observer_name: $('#oi-observer-name')?.value || '',
        observer_designation: $('#oi-observer-desg')?.value || '',
        observer_discipline: $('#oi-observer-disc')?.value || '',
        employee_type: $('#oi-emp-type')?.value || '',
        observation_group: group,
        observation_type: $('#oi-type')?.value || '',
        potential_severity: $('#oi-severity')?.value || '',
        risk_rating: $('#oi-risk')?.value || '',
        observation_text: $('#oi-text')?.value || '',
        corrective_action: $('#oi-action')?.value || '',
    };
    const res = await api('/observations', { method: 'POST', body: JSON.stringify(body) });
    if (res.success) {
        toast('Observation recorded', 'success');
        $('#oi-entry-form').reset();
        $('#oi-date').value = new Date().toISOString().split('T')[0];
        loadOIData();
    } else {
        toast(res.message || 'Failed', 'error');
    }
}

async function loadOIData() {
    const division = $('#oi-filter-division')?.value;
    const area = $('#oi-filter-area')?.value;
    const project = $('#oi-filter-project')?.value;
    let qp = `days=60`;
    if (project) qp += `&project_id=${project}`;
    else if (area) qp += `&area_id=${area}`;
    else if (division) qp += `&division_id=${division}`;

    const [summary, readings, insights] = await Promise.all([
        api('/observations/summary?' + qp),
        api('/observations?' + qp),
        api('/observations/insights?' + qp)
    ]);

    renderOISummary(summary);
    requestAnimationFrame(() => {
        renderOICharts(summary);
        renderOIRecurringChart(insights);
        renderOIDisciplineChart(insights);
        renderOITrendChart(summary);
    });
    renderOIInsights(insights);
    renderOIReadings(readings);
}

function renderOISummary(data) {
    const el = $('#oi-summary-cards');
    if (!el || !data) return;
    const safeRate = data.total > 0 ? Math.round((data.safe / data.total) * 100) : 0;
    el.innerHTML = `
        <div class="stat-card"><div class="stat-value blue">${data.total}</div><div class="stat-label">Total Observations</div></div>
        <div class="stat-card"><div class="stat-value green">${data.safe} <small style="font-size:0.6em;opacity:0.7">(${safeRate}%)</small></div><div class="stat-label">Safe</div></div>
        <div class="stat-card"><div class="stat-value orange">${data.unsafe}</div><div class="stat-label">Unsafe / Near Miss / HIPO</div></div>
        <div class="stat-card"><div class="stat-value">${data.by_type?.length || 0}</div><div class="stat-label">Observation Types</div></div>`;
}

function renderOICharts(data) {
    if (!data || !data.total) return;
    const groupColors = {
        'Safe Act': '#22c55e', 'Safe Condition': '#16a34a',
        'Unsafe Act': '#f59e0b', 'Unsafe Condition': '#ef4444',
        'Near Miss': '#f97316', 'HIPO': '#a855f7'
    };

    const groupCanvas = $('#oi-group-chart');
    if (groupCanvas && groupCanvas.clientWidth > 0 && data.by_group?.length) {
        drawDonutChart(groupCanvas, data.by_group.map(g => ({
            label: g.observation_group, value: g.c, color: groupColors[g.observation_group] || '#94a3b8'
        })), data.total);
    }

    const typeCanvas = $('#oi-type-chart');
    if (typeCanvas && typeCanvas.clientWidth > 0 && data.by_type?.length) {
        const colors = ['#3b82f6', '#22c55e', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4', '#ec4899', '#f97316', '#14b8a6', '#64748b'];
        drawHorizontalBarChart(typeCanvas, data.by_type.map(t => t.observation_type), data.by_type.map(t => t.c), colors, data.total);
    }

    const sevCanvas = $('#oi-severity-chart');
    if (sevCanvas && sevCanvas.clientWidth > 0 && data.by_severity?.length) {
        const sevColors = { 'N/A': '#94a3b8', 'Low': '#22c55e', 'Medium': '#f59e0b', 'High': '#ef4444', 'Critical': '#a855f7' };
        drawDonutChart(sevCanvas, data.by_severity.map(s => ({
            label: s.potential_severity || 'N/A', value: s.c, color: sevColors[s.potential_severity] || '#94a3b8'
        })), data.total);
    }
}

function renderOIRecurringChart(data) {
    const canvas = $('#oi-recurring-chart');
    if (!canvas || !data?.recurring?.length || canvas.clientWidth <= 0) return;
    const colors = ['#ef4444', '#f59e0b', '#3b82f6', '#8b5cf6', '#06b6d4', '#ec4899', '#22c55e', '#f97316', '#14b8a6', '#64748b'];
    const labels = data.recurring.map(r => r.observation_type);
    const values = data.recurring.map(r => r.c);
    const total = values.reduce((a, b) => a + b, 0);
    drawHorizontalBarChart(canvas, labels, values, colors, total);
}

function renderOIDisciplineChart(data) {
    const canvas = $('#oi-discipline-chart');
    if (!canvas || !data?.by_discipline?.length || canvas.clientWidth <= 0) return;
    const discColors = {
        'Civil': '#ef4444', 'Mechanical': '#3b82f6', 'Electrical': '#f59e0b',
        'Piping': '#22c55e', 'Instrumentation': '#8b5cf6', 'HSE': '#06b6d4',
        'Structural': '#ec4899', 'Welding': '#f97316', 'Painting': '#14b8a6',
        'Insulation': '#64748b', 'Scaffolding': '#a855f7', 'QA/QC': '#10b981',
        'Rigging': '#d946ef', 'Operations': '#0ea5e9', 'Logistics': '#84cc16'
    };
    const segments = data.by_discipline.filter(d => d.observer_discipline).map(d => ({
        label: d.observer_discipline,
        value: d.c,
        color: discColors[d.observer_discipline] || '#94a3b8'
    }));
    const total = segments.reduce((a, s) => a + s.value, 0);
    if (segments.length) drawDonutChart(canvas, segments, total);
}

function renderOITrendChart(data) {
    const canvas = $('#oi-trend-chart');
    if (!canvas || !data?.by_date?.length || canvas.clientWidth <= 0) return;
    const labels = data.by_date.map(d => d.observation_date);
    const values = data.by_date.map(d => d.c);
    drawLineChart(canvas, labels, values, Math.max(...values) + 2);
}

function renderOIInsights(data) {
    const el = $('#oi-insights-list');
    const countBadge = $('#oi-insight-count');
    if (!el) return;
    if (!data?.insights?.length) {
        el.innerHTML = '<div class="empty-state">No anomalies detected in this period</div>';
        if (countBadge) countBadge.textContent = '0';
        return;
    }
    if (countBadge) countBadge.textContent = data.count;

    const sevColors = { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#16a34a' };
    const catIcons = { Trend: '📈', Discipline: '👷', HIPO: '⚠️', Recurring: '🔄', Area: '📍', Ratio: '⚖️' };

    el.innerHTML = `<table class="worker-table"><thead><tr>
        <th style="width:30px"></th><th>Insight</th><th>Category</th><th>Severity</th><th style="text-align:right">Metric</th>
        </tr></thead><tbody>` +
        data.insights.map(i => `<tr style="border-left:3px solid ${sevColors[i.severity] || '#94a3b8'}">
            <td style="font-size:1.1em;text-align:center">${catIcons[i.category] || '📊'}</td>
            <td><strong>${esc(i.title)}</strong><br><small style="color:var(--text-dim)">${esc(i.detail)}</small></td>
            <td><span class="oi-badge oi-badge-${i.category === 'HIPO' ? 'hipo' : i.severity === 'high' ? 'unsafe' : 'safe'}">${esc(i.category)}</span></td>
            <td><span style="color:${sevColors[i.severity]};font-weight:600;text-transform:uppercase;font-size:0.8em">${esc(i.severity)}</span></td>
            <td style="text-align:right;font-weight:700;font-size:1.1em;color:${sevColors[i.severity]}">${esc(i.metric)}</td>
        </tr>`).join('') + '</tbody></table>';
}

function renderOIReadings(readings) {
    const el = $('#oi-readings-list');
    if (!el) return;
    if (!Array.isArray(readings) || !readings.length) {
        el.innerHTML = '<div class="empty-state">No observations in this period</div>';
        return;
    }
    const groupBadge = (g) => {
        const cls = g === 'HIPO' ? 'hipo' : g === 'Near Miss' ? 'near-miss' : (g || '').includes('Safe') ? 'safe' : 'unsafe';
        return `<span class="oi-badge oi-badge-${cls}">${esc(g)}</span>`;
    };
    el.innerHTML = `<table class="worker-table"><thead><tr>
        <th>Date</th><th>Group</th><th>Type</th><th>Severity</th><th>Risk</th>
        <th>Observer</th><th>Discipline</th><th>Division</th><th>Outcome</th>
        </tr></thead><tbody>` +
        readings.slice(0, 200).map(r => `<tr>
            <td>${formatHeadcountDate(r.observation_date)}</td>
            <td>${groupBadge(r.observation_group)}</td>
            <td>${esc(r.observation_type || '—')}</td>
            <td>${esc(r.potential_severity || '—')}</td>
            <td>${esc(r.risk_rating || '—')}</td>
            <td>${esc(r.observer_name || '—')}</td>
            <td>${esc(r.observer_discipline || '—')}</td>
            <td>${esc(r.division_name || '—')}</td>
            <td>${esc(r.outcome || '—')}</td>
        </tr>`).join('') + '</tbody></table>';
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
    const dashDateEl = $('#dash-date');
    if (dashDateEl) dashDateEl.value = new Date().toISOString().split('T')[0];

    if (state.token && state.user) {
        showApp();
    } else {
        showLogin();
    }
});

if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
