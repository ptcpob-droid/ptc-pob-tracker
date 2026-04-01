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
    $('#trends-tab').style.display = isAdminRole(role) ? '' : 'none';
    const scannerTab = document.querySelector('.tab[data-tab="scanner"]');
    const dashTab = document.querySelector('.tab[data-tab="dashboard"]');
    const qrTab = document.querySelector('.tab[data-tab="qrcodes"]');

    if (role === 'scanner') {
        if (scannerTab) scannerTab.style.display = '';
        if (dashTab) dashTab.style.display = 'none';
        if (qrTab) qrTab.style.display = 'none';
        $('#setup-overlay').classList.remove('hidden');
    } else {
        if (scannerTab) scannerTab.style.display = 'none';
        if (dashTab) dashTab.style.display = '';
        if (qrTab) qrTab.style.display = 'none';
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
    let loginMode = 'scanner';

    const scannerFields = $('#login-scanner-fields');
    const adminFields = $('#login-admin-fields');
    const modeScanner = $('#login-mode-scanner');
    const modeAdmin = $('#login-mode-admin');

    function setMode(mode) {
        loginMode = mode;
        errorDiv.textContent = '';
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

    async function doLogin() {
        errorDiv.textContent = '';
        let body;
        if (loginMode === 'scanner') {
            const username = $('#login-username').value.trim();
            const pin = $('#login-pin').value.trim();
            if (!username || !pin) { errorDiv.textContent = 'Enter username and PIN'; return; }
            body = { username, pin, login_mode: 'scanner' };
        } else {
            const username = $('#login-admin-username').value.trim();
            const totp_code = $('#login-totp').value.trim();
            if (!username || !totp_code) { errorDiv.textContent = 'Enter username and 2FA code'; return; }
            if (totp_code.length !== 6 || !/^\d+$/.test(totp_code)) { errorDiv.textContent = 'Enter the 6-digit code from your authenticator app'; return; }
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
                $('#login-pin').value = '';
                $('#login-totp').value = '';
                showApp();
                toast(`Welcome, ${data.user.display_name}`, 'success');
            } else {
                errorDiv.textContent = data.message;
            }
        } catch (e) {
            errorDiv.textContent = 'Connection error. Is the server running?';
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
    const divisionSelect = $('#setup-division');
    const areaSelect = $('#setup-area');
    const projectSelect = $('#setup-project');
    const siteSelect = $('#setup-site');

    function updateSetupConfirmState() {
        const btn = $('#setup-confirm');
        if (!btn) return;
        const ok = divisionSelect.value && areaSelect.value && projectSelect.value && siteSelect.value;
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
                await loadSitesForProject(siteSelect, p.id);
                if (siteSelect.options.length > 0) siteSelect.selectedIndex = 1;
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
        siteSelect.innerHTML = '<option value="">Select project first</option>';
        siteSelect.disabled = true;
    });
    areaSelect.addEventListener('change', async () => {
        const areaId = areaSelect.value;
        await loadProjects(projectSelect, false, areaId || null, null);
        if (!areaId) projectSelect.disabled = true;
        siteSelect.innerHTML = '<option value="">Select project first</option>';
        siteSelect.disabled = true;
    });
    projectSelect.addEventListener('change', () => {
        loadSitesForProject(siteSelect, projectSelect.value);
        updateSetupConfirmState();
    });
    divisionSelect.addEventListener('change', () => setTimeout(updateSetupConfirmState, 0));
    areaSelect.addEventListener('change', () => setTimeout(updateSetupConfirmState, 0));
    siteSelect.addEventListener('change', updateSetupConfirmState);

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
        if (!divisionSelect.value) return toast('Select a division', 'error');
        if (!areaSelect.value) return toast('Select an area', 'error');
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
                    await loadSitesForProject(siteSelect, s.projectId);
                    siteSelect.value = s.siteId;
                }
                updateSetupConfirmState();
            })();
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
let _dashWorkers = [];

async function initDashFilters() {
    const dd = $('#dash-division'), da = $('#dash-area'), dp = $('#dash-project'), dc = $('#dash-contractor');
    const divs = await api('/divisions');
    if (Array.isArray(divs)) {
        dd.innerHTML = '<option value="">All Divisions</option>' + divs.map(d => `<option value="${d.id}">${esc(d.name)}</option>`).join('');
    }
    dd.addEventListener('change', async () => {
        da.innerHTML = '<option value="">All Areas</option>';
        dp.innerHTML = '<option value="">All Projects</option>';
        if (dc) dc.innerHTML = '<option value="">All Contractors</option>';
        if (dd.value) {
            const areas = await api(`/areas?division_id=${dd.value}`);
            if (Array.isArray(areas)) da.innerHTML = '<option value="">All Areas</option>' + areas.map(a => `<option value="${a.id}">${esc(a.name)}</option>`).join('');
        }
        refreshDashboard();
    });
    da.addEventListener('change', async () => {
        dp.innerHTML = '<option value="">All Projects</option>';
        if (dc) dc.innerHTML = '<option value="">All Contractors</option>';
        if (da.value) await loadProjects(dp, true, da.value, null);
        refreshDashboard();
    });
    dp.addEventListener('change', async () => {
        await loadContractors();
        refreshDashboard();
    });
    if (dc) dc.addEventListener('change', refreshDashboard);

    $('#dash-import-btn').addEventListener('click', async () => {
        const file = $('#dash-import-file')?.files?.[0];
        if (!file) return toast('Select an Excel file', 'error');
        const areaId = $('#dash-area').value;
        if (!areaId) return toast('Select a Division and Area in the filter bar above first', 'error');
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
                refreshDashboard();
            }
        } catch { status.textContent = 'Upload failed'; }
    });
}

function refreshDashboard() {
    loadDashboard();
    loadWorkerList();
    loadDashQRCodes();
    loadPersonnel('present');
    loadContractors();
}

async function loadDashboard() {
    const d = $('#dash-date'), p = $('#dash-project');
    if (!d.value) d.value = new Date().toISOString().split('T')[0];

    const filterParams = getDashFilterParams();
    let url = `/headcount?date=${d.value}` + (filterParams ? '&' + filterParams : '');
    let su = '/stats' + (filterParams ? '?' + filterParams : '');

    const [hc, stats] = await Promise.all([api(url), api(su)]);
    if (!stats.total_employees && stats.total_employees !== 0) return;

    const headcountDate = d.value || hc.date || new Date().toISOString().split('T')[0];
    const dateLabel = formatHeadcountDate(headcountDate);
    const dateEl = $('#headcount-date-label');
    if (dateEl) dateEl.textContent = dateLabel ? ` — ${dateLabel}` : '';

    const amP = stats.total_employees > 0 ? Math.round(((stats.today_am || 0) / stats.total_employees) * 100) : 0;
    const evP = stats.total_employees > 0 ? Math.round(((stats.today_ev || 0) / stats.total_employees) * 100) : 0;
    $('#stats-cards').innerHTML = `
        <div class="stat-card"><div class="stat-value blue">${esc(String(stats.total_employees))}</div><div class="stat-label">Total Workforce</div></div>
        <div class="stat-card"><div class="stat-value green">${esc(String(stats.today_am ?? 0))} <small style="font-size:0.7em;opacity:0.7">(${amP}%)</small></div><div class="stat-label">9 AM Present</div></div>
        <div class="stat-card"><div class="stat-value teal">${esc(String(stats.today_ev ?? 0))} <small style="font-size:0.7em;opacity:0.7">(${evP}%)</small></div><div class="stat-label">7 PM Present</div></div>
        <div class="stat-card"><div class="stat-value orange">${esc(String(stats.total_projects))}</div><div class="stat-label">Projects</div></div>`;

    const tw = $('#headcount-table-wrap');
    if (!hc.sites || hc.sites.length === 0) {
        tw.innerHTML = `<div class="empty-state">No attendance data for ${dateLabel || headcountDate}</div>`;
    } else {
        let h = `<div class="text-dim" style="font-size:0.85rem;margin-bottom:6px">Date: ${dateLabel || headcountDate}</div><table><thead><tr><th>Project</th><th>Site</th><th>Total</th><th>9 AM</th><th>7 PM</th><th>9 AM %</th></tr></thead><tbody>`;
        hc.sites.forEach(r => {
            const am = r.AM ?? 0, ev = r.EV ?? 0;
            const pct = r.total_employees > 0 ? Math.round((am / r.total_employees) * 100) : 0;
            const c = pct >= 80 ? 'var(--success)' : pct >= 50 ? 'var(--warning)' : 'var(--danger)';
            h += `<tr><td>${esc(r.project)}</td><td>${esc(r.site)}</td><td>${r.total_employees}</td><td><strong>${am}</strong></td><td><strong>${ev}</strong></td>
                <td><div style="display:flex;align-items:center;gap:6px"><div class="progress-bar"><div class="progress-fill" style="width:${pct}%;background:${c}"></div></div><span style="font-size:0.8rem">${pct}%</span></div></td></tr>`;
        });
        tw.innerHTML = h + '</tbody></table>';
    }
}

function getDashFilterParams() {
    const parts = [];
    const div = $('#dash-division')?.value;
    const area = $('#dash-area')?.value;
    const proj = $('#dash-project')?.value;
    const contractor = $('#dash-contractor')?.value;
    if (proj) parts.push(`project_id=${proj}`);
    else if (area) parts.push(`area_id=${area}`);
    else if (div) parts.push(`division_id=${div}`);
    if (contractor) parts.push(`subcontractor=${encodeURIComponent(contractor)}`);
    return parts.join('&');
}

async function loadContractors() {
    const dc = $('#dash-contractor');
    if (!dc) return;
    const params = getDashFilterParams();
    const data = await api('/contractors' + (params ? '?' + params : ''));
    const cur = dc.value;
    dc.innerHTML = '<option value="">All Contractors</option>';
    if (Array.isArray(data)) {
        dc.innerHTML += data.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join('');
    }
    dc.value = cur;
}

async function loadWorkerList() {
    const wrap = $('#worker-list');
    if (!wrap) return;
    wrap.innerHTML = '<div class="spinner"></div>';
    const params = getDashFilterParams();
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
        <th>Agreement No.</th><th>Project</th><th>Name</th><th>Nationality</th><th>DOB</th>
        <th>Designation</th><th>Physical Work Location</th><th>Residing Camp</th>
        <th>Employee No.</th><th>Qualification</th><th>Date of Joining</th>
        <th>Date of Deployment</th><th>Medical Date</th><th>Discipline</th>
        <th>Sub-contractor</th><th>Remarks</th><th>QR</th></tr></thead><tbody>` +
        data.slice(0, 500).map((w) => `<tr>
        <td>${esc(w.agreement_no || '')}</td><td>${esc(w.project_name || '')}</td>
        <td>${esc(w.name)}</td><td>${esc(w.nationality || '')}</td><td>${esc(w.dob || '')}</td>
        <td>${esc(w.designation || '')}</td><td>${esc(w.work_location || '')}</td>
        <td>${esc(w.camp_name || '')}</td><td>${esc(w.employee_no)}</td>
        <td>${esc(w.qualification || '')}</td><td>${esc(w.date_joining || '')}</td>
        <td>${esc(w.date_deployment || '')}</td><td>${esc(w.medical_date || '')}</td>
        <td>${esc(w.discipline || '')}</td><td>${esc(w.subcontractor || '')}</td>
        <td>${esc(w.remarks || '')}</td>
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
    const filterParams = getDashFilterParams();
    let url = '/qrcodes/batch' + (filterParams ? '?' + filterParams : '');
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
        <div class="qr-handout">POB Tracker — present at site</div>
        </div>`).join('');
}

function formatHeadcountDate(iso) {
    if (!iso) return '';
    const [y, m, day] = iso.split('-');
    const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    return `${day} ${months[parseInt(m,10)-1]} ${y}`;
}

async function loadPersonnel(view = 'present') {
    const d = $('#dash-date').value || new Date().toISOString().split('T')[0];
    const personnelDateEl = $('#personnel-date-label');
    if (personnelDateEl) personnelDateEl.textContent = formatHeadcountDate(d) ? ` (${formatHeadcountDate(d)})` : '';
    const list = $('#personnel-list');
    list.innerHTML = '<div class="spinner"></div>';

    const sess = $('#dash-session')?.value || 'AM';
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
// TRENDS (line chart)
// ============================================================
let _trendsInited = false;
async function initTrends() {
    if (_trendsInited) return;
    _trendsInited = true;
    const sess = $('#trend-session'), desig = $('#trend-designation'), nat = $('#trend-nationality'), days = $('#trend-days');
    [sess, desig, nat, days].forEach(el => el?.addEventListener('change', loadTrends));
    await loadTrends();
}

async function loadTrends() {
    const params = new URLSearchParams();
    const filterParams = getDashFilterParams();
    if (filterParams) filterParams.split('&').forEach(p => { const [k,v] = p.split('='); params.set(k,v); });
    const sess = $('#trend-session').value;
    const desig = $('#trend-designation').value;
    const nat = $('#trend-nationality').value;
    const days = $('#trend-days').value;
    if (sess) params.set('session', sess);
    if (desig) params.set('designation', desig);
    if (nat) params.set('nationality', nat);
    params.set('days', days);

    const data = await api('/trends?' + params.toString());
    if (!data || !data.labels) return;

    // Populate filter dropdowns (keep selection)
    const prevD = desig, prevN = nat;
    const dSel = $('#trend-designation'), nSel = $('#trend-nationality');
    if (data.designations) {
        const curVal = dSel.value;
        dSel.innerHTML = '<option value="">All Designations</option>' + data.designations.map(d => `<option value="${esc(d)}">${esc(d)}</option>`).join('');
        dSel.value = curVal;
    }
    if (data.nationalities) {
        const curVal = nSel.value;
        nSel.innerHTML = '<option value="">All Nationalities</option>' + data.nationalities.map(n => `<option value="${esc(n)}">${esc(n)}</option>`).join('');
        nSel.value = curVal;
    }

    drawLineChart($('#trend-chart'), data.labels, data.values, data.total);

    const bd = $('#trend-breakdown');
    if (bd && data.labels.length) {
        const recent = data.labels.slice(-7);
        const recentV = data.values.slice(-7);
        bd.innerHTML = `<table class="worker-table"><thead><tr><th>Date</th><th>Present</th><th>Total</th><th>%</th></tr></thead><tbody>` +
            recent.map((d, i) => {
                const pct = data.total > 0 ? Math.round((recentV[i] / data.total) * 100) : 0;
                return `<tr><td>${formatHeadcountDate(d)}</td><td><strong>${recentV[i]}</strong></td><td>${data.total}</td><td>${pct}%</td></tr>`;
            }).join('') + '</tbody></table>';
    }
}

function drawLineChart(canvas, labels, values, total) {
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth, h = canvas.clientHeight;
    canvas.width = w * dpr; canvas.height = h * dpr;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    if (!values.length) { ctx.fillStyle = '#94a3b8'; ctx.font = '14px Inter, sans-serif'; ctx.fillText('No data', w/2 - 25, h/2); return; }

    const pad = { top: 30, right: 20, bottom: 40, left: 50 };
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

    // X labels (show ~7 evenly spaced)
    ctx.fillStyle = '#94a3b8'; ctx.font = '10px Inter, sans-serif'; ctx.textAlign = 'center';
    const step = Math.max(1, Math.floor(labels.length / 7));
    labels.forEach((l, i) => {
        if (i % step === 0 || i === labels.length - 1) {
            const x = pad.left + i * stepX;
            const parts = l.split('-');
            ctx.fillText(`${parts[2]}/${parts[1]}`, x, h - pad.bottom + 16);
        }
    });
}

// ============================================================
// QR CODES (separate tab for print view)
// ============================================================
async function loadQRCodesTab() {
    const grid = $('#qr-grid-tab');
    if (!grid) return;
    const pf = $('#qr-project-filter').value, search = ($('#qr-search-tab')?.value || '').toLowerCase();
    grid.innerHTML = '<div class="spinner"></div>';

    let url = '/qrcodes/batch';
    if (pf) url += `?project_id=${pf}`;
    const data = await api(url);
    if (!Array.isArray(data)) { grid.innerHTML = '<div class="empty-state">Error loading</div>'; return; }

    let filtered = search ? data.filter(e => e.name.toLowerCase().includes(search) || e.employee_no.toLowerCase().includes(search)) : data;
    if (!filtered.length) { grid.innerHTML = '<div class="empty-state">No employees found</div>'; return; }

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

function initAdmin() {
    loadAdmin();
    loadDivAreas();

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
            else if (target === 'qrcodes') { loadProjects($('#qr-project-filter'), true); loadQRCodesTab(); }
            else if (target === 'trends') { initTrends(); }
            else if (target === 'admin') { if (!adminInit) { initAdmin(); adminInit = true; } else loadAdmin(); }
            else if (target === 'scanner' && !state.scanning) startScanner();
        });
    });

    $('#dash-date').addEventListener('change', refreshDashboard);
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
    $('#qr-search')?.addEventListener('input', () => { clearTimeout(qrT); qrT = setTimeout(loadDashQRCodes, 300); });
    $('#btn-print-qr')?.addEventListener('click', () => window.print());

    let qrT2;
    $('#qr-search-tab')?.addEventListener('input', () => { clearTimeout(qrT2); qrT2 = setTimeout(loadQRCodesTab, 300); });
    $('#qr-project-filter')?.addEventListener('change', loadQRCodesTab);
    $('#btn-print-qr-tab')?.addEventListener('click', () => window.print());

    let workerT;
    $('#worker-search')?.addEventListener('input', () => {
        clearTimeout(workerT);
        workerT = setTimeout(() => {
            const s = ($('#worker-search').value || '').toLowerCase();
            const filtered = s ? _dashWorkers.filter(w => w.name.toLowerCase().includes(s) || w.employee_no.toLowerCase().includes(s)) : _dashWorkers;
            renderWorkerTable(filtered);
        }, 300);
    });

    $('#btn-export').addEventListener('click', async () => {
        const d = $('#dash-date').value || new Date().toISOString().split('T')[0];
        try {
            const { token: dlToken } = await api('/export/download-token', { method: 'POST' });
            let url = `/api/export/attendance?date=${d}&dl_token=${dlToken}`;
            if ($('#dash-project').value) url += `&project_id=${$('#dash-project').value}`;
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
        showApp();
    } else {
        showLogin();
    }
});

if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
