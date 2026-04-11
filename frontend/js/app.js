/**
 * Q-ARMOR Dashboard Controller
 * Discovery and overview
 * PQC assessment, remediation, and NIST matrix
 * Tri-mode probing, history, and baseline
 * PQC classification + agility assessment + SQLite DB
 * Regression detection + CycloneDX 1.7 CBOM
 * PQC labeling + registry + FIPS attestation
 */

const API_BASE = (() => {
    const configured =
        typeof window !== 'undefined' && typeof window.__QARMOR_API_BASE__ === 'string'
            ? window.__QARMOR_API_BASE__.trim()
            : '';
    return configured.endsWith('/') ? configured.slice(0, -1) : configured;
})();
const DEFAULT_AUTH_TOKEN_KEY = 'token';
let authUserContext = null;
let dashboardAuthBootstrap = null;

function getAuthTokenKey() {
    return window.qArmorAuth?.TOKEN_KEY || DEFAULT_AUTH_TOKEN_KEY;
}

function getStoredToken() {
    return localStorage.getItem(getAuthTokenKey());
}

function redirectToAuth(reason = 'login-required') {
    const target = new URL('/auth', window.location.origin);
    target.searchParams.set('reason', reason);
    window.location.replace(target.toString());
}

async function clearStoredSession() {
    try {
        if (window.qArmorAuth?.signOut) {
            await window.qArmorAuth.signOut();
            return;
        }
    } catch (error) {
        console.warn('Supabase sign-out failed:', error.message);
    }

    localStorage.removeItem(getAuthTokenKey());
}

function renderAuthUser(user) {
    const emailEl = document.getElementById('authUserEmail');
    const roleEl = document.getElementById('authUserRole');
    if (!emailEl || !roleEl) return;

    emailEl.textContent = user?.email || 'Authenticated user';
    roleEl.textContent = user?.role ? `Role: ${user.role}` : 'Role: profile pending';
}

function buildAuthorizedHeaders(headers, token) {
    const nextHeaders = new Headers(headers || {});
    if (token && !nextHeaders.has('Authorization')) {
        nextHeaders.set('Authorization', `Bearer ${token}`);
    }
    return nextHeaders;
}

async function ensureDashboardSession() {
    if (dashboardAuthBootstrap) return dashboardAuthBootstrap;

    dashboardAuthBootstrap = (async () => {
        try {
            if (window.qArmorAuthReady) {
                await window.qArmorAuthReady;
            }
        } catch (error) {
            console.warn('Supabase session bootstrap failed:', error.message);
        }

        const token = getStoredToken();
        if (!token) {
            redirectToAuth('missing-token');
            throw new Error('Missing authentication token');
        }

        const response = await fetch(`${API_BASE}/api/auth/me`, {
            headers: buildAuthorizedHeaders(null, token),
        });

        if (!response.ok) {
            await clearStoredSession();
            redirectToAuth(response.status === 401 ? 'session-expired' : 'auth-failed');
            throw new Error(`Session validation failed (${response.status})`);
        }

        authUserContext = await response.json();
        renderAuthUser(authUserContext);
        return authUserContext;
    })();

    return dashboardAuthBootstrap;
}

async function authorizedFetch(resource, options = {}) {
    await ensureDashboardSession();

    const token = getStoredToken();
    const response = await fetch(resource, {
        ...options,
        headers: buildAuthorizedHeaders(options.headers, token),
    });

    if (response.status === 401) {
        await clearStoredSession();
        redirectToAuth('session-expired');
        throw new Error('Authentication expired');
    }

    return response;
}

async function logoutUser() {
    await clearStoredSession();
    redirectToAuth('signed-out');
}

window.logoutUser = logoutUser;

/* ─── Toast Notification ─── */
function showToast(message, type = 'error') {
    const existing = document.querySelector('.toast');
    if (existing) existing.remove();
    const toast = document.createElement('div');
    toast.className = `toast toast--${type}`;
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed; top: 20px; right: 20px; z-index: 9999;
        padding: 14px 24px; border-radius: 10px; font-size: 0.85rem;
        font-weight: 600; font-family: var(--font-sans);
        backdrop-filter: blur(12px); animation: slideIn 0.3s ease;
        max-width: 400px; cursor: pointer;
        ${type === 'error' ? 'background: rgba(255,71,87,0.15); color: #DC2626; border: 1px solid rgba(255,71,87,0.3);' : ''}
        ${type === 'success' ? 'background: rgba(0,255,136,0.15); color: #16A34A; border: 1px solid rgba(0,255,136,0.3);' : ''}
        ${type === 'info' ? 'background: rgba(0,212,255,0.15); color: #2563EB; border: 1px solid rgba(0,212,255,0.3);' : ''}
    `;
    toast.onclick = () => toast.remove();
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
}

/* ─── State ─── */
let scanData = null;
let assessmentData = null;
let remediationData = null;
let trimodeData = null;
let historyData = null;
let classifiedData = null;
let dbScansData = null;
let compareScanOptions = [];
let phase9Data = null;
let nistMatrixData = null;
let enterpriseDashboardData = null;

/* ─── API Calls ─── */
async function apiCall(endpoint, method = 'GET') {
    const resp = await authorizedFetch(`${API_BASE}${endpoint}`, { method });
    if (!resp.ok) {
        let detail = '';
        try {
            const data = await resp.json();
            detail = data?.detail || data?.message || '';
        } catch {
            try {
                detail = await resp.text();
            } catch {
                detail = '';
            }
        }
        throw new Error(detail || `API error: ${resp.status}`);
    }
    return resp.json();
}

document.addEventListener('DOMContentLoaded', () => {
    // Wake Render free-tier instance while auth validates in parallel
    fetch(`${API_BASE}/api/health`).catch(() => {});
    ensureDashboardSession().catch((error) => {
        console.warn('Dashboard auth bootstrap failed:', error.message);
    });
});

function normalizeScanTarget(rawValue, opts = {}) {
    const allowPort = Boolean(opts.allowPort);
    const fallbackPort = Number.isFinite(opts.fallbackPort) ? opts.fallbackPort : 443;
    const raw = String(rawValue || '').trim();
    if (!raw) return null;

    const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;

    try {
        const parsed = new URL(candidate);
        const hostname = (parsed.hostname || '').trim().replace(/\.$/, '');
        if (!hostname) return null;
        const normalized = { hostname };
        if (allowPort) {
            normalized.port = parsed.port ? Number(parsed.port) : fallbackPort;
        }
        return normalized;
    } catch {
        const stripped = raw
            .replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
            .replace(/[/?#].*$/, '')
            .replace(/\.$/, '');
        if (!stripped) return null;

        if (allowPort) {
            const match = stripped.match(/^\[?([^\]]+)\]?(?::(\d+))?$/);
            if (!match) return null;
            return {
                hostname: match[1],
                port: match[2] ? Number(match[2]) : fallbackPort,
            };
        }

        return { hostname: stripped.replace(/:\d+$/, '') };
    }
}

function formatCount(value) {
    const n = Number(value);
    return Number.isFinite(n) ? n.toLocaleString('en-IN') : '—';
}

function formatPercent(value) {
    const n = Number(value);
    return Number.isFinite(n) ? n.toFixed(1) : '0.0';
}

function selectEnterpriseMode(mode, domain = '') {
    const modeSel = document.getElementById('enterpriseModeSelect');
    const domainInput = document.getElementById('enterpriseDomainInput');
    if (modeSel) modeSel.value = mode;
    if (domainInput && domain) domainInput.value = domain;
    onEnterpriseModeChange();
}

function setTextSafe(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function renderEnterpriseNotice(demoMode, dataNotice) {
    const badge = document.getElementById('apiDataNoticeBadge');
    const hint = document.getElementById('enterpriseModeHint');
    if (!badge) return;
    badge.textContent = dataNotice || (demoMode ? 'SIMULATED DATA' : 'LIVE DATA');
    if (demoMode) {
        badge.style.background = 'rgba(255, 179, 0, 0.12)';
        badge.style.color = 'var(--accent-amber)';
        if (hint) {
            hint.textContent = 'Demo mode is active. Switch to Live mode and provide a domain to fetch real data.';
        }
    } else {
        badge.style.background = 'rgba(0, 255, 136, 0.12)';
        badge.style.color = 'var(--accent-green)';
        if (hint) {
            hint.textContent = 'Live mode is active. Data is fetched from real discovery and tri-mode probing.';
        }
    }
}

function onEnterpriseModeChange() {
    const modeSel = document.getElementById('enterpriseModeSelect');
    const domainInput = document.getElementById('enterpriseDomainInput');
    if (!modeSel || !domainInput) return;

    const isLive = modeSel.value === 'live';
    domainInput.style.display = isLive ? '' : 'none';

    if (isLive && !domainInput.value.trim()) {
        const mainDomain = document.getElementById('domainInput')?.value.trim();
        if (mainDomain) domainInput.value = mainDomain;
    }
}

function getEnterpriseContext(opts = {}) {
    const notifyOnError = Boolean(opts.notifyOnError);
    const modeSel = document.getElementById('enterpriseModeSelect');
    const domainInput = document.getElementById('enterpriseDomainInput');
    const mode = (modeSel?.value || 'demo').toLowerCase();

    if (mode !== 'live') {
        return { mode: 'demo', domain: '' };
    }

    const domain = (domainInput?.value || document.getElementById('domainInput')?.value || '').trim();
    if (!domain) {
        if (notifyOnError) showToast('Enter a domain for live enterprise data', 'info');
        return null;
    }

    if (domainInput) domainInput.value = domain;
    return { mode: 'live', domain };
}

function buildEnterpriseEndpoint(endpoint, context, refresh = false) {
    const params = new URLSearchParams();
    params.set('mode', context.mode);
    if (context.domain) params.set('domain', context.domain);
    if (refresh) params.set('refresh', 'true');
    return `${endpoint}?${params.toString()}`;
}

function renderHomeSummaryV2(home) {
    const discovery = home.asset_discovery_summary || {};
    const inventory = home.assets_inventory_summary || {};
    const posture = home.posture_of_pqc || {};
    const cbom = home.cbom_summary || {};

    setTextSafe('homeDomainCount', formatCount(discovery.domain_count));
    setTextSafe('homeIpCount', formatCount(discovery.ip_count));
    setTextSafe('homeSubdomainCount', formatCount(discovery.subdomain_count));
    setTextSafe('homeCloudCount', formatCount(discovery.cloud_asset_count));

    setTextSafe('homeSslCount', formatCount(inventory.ssl_cert_count));
    setTextSafe('homeSoftwareCount', formatCount(inventory.software_count));
    setTextSafe('homeIotCount', formatCount(inventory.iot_device_count));
    setTextSafe('homeLoginFormCount', formatCount(inventory.login_form_count));

    setTextSafe('homePqcAdoptionPct', `${formatPercent(posture.pqc_adoption_pct)}%`);
    setTextSafe('homeTransitionPct', `${formatPercent(posture.transition_pct)}%`);

    setTextSafe('homeVulnComponents', formatCount(cbom.vulnerable_component_count));
    setTextSafe('homeWeakCrypto', formatCount(cbom.weak_crypto_count));

    // Phase 8 — overview summary cards (home data portion)
    _updateOverviewCards_Home(discovery, inventory, posture, cbom);
}

function _updateOverviewCards_Home(discovery, inventory, posture, cbom) {
    setTextSafe('ovDomains',    formatCount(discovery.domain_count    ?? 0));
    setTextSafe('ovIPs',        formatCount(discovery.ip_count        ?? 0));
    setTextSafe('ovCloud',      formatCount(discovery.cloud_asset_count ?? 0));
    setTextSafe('ovVulnComp',   formatCount(cbom.vulnerable_component_count ?? 0));
    setTextSafe('ovWeakCrypto', formatCount(cbom.weak_crypto_count    ?? 0));
    setTextSafe('ovSslCerts',   formatCount(inventory.ssl_cert_count  ?? 0));

    const pqcPct   = posture.pqc_adoption_pct   ?? 0;
    const transPct = posture.transition_pct      ?? 0;
    setTextSafe('ovPqcPct',   `${Math.round(pqcPct)}%`);
    setTextSafe('ovTransPct', `${Math.round(transPct)}%`);
    // Animate progress bars after a brief delay so they're visible
    setTimeout(() => {
        const pBar = document.getElementById('ovPqcBar');
        const tBar = document.getElementById('ovTransBar');
        if (pBar) pBar.style.width = `${Math.min(100, Math.round(pqcPct))}%`;
        if (tBar) tBar.style.width = `${Math.min(100, Math.round(transPct))}%`;
    }, 120);
}

function renderAssetDiscoveryV2(domains, ssl, ip, software, graph) {
    const domainItems = domains.items || [];
    const sslItems = ssl.items || [];
    const ipItems = ip.items || [];
    const softwareItems = software.items || [];
    const nodes = graph.nodes || [];
    const edges = graph.edges || [];

    setTextSafe('domainsCount', formatCount(domainItems.length));
    setTextSafe('sslCount', formatCount(sslItems.length));
    setTextSafe('ipCount', formatCount(ipItems.length));
    setTextSafe('softwareCount', formatCount(softwareItems.length));
    setTextSafe('networkNodesCount', formatCount(nodes.length));
    setTextSafe('networkEdgesCount', formatCount(edges.length));

    const statusCounts = nodes.reduce((acc, node) => {
        const key = node.pqc_status || 'UNKNOWN';
        acc[key] = (acc[key] || 0) + 1;
        return acc;
    }, {});

    const statusSummary = Object.entries(statusCounts)
        .sort((a, b) => b[1] - a[1])
        .map(([status, count]) => `<span><strong>${escHtml(status)}</strong>: ${count}</span>`)
        .join(' · ');

    const networkStatus = document.getElementById('networkStatusSummary');
    if (networkStatus) {
        networkStatus.innerHTML = statusSummary || 'No network status distribution available.';
    }

    // NEW UI FEATURES: Global State Update
    if (!window.adState) {
        window.adState = {
            data: { domains: [], ssl: [], ip: [], software: [] },
            currentTab: 'domains',
            search: '',
            startDate: '',
            endDate: '',
            filter: 'All'
        };
    }
    
    window.adState.data = {
        domains: domainItems,
        ssl: sslItems,
        ip: ipItems,
        software: softwareItems
    };

    const assetSamples = document.getElementById('assetSamples');
    if (assetSamples) {
        // Prepare container for tables
        assetSamples.className = '';
        assetSamples.style.marginTop = '15px';
        assetSamples.style.paddingTop = '15px';
        assetSamples.style.borderTop = '1px solid #7B003033';
        
        assetSamples.innerHTML = `
            <div id="adHeaderUI"></div>
            <div id="adFilterRow" style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px;"></div>
            <div id="adTableContainer" style="overflow-x: auto; max-height: 480px; border: 1px solid #eaeaea; border-radius: 4px; background: #fff;"></div>
        `;
        renderAdHeader();
        renderAdTable();
    }
}

// ─── NEW INTERACTIVE ASSET DISCOVERY FRONTEND ───
window.setAdTab = function(tab) {
    window.adState.currentTab = tab;
    window.adState.filter = 'All'; // Reset filter on tab change
    renderAdHeader();
    renderAdTable();
};

window.setAdFilter = function(filter) {
    window.adState.filter = filter;
    renderAdTable(); 
};

function renderAdHeader() {
    const headerEl = document.getElementById('adHeaderUI');
    if (!headerEl) return;
    
    const state = window.adState;
    const counts = {
        domains: state.data.domains.length,
        ssl: state.data.ssl.length,
        ip: state.data.ip.length,
        software: state.data.software.length
    };

    const buildPill = (key, label, count) => {
        const isActive = state.currentTab === key;
        const bg = isActive ? '#7B0030' : '#ffffff';
        const color = isActive ? '#ffffff' : '#7B0030';
        const border = isActive ? '1px solid #7B0030' : '1px solid #7B003040';
        return `<button onclick="window.setAdTab('${key}')" style="background: ${bg}; color: ${color}; border: ${border}; border-radius: 16px; padding: 4px 12px; font-size: 12px; font-weight: 500; cursor: pointer; transition: all 0.2s;">${label} (${count})</button>`;
    };

    headerEl.innerHTML = `
        <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px;">
            ${buildPill('domains', 'Domains', counts.domains)}
            ${buildPill('ssl', 'SSL', counts.ssl)}
            ${buildPill('ip', 'IP Address/Subnets', counts.ip)}
            ${buildPill('software', 'Software', counts.software)}
        </div>
        <div style="display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 12px; align-items: center; background: #f9f9f9; padding: 8px; border-radius: 6px;">
            <input type="text" value="${escHtml(state.search)}" placeholder="Search domain, URL, contact, IoC or other..." style="flex: 1; padding: 6px 10px; border: 1px solid #ddd; border-radius: 4px; min-width: 200px; font-size: 12px;" oninput="window.adState.search = this.value; renderAdTable();">
            <div style="display: flex; gap: 4px; align-items: center;">
                <label style="font-size: 11px; color: #666; font-weight: bold;">Start Date:</label>
                <input type="date" value="${state.startDate}" style="padding: 4px 8px; border: 1px solid #ddd; border-radius: 4px; font-size:11px;" onchange="window.adState.startDate = this.value; renderAdTable();">
            </div>
            <div style="display: flex; gap: 4px; align-items: center;">
                <label style="font-size: 11px; color: #666; font-weight: bold;">End Date:</label>
                <input type="date" value="${state.endDate}" style="padding: 4px 8px; border: 1px solid #ddd; border-radius: 4px; font-size:11px;" onchange="window.adState.endDate = this.value; renderAdTable();">
            </div>
        </div>
    `;
}

function renderAdTable() {
    const state = window.adState;
    const rawData = state.data[state.currentTab] || [];
    
    // Assign generic _uiStatus logic for pills
    const filterCounts = { 'New': 0, 'False Positive': 0, 'Confirmed': 0, 'All': rawData.length };
    
    rawData.forEach(item => {
        let st = item.status || 'New';
        if (st === 'UNKNOWN') st = 'New';
        if (st === 'false_positive' || st === 'FALSE_POSITIVE') st = 'False Positive';
        if (st === 'confirmed' || st === 'CONFIRMED' || String(st).includes('QUANTUM') || String(st).includes('PQC')) st = 'Confirmed';
        if (st !== 'New' && st !== 'False Positive' && st !== 'Confirmed') st = 'New'; // map stragglers
        
        filterCounts[st]++;
        item._uiStatus = st;
    });

    const filterRow = document.getElementById('adFilterRow');
    if (filterRow) {
        let fHtml = '';
        ['New', 'False Positive', 'Confirmed', 'All'].forEach(f => {
            const isActive = state.filter === f;
            const bg = isActive ? '#7B0030' : '#f5f5f5';
            const color = isActive ? '#ffffff' : '#444';
            const border = isActive ? '1px solid #7B0030' : '1px solid #ccc';
            fHtml += `<button onclick="window.setAdFilter('${f}')" style="background: ${bg}; color: ${color}; border: ${border}; border-radius: 4px; padding: 4px 10px; font-size: 11px; cursor: pointer; display: flex; align-items: center; gap: 6px;">
                ${f} <span style="background: ${isActive ? 'rgba(255,255,255,0.2)' : 'rgba(0,0,0,0.08)'}; padding: 1px 5px; border-radius: 10px; font-size: 10px;">${filterCounts[f]}</span>
            </button>`;
        });
        filterRow.innerHTML = fHtml;
    }

    // Apply Filter Row
    let filtered = rawData.filter(d => state.filter === 'All' || d._uiStatus === state.filter);
    
    // Apply Search Input
    if (state.search.trim()) {
        const q = state.search.trim().toLowerCase();
        filtered = filtered.filter(item => {
            return Object.values(item).some(val => String(val).toLowerCase().includes(q));
        });
    }

    // Apply Dates
    const parseDate = (isoOrStr) => {
        if (!isoOrStr) return new Date();
        const pd = new Date(isoOrStr);
        return isNaN(pd.getTime()) ? new Date() : pd;
    };
    if (state.startDate) {
        filtered = filtered.filter(item => parseDate(item.timestamp || item.creation_date || item.detection_date || item.last_seen || item.first_seen) >= new Date(state.startDate));
    }
    if (state.endDate) {
        filtered = filtered.filter(item => {
            let d = parseDate(item.timestamp || item.creation_date || item.detection_date || item.last_seen || item.first_seen);
            d.setHours(23,59,59);
            return d <= new Date(state.endDate);
        });
    }

    const tableContainer = document.getElementById('adTableContainer');
    if (!tableContainer) return;

    if (filtered.length === 0) {
        tableContainer.innerHTML = '<div style="padding: 30px; text-align: center; color: #666; font-size: 13px; font-style: italic;">No assets match your search criteria.</div>';
        return;
    }

    const thStyle = "text-align: left; padding: 10px 12px; border-bottom: 2px solid #ddd; font-size: 12px; color: #444; white-space: nowrap; background: #fafafa; position: sticky; top: 0;";
    const tdStyle = "padding: 8px 12px; border-bottom: 1px solid #eee; font-size: 12px; color: #333; max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;";
    
    const formatDate = (iso) => {
        if (!iso) return '-';
        try { 
            const d = new Date(iso);
            if(isNaN(d.getTime())) return iso;
            return d.toISOString().slice(0,10); 
        } catch(e) { return iso; }
    };

    let thead = '';
    let rows = '';

    if (state.currentTab === 'domains') {
        thead = `<tr>
            <th style="${thStyle}">Detection Date</th>
            <th style="${thStyle}">Domain Name</th>
            <th style="${thStyle}">Registration Date</th>
            <th style="${thStyle}">Registrar</th>
            <th style="${thStyle}">Company Name</th>
        </tr>`;
        rows = filtered.map(d => `<tr>
            <td style="${tdStyle}">${formatDate(d.timestamp || d.detection_date || d.last_seen)}</td>
            <td style="${tdStyle}" title="${escHtml(d.domain_name)}"><strong>${escHtml(d.domain_name || '-')}</strong></td>
            <td style="${tdStyle}">${formatDate(d.creation_date || d.registration_date)}</td>
            <td style="${tdStyle}">${escHtml(d.registrar || 'NameCheap')}</td>
            <td style="${tdStyle}">${escHtml(d.organization || d.company_name || '-')}</td>
        </tr>`).join('');
    } else if (state.currentTab === 'ssl') {
        thead = `<tr>
            <th style="${thStyle}">Detection Date</th>
            <th style="${thStyle}">SSL SHA Fingerprint</th>
            <th style="${thStyle}">Valid From</th>
            <th style="${thStyle}">Common Name</th>
            <th style="${thStyle}">Company Name</th>
            <th style="${thStyle}">Certificate Authority</th>
        </tr>`;
        rows = filtered.map(d => `<tr>
            <td style="${tdStyle}">${formatDate(d.timestamp || d.detection_date || d.last_seen)}</td>
            <td style="${tdStyle}" title="${escHtml(d.ssl_sha_fingerprint)}"><code style="background:#f5f5f5;padding:2px 4px;border-radius:3px;">${escHtml((d.ssl_sha_fingerprint || '-').substring(0, 20))}...</code></td>
            <td style="${tdStyle}">${formatDate(d.valid_from)}</td>
            <td style="${tdStyle}" title="${escHtml(d.common_name)}"><strong>${escHtml(d.common_name || '-')}</strong></td>
            <td style="${tdStyle}">${escHtml(d.organization || d.company_name || '-')}</td>
            <td style="${tdStyle}">${escHtml(d.issuer_common_name || d.certificate_authority || '-')}</td>
        </tr>`).join('');
    } else if (state.currentTab === 'ip') {
        thead = `<tr>
            <th style="${thStyle}">Detection Date</th>
            <th style="${thStyle}">IP Address</th>
            <th style="${thStyle}">Ports</th>
            <th style="${thStyle}">Subnet</th>
            <th style="${thStyle}">Cloud Provider</th>
            <th style="${thStyle}">Pool</th>
            <th style="${thStyle}">Netname</th>
            <th style="${thStyle}">Company</th>
        </tr>`;
        const _cloudBadgeColor = { aws:'#ff9900', azure:'#0078d4', microsoft:'#0078d4', gcp:'#4285f4', cloudflare:'#f48120', fastly:'#e8131a', akamai:'#009bde', digitalocean:'#0080ff', oracle:'#c74634', alibaba:'#ff6a00', self_hosted:'#6b7280', unknown:'#6b7280' };
        rows = filtered.map(d => {
            const cp = d.cloud_provider || 'unknown';
            const cpColor = _cloudBadgeColor[cp] || '#6b7280';
            const cpLabel = d.cloud_display_name || (cp === 'self_hosted' ? 'Self-Hosted' : cp === 'unknown' ? '—' : cp.toUpperCase());
            const poolLabel = d.pool === 'cloud' ? '☁ Cloud' : d.pool === 'self_hosted' ? '⬛ Self-Hosted' : '—';
            const poolColor = d.pool === 'cloud' ? '#7c3aed' : '#6b7280';
            return `<tr>
            <td style="${tdStyle}">${formatDate(d.timestamp || d.detection_date || d.last_seen)}</td>
            <td style="${tdStyle}"><strong>${escHtml(d.ip_address || '-')}</strong></td>
            <td style="${tdStyle}">${escHtml(Array.isArray(d.ports) ? d.ports.join(', ') : (d.port || '443'))}</td>
            <td style="${tdStyle}">${escHtml(d.subnet || (d.ip_address ? d.ip_address.split('.').slice(0,3).join('.')+'.0/24' : '-'))}</td>
            <td style="${tdStyle}"><span style="background:${cpColor}18;color:${cpColor};padding:1px 7px;border-radius:4px;font-size:0.7rem;font-weight:700;">${escHtml(cpLabel)}</span></td>
            <td style="${tdStyle}"><span style="color:${poolColor};font-weight:600;font-size:0.75rem;">${poolLabel}</span></td>
            <td style="${tdStyle}">${escHtml(d.netname || d.cloud_display_name || '—')}</td>
            <td style="${tdStyle}">${escHtml(d.organization || d.company || '-')}</td>
        </tr>`;
        }).join('');
    } else if (state.currentTab === 'software') {
        thead = `<tr>
            <th style="${thStyle}">Detection Date</th>
            <th style="${thStyle}">Product</th>
            <th style="${thStyle}">Version</th>
            <th style="${thStyle}">Type</th>
            <th style="${thStyle}">Port</th>
            <th style="${thStyle}">Host</th>
            <th style="${thStyle}">Company Name</th>
        </tr>`;
        rows = filtered.map(d => `<tr>
            <td style="${tdStyle}">${formatDate(d.timestamp || d.detection_date || d.last_seen)}</td>
            <td style="${tdStyle}"><strong>${escHtml(d.product || '-')}</strong></td>
            <td style="${tdStyle}">${escHtml(d.version || '-')}</td>
            <td style="${tdStyle}">${escHtml(d.type || 'Web Server')}</td>
            <td style="${tdStyle}">${escHtml(d.port || '443')}</td>
            <td style="${tdStyle}" title="${escHtml(d.host)}">${escHtml(d.host || '-')}</td>
            <td style="${tdStyle}">${escHtml(d.organization || d.company_name || '-')}</td>
        </tr>`).join('');
    }

    tableContainer.innerHTML = `<table style="width: 100%; border-collapse: collapse;">
        <thead>${thead}</thead>
        <tbody>${rows}</tbody>
    </table>`;
}


function renderCyberPqcV2(cyber, heatmap, negotiation) {
    setTextSafe('cyberEnterpriseScore', formatCount(cyber.enterprise_score));
    setTextSafe('cyberTier', cyber.tier || '—');
    setTextSafe('cyberDisplayTier', cyber.display_tier || cyber.tier_label || '—');

    // Phase 8 — overview summary cards (cyber data portion)
    _updateOverviewCards_Cyber(cyber);

    const policies = negotiation.policies || {};
    const entries = Object.entries(policies);
    setTextSafe('negotiationCount', formatCount(entries.length));

    const heatmapContainer = document.getElementById('heatmapTableContainer');
    if (heatmapContainer) {
        const grid = heatmap.grid || {};
        const rows = [
            ['pqc_ready', 'PQC Ready'],
            ['transition', 'Transition'],
            ['legacy', 'Legacy'],
        ];
        const cols = [
            ['strong', 'Strong'],
            ['medium', 'Medium'],
            ['weak', 'Weak'],
        ];

        heatmapContainer.innerHTML = rows.map(([rowKey, rowLabel]) => {
            const cells = cols.map(([colKey, colLabel]) => {
                const count = grid?.[rowKey]?.[colKey]?.count ?? 0;
                return `<div class="heatmap-cell"><span>${colLabel}</span><strong>${count}</strong></div>`;
            }).join('');
            return `<div class="heatmap-row"><div class="heatmap-row-label">${rowLabel}</div><div class="heatmap-row-cells">${cells}</div></div>`;
        }).join('');
    }

    const negotiationContainer = document.getElementById('negotiationTableContainer');
    if (negotiationContainer) {
        if (!entries.length) {
            negotiationContainer.textContent = 'No negotiation policies available.';
        } else {
            const top = [...entries]
                .sort((a, b) => (a[1].negotiation_security_score || 0) - (b[1].negotiation_security_score || 0))
                .slice(0, 5)
                .map(([host, policy]) => {
                    const tier = policy.negotiation_tier || 'UNKNOWN';
                    const score = policy.negotiation_security_score ?? 0;
                    return `<div><strong>${escHtml(host)}</strong> · ${escHtml(tier)} · score ${score}</div>`;
                })
                .join('');
            negotiationContainer.innerHTML = top;
        }
    }
}

/* ─── Tab status badges ─── */
function _setTabBadge(tabName, state) {
    const btn = document.querySelector(`.tab-btn[data-tab="${tabName}"]`);
    if (!btn) return;
    let badge = btn.querySelector('.tab-badge');
    if (!badge) {
        badge = document.createElement('span');
        badge.className = 'tab-badge';
        btn.appendChild(badge);
    }
    badge.className = 'tab-badge';
    if (state === 'loading') {
        badge.classList.add('tab-badge--loading');
        badge.textContent = '●';
    } else if (state === 'ready') {
        badge.classList.add('tab-badge--ready');
        badge.textContent = '✓';
        setTimeout(() => badge.remove(), 2500);
    } else {
        badge.remove();
    }
}

/* ─── Primary / All Assets toggle ─── */
function setAssetView(view) {
    const pa = document.getElementById('togglePrimaryAssets');
    const aa = document.getElementById('toggleAllAssets');
    if (pa) pa.classList.toggle('tab-btn--active', view === 'primary');
    if (aa) aa.classList.toggle('tab-btn--active', view === 'all');
    if (view === 'all') {
        document.getElementById('assetTableContainer')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

/* ─── Section-level loading indicator ─── */
function _showStatsLoading(visible) {
    const badge = document.getElementById('statsLoadingBadge');
    if (badge) badge.style.display = visible ? '' : 'none';
}

/* ─── Dashboard Cache (localStorage) ─── */
const _DASHBOARD_CACHE_KEY = 'qarmor_dashboard_cache';
const _DASHBOARD_CACHE_MAX_AGE = 10 * 60 * 1000; // 10 minutes

function _saveDashboardCache(data) {
    try {
        const payload = JSON.stringify({ ts: Date.now(), data });
        if (payload.length > 2 * 1024 * 1024) return; // 2MB guard
        localStorage.setItem(_DASHBOARD_CACHE_KEY, payload);
    } catch (_) { /* quota exceeded — ignore */ }
}

function _loadDashboardCache() {
    try {
        const raw = localStorage.getItem(_DASHBOARD_CACHE_KEY);
        if (!raw) return null;
        const { ts, data } = JSON.parse(raw);
        if (Date.now() - ts > _DASHBOARD_CACHE_MAX_AGE) return null;
        return data;
    } catch (_) { return null; }
}

function _renderCachedDashboard(cached) {
    if (cached.home) {
        renderEnterpriseNotice(cached.home.demo_mode, cached.home.data_notice);
        renderHomeSummaryV2(cached.home);
    }
    if (cached.domains || cached.ssl || cached.ip || cached.software || cached.graph) {
        renderAssetDiscoveryV2(cached.domains, cached.ssl, cached.ip, cached.software, cached.graph);
    }
    if (cached.cyber || cached.heatmap || cached.negotiation) {
        renderCyberPqcV2(cached.cyber, cached.heatmap, cached.negotiation);
        if (cached.negotiation) assessmentNegotiationPolicies = cached.negotiation.policies || {};
    }
    enterpriseDashboardData = cached;
    window.enterpriseDashboardData = cached;
}

async function loadEnterpriseDashboardData(opts = {}) {
    const notifyOnError = Boolean(opts.notifyOnError);
    const forceRefresh = Boolean(opts.forceRefresh);
    const context = getEnterpriseContext({ notifyOnError });
    if (!context) return;

    try {
        const home = await apiCall(buildEnterpriseEndpoint('/api/home/summary', context, forceRefresh));

        const [
            domains,
            ssl,
            ip,
            software,
            graph,
            cyber,
            heatmap,
            negotiation,
        ] = await Promise.all([
            apiCall(buildEnterpriseEndpoint('/api/assets/domains', context)),
            apiCall(buildEnterpriseEndpoint('/api/assets/ssl', context)),
            apiCall(buildEnterpriseEndpoint('/api/assets/ip', context)),
            apiCall(buildEnterpriseEndpoint('/api/assets/software', context)),
            apiCall(buildEnterpriseEndpoint('/api/assets/network-graph', context)),
            apiCall(buildEnterpriseEndpoint('/api/cyber-rating', context)),
            apiCall(buildEnterpriseEndpoint('/api/pqc/heatmap', context)),
            apiCall(buildEnterpriseEndpoint('/api/pqc/negotiation', context)),
        ]);

        enterpriseDashboardData = { home, domains, ssl, ip, software, graph, cyber, heatmap, negotiation };
        window.enterpriseDashboardData = enterpriseDashboardData;
        renderEnterpriseNotice(home.demo_mode, home.data_notice);
        renderHomeSummaryV2(home);
        renderAssetDiscoveryV2(domains, ssl, ip, software, graph);
        renderCyberPqcV2(cyber, heatmap, negotiation);
    } catch (e) {
        console.warn('Enterprise data API fetch failed:', e);
        if (notifyOnError) showToast('Failed to refresh enterprise APIs: ' + e.message, 'error');
    }
}

async function refreshNewDashboardApis() {
    _showStatsLoading(true);
    try {
        await loadEnterpriseDashboardData({ notifyOnError: true, forceRefresh: true });
        showToast('Enterprise dashboard APIs refreshed', 'success');
    } finally {
        _showStatsLoading(false);
    }
}

async function generateApiReport() {
    const reportType = document.getElementById('reportTypeSelect')?.value || 'executive';
    const reportFormat = document.getElementById('reportFormatSelect')?.value || 'json';
    const preview = document.getElementById('reportPreview');
    const badge = document.getElementById('reportMetaBadge');
    const context = getEnterpriseContext({ notifyOnError: true });
    if (!context) return;

    showLoading(`Generating ${reportType} report (${reportFormat})...`);
    try {
        const params = new URLSearchParams({
            report_type: reportType,
            format: reportFormat,
            mode: context.mode,
        });
        if (context.domain) params.set('domain', context.domain);
        const endpoint = `/api/reporting/generate?${params.toString()}`;
        const payload = await apiCall(endpoint);

        if (badge) {
            badge.textContent = `${payload.report_type} • ${payload.data_notice || 'DATA'} • ${payload.generated_at || 'now'}`;
        }

        if (preview) {
            if (reportFormat === 'html') {
                preview.textContent = payload.data?.html || '<empty html payload>';
            } else {
                preview.textContent = JSON.stringify(payload.data, null, 2);
            }
        }

        showToast('Report generated successfully', 'success');
    } catch (e) {
        if (preview) preview.textContent = 'Report generation failed.';
        if (badge) badge.textContent = 'Report generation failed';
        showToast('Report generation failed: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

/* ─── Exponential progress bar ─── */
let _loadingRafId  = null;   // requestAnimationFrame handle
let _loadingPct    = 0;      // current displayed %
let _loadingTarget = 0;      // target % (crawls toward 94 then holds)

function _tickLoadingBar() {
    const fill = document.getElementById('loadingBarFill');
    const pctEl = document.getElementById('loadingPct');
    if (!fill || !pctEl) return;

    // Exponential ease: large jumps early, tiny crawl near the cap
    // Formula: step = k * (cap - current)^1.6  — fast start, asymptotic approach
    const cap  = 94;
    const gap  = Math.max(0, cap - _loadingPct);
    const step = Math.max(0.04, 0.008 * Math.pow(gap, 1.6));
    _loadingPct = Math.min(cap, _loadingPct + step * 0.3);

    fill.style.width  = _loadingPct.toFixed(1) + '%';
    pctEl.textContent = Math.floor(_loadingPct) + '%';

    if (_loadingPct < cap) {
        _loadingRafId = requestAnimationFrame(_tickLoadingBar);
    }
}

function showLoading(msg = 'Scanning cryptographic surface...') {
    const overlay = document.getElementById('loadingOverlay');
    overlay.querySelector('.loading-text').textContent = msg;

    // Reset bar to 0 before showing
    _loadingPct    = 0;
    _loadingTarget = 0;
    const fill  = document.getElementById('loadingBarFill');
    const pctEl = document.getElementById('loadingPct');
    if (fill)  { fill.style.transition = 'none'; fill.style.width = '0%'; }
    if (pctEl) pctEl.textContent = '0%';

    overlay.classList.add('active');

    // Kick off the exponential crawl after a tiny delay so the reset paint lands
    cancelAnimationFrame(_loadingRafId);
    setTimeout(() => {
        if (fill) fill.style.transition = 'width 0.28s ease-out';
        _loadingRafId = requestAnimationFrame(_tickLoadingBar);
    }, 60);
}

function hideLoading() {
    // Snap to 100% then fade the overlay out
    cancelAnimationFrame(_loadingRafId);
    const fill  = document.getElementById('loadingBarFill');
    const pctEl = document.getElementById('loadingPct');
    if (fill)  { fill.style.transition = 'width 0.18s ease-out'; fill.style.width = '100%'; }
    if (pctEl) pctEl.textContent = '100%';

    setTimeout(() => {
        document.getElementById('loadingOverlay').classList.remove('active');
        // Reset silently after fade finishes
        setTimeout(() => {
            _loadingPct = 0;
            if (fill)  { fill.style.transition = 'none'; fill.style.width = '0%'; }
            if (pctEl) pctEl.textContent = '0%';
        }, 420);
    }, 200);
}

/* ─── Tab Navigation ─── */
function switchTab(tabName) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('tab-btn--active'));
    document.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('tab-content--active'));

    const btn = document.querySelector(`.tab-btn[data-tab="${tabName}"]`);
    const content = document.getElementById(`tab-${tabName}`);
    if (btn) btn.classList.add('tab-btn--active');
    if (content) content.classList.add('tab-content--active');
}

/* ─── Demo Scan ─── */
async function runDemoScan() {
    showLoading('Running demo scan on simulated bank assets...');
    try {
        selectEnterpriseMode('demo');
        scanData = await apiCall('/api/scan/demo');
        window.scanData = scanData;   // expose for inventory tab
        latestScanPayload = scanData;
        latestScanKey = '/api/scan/latest';
        renderDashboard(scanData);
        document.getElementById('btnExportCBOM').disabled = false;
        document.getElementById('btnExportPDF').disabled = false;
        const cdxaBtn = document.getElementById('btnExportCDXA');
        if (cdxaBtn) cdxaBtn.disabled = false;
        showToast(`Scan complete — ${scanData.total_assets} assets analyzed`, 'success');

        // Auto-fetch Phase 2 assessment
        fetchPhase2Assessment();

        // Auto-fetch Phase 6 tri-mode demo data
        fetchTrimodeDemoData();

        // Refresh new API-backed enterprise dashboard
        await loadEnterpriseDashboardData();

        // Auto-populate Regression & Certification tab
        try { await runPhase9Demo(); } catch(e) { console.warn('Phase 9 auto-run:', e.message); }
    } catch (e) {
        showToast('Scan failed: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

/* ─── Domain Scan ─── */
async function scanDomain() {
    const domainInput = document.getElementById('domainInput');
    const normalized = normalizeScanTarget(domainInput?.value);
    if (!normalized?.hostname) { showToast('Please enter a valid domain', 'info'); return; }
    const domain = normalized.hostname;
    if (domainInput) domainInput.value = domain;
    selectEnterpriseMode('live', domain);
    const enterpriseDomainInput = document.getElementById('enterpriseDomainInput');
    if (enterpriseDomainInput && !enterpriseDomainInput.value.trim()) {
        enterpriseDomainInput.value = domain;
    }
    // Reset all tab-level caches so each tab reloads fresh data for this scan
    enterpriseDashboardData = null;
    assessmentData = null;
    trimodeData = null;
    phase9Data = null;
    const fullScan = document.getElementById('fullScanToggle')?.checked;
    await scanDomainStreaming(domain, fullScan);
}

/* ─── Streaming Domain Scan (SSE) ─── */
async function scanDomainStreaming(domain, fullScan = false) {
    const scanBtn = document.querySelector('.scan-input-section button');
    const origLabel = scanBtn?.textContent;
    if (scanBtn) { scanBtn.disabled = true; scanBtn.textContent = 'Scanning\u2026'; }

    const STATUS_ICONS = {
        FULLY_QUANTUM_SAFE: '\u2736',      // ✦ star
        PQC_TRANSITION:      '\u25D1',      // ◑ half circle
        QUANTUM_VULNERABLE:  '\u26A0',      // ⚠
        CRITICALLY_VULNERABLE: '\u2716',    // ✖
        ERROR:               '\u2716',
    };

    // Pre-clear the asset table so live rows start appearing immediately
    const tableContainer = document.getElementById('assetTableContainer');
    if (tableContainer) tableContainer.innerHTML = '';

    _showScanBanner('Discovering assets for ' + domain + '\u2026', 0, '');

    const url = `/api/scan/stream/${encodeURIComponent(domain)}${fullScan ? '?full_scan=true' : ''}`;
    const es = new EventSource(url);
    let liveRowCount = 0;

    return new Promise((resolve, reject) => {
        es.onmessage = (evt) => {
            let event;
            try { event = JSON.parse(evt.data); } catch { return; }

            if (event.type === 'status') {
                _showScanBanner(event.message, event.pct, '');

            } else if (event.type === 'discovered') {
                _showScanBanner(
                    `Found ${event.count} asset${event.count !== 1 ? 's' : ''} \u2014 probing TLS\u2026`,
                    event.pct,
                    `0\u2009/\u2009${event.count}`,
                );

            } else if (event.type === 'asset_scanned') {
                const icon = STATUS_ICONS[event.status] || '\u25CB';
                _showScanBanner(
                    `${icon}\u2009${event.asset}`,
                    event.pct,
                    `${event.done}\u2009/\u2009${event.total} scanned`,
                );
                _appendLiveAssetRow(event, ++liveRowCount);

            } else if (event.type === 'complete') {
                es.close();
                scanData = event.data;
                window.scanData = scanData;
                latestScanPayload = scanData;
                latestScanKey = '/api/scan/latest';
                _hideScanBanner();
                renderDashboard(scanData);
                document.getElementById('btnExportCBOM').disabled = false;
                document.getElementById('btnExportPDF').disabled = false;
                showToast(`Scan complete \u2014 ${scanData.total_assets} assets analyzed`, 'success');
                resolve(scanData);

            } else if (event.type === 'error') {
                es.close();
                _hideScanBanner();
                showToast(event.message || 'Scan failed', 'error');
                reject(new Error(event.message || 'Scan error'));
            }
        };

        es.onerror = () => {
            es.close();
            _hideScanBanner();
            showToast('Streaming connection lost', 'error');
            reject(new Error('EventSource error'));
        };
    }).finally(() => {
        if (scanBtn) { scanBtn.disabled = false; scanBtn.textContent = origLabel || 'Scan Domain'; }
    });
}

function _showScanBanner(phase, pct, counter) {
    const b = document.getElementById('scanStreamBanner');
    if (!b) return;
    b.style.display = 'block';
    const phaseEl = document.getElementById('scanBannerPhase');
    const fillEl  = document.getElementById('scanBannerFill');
    const pctEl   = document.getElementById('scanBannerPct');
    const cntEl   = document.getElementById('scanBannerCounter');
    if (phaseEl) phaseEl.textContent = phase;
    if (fillEl)  fillEl.style.width  = pct + '%';
    if (pctEl)   pctEl.textContent   = Math.floor(pct) + '%';
    if (cntEl && counter !== undefined) cntEl.textContent = counter;
}

function _hideScanBanner() {
    const b = document.getElementById('scanStreamBanner');
    if (b) b.style.display = 'none';
}

function _appendLiveAssetRow(event, rowNum) {
    const container = document.getElementById('assetTableContainer');
    if (!container) return;
    let tbody = container.querySelector('tbody#liveAssetBody');
    if (!tbody) {
        container.innerHTML = `
            <table class="asset-table" style="width:100%">
                <thead><tr>
                    <th style="width:2.5rem">#</th>
                    <th>Hostname</th>
                    <th style="width:4rem">Port</th>
                    <th style="width:11rem">Status</th>
                </tr></thead>
                <tbody id="liveAssetBody"></tbody>
            </table>`;
        tbody = container.querySelector('tbody#liveAssetBody');
    }
    const STATUS_CLASS = {
        FULLY_QUANTUM_SAFE:   'safe',
        PQC_TRANSITION:       'transition',
        QUANTUM_VULNERABLE:   'vulnerable',
        CRITICALLY_VULNERABLE:'critical',
        ERROR:                'unknown',
    };
    const cls   = STATUS_CLASS[event.status] || 'unknown';
    const label = (event.status || 'UNKNOWN').replace(/_/g, '\u00A0');
    const row   = document.createElement('tr');
    row.innerHTML = `
        <td style="color:var(--text-dim);font-size:0.75rem;text-align:center;">${rowNum}</td>
        <td style="font-family:var(--font-mono);font-size:0.82rem;">${event.asset}</td>
        <td style="font-size:0.8rem;text-align:center;">${event.port}</td>
        <td><span class="status-badge status-badge--${cls}" style="font-size:0.71rem;">${label}</span></td>`;
    tbody.appendChild(row);
    // Scroll last row into view if table is already visible
    row.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}

/* ─── Single Host Scan ─── */
async function scanSingleHost() {
    const hostInput = document.getElementById('singleHostInput');
    const normalized = normalizeScanTarget(hostInput?.value, { allowPort: true, fallbackPort: 443 });
    if (!normalized?.hostname) { showToast('Please enter a valid hostname', 'info'); return; }
    const host = normalized.hostname;
    const port = normalized.port || 443;
    if (hostInput) {
        hostInput.value = port === 443 ? host : `${host}:${port}`;
    }
    selectEnterpriseMode('live', host);
    // Reset tab-level caches for fresh loads
    enterpriseDashboardData = null;
    assessmentData = null;
    trimodeData = null;
    phase9Data = null;
    showLoading(`Probing ${host}${port === 443 ? '' : `:${port}`}...`);
    try {
        const result = await apiCall(`/api/scan/single/${encodeURIComponent(host)}?port=${port}`);
        scanData = {
            total_assets: 1,
            fully_quantum_safe: result.q_score.status === 'FULLY_QUANTUM_SAFE' ? 1 : 0,
            pqc_transition: result.q_score.status === 'PQC_TRANSITION' ? 1 : 0,
            quantum_vulnerable: result.q_score.status === 'QUANTUM_VULNERABLE' ? 1 : 0,
            critically_vulnerable: result.q_score.status === 'CRITICALLY_VULNERABLE' ? 1 : 0,
            average_q_score: result.q_score.total,
            results: [result],
            remediation_roadmap: [],
            labels: [],
        };
        window.scanData = scanData;   // expose for inventory tab
        latestScanPayload = scanData;
        latestScanKey = '/api/scan/latest';
        renderDashboard(scanData);
    } catch (e) {
        showToast('Probe failed: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

/* ─── CBOM Export ─── */
async function exportCBOM() {
    try {
        const targetDomain = document.getElementById('domainInput')?.value || 'Demo_Environment';
        const dateStr = new Date().toISOString().slice(0,10);
        const filename = `Q_ARMOR_CBOM_V2_${targetDomain}_${dateStr}.json`;

        let blob = null;
        const phase9Resp = await authorizedFetch(`${API_BASE}/api/phase9/cbom/download`);
        if (phase9Resp.ok) {
            const phase9Blob = await phase9Resp.blob();
            if (phase9Blob.size > 2) {
                blob = phase9Blob;
            }
        }

        if (!blob) {
            const json = await fetchCbomLatest(false);
            if (!hasRenderableCbom(json)) {
                throw new Error('No CBOM v2 is loaded yet. Run the Phase 9 pipeline or open a stored scan with CBOM data first.');
            }
            blob = new Blob([JSON.stringify(json, null, 2)], { type: 'application/json' });
        }
        
        // Sync to backend
        let fd = new FormData();
        fd.append('file', blob, filename);
        authorizedFetch('/api/reports/save', { method: 'POST', body: fd }).catch(e => console.warn(e));

        const objUrl = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = objUrl;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(objUrl);
        showToast('CBOM v2 exported successfully', 'success');
    } catch (e) {
        showToast('Export failed: ' + e.message, 'error');
    }
}

/* ─── CDXA Export ─── */
async function exportCDXA() {
    try {
        const targetDomain = document.getElementById('domainInput')?.value || 'Demo_Environment';
        const dateStr = new Date().toISOString().slice(0,10);
        const filename = `Q_ARMOR_CDXA_${targetDomain}_${dateStr}.json`;
        
        const resp = await authorizedFetch(`${API_BASE}/api/attestation/download`);
        if (!resp.ok) throw new Error(`HTTP Error ${resp.status}`);
        const blob = await resp.blob();
        
        // Sync to backend
        let fd = new FormData();
        fd.append('file', blob, filename);
        authorizedFetch('/api/reports/save', { method: 'POST', body: fd }).catch(e => console.warn(e));

        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
        showToast('CDXA attestation exported successfully', 'success');
    } catch (e) {
        showToast('CDXA export failed: ' + e.message, 'error');
    }
}

/* ─── Fetch Attestation + Alerts ─── */
async function fetchPhase5Data() {
    try {
        const [attestation, alerts] = await Promise.all([
            apiCall('/api/attestation/summary'),
            apiCall('/api/alerts'),
        ]);
        renderAttestation(attestation);
        renderAlerts(alerts);
        const cdxaBtn = document.getElementById('btnExportCDXA');
        if (cdxaBtn) cdxaBtn.disabled = false;
    } catch (e) {
        console.warn('Attestation and alerts fetch failed:', e);
    }
}

function renderAttestation(data) {
    const section = document.getElementById('attestationSection');
    if (!section) return;
    section.style.display = '';

    const statusBadge = document.getElementById('attestStatus');
    const overall = data.overallStatus || 'UNKNOWN';
    const statusColors = {
        'COMPLIANT': { bg: 'rgba(0, 255, 136, 0.12)', color: '#16A34A' },
        'PARTIAL': { bg: 'rgba(0, 212, 255, 0.12)', color: '#2563EB' },
        'NON_COMPLIANT': { bg: 'rgba(255, 71, 87, 0.12)', color: '#DC2626' },
    };
    const sc = statusColors[overall] || statusColors['NON_COMPLIANT'];
    statusBadge.style.background = sc.bg;
    statusBadge.style.color = sc.color;
    statusBadge.textContent = overall;

    animateNumber('attestCompliant', data.compliant || 0);
    animateNumber('attestPartial', data.partial || 0);
    animateNumber('attestNonCompliant', data.nonCompliant || 0);

    const signedEl = document.getElementById('attestSigned');
    if (signedEl) {
        signedEl.textContent = data.signed ? '✓ Yes' : '✗ No';
        signedEl.style.color = data.signed ? '#a855f7' : '#DC2626';
    }

    const details = document.getElementById('attestDetails');
    if (details) {
        details.innerHTML = `
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 8px;">
                <div>Serial: <span style="color: var(--text-primary); font-family: monospace; font-size: 0.72rem;">${data.serialNumber || '—'}</span></div>
                <div>Valid Until: <span style="color: var(--text-primary);">${data.validUntil ? new Date(data.validUntil).toLocaleDateString() : '—'}</span></div>
                <div>Endpoints: <span style="color: var(--text-primary);">${data.totalEndpoints || 0}</span></div>
                <div>Fully Quantum Safe: <span style="color: var(--accent-green);">${data.fullyQuantumSafe || 0}</span> · PQC Ready: <span style="color: var(--accent-cyan);">${data.pqcReady || 0}</span></div>
            </div>
        `;
    }
}

function renderAlerts(data) {
    const section = document.getElementById('alertsSection');
    const container = document.getElementById('alertsContainer');
    const countBadge = document.getElementById('alertCount');
    if (!section || !container) return;

    const alerts = data.alerts || [];
    if (!alerts.length) {
        section.style.display = '';
        countBadge.textContent = '0 alerts';
        countBadge.style.background = 'rgba(0, 255, 136, 0.12)';
        countBadge.style.color = '#16A34A';
        container.innerHTML = '<div style="padding: 20px; text-align: center; color: var(--text-secondary);">✅ No security alerts — all clear</div>';
        return;
    }

    section.style.display = '';
    countBadge.textContent = `${alerts.length} alert${alerts.length !== 1 ? 's' : ''}`;
    countBadge.style.background = 'rgba(255, 59, 48, 0.12)';
    countBadge.style.color = '#ff3b30';

    const severityStyles = {
        'CRITICAL': { bg: 'rgba(255, 59, 48, 0.08)', border: 'rgba(255, 59, 48, 0.3)', icon: '🔴' },
        'HIGH': { bg: 'rgba(255, 149, 0, 0.08)', border: 'rgba(255, 149, 0, 0.3)', icon: '🟠' },
        'MEDIUM': { bg: 'rgba(255, 204, 0, 0.08)', border: 'rgba(255, 204, 0, 0.3)', icon: '🟡' },
        'LOW': { bg: 'rgba(0, 255, 136, 0.08)', border: 'rgba(0, 255, 136, 0.3)', icon: '🟢' },
    };

    container.innerHTML = alerts.map(a => {
        const s = severityStyles[a.severity] || severityStyles['HIGH'];
        const endpoints = (a.affected_endpoints || []).slice(0, 5).join(', ');
        return `<div style="padding: 12px 16px; margin-bottom: 8px; border-radius: 8px; border: 1px solid ${s.border}; background: ${s.bg};">
            <div style="font-weight: 600; margin-bottom: 4px;">${s.icon} ${a.title || 'Alert'} <span style="font-size: 0.72rem; opacity: 0.7;">[${a.severity}]</span></div>
            <div style="font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 6px;">${a.message || ''}</div>
            ${endpoints ? `<div style="font-size: 0.75rem; color: var(--text-dim);">Affected: ${endpoints}</div>` : ''}
            <div style="font-size: 0.75rem; margin-top: 4px; color: var(--accent-cyan);">→ ${a.action_required || 'Review scan results'}</div>
        </div>`;
    }).join('');
}

/* ─── Fetch Assessment + Remediation ─── */
async function fetchPhase2Assessment() {
    try {
        const [assess, remediation] = await Promise.all([
            apiCall('/api/assess'),
            apiCall('/api/assess/remediation'),
        ]);
        assessmentData = assess;
        remediationData = remediation;
        renderPhase2Assessment(assess);
        renderPhase2Remediation(remediation);
    } catch (e) {
        console.warn('Assessment fetch failed:', e);
    }
}


/* ─── Tri-Mode Tab Lazy Loader ─── */
async function _loadTrimodeTab() {
    const empty = document.getElementById('trimodeEmpty');
    if (empty) {
        empty.style.display = 'block';
        empty.innerHTML = `
            <div class="viz-state">
                <div class="viz-state-content">
                    <div class="viz-spinner"></div>
                    <div class="viz-state-title">Loading tri-mode results</div>
                    <div class="viz-state-copy">Fetching probe A / B / C fingerprints from last scan...</div>
                </div>
            </div>`;
    }
    try {
        const data = await apiCall('/api/scan/trimode/fingerprints');
        data.mode = 'live';
        data.total_assets = data.total || data.fingerprints?.length || 0;
        trimodeData = data;
        renderTrimode(trimodeData);
    } catch (e) {
        trimodeData = null;
        if (empty) {
            empty.style.display = 'block';
            empty.innerHTML = `
                <div class="viz-state">
                    <div class="viz-state-content">
                        <div class="viz-state-title">Tri-mode data unavailable</div>
                        <div class="viz-state-copy">${e.message}</div>
                        <button class="viz-retry" type="button" onclick="switchTab('trimode')">Retry</button>
                    </div>
                </div>`;
        }
        console.warn('Trimode tab load failed:', e);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
   Phase 1 Rendering (Overview Tab)
   ═══════════════════════════════════════════════════════════════════════════ */

function renderDashboard(data) {
    renderStats(data);
    renderAssetTable(data.results || []);
    renderQScoreRing(data.average_q_score);
    renderDistBars(data);
    renderRemediation(data.remediation_roadmap || []);
    renderLabels(data.labels || []);
    fetchPhase4Labels();
    // fetchPhase5Data() is now lazy — fires in _autoScanSecondary or on reporting tab visit
}

function renderStats(data) {
    const total = data.total_assets || 0;
    animateNumber('statTotal', total);
    animateNumber('statSafe', data.fully_quantum_safe || 0);
    animateNumber('statTransition', data.pqc_transition || 0);
    animateNumber('statVulnerable', data.quantum_vulnerable || 0);
    animateNumber('statCritical', data.critically_vulnerable || 0);
    if (document.getElementById('statUnknown')) {
        animateNumber('statUnknown', data.unknown || 0);
    }

    document.getElementById('statAvgScore').textContent = `Avg Q-Score: ${(data.average_q_score || 0).toFixed(1)}`;
    document.getElementById('statSafePct').textContent = total ? `${((data.fully_quantum_safe / total) * 100).toFixed(0)}%` : '—';
    document.getElementById('statTransitionPct').textContent = total ? `${((data.pqc_transition / total) * 100).toFixed(0)}%` : '—';
    document.getElementById('statVulnerablePct').textContent = total ? `${((data.quantum_vulnerable / total) * 100).toFixed(0)}%` : '—';
    document.getElementById('statCriticalPct').textContent = total ? `${((data.critically_vulnerable / total) * 100).toFixed(0)}%` : '—';
    if (document.getElementById('statUnknownPct')) {
        document.getElementById('statUnknownPct').textContent = total ? `${(((data.unknown || 0) / total) * 100).toFixed(0)}%` : '—';
    }
}

function animateNumber(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    let current = 0;
    const step = Math.max(1, Math.floor(target / 20));
    const timer = setInterval(() => {
        current += step;
        if (current >= target) { current = target; clearInterval(timer); }
        el.textContent = current;
    }, 30);
}

function inventoryScore(entry) {
    return Number(entry?.q_score?.total ?? entry?.worst_case_score ?? entry?.worst_score ?? entry?.q_score ?? 0) || 0;
}

function inventoryStatus(entry) {
    return entry?.q_score?.status || entry?.status || entry?.pqc_status || 'UNKNOWN';
}

function normalizeInventoryEntry(entry) {
    if (entry?.asset) {
        const asset = entry.asset || {};
        const fingerprint = entry.fingerprint || {};
        const tls = fingerprint.tls || {};
        const cert = fingerprint.certificate || {};
        const score = entry.q_score || {};
        return {
            hostname: asset.hostname || '?',
            port: asset.port || 443,
            assetType: asset.asset_type || 'web',
            tlsVersion: tls.version || '—',
            cipherSuite: tls.cipher_suite || tls.cipher_algorithm || '—',
            keyExchange: tls.key_exchange || '—',
            certificate: cert.signature_algorithm || cert.public_key_type || '—',
            score: score.total || 0,
            status: score.status || 'UNKNOWN',
        };
    }

    return {
        hostname: entry?.hostname || '?',
        port: entry?.port || 443,
        assetType: entry?.asset_type || 'web',
        tlsVersion: entry?.tls_version || '—',
        cipherSuite: entry?.cipher_suite || entry?.cipher || '—',
        keyExchange: entry?.key_exchange || '—',
        certificate: entry?.cert_algorithm || entry?.certificate_algorithm || '—',
        score: inventoryScore(entry),
        status: inventoryStatus(entry),
    };
}

function showAssetDetailModal(entry) {
    const existing = document.getElementById('assetDetailModal');
    if (existing) existing.remove();

    const row = normalizeInventoryEntry(entry);
    const scoreColor = getScoreColor(row.score || 0);
    const statusClass = getStatusClass(row.status);
    const statusLabel = getStatusLabel(row.status);

    // Tri-mode scores from ClassifiedAsset format (if available)
    const best = entry.best_case_score ?? entry.best_case_q?.total ?? row.score;
    const typical = entry.typical_score ?? entry.typical_q?.total ?? row.score;
    const worst = entry.worst_case_score ?? entry.worst_case_q?.total ?? row.score;

    function scoreBar(val, label) {
        const c = getScoreColor(val);
        return `<div style="margin-bottom:8px;">
            <div style="display:flex;justify-content:space-between;font-size:0.72rem;margin-bottom:3px;">
                <span style="color:var(--text-secondary);">${label}</span>
                <span style="color:${c};font-weight:700;">${val}</span>
            </div>
            <div style="height:6px;background:rgba(255,255,255,0.08);border-radius:3px;">
                <div style="height:100%;width:${val}%;background:${c};border-radius:3px;transition:width 0.4s ease;"></div>
            </div>
        </div>`;
    }

    const findings = entry.worst_case_q?.findings || entry.q_score?.findings || [];
    const recommendations = entry.worst_case_q?.recommendations || entry.q_score?.recommendations || [];
    const findingsHtml = findings.length
        ? findings.map(f => `<li style="margin-bottom:4px;">${escHtml(f)}</li>`).join('')
        : '<li style="color:var(--text-dim);">No findings recorded.</li>';
    const recoHtml = recommendations.length
        ? recommendations.map(r => `<li style="margin-bottom:4px;color:var(--accent-cyan);">${escHtml(r)}</li>`).join('')
        : '<li style="color:var(--text-dim);">No remediation required.</li>';

    const modal = document.createElement('div');
    modal.id = 'assetDetailModal';
    modal.style.cssText = 'position:fixed;inset:0;z-index:10000;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.65);backdrop-filter:blur(4px);';
    modal.innerHTML = `
        <div style="background:var(--surface-secondary,#1a1f2e);border:1px solid rgba(255,255,255,0.1);border-radius:14px;padding:28px 32px;max-width:640px;width:90%;max-height:85vh;overflow-y:auto;box-shadow:0 24px 64px rgba(0,0,0,0.5);">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;">
                <div>
                    <div style="font-size:1.05rem;font-weight:700;color:var(--text-primary);">${escHtml(row.hostname)}<span style="color:var(--text-dim);font-weight:400;">:${row.port}</span></div>
                    <div style="font-size:0.78rem;color:var(--text-secondary);margin-top:2px;">${row.assetType} asset</div>
                </div>
                <div style="margin-left:auto;display:flex;align-items:center;gap:10px;">
                    <span class="status-badge status-badge--${statusClass}">${statusLabel}</span>
                    <button onclick="document.getElementById('assetDetailModal').remove()" style="background:none;border:none;color:var(--text-dim);font-size:1.2rem;cursor:pointer;padding:0 4px;">✕</button>
                </div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px;">
                <div>
                    <div style="font-size:0.72rem;font-weight:700;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.08em;margin-bottom:10px;">TLS DETAILS</div>
                    <table style="width:100%;font-size:0.78rem;border-collapse:collapse;">
                        <tr><td style="color:var(--text-secondary);padding:3px 0;">Protocol</td><td style="color:var(--text-primary);font-weight:600;">${row.tlsVersion}</td></tr>
                        <tr><td style="color:var(--text-secondary);padding:3px 0;">Key Exchange</td><td style="color:var(--text-primary);font-weight:600;">${row.keyExchange}</td></tr>
                        <tr><td style="color:var(--text-secondary);padding:3px 0;">Cipher Suite</td><td style="color:var(--text-primary);font-size:0.72rem;">${row.cipherSuite}</td></tr>
                        <tr><td style="color:var(--text-secondary);padding:3px 0;">Certificate</td><td style="color:var(--text-primary);font-size:0.72rem;">${row.certificate}</td></tr>
                    </table>
                </div>
                <div>
                    <div style="font-size:0.72rem;font-weight:700;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.08em;margin-bottom:10px;">TRI-MODE Q-SCORES</div>
                    ${scoreBar(best, 'Best Case (Probe A — PQC)')}
                    ${scoreBar(typical, 'Typical (Probe B — TLS 1.3)')}
                    ${scoreBar(worst, 'Worst Case (Probe C — Downgrade)')}
                </div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
                <div>
                    <div style="font-size:0.72rem;font-weight:700;color:#D97706;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:8px;">FINDINGS</div>
                    <ul style="margin:0;padding-left:16px;font-size:0.75rem;color:var(--text-secondary);">${findingsHtml}</ul>
                </div>
                <div>
                    <div style="font-size:0.72rem;font-weight:700;color:var(--accent-cyan);text-transform:uppercase;letter-spacing:0.08em;margin-bottom:8px;">REMEDIATION</div>
                    <ul style="margin:0;padding-left:16px;font-size:0.75rem;">${recoHtml}</ul>
                </div>
            </div>
        </div>`;
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
    document.body.appendChild(modal);
}

function renderAssetTable(results) {
    const container = document.getElementById('assetTableContainer');
    document.getElementById('assetCount').textContent = `${results.length} assets`;

    if (!results.length) {
        container.innerHTML = `<div class="empty-state"><div class="empty-state-icon">🔍</div><div class="empty-state-title">No assets found</div></div>`;
        return;
    }

    const sorted = [...results].sort((a, b) => inventoryScore(a) - inventoryScore(b));
    const normalised = sorted.map(normalizeInventoryEntry);

    let html = `<table class="asset-table"><thead><tr>
        <th>Asset</th><th>Type</th><th>TLS</th><th>Cipher Suite</th><th>Key Exchange</th><th>Certificate</th><th>Q-Score</th><th>Status</th>
    </tr></thead><tbody>`;

    for (let i = 0; i < normalised.length; i++) {
        const row = normalised[i];
        const statusClass = getStatusClass(row.status);
        const statusLabel = getStatusLabel(row.status);
        const scoreColor = getScoreColor(row.score || 0);

        html += `<tr style="cursor:pointer;" onclick="_assetDetailEntries[${i}] && showAssetDetailModal(_assetDetailEntries[${i}])">
            <td><span class="asset-hostname">${row.hostname}:${row.port}</span></td>
            <td><span class="asset-type">${row.assetType}</span></td>
            <td>${row.tlsVersion}</td>
            <td style="font-size:0.75rem">${row.cipherSuite}</td>
            <td>${row.keyExchange}</td>
            <td style="font-size:0.75rem">${row.certificate}</td>
            <td>
                <div class="qscore-bar-container">
                    <div class="qscore-bar"><div class="qscore-bar-fill" style="width:${row.score || 0}%;background:${scoreColor}"></div></div>
                    <span class="qscore-value" style="color:${scoreColor}">${row.score || 0}</span>
                </div>
            </td>
            <td><span class="status-badge status-badge--${statusClass}">${statusLabel}</span></td>
        </tr>`;
    }

    html += '</tbody></table>';
    container.innerHTML = html;
    window._assetDetailEntries = sorted;

    requestAnimationFrame(() => {
        container.querySelectorAll('.qscore-bar-fill').forEach(el => {
            const w = el.style.width;
            el.style.width = '0'; requestAnimationFrame(() => { el.style.width = w; });
        });
    });
}

async function syncOverviewWithLatestScan(forceRefresh = false) {
    try {
        const payload = await fetchLatestScan(forceRefresh);
        const assets = payload.assets || payload.asset_scores || [];
        if (!assets.length) return;

        const counts = {
            FULLY_QUANTUM_SAFE: 0,
            PQC_TRANSITION: 0,
            QUANTUM_VULNERABLE: 0,
            CRITICALLY_VULNERABLE: 0,
            UNKNOWN: 0,
        };

        assets.forEach((entry) => {
            const status = inventoryStatus(entry);
            counts[status] = (counts[status] || 0) + 1;
        });

        const averageScore = assets.reduce((sum, entry) => sum + inventoryScore(entry), 0) / Math.max(assets.length, 1);
        renderStats({
            total_assets: assets.length,
            fully_quantum_safe: counts.FULLY_QUANTUM_SAFE,
            pqc_transition: counts.PQC_TRANSITION,
            quantum_vulnerable: counts.QUANTUM_VULNERABLE,
            critically_vulnerable: counts.CRITICALLY_VULNERABLE,
            unknown: counts.UNKNOWN,
            average_q_score: averageScore,
        });
        renderAssetTable(assets);
        renderQScoreRing(averageScore);
        renderDistBars({
            total_assets: assets.length,
            fully_quantum_safe: counts.FULLY_QUANTUM_SAFE,
            pqc_transition: counts.PQC_TRANSITION,
            quantum_vulnerable: counts.QUANTUM_VULNERABLE,
            critically_vulnerable: counts.CRITICALLY_VULNERABLE,
            unknown: counts.UNKNOWN,
        });
    } catch (error) {
        console.warn('Latest scan sync failed:', error);
    }
}

function renderQScoreRing(score) {
    const circumference = 2 * Math.PI * 68;
    const offset = circumference - (score / 100) * circumference;
    const fill = document.getElementById('qscoreRingFill');
    const num = document.getElementById('qscoreRingNumber');

    fill.style.stroke = getScoreColor(score);
    fill.style.strokeDashoffset = offset;
    num.textContent = Math.round(score);
    num.style.color = getScoreColor(score);
}

function renderDistBars(data) {
    const container = document.getElementById('distBars');
    const total = data.total_assets || 1;

    const bars = [
        { label: 'Quantum Safe', count: data.fully_quantum_safe || 0, color: 'var(--status-safe)' },
        { label: 'PQC Transition', count: data.pqc_transition || 0, color: 'var(--status-transition)' },
        { label: 'Vulnerable', count: data.quantum_vulnerable || 0, color: 'var(--status-vulnerable)' },
        { label: 'Critical', count: data.critically_vulnerable || 0, color: 'var(--status-critical)' },
        { label: 'Unknown', count: data.unknown || 0, color: 'var(--status-unknown)' },
    ];

    container.innerHTML = bars.map(b => `
        <div class="dist-bar-row">
            <span class="dist-bar-label">${b.label}</span>
            <div class="dist-bar-track"><div class="dist-bar-fill" style="width:${(b.count / total) * 100}%;background:${b.color}"></div></div>
            <span class="dist-bar-count" style="color:${b.color}">${b.count}</span>
        </div>
    `).join('');
}

function renderRemediation(roadmap) {
    const container = document.getElementById('remediationContainer');
    if (!roadmap.length) {
        container.innerHTML = `<div class="empty-state"><div class="empty-state-icon"><span class="material-symbols-outlined" style="font-size:32px;">task_alt</span></div><div class="empty-state-title">No remediation needed</div></div>`;
        return;
    }

    const priorityMap = { 'P1_IMMEDIATE': 'P1', 'P2_SHORT_TERM': 'P2', 'P3_MEDIUM_TERM': 'P3', 'P4_STRATEGIC': 'P4' };
    const priorityLabel = { 'P1': 'Priority 1 — Immediate', 'P2': 'Priority 2 — Short Term', 'P3': 'Priority 3 — Medium Term', 'P4': 'Priority 4 — Strategic' };
    const iconMap = { 'P1': 'warning', 'P2': 'schedule', 'P3': 'trending_up', 'P4': 'architecture' };

    let html = '<div class="remediation-timeline">';
    for (const item of roadmap) {
        const p = priorityMap[item.priority] || 'P4';
        const icon = iconMap[p];
        html += `
            <div class="remediation-item remediation-item--${p}">
                <div class="remediation-item-header" style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">
                    <span class="material-symbols-outlined" style="font-size: 20px;">${icon}</span>
                    <div class="remediation-priority" style="font-weight: 700; color: var(--text-primary);">${priorityLabel[p] || item.priority}</div>
                </div>
                <div class="remediation-desc" style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 8px; font-weight: 500;">${item.description}</div>
                <div class="remediation-timeframe" style="display: flex; align-items: center; gap: 12px; font-size: 0.75rem; color: var(--text-dim); margin-bottom: 12px;">
                    <span style="display: flex; align-items: center; gap: 4px;"><span class="material-symbols-outlined" style="font-size: 14px;">schedule</span> ${item.timeframe}</span>
                    <span style="display: flex; align-items: center; gap: 4px;"><span class="material-symbols-outlined" style="font-size: 14px;">dns</span> ${(item.affected_assets || []).length} asset(s)</span>
                </div>
                <ul class="remediation-actions" style="list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 6px;">
                    ${(item.specific_actions || []).map(a => `<li style="display: flex; align-items: flex-start; gap: 6px; font-size: 0.8rem; color: var(--text-primary);"><span class="material-symbols-outlined" style="font-size: 16px; color: var(--primary);">chevron_right</span>${a}</li>`).join('')}
                </ul>
            </div>`;
    }
    html += '</div>';
    container.innerHTML = html;
}

function renderLabels(labels) {
    const section = document.getElementById('labelsSection');
    const container = document.getElementById('labelsContainer');

    if (!labels.length) { section.style.display = 'none'; return; }
    section.style.display = '';

    container.innerHTML = labels.map(l => `
        <div class="cert-card" style="border-top-color: var(--primary);">
            <div class="cert-header">
                <div>
                    <span class="cert-domain">${l.asset}</span>
                    <span class="cert-issuer" style="margin-top:4px;"><span class="material-symbols-outlined" style="font-size: 14px; margin-right:4px;">verified_user</span> PQC-Ready Certified</span>
                </div>
            </div>
            <div class="cert-body">
                <div class="cert-detail"><span class="material-symbols-outlined">memory</span> <strong>Algorithms:</strong> ${(l.algorithms || []).join(', ')}</div>
                <div class="cert-detail"><span class="material-symbols-outlined">gavel</span> <strong>Standards:</strong> ${(l.standards || []).join(', ')}</div>
                <div class="cert-detail" style="color: var(--primary);"><span class="material-symbols-outlined">event</span> <strong>Valid Until:</strong> ${l.valid_until}</div>
                <div class="cert-detail"><span class="material-symbols-outlined">fingerprint</span> <strong>ID:</strong> <span style="font-family: monospace; margin-left:4px;">${l.label_id}</span></div>
            </div>
        </div>
    `).join('');
}


/* ─── Certification Labels ─── */
async function fetchPhase4Labels() {
    try {
        const data = await apiCall('/api/labels/phase4');
        renderCertLabels(data);
    } catch (e) {
        console.warn('Certification labels fetch failed:', e);
    }
}

function renderCertLabels(data) {
    const section = document.getElementById('certLabelsSection');
    const container = document.getElementById('certLabelsContainer');
    const countBadge = document.getElementById('certLabelCount');

    const labels = data.labels || [];
    if (!labels.length) { section.style.display = 'none'; return; }
    section.style.display = '';

    countBadge.textContent = `${data.total_endpoints || labels.length} endpoints`;
    animateNumber('certFullySafe', data.fully_quantum_safe || 0);
    animateNumber('certPQCReady', data.pqc_ready || 0);
    animateNumber('certNonCompliant', data.non_compliant || 0);

    const tierConfig = {
        1: { cls: 'cert-label--safe', icon: 'verified_user', color: 'var(--accent-green)', bg: 'rgba(22, 163, 74, 0.04)' },
        2: { cls: 'cert-label--ready', icon: 'shield_with_heart', color: 'var(--accent-amber)', bg: 'rgba(217, 119, 6, 0.04)' },
        3: { cls: 'cert-label--noncompliant', icon: 'gpp_bad', color: 'var(--accent-red)', bg: 'rgba(220, 38, 38, 0.04)' },
    };

    container.innerHTML = labels.map(l => {
        const cfg = tierConfig[l.tier] || tierConfig[3];
        return `<div class="label-card ${cfg.cls}" style="border: 1px solid ${cfg.color}; background: ${cfg.bg}; border-radius: var(--radius-md); padding: 18px; transition: box-shadow 0.2s; box-shadow: 0 4px 12px rgba(0,0,0,0.02);">
            <div class="label-header" style="color: ${cfg.color}; display: flex; align-items: center; gap: 8px; font-weight: 700; margin-bottom: 16px; font-size: 0.95rem;">
                <span class="material-symbols-outlined" style="font-variation-settings: 'FILL' 1; font-size: 22px;">${cfg.icon}</span> 
                ${l.label}
            </div>
            <div class="label-asset" style="font-family: var(--font-mono); font-size: 0.85rem; font-weight: 700; color: var(--primary); margin-bottom: 12px;">${l.target}:${l.port}</div>
            <div class="label-detail" style="font-size: 0.75rem; color: var(--text-secondary); margin-bottom: 6px; display: flex; justify-content: space-between;">
                <span>TLS: <strong style="color: var(--text-primary)">${l.tls_version || '—'}</strong></span>
                <span>KEX: <strong style="color: var(--text-primary)">${l.key_exchange || '—'}</strong></span>
            </div>
            <div class="label-detail" style="font-size: 0.75rem; color: var(--text-secondary); margin-bottom: 6px; display: flex; justify-content: space-between;">
                <span>Cert: <strong style="color: var(--text-primary)">${l.certificate || '—'}</strong></span>
                <span>Risk: <strong style="color: var(--text-primary)">${l.risk || '—'}</strong></span>
            </div>
            <div class="label-detail" style="margin-top: 14px; font-size: 0.72rem; color: var(--text-secondary); background: white; padding: 8px 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); line-height: 1.4;">${l.reason}</div>
        </div>`;
    }).join('');
}


/* ═══════════════════════════════════════════════════════════════════════════
   Phase 2 Rendering — PQC Assessment Tab
   ═══════════════════════════════════════════════════════════════════════════ */

function renderPhase2Assessment(data) {
    const agg = data.aggregate || {};
    const assessments = data.assessments || [];

    // Show content, hide empty state
    document.getElementById('assessmentEmpty').style.display = 'none';
    document.getElementById('assessmentContent').style.display = 'block';

    // KPI Cards
    const total = agg.total_endpoints || 0;
    animateNumber('p2StatEndpoints', total);
    animateNumber('p2StatHigh', agg.risk_high || 0);
    animateNumber('p2StatMedium', agg.risk_medium || 0);
    animateNumber('p2StatLow', agg.risk_low || 0);
    animateNumber('p2StatHNDL', agg.hndl_vulnerable || 0);

    document.getElementById('p2AvgScore').textContent = `Avg Q-Score: ${agg.average_q_score || 0}`;
    document.getElementById('p2StatHighPct').textContent = total ? `${agg.risk_high_pct || 0}%` : '—';
    document.getElementById('p2StatMediumPct').textContent = total ? `${((agg.risk_medium / total) * 100).toFixed(0)}%` : '—';
    document.getElementById('p2StatLowPct').textContent = total ? `${((agg.risk_low / total) * 100).toFixed(0)}%` : '—';
    document.getElementById('p2StatHNDLPct').textContent = total ? `${agg.hndl_vulnerable_pct || 0}%` : '—';

    // Charts
    drawDonutChart('chartKEX', 'legendKEX', [
        { label: 'Vulnerable', value: agg.kex_vulnerable || 0, color: '#DC2626' },
        { label: 'Hybrid PQC', value: agg.kex_hybrid || 0, color: '#2563EB' },
        { label: 'PQC Safe', value: agg.kex_pqc_safe || 0, color: '#16A34A' },
    ]);

    drawDonutChart('chartTLS', 'legendTLS', [
        { label: 'TLS Pass', value: agg.tls_pass || 0, color: '#16A34A' },
        { label: 'TLS Fail', value: agg.tls_fail || 0, color: '#DC2626' },
    ]);

    drawDonutChart('chartRisk', 'legendRisk', [
        { label: 'High Risk', value: agg.risk_high || 0, color: '#DC2626' },
        { label: 'Medium Risk', value: agg.risk_medium || 0, color: '#D97706' },
        { label: 'Low Risk', value: agg.risk_low || 0, color: '#16A34A' },
    ]);

    // Dimension breakdown bars
    renderDimensionBars(agg);

    // Per-endpoint table
    renderAssessmentTable(assessments);
}

/* ─── Canvas Donut Chart ─── */
const donutCharts = {};
let donutResizeBound = false;

function fitDonutCanvas(canvas) {
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    const width = Math.max(1, Math.round(rect.width || canvas.clientWidth || parseInt(canvas.getAttribute('width') || '280', 10)));
    const height = Math.max(1, Math.round(rect.height || canvas.clientHeight || parseInt(canvas.getAttribute('height') || `${width}`, 10)));

    if (canvas.width !== Math.round(width * dpr) || canvas.height !== Math.round(height * dpr)) {
        canvas.width = Math.round(width * dpr);
        canvas.height = Math.round(height * dpr);
    }

    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;

    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return { ctx, width, height };
}

function redrawDonutCharts() {
    Object.entries(donutCharts).forEach(([canvasId, chart]) => {
        drawDonutChart(canvasId, chart.legendId, chart.segments);
    });
}

function drawDonutChart(canvasId, legendId, segments) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    donutCharts[canvasId] = { legendId, segments };
    if (!donutResizeBound) {
        window.addEventListener('resize', redrawDonutCharts);
        donutResizeBound = true;
    }

    const { ctx, width, height } = fitDonutCanvas(canvas);
    const cx = width / 2;
    const cy = height / 2;
    const outerR = Math.max(24, (Math.min(width, height) / 2) - 16);
    const innerR = outerR * 0.58;

    ctx.clearRect(0, 0, width, height);

    const total = segments.reduce((s, seg) => s + seg.value, 0);
    if (total === 0) {
        ctx.beginPath();
        ctx.arc(cx, cy, outerR, 0, Math.PI * 2);
        ctx.arc(cx, cy, innerR, 0, Math.PI * 2, true);
        ctx.fillStyle = 'rgba(55, 65, 81, 0.3)';
        ctx.fill();
        ctx.fillStyle = '#6b7280';
        ctx.font = '600 0.875rem Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('No data', cx, cy);
    } else {
        let angle = -Math.PI / 2;
        for (const seg of segments) {
            if (seg.value === 0) continue;
            const sliceAngle = (seg.value / total) * Math.PI * 2;
            ctx.beginPath();
            ctx.arc(cx, cy, outerR, angle, angle + sliceAngle);
            ctx.arc(cx, cy, innerR, angle + sliceAngle, angle, true);
            ctx.closePath();
            ctx.fillStyle = seg.color;
            ctx.fill();
            angle += sliceAngle;
        }

        ctx.fillStyle = '#f0f4f8';
        ctx.font = '800 1.75rem "JetBrains Mono", monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(total, cx, cy - 6);
        ctx.fillStyle = '#6b7280';
        ctx.font = '500 0.625rem Inter, sans-serif';
        ctx.fillText('TOTAL', cx, cy + 14);
    }

    // Legend
    const legend = document.getElementById(legendId);
    if (legend) {
        legend.innerHTML = segments.map(s => `
            <div class="chart-legend-item">
                <span class="chart-legend-dot" style="background:${s.color}"></span>
                ${s.label}: <span class="chart-legend-value">${s.value}</span>
            </div>
        `).join('');
    }
}

/* ─── Dimension Breakdown Bars ─── */
function renderDimensionBars(agg) {
    const container = document.getElementById('dimensionBars');
    if (!container) return;
    const total = agg.total_endpoints || 1;

    const dimensions = [
        {
            label: 'Key Exchange',
            segments: [
                { label: 'Vulnerable', value: agg.kex_vulnerable || 0, cls: 'critical' },
                { label: 'Hybrid', value: agg.kex_hybrid || 0, cls: 'transition' },
                { label: 'PQC Safe', value: agg.kex_pqc_safe || 0, cls: 'safe' },
            ]
        },
        {
            label: 'TLS Protocol',
            segments: [
                { label: 'Fail', value: agg.tls_fail || 0, cls: 'critical' },
                { label: 'Pass', value: agg.tls_pass || 0, cls: 'safe' },
            ]
        },
        {
            label: 'Certificate',
            segments: [
                { label: 'Vulnerable', value: agg.cert_vulnerable || 0, cls: 'critical' },
                { label: 'Hybrid', value: agg.cert_hybrid || 0, cls: 'transition' },
                { label: 'PQC Safe', value: agg.cert_pqc_safe || 0, cls: 'safe' },
            ]
        },
        {
            label: 'Symmetric Cipher',
            segments: [
                { label: 'Fail', value: agg.sym_fail || 0, cls: 'critical' },
                { label: 'Pass', value: agg.sym_pass || 0, cls: 'safe' },
            ]
        },
        {
            label: 'HNDL Exposure',
            segments: [
                { label: 'Exposed', value: agg.hndl_vulnerable || 0, cls: 'vulnerable' },
                { label: 'Protected', value: total - (agg.hndl_vulnerable || 0), cls: 'safe' },
            ]
        },
    ];

    container.innerHTML = dimensions.map(dim => {
        const valText = dim.segments.map(s => `${s.label}: ${s.value}`).join(' · ');
        const barSegments = dim.segments.map(s => {
            const pct = (s.value / total) * 100;
            return pct > 0
                ? `<div class="dim-bar-segment dim-bar-segment--${s.cls}" style="width:${pct}%">${s.value > 0 ? s.value : ''}</div>`
                : '';
        }).join('');

        return `<div class="dim-bar-group">
            <div class="dim-bar-header">
                <span class="dim-bar-label">${dim.label}</span>
                <span class="dim-bar-values">${valText}</span>
            </div>
            <div class="dim-bar-track">${barSegments}</div>
        </div>`;
    }).join('');
}

/* ─── Assessment Table ─── */
function renderAssessmentTable(assessments) {
    const container = document.getElementById('assessTableContainer');
    const badge = document.getElementById('assessCount');
    badge.textContent = `${assessments.length} endpoints`;

    if (!assessments.length) {
        container.innerHTML = `<div class="empty-state"><div class="empty-state-icon">🛡️</div><div class="empty-state-title">No assessments</div></div>`;
        return;
    }

    const riskOrder = { HIGH: 0, MEDIUM: 1, LOW: 2 };
    const sorted = [...assessments].sort((a, b) =>
        (riskOrder[a.overall_quantum_risk] ?? 9) - (riskOrder[b.overall_quantum_risk] ?? 9)
    );

    let html = `<table class="assess-table"><thead><tr>
        <th>Endpoint</th>
        <th>Risk</th>
        <th>TLS</th>
        <th>Key Exchange</th>
        <th>Certificate</th>
        <th>Symmetric</th>
        <th>HNDL</th>
        <th>Q-Score</th>
    </tr></thead><tbody>`;

    for (const a of sorted) {
        const riskCls = a.overall_quantum_risk || 'HIGH';
        html += `<tr>
            <td><span class="asset-hostname">${a.target || '?'}:${a.port || 443}</span></td>
            <td><span class="risk-badge risk-badge--${riskCls}">${riskCls}</span></td>
            <td>${dimPill(a.tls_status, a.tls_version)}</td>
            <td>${dimPillKex(a.key_exchange_status, a.key_exchange_algorithm)}</td>
            <td>${dimPillKex(a.certificate_status, a.certificate_algorithm)}</td>
            <td>${dimPill(a.symmetric_cipher_status, a.symmetric_cipher)}</td>
            <td>${hndlBadge(a.hndl_vulnerable)}</td>
            <td><span class="qscore-value" style="color:${getScoreColor(a.q_score || 0)}">${a.q_score || 0}</span></td>
        </tr>`;
    }

    html += '</tbody></table>';
    container.innerHTML = html;
}

function dimPill(status, label) {
    const cls = status === 'PASS' ? 'pass' : 'fail';
    return `<span class="dim-pill dim-pill--${cls}" title="${label || ''}">${status || '?'}</span>`;
}

function dimPillKex(status, label) {
    const clsMap = { PQC_SAFE: 'pqc', HYBRID: 'hybrid', VULNERABLE: 'vuln' };
    const cls = clsMap[status] || 'vuln';
    return `<span class="dim-pill dim-pill--${cls}" title="${label || ''}">${status || '?'}</span>`;
}

function hndlBadge(isVulnerable) {
    if (isVulnerable) return `<span class="hndl-indicator hndl-indicator--yes">⚠ YES</span>`;
    return `<span class="hndl-indicator hndl-indicator--no">✓ NO</span>`;
}


/* ═══════════════════════════════════════════════════════════════════════════
   Phase 2 Rendering — Remediation Plan Tab
   ═══════════════════════════════════════════════════════════════════════════ */

function renderPhase2Remediation(data) {
    document.getElementById('remPlanEmpty').style.display = 'none';
    document.getElementById('remPlanContent').style.display = 'block';

    // Summary cards
    animateNumber('remTotal', data.total_remediations || 0);
    const bp = data.by_priority || {};
    animateNumber('remP1', bp.P1_CRITICAL || 0);
    animateNumber('remP2', bp.P2_HIGH || 0);
    animateNumber('remP3', bp.P3_MEDIUM || 0);
    animateNumber('remP4', bp.P4_LOW || 0);

    // Category bars
    renderCategoryBars(data.by_category || {});

    // Strategic roadmap
    renderStrategicRoadmap(data.strategic_roadmap || []);
}

function renderCategoryBars(byCategory) {
    const container = document.getElementById('remCategoryBars');
    if (!container) return;

    const categories = Object.entries(byCategory);
    const maxCount = Math.max(1, ...categories.map(c => c[1]));

    const catLabels = {
        tls: 'TLS Protocol',
        key_exchange: 'Key Exchange',
        certificate: 'Certificate',
        symmetric: 'Symmetric Cipher',
        hndl_advisory: 'HNDL Advisory',
    };

    const catColors = {
        tls: 'critical',
        key_exchange: 'critical',
        certificate: 'vulnerable',
        symmetric: 'transition',
        hndl_advisory: 'vulnerable',
    };

    container.innerHTML = categories.map(([cat, count]) => {
        const pct = (count / maxCount) * 100;
        const label = catLabels[cat] || cat;
        const cls = catColors[cat] || 'transition';
        return `<div class="dim-bar-group">
            <div class="dim-bar-header">
                <span class="dim-bar-label">${label}</span>
                <span class="dim-bar-values">${count} action(s)</span>
            </div>
            <div class="dim-bar-track">
                <div class="dim-bar-segment dim-bar-segment--${cls}" style="width:${pct}%">${count}</div>
            </div>
        </div>`;
    }).join('');
}

function renderStrategicRoadmap(phases) {
    const container = document.getElementById('remRoadmapContainer');
    if (!container) return;

    if (!phases.length) {
        container.innerHTML = `<div class="empty-state"><div class="empty-state-icon">✅</div><div class="empty-state-title">No actions required</div></div>`;
        return;
    }

    const phaseClass = { P1_CRITICAL: 'P1', P2_HIGH: 'P2', P3_MEDIUM: 'P3', P4_LOW: 'P4' };
    const roadmapTitleByPriority = {
        P1_CRITICAL: 'Critical Actions (0-30 days)',
        P2_HIGH: 'High-Priority Actions (30-90 days)',
        P3_MEDIUM: 'Planned Actions (90-180 days)',
        P4_LOW: 'Optimization Actions (180-365 days)',
    };

    container.innerHTML = phases.map(phase => {
        const pCls = phaseClass[phase.priority] || 'P4';
        const headingRaw = String(phase.phase || '').trim();
        const headingClean = headingRaw
            .replace(/^\s*phase\s*\d+\s*[:\-]?\s*/i, '')
            .replace(/\bphase\b/ig, '')
            .replace(/\s{2,}/g, ' ')
            .trim();
        const heading = headingClean || roadmapTitleByPriority[phase.priority] || 'Roadmap Actions';
        const actionsHtml = (phase.actions || []).map(action => `
            <div class="roadmap-action">
                <div class="roadmap-action-title">${action.title || ''}</div>
                <div class="roadmap-action-desc">${action.description || ''}</div>
                ${action.actions && action.actions.length ? `
                    <ul class="roadmap-action-steps">
                        ${action.actions.slice(0, 5).map(s => `<li>${s}</li>`).join('')}
                        ${action.actions.length > 5 ? `<li>... and ${action.actions.length - 5} more steps</li>` : ''}
                    </ul>
                ` : ''}
                ${action.impact ? `<div class="roadmap-action-impact">⚠ ${action.impact}</div>` : ''}
            </div>
        `).join('');

        return `<div class="roadmap-phase roadmap-phase--${pCls}">
            <div class="roadmap-phase-header">${heading}</div>
            ${actionsHtml}
        </div>`;
    }).join('');
}


/* ═══════════════════════════════════════════════════════════════════════════
   Phase 2 Rendering — NIST Matrix Tab
   ═══════════════════════════════════════════════════════════════════════════ */

async function loadNISTMatrix() {
    try {
        const data = await apiCall('/api/assess/matrix');
        nistMatrixData = data;
        renderNISTMatrix(data);
        showToast('NIST matrix loaded', 'success');
    } catch (e) {
        showToast('Failed to load matrix: ' + e.message, 'error');
    }
}

function renderNISTMatrix(data) {
    const container = document.getElementById('matrixTables');

    const sections = [
        { title: '🔴 Quantum-Vulnerable Algorithms', key: 'vulnerable', tagClass: 'vuln',
          desc: 'These classical algorithms are broken by Shor\'s or Grover\'s algorithm on a quantum computer.' },
        { title: '🟢 PQC-Safe Algorithms', key: 'pqc_safe', tagClass: 'safe',
          desc: 'NIST-approved post-quantum algorithms (FIPS 203/204/205) safe against both classical and quantum attacks.' },
        { title: '🔵 Hybrid PQC Algorithms', key: 'hybrid', tagClass: 'hybrid',
          desc: 'Transitional hybrid algorithms combining classical + post-quantum key exchange for interoperability.' },
    ];

    container.innerHTML = sections.map(sec => {
        const items = data[sec.key] || [];
        return `<div class="matrix-section">
            <div class="matrix-section-title">${sec.title}</div>
            <p style="font-size: 0.75rem; color: var(--text-dim); margin-bottom: 10px;">${sec.desc}</p>
            <div class="matrix-tag-grid">
                ${items.map(algo => `<span class="matrix-tag matrix-tag--${sec.tagClass}">${algo}</span>`).join('')}
            </div>
        </div>`;
    }).join('');
}


/* ═══════════════════════════════════════════════════════════════════════════
   Helpers
   ═══════════════════════════════════════════════════════════════════════════ */

function getStatusClass(status) {
    const map = {
        'FULLY_QUANTUM_SAFE': 'safe',
        'PQC_TRANSITION': 'transition',
        'QUANTUM_VULNERABLE': 'vulnerable',
        'CRITICALLY_VULNERABLE': 'critical',
        'UNKNOWN': 'unknown',
    };
    return map[status] || 'vulnerable';
}

function getStatusLabel(status) {
    const map = {
        'FULLY_QUANTUM_SAFE': '✅ Quantum Safe',
        'PQC_TRANSITION': '🔶 PQC Transition',
        'QUANTUM_VULNERABLE': '⚠️ Vulnerable',
        'CRITICALLY_VULNERABLE': '🚨 Critical',
        'UNKNOWN': '❓ Unknown',
    };
    return map[status] || status;
}

function getScoreColor(score) {
    if (score >= 90) return 'var(--status-safe)';
    if (score >= 70) return 'var(--status-transition)';
    if (score >= 40) return 'var(--status-vulnerable)';
    return 'var(--status-critical)';
}


/* ═══════════════════════════════════════════════════════════════════════════
   Phase 6: Tri-Mode Probing
   ═══════════════════════════════════════════════════════════════════════════ */

async function fetchTrimodeDemoData() {
    try {
        trimodeData = await apiCall('/api/scan/trimode/demo');
        renderTrimode(trimodeData);
    } catch (e) {
        console.warn('Tri-mode demo fetch failed:', e);
    }
}

/* ── probeSingleHost: live TLS probe for any user-supplied hostname ── */
async function probeSingleHost() {
    const hostname = (document.getElementById('singleHostInput')?.value || '').trim();
    const port = parseInt(document.getElementById('singlePortInput')?.value) || 443;
    if (!hostname) { showToast('Enter a hostname first', 'warn'); return; }

    const btn = document.getElementById('singleProbeBtn');
    const resultEl = document.getElementById('singleHostResult');
    if (btn) { btn.disabled = true; btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg> Probing…'; }
    if (resultEl) resultEl.innerHTML = '<div style="color:var(--text-dim);padding:12px 0;font-size:0.85rem;">Running three TLS handshakes (A/B/C) against <strong>' + escHtml(hostname) + '</strong>…</div>';

    try {
        const fp = await apiCall(`/api/scan/trimode/single/${encodeURIComponent(hostname)}?port=${port}`);
        renderSingleHostResult(fp, resultEl);
    } catch (e) {
        if (resultEl) resultEl.innerHTML = `<div style="color:var(--accent-pink);padding:12px 0;font-size:0.85rem;">⚠ Probe failed: ${escHtml(e.message)}</div>`;
        showToast('Probe failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Probe'; }
    }
}

function renderSingleHostResult(fp, container) {
    if (!fp || !container) return;

    const st = fp.q_score?.status || 'UNKNOWN';
    const score = fp.q_score?.total ?? '—';
    const cls = getStatusClass(st);
    const lbl = getStatusLabel(st);
    const scColor = getScoreColor(score);

    function probeRow(label, p, description) {
        if (!p) return `<tr><td><span class="probe-label">${label}</span></td><td colspan="4" style="color:var(--text-dim)">—</td></tr>`;
        const tls = escHtml(p.tls_version || '—');
        const kex = escHtml(p.key_exchange_group || p.key_exchange || '—');
        const cipher = escHtml(p.cipher_suite || '—');
        const bits = p.cipher_bits ? `${p.cipher_bits}-bit` : '—';
        const err = p.error ? `<span style="color:var(--accent-pink)">${escHtml(p.error)}</span>` : '';

        const isPqc = kex.includes('ML-KEM') || kex.includes('MLKEM') || kex.includes('KYBER');
        const isBad = tls.includes('TLSv1.0') || tls.includes('TLSv1.1') || tls.includes('SSLv');
        let tlsColor = isBad ? 'var(--accent-pink)' : tls.includes('1.3') ? 'var(--accent-green)' : 'var(--accent-yellow)';
        let kexColor = isPqc ? 'var(--accent-cyan)' : (kex === 'RSA' ? 'var(--accent-pink)' : 'var(--text-primary)');

        return `<tr>
            <td><span class="probe-label">${label}</span><br><span style="color:var(--text-dim);font-size:0.7rem">${description}</span></td>
            <td style="color:${tlsColor};font-weight:600">${tls}</td>
            <td style="color:${kexColor}">${kex}</td>
            <td style="color:var(--text-dim)">${cipher}</td>
            <td>${bits}${err}</td>
        </tr>`;
    }

    const cert = fp.certificate || {};
    const certInfo = cert.subject
        ? `<div style="font-size:0.75rem;color:var(--text-dim);margin-top:10px;padding:8px 12px;background:rgba(255,255,255,0.03);border-radius:6px;border:1px solid var(--border-subtle)">
            <strong style="color:var(--text-secondary)">Certificate</strong> &nbsp;
            ${escHtml(cert.subject || '')} &nbsp;·&nbsp;
            expires ${escHtml(cert.not_after || '?')} &nbsp;·&nbsp;
            <span style="color:${(cert.days_until_expiry||0) < 30 ? 'var(--accent-pink)' : 'var(--accent-green)'}">${cert.days_until_expiry ?? '?'} days left</span>
          </div>` : '';

    container.innerHTML = `
        <div style="margin-top:14px;padding-top:14px;border-top:1px solid var(--border-subtle);">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">
                <span style="font-size:1rem;font-weight:700;color:var(--text-primary)">${escHtml(fp.hostname)}</span>
                <span class="status-badge status-badge--${cls}">${lbl}</span>
                <span style="font-size:1.1rem;font-weight:700;color:${scColor}">Q-Score: ${score}</span>
                <span style="color:var(--text-dim);font-size:0.75rem;margin-left:auto">${fp.scan_duration_ms ? fp.scan_duration_ms + ' ms' : ''}</span>
            </div>
            <table class="trimode-table" style="margin-bottom:0">
                <thead><tr><th>Probe</th><th>TLS Version</th><th>Key Exchange</th><th>Cipher Suite</th><th>Key Bits</th></tr></thead>
                <tbody>
                    ${probeRow('A', fp.probe_a, 'PQC-capable')}
                    ${probeRow('B', fp.probe_b, 'TLS 1.3 classical')}
                    ${probeRow('C', fp.probe_c, 'TLS 1.2 downgrade')}
                </tbody>
            </table>
            ${certInfo}
        </div>`;
}

function renderTrimode(data) {
    const empty = document.getElementById('trimodeEmpty');
    const content = document.getElementById('trimodeContent');
    if (!data || !data.fingerprints || data.fingerprints.length === 0) {
        if (empty) empty.style.display = '';
        if (content) content.style.display = 'none';
        return;
    }
    if (empty) empty.style.display = 'none';
    if (content) content.style.display = '';

    // Summary stats
    const fps = data.fingerprints;
    const counts = { safe: 0, transition: 0, vulnerable: 0, critical: 0, unknown: 0 };
    fps.forEach(fp => {
        const s = fp.q_score?.status || 'UNKNOWN';
        if (s === 'FULLY_QUANTUM_SAFE') counts.safe++;
        else if (s === 'PQC_TRANSITION') counts.transition++;
        else if (s === 'QUANTUM_VULNERABLE') counts.vulnerable++;
        else if (s === 'CRITICALLY_VULNERABLE') counts.critical++;
        else counts.unknown++;
    });

    setText('tmStatTotal', fps.length);
    setText('tmStatMode', `Mode: ${data.mode || 'live'}`);
    setText('tmStatSafe', counts.safe);
    setText('tmStatTransition', counts.transition);
    setText('tmStatVulnerable', counts.vulnerable);
    setText('tmStatCritical', counts.critical);
    setText('tmAssetCount', `${fps.length} assets`);

    // Demo banner
    const banner = document.getElementById('trimodeDemoBanner');
    if (banner) banner.style.display = data.mode === 'demo' ? '' : 'none';

    // Build tri-mode table with per-row expert-insight expansion
    const tbody = fps.map((fp, idx) => {
        const st = fp.q_score?.status || 'UNKNOWN';
        const cls = getStatusClass(st);
        const lbl = getStatusLabel(st);
        const score = fp.q_score?.total ?? '—';
        const scColor = getScoreColor(score);
        const insightId = `tmInsight_${idx}`;

        function probeCell(p, mode) {
            if (!p) return '<span class="probe-err">—</span>';
            if (p.error) return `<span class="probe-err">${escHtml(p.error)}</span>`;
            const tls = p.tls_version || '—';
            const kex = p.key_exchange || '—';
            const bits = p.cipher_bits ? `${p.cipher_bits}b` : '';

            let colorClass = 'probe-warn';
            if (tls.includes('1.3') && (kex.includes('ML-KEM') || kex.includes('MLKEM'))) colorClass = 'probe-ok';
            else if (tls.includes('1.1') || tls.includes('1.0') || kex === 'RSA') colorClass = 'probe-bad';

            return `<span class="${colorClass}">${tls} | ${kex} | ${bits}</span>`;
        }

        function probeInsight(p, label, desc) {
            if (!p) return '';
            const tls = p.tls_version || '';
            const kex = p.key_exchange || '';
            const isPqc = kex.includes('ML-KEM') || kex.includes('MLKEM') || kex.includes('X25519MLKEM');
            const isLegacy = tls.includes('1.0') || tls.includes('1.1') || kex === 'RSA';
            const icon = isPqc ? '✅' : isLegacy ? '❌' : '⚠️';
            const tone = isPqc ? '#16A34A' : isLegacy ? '#DC2626' : '#D97706';
            let explanation = isPqc
                ? 'Post-Quantum Cryptography enabled — resistant to CRQC Shor\'s algorithm attacks.'
                : isLegacy
                    ? 'Legacy TLS or RSA key exchange — vulnerable to harvest-now-decrypt-later (HNDL) attacks.'
                    : 'Classical TLS 1.3 only — strong against today\'s threats but not quantum-resistant.';
            if (p.error) explanation = `Probe failed: ${p.error}`;
            return `<div style="margin-bottom:8px;padding:8px 12px;border-radius:6px;background:rgba(0,0,0,0.2);border-left:3px solid ${tone};">
                <div style="font-weight:600;font-size:0.8rem;color:${tone};margin-bottom:2px;">${icon} ${label} — ${desc}</div>
                <div style="font-size:0.75rem;color:var(--text-secondary);">${explanation}</div>
                <div style="font-size:0.72rem;color:var(--text-dim);margin-top:4px;">TLS: ${tls || '—'} · KEX: ${kex || '—'} · Auth: ${p.authentication || '—'}</div>
            </div>`;
        }

        const findings = fp.q_score?.findings || [];
        const recommendations = fp.q_score?.recommendations || [];
        const findingsHtml = findings.length
            ? findings.map(f => `<li style="margin-bottom:3px;">${escHtml(f)}</li>`).join('')
            : '<li style="color:var(--text-dim);">No findings — posture is clean.</li>';
        const recommendationsHtml = recommendations.length
            ? recommendations.map(r => `<li style="margin-bottom:3px;color:var(--accent-cyan);">${escHtml(r)}</li>`).join('')
            : '<li style="color:var(--text-dim);">No remediation required.</li>';

        const insightPanel = `<tr id="${insightId}" style="display:none;">
            <td colspan="7" style="padding:0 12px 12px 12px;background:rgba(0,0,0,0.15);">
                <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;padding-top:12px;">
                    <div>${probeInsight(fp.probe_a, 'Probe A', 'PQC-capable')}</div>
                    <div>${probeInsight(fp.probe_b, 'Probe B', 'TLS 1.3 classical')}</div>
                    <div>${probeInsight(fp.probe_c, 'Probe C', 'TLS 1.2 downgrade')}</div>
                </div>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:8px;">
                    <div>
                        <div style="font-size:0.75rem;font-weight:700;color:#D97706;margin-bottom:6px;">FINDINGS</div>
                        <ul style="margin:0;padding-left:18px;font-size:0.75rem;color:var(--text-secondary);">${findingsHtml}</ul>
                    </div>
                    <div>
                        <div style="font-size:0.75rem;font-weight:700;color:var(--accent-cyan);margin-bottom:6px;">REMEDIATION</div>
                        <ul style="margin:0;padding-left:18px;font-size:0.75rem;">${recommendationsHtml}</ul>
                    </div>
                </div>
            </td>
        </tr>`;

        const mainRow = `<tr style="cursor:pointer;" onclick="document.getElementById('${insightId}').style.display=document.getElementById('${insightId}').style.display==='none'?'':'none'">
            <td><strong>${escHtml(fp.hostname)}</strong><br><span style="color:var(--text-dim);font-size:0.7rem">${fp.asset_type || 'web'} :${fp.port}</span></td>
            <td><span class="status-badge status-badge--${cls}">${lbl}</span></td>
            <td style="color:${scColor}; font-weight:600;">${score}</td>
            <td class="probe-cell"><span class="probe-label">A</span> ${probeCell(fp.probe_a)}</td>
            <td class="probe-cell"><span class="probe-label">B</span> ${probeCell(fp.probe_b)}</td>
            <td class="probe-cell"><span class="probe-label">C</span> ${probeCell(fp.probe_c)}</td>
            <td style="color:var(--text-dim);font-size:0.7rem;">▼ insights</td>
        </tr>`;

        return mainRow + insightPanel;
    }).join('');

    const container = document.getElementById('trimodeTableContainer');
    if (container) {
        container.innerHTML = `
            <table class="trimode-table">
                <thead><tr>
                    <th>Asset</th><th>Status</th><th>Q-Score</th>
                    <th>Probe A (PQC)</th><th>Probe B (TLS 1.3)</th><th>Probe C (Downgrade)</th>
                    <th></th>
                </tr></thead>
                <tbody>${tbody}</tbody>
            </table>`;
    }
}

function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}

function escHtml(str) {
    const div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
}

function displayScanSerial(scanId, fallbackNumber = null) {
    if (Number.isInteger(fallbackNumber) && fallbackNumber > 0) {
        return `Scan ${String(fallbackNumber).padStart(2, '0')}`;
    }
    const raw = String(scanId || '').trim();
    if (!raw) return 'Scan';
    if (/^\d+$/.test(raw)) return `Scan ${raw}`;
    return `Scan ${raw.replace(/-/g, '').slice(0, 6).toUpperCase()}`;
}

function lookupScanSerial(scanId) {
    const scans = Array.isArray(dbScansData) ? dbScansData : [];
    const index = scans.findIndex((scan) => String(scan.id) === String(scanId));
    if (index >= 0) {
        return displayScanSerial(scanId, scans.length - index);
    }
    return displayScanSerial(scanId);
}

function scanSerialForPosition(scans, scan, index) {
    return displayScanSerial(scan?.id, Array.isArray(scans) ? scans.length - index : null);
}

function normalizeStoredAssetForPhase7(asset) {
    if (!asset || typeof asset !== 'object') {
        return null;
    }

    const innerAsset = asset.asset && typeof asset.asset === 'object' ? asset.asset : {};
    const qScore = asset.q_score && typeof asset.q_score === 'object' ? asset.q_score : {};
    const score = Number(
        asset.worst_case_score
        ?? asset.worst_score
        ?? asset.typical_score
        ?? qScore.total
        ?? asset.score
        ?? 0
    ) || 0;
    const status = asset.status || asset.pqc_status || qScore.status || 'UNKNOWN';

    return {
        hostname: asset.hostname || innerAsset.hostname || innerAsset.ip || asset.asset || 'unknown',
        port: Number(asset.port ?? innerAsset.port ?? 443) || 443,
        asset_type: asset.asset_type || innerAsset.asset_type || 'web',
        status,
        pqc_support: Boolean(asset.pqc_support),
        best_case_score: Number(asset.best_case_score ?? score) || 0,
        typical_score: Number(asset.typical_score ?? score) || 0,
        worst_case_score: score,
        agility_score: Number(asset.agility_score ?? 0) || 0,
        summary: asset.summary || '',
        recommended_action: asset.recommended_action || '',
        agility_details: Array.isArray(asset.agility_details) ? asset.agility_details : [],
    };
}

function formatUiDateTime(value, includeTime = true) {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return String(value);
    }
    return includeTime
        ? date.toLocaleString('en-IN', {
            day: '2-digit',
            month: 'short',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
        })
        : date.toLocaleDateString('en-IN', {
            day: '2-digit',
            month: 'short',
            year: 'numeric',
        });
}

function shortenDocumentId(value, fallback = '—') {
    const raw = String(value || '')
        .replace(/^urn:uuid:/i, '')
        .trim();
    if (!raw) return fallback;
    return raw.replace(/-/g, '').slice(0, 8).toUpperCase();
}

function extractNamedProperty(properties, key) {
    if (!Array.isArray(properties)) return '';
    const match = properties.find((property) => property?.name === key);
    return match?.value || '';
}

function compliancePalette(status) {
    const normalized = String(status || '').toUpperCase();
    if (normalized === 'COMPLIANT' || normalized === 'FULLY_QUANTUM_SAFE') {
        return { bg: 'rgba(34, 197, 94, 0.12)', color: 'var(--accent-green)' };
    }
    if (normalized === 'PARTIALLY_COMPLIANT' || normalized === 'PQC_TRANSITION') {
        return { bg: 'rgba(217, 119, 6, 0.12)', color: '#D97706' };
    }
    if (normalized === 'NOT_APPLICABLE' || normalized === 'UNKNOWN') {
        return { bg: 'rgba(148, 163, 184, 0.12)', color: 'var(--text-secondary)' };
    }
    return { bg: 'rgba(220, 38, 38, 0.12)', color: '#DC2626' };
}

function renderToneBadge(label, status) {
    const tone = compliancePalette(status || label);
    return `<span style="display:inline-flex;align-items:center;padding:0.2rem 0.55rem;border-radius:999px;background:${tone.bg};color:${tone.color};font-size:0.72rem;font-weight:700;">${escHtml(label || '—')}</span>`;
}

async function openHistoryScanDetails(scanId) {
    showLoading(`Loading ${lookupScanSerial(scanId)} details...`);
    try {
        const scan = await apiCall(`/api/db/scans/${scanId}`);
        const details = scan.details && typeof scan.details === 'object' ? scan.details : {};
        const parsedAssets = Array.isArray(details.assets)
            ? details.assets
            : (scan.results_json ? JSON.parse(scan.results_json) : []);
        const assets = parsedAssets
            .map(normalizeStoredAssetForPhase7)
            .filter(Boolean);
        const phase7Payload = {
            mode: scan.mode || 'live',
            scan_id: scan.id,
            total_assets: scan.total_assets || assets.length,
            avg_worst_score: Number(scan.avg_score || scan.average_q_score || 0),
            summary: {
                fully_quantum_safe: scan.fully_safe ?? scan.fully_quantum_safe ?? 0,
                pqc_transition: scan.pqc_trans ?? scan.pqc_transition ?? 0,
                quantum_vulnerable: scan.q_vuln ?? scan.quantum_vulnerable ?? 0,
                critically_vulnerable: scan.crit_vuln ?? scan.critically_vulnerable ?? 0,
                unknown: scan.unknown ?? 0,
            },
            assets,
        };
        classifiedData = phase7Payload;
        renderPhase7(phase7Payload);
        const storedPhase9 = details.phase9
            || (details.cbom || details.attestation || details.labels || details.regression
                ? {
                    cbom: details.cbom || {},
                    attestation: details.attestation || {},
                    attestation_summary: details.attestation_summary || {},
                    labels: details.labels || {},
                    regression: details.regression || {},
                    registry: details.registry || {},
                }
                : null);
        if (storedPhase9) {
            phase9Data = storedPhase9;
            latestCbomPayload = storedPhase9.cbom || null;
            renderPhase9(storedPhase9);
        }
        switchTab('phase7');
        showToast(`Opened ${lookupScanSerial(scanId)} details`, 'success');
    } catch (e) {
        showToast('Failed to load scan details: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

async function deleteScan(scanId) {
    const label = lookupScanSerial(scanId);
    if (!window.confirm(`Delete ${label}? This cannot be undone.`)) return;
    showLoading(`Deleting ${label}...`);
    try {
        await authorizedFetch(`${API_BASE}/api/db/scans/${scanId}`, { method: 'DELETE' });
        dbScansData = (dbScansData || []).filter((scan) => String(scan.id) !== String(scanId));
        latestHistoryPayload = null;
        historyData = null;
        renderDbScans(dbScansData);
        const historyContent = document.getElementById('historyContent');
        if (historyContent?.style.display !== 'none') {
            await loadLiveHistory();
        }
        showToast(`${label} deleted`, 'success');
    } catch (e) {
        showToast('Failed to delete scan: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
   Phase 6: Historical Trends & Baseline
   ═══════════════════════════════════════════════════════════════════════════ */

async function loadHistory() {
    // Delegate to loadLiveHistory which uses /api/history + /api/compare/latest
    // and handles both stored scans and the demo fallback gracefully.
    return loadLiveHistory();
}

async function loadLiveHistory() {
    showLoading('Loading previous scan history...');
    try {
        const [historyPayload, comparePayload] = await Promise.all([
            fetchHistoryLatest(true),
            apiCall('/api/compare/latest').catch(() => null),
        ]);
        const scans = Array.isArray(historyPayload?.scans) ? historyPayload.scans : [];
        if (!scans || !scans.length) {
            showToast('No previous scans found yet — run a scan first', 'info');
            hideLoading();
            return;
        }

        const recentScans = scans.slice(-10);
        const weeks = recentScans.map((s, i) => ({
            week: i + 1,
            scan_date: s.scan_date,
            total_assets: s.total_assets || 0,
            quantum_safety_score: Math.round(Number(s.average_q_score ?? s.avg_score ?? 0)),
            fully_quantum_safe: s.fully_quantum_safe ?? s.fully_safe ?? 0,
            pqc_transition: s.pqc_transition ?? s.pqc_trans ?? 0,
            quantum_vulnerable: s.quantum_vulnerable ?? s.q_vuln ?? 0,
            critically_vulnerable: s.critically_vulnerable ?? s.crit_vuln ?? 0,
            unknown: s.unknown || 0,
        }));

        const modeLabel = historyPayload?.demo_mode ? 'demo' : 'stored scans';
        const histData = { mode: modeLabel, weeks, scans };
        historyData = histData;
        renderHistory(histData);

        const latest = scans[scans.length - 1];
        const previous = scans.length >= 2 ? scans[scans.length - 2] : null;
        if (comparePayload?.scan_a && comparePayload?.scan_b) {
            renderCompareBaseline(comparePayload);
        } else {
            renderLiveBaseline(latest, previous);
        }

        document.getElementById('historyEmpty').style.display = 'none';
        document.getElementById('historyContent').style.display = '';
        showToast(`Loaded ${scans.length} previous scans`, 'success');
    } catch (e) {
        showToast('Failed to load previous scans: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

function renderLiveBaseline(latest, previous) {
    const container = document.getElementById('baselineContent');
    if (!container) return;

    if (!latest) {
        container.innerHTML = '<div class="empty-state"><div class="empty-state-desc">No scan data available</div></div>';
        return;
    }

    const latestDomain = latest.domain || 'unknown';
    const prevDomain = previous ? (previous.domain || 'unknown') : '—';
    const delta = previous ? {
        total: (latest.total_assets || 0) - (previous.total_assets || 0),
        avg: ((latest.avg_score || 0) - (previous.avg_score || 0)).toFixed(1),
        safe: (latest.fully_safe || 0) - (previous.fully_safe || 0),
        trans: (latest.pqc_trans || 0) - (previous.pqc_trans || 0),
        vuln: (latest.q_vuln || 0) - (previous.q_vuln || 0),
        crit: (latest.crit_vuln || 0) - (previous.crit_vuln || 0),
    } : null;

    function diffBadge(val) {
        if (!val || val == 0) return '<span style="color:var(--text-dim);">0</span>';
        return val > 0
            ? `<span style="color:var(--accent-green);font-weight:600;">+${val}</span>`
            : `<span style="color:#DC2626;font-weight:600;">${val}</span>`;
    }

    container.innerHTML = `
        <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:16px;">
            <div class="stat-card stat-card--total" style="padding:12px;">
                <div class="stat-value" style="font-size:1.4rem;">${latest.total_assets || 0}</div>
                <div class="stat-label">Latest Assets</div>
            </div>
            <div class="stat-card stat-card--safe" style="padding:12px;">
                <div class="stat-value" style="font-size:1.4rem;">${latest.fully_safe || 0}</div>
                <div class="stat-label">Quantum Safe</div>
            </div>
            <div class="stat-card stat-card--transition" style="padding:12px;">
                <div class="stat-value" style="font-size:1.4rem;">${latest.pqc_trans || 0}</div>
                <div class="stat-label">Transition</div>
            </div>
            <div class="stat-card stat-card--vulnerable" style="padding:12px;">
                <div class="stat-value" style="font-size:1.4rem;">${latest.q_vuln || 0}</div>
                <div class="stat-label">Vulnerable</div>
            </div>
            <div class="stat-card stat-card--critical" style="padding:12px;">
                <div class="stat-value" style="font-size:1.4rem;">${latest.crit_vuln || 0}</div>
                <div class="stat-label">Critical</div>
            </div>
        </div>
        ${delta ? `
        <table class="asset-table" style="margin-bottom:12px;"><thead><tr>
            <th>Metric</th><th>Latest (#${latest.id})</th><th>Previous (#${previous.id})</th><th>Delta</th>
        </tr></thead><tbody>
            <tr><td>Domain</td><td>${escHtml(latestDomain)}</td><td>${escHtml(prevDomain)}</td><td>—</td></tr>
            <tr><td>Total Assets</td><td>${latest.total_assets || 0}</td><td>${previous.total_assets || 0}</td><td>${diffBadge(delta.total)}</td></tr>
            <tr><td>Avg Score</td><td>${latest.avg_score || 0}</td><td>${previous.avg_score || 0}</td><td>${diffBadge(delta.avg)}</td></tr>
            <tr><td style="color:var(--status-safe)">Fully Safe</td><td>${latest.fully_safe || 0}</td><td>${previous.fully_safe || 0}</td><td>${diffBadge(delta.safe)}</td></tr>
            <tr><td style="color:var(--status-transition)">PQC Transition</td><td>${latest.pqc_trans || 0}</td><td>${previous.pqc_trans || 0}</td><td>${diffBadge(delta.trans)}</td></tr>
            <tr><td style="color:var(--status-vulnerable)">Vulnerable</td><td>${latest.q_vuln || 0}</td><td>${previous.q_vuln || 0}</td><td>${diffBadge(delta.vuln)}</td></tr>
            <tr><td style="color:var(--status-critical)">Critical</td><td>${latest.crit_vuln || 0}</td><td>${previous.crit_vuln || 0}</td><td>${diffBadge(delta.crit)}</td></tr>
        </tbody></table>` : '<p style="color:var(--text-dim);font-size:0.82rem;">Only one scan in database — run another scan for comparison.</p>'}
        <p style="font-size:0.82rem;color:var(--text-secondary);">
            Latest scan: <strong>${escHtml(latestDomain)}</strong> (${latest.mode || 'live'}) on ${latest.scan_date ? new Date(latest.scan_date).toLocaleString() : '—'}
        </p>
    `;
}

function renderCompareBaseline(comparePayload) {
    const container = document.getElementById('baselineContent');
    if (!container) return;
    const latest = comparePayload?.scan_b || {};
    const previous = comparePayload?.scan_a || {};
    const delta = comparePayload?.delta || {};
    const latestDomain = latest.domain || 'latest scan';
    const previousDomain = previous.domain || 'previous scan';

    function diffBadge(val) {
        if (!val || Number(val) === 0) return '<span style="color:var(--text-dim);">0</span>';
        return Number(val) > 0
            ? `<span style="color:var(--accent-green);font-weight:600;">+${val}</span>`
            : `<span style="color:#DC2626;font-weight:600;">${val}</span>`;
    }

    container.innerHTML = `
        <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:16px;">
            <div class="stat-card stat-card--total" style="padding:12px;">
                <div class="stat-value" style="font-size:1.4rem;">${latest.total || latest.total_assets || 0}</div>
                <div class="stat-label">Latest Assets</div>
            </div>
            <div class="stat-card stat-card--safe" style="padding:12px;">
                <div class="stat-value" style="font-size:1.4rem;">${latest.fully_safe || 0}</div>
                <div class="stat-label">Quantum Safe</div>
            </div>
            <div class="stat-card stat-card--transition" style="padding:12px;">
                <div class="stat-value" style="font-size:1.4rem;">${latest.pqc_trans || 0}</div>
                <div class="stat-label">Transition</div>
            </div>
            <div class="stat-card stat-card--vulnerable" style="padding:12px;">
                <div class="stat-value" style="font-size:1.4rem;">${latest.q_vuln || 0}</div>
                <div class="stat-label">Vulnerable</div>
            </div>
            <div class="stat-card stat-card--critical" style="padding:12px;">
                <div class="stat-value" style="font-size:1.4rem;">${latest.crit_vuln || 0}</div>
                <div class="stat-label">Critical</div>
            </div>
        </div>
        <table class="asset-table" style="margin-bottom:12px;"><thead><tr>
            <th>Metric</th><th>Latest</th><th>Previous</th><th>Delta</th>
        </tr></thead><tbody>
            <tr><td>Scan Label</td><td>${escHtml(latestDomain)}</td><td>${escHtml(previousDomain)}</td><td>—</td></tr>
            <tr><td>Total Assets</td><td>${latest.total || latest.total_assets || 0}</td><td>${previous.total || previous.total_assets || 0}</td><td>${diffBadge(delta.total_assets || 0)}</td></tr>
            <tr><td>Avg Score</td><td>${latest.avg || latest.avg_score || 0}</td><td>${previous.avg || previous.avg_score || 0}</td><td>${diffBadge(delta.avg_score || 0)}</td></tr>
            <tr><td style="color:var(--status-safe)">Fully Safe</td><td>${latest.fully_safe || 0}</td><td>${previous.fully_safe || 0}</td><td>${diffBadge(delta.fully_safe || 0)}</td></tr>
            <tr><td style="color:var(--status-transition)">PQC Transition</td><td>${latest.pqc_trans || 0}</td><td>${previous.pqc_trans || 0}</td><td>${diffBadge(delta.pqc_trans || 0)}</td></tr>
            <tr><td style="color:var(--status-vulnerable)">Vulnerable</td><td>${latest.q_vuln || 0}</td><td>${previous.q_vuln || 0}</td><td>${diffBadge(delta.q_vuln || 0)}</td></tr>
            <tr><td style="color:var(--status-critical)">Critical</td><td>${latest.crit_vuln || 0}</td><td>${previous.crit_vuln || 0}</td><td>${diffBadge(delta.crit_vuln || 0)}</td></tr>
        </tbody></table>
    `;
}

function renderHistory(data) {
    if (!data || !data.weeks) return;
    const modeEl = document.getElementById('historyMode');
    if (modeEl) modeEl.textContent = data.mode || 'live';
    const scans = Array.isArray(data.scans) ? data.scans : [];

    const rows = data.weeks.map((w, index) => {
        const score = Math.max(0, Math.min(100, Number(w.quantum_safety_score || 0)));
        const barW = Math.round((score / 100) * 200);
        const date = w.scan_date ? new Date(w.scan_date).toLocaleDateString() : `Scan ${w.week}`;
        const scan = scans[index] || null;
        const serial = scanSerialForPosition(scans, scan, index);
        const rowAction = scan?.id
            ? `onclick="openHistoryScanDetails('${escHtml(String(scan.id))}')" style="cursor:pointer;"`
            : '';
        return `<tr ${rowAction}>
            <td>${serial}</td>
            <td>${date}</td>
            <td>${w.total_assets}</td>
            <td style="font-weight:600;color:${getScoreColor(score)};">${score} <span class="score-bar" style="width:${barW}px;"></span></td>
            <td style="color:var(--status-safe);">${w.fully_quantum_safe}</td>
            <td style="color:var(--status-transition);">${w.pqc_transition}</td>
            <td style="color:var(--status-vulnerable);">${w.quantum_vulnerable}</td>
            <td style="color:var(--status-critical);">${w.critically_vulnerable}</td>
            <td style="color:var(--status-unknown);">${w.unknown}</td>
        </tr>`;
    }).join('');

    const container = document.getElementById('historyTable');
    if (container) {
        container.innerHTML = `
            <table class="history-table">
                <thead><tr>
                    <th>Scan</th><th>Date</th><th>Assets</th><th>Average Q-Score</th>
                    <th>Safe</th><th>Transition</th><th>Vulnerable</th><th>Critical</th><th>Unknown</th>
                </tr></thead>
                <tbody>${rows}</tbody>
            </table>`;
    }
}

function renderBaseline(data) {
    const container = document.getElementById('baselineContent');
    if (!container) return;
    if (!data || !data.fingerprints) {
        container.innerHTML = '<div class="empty-state"><div class="empty-state-desc">No baseline data</div></div>';
        return;
    }

    const total = data.total_assets || data.fingerprints.length;
    const counts = { safe: 0, transition: 0, vulnerable: 0, critical: 0, unknown: 0 };
    data.fingerprints.forEach(fp => {
        const s = fp.q_score?.status || 'UNKNOWN';
        if (s === 'FULLY_QUANTUM_SAFE') counts.safe++;
        else if (s === 'PQC_TRANSITION') counts.transition++;
        else if (s === 'QUANTUM_VULNERABLE') counts.vulnerable++;
        else if (s === 'CRITICALLY_VULNERABLE') counts.critical++;
        else counts.unknown++;
    });

    container.innerHTML = `
        <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:16px;">
            <div class="stat-card stat-card--total" style="padding:12px;">
                <div class="stat-value" style="font-size:1.4rem;">${total}</div>
                <div class="stat-label">Baseline Assets</div>
            </div>
            <div class="stat-card stat-card--safe" style="padding:12px;">
                <div class="stat-value" style="font-size:1.4rem;">${counts.safe}</div>
                <div class="stat-label">Quantum Safe</div>
            </div>
            <div class="stat-card stat-card--transition" style="padding:12px;">
                <div class="stat-value" style="font-size:1.4rem;">${counts.transition}</div>
                <div class="stat-label">Transition</div>
            </div>
            <div class="stat-card stat-card--vulnerable" style="padding:12px;">
                <div class="stat-value" style="font-size:1.4rem;">${counts.vulnerable}</div>
                <div class="stat-label">Vulnerable</div>
            </div>
            <div class="stat-card stat-card--critical" style="padding:12px;">
                <div class="stat-value" style="font-size:1.4rem;">${counts.critical}</div>
                <div class="stat-label">Critical</div>
            </div>
        </div>
        <p style="font-size:0.82rem;color:var(--text-secondary);">
            ${data.description || 'Baseline comparison from 1 week ago.'}
            Current scan: <strong>${trimodeData?.total_assets || '—'}</strong> assets.
            Baseline: <strong>${total}</strong> assets (${trimodeData?.total_assets - total > 0 ? '+' : ''}${(trimodeData?.total_assets || 0) - total} net change).
        </p>
        <div class="demo-banner" style="margin-top:12px;">
            ⚠️ <strong>SIMULATED BASELINE</strong> — This comparison uses demo seed data.
        </div>
    `;
}


/* ═══════════════════════════════════════════════════════════════════════════
    PQC Classification + Agility Assessment + SQLite DB
   ═══════════════════════════════════════════════════════════════════════════ */

async function runPhase7Demo() {
    showLoading('Running tri-mode classification on 21 demo assets...');
    try {
        const data = await apiCall('/api/classify/demo');
        classifiedData = data;
        renderPhase7(data);
        loadDbScans();
        showToast(`Classified ${data.total_assets} assets (${displayScanSerial(data.scan_id)})`, 'success');
    } catch (e) {
        showToast('Classification failed: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

async function runPhase7Live() {
    const domain = (document.getElementById('p7DomainInput')?.value || '').trim();
    if (!domain) { showToast('Enter a domain to classify', 'error'); return; }
    showLoading(`Running live classification on ${domain}... (this may take 15-30s)`);
    try {
        const data = await apiCall(`/api/classify/live/${encodeURIComponent(domain)}`, 'POST');
        classifiedData = data;
        renderPhase7(data);
        loadDbScans();
        showToast(`Classified ${data.total_assets} live assets for ${domain} (${displayScanSerial(data.scan_id)})`, 'success');
    } catch (e) {
        showToast('Live classification failed: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

function renderPhase7(data) {
    document.getElementById('p7Empty').style.display = 'none';
    document.getElementById('p7Content').style.display = '';

    const s = data.summary || {};
    const total = data.total_assets || 0;

    animateNumber('p7Total', total);
    animateNumber('p7Safe', s.fully_quantum_safe || 0);
    animateNumber('p7Trans', s.pqc_transition || 0);
    animateNumber('p7Vuln', s.quantum_vulnerable || 0);
    animateNumber('p7Crit', s.critically_vulnerable || 0);
    animateNumber('p7Unknown', s.unknown || 0);
    document.getElementById('p7AvgScore').textContent = `Avg Worst: ${data.avg_worst_score || 0}`;

    const assets = data.assets || [];
    document.getElementById('p7AssetCount').textContent = `${assets.length} assets`;

    renderP7Table(assets);
    renderP7Agility(assets);

    const banner = document.getElementById('p7DemoBanner');
    if (banner) banner.style.display = data.mode === 'demo' ? '' : 'none';
}

function renderP7Table(assets) {
    const container = document.getElementById('p7TableContainer');
    if (!assets.length) {
        container.innerHTML = '<div class="empty-state"><div class="empty-state-title">No classified assets</div></div>';
        return;
    }

    const sorted = [...assets].sort((a, b) => (a.worst_case_score || 0) - (b.worst_case_score || 0));

    let html = `<table class="asset-table"><thead><tr>
        <th>Asset</th><th>Type</th><th>Status</th>
        <th style="text-align:center;">PQC Support</th>
        <th>Best (A)</th><th>Typical (B)</th><th>Worst (C)</th>
        <th>Agility</th><th>Summary</th><th>Action</th>
    </tr></thead><tbody>`;

    for (const a of sorted) {
        const cls = getStatusClass(a.status);
        const lbl = getStatusLabel(a.status);
        const bestCol = getScoreColor(a.best_case_score || 0);
        const typCol = getScoreColor(a.typical_score || 0);
        const worstCol = getScoreColor(a.worst_case_score || 0);
        const agiCol = a.agility_score >= 12 ? 'var(--status-safe)' : a.agility_score >= 6 ? 'var(--status-transition)' : 'var(--status-vulnerable)';
        
        const pqcMark = a.pqc_support ? '<span style="color: var(--status-safe); font-weight: bold;">✔</span>' : '<span style="color: var(--status-critical); font-weight: bold;">✘</span>';

        html += `<tr>
            <td><span class="asset-hostname">${escHtml(a.hostname)}:${a.port}</span></td>
            <td><span class="asset-type">${a.asset_type || 'web'}</span></td>
            <td><span class="status-badge status-badge--${cls}">${lbl}</span></td>
            <td style="text-align:center;">${pqcMark}</td>
            <td>
                <div class="qscore-bar-container">
                    <div class="qscore-bar"><div class="qscore-bar-fill" style="width:${a.best_case_score}%;background:${bestCol}"></div></div>
                    <span class="qscore-value" style="color:${bestCol}">${a.best_case_score}</span>
                </div>
            </td>
            <td>
                <div class="qscore-bar-container">
                    <div class="qscore-bar"><div class="qscore-bar-fill" style="width:${a.typical_score}%;background:${typCol}"></div></div>
                    <span class="qscore-value" style="color:${typCol}">${a.typical_score}</span>
                </div>
            </td>
            <td>
                <div class="qscore-bar-container">
                    <div class="qscore-bar"><div class="qscore-bar-fill" style="width:${a.worst_case_score}%;background:${worstCol}"></div></div>
                    <span class="qscore-value" style="color:${worstCol}">${a.worst_case_score}</span>
                </div>
            </td>
            <td style="text-align:center;"><span style="color:${agiCol};font-weight:700;">${a.agility_score}/15</span></td>
            <td style="font-size:0.75rem;max-width:200px;">${escHtml(a.summary)}</td>
            <td style="font-size:0.75rem;color:var(--accent-cyan);max-width:180px;">${escHtml(a.recommended_action)}</td>
        </tr>`;
    }

    html += '</tbody></table>';
    container.innerHTML = html;

    requestAnimationFrame(() => {
        container.querySelectorAll('.qscore-bar-fill').forEach(el => {
            const w = el.style.width;
            el.style.width = '0';
            requestAnimationFrame(() => { el.style.width = w; });
        });
    });
}

function renderP7Agility(assets) {
    const container = document.getElementById('p7AgilityContainer');
    if (!assets.length) {
        container.innerHTML = '<div class="empty-state"><div class="empty-state-desc">No agility data</div></div>';
        return;
    }

    const sorted = [...assets].sort((a, b) => (a.agility_score || 0) - (b.agility_score || 0));

    let html = `<table class="asset-table"><thead><tr>
        <th>Asset</th><th>Score</th><th>Bar</th><th>Indicators</th>
    </tr></thead><tbody>`;

    for (const a of sorted) {
        const agiPct = ((a.agility_score || 0) / 15) * 100;
        const agiCol = a.agility_score >= 12 ? 'var(--status-safe)' : a.agility_score >= 6 ? 'var(--status-transition)' : 'var(--status-vulnerable)';
        const indicators = (a.agility_details || []).map(d => {
            const icon = d.met ? '✅' : '❌';
            return `<span style="font-size:0.72rem;margin-right:8px;" title="${escHtml(d.indicator)}: ${d.met ? 'met' : 'not met'} (+${d.points}pt)">${icon} ${escHtml(d.indicator)} <span style="color:${d.met ? 'var(--accent-green)' : 'var(--text-dim)'}">(+${d.points})</span></span>`;
        }).join('');

        html += `<tr>
            <td><span class="asset-hostname">${escHtml(a.hostname)}:${a.port}</span></td>
            <td style="text-align:center;"><span style="color:${agiCol};font-weight:700;">${a.agility_score}/15</span></td>
            <td style="min-width:100px;">
                <div class="qscore-bar"><div class="qscore-bar-fill" style="width:${agiPct}%;background:${agiCol}"></div></div>
            </td>
            <td>${indicators}</td>
        </tr>`;
    }

    html += '</tbody></table>';
    container.innerHTML = html;
}


/* ─── Phase 7: Scan Database UI ─────────────────────────────────────────── */

async function loadDbScans() {
    try {
        const [scans, compareOptions] = await Promise.all([
            apiCall('/api/db/scans'),
            apiCall('/api/scans').catch(() => []),
        ]);
        dbScansData = scans;
        compareScanOptions = Array.isArray(compareOptions) && compareOptions.length ? compareOptions : scans;
        renderDbScans(scans);
    } catch (e) {
        console.warn('Failed to load DB scans:', e);
    }
}

function formatCompareScanOption(scan, index, total) {
    if (!scan) return '';
    const serial = displayScanSerial(scan.id, total - index);
    const created = formatUiDateTime(scan.created_at || scan.scan_date, false);
    const domain = scan.domain || scan.mode || 'scan';
    const score = Number(scan.overall_score ?? scan.avg_score ?? 0) || 0;
    return `${serial} • ${created} • Score ${score} • ${domain}`;
}

function renderDbScans(scans) {
    const container = document.getElementById('p7DbScansContainer');
    if (!scans || !scans.length) {
        container.innerHTML = '<div class="empty-state"><div class="empty-state-desc">No scans stored yet</div></div>';
        return;
    }

    const compareOptions = Array.isArray(compareScanOptions) && compareScanOptions.length ? compareScanOptions : scans;
    const optionHtml = compareOptions.map((scan, index) => `
        <option value="${escHtml(String(scan.id))}">${escHtml(formatCompareScanOption(scan, index, compareOptions.length))}</option>
    `).join('');
    const defaultA = compareOptions[1]?.id ?? compareOptions[0]?.id ?? '';
    const defaultB = compareOptions[0]?.id ?? '';

    let html = `<table class="asset-table"><thead><tr>
        <th>Serial</th><th>Date</th><th>Mode</th><th>Domain</th><th>Assets</th><th>Avg Score</th>
        <th>Safe</th><th>Trans</th><th>Vuln</th><th>Crit</th><th>Actions</th>
    </tr></thead><tbody>`;

    for (let index = 0; index < scans.length; index += 1) {
        const s = scans[index];
        const date = s.scan_date ? new Date(s.scan_date).toLocaleString() : '—';
        const serial = displayScanSerial(s.id, scans.length - index);
        html += `<tr>
            <td style="font-weight:600;">${serial}</td>
            <td style="font-size:0.75rem;">${date}</td>
            <td><span class="asset-type">${s.mode || '—'}</span></td>
            <td>${escHtml(s.domain || '—')}</td>
            <td style="text-align:center;">${s.total_assets || 0}</td>
            <td style="text-align:center;color:${getScoreColor(s.avg_score || 0)};font-weight:600;">${s.avg_score || 0}</td>
            <td style="color:var(--status-safe);text-align:center;">${s.fully_safe || 0}</td>
            <td style="color:var(--status-transition);text-align:center;">${s.pqc_trans || 0}</td>
            <td style="color:var(--status-vulnerable);text-align:center;">${s.q_vuln || 0}</td>
            <td style="color:var(--status-critical);text-align:center;">${s.crit_vuln || 0}</td>
            <td>
                <button class="btn" style="font-size:0.7rem;padding:2px 8px;" onclick="viewScan('${escHtml(String(s.id))}')">View</button>
                ${scans.length >= 2 ? `<button class="btn" style="font-size:0.7rem;padding:2px 8px;margin-left:4px;" onclick="compareScanPick('${escHtml(String(s.id))}')">Compare</button>` : ''}
                <button class="btn" style="font-size:0.7rem;padding:2px 8px;margin-left:4px;" onclick="deleteScan('${escHtml(String(s.id))}')">Delete</button>
            </td>
        </tr>`;
    }

    html += '</tbody></table>';
    container.innerHTML = `
        <div style="display:grid;gap:0.9rem;">
            <div style="display:flex;flex-wrap:wrap;gap:0.75rem;align-items:end;padding:0.85rem 1rem;border:1px solid var(--border-subtle);border-radius:var(--radius-md);background:var(--bg-tertiary);">
                <div style="display:grid;gap:0.3rem;flex:1 1 16rem;min-width:12rem;">
                    <label for="compareScanA" style="font-size:0.74rem;font-weight:700;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.04em;">Scan A</label>
                    <select id="compareScanA" class="scan-input">${optionHtml}</select>
                </div>
                <div style="display:grid;gap:0.3rem;flex:1 1 16rem;min-width:12rem;">
                    <label for="compareScanB" style="font-size:0.74rem;font-weight:700;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.04em;">Scan B</label>
                    <select id="compareScanB" class="scan-input">${optionHtml}</select>
                </div>
                <button class="btn btn-primary" type="button" onclick="compareSelectedScans()">Compare Scans</button>
            </div>
            <div id="p7CompareResultContainer"></div>
            <div style="overflow-x:auto;">${html}</div>
        </div>
    `;

    const compareScanA = document.getElementById('compareScanA');
    const compareScanB = document.getElementById('compareScanB');
    if (compareScanA && defaultA !== '') compareScanA.value = String(defaultA);
    if (compareScanB && defaultB !== '') compareScanB.value = String(defaultB);
}

async function viewScan(scanId) {
    showLoading(`Loading ${lookupScanSerial(scanId)}...`);
    try {
        const scan = await apiCall(`/api/db/scans/${scanId}`);
        if (scan.results_json) {
            try {
                const assets = JSON.parse(scan.results_json);
                renderP7Table(assets);
                renderP7Agility(assets);
            } catch { /* ignore parse failure */ }
        }
        showToast(`Loaded ${lookupScanSerial(scanId)}`, 'info');
    } catch (e) {
        showToast('Failed to load scan: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

async function compareScanPick(scanId) {
    if (!dbScansData || dbScansData.length < 2) {
        showToast('Need at least two scans to compare', 'info');
        return;
    }
    const other = dbScansData.find(s => s.id !== scanId);
    if (!other) { showToast('No other scan to compare against', 'info'); return; }
    const compareScanA = document.getElementById('compareScanA');
    const compareScanB = document.getElementById('compareScanB');
    if (compareScanA) compareScanA.value = String(other.id);
    if (compareScanB) compareScanB.value = String(scanId);
    await compareTwoScans(scanId, other.id);
}

async function compareSelectedScans() {
    const scanA = document.getElementById('compareScanA')?.value;
    const scanB = document.getElementById('compareScanB')?.value;
    if (!scanA || !scanB) {
        showToast('Select both scans before comparing', 'info');
        return;
    }
    if (String(scanA) === String(scanB)) {
        showToast('Choose two different scans', 'info');
        return;
    }
    await compareTwoScans(scanA, scanB);
}

async function compareTwoScans(a, b) {
    showLoading(`Comparing ${lookupScanSerial(a)} vs ${lookupScanSerial(b)}...`);
    try {
        const delta = await apiCall(`/api/compare?scan_a=${encodeURIComponent(a)}&scan_b=${encodeURIComponent(b)}`);
        renderScanComparison(delta, a, b);
        showToast(`Comparison ready: ${lookupScanSerial(a)} vs ${lookupScanSerial(b)}`, 'success');
    } catch (e) {
        showToast('Comparison failed: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

function renderScanComparison(delta, idA, idB) {
    const container = document.getElementById('p7CompareResultContainer');
    if (!container) return;
    const a = delta.scan_a || {};
    const b = delta.scan_b || {};
    const d = delta.delta || {};
    const labelA = lookupScanSerial(idA);
    const labelB = lookupScanSerial(idB);
    const newAssets = Array.isArray(delta.new_assets) ? delta.new_assets : (Array.isArray(delta.new) ? delta.new.map((asset) => ({ asset })) : []);
    const removedAssets = Array.isArray(delta.removed_assets) ? delta.removed_assets : (Array.isArray(delta.removed) ? delta.removed.map((asset) => ({ asset })) : []);
    const changedAssets = Array.isArray(delta.changed_assets) ? delta.changed_assets : (Array.isArray(delta.changed) ? delta.changed : []);
    const regressions = Array.isArray(delta.regressions) ? delta.regressions : [];

    function diffBadge(val) {
        if (val > 0) return `<span style="color:var(--accent-green);font-weight:600;">+${val}</span>`;
        if (val < 0) return `<span style="color:var(--status-critical);font-weight:600;">${val}</span>`;
        return `<span style="color:var(--text-dim);">0</span>`;
    }

    function renderAssetList(items, emptyLabel, formatter) {
        if (!items.length) {
            return `<div class="empty-state"><div class="empty-state-desc">${emptyLabel}</div></div>`;
        }
        return `<table class="asset-table"><tbody>${items.map(formatter).join('')}</tbody></table>`;
    }

    container.innerHTML = `
        <div style="margin-bottom:12px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
            <strong style="color:var(--text-primary);">${labelA} vs ${labelB}</strong>
            <button class="btn" style="font-size:0.7rem;padding:2px 8px;" onclick="document.getElementById('p7CompareResultContainer').innerHTML=''">Clear</button>
        </div>
        <table class="asset-table" style="margin-bottom:1rem;"><thead><tr>
            <th>Metric</th><th>${labelA}</th><th>${labelB}</th><th>Delta</th>
        </tr></thead><tbody>
            <tr><td>Total Assets</td><td>${a.total_assets || a.total || 0}</td><td>${b.total_assets || b.total || 0}</td><td>${diffBadge(d.total_assets || 0)}</td></tr>
            <tr><td>Avg Score</td><td>${a.avg_score || a.avg || 0}</td><td>${b.avg_score || b.avg || 0}</td><td>${diffBadge(d.avg_score || 0)}</td></tr>
            <tr><td style="color:var(--status-safe)">Fully Safe</td><td>${a.fully_safe || 0}</td><td>${b.fully_safe || 0}</td><td>${diffBadge(d.fully_safe || 0)}</td></tr>
            <tr><td style="color:var(--status-transition)">PQC Transition</td><td>${a.pqc_trans || 0}</td><td>${b.pqc_trans || 0}</td><td>${diffBadge(d.pqc_trans || 0)}</td></tr>
            <tr><td style="color:var(--status-vulnerable)">Vulnerable</td><td>${a.q_vuln || 0}</td><td>${b.q_vuln || 0}</td><td>${diffBadge(d.q_vuln || 0)}</td></tr>
            <tr><td style="color:var(--status-critical)">Critical</td><td>${a.crit_vuln || 0}</td><td>${b.crit_vuln || 0}</td><td>${diffBadge(d.crit_vuln || 0)}</td></tr>
        </tbody></table>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(18rem,1fr));gap:1rem;margin-top:1rem;">
            <div>
                <div class="panel-title" style="margin-bottom:0.5rem;">New Assets</div>
                ${renderAssetList(newAssets, 'No new assets detected.', (item) => `<tr><td>${escHtml(item.asset || item)}</td></tr>`)}
            </div>
            <div>
                <div class="panel-title" style="margin-bottom:0.5rem;">Removed Assets</div>
                ${renderAssetList(removedAssets, 'No removed assets detected.', (item) => `<tr><td>${escHtml(item.asset || item)}</td></tr>`)}
            </div>
            <div style="grid-column:1 / -1;">
                <div class="panel-title" style="margin-bottom:0.5rem;">Changed Scores</div>
                ${renderAssetList(changedAssets, 'No score changes detected.', (item) => `
                    <tr>
                        <td><strong>${escHtml(item.asset)}</strong></td>
                        <td>Old: ${item.old_score ?? item.old ?? '-'}</td>
                        <td>New: ${item.new_score ?? item.new ?? '-'}</td>
                        <td>Delta: ${diffBadge(item.delta)}</td>
                        <td>${escHtml(item.reason || `${item.old_status || 'UNKNOWN'} → ${item.new_status || 'UNKNOWN'}`)}</td>
                    </tr>
                `)}
            </div>
            <div style="grid-column:1 / -1;">
                <div class="panel-title" style="margin-bottom:0.5rem;color:var(--status-critical);">Regressions</div>
                ${renderAssetList(regressions, 'No regressions detected.', (item) => `
                    <tr>
                        <td><strong style="color:var(--status-critical);">${escHtml(item.asset)}</strong></td>
                        <td>Old: ${item.old_score ?? item.old ?? '-'}</td>
                        <td>New: ${item.new_score ?? item.new ?? '-'}</td>
                        <td>Delta: <span style="color:var(--status-critical);font-weight:700;">${item.delta}</span></td>
                        <td>${escHtml(item.reason || 'Score drop ≥ 5 detected')}</td>
                    </tr>
                `)}
            </div>
        </div>
    `;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Full Pipeline — Regression + Labels + CBOM v2 + Attestation
 * ═══════════════════════════════════════════════════════════════════════════ */

async function runPhase9Demo() {
    showLoading('Running regression and certification pipeline: classify → regress → label → register → CBOM v2 → attest...');
    try {
        phase9Data = await apiCall('/api/phase9/demo');
        renderPhase9(phase9Data);
        document.getElementById('p9Empty').style.display = 'none';
        document.getElementById('p9Content').style.display = 'block';
        showToast(`Pipeline complete — ${phase9Data.classification?.total_assets || 0} assets processed`, 'success');
    } catch (e) {
        showToast('Pipeline failed: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

async function runPhase9Live() {
    const domain = (document.getElementById('p9DomainInput')?.value || '').trim();
    if (!domain) { showToast('Enter a domain to run the pipeline on', 'error'); return; }
    showLoading(`Running live pipeline on ${domain}... (this may take 30-60s)`);
    try {
        phase9Data = await apiCall(`/api/phase9/live/${encodeURIComponent(domain)}`, 'POST');
        renderPhase9(phase9Data);
        document.getElementById('p9Empty').style.display = 'none';
        document.getElementById('p9Content').style.display = 'block';
        const banner = document.getElementById('p9DemoBanner');
        if (banner) banner.style.display = 'none';
        showToast(`Live pipeline complete — ${phase9Data.classification?.total_assets || 0} assets from ${domain}`, 'success');
    } catch (e) {
        showToast('Live pipeline failed: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

function renderPhase9(data) {
    const labels = data.labels || {};
    const regr = data.regression || {};
    const attest = data.attestation_summary || {};
    const registry = data.registry || {};
    const attestFull = data.attestation || {};
    if (hasRenderableCbom(data.cbom)) {
        latestCbomPayload = data.cbom;
    }

    // KPI cards
    document.getElementById('p9Total').textContent = labels.total_assets || 0;
    document.getElementById('p9QSScore').textContent = `Q-Safety: ${labels.quantum_safety_score || 0}/100`;
    document.getElementById('p9Tier1').textContent = labels.tier_1_count || 0;
    document.getElementById('p9Tier1Pct').textContent = `${(labels.tier_1_pct || 0).toFixed(1)}%`;
    document.getElementById('p9Tier2').textContent = labels.tier_2_count || 0;
    document.getElementById('p9Tier2Pct').textContent = `${(labels.tier_2_pct || 0).toFixed(1)}%`;
    document.getElementById('p9Tier3').textContent = labels.tier_3_count || 0;
    document.getElementById('p9Tier3Pct').textContent = `${(labels.tier_3_pct || 0).toFixed(1)}%`;
    document.getElementById('p9Regressions').textContent = regr.total_findings || 0;

    const overallComp = attest.overallCompliance || 'UNKNOWN';
    document.getElementById('p9Compliance').textContent = overallComp;
    document.getElementById('p9Compliance').style.color =
        overallComp === 'COMPLIANT' ? 'var(--accent-green)' :
        overallComp === 'PARTIALLY_COMPLIANT' ? '#D97706' : '#DC2626';

    // Regression table
    renderRegressionTable(regr);

    // Labels table
    renderPhase9Labels(labels);

    // Registry
    renderRegistry(registry);

    // Attestation
    renderPhase9Attestation(attestFull, attest);
}

function renderRegressionTable(regr) {
    const container = document.getElementById('p9RegressionContainer');
    const all = [
        ...(regr.new_assets || []).map(r => ({ ...r, _cat: 'New Asset' })),
        ...(regr.score_regressions || []).map(r => ({ ...r, _cat: 'Score Regression' })),
        ...(regr.missed_upgrades || []).map(r => ({ ...r, _cat: 'Missed Upgrade' })),
    ];
    document.getElementById('p9RegrBadge').textContent = `${all.length} findings`;

    if (!all.length) {
        container.innerHTML = '<div style="padding:16px;color:var(--text-dim);text-align:center;">No regressions detected — all clear!</div>';
        return;
    }

    let html = `<table class="asset-table"><thead><tr>
        <th>Host</th><th>Port</th><th>Category</th><th>Urgency</th><th>Description</th><th>Action</th>
    </tr></thead><tbody>`;
    for (const r of all) {
        const urgColor = r.urgency === 'HIGH' ? '#DC2626' : r.urgency === 'MEDIUM' ? '#D97706' : 'var(--text-dim)';
        html += `<tr>
            <td>${r.hostname || ''}</td>
            <td>${r.port || 443}</td>
            <td><span style="background:rgba(0,212,255,0.12);color:var(--accent-cyan);padding:2px 8px;border-radius:4px;font-size:0.72rem;">${r._cat}</span></td>
            <td><span style="color:${urgColor};font-weight:600;">${r.urgency || ''}</span></td>
            <td style="max-width:300px;">${r.description || ''}</td>
            <td style="font-size:0.75rem;color:var(--text-secondary);">${r.recommended_action || ''}</td>
        </tr>`;
    }
    html += '</tbody></table>';
    container.innerHTML = html;
}

function renderPhase9Labels(labels) {
    const container = document.getElementById('p9LabelsContainer');
    const execSummary = document.getElementById('p9LabelExecSummary');
    const items = labels.labels || [];
    document.getElementById('p9LabelBadge').textContent = `${items.length} labels`;
    execSummary.textContent = labels.executive_summary || '';

    if (!items.length) {
        container.innerHTML = '<div style="padding:16px;color:var(--text-dim);text-align:center;">No labels issued</div>';
        return;
    }

    let html = `<table class="asset-table"><thead><tr>
        <th>Label ID</th><th>Host</th><th>Port</th><th>Tier</th><th>Certification</th><th>Badge</th><th>Standards</th><th>Gap</th><th>Fix</th>
    </tr></thead><tbody>`;
    for (const l of items) {
        const tierColor = l.tier === 1 ? 'var(--accent-green)' : l.tier === 2 ? 'var(--accent-cyan)' : '#DC2626';
        const tierName = l.tier === 1 ? 'Tier 1' : l.tier === 2 ? 'Tier 2' : 'Tier 3';
        html += `<tr>
            <td style="font-family:monospace;font-size:0.72rem;">${l.label_id || ''}</td>
            <td>${l.hostname || ''}</td>
            <td>${l.port || 443}</td>
            <td><span style="color:${tierColor};font-weight:700;">${tierName}</span></td>
            <td>${l.certification_title || ''}</td>
            <td><span style="display:inline-block;padding:2px 8px;border-radius:4px;background:${l.badge_color || '#333'};color:#fff;font-size:0.72rem;">${l.badge_icon || ''}</span></td>
            <td style="font-size:0.72rem;">${(l.nist_standards || []).join(', ')}</td>
            <td style="color:#D97706;font-size:0.75rem;">${l.primary_gap || '—'}</td>
            <td>${l.fix_in_days ? l.fix_in_days + 'd' : '—'}</td>
        </tr>`;
    }
    html += '</tbody></table>';
    container.innerHTML = html;
}

function renderRegistry(registry) {
    const container = document.getElementById('p9RegistryContainer');
    const badge = document.getElementById('p9RegistryBadge');
    const persisted = registry.labels_persisted || 0;
    const revocations = Array.isArray(registry.auto_revocations) ? registry.auto_revocations.length : (registry.auto_revocations || 0);

    badge.textContent = `${persisted} persisted`;
    container.innerHTML = `
        <div style="display:flex;gap:24px;padding:8px 0;">
            <div><strong style="color:var(--accent-green);">${persisted}</strong> labels persisted to append-only registry</div>
            <div><strong style="color:${revocations > 0 ? '#DC2626' : 'var(--text-dim)'};">${revocations}</strong> auto-revocations triggered</div>
        </div>
        <div style="font-size:0.75rem;color:var(--text-dim);margin-top:4px;">
            Registry endpoints: <code>/api/registry/verify/{id}</code> · <code>/api/registry/list</code> · <code>POST /api/registry/revoke</code>
        </div>
    `;
}

function renderPhase9Attestation(attestFull, summary) {
    const container = document.getElementById('p9AttestContainer');
    const badge = document.getElementById('p9AttestBadge');

    const overallComp = summary.overallCompliance || 'UNKNOWN';
    const overallTone = compliancePalette(overallComp);
    badge.textContent = overallComp;
    badge.style.background = overallTone.bg;
    badge.style.color = overallTone.color;

    const attestBody = attestFull?.attestation || {};
    const decls = attestBody.declarations || {};
    const claims = decls.claims || [];
    const labelClaims = attestBody.labelClaims || [];
    const evidence = attestBody.evidence || {};
    const cbomEvidence = evidence.cbom || {};
    const signature = attestFull?.signature || {};

    let claimsHtml = '';
    for (const c of claims) {
        claimsHtml += `<tr>
            <td style="font-weight:600;">${c.id || ''}</td>
            <td style="max-width:240px;">${c.title || ''}</td>
            <td>${renderToneBadge(c.complianceStatus || 'UNKNOWN', c.complianceStatus)}</td>
            <td>${escHtml(c.coverage || '—')}</td>
            <td style="font-size:0.75rem;color:var(--text-secondary);">${escHtml(c.evidence || '')}</td>
        </tr>`;
    }

    container.innerHTML = `
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(11rem,1fr));gap:0.75rem;margin-bottom:1rem;">
            <div style="background:rgba(255,255,255,0.03);border:0.0625rem solid var(--border-subtle);border-radius:0.75rem;padding:0.9rem;">
                <div style="font-size:0.72rem;color:var(--text-secondary);margin-bottom:0.25rem;">CDXA Document</div>
                <div style="font-size:1.05rem;font-weight:700;">CDXA ${escHtml(shortenDocumentId(summary.serialNumber, 'LATEST'))}</div>
                <div style="font-size:0.76rem;color:var(--text-secondary);margin-top:0.35rem;">Issued ${escHtml(formatUiDateTime(summary.timestamp))}</div>
            </div>
            <div style="background:rgba(255,255,255,0.03);border:0.0625rem solid var(--border-subtle);border-radius:0.75rem;padding:0.9rem;">
                <div style="font-size:0.72rem;color:var(--text-secondary);margin-bottom:0.25rem;">Signature</div>
                <div style="font-size:1rem;font-weight:700;color:${summary.signed ? 'var(--accent-green)' : '#DC2626'};">${summary.signed ? escHtml(signature.algorithm || 'Ed25519') : 'Unsigned'}</div>
                <div style="font-size:0.76rem;color:var(--text-secondary);margin-top:0.35rem;">Valid until ${escHtml(formatUiDateTime(summary.validUntil, false))}</div>
            </div>
            <div style="background:rgba(255,255,255,0.03);border:0.0625rem solid var(--border-subtle);border-radius:0.75rem;padding:0.9rem;">
                <div style="font-size:0.72rem;color:var(--text-secondary);margin-bottom:0.25rem;">Coverage</div>
                <div style="font-size:1rem;font-weight:700;">${escHtml(String(summary.totalAssets || 0))} assets</div>
                <div style="font-size:0.76rem;color:var(--text-secondary);margin-top:0.35rem;">Q-Safety ${escHtml(String(summary.quantumSafetyScore || 0))}/100</div>
            </div>
            <div style="background:rgba(255,255,255,0.03);border:0.0625rem solid var(--border-subtle);border-radius:0.75rem;padding:0.9rem;">
                <div style="font-size:0.72rem;color:var(--text-secondary);margin-bottom:0.25rem;">Evidence Link</div>
                <div style="font-size:1rem;font-weight:700;">CBOM ${escHtml(shortenDocumentId(cbomEvidence.serialNumber, '—'))}</div>
                <div style="font-size:0.76rem;color:var(--text-secondary);margin-top:0.35rem;">${escHtml(String(cbomEvidence.componentsCount || 0))} components • ${escHtml(String(summary.dataMode || 'live').toUpperCase())}</div>
            </div>
        </div>
        <div style="padding:0.9rem 1rem;border-radius:0.75rem;background:rgba(255,255,255,0.03);border:0.0625rem solid var(--border-subtle);margin-bottom:1rem;">
            <div style="font-size:0.78rem;color:var(--text-secondary);margin-bottom:0.35rem;">Executive Summary</div>
            <div style="font-size:0.85rem;line-height:1.6;">${escHtml(summary.executiveSummary || attestBody.subject?.executiveSummary || 'No attestation summary available.')}</div>
        </div>
        <div style="overflow-x:auto;margin-bottom:1rem;">
            <table class="asset-table"><thead><tr>
                <th>FIPS Standard</th><th>Title</th><th>Status</th><th>Coverage</th><th>Evidence</th>
            </tr></thead><tbody>${claimsHtml || '<tr><td colspan="5" style="text-align:center;color:var(--text-secondary);padding:1rem 0.75rem;">No compliance claims available.</td></tr>'}</tbody></table>
        </div>
        <div style="overflow-x:auto;margin-bottom:1rem;">
            <table class="asset-table">
                <thead><tr>
                    <th>Endpoint</th><th>Tier</th><th>Standards</th><th>Algorithms</th><th>Gap</th><th>Fix Window</th>
                </tr></thead>
                <tbody>
                    ${labelClaims.length ? labelClaims.map((claim) => `
                        <tr>
                            <td>
                                <div style="font-weight:600;">${escHtml(`${claim.hostname || 'unknown'}:${claim.port || 443}`)}</div>
                                <div style="font-size:0.72rem;color:var(--text-secondary);">${escHtml(claim.certificationTitle || 'Certification pending')}</div>
                            </td>
                            <td>${renderToneBadge(`Tier ${claim.tier || 3}`, claim.tier === 1 ? 'COMPLIANT' : claim.tier === 2 ? 'PARTIALLY_COMPLIANT' : 'NON_COMPLIANT')}</td>
                            <td style="font-size:0.76rem;">${escHtml((claim.nistStandards || []).join(', ') || '—')}</td>
                            <td style="font-size:0.76rem;">${escHtml((claim.algorithmsInUse || []).join(', ') || '—')}</td>
                            <td style="color:var(--text-secondary);">${escHtml(claim.primaryGap || '—')}</td>
                            <td>${claim.fixInDays ? `${escHtml(String(claim.fixInDays))} days` : '—'}</td>
                        </tr>
                    `).join('') : '<tr><td colspan="6" style="text-align:center;color:var(--text-secondary);padding:1rem 0.75rem;">No endpoint attestation details available.</td></tr>'}
                </tbody>
            </table>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:0.6rem;font-size:0.78rem;color:var(--text-secondary);">
            <div style="padding:0.55rem 0.75rem;border-radius:999px;background:rgba(255,255,255,0.03);border:0.0625rem solid var(--border-subtle);">Classification: ${escHtml(evidence.classificationSource || '—')}</div>
            <div style="padding:0.55rem 0.75rem;border-radius:999px;background:rgba(255,255,255,0.03);border:0.0625rem solid var(--border-subtle);">Labeling: ${escHtml(evidence.labelingSource || '—')}</div>
            <div style="padding:0.55rem 0.75rem;border-radius:999px;background:rgba(255,255,255,0.03);border:0.0625rem solid var(--border-subtle);">Regression: ${escHtml(evidence.regressionSource || '—')}</div>
        </div>
    `;
}

async function downloadPhase9CBOM() {
    try {
        const resp = await authorizedFetch(`${API_BASE}/api/phase9/cbom/download`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = 'qarmor-cbom-v2.json'; a.click();
        URL.revokeObjectURL(url);
        showToast('CBOM v2 downloaded', 'success');
    } catch (e) { showToast('Download failed: ' + e.message, 'error'); }
}

async function downloadPhase9CDXA() {
    try {
        const resp = await authorizedFetch(`${API_BASE}/api/attestation/v2/download`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = 'qarmor-attestation-cdxa-v2.json'; a.click();
        URL.revokeObjectURL(url);
        showToast('CDXA v2 downloaded', 'success');
    } catch (e) { showToast('Download failed: ' + e.message, 'error'); }
}

document.addEventListener('DOMContentLoaded', () => {
    onEnterpriseModeChange();
    // Render cached data instantly, then refresh in background
    const cached = _loadDashboardCache();
    if (cached && cached.home) {
        _renderCachedDashboard(cached);
    }
    loadEnterpriseDashboardData();
});

/* ═══════════════════════════════════════════════════════════════════════════
   Interactive Visualizations
   ═══════════════════════════════════════════════════════════════════════════ */

const chartInstances = {};

function destroyChart(id) {
    if (chartInstances[id]) {
        chartInstances[id].destroy();
        delete chartInstances[id];
    }
}

function sizeCanvasToParent(id, fallbackHeight = 200) {
    const canvas = document.getElementById(id);
    if (!canvas) return null;
    const parent = canvas.parentElement;
    const width = Math.max(240, Math.round(parent?.clientWidth || canvas.offsetWidth || 240));
    const height = Math.max(160, Math.round(parent?.clientHeight || fallbackHeight));
    canvas.width = width;
    canvas.height = height;
    return canvas;
}

function makeChart(id, config) {
    destroyChart(id);
    if (typeof Chart === 'undefined') return null;
    const canvas = sizeCanvasToParent(id, config?.options?.indexAxis === 'y' ? 300 : 200);
    if (!canvas) return null;
    chartInstances[id] = new Chart(canvas, config);
    return chartInstances[id];
}

const VIZ_COLORS = {
    elite: '#2e7d32',
    standard: '#f57f17',
    legacy: '#e64a19',
    critical: '#b71c1c',
    unknown: '#616161',
    blue: '#1976d2',
    purple: '#6a1b9a',
    amber: '#ff8f00',
};

function scoreColor(s) {
    return s >= 70 ? VIZ_COLORS.elite : s >= 40 ? '#e65100' : VIZ_COLORS.critical;
}

function tierColor(tier) {
    const t = (tier || '').toLowerCase();
    if (t.includes('elite') || t.includes('fully')) return VIZ_COLORS.elite;
    if (t.includes('standard') || t.includes('transition')) return VIZ_COLORS.standard;
    if (t.includes('critical')) return VIZ_COLORS.critical;
    if (t.includes('legacy') || t.includes('vulnerable')) return VIZ_COLORS.legacy;
    return VIZ_COLORS.unknown;
}

function vizTierLabel(asset) {
    const raw = asset?.display_tier || asset?.pqc_status || asset?.status || asset?.q_score?.status || '';
    const value = String(raw || '');
    const knownLabels = {
        FULLY_QUANTUM_SAFE: 'Fully Quantum Safe',
        PQC_TRANSITION: 'PQC Transition',
        QUANTUM_VULNERABLE: 'Quantum Vulnerable',
        CRITICALLY_VULNERABLE: 'Critically Vulnerable',
        UNKNOWN: 'Unknown',
    };
    if (knownLabels[value]) return knownLabels[value];
    return value.replace(/_/g, ' ');
}

function vizAssetScore(asset) {
    const q = asset?.q_score;
    const qNum = (q !== null && q !== undefined && typeof q === 'object') ? q?.total : q;
    return Number(
        asset?.worst_case_score
        ?? asset?.worst_score
        ?? qNum
        ?? 0
    ) || 0;
}

const vizInit = {
    network: false,
    heatmap: false,
    gauges: false,
    cbom: false,
    cyber: false,
    timeline: false,
};

let latestScanPayload = null;
let latestScanKey = '';
let latestCbomPayload = null;
let latestHistoryPayload = null;
let assessmentNegotiationPolicies = {};

function getActiveEnterpriseContext() {
    return getEnterpriseContext({ notifyOnError: false }) || { mode: 'demo', domain: '' };
}

function buildContextEndpoint(path, forceRefresh = false) {
    return buildEnterpriseEndpoint(path, getActiveEnterpriseContext(), forceRefresh);
}

function isTabActive(tabName) {
    return document.getElementById(`tab-${tabName}`)?.classList.contains('tab-content--active');
}

function bannerHtml(payload) {
    if (!payload?.demo_mode) return '';
    return `<div class="viz-banner">${escHtml(payload.data_notice || 'SIMULATED DATA')}</div>`;
}

function renderVizLoading(mountId, title, copy) {
    const mount = document.getElementById(mountId);
    if (!mount) return;
    mount.innerHTML = `
        <div class="viz-state">
            <div class="viz-state-content">
                <div class="viz-spinner"></div>
                <div class="viz-state-title">${escHtml(title)}</div>
                <div class="viz-state-copy">${escHtml(copy)}</div>
            </div>
        </div>
    `;
}

function renderVizError(mountId, title, message, retryFn) {
    const mount = document.getElementById(mountId);
    if (!mount) return;
    mount.innerHTML = `
        <div class="viz-state">
            <div class="viz-state-content">
                <div class="viz-state-title">${escHtml(title)}</div>
                <div class="viz-state-copy">${escHtml(message)}</div>
                <button class="viz-retry" type="button" onclick="${retryFn}">Retry</button>
            </div>
        </div>
    `;
}

function ensureOverviewVizLoading() {
    renderVizLoading('networkVizMount', 'Loading network graph', 'Mapping nodes, edges, and PQC tiers...');
    renderVizLoading('cyberVizMount', 'Loading cyber rating', 'Scoring enterprise posture and tiering assets...');
    renderVizLoading('heatmapVizMount', 'Loading PQC posture', 'Building heatmap and gauge summaries...');
    renderVizLoading('certVizMount', 'Loading certificate expiry', 'Fetching SSL inventory and expiry windows...');
}

function prepareOverviewVisualizations(forceRefresh = false) {
    if (!enterpriseDashboardData) return;
    renderNetworkGraphSection(enterpriseDashboardData.graph || {});
    renderHeatmapSection(enterpriseDashboardData.heatmap || {});
    renderCyberRatingSection(enterpriseDashboardData.cyber || {});
    initCertChart(enterpriseDashboardData.ssl?.items || [], enterpriseDashboardData.ssl || {});
    initGauges(forceRefresh);
}

async function fetchLatestScan(forceRefresh = false) {
    const endpoint = '/api/scan/latest';
    if (!forceRefresh && latestScanPayload && latestScanKey === endpoint) return latestScanPayload;
    latestScanPayload = await apiCall(endpoint);
    latestScanKey = endpoint;
    return latestScanPayload;
}

function hasRenderableCbom(payload) {
    if (!payload || typeof payload !== 'object') return false;
    const components = Array.isArray(payload.components) ? payload.components : [];
    const totalAssets = Number(payload?.pqcSummary?.totalAssets ?? 0) || 0;
    return components.length > 0 || totalAssets > 0;
}

async function fetchCbomLatest(forceRefresh = false) {
    if (!forceRefresh && latestCbomPayload && hasRenderableCbom(latestCbomPayload)) return latestCbomPayload;
    if (!forceRefresh && hasRenderableCbom(phase9Data?.cbom)) {
        latestCbomPayload = phase9Data.cbom;
        return latestCbomPayload;
    }
    latestCbomPayload = await apiCall(buildContextEndpoint('/api/cbom/latest', forceRefresh));
    if (!hasRenderableCbom(latestCbomPayload) && hasRenderableCbom(phase9Data?.cbom)) {
        latestCbomPayload = phase9Data.cbom;
        return latestCbomPayload;
    }
    if (!forceRefresh && !hasRenderableCbom(latestCbomPayload)) {
        // Recover from stale/empty cache snapshots by forcing a fresh backend pipeline read.
        latestCbomPayload = await apiCall(buildContextEndpoint('/api/cbom/latest', true));
        if (!hasRenderableCbom(latestCbomPayload) && hasRenderableCbom(phase9Data?.cbom)) {
            latestCbomPayload = phase9Data.cbom;
        }
    }
    return latestCbomPayload;
}

async function fetchHistoryLatest(forceRefresh = false) {
    if (!forceRefresh && latestHistoryPayload) return latestHistoryPayload;
    latestHistoryPayload = await apiCall('/api/history');
    return latestHistoryPayload;
}

function primeOverviewVisuals() {
    vizInit.network = true;
    vizInit.heatmap = true;
    vizInit.gauges = true;
    vizInit.cyber = true;
    ensureOverviewVizLoading();
    if (enterpriseDashboardData) {
        prepareOverviewVisualizations();
    }
}

const NET = {
    nodes: [],
    edges: [],
    filter: 'all',
    view: 'graph',
    drag: null,
    canvas: null,
    ctx: null,
    width: 0,
    height: 0,
    byId: new Map(),
    resizeBound: false,
};

function initNetworkGraph() {
    primeOverviewVisuals();
}

function graphFilter(filter, btn) {
    NET.filter = filter;
    document.querySelectorAll('.graph-filter-btn').forEach((node) => node.classList.remove('active'));
    if (btn) btn.classList.add('active');
    // Re-render vis network with filtered nodes
    if (NET.rawNodes) {
        const filtered = NET.rawNodes.filter(nodeVisible);
        if (NET.view === 'graph') {
            NET.visNetwork = buildVisNetwork('networkCanvasWrap', filtered, NET.rawEdges || []);
        }
    }
    renderNetworkTable();
}

function toggleGraphView() {
    NET.view = NET.view === 'graph' ? 'table' : 'graph';
    const graphWrap = document.getElementById('networkCanvasWrap');
    const tableWrap = document.getElementById('networkTableWrap');
    const button = document.getElementById('graphViewToggleBtn');
    if (graphWrap) graphWrap.style.display = NET.view === 'graph' ? 'block' : 'none';
    if (tableWrap) tableWrap.style.display = NET.view === 'table' ? 'block' : 'none';
    if (button) button.textContent = NET.view === 'graph' ? 'Switch to Table' : 'Switch to Graph';
}

function nodeVisible(node) {
    if (NET.filter === 'all') return true;
    const tier = (node.pqc_status || node.display_tier || '').toLowerCase();
    const pool = (node.pool || '').toLowerCase();
    const t = (node.type || '').toLowerCase();
    // Always show pool group nodes when filtering by pool
    if (NET.filter === 'cloud') return pool === 'cloud' || t === 'pool';
    if (NET.filter === 'self_hosted') return pool === 'self_hosted' || t === 'pool';
    if (NET.filter === 'elite') return tier.includes('elite') || tier.includes('fully');
    if (NET.filter === 'standard') return tier.includes('standard') || tier.includes('transition');
    if (NET.filter === 'vulnerable') return tier.includes('vulnerable') || tier.includes('critical') || tier.includes('legacy');
    return true;
}

function resizeNetCanvas() {
    if (!NET.canvas) return;
    const rect = NET.canvas.getBoundingClientRect();
    NET.width = NET.canvas.width = Math.max(320, Math.round(rect.width || NET.canvas.offsetWidth || 320));
    NET.height = NET.canvas.height = 420;
    drawNet();
}

function netSimStep() {
    const repulsion = 3200;
    const spring = 0.05;
    const rest = 130;
    const damp = 0.86;

    for (let index = 0; index < NET.nodes.length; index += 1) {
        for (let otherIndex = index + 1; otherIndex < NET.nodes.length; otherIndex += 1) {
            const a = NET.nodes[index];
            const b = NET.nodes[otherIndex];
            const dx = a.x - b.x;
            const dy = a.y - b.y;
            const distance = Math.max(Math.hypot(dx, dy), 1);
            const force = repulsion / distance / distance;
            a.vx += dx / distance * force;
            a.vy += dy / distance * force;
            b.vx -= dx / distance * force;
            b.vy -= dy / distance * force;
        }
    }

    NET.edges.forEach((edge) => {
        const a = NET.byId.get(edge.source);
        const b = NET.byId.get(edge.target);
        if (!a || !b) return;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const distance = Math.max(Math.hypot(dx, dy), 1);
        const force = (distance - rest) * spring;
        a.vx += dx / distance * force;
        a.vy += dy / distance * force;
        b.vx -= dx / distance * force;
        b.vy -= dy / distance * force;
    });

    NET.nodes.forEach((node) => {
        node.vx *= damp;
        node.vy *= damp;
        node.x = Math.max(36, Math.min(NET.width - 36, node.x + node.vx));
        node.y = Math.max(36, Math.min(NET.height - 36, node.y + node.vy));
    });
}

function drawNet() {
    if (!NET.ctx) return;
    const ctx = NET.ctx;
    ctx.clearRect(0, 0, NET.width, NET.height);

    NET.edges.forEach((edge) => {
        const a = NET.byId.get(edge.source);
        const b = NET.byId.get(edge.target);
        if (!a || !b) return;
        const aVisible = nodeVisible(a);
        const bVisible = nodeVisible(b);
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.strokeStyle = aVisible && bVisible ? 'rgba(120,120,120,0.3)' : 'rgba(120,120,120,0.05)';
        ctx.lineWidth = 1;
        ctx.stroke();
    });

    NET.nodes.forEach((node) => {
        const visible = nodeVisible(node);
        ctx.globalAlpha = visible ? 1 : 0.12;
        ctx.beginPath();
        ctx.arc(node.x, node.y, 22, 0, Math.PI * 2);
        ctx.fillStyle = `${tierColor(node.pqc_status || node.display_tier)}22`;
        ctx.fill();

        ctx.beginPath();
        ctx.arc(node.x, node.y, 16, 0, Math.PI * 2);
        ctx.fillStyle = tierColor(node.pqc_status || node.display_tier);
        ctx.fill();
        ctx.strokeStyle = 'rgba(255,255,255,0.72)';
        ctx.lineWidth = 1.5;
        ctx.stroke();

        ctx.fillStyle = 'rgba(156,163,175,0.9)';
        ctx.font = '600 10px Inter, sans-serif';
        ctx.textAlign = 'center';
        const shortLabel = (node.label || node.id || '').split('.')[0];
        ctx.fillText(shortLabel, node.x, node.y + 30);
        ctx.globalAlpha = 1;
    });
}

function netPos(event) {
    const rect = NET.canvas.getBoundingClientRect();
    return { x: event.clientX - rect.left, y: event.clientY - rect.top };
}

function netMouseDown(event) {
    const point = netPos(event);
    NET.drag = NET.nodes.find((node) => Math.hypot(node.x - point.x, node.y - point.y) < 22) || null;
    if (NET.drag) NET.canvas.style.cursor = 'grabbing';
}

function netMouseMove(event) {
    if (!NET.canvas) return;
    const point = netPos(event);
    const tooltip = document.getElementById('networkTooltip');
    if (NET.drag) {
        NET.drag.x = point.x;
        NET.drag.y = point.y;
        drawNet();
        if (tooltip) tooltip.style.display = 'none';
        return;
    }

    const hover = NET.nodes.find((node) => Math.hypot(node.x - point.x, node.y - point.y) < 22);
    NET.canvas.style.cursor = hover ? 'pointer' : 'grab';
    if (!hover || !tooltip) {
        if (tooltip) tooltip.style.display = 'none';
        return;
    }

    const tier = hover.display_tier || hover.pqc_status || 'Unknown';
    tooltip.style.display = 'block';
    tooltip.style.left = `${event.clientX + 14}px`;
    tooltip.style.top = `${event.clientY - 10}px`;
    tooltip.innerHTML = `<strong>${escHtml(hover.label || hover.id)}</strong><br><span style="color:${tierColor(tier)}">${escHtml(tier)}</span><br><span style="color:var(--text-secondary);font-size:0.75rem">${escHtml(hover.ip_address || '')}</span>`;
}

function renderNetworkTable() {
    const tableWrap = document.getElementById('networkTableWrap');
    if (!tableWrap) return;
    const visibleNodes = NET.nodes.filter((node) => nodeVisible(node));
    tableWrap.innerHTML = `
        <div class="network-table-wrap">
            <table class="network-table">
                <thead>
                    <tr>
                        <th>Node</th>
                        <th>Type</th>
                        <th>Tier</th>
                        <th>IP</th>
                    </tr>
                </thead>
                <tbody>
                    ${visibleNodes.map((node) => `
                        <tr>
                            <td><strong>${escHtml(node.label || node.id)}</strong></td>
                            <td>${escHtml(node.type || 'asset')}</td>
                            <td style="color:${tierColor(node.display_tier || node.pqc_status)}">${escHtml(node.display_tier || node.pqc_status || 'Unknown')}</td>
                            <td>${escHtml(node.ip_address || '—')}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

/* ── vis-network node/edge mapper ── */
// Cloud provider badge colors for IP nodes
const _CLOUD_COLORS = {
    aws:          { bg: '#ff9900', border: '#cc7a00' },
    azure:        { bg: '#0078d4', border: '#005a9e' },
    microsoft:    { bg: '#0078d4', border: '#005a9e' },
    gcp:          { bg: '#4285f4', border: '#2a56c6' },
    cloudflare:   { bg: '#f48120', border: '#c8660e' },
    fastly:       { bg: '#e8131a', border: '#b00d12' },
    akamai:       { bg: '#009bde', border: '#007ab2' },
    digitalocean: { bg: '#0080ff', border: '#0060c0' },
    oracle:       { bg: '#c74634', border: '#9e3528' },
    alibaba:      { bg: '#ff6a00', border: '#cc5500' },
};

function _visNodeColor(n) {
    const t = (n.type || '').toLowerCase();
    // Pool group nodes
    if (t === 'pool') {
        return n.pool === 'cloud'
            ? { bg: '#7c3aed', border: '#5b21b6' }
            : { bg: '#374151', border: '#1f2937' };
    }
    // IP nodes: color by cloud provider if known
    if (t === 'ip' && n.cloud_provider && _CLOUD_COLORS[n.cloud_provider]) {
        return _CLOUD_COLORS[n.cloud_provider];
    }
    const tier = (n.pqc_status || n.display_tier || '').toLowerCase();
    if (tier.includes('fully') || tier.includes('elite')) return { bg: '#16a34a', border: '#15803d' };
    if (tier.includes('transition') || tier.includes('standard')) return { bg: '#0891b2', border: '#0e7490' };
    if (tier.includes('critical')) return { bg: '#dc2626', border: '#b91c1c' };
    if (tier.includes('non_compliant') || tier.includes('legacy') || tier.includes('vulnerable')) return { bg: '#d97706', border: '#b45309' };
    if (t === 'domain' || t === 'www') return { bg: '#16a34a', border: '#15803d' };
    if (t === 'ip') return { bg: '#0891b2', border: '#0e7490' };
    if (t === 'ssl') return { bg: '#2563eb', border: '#1d4ed8' };
    if (t === 'ssh') return { bg: '#7c3aed', border: '#6d28d9' };
    if (t === 'tag') return { bg: '#d97706', border: '#b45309' };
    return { bg: '#6b7280', border: '#4b5563' };
}

function _visNodeShape(type) {
    const t = (type || '').toLowerCase();
    if (t === 'ssl') return 'diamond';
    if (t === 'ssh') return 'triangle';
    if (t === 'tag') return 'star';
    if (t === 'pool') return 'square';
    if (t === 'ip') return 'dot';
    return 'dot';
}

function buildVisNetwork(containerId, rawNodes, rawEdges, opts = {}) {
    const container = document.getElementById(containerId);
    if (!container || typeof vis === 'undefined') return null;

    const visNodes = rawNodes.map((n, i) => {
        const c = _visNodeColor(n);
        const tier = (n.pqc_status || n.display_tier || 'Unknown');
        return {
            id: n.id || i,
            label: n.label || n.id || `Node ${i}`,
            shape: _visNodeShape(n.type),
            color: { background: c.bg, border: c.border, highlight: { background: c.bg, border: '#fec800' } },
            font: { color: '#ffffff', size: 11, face: 'Inter, sans-serif' },
            borderWidth: 2,
            size: n.type === 'domain' ? 18 : 14,
            title: `${n.label || n.id}\nType: ${n.type || '—'}${n.ip_address ? '\nIP: ' + n.ip_address : ''}${n.cloud_provider && n.cloud_provider !== 'unknown' ? '\nCloud: ' + n.cloud_provider.toUpperCase() : ''}${n.pool ? '\nPool: ' + (n.pool === 'cloud' ? 'Cloud-Hosted' : 'Self-Hosted') : ''}\nTier: ${tier}`,
            _raw: n,
        };
    });

    const visEdges = rawEdges.map((e, i) => ({
        id: i,
        from: e.source || e.from,
        to: e.target || e.to,
        color: { color: '#d1d5db', highlight: '#fec800', opacity: 0.8 },
        width: 1.5,
        smooth: { type: 'continuous' },
    }));

    const data = {
        nodes: new vis.DataSet(visNodes),
        edges: new vis.DataSet(visEdges),
    };

    const options = {
        physics: {
            enabled: true,
            solver: 'forceAtlas2Based',
            forceAtlas2Based: { gravitationalConstant: -50, centralGravity: 0.01, springLength: 120, springConstant: 0.08 },
            stabilization: { iterations: 150, updateInterval: 25 },
        },
        interaction: { hover: true, tooltipDelay: 100, zoomView: true, dragView: true },
        layout: { randomSeed: 42 },
        nodes: { borderWidth: 2 },
        edges: { arrows: { to: { enabled: false } } },
        ...(opts.options || {}),
    };

    return new vis.Network(container, data, options);
}

function renderNetworkGraphSection(graphPayload) {
    const mount = document.getElementById('networkVizMount');
    if (!mount) return;
    const rawNodes = Array.isArray(graphPayload.nodes) ? graphPayload.nodes : [];
    const rawEdges = Array.isArray(graphPayload.edges) ? graphPayload.edges : [];

    if (!rawNodes.length) {
        mount.innerHTML = `${bannerHtml(graphPayload)}<div class="viz-state"><div class="viz-state-content"><div class="viz-state-title">No network data</div><div class="viz-state-copy">Run or refresh the enterprise pipeline to map related assets.</div></div></div>`;
        return;
    }

    mount.innerHTML = `
        ${bannerHtml(graphPayload)}
        <div id="graphControls" style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;margin-bottom:0.75rem">
            <span style="font-size:0.8rem;color:var(--text-secondary)">PQC:</span>
            <button class="graph-filter-btn active" data-filter="all" onclick="graphFilter('all', this)">All</button>
            <button class="graph-filter-btn" data-filter="elite" onclick="graphFilter('elite', this)">Elite-PQC</button>
            <button class="graph-filter-btn" data-filter="standard" onclick="graphFilter('standard', this)">Standard</button>
            <button class="graph-filter-btn" data-filter="vulnerable" onclick="graphFilter('vulnerable', this)">Vulnerable</button>
            <span style="font-size:0.8rem;color:var(--text-secondary);margin-left:0.5rem">Pool:</span>
            <button class="graph-filter-btn" data-filter="cloud" onclick="graphFilter('cloud', this)" style="background:rgba(124,58,237,0.12);color:#7c3aed;border-color:#7c3aed44;">☁ Cloud</button>
            <button class="graph-filter-btn" data-filter="self_hosted" onclick="graphFilter('self_hosted', this)" style="background:rgba(55,65,81,0.12);color:#9ca3af;border-color:#4b556344;">⬛ Self-Hosted</button>
            <button class="graph-view-toggle" id="graphViewToggleBtn" type="button" onclick="toggleGraphView()" style="margin-left:auto">Switch to Table</button>
        </div>
        <div class="network-view-shell">
            <div id="networkCanvasWrap" style="height:420px;border:1px solid var(--border);border-radius:6px;overflow:hidden;"></div>
            <div id="networkTableWrap" style="display:none"></div>
        </div>
        <div style="display:flex;gap:16px;margin-top:10px;flex-wrap:wrap;font-size:0.72rem;color:var(--text-secondary);">
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#16a34a;margin-right:5px;vertical-align:middle;"></span>Elite-PQC / Domain</span>
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#0891b2;margin-right:5px;vertical-align:middle;"></span>Standard / IP</span>
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#2563eb;margin-right:5px;vertical-align:middle;transform:rotate(45deg);"></span>SSL Cert</span>
            <span><span style="display:inline-block;width:10px;height:10px;background:#d97706;margin-right:5px;vertical-align:middle;"></span>Legacy / TAG</span>
            <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#dc2626;margin-right:5px;vertical-align:middle;"></span>Critical</span>
        </div>
    `;

    NET.rawNodes = rawNodes;
    NET.rawEdges = rawEdges;
    NET.view = 'graph';
    NET.filter = 'all';
    NET.visNetwork = buildVisNetwork('networkCanvasWrap', rawNodes, rawEdges);
    renderNetworkTable();
}

const HM_COLORS = {
    pqc_ready_strong: '#00C853',
    pqc_ready_medium: '#76C442',
    pqc_ready_weak: '#FFB800',
    transition_strong: '#76C442',
    transition_medium: '#FFB800',
    transition_weak: '#FF6D00',
    legacy_strong: '#FFB800',
    legacy_medium: '#FF6D00',
    legacy_weak: '#FF3A5C',
};

const HM_ROWS = ['pqc_ready', 'transition', 'legacy'];
const HM_COLS = ['strong', 'medium', 'weak'];
const HM_ROW_LABELS = { pqc_ready: 'PQC Ready', transition: 'Transition', legacy: 'Legacy' };
const HM_COL_LABELS = { strong: 'Strong Crypto', medium: 'Medium Crypto', weak: 'Weak Crypto' };

function initHeatmap() {
    primeOverviewVisuals();
}

function renderHeatmap(grid, arrow) {
    const heatmapGrid = document.getElementById('heatmapGrid');
    if (!heatmapGrid) return;
    let html = '<div></div>';
    HM_COLS.forEach((col) => {
        html += `<div class="hm-header">${HM_COL_LABELS[col]}</div>`;
    });

    HM_ROWS.forEach((row) => {
        html += `<div class="hm-row-label">${HM_ROW_LABELS[row]}</div>`;
        HM_COLS.forEach((col) => {
            const key = `${row}_${col}`;
            const cell = grid?.[row]?.[col] || { count: 0, hostnames: [] };
            const count = Number(cell.count || 0);
            const zeroClass = count === 0 ? 'zero' : '';
            html += `<div class="hm-cell ${zeroClass}" data-row="${row}" data-col="${col}" style="background:${HM_COLORS[key] || '#888'}">
                <div class="hm-count">${count}</div>
                <div class="hm-label">assets</div>
            </div>`;
        });
    });
    heatmapGrid.innerHTML = html;

    heatmapGrid.querySelectorAll('.hm-cell').forEach((cell) => {
        if (cell.classList.contains('zero')) return;
        const row = cell.dataset.row;
        const col = cell.dataset.col;
        cell.addEventListener('click', () => {
            hmClick(row, col, grid?.[row]?.[col]?.hostnames || []);
        });
    });

    const arrowEl = document.getElementById('heatmapArrow');
    if (arrowEl && arrow) {
        const current = arrow.current_state || {};
        const curLabel = `${HM_ROW_LABELS[current.row] || current.row || 'Unknown'} + ${HM_COL_LABELS[current.col] || current.col || 'Unknown'}`;
        const curColor = HM_COLORS[`${current.row}_${current.col}`] || '#888';
        arrowEl.innerHTML = `
            <div style="background:${curColor};border-radius:0.375rem;padding:0.4rem 0.75rem;font-size:0.75rem;font-weight:600;color:#fff">${escHtml(curLabel)} (current)</div>
            <span style="font-size:1.1rem;color:var(--text-secondary)">→</span>
            <div style="background:#00C853;border-radius:0.375rem;padding:0.4rem 0.75rem;font-size:0.75rem;font-weight:600;color:#fff">PQC Ready + Strong</div>
            <span style="color:var(--text-secondary);font-size:0.75rem;margin-left:0.25rem">Your migration target</span>
        `;
    }
}

function hmClick(row, col, hostnames) {
    const detail = document.getElementById('heatmapDetail');
    if (!detail) return;
    if (!hostnames || hostnames.length === 0) {
        detail.style.display = 'none';
        return;
    }
    const label = `${HM_ROW_LABELS[row]} + ${HM_COL_LABELS[col]}`;
    detail.style.display = 'block';
    detail.innerHTML = `
        <strong>${escHtml(label)} — ${hostnames.length} assets</strong>
        <div style="display:flex;flex-wrap:wrap;gap:0.4rem;margin-top:0.5rem">
            ${hostnames.map((host) => `<span style="background:rgba(255,255,255,0.03);border:0.0625rem solid var(--border-subtle);border-radius:0.375rem;padding:0.15rem 0.5rem;font-size:0.75rem">${escHtml(host)}</span>`).join('')}
        </div>
    `;
}

function renderHeatmapSection(payload) {
    const mount = document.getElementById('heatmapVizMount');
    if (!mount) return;
    mount.innerHTML = `
        ${bannerHtml(payload)}
        <div id="heatmapWrap" style="max-width:min(90vw,36rem)">
            <div style="display:grid;grid-template-columns:6rem 1fr 1fr 1fr;gap:0.25rem" id="heatmapGrid"></div>
            <div id="heatmapArrow" style="display:flex;align-items:center;gap:0.75rem;margin-top:1rem;padding:0.75rem 1rem;background:rgba(255,255,255,0.03);border-radius:0.5rem;font-size:0.8rem;flex-wrap:wrap"></div>
            <div id="heatmapDetail" style="display:none;margin-top:0.75rem;padding:0.75rem 1rem;border:0.0625rem solid var(--border-subtle);border-radius:0.5rem;font-size:0.8rem"></div>
            <div style="margin-top:1.5rem;display:flex;align-items:center;justify-content:space-between;gap:0.75rem;flex-wrap:wrap">
                <div class="viz-surface-head" style="margin:0">Per-Asset Q-Score Gauges</div>
                <div id="gaugeBannerSlot"></div>
            </div>
            <div id="gaugeGrid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(8.5rem,1fr));gap:0.75rem;margin-top:0.75rem"></div>
        </div>
    `;
    renderHeatmap(payload.grid || payload.heatmap || {}, payload.migration_arrow);
}

function buildGaugeArc(cx, cy, radius, score) {
    const pct = Math.min(Math.max(score, 0), 100) / 100;
    const startAngle = Math.PI;
    const endAngle = Math.PI + Math.PI * pct;
    const startX = cx + radius * Math.cos(startAngle);
    const startY = cy + radius * Math.sin(startAngle);
    const endX = cx + radius * Math.cos(endAngle);
    const endY = cy + radius * Math.sin(endAngle);
    if (pct <= 0) return `M${startX},${startY}`;
    return `M${startX},${startY} A${radius},${radius} 0 0,1 ${endX},${endY}`;
}

function renderGaugesFrame(assets, progress) {
    const grid = document.getElementById('gaugeGrid');
    if (!grid) return;
    grid.innerHTML = assets.map((asset) => {
        const rawScore = vizAssetScore(asset);
        const score = Math.round(rawScore * progress);
        const tier = vizTierLabel(asset);
        const color = tierColor(tier) !== VIZ_COLORS.unknown ? tierColor(tier) : scoreColor(rawScore);
        const tierShade = `${tierColor(tier)}18`;
        const arc = buildGaugeArc(56, 56, 40, score);
        const bgArc = buildGaugeArc(56, 56, 40, 100);
        return `<div class="gauge-card">
            <svg width="112" height="68" viewBox="0 0 112 68">
                <path d="${bgArc}" fill="none" stroke="rgba(55,65,81,0.55)" stroke-width="7" stroke-linecap="round"></path>
                <path d="${arc}" fill="none" stroke="${color}" stroke-width="7" stroke-linecap="round"></path>
                <text x="56" y="52" text-anchor="middle" font-size="18" font-weight="600" fill="${color}">${score}</text>
            </svg>
            <div class="gauge-name">${escHtml((asset.hostname || asset.asset?.hostname || asset.name || '').replace('.bank.com', '').replace('.pnb.bank.in', ''))}</div>
            <span class="gauge-tier" style="background:${tierShade};color:${tierColor(tier)}">${escHtml(tier || 'Unknown')}</span>
        </div>`;
    }).join('');
}

async function initGauges(forceRefresh = false) {
    const grid = document.getElementById('gaugeGrid');
    const bannerSlot = document.getElementById('gaugeBannerSlot');
    if (!grid) return;
    grid.innerHTML = '<div class="viz-state" style="grid-column:1 / -1"><div class="viz-state-content"><div class="viz-spinner"></div><div class="viz-state-copy">Loading latest asset scores...</div></div></div>';
    try {
        const payload = await fetchLatestScan(forceRefresh);
        if (bannerSlot) bannerSlot.innerHTML = bannerHtml(payload);
        const assets = [...(payload.assets || payload.asset_scores || [])].sort((a, b) => vizAssetScore(b) - vizAssetScore(a));
        if (!assets.length) {
            grid.innerHTML = '<div class="viz-state" style="grid-column:1 / -1"><div class="viz-state-content"><div class="viz-state-title">No score data yet</div><div class="viz-state-copy">Run a scan or refresh the enterprise APIs to populate gauges.</div></div></div>';
            return;
        }

        const start = performance.now();
        const duration = 700;
        const step = (now) => {
            const progress = Math.min(1, (now - start) / duration);
            renderGaugesFrame(assets, progress);
            if (progress < 1) requestAnimationFrame(step);
        };
        requestAnimationFrame(step);
    } catch (error) {
        grid.innerHTML = `<div class="viz-state" style="grid-column:1 / -1"><div class="viz-state-content"><div class="viz-state-title">Gauge render failed</div><div class="viz-state-copy">${escHtml(error.message)}</div><button class="viz-retry" type="button" onclick="initGauges(true)">Retry</button></div></div>`;
    }
}

const CYBER_BG = { elite: '#1B5E20', standard: '#E65100', legacy: '#B71C1C' };

function cyberBg(score) {
    return parseInt(score, 10) > 700 ? CYBER_BG.elite : parseInt(score, 10) > 400 ? CYBER_BG.standard : CYBER_BG.legacy;
}

function cyberTier(score) {
    return parseInt(score, 10) > 700 ? 'Elite-PQC' : parseInt(score, 10) > 400 ? 'Standard' : 'Legacy';
}

function cyberTierSub(score) {
    return parseInt(score, 10) > 700 ? 'Indicates a stronger security posture' : parseInt(score, 10) > 400 ? 'Acceptable enterprise configuration' : 'Remediation required';
}

function updateCyberCard(score) {
    const scoreNode = document.getElementById('cyberScore');
    const cardNode = document.getElementById('cyberCard');
    const labelNode = document.getElementById('cyberTierLabel');
    const subNode = document.getElementById('cyberTierSub');
    if (scoreNode) scoreNode.textContent = Math.round(score);
    if (cardNode) cardNode.style.background = cyberBg(score);
    if (labelNode) labelNode.textContent = cyberTier(score);
    if (subNode) subNode.textContent = cyberTierSub(score);
}

function initCyberRating() {
    primeOverviewVisuals();
}

function renderCyberRatingSection(payload) {
    const mount = document.getElementById('cyberVizMount');
    if (!mount) return;
    const score = payload.enterprise_score ?? 0;
    const assets = payload.per_asset || [];
    const tiers = payload.tier_criteria || [];
    mount.innerHTML = `
        ${bannerHtml(payload)}
        <div id="cyberCard" style="border-radius:0.75rem;padding:1.75rem 2rem;display:flex;align-items:center;gap:1.5rem;flex-wrap:wrap;margin-bottom:1.25rem;transition:background 0.4s">
            <div>
                <div style="display:flex;align-items:baseline;gap:0.75rem">
                    <span id="cyberScore" style="font-size:4rem;font-weight:800;line-height:1;color:#fff">0</span>
                    <span style="font-size:1.5rem;color:rgba(255,255,255,0.6);font-weight:300">/ 1000</span>
                </div>
            </div>
            <div>
                <div id="cyberTierLabel" style="font-size:1.25rem;font-weight:600;color:#fff">Standard</div>
                <div id="cyberTierSub" style="font-size:0.8rem;color:rgba(255,255,255,0.7);margin-top:0.2rem">Enterprise posture summary</div>
            </div>
            <div style="margin-left:auto;text-align:right">
                <div style="font-size:0.75rem;color:rgba(255,255,255,0.6);margin-bottom:0.4rem">Simulate score</div>
                <input type="range" id="cyberSlider" min="0" max="1000" value="${score}" style="width:9rem" oninput="updateCyberCard(this.value)">
            </div>
        </div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(16rem,1fr));gap:1rem">
            <div style="background:rgba(255,255,255,0.03);border:0.0625rem solid var(--border-subtle);border-radius:0.75rem;padding:1rem">
                <div style="font-size:0.8rem;font-weight:600;margin-bottom:0.75rem">Asset Scores</div>
                <div id="cyberAssetList"></div>
            </div>
            <div style="background:rgba(255,255,255,0.03);border:0.0625rem solid var(--border-subtle);border-radius:0.75rem;padding:1rem">
                <div style="font-size:0.8rem;font-weight:600;margin-bottom:0.75rem">Tier Reference</div>
                <div id="cyberTierTable"></div>
            </div>
        </div>
    `;

    updateCyberCard(score);

    const assetList = document.getElementById('cyberAssetList');
    if (assetList) {
        assetList.innerHTML = assets.map((asset) => `
            <div class="cyber-asset-row">
                <div style="font-size:0.75rem;flex:1;color:var(--text-secondary)">${escHtml((asset.hostname || asset.asset?.hostname || '').replace('.pnb.bank.in', '').replace('.bank.com', ''))}</div>
                <div style="width:4rem;height:0.375rem;background:rgba(55,65,81,0.35);border-radius:0.25rem;overflow:hidden">
                    <div style="height:100%;width:${vizAssetScore(asset)}%;background:${scoreColor(vizAssetScore(asset))};border-radius:0.25rem"></div>
                </div>
                <div style="font-size:0.8rem;font-weight:600;min-width:1.75rem;text-align:right;color:${scoreColor(vizAssetScore(asset))}">${vizAssetScore(asset)}</div>
            </div>
        `).join('');
    }

    const tierTable = document.getElementById('cyberTierTable');
    if (tierTable) {
        tierTable.innerHTML = tiers.map((tier) => `
            <div style="display:flex;align-items:center;gap:0.625rem;padding:0.625rem 0;border-bottom:0.0625rem solid rgba(55,65,81,0.25);${cyberTier(score) === tier.tier ? 'background:rgba(255,165,0,0.06);border-radius:0.375rem;padding-inline:0.5rem' : ''}">
                <span style="width:0.6rem;height:0.6rem;border-radius:50%;background:${tierColor(tier.tier)};display:inline-block;flex-shrink:0"></span>
                <span style="font-size:0.8rem;flex:1">${escHtml(tier.tier || 'Tier')}</span>
                <span style="font-size:0.76rem;color:var(--text-secondary);text-align:right">${escHtml(tier.security_level || tier.compliance_criteria || '')}</span>
            </div>
        `).join('');
    }
}

function certColor(daysLeft) {
    return daysLeft <= 30 ? '#c62828' : daysLeft <= 60 ? '#e64a19' : daysLeft <= 90 ? '#f57f17' : '#2e7d32';
}

async function initCertChart(sslData, payloadMeta = {}) {
    const mount = document.getElementById('certVizMount');
    if (!mount) return;
    const items = Array.isArray(sslData) ? sslData : [];
    if (!items.length) {
        mount.innerHTML = `${bannerHtml(payloadMeta)}<div class="viz-state"><div class="viz-state-content"><div class="viz-state-title">No SSL inventory</div><div class="viz-state-copy">Refresh the overview to load certificate records.</div></div></div>`;
        return;
    }

    mount.innerHTML = `
        ${bannerHtml(payloadMeta)}
        <div class="cert-stat-grid" id="certStatCards"></div>
        <div style="background:rgba(255,255,255,0.03);border:0.0625rem solid var(--border-subtle);border-radius:0.75rem;padding:1rem">
            <div style="font-size:0.8rem;font-weight:600;margin-bottom:0.75rem">Certificate Expiry Timeline</div>
            <div class="cert-chart-wrap" id="certChartWrap">
                <canvas id="certExpiryChart"></canvas>
            </div>
        </div>
    `;

    const certs = items.slice(0, 12).map((cert) => {
        const validFrom = new Date(cert.valid_from);
        const validTo = cert.valid_to ? new Date(cert.valid_to) : new Date(validFrom.getTime() + 90 * 24 * 60 * 60 * 1000);
        const today = new Date();
        const daysLeft = Math.max(0, Math.round((validTo - today) / (1000 * 60 * 60 * 24)));
        return {
            label: (cert.common_name || cert.ssl_sha_fingerprint || '').slice(0, 20),
            daysLeft,
        };
    });

    const chartWrap = document.getElementById('certChartWrap');
    if (chartWrap) chartWrap.style.height = `${Math.max(200, certs.length * 36 + 60)}px`;

    makeChart('certExpiryChart', {
        type: 'bar',
        data: {
            labels: certs.map((cert) => cert.label),
            datasets: [{
                label: 'Days remaining',
                data: certs.map((cert) => cert.daysLeft),
                backgroundColor: certs.map((cert) => certColor(cert.daysLeft)),
                borderRadius: 3,
                borderSkipped: false,
            }],
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: (ctx) => `${ctx.raw} days remaining`,
                    },
                },
            },
            scales: {
                x: {
                    min: 0,
                    max: 180,
                    grid: { color: 'rgba(128,128,128,0.1)' },
                    ticks: { color: '#9ca3af', font: { size: 11 } },
                },
                y: {
                    ticks: { color: '#9ca3af', font: { size: 11 } },
                    grid: { display: false },
                },
            },
        },
    });

    const counts = { lt30: 0, lt60: 0, lt90: 0, ok: 0 };
    certs.forEach((cert) => {
        if (cert.daysLeft <= 30) counts.lt30 += 1;
        else if (cert.daysLeft <= 60) counts.lt60 += 1;
        else if (cert.daysLeft <= 90) counts.lt90 += 1;
        else counts.ok += 1;
    });
    const statsNode = document.getElementById('certStatCards');
    if (statsNode) {
        statsNode.innerHTML = [
            { label: 'Expiring < 30 days', val: counts.lt30, color: '#c62828' },
            { label: 'Expiring 30–60 days', val: counts.lt60, color: '#e64a19' },
            { label: 'Expiring 60–90 days', val: counts.lt90, color: '#f57f17' },
            { label: 'Valid > 90 days', val: counts.ok, color: '#2e7d32' },
        ].map((stat) => `
            <div style="background:rgba(255,255,255,0.03);border-radius:0.5rem;padding:0.875rem">
                <div style="font-size:0.7rem;color:var(--text-secondary)">${stat.label}</div>
                <div style="font-size:1.5rem;font-weight:700;color:${stat.color}">${stat.val}</div>
            </div>
        `).join('');
    }
}

function cipherColor(name) {
    if (/MLKEM|X25519MLKEM/i.test(name)) return '#2e7d32';
    if (/AES.?256.*GCM|CHACHA20/i.test(name)) return '#1976d2';
    if (/DES|CBC|RC4|NULL/i.test(name)) return '#c62828';
    return '#f57f17';
}

function deriveCbomMetrics(cbom) {
    const components = (cbom.components || []).filter((component) => (
        component.type === 'cryptographic-asset'
        && component.cryptoProperties?.assetType === 'protocol'
    ));
    const summary = cbom.pqcSummary || {};
    const distribution = summary.distribution || {};
    const keyLengthDistribution = {};
    const tlsDistribution = {};
    const cipherUsage = [];
    const componentByRef = new Map();

    components.forEach((component) => {
        componentByRef.set(component['bom-ref'], component);
    });

    components.forEach((component) => {
        const algorithmProperties = component.cryptoProperties?.algorithmProperties || {};
        const protocolProperties = component.cryptoProperties?.protocolProperties || {};
        const keyLength = Number(algorithmProperties.keySize || 0) || 0;
        const keyBucket = keyLength >= 3072 ? '3072+' : keyLength >= 2048 ? '2048' : keyLength ? String(keyLength) : 'Unknown';
        keyLengthDistribution[keyBucket] = (keyLengthDistribution[keyBucket] || 0) + 1;

        const protocol = protocolProperties.version || 'Unknown';
        tlsDistribution[protocol] = (tlsDistribution[protocol] || 0) + 1;

        const cipherName = [algorithmProperties.keyExchange, algorithmProperties.authentication].filter(Boolean).join(' / ') || component.name || 'Unknown';
        const existing = cipherUsage.find((entry) => entry.name === cipherName);
        if (existing) existing.count += 1;
        else cipherUsage.push({ name: cipherName, count: 1 });
    });

    const vulnerabilities = (cbom.vulnerabilities || []).map((entry) => {
        const affectedRef = entry?.affects?.[0]?.ref || '';
        const affectedComponent = componentByRef.get(affectedRef) || {};
        const properties = entry.properties || [];
        const previousValue = extractNamedProperty(properties, 'qarmor:previousValue');
        const currentValue = extractNamedProperty(properties, 'qarmor:currentValue');
        return {
            asset: affectedComponent.name || affectedRef || 'Unknown asset',
            category: (extractNamedProperty(properties, 'qarmor:category') || 'finding').replace(/_/g, ' '),
            urgency: String(extractNamedProperty(properties, 'qarmor:urgency') || entry?.ratings?.[0]?.severity || 'info').toUpperCase(),
            description: entry.description || '',
            recommendation: entry.recommendation || '',
            evidence: previousValue || currentValue ? `${previousValue || '—'} -> ${currentValue || '—'}` : '',
        };
    });

    return {
        stats: [
            { label: 'Protected Assets', val: summary.totalAssets ?? components.length },
            { label: 'Q-Safety Score', val: summary.quantumSafetyScore ?? 0 },
            { label: 'Average Agility', val: summary.averageAgilityScore ?? 0 },
            { label: 'Weak Cryptography', val: (distribution.quantumVulnerable || 0) + (distribution.criticallyVulnerable || 0), warn: true },
            { label: 'Open Findings', val: vulnerabilities.length, warn: vulnerabilities.length > 0 },
        ],
        serialNumber: cbom.serialNumber || '',
        generatedAt: cbom.metadata?.timestamp || '',
        dataMode: extractNamedProperty(cbom.metadata?.properties, 'qarmor:dataMode') || cbom.dataMode || 'live',
        contentHash: extractNamedProperty(cbom.metadata?.properties, 'qarmor:contentHash'),
        averages: {
            best: summary.averageBestScore ?? 0,
            worst: summary.averageWorstScore ?? 0,
            agility: summary.averageAgilityScore ?? 0,
        },
        distribution,
        keyLengthDistribution,
        tlsDistribution,
        cipherUsage: cipherUsage.sort((a, b) => b.count - a.count).slice(0, 8),
        vulnerabilities,
        applications: components.map((component) => ({
            name: component.name,
            tlsVersion: component.cryptoProperties?.protocolProperties?.version || '—',
            keyExchange: component.cryptoProperties?.algorithmProperties?.keyExchange || '—',
            authentication: component.cryptoProperties?.algorithmProperties?.authentication || '—',
            keyLength: component.cryptoProperties?.algorithmProperties?.keySize || '—',
            status: component.pqcAssessment?.status || 'UNKNOWN',
            typicalScore: component.pqcAssessment?.typicalScore ?? '—',
            worstScore: component.pqcAssessment?.worstCaseScore ?? '—',
            agilityScore: component.pqcAssessment?.agilityScore ?? '—',
            standards: (component.nistStandardRefs || []).map((ref) => ref.replace(/^nist-/i, '').toUpperCase()).join(', ') || '—',
            summary: component.pqcAssessment?.summary || '—',
            action: component.pqcAssessment?.recommendedAction || '—',
        })),
    };
}

async function downloadCBOM(format) {
    try {
        let resp;
        if (format === 'cdxa') {
            resp = await authorizedFetch(`${API_BASE}/api/attestation/v2/download`);
            if (!resp.ok) resp = await authorizedFetch(`${API_BASE}/api/attestation/download`);
        } else {
            resp = await authorizedFetch(buildContextEndpoint('/api/cbom/latest'));
        }
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = format === 'cdxa' ? 'qarmor-attestation-cdxa.json' : 'qarmor-cbom-latest.json';
        anchor.click();
        URL.revokeObjectURL(url);
        showToast(format === 'cdxa' ? 'CDXA downloaded' : 'CBOM downloaded', 'success');
    } catch (error) {
        showToast(`Download failed: ${error.message}`, 'error');
    }
}

async function initCBOM(forceRefresh = false) {
    const mount = document.getElementById('cbomVizMount');
    if (!mount) return;
    renderVizLoading('cbomVizMount', 'Loading CBOM analytics', 'Summarizing components, protocols, and cryptographic posture...');
    try {
        const cbom = await fetchCbomLatest(forceRefresh);
        latestCbomPayload = cbom;
        const metrics = deriveCbomMetrics(cbom);
        const distributionCards = [
            { label: 'Fully Quantum Safe', value: metrics.distribution.fullyQuantumSafe || 0, tone: 'FULLY_QUANTUM_SAFE' },
            { label: 'Transition Ready', value: metrics.distribution.pqcTransition || 0, tone: 'PQC_TRANSITION' },
            { label: 'Quantum Vulnerable', value: metrics.distribution.quantumVulnerable || 0, tone: 'NON_COMPLIANT' },
            { label: 'Critical', value: metrics.distribution.criticallyVulnerable || 0, tone: 'CRITICALLY_VULNERABLE' },
            { label: 'Unknown', value: metrics.distribution.unknown || 0, tone: 'UNKNOWN' },
        ];
        mount.innerHTML = `
            ${bannerHtml(cbom)}
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(12rem,1fr));gap:0.75rem;margin-bottom:1rem;">
                <div style="background:rgba(255,255,255,0.03);border:0.0625rem solid var(--border-subtle);border-radius:0.75rem;padding:1rem;">
                    <div style="font-size:0.72rem;color:var(--text-secondary);margin-bottom:0.35rem;">CBOM Document</div>
                    <div style="font-size:1.15rem;font-weight:700;">CBOM ${escHtml(shortenDocumentId(metrics.serialNumber, 'LATEST'))}</div>
                    <div style="font-size:0.78rem;color:var(--text-secondary);margin-top:0.35rem;">Generated ${escHtml(formatUiDateTime(metrics.generatedAt))}</div>
                </div>
                <div style="background:rgba(255,255,255,0.03);border:0.0625rem solid var(--border-subtle);border-radius:0.75rem;padding:1rem;">
                    <div style="font-size:0.72rem;color:var(--text-secondary);margin-bottom:0.35rem;">Scan Context</div>
                    <div style="display:flex;flex-wrap:wrap;gap:0.45rem;margin-bottom:0.45rem;">
                        ${renderToneBadge(String(metrics.dataMode || 'live').toUpperCase(), metrics.dataMode === 'demo' ? 'PARTIALLY_COMPLIANT' : 'COMPLIANT')}
                    </div>
                    <div style="font-size:0.78rem;color:var(--text-secondary);">Hash ${escHtml(shortenDocumentId(metrics.contentHash, '—'))}</div>
                </div>
                <div style="background:rgba(255,255,255,0.03);border:0.0625rem solid var(--border-subtle);border-radius:0.75rem;padding:1rem;">
                    <div style="font-size:0.72rem;color:var(--text-secondary);margin-bottom:0.35rem;">Posture Summary</div>
                    <div style="font-size:0.9rem;line-height:1.6;">
                        <div><strong>Average Best:</strong> ${escHtml(String(metrics.averages.best || 0))}</div>
                        <div><strong>Average Worst:</strong> ${escHtml(String(metrics.averages.worst || 0))}</div>
                        <div><strong>Agility:</strong> ${escHtml(String(metrics.averages.agility || 0))}/15</div>
                    </div>
                </div>
            </div>
            <div id="cbomStats" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(9rem,1fr));gap:0.75rem;margin-bottom:1.25rem"></div>
            <div style="display:flex;flex-wrap:wrap;gap:0.55rem;margin-bottom:1.1rem;">
                ${distributionCards.map((item) => `
                    <div style="display:flex;align-items:center;gap:0.5rem;padding:0.55rem 0.75rem;border-radius:999px;background:rgba(255,255,255,0.03);border:0.0625rem solid var(--border-subtle);">
                        ${renderToneBadge(item.label, item.tone)}
                        <strong style="font-size:0.85rem;">${escHtml(String(item.value))}</strong>
                    </div>
                `).join('')}
            </div>
            <div class="viz-grid viz-grid--two" style="margin-bottom:1rem">
                <div style="background:rgba(255,255,255,0.03);border:0.0625rem solid var(--border-subtle);border-radius:0.75rem;padding:1rem">
                    <div style="font-size:0.8rem;font-weight:600;margin-bottom:0.75rem">Key Length Distribution</div>
                    <div class="cbom-chart-wrap" style="position:relative;height:12.5rem">
                        <canvas id="keyLengthChart"></canvas>
                    </div>
                </div>
                <div style="background:rgba(255,255,255,0.03);border:0.0625rem solid var(--border-subtle);border-radius:0.75rem;padding:1rem">
                    <div style="font-size:0.8rem;font-weight:600;margin-bottom:0.75rem">Encryption Protocols</div>
                    <div class="cbom-chart-wrap" style="position:relative;height:12.5rem">
                        <canvas id="protoChart"></canvas>
                    </div>
                </div>
            </div>
            <div style="background:rgba(255,255,255,0.03);border:0.0625rem solid var(--border-subtle);border-radius:0.75rem;padding:1rem;margin-bottom:1rem">
                <div style="font-size:0.8rem;font-weight:600;margin-bottom:0.75rem">Cipher Suite Usage</div>
                <div id="cipherBars"></div>
            </div>
            <div style="background:rgba(255,255,255,0.03);border:0.0625rem solid var(--border-subtle);border-radius:0.75rem;padding:1rem;margin-bottom:1rem">
                <div style="display:flex;justify-content:space-between;align-items:center;gap:1rem;margin-bottom:0.75rem;">
                    <div style="font-size:0.8rem;font-weight:600;">Priority Findings</div>
                    <div style="font-size:0.75rem;color:var(--text-secondary);">${metrics.vulnerabilities.length} flagged issues</div>
                </div>
                <div style="overflow-x:auto">
                    <table id="cbomFindingsTable" class="asset-table"></table>
                </div>
            </div>
            <div style="background:rgba(255,255,255,0.03);border:0.0625rem solid var(--border-subtle);border-radius:0.75rem;padding:1rem">
                <div style="font-size:0.8rem;font-weight:600;margin-bottom:0.75rem">Asset Inventory</div>
                <div style="overflow-x:auto">
                    <table id="cbomTable" style="width:100%;border-collapse:collapse;font-size:0.8rem"></table>
                </div>
            </div>
        `;

        const statsNode = document.getElementById('cbomStats');
        if (statsNode) {
            statsNode.innerHTML = metrics.stats.map((stat) => `
                <div style="background:${stat.warn ? 'rgba(198,40,40,0.08)' : 'rgba(255,255,255,0.03)'};border-radius:0.5rem;padding:0.875rem">
                    <div style="font-size:0.7rem;color:var(--text-secondary)">${stat.label}</div>
                    <div style="font-size:1.5rem;font-weight:700;color:${stat.warn ? '#c62828' : 'var(--text-primary)'}">${stat.val}</div>
                </div>
            `).join('');
        }

        makeChart('keyLengthChart', {
            type: 'bar',
            data: {
                labels: Object.keys(metrics.keyLengthDistribution),
                datasets: [{
                    data: Object.values(metrics.keyLengthDistribution),
                    backgroundColor: Object.keys(metrics.keyLengthDistribution).map((key) => {
                        const numeric = parseInt(key, 10);
                        if (numeric >= 3072) return '#1565c0';
                        if (numeric >= 2048) return '#1976d2';
                        return '#c62828';
                    }),
                    borderRadius: 4,
                    borderSkipped: false,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: { grid: { color: 'rgba(128,128,128,0.1)' }, ticks: { color: '#9ca3af', font: { size: 11 } } },
                    x: { ticks: { color: '#9ca3af', font: { size: 11 } }, grid: { display: false } },
                },
            },
        });

        makeChart('protoChart', {
            type: 'doughnut',
            data: {
                labels: Object.keys(metrics.tlsDistribution),
                datasets: [{
                    data: Object.values(metrics.tlsDistribution),
                    backgroundColor: ['#2e7d32', '#f57f17', '#e64a19', '#b71c1c', '#616161'],
                    borderWidth: 0,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { color: '#9ca3af', font: { size: 11 }, boxWidth: 12 },
                    },
                },
            },
        });

        const cipherNode = document.getElementById('cipherBars');
        if (cipherNode) {
            const maxCount = Math.max(1, ...metrics.cipherUsage.map((entry) => entry.count));
            cipherNode.innerHTML = metrics.cipherUsage.map((entry) => `
                <div class="cipher-row">
                    <div class="cipher-name">${escHtml(entry.name)}</div>
                    <div class="cipher-bar-wrap"><div class="cipher-bar" data-pct="${(entry.count / maxCount) * 100}" style="background:${cipherColor(entry.name)}"></div></div>
                    <div class="cipher-count">${entry.count}</div>
                </div>
            `).join('');
            requestAnimationFrame(() => {
                document.querySelectorAll('.cipher-bar').forEach((bar) => {
                    bar.style.width = `${bar.dataset.pct}%`;
                });
            });
        }

        const tableNode = document.getElementById('cbomTable');
        if (tableNode) {
            tableNode.innerHTML = `
                <thead>
                    <tr style="border-bottom:0.0625rem solid var(--border-subtle)">
                        ${['Asset', 'TLS', 'Key Exchange', 'Signature', 'Status', 'Worst', 'Agility', 'Standards', 'Next Step'].map((header) => `<th style="padding:0.5rem 0.75rem;text-align:left;font-size:0.75rem;color:var(--text-secondary);font-weight:600">${header}</th>`).join('')}
                    </tr>
                </thead>
                <tbody>
                    ${metrics.applications.map((app) => {
                        const rowClass = /DES|CBC|RC4/i.test(`${app.keyExchange} ${app.authentication}`) ? 'cbom-table-row-weak' : /MLKEM|ML-KEM|MLDSA|ML-DSA|SLH/i.test(`${app.keyExchange} ${app.authentication}`) ? 'cbom-table-row-pqc' : 'cbom-table-row-normal';
                        return `<tr class="${rowClass}">
                            <td style="padding:0.5rem 0.75rem;font-size:0.8rem">
                                <div style="font-weight:600;">${escHtml(app.name || '')}</div>
                                <div style="font-size:0.72rem;color:var(--text-secondary);">${escHtml(app.summary || '—')}</div>
                            </td>
                            <td style="padding:0.5rem 0.75rem;font-size:0.8rem">${escHtml(String(app.tlsVersion || '—'))}</td>
                            <td style="padding:0.5rem 0.75rem;font-size:0.8rem;color:${cipherColor(app.keyExchange || '')}">${escHtml(app.keyExchange || '—')}</td>
                            <td style="padding:0.5rem 0.75rem;font-size:0.8rem">${escHtml(app.authentication || '—')}</td>
                            <td style="padding:0.5rem 0.75rem;font-size:0.8rem">${renderToneBadge(String(app.status || 'UNKNOWN').replace(/_/g, ' '), app.status)}</td>
                            <td style="padding:0.5rem 0.75rem;font-size:0.8rem;font-weight:700;">${escHtml(String(app.worstScore || '—'))}</td>
                            <td style="padding:0.5rem 0.75rem;font-size:0.8rem">${escHtml(String(app.agilityScore || '—'))}/15</td>
                            <td style="padding:0.5rem 0.75rem;font-size:0.78rem">${escHtml(app.standards || '—')}</td>
                            <td style="padding:0.5rem 0.75rem;font-size:0.78rem;color:var(--text-secondary);max-width:18rem;">${escHtml(app.action || '—')}</td>
                        </tr>`;
                    }).join('')}
                </tbody>
            `;
        }

        const findingsNode = document.getElementById('cbomFindingsTable');
        if (findingsNode) {
            findingsNode.innerHTML = metrics.vulnerabilities.length
                ? `
                    <thead><tr>
                        <th>Asset</th><th>Category</th><th>Urgency</th><th>What Changed</th><th>Recommended Action</th>
                    </tr></thead>
                    <tbody>
                        ${metrics.vulnerabilities.map((item) => `
                            <tr>
                                <td>${escHtml(item.asset || '—')}</td>
                                <td>${escHtml(item.category || '—')}</td>
                                <td>${renderToneBadge(item.urgency || 'INFO', item.urgency)}</td>
                                <td>
                                    <div>${escHtml(item.description || '—')}</div>
                                    ${item.evidence ? `<div style="font-size:0.72rem;color:var(--text-secondary);margin-top:0.25rem;">${escHtml(item.evidence)}</div>` : ''}
                                </td>
                                <td style="color:var(--text-secondary);">${escHtml(item.recommendation || '—')}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                `
                : `
                    <tbody><tr><td colspan="5" style="text-align:center;color:var(--text-secondary);padding:1rem 0.75rem;">No open CBOM findings for this scan.</td></tr></tbody>
                `;
        }
    } catch (error) {
        renderVizError('cbomVizMount', 'CBOM analytics failed', error.message, 'initCBOM(true)');
    }
}

const NEG_TIER_COLORS = {
    STRONG: { bg: '#e8f5e9', color: '#2e7d32' },
    MEDIUM: { bg: '#fff3e0', color: '#e65100' },
    CLASSICAL: { bg: '#e3f2fd', color: '#1565c0' },
    WEAK: { bg: '#fce4ec', color: '#c62828' },
    CRITICAL: { bg: '#ffebee', color: '#b71c1c' },
};

function buildNegIndicator(policy) {
    if (!policy) return '<span style="color:var(--text-dim);font-size:0.75rem">—</span>';
    const tier = (policy.negotiation_tier || 'UNKNOWN').toUpperCase();
    const colors = NEG_TIER_COLORS[tier] || { bg: '#f5f5f5', color: '#616161' };
    const score = policy.negotiation_security_score ?? 0;
    const scoreTone = score >= 0 ? '#2e7d32' : '#c62828';
    return `<div style="min-width:7rem">
        <div class="neg-dots">
            <div class="neg-dot-wrap">
                <div class="neg-dot" style="background:${policy.pqc_supported ? '#2e7d32' : 'rgba(55,65,81,0.55)'}"></div>
                <div class="neg-dot-label">PQC</div>
            </div>
            <div class="neg-dot-wrap">
                <div class="neg-dot" style="background:${policy.tls13_supported ? '#1565c0' : 'rgba(55,65,81,0.55)'}"></div>
                <div class="neg-dot-label">TLS13</div>
            </div>
            <div class="neg-dot-wrap">
                <div class="neg-dot" style="background:${policy.downgrade_possible ? '#c62828' : 'rgba(55,65,81,0.55)'}"></div>
                <div class="neg-dot-label">DWN</div>
            </div>
            <span class="neg-score" style="color:${scoreTone};margin-left:0.5rem">${score >= 0 ? '+' : ''}${score}</span>
        </div>
        <span class="neg-tier-badge" style="background:${colors.bg};color:${colors.color}">${tier}</span>
    </div>`;
}

function toggleAssessmentDetail(rowId) {
    const detailRow = document.getElementById(`assessment-detail-${rowId}`);
    if (!detailRow) return;
    detailRow.style.display = detailRow.style.display === 'table-row' ? 'none' : 'table-row';
}

function renderAssessmentTable(assessments) {
    const container = document.getElementById('assessTableContainer');
    const badge = document.getElementById('assessCount');
    if (badge) badge.textContent = `${assessments.length} endpoints`;

    if (!assessments.length) {
        container.innerHTML = `<div class="empty-state"><div class="empty-state-icon">🛡️</div><div class="empty-state-title">No assessments</div></div>`;
        return;
    }

    const riskOrder = { HIGH: 0, MEDIUM: 1, LOW: 2 };
    const sorted = [...assessments].sort((a, b) => (riskOrder[a.overall_quantum_risk] ?? 9) - (riskOrder[b.overall_quantum_risk] ?? 9));

    let html = `<table class="assess-table"><thead><tr>
        <th>Endpoint</th>
        <th>Risk</th>
        <th>TLS</th>
        <th>Key Exchange</th>
        <th>Certificate</th>
        <th>Symmetric</th>
        <th>HNDL</th>
        <th>Negotiation Policy</th>
        <th>Q-Score</th>
    </tr></thead><tbody>`;

    sorted.forEach((assessment, index) => {
        const hostname = String(assessment.target || '').trim();
        const policy = assessmentNegotiationPolicies[hostname];
        const rowId = `row-${index}`;
        html += `<tr class="assessment-row-expand" onclick="toggleAssessmentDetail('${rowId}')">
            <td><span class="asset-hostname">${escHtml(hostname || '?')}:${assessment.port || 443}</span></td>
            <td><span class="risk-badge risk-badge--${assessment.overall_quantum_risk || 'HIGH'}">${escHtml(assessment.overall_quantum_risk || 'HIGH')}</span></td>
            <td>${dimPill(assessment.tls_status, assessment.tls_version)}</td>
            <td>${dimPillKex(assessment.key_exchange_status, assessment.key_exchange_algorithm)}</td>
            <td>${dimPillKex(assessment.certificate_status, assessment.certificate_algorithm)}</td>
            <td>${dimPill(assessment.symmetric_cipher_status, assessment.symmetric_cipher)}</td>
            <td>${hndlBadge(assessment.hndl_vulnerable)}</td>
            <td>${buildNegIndicator(policy)}</td>
            <td><span class="qscore-value" style="color:${getScoreColor(assessment.q_score || 0)}">${assessment.q_score || 0}</span></td>
        </tr>
        <tr class="assessment-detail-row" id="assessment-detail-${rowId}" style="display:none">
            <td colspan="9">
                <div class="assessment-detail">
                    <div class="assessment-detail-summary">${escHtml(policy?.policy_summary || 'No negotiation policy summary available for this endpoint.')}</div>
                    <div class="assessment-detail-grid">
                        <div><strong>PQC clients:</strong> ${escHtml(policy?.client_segmentation?.pqc_clients || '—')}</div>
                        <div><strong>Classical clients:</strong> ${escHtml(policy?.client_segmentation?.classical_clients || '—')}</div>
                        <div><strong>Legacy clients:</strong> ${escHtml(policy?.client_segmentation?.legacy_clients || '—')}</div>
                    </div>
                </div>
            </td>
        </tr>`;
    });

    html += '</tbody></table>';
    container.innerHTML = html;
}

function buildAssetSeries(scans) {
    const hostnames = [...new Set(scans.flatMap((scan) => (scan.asset_scores || scan.assets || []).map((asset) => asset.hostname).filter(Boolean)))].slice(0, 5);
    return hostnames.map((hostname) => ({
        hostname,
        scores: scans.map((scan) => {
            const asset = (scan.asset_scores || scan.assets || []).find((item) => item.hostname === hostname);
            return asset ? (asset.worst_case_score ?? asset.worst_score ?? asset.q_score ?? null) : null;
        }),
    })).filter((series) => series.scores.some((score) => score !== null));
}

function renderLatestComparison(comparePayload) {
    const baseline = document.getElementById('baselineContent');
    if (!baseline || !comparePayload) return;
    const delta = comparePayload.delta || {};
    baseline.innerHTML = `
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(9rem,1fr));gap:0.75rem;margin-bottom:1rem">
            <div class="stat-card stat-card--total" style="padding:0.875rem"><div class="stat-value" style="font-size:1.4rem">${comparePayload.scan_b?.total || 0}</div><div class="stat-label">Latest Assets</div></div>
            <div class="stat-card stat-card--safe" style="padding:0.875rem"><div class="stat-value" style="font-size:1.4rem">${delta.fully_safe || 0}</div><div class="stat-label">Safe Delta</div></div>
            <div class="stat-card stat-card--critical" style="padding:0.875rem"><div class="stat-value" style="font-size:1.4rem">${delta.crit_vuln || 0}</div><div class="stat-label">Critical Delta</div></div>
            <div class="stat-card stat-card--transition" style="padding:0.875rem"><div class="stat-value" style="font-size:1.4rem">${delta.avg_score || 0}</div><div class="stat-label">Average Score Delta</div></div>
        </div>
        ${bannerHtml(comparePayload)}
        <table class="asset-table">
            <thead><tr><th>Metric</th><th>Previous</th><th>Latest</th><th>Delta</th></tr></thead>
            <tbody>
                <tr><td>Total Assets</td><td>${comparePayload.scan_a?.total || 0}</td><td>${comparePayload.scan_b?.total || 0}</td><td>${delta.total_assets || 0}</td></tr>
                <tr><td>Average Score</td><td>${comparePayload.scan_a?.avg || 0}</td><td>${comparePayload.scan_b?.avg || 0}</td><td>${delta.avg_score || 0}</td></tr>
                <tr><td>Fully Safe</td><td>${comparePayload.scan_a?.fully_safe || '—'}</td><td>${comparePayload.scan_b?.fully_safe || '—'}</td><td>${delta.fully_safe || 0}</td></tr>
                <tr><td>Critical</td><td>${comparePayload.scan_a?.crit_vuln || '—'}</td><td>${comparePayload.scan_b?.crit_vuln || '—'}</td><td>${delta.crit_vuln || 0}</td></tr>
            </tbody>
        </table>
    `;
}

async function initTimeline(forceRefresh = false) {
    const enterpriseMount = document.getElementById('enterpriseTimelineMount');
    const assetMount = document.getElementById('assetTimelineMount');
    if (!enterpriseMount || !assetMount) return;
    renderVizLoading('enterpriseTimelineMount', 'Loading enterprise timeline', 'Reading recent scan history for trend analysis...');
    renderVizLoading('assetTimelineMount', 'Loading asset trends', 'Finding the assets with the biggest Q-Score changes...');

    try {
        const [historyPayload, comparePayload] = await Promise.all([
            fetchHistoryLatest(forceRefresh),
            apiCall('/api/compare/latest').catch(() => null),
        ]);
        latestHistoryPayload = historyPayload;
        const scans = (historyPayload.scans || historyPayload || []).slice(-6);
        const labels = scans.map((scan, index) => scanSerialForPosition(scans, scan, index));
        const scores = scans.map((scan) => scan.enterprise_score ?? scan.cyber_rating ?? Math.round((scan.avg_score || 0) * 10) ?? 0);

        enterpriseMount.innerHTML = `${bannerHtml(historyPayload)}<div class="timeline-chart-wrap" style="position:relative;height:13.75rem"><canvas id="enterpriseTimelineChart"></canvas></div>`;
        assetMount.innerHTML = `${bannerHtml(historyPayload)}<div class="timeline-chart-wrap" style="position:relative;height:13.75rem"><canvas id="assetTrendChart"></canvas></div>`;

        makeChart('enterpriseTimelineChart', {
            type: 'line',
            data: {
                labels,
                datasets: [{
                    label: 'Enterprise Score',
                    data: scores,
                    borderColor: '#2e7d32',
                    backgroundColor: 'rgba(46,125,50,0.08)',
                    fill: true,
                    tension: 0.4,
                    pointBackgroundColor: '#2e7d32',
                    pointRadius: 5,
                    pointHoverRadius: 7,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: (ctx) => `Score: ${ctx.raw} — ${cyberTier(ctx.raw)}`,
                        },
                    },
                },
                scales: {
                    y: { min: 0, max: 1000, grid: { color: 'rgba(128,128,128,0.1)' }, ticks: { color: '#9ca3af', font: { size: 11 } } },
                    x: { grid: { display: false }, ticks: { color: '#9ca3af', font: { size: 11 } } },
                },
            },
        });

        const assetSeries = buildAssetSeries(scans);
        const palette = ['#2e7d32', '#1976d2', '#c62828', '#f57f17', '#6a1b9a'];
        makeChart('assetTrendChart', {
            type: 'line',
            data: {
                labels,
                datasets: assetSeries.map((series, index) => ({
                    label: series.hostname.replace('.pnb.bank.in', '').replace('.bank.com', ''),
                    data: series.scores,
                    borderColor: palette[index % palette.length],
                    tension: 0.4,
                    pointRadius: 3,
                    pointHoverRadius: 5,
                    fill: false,
                })),
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'top', labels: { color: '#9ca3af', font: { size: 11 }, boxWidth: 12, padding: 16 } },
                },
                scales: {
                    y: { min: 0, max: 100, grid: { color: 'rgba(128,128,128,0.1)' }, ticks: { color: '#9ca3af', font: { size: 11 } } },
                    x: { grid: { display: false }, ticks: { color: '#9ca3af', font: { size: 11 } } },
                },
            },
        });

        if (comparePayload) renderLatestComparison(comparePayload);
    } catch (error) {
        renderVizError('enterpriseTimelineMount', 'Timeline failed', error.message, 'initTimeline(true)');
        renderVizError('assetTimelineMount', 'Asset trends failed', error.message, 'initTimeline(true)');
    }
}

const originalLoadHistory = loadHistory;
const originalLoadLiveHistory = loadLiveHistory;
const originalRunPhase9Demo = runPhase9Demo;
const originalRunPhase9Live = runPhase9Live;
const originalRunDemoScan = runDemoScan;
const originalScanDomain = scanDomain;
const originalScanSingleHost = scanSingleHost;

loadEnterpriseDashboardData = async function loadEnterpriseDashboardDataInteractive(opts = {}) {
    const notifyOnError = Boolean(opts.notifyOnError);
    const forceRefresh = Boolean(opts.forceRefresh);
    const context = getEnterpriseContext({ notifyOnError });
    if (!context) return;

    if (isTabActive('overview') || vizInit.network || vizInit.heatmap || vizInit.cyber || vizInit.gauges) {
        ensureOverviewVizLoading();
    }

    _showStatsLoading(true);

    // Try combined endpoint first (single HTTP call), fall back to progressive groups
    try {
        const initData = await apiCall(buildEnterpriseEndpoint('/api/dashboard/init', context, forceRefresh));
        const { home, domains, ssl, ip, software, graph, cyber, heatmap, negotiation } = initData;
        enterpriseDashboardData = { home, domains, ssl, ip, software, graph, cyber, heatmap, negotiation };
        window.enterpriseDashboardData = enterpriseDashboardData;
        assessmentNegotiationPolicies = (negotiation && negotiation.policies) || {};
        _saveDashboardCache(enterpriseDashboardData);
        renderEnterpriseNotice(home.demo_mode, home.data_notice);
        renderHomeSummaryV2(home);
        renderAssetDiscoveryV2(domains, ssl, ip, software, graph);
        renderCyberPqcV2(cyber, heatmap, negotiation);
        _showStatsLoading(false);
        await syncOverviewWithLatestScan(forceRefresh);
        if (isTabActive('overview') || vizInit.network || vizInit.heatmap || vizInit.cyber || vizInit.gauges) {
            prepareOverviewVisualizations(forceRefresh);
        }
        if (vizInit.cbom && isTabActive('phase9')) {
            initCBOM(forceRefresh);
        }
        return;
    } catch (_combinedErr) {
        // Combined endpoint not available — fall back to progressive loading
    }

    // Progressive group rendering: fire all groups simultaneously, render each as it completes
    const results = { home: null, domains: null, ssl: null, ip: null, software: null, graph: null, cyber: null, heatmap: null, negotiation: null };
    let groupErrors = [];

    // Group A: home summary (smallest payload — renders stat cards first)
    const groupA = apiCall(buildEnterpriseEndpoint('/api/home/summary', context, forceRefresh))
        .then(home => {
            results.home = home;
            renderEnterpriseNotice(home.demo_mode, home.data_notice);
            renderHomeSummaryV2(home);
            _showStatsLoading(false);
        })
        .catch(err => { groupErrors.push(err); _showStatsLoading(false); });

    // Group B: asset discovery (domains, ssl, ip, software, network graph)
    const groupB = Promise.all([
        apiCall(buildEnterpriseEndpoint('/api/assets/domains', context)),
        apiCall(buildEnterpriseEndpoint('/api/assets/ssl', context)),
        apiCall(buildEnterpriseEndpoint('/api/assets/ip', context)),
        apiCall(buildEnterpriseEndpoint('/api/assets/software', context)),
        apiCall(buildEnterpriseEndpoint('/api/assets/network-graph', context)),
    ]).then(([domains, ssl, ip, software, graph]) => {
        Object.assign(results, { domains, ssl, ip, software, graph });
        renderAssetDiscoveryV2(domains, ssl, ip, software, graph);
    }).catch(err => {
        groupErrors.push(err);
        renderVizError('networkVizMount', 'Network graph failed', err.message, 'loadEnterpriseDashboardData({ notifyOnError: true, forceRefresh: true })');
    });

    // Group C: cyber rating + PQC posture
    const groupC = Promise.all([
        apiCall(buildEnterpriseEndpoint('/api/cyber-rating', context)),
        apiCall(buildEnterpriseEndpoint('/api/pqc/heatmap', context)),
        apiCall(buildEnterpriseEndpoint('/api/pqc/negotiation', context)),
    ]).then(([cyber, heatmap, negotiation]) => {
        Object.assign(results, { cyber, heatmap, negotiation });
        assessmentNegotiationPolicies = (negotiation && negotiation.policies) || {};
        renderCyberPqcV2(cyber, heatmap, negotiation);
    }).catch(err => {
        groupErrors.push(err);
        renderVizError('cyberVizMount', 'Cyber rating failed', err.message, 'loadEnterpriseDashboardData({ notifyOnError: true, forceRefresh: true })');
        renderVizError('heatmapVizMount', 'PQC posture failed', err.message, 'loadEnterpriseDashboardData({ notifyOnError: true, forceRefresh: true })');
    });

    // Wait for all groups, then finalize
    await Promise.all([groupA, groupB, groupC]);

    enterpriseDashboardData = results;
    window.enterpriseDashboardData = results;
    _saveDashboardCache(results);

    if (groupErrors.length === 0) {
        await syncOverviewWithLatestScan(forceRefresh);
        if (isTabActive('overview') || vizInit.network || vizInit.heatmap || vizInit.cyber || vizInit.gauges) {
            prepareOverviewVisualizations(forceRefresh);
        }
        if (vizInit.cbom && isTabActive('phase9')) {
            initCBOM(forceRefresh);
        }
    } else if (notifyOnError) {
        showToast(`Some enterprise APIs failed: ${groupErrors[0].message}`, 'error');
    }
};

fetchPhase2Assessment = async function fetchPhase2AssessmentInteractive() {
    const assessmentEmpty = document.getElementById('assessmentEmpty');
    const assessmentContent = document.getElementById('assessmentContent');
    const assessTable = document.getElementById('assessTableContainer');
    if (assessmentEmpty) assessmentEmpty.style.display = 'none';
    if (assessmentContent) assessmentContent.style.display = 'block';
    if (assessTable) {
        assessTable.innerHTML = `
            <div class="viz-state">
                <div class="viz-state-content">
                    <div class="viz-spinner"></div>
                    <div class="viz-state-title">Loading assessment intelligence</div>
                    <div class="viz-state-copy">Calculating NIST posture and negotiation policy indicators...</div>
                </div>
            </div>
        `;
    }
    try {
        const [assessResult, remediationResult, negotiationResult] = await Promise.allSettled([
            apiCall('/api/assess'),
            apiCall('/api/assess/remediation'),
            apiCall(buildContextEndpoint('/api/pqc/negotiation')),
        ]);
        if (assessResult.status !== 'fulfilled') {
            throw assessResult.reason;
        }
        const assess = assessResult.value;
        const remediation = remediationResult.status === 'fulfilled' ? remediationResult.value : null;
        const negotiation = negotiationResult.status === 'fulfilled' ? negotiationResult.value : { policies: {} };
        assessmentData = assess;
        assessmentNegotiationPolicies = negotiation.policies || {};
        renderPhase2Assessment(assess);
        if (remediation) {
            remediationData = remediation;
            renderPhase2Remediation(remediation);
        }
    } catch (error) {
        console.warn('Assessment fetch failed:', error);
        showToast(`Assessment fetch failed: ${error.message}`, 'error');
    }
};

switchTab = function switchTabInteractive(tabName) {
    document.querySelectorAll('.tab-btn').forEach((button) => button.classList.remove('tab-btn--active'));
    document.querySelectorAll('.tab-content').forEach((contentNode) => contentNode.classList.remove('tab-content--active'));

    const button = document.querySelector(`.tab-btn[data-tab="${tabName}"]`);
    const content = document.getElementById(`tab-${tabName}`);
    if (button) button.classList.add('tab-btn--active');
    if (content) content.classList.add('tab-content--active');

    if (tabName === 'overview') {
        primeOverviewVisuals();
        if (!enterpriseDashboardData) {
            loadEnterpriseDashboardData({ notifyOnError: true });
        } else {
            prepareOverviewVisualizations();
        }
    }

    if ((tabName === 'inventory' || tabName === 'discovery' || tabName === 'cyberrating' || tabName === 'reporting') && !enterpriseDashboardData) {
        loadEnterpriseDashboardData({ notifyOnError: true });
    }

    // Assessment: use background-prefetched cache if available, else lazy-load
    if (tabName === 'assessment') {
        if (assessmentData) {
            renderPhase2Assessment(assessmentData);
            if (remediationData) renderPhase2Remediation(remediationData);
        } else if (scanData) {
            fetchPhase2Assessment();
        }
    }

    // Lazy-load tri-mode fingerprints when user navigates to Tri-Mode tab
    if (tabName === 'trimode' && !trimodeData && scanData) {
        _loadTrimodeTab();
    }

    // Phase9: use background-prefetched cache if available, else init normally
    if (tabName === 'phase9') {
        vizInit.cbom = true;
        if (phase9Data) {
            renderPhase9(phase9Data);
            const p9Empty = document.getElementById('p9Empty');
            const p9Content = document.getElementById('p9Content');
            if (p9Empty) p9Empty.style.display = 'none';
            if (p9Content) p9Content.style.display = 'block';
        } else {
            initCBOM();
        }
    }

    // Lazy-load attestation + alerts on reporting tab visit
    if (tabName === 'reporting' && !window._attestationLoaded) {
        window._attestationLoaded = true;
        fetchPhase5Data();
    }

    if (tabName === 'history' && !vizInit.timeline && document.getElementById('historyContent')?.style.display !== 'none') {
        vizInit.timeline = true;
        initTimeline();
    }

    if (tabName === 'history' && document.getElementById('historyContent')?.style.display === 'none') {
        loadLiveHistory().catch((error) => {
            console.warn('Automatic history load failed:', error);
        });
    }
};

loadHistory = async function loadHistoryInteractive() {
    await originalLoadHistory();
    if (document.getElementById('historyContent')?.style.display !== 'none') {
        vizInit.timeline = true;
        initTimeline(true);
    }
};

loadLiveHistory = async function loadLiveHistoryInteractive() {
    await originalLoadLiveHistory();
    if (document.getElementById('historyContent')?.style.display !== 'none') {
        vizInit.timeline = true;
        initTimeline(true);
    }
};

runPhase9Demo = async function runPhase9DemoInteractive() {
    await originalRunPhase9Demo();
    if (vizInit.cbom || isTabActive('phase9')) {
        vizInit.cbom = true;
        initCBOM(true);
    }
};

runPhase9Live = async function runPhase9LiveInteractive() {
    await originalRunPhase9Live();
    if (vizInit.cbom || isTabActive('phase9')) {
        vizInit.cbom = true;
        initCBOM(true);
    }
};

runDemoScan = async function runDemoScanInteractive() {
    await originalRunDemoScan();
    latestCbomPayload = null;
    if (isTabActive('overview') || vizInit.network || vizInit.heatmap || vizInit.cyber || vizInit.gauges) {
        await loadEnterpriseDashboardData({ notifyOnError: false, forceRefresh: false });
        await syncOverviewWithLatestScan(false);
    }
};

/* ─── Background secondary scan (assessment, matrix, phase9) ─── */
async function _autoScanSecondary(domain) {
    // Step 1: Assessment + Remediation (feeds Assessment & Remediation tabs)
    _setTabBadge('assessment', 'loading');
    _setTabBadge('remediation', 'loading');
    try {
        const [assess, remediation] = await Promise.all([
            apiCall('/api/assess'),
            apiCall('/api/assess/remediation'),
        ]);
        assessmentData = assess;
        remediationData = remediation;
        _setTabBadge('assessment', 'ready');
        _setTabBadge('remediation', 'ready');
    } catch (e) {
        _setTabBadge('assessment', null);
        _setTabBadge('remediation', null);
        console.warn('Background assessment failed:', e.message);
    }

    // Step 2: NIST Matrix (feeds Matrix tab)
    try {
        nistMatrixData = await apiCall('/api/assess/matrix');
    } catch (e) {
        console.warn('Background NIST matrix failed:', e.message);
    }

    // Step 3: Attestation + Alerts (feeds Reporting tab)
    try {
        await fetchPhase5Data();
        window._attestationLoaded = true;
    } catch (e) {
        console.warn('Background attestation failed:', e.message);
    }

    // Step 4: Phase 9 pipeline (feeds Phase 9 tab — slowest, runs last)
    if (domain) {
        _setTabBadge('phase9', 'loading');
        try {
            phase9Data = await apiCall(`/api/phase9/live/${encodeURIComponent(domain)}`, 'POST');
            _setTabBadge('phase9', 'ready');
        } catch (e) {
            _setTabBadge('phase9', null);
            console.warn('Background phase9 failed:', e.message);
        }
    }
}

scanDomain = async function scanDomainInteractive() {
    await originalScanDomain();
    latestCbomPayload = null;
    if (scanData) {
        const domain = document.getElementById('domainInput')?.value.trim();
        // Refresh enterprise panels (no overlay — uses inline loading badge)
        loadEnterpriseDashboardData({ notifyOnError: false }).catch((e) => {
            console.warn('Background enterprise load after scan:', e.message);
        });
        // Pre-fetch all secondary tabs in background
        if (domain) _autoScanSecondary(domain).catch(() => {});
    }
};

scanSingleHost = async function scanSingleHostInteractive() {
    await originalScanSingleHost();
    latestCbomPayload = null;
    // Load enterprise overview data in background after single-host probe
    if (scanData) {
        loadEnterpriseDashboardData({ notifyOnError: false }).catch((e) => {
            console.warn('Background enterprise load after probe:', e.message);
        });
    }
};

document.addEventListener('DOMContentLoaded', () => {
    ensureOverviewVizLoading();
    primeOverviewVisuals();
});

function pdfSafeText(value, fallback = '-') {
    if (value === null || value === undefined) return fallback;
    const text = String(value)
        .replace(/[•]/g, '-')
        .replace(/[–—]/g, '-')
        .replace(/[^\x20-\x7E]/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
    return text || fallback;
}

function pdfDate(value = new Date()) {
    try {
        return new Date(value).toLocaleDateString('en-IN', {
            day: '2-digit',
            month: 'short',
            year: 'numeric',
        });
    } catch {
        return pdfSafeText(value);
    }
}

function pdfPercent(part, total) {
    if (!total) return '0%';
    return `${Math.round((Number(part || 0) / Number(total || 1)) * 100)}%`;
}

function pdfFilenameTarget() {
    const raw = document.getElementById('domainInput')?.value || 'Demo_Environment';
    return String(raw).trim().replace(/[^a-z0-9._-]+/gi, '_') || 'Demo_Environment';
}

function summarizePdfInventoryResults(results = []) {
    return results.map(normalizeInventoryEntry).sort((a, b) => (a.score || 0) - (b.score || 0));
}

function summarizePdfAssessmentRows(assessments = []) {
    const riskOrder = { HIGH: 0, MEDIUM: 1, LOW: 2 };
    return [...assessments].sort((a, b) =>
        (riskOrder[a.overall_quantum_risk] ?? 9) - (riskOrder[b.overall_quantum_risk] ?? 9)
    );
}

function buildPdfExecutiveHighlights() {
    const scan = latestScanPayload || scanData || {};
    const assess = assessmentData || {};
    const agg = assess.aggregate || {};
    const total = scan.total_assets || agg.total_endpoints || 0;
    const critical = scan.critically_vulnerable || 0;
    const vulnerable = scan.quantum_vulnerable || 0;
    const highRisk = agg.risk_high || 0;
    const avgScore = Number(scan.average_q_score || agg.average_q_score || 0).toFixed(1);
    const transition = scan.pqc_transition || 0;

    const lines = [];
    lines.push(`Average Q-Score is ${avgScore} across ${total || 0} assessed asset${total === 1 ? '' : 's'}.`);

    if (critical > 0) {
        lines.push(`${critical} asset${critical === 1 ? '' : 's'} are critically vulnerable and should be prioritized immediately.`);
    } else if (highRisk > 0) {
        lines.push(`${highRisk} endpoint${highRisk === 1 ? '' : 's'} remain high risk with no critical posture detected.`);
    } else {
        lines.push('No critical exposure is currently reflected in the latest report snapshot.');
    }

    if (transition > 0) {
        lines.push(`${transition} asset${transition === 1 ? '' : 's'} are in PQC transition, indicating partial modernization is underway.`);
    } else if (vulnerable > 0) {
        lines.push(`${vulnerable} asset${vulnerable === 1 ? '' : 's'} still rely on quantum-vulnerable controls.`);
    } else {
        lines.push('The current dataset shows a stable posture with no outstanding transition backlog.');
    }

    return lines;
}

function syncPdfToBackend(blob, filename) {
    const fd = new FormData();
    fd.append('file', blob, filename);
    authorizedFetch('/api/reports/save', { method: 'POST', body: fd }).catch(e => console.warn(e));
}

function reportTable(headers, rows, emptyMessage = 'No data available.') {
    if (!rows.length) {
        return `<div class="report-empty">${escHtml(emptyMessage)}</div>`;
    }
    return `
        <table>
            <thead>
                <tr>${headers.map((header) => `<th>${escHtml(header)}</th>`).join('')}</tr>
            </thead>
            <tbody>
                ${rows.map((row) => `<tr>${row.map((cell) => `<td>${escHtml(pdfSafeText(cell))}</td>`).join('')}</tr>`).join('')}
            </tbody>
        </table>
    `;
}

function reportMetricCards(metrics) {
    return `
        <div class="metrics">
            ${metrics.map((metric) => `
                <div class="metric">
                    <div class="metric-label">${escHtml(metric.label)}</div>
                    <div class="metric-value">${escHtml(pdfSafeText(metric.value))}</div>
                </div>
            `).join('')}
        </div>
    `;
}

function reportSection(title, body, subtitle = '') {
    return `
        <section class="section">
            <h2>${escHtml(title)}</h2>
            ${subtitle ? `<p>${escHtml(subtitle)}</p>` : ''}
            ${body}
        </section>
    `;
}

function reportList(items, emptyMessage = 'No items available.') {
    if (!items.length) {
        return `<div class="report-empty">${escHtml(emptyMessage)}</div>`;
    }
    return `<ul class="highlights">${items.map((item) => `<li>${escHtml(pdfSafeText(item))}</li>`).join('')}</ul>`;
}

function buildNetworkGraphSvg(graphPayload) {
    const nodes = Array.isArray(graphPayload?.nodes) ? graphPayload.nodes : [];
    const edges = Array.isArray(graphPayload?.edges) ? graphPayload.edges : [];
    if (!nodes.length) {
        return '<div class="report-empty">No network graph data available.</div>';
    }

    const width = 920;
    const height = 420;
    const cx = width / 2;
    const cy = height / 2;
    const radius = Math.max(90, Math.min(width, height) / 2 - 70);
    const points = nodes.map((node, index) => {
        const angle = (Math.PI * 2 * index) / Math.max(nodes.length, 1) - Math.PI / 2;
        return {
            ...node,
            x: cx + Math.cos(angle) * radius,
            y: cy + Math.sin(angle) * (radius * 0.72),
        };
    });
    const byId = new Map(points.map((point) => [point.id, point]));
    const tierCounts = points.reduce((acc, point) => {
        const label = vizTierLabel(point);
        acc[label] = (acc[label] || 0) + 1;
        return acc;
    }, {});

    const svg = `
        <div class="graph-shell">
            <svg viewBox="0 0 ${width} ${height}" class="graph-svg" role="img" aria-label="Network graph">
                <rect x="0" y="0" width="${width}" height="${height}" rx="16" fill="#fafafa" stroke="#d9dde3"/>
                ${edges.map((edge) => {
                    const source = byId.get(edge.source);
                    const target = byId.get(edge.target);
                    if (!source || !target) return '';
                    return `<line x1="${source.x}" y1="${source.y}" x2="${target.x}" y2="${target.y}" stroke="#c9ced6" stroke-width="1.5" />`;
                }).join('')}
                ${points.map((point) => {
                    const fill = tierColor(point.display_tier || point.pqc_status);
                    const label = pdfSafeText((point.label || point.id || '').split('.')[0], 'node').slice(0, 14);
                    const ip = pdfSafeText(point.ip_address || '', '');
                    return `
                        <circle cx="${point.x}" cy="${point.y}" r="22" fill="${fill}" fill-opacity="0.14" stroke="${fill}" stroke-width="2"></circle>
                        <circle cx="${point.x}" cy="${point.y}" r="12" fill="${fill}"></circle>
                        <text x="${point.x}" y="${point.y + 38}" text-anchor="middle" font-size="12" font-family="Segoe UI, Arial, sans-serif" fill="#202124">${escHtml(label)}</text>
                        ${ip ? `<text x="${point.x}" y="${point.y + 54}" text-anchor="middle" font-size="10" font-family="Segoe UI, Arial, sans-serif" fill="#6b7280">${escHtml(ip)}</text>` : ''}
                    `;
                }).join('')}
            </svg>
            <div class="graph-legend">
                ${Object.entries(tierCounts).map(([label, count]) => `<span>${escHtml(label)}: <strong>${count}</strong></span>`).join('')}
            </div>
        </div>
    `;

    return svg;
}

async function ensureReportState() {
    if (!enterpriseDashboardData) {
        await loadEnterpriseDashboardData({ notifyOnError: false, forceRefresh: false });
    }

    if (!latestScanPayload && !scanData) {
        try {
            latestScanPayload = await fetchLatestScan(false);
        } catch (error) {
            console.warn('Latest scan fetch failed for report:', error);
        }
    }

    if (!assessmentData || !remediationData) {
        try {
            const [assess, remediation] = await Promise.all([
                apiCall('/api/assess'),
                apiCall('/api/assess/remediation'),
            ]);
            assessmentData = assess;
            remediationData = remediation;
        } catch (error) {
            console.warn('Assessment data fetch failed for report:', error);
        }
    }

    if (!trimodeData) {
        try {
            trimodeData = await apiCall('/api/scan/trimode/fingerprints');
            trimodeData.mode = trimodeData.mode || getActiveEnterpriseContext().mode || 'live';
            trimodeData.total_assets = trimodeData.total || trimodeData.fingerprints?.length || 0;
        } catch (error) {
            console.warn('Tri-mode data fetch failed for report:', error);
        }
    }

    if (!historyData) {
        try {
            historyData = await fetchHistoryLatest(false);
        } catch (error) {
            console.warn('History data fetch failed for report:', error);
        }
    }

    if (!nistMatrixData) {
        try {
            nistMatrixData = await apiCall('/api/assess/matrix');
        } catch (error) {
            console.warn('NIST matrix fetch failed for report:', error);
        }
    }
}

function buildPrintableAssessmentHtml(filename) {
    const scan = latestScanPayload || scanData || {};
    const assessment = assessmentData || {};
    const agg = assessment.aggregate || {};
    const remediation = remediationData || {};
    const inventoryRows = summarizePdfInventoryResults(scan.results || []);
    const assessmentRows = summarizePdfAssessmentRows(assessment.assessments || []);
    const highlights = buildPdfExecutiveHighlights();
    const totalAssets = scan.total_assets || agg.total_endpoints || inventoryRows.length || 0;
    const company = pdfSafeText(
        document.getElementById('domainInput')?.value ||
        document.getElementById('enterpriseDomainInput')?.value ||
        'Demo Environment',
        'Demo Environment'
    );
    const mode = pdfSafeText((document.getElementById('enterpriseModeSelect')?.value || 'demo').toUpperCase(), 'DEMO');
    const findingRows = assessmentRows.length
        ? assessmentRows.slice(0, 8).map(a => ({
            endpoint: `${pdfSafeText(a.target, '?')}:${a.port || 443}`,
            risk: pdfSafeText(a.overall_quantum_risk),
            kex: pdfSafeText(a.key_exchange_algorithm),
            cert: pdfSafeText(a.certificate_algorithm),
            score: pdfSafeText(a.q_score, '0'),
        }))
        : inventoryRows.slice(0, 8).map(row => ({
            endpoint: `${pdfSafeText(row.hostname, '?')}:${row.port || 443}`,
            risk: pdfSafeText(row.status),
            kex: pdfSafeText(row.keyExchange),
            cert: pdfSafeText(row.certificate),
            score: pdfSafeText(row.score, '0'),
        }));
    const actionRows = (remediation.items || remediation.remediations || []).slice(0, 6).map(item => ({
        priority: pdfSafeText(item.priority || item.severity || 'Planned', 'Planned'),
        category: pdfSafeText(item.category || item.dimension || 'General', 'General'),
        action: pdfSafeText(item.title || item.recommendation || item.summary || 'Review cryptographic controls'),
    }));
    const assetRows = inventoryRows.slice(0, 12).map(row => ({
        asset: `${pdfSafeText(row.hostname, '?')}:${row.port || 443}`,
        type: pdfSafeText(row.assetType),
        tls: pdfSafeText(row.tlsVersion),
        kex: pdfSafeText(row.keyExchange),
        score: pdfSafeText(row.score, '0'),
        status: pdfSafeText(row.status),
    }));

    const tableRows = (rows, cells) => rows.length
        ? rows.map(row => `<tr>${cells.map(cell => `<td>${escHtml(row[cell] || '-')}</td>`).join('')}</tr>`).join('')
        : `<tr>${cells.map(() => '<td>-</td>').join('')}</tr>`;

    const enterprise = enterpriseDashboardData || {};
    const home = enterprise.home || {};
    const discovery = home.asset_discovery_summary || {};
    const inventory = home.assets_inventory_summary || {};
    const posture = home.posture_of_pqc || {};
    const cbomSummary = home.cbom_summary || {};
    const cyber = enterprise.cyber || {};
    const graph = enterprise.graph || {};
    const heatmap = enterprise.heatmap || {};
    const domains = enterprise.domains?.items || [];
    const ssl = enterprise.ssl?.items || [];
    const ipAssets = enterprise.ip?.items || [];
    const software = enterprise.software?.items || [];
    const historyWeeks = historyData?.weeks || [];
    const remediationEndpointRows = Object.entries(remediation.per_endpoint || {}).slice(0, 40).flatMap(([endpoint, actions]) =>
        (actions || []).slice(0, 3).map((action) => [
            endpoint,
            action.priority || '-',
            action.category || '-',
            action.title || action.description || '-',
        ])
    );
    const roadmapRows = (remediation.strategic_roadmap || []).flatMap((phase) =>
        (phase.actions || []).map((action) => [
            phase.phase || phase.priority || '-',
            action.priority || phase.priority || '-',
            action.category || '-',
            action.title || '-',
            action.description || '-',
        ])
    );
    const assessmentTableRows = assessmentRows.map((row) => [
        `${row.target || '?'}:${row.port || 443}`,
        row.overall_quantum_risk || '-',
        row.tls_status || '-',
        row.key_exchange_status || '-',
        row.certificate_status || '-',
        row.symmetric_cipher_status || '-',
        row.hndl_vulnerable ? 'YES' : 'NO',
        row.q_score || 0,
    ]);
    const trimodeRows = (trimodeData?.fingerprints || []).map((fp) => [
        `${fp.hostname || '?'}:${fp.port || 443}`,
        fp.asset_type || 'web',
        fp.q_score?.status || 'UNKNOWN',
        fp.q_score?.total || 0,
        `${fp.probe_a?.tls_version || '-'} / ${fp.probe_a?.key_exchange || '-'}`,
        `${fp.probe_b?.tls_version || '-'} / ${fp.probe_b?.key_exchange || '-'}`,
        `${fp.probe_c?.tls_version || '-'} / ${fp.probe_c?.key_exchange || '-'}`,
    ]);
    const phase7Assets = classifiedData?.assets || [];
    const phase7AgilityRows = phase7Assets.map((asset) => [
        `${asset.hostname || '?'}:${asset.port || 443}`,
        asset.status || '-',
        asset.best_case_score || 0,
        asset.typical_score || 0,
        asset.worst_case_score || 0,
        `${asset.agility_score || 0}/15`,
        asset.recommended_action || '-',
    ]);
    const phase9Labels = phase9Data?.labels?.labels || [];
    const phase9Regressions = [
        ...((phase9Data?.regression?.new_assets || []).map((item) => ({ ...item, category: 'New Asset' }))),
        ...((phase9Data?.regression?.score_regressions || []).map((item) => ({ ...item, category: 'Score Regression' }))),
        ...((phase9Data?.regression?.missed_upgrades || []).map((item) => ({ ...item, category: 'Missed Upgrade' }))),
    ];
    const phase9Claims = phase9Data?.attestation?.attestation?.declarations?.claims || [];
    const nist = nistMatrixData || {};
    const heatmapRows = [];
    HM_ROWS.forEach((rowKey) => {
        HM_COLS.forEach((colKey) => {
            heatmapRows.push([
                HM_ROW_LABELS[rowKey],
                HM_COL_LABELS[colKey],
                heatmap?.grid?.[rowKey]?.[colKey]?.count || 0,
                (heatmap?.grid?.[rowKey]?.[colKey]?.hostnames || []).slice(0, 6).join(', ') || '-',
            ]);
        });
    });

    const sections = [];

    sections.push(reportSection(
        'Executive Summary',
        `
            ${reportMetricCards([
                { label: 'Assets Assessed', value: totalAssets },
                { label: 'Average Q-Score', value: Number(scan.average_q_score || agg.average_q_score || 0).toFixed(1) },
                { label: 'Critically Vulnerable', value: `${scan.critically_vulnerable || 0} (${pdfPercent(scan.critically_vulnerable || 0, totalAssets)})` },
                { label: 'Fully Quantum Safe', value: `${scan.fully_quantum_safe || 0} (${pdfPercent(scan.fully_quantum_safe || 0, totalAssets)})` },
            ])}
            ${reportList(highlights)}
        `,
        'A print-ready dashboard report generated from the current Q-ARMOR state.'
    ));

    sections.push(reportSection(
        'Enterprise Overview',
        `
            ${reportMetricCards([
                { label: 'Domains', value: discovery.domain_count || 0 },
                { label: 'IPs', value: discovery.ip_count || 0 },
                { label: 'Subdomains', value: discovery.subdomain_count || 0 },
                { label: 'Cloud Assets', value: discovery.cloud_asset_count || 0 },
                { label: 'SSL Records', value: inventory.ssl_cert_count || 0 },
                { label: 'Software Records', value: inventory.software_count || 0 },
                { label: 'IoT Devices', value: inventory.iot_device_count || 0 },
                { label: 'Login Forms', value: inventory.login_form_count || 0 },
                { label: 'PQC Adoption', value: `${formatPercent(posture.pqc_adoption_pct)}%` },
                { label: 'Transition Rate', value: `${formatPercent(posture.transition_pct)}%` },
                { label: 'Vulnerable Components', value: cbomSummary.vulnerable_component_count || 0 },
                { label: 'Weak Crypto', value: cbomSummary.weak_crypto_count || 0 },
            ])}
        `,
        'High-level enterprise discovery and posture metrics reflected in the overview dashboard.'
    ));

    sections.push(reportSection(
        'Network Graph',
        `
            ${buildNetworkGraphSvg(graph)}
            ${reportTable(
                ['Node', 'Type', 'Tier', 'IP Address'],
                (graph.nodes || []).map((node) => [
                    node.label || node.id || '-',
                    node.type || 'asset',
                    node.display_tier || node.pqc_status || '-',
                    node.ip_address || '-',
                ]),
                'No network nodes available.'
            )}
        `,
        'Topology of discovered assets and their current PQC tiers.'
    ));

    sections.push(reportSection(
        'Cyber Rating and Heatmap',
        `
            ${reportMetricCards([
                { label: 'Enterprise Score', value: cyber.enterprise_score || 0 },
                { label: 'Tier', value: cyber.tier || '-' },
                { label: 'Display Tier', value: cyber.display_tier || cyber.tier_label || '-' },
                { label: 'Negotiation Policies', value: Object.keys(enterprise.negotiation?.policies || {}).length },
            ])}
            ${reportTable(['Posture', 'Crypto Strength', 'Asset Count', 'Host Sample'], heatmapRows, 'No heatmap data available.')}
        `,
        'Summary of enterprise rating and per-cell heatmap distribution.'
    ));

    sections.push(reportSection(
        'Asset Discovery Tables',
        `
            <h3>Domains</h3>
            ${reportTable(['Detection Date', 'Domain', 'Registration Date', 'Registrar', 'Company'], domains.map((item) => [
                item.timestamp || item.detection_date || item.last_seen || '-',
                item.domain_name || '-',
                item.creation_date || item.registration_date || '-',
                item.registrar || '-',
                item.organization || item.company_name || '-',
            ]), 'No domain records available.')}
            <h3>SSL Inventory</h3>
            ${reportTable(['Detection Date', 'Fingerprint', 'Valid From', 'Common Name', 'Company', 'CA'], ssl.map((item) => [
                item.timestamp || item.detection_date || item.last_seen || '-',
                item.ssl_sha_fingerprint || '-',
                item.valid_from || '-',
                item.common_name || '-',
                item.organization || item.company_name || '-',
                item.issuer_common_name || item.certificate_authority || '-',
            ]), 'No SSL records available.')}
            <h3>IP Inventory</h3>
            ${reportTable(['Detection Date', 'IP Address', 'Ports', 'Subnet', 'ASN', 'Location', 'Company'], ipAssets.map((item) => [
                item.timestamp || item.detection_date || item.last_seen || '-',
                item.ip_address || '-',
                Array.isArray(item.ports) ? item.ports.join(', ') : (item.port || '443'),
                item.subnet || '-',
                item.asn || '-',
                item.location || '-',
                item.organization || item.company || '-',
            ]), 'No IP records available.')}
            <h3>Software Inventory</h3>
            ${reportTable(['Detection Date', 'Product', 'Version', 'Type', 'Port', 'Host', 'Company'], software.map((item) => [
                item.timestamp || item.detection_date || item.last_seen || '-',
                item.product || '-',
                item.version || '-',
                item.type || '-',
                item.port || '-',
                item.host || '-',
                item.organization || item.company_name || '-',
            ]), 'No software records available.')}
        `,
        'Detailed asset discovery data mirrored from the overview dashboard.'
    ));

    sections.push(reportSection(
        'Asset Inventory Snapshot',
        reportTable(
            ['Asset', 'Type', 'TLS', 'Cipher Suite', 'Key Exchange', 'Certificate', 'Q-Score', 'Status'],
            inventoryRows.map((row) => [
                `${row.hostname || '?'}:${row.port || 443}`,
                row.assetType || '-',
                row.tlsVersion || '-',
                row.cipherSuite || '-',
                row.keyExchange || '-',
                row.certificate || '-',
                row.score || 0,
                row.status || '-',
            ]),
            'No asset inventory rows available.'
        ),
        'Current asset inventory from the primary scan table.'
    ));

    sections.push(reportSection(
        'PQC Assessment',
        `
            ${reportMetricCards([
                { label: 'Endpoints', value: agg.total_endpoints || 0 },
                { label: 'High Risk', value: agg.risk_high || 0 },
                { label: 'Medium Risk', value: agg.risk_medium || 0 },
                { label: 'Low Risk', value: agg.risk_low || 0 },
                { label: 'HNDL Vulnerable', value: agg.hndl_vulnerable || 0 },
                { label: 'Average Q-Score', value: agg.average_q_score || 0 },
            ])}
            ${reportTable(
                ['Endpoint', 'Risk', 'TLS', 'Key Exchange', 'Certificate', 'Symmetric', 'HNDL', 'Q-Score'],
                assessmentTableRows,
                'No assessment rows available.'
            )}
        `,
        'Endpoint-level PQC assessment and risk analysis.'
    ));

    sections.push(reportSection(
        'Remediation Plan',
        `
            ${reportMetricCards([
                { label: 'Total Remediations', value: remediation.total_remediations || 0 },
                { label: 'P1 Critical', value: remediation.by_priority?.P1_CRITICAL || 0 },
                { label: 'P2 High', value: remediation.by_priority?.P2_HIGH || 0 },
                { label: 'P3 Medium', value: remediation.by_priority?.P3_MEDIUM || 0 },
                { label: 'P4 Low', value: remediation.by_priority?.P4_LOW || 0 },
            ])}
            <h3>Strategic Roadmap</h3>
            ${reportTable(['Phase', 'Priority', 'Category', 'Action', 'Description'], roadmapRows, 'No remediation roadmap available.')}
            <h3>Per-Endpoint Recommendations</h3>
            ${reportTable(['Endpoint', 'Priority', 'Category', 'Action'], remediationEndpointRows, 'No endpoint remediation data available.')}
        `,
        'Prioritized roadmap and endpoint actions from the remediation dashboard.'
    ));

    sections.push(reportSection(
        'NIST Matrix',
        `
            <h3>Quantum-Vulnerable Algorithms</h3>
            ${reportList(nist.vulnerable || [], 'No vulnerable algorithms listed.')}
            <h3>PQC-Safe Algorithms</h3>
            ${reportList(nist.pqc_safe || [], 'No PQC-safe algorithms listed.')}
            <h3>Hybrid Algorithms</h3>
            ${reportList(nist.hybrid || [], 'No hybrid algorithms listed.')}
        `,
        'Algorithm reference matrix shown in the NIST Matrix tab.'
    ));

    sections.push(reportSection(
        'Tri-Mode Probing',
        reportTable(
            ['Asset', 'Type', 'Status', 'Q-Score', 'Probe A', 'Probe B', 'Probe C'],
            trimodeRows,
            'No tri-mode fingerprints available.'
        ),
        'Probe A/B/C results showing PQC-capable, typical, and downgrade handshake behavior.'
    ));

    sections.push(reportSection(
        'Historical Trends',
        reportTable(
            ['Week', 'Date', 'Assets', 'Q-Safety Score', 'Safe', 'Transition', 'Vulnerable', 'Critical', 'Unknown'],
            historyWeeks.map((week) => [
                `Week ${week.week}`,
                week.scan_date ? new Date(week.scan_date).toLocaleDateString() : `Week ${week.week}`,
                week.total_assets || 0,
                week.quantum_safety_score || 0,
                week.fully_quantum_safe || 0,
                week.pqc_transition || 0,
                week.quantum_vulnerable || 0,
                week.critically_vulnerable || 0,
                week.unknown || 0,
            ]),
            'No historical trend data available.'
        ),
        'Weekly posture movement from the history dashboard.'
    ));

    if (phase7Assets.length) {
        sections.push(reportSection(
            'Classification and Agility',
            `
                ${reportMetricCards([
                    { label: 'Classified Assets', value: classifiedData?.total_assets || 0 },
                    { label: 'Average Worst Score', value: classifiedData?.avg_worst_score || 0 },
                    { label: 'Quantum Safe', value: classifiedData?.summary?.fully_quantum_safe || 0 },
                    { label: 'PQC Transition', value: classifiedData?.summary?.pqc_transition || 0 },
                    { label: 'Vulnerable', value: classifiedData?.summary?.quantum_vulnerable || 0 },
                    { label: 'Critical', value: classifiedData?.summary?.critically_vulnerable || 0 },
                ])}
                ${reportTable(['Asset', 'Status', 'Best', 'Typical', 'Worst', 'Agility', 'Action'], phase7AgilityRows, 'No classification rows available.')}
            `,
            'Classification posture and agility assessment from Phase 7.'
        ));
    }

    if (phase9Data) {
        sections.push(reportSection(
            'Regression and Certification',
            `
                ${reportMetricCards([
                    { label: 'Total Assets', value: phase9Data.labels?.total_assets || 0 },
                    { label: 'Quantum Safety Score', value: phase9Data.labels?.quantum_safety_score || 0 },
                    { label: 'Tier 1', value: phase9Data.labels?.tier_1_count || 0 },
                    { label: 'Tier 2', value: phase9Data.labels?.tier_2_count || 0 },
                    { label: 'Tier 3', value: phase9Data.labels?.tier_3_count || 0 },
                    { label: 'Regressions', value: phase9Data.regression?.total_findings || 0 },
                ])}
                <h3>Regression Findings</h3>
                ${reportTable(['Host', 'Port', 'Category', 'Urgency', 'Description', 'Action'], phase9Regressions.map((item) => [
                    item.hostname || '-',
                    item.port || 443,
                    item.category || '-',
                    item.urgency || '-',
                    item.description || '-',
                    item.recommended_action || '-',
                ]), 'No regression findings.')}
                <h3>Issued Labels</h3>
                ${reportTable(['Label ID', 'Host', 'Port', 'Tier', 'Certification', 'Standards', 'Gap', 'Fix'], phase9Labels.map((item) => [
                    item.label_id || '-',
                    item.hostname || '-',
                    item.port || 443,
                    item.tier || '-',
                    item.certification_title || '-',
                    (item.nist_standards || []).join(', ') || '-',
                    item.primary_gap || '-',
                    item.fix_in_days ? `${item.fix_in_days}d` : '-',
                ]), 'No labels issued.')}
                <h3>Attestation Claims</h3>
                ${reportTable(['Standard', 'Title', 'Status', 'Coverage', 'Evidence'], phase9Claims.map((claim) => [
                    claim.id || '-',
                    claim.title || '-',
                    claim.complianceStatus || '-',
                    claim.coverage || '-',
                    claim.evidence || '-',
                ]), 'No attestation claims available.')}
            `,
            'Regression, labeling, and attestation outputs from the certification pipeline.'
        ));
    }

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${escHtml(filename)}</title>
    <style>
        @page {
            size: A4;
            margin: 16mm;
        }
        * {
            box-sizing: border-box;
        }
        body {
            margin: 0;
            color: #1c1c1c;
            font-family: "Segoe UI", Arial, sans-serif;
            background: #ffffff;
        }
        .report {
            max-width: 180mm;
            margin: 0 auto;
        }
        .header {
            border-bottom: 1px solid #d9dde3;
            padding-bottom: 14px;
            margin-bottom: 20px;
        }
        .brand {
            color: #7b0030;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.18em;
            text-transform: uppercase;
            margin-bottom: 12px;
        }
        h1 {
            margin: 0 0 8px;
            font-size: 28px;
            line-height: 1.1;
            font-weight: 700;
        }
        .meta {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 6px 24px;
            color: #5f6368;
            font-size: 12px;
        }
        .section {
            margin: 0 0 22px;
            page-break-inside: avoid;
        }
        .section h2 {
            margin: 0 0 10px;
            font-size: 15px;
            font-weight: 700;
            padding-top: 6px;
            border-top: 2px solid #7b0030;
        }
        .section h3 {
            margin: 14px 0 8px;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            color: #7b0030;
        }
        .section p {
            margin: 0 0 10px;
            color: #5f6368;
            font-size: 12px;
            line-height: 1.5;
        }
        .metrics {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 10px;
            margin-bottom: 12px;
        }
        .metric {
            border: 1px solid #d9dde3;
            background: #fafafa;
            padding: 12px 14px;
            border-radius: 8px;
        }
        .metric-label {
            color: #5f6368;
            font-size: 11px;
            margin-bottom: 4px;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }
        .metric-value {
            font-size: 22px;
            font-weight: 700;
            color: #1c1c1c;
        }
        .highlights {
            margin: 0;
            padding-left: 18px;
        }
        .highlights li {
            margin-bottom: 8px;
            font-size: 13px;
            line-height: 1.5;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
        }
        th, td {
            border: 1px solid #d9dde3;
            padding: 8px 9px;
            text-align: left;
            vertical-align: top;
        }
        th {
            background: #f5f6f8;
            color: #5f6368;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }
        .report-empty {
            border: 1px dashed #d9dde3;
            color: #7b7f85;
            padding: 12px 14px;
            border-radius: 8px;
            font-size: 12px;
            background: #fafafa;
        }
        .graph-shell {
            margin-bottom: 12px;
        }
        .graph-svg {
            width: 100%;
            height: auto;
            display: block;
        }
        .graph-legend {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin-top: 8px;
            color: #5f6368;
            font-size: 12px;
        }
        .footer-note {
            margin-top: 18px;
            color: #7b7f85;
            font-size: 11px;
            border-top: 1px solid #d9dde3;
            padding-top: 10px;
        }
        @media print {
            .print-hint {
                display: none;
            }
        }
    </style>
</head>
<body>
    <div class="report">
        <div class="header">
            <div class="brand">Q-ARMOR</div>
            <h1>Quantum Risk Assessment</h1>
            <div class="meta">
                <div><strong>Organization:</strong> ${escHtml(company)}</div>
                <div><strong>Mode:</strong> ${escHtml(mode)}</div>
                <div><strong>Generated:</strong> ${escHtml(pdfDate(new Date()))}</div>
                <div><strong>Prepared By:</strong> Q-ARMOR Reporting Engine</div>
            </div>
        </div>
        ${sections.join('')}

        <div class="footer-note print-hint">
            If the print dialog does not open automatically, use your browser print action and choose "Save as PDF".
        </div>
    </div>
</body>
</html>`;
}

function openPrintableAssessmentReport(filename) {
    const existing = document.getElementById('qarmorPrintFrame');
    if (existing) existing.remove();

    const frame = document.createElement('iframe');
    frame.id = 'qarmorPrintFrame';
    frame.title = filename;
    frame.style.position = 'fixed';
    frame.style.right = '0';
    frame.style.bottom = '0';
    frame.style.width = '1px';
    frame.style.height = '1px';
    frame.style.opacity = '0';
    frame.style.pointerEvents = 'none';
    frame.style.border = '0';

    document.body.appendChild(frame);

    const doc = frame.contentWindow?.document;
    if (!doc || !frame.contentWindow) {
        frame.remove();
        throw new Error('Unable to create print frame');
    }

    doc.open();
    doc.write(buildPrintableAssessmentHtml(filename));
    doc.close();

    setTimeout(() => {
        try {
            frame.contentWindow.focus();
            frame.contentWindow.print();
        } catch (error) {
            console.error(error);
        }
    }, 300);
}

function buildDirectExportContainer(filename) {
    const existing = document.getElementById('qarmorDirectPdfRoot');
    if (existing) existing.remove();

    const parser = new DOMParser();
    const fullHtml = buildPrintableAssessmentHtml(filename);
    const parsed = parser.parseFromString(fullHtml, 'text/html');
    const root = document.createElement('div');
    root.id = 'qarmorDirectPdfRoot';
    root.style.position = 'absolute';
    root.style.left = '-100000px';
    root.style.top = '0';
    root.style.width = '210mm';
    root.style.background = '#ffffff';
    root.style.zIndex = '-1';

    const styleText = Array.from(parsed.head.querySelectorAll('style'))
        .map((node) => node.textContent || '')
        .join('\n');

    root.innerHTML = `
        <style>${styleText}</style>
        ${parsed.body.innerHTML}
    `;

    document.body.appendChild(root);
    return root;
}

async function tryDirectAssessmentPdfExport(filename) {
    if (typeof window.html2pdf !== 'function') {
        throw new Error('html2pdf is unavailable');
    }

    const container = buildDirectExportContainer(filename);
    try {
        await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
        const worker = window.html2pdf().set({
            margin: [8, 8, 8, 8],
            filename,
            image: { type: 'jpeg', quality: 0.96 },
            html2canvas: {
                scale: 2,
                useCORS: true,
                backgroundColor: '#ffffff',
                logging: false,
                windowWidth: Math.max(container.scrollWidth, 1200),
            },
            pagebreak: {
                mode: ['css', 'legacy'],
                avoid: ['table', 'tr', '.metric', '.graph-shell', '.section'],
            },
            jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' },
        }).from(container).toPdf().get('pdf');

        const pdfBlob = worker.output('blob');
        syncPdfToBackend(pdfBlob, filename);
        worker.save(filename);
    } finally {
        container.remove();
    }
}

/* ─── PDF Assessment Generation ─── */
async function exportAssessment() {
    const btn = document.getElementById('btnExportPDF');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<span class="material-symbols-outlined" style="margin-right:8px; animation: spin 2s linear infinite;">autorenew</span> Generating...';
    btn.disabled = true;

    try {
        const filename = `Q_ARMOR_Assessment_${pdfFilenameTarget()}_${new Date().toISOString().slice(0,10)}.pdf`;
        await ensureReportState();
        try {
            await tryDirectAssessmentPdfExport(filename);
            showToast('Report exported successfully.', 'success');
        } catch (directError) {
            console.error(directError);
            openPrintableAssessmentReport(filename);
            showToast('Direct export failed. Opened the full report in print mode instead.', 'info');
        }

    } catch (e) {
        console.error(e);
        showToast('Report generation failed.', 'error');
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

/* ═══════════════════════════════════════════════════════════════
   ASSET INVENTORY TAB — Full implementation
   ═══════════════════════════════════════════════════════════════ */

const INV_ASSETS_DEFAULT = [
  { name: 'netbanking.pnb.bank.in',  url: 'https://netbanking.pnb.bank.in', ipv4: '103.109.224.11', ipv6: '2001:0db8::0011', type: 'Web App', owner: 'IT',       risk: 'high',     certStatus: 'Valid',    keyLength: '2048-bit', lastScan: '2 hrs ago',  cipher: 'ECDHE-RSA-AES256-GCM-SHA384',    tls: '1.2', ca: 'DigiCert'    },
  { name: 'api.pnb.bank.in',         url: 'https://api.pnb.bank.in',        ipv4: '103.109.224.90', ipv6: '2001:0db8::0090', type: 'API',     owner: 'DevOps',   risk: 'medium',   certStatus: 'Expiring', keyLength: '4096-bit', lastScan: '5 hrs ago',  cipher: 'TLS_AES_256_GCM_SHA384',         tls: '1.3', ca: 'Let\'s Encrypt' },
  { name: 'vpn.pnb.bank.in',         url: 'https://vpn.pnb.bank.in',        ipv4: '103.109.224.21', ipv6: '2001:0db8::0021', type: 'Gateway', owner: 'Infra',    risk: 'critical', certStatus: 'Expired',  keyLength: '1024-bit', lastScan: '1 hr ago',   cipher: 'TLS_RSA_WITH_DES_CBC_SHA',       tls: '1.0', ca: 'COMODO'       },
  { name: 'mobile.pnb.bank.in',      url: 'https://mobile.pnb.bank.in',     ipv4: '103.109.224.10', ipv6: '2001:0db8::0010', type: 'Web App', owner: 'IT',       risk: 'low',      certStatus: 'Valid',    keyLength: '3072-bit', lastScan: '1 day ago',  cipher: 'ECDHE-ECDSA-AES256-GCM-SHA384',  tls: '1.2', ca: 'GlobalSign'  },
  { name: 'portal.pnb.bank.in',      url: 'https://portal.pnb.bank.in',     ipv4: '103.109.224.12', ipv6: '2001:0db8::0012', type: 'Web App', owner: 'IT',       risk: 'medium',   certStatus: 'Valid',    keyLength: '2048-bit', lastScan: '5 days ago', cipher: 'TLS_AES_128_GCM_SHA256',         tls: '1.3', ca: 'DigiCert'    },
  { name: 'gateway.pnb.bank.in',     url: 'https://gateway.pnb.bank.in',    ipv4: '103.109.225.1',  ipv6: '2001:0db8::0001', type: 'Gateway', owner: 'Infra',    risk: 'medium',   certStatus: 'Valid',    keyLength: '4096-bit', lastScan: '3 hrs ago',  cipher: 'ECDHE-RSA-AES256-GCM-SHA384',    tls: '1.3', ca: 'DigiCert'    },
  { name: 'auth.pnb.bank.in',        url: 'https://auth.pnb.bank.in',       ipv4: '103.109.225.2',  ipv6: '2001:0db8::0002', type: 'API',     owner: 'Security', risk: 'low',      certStatus: 'Valid',    keyLength: '4096-bit', lastScan: '6 hrs ago',  cipher: 'ECDHE-ECDSA-AES256-GCM-SHA384',  tls: '1.3', ca: 'Entrust'     },
  { name: 'legacy.pnb.bank.in',      url: 'https://legacy.pnb.bank.in',     ipv4: '40.101.72.212',  ipv6: '',                type: 'Server',  owner: 'IT',       risk: 'critical', certStatus: 'Expired',  keyLength: '1024-bit', lastScan: '2 days ago', cipher: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',  tls: '1.0', ca: 'COMODO'      },
];

// Live assets from a real scan override the defaults; populated by invInit()
let INV_ASSETS = [...INV_ASSETS_DEFAULT];

const INV_GEO = [
  { region: 'USA',       count: 42, lat: 37.09,  lng: -95.71, color: '#7b0030' },
  { region: 'Germany',   count: 18, lat: 51.16,  lng: 10.45,  color: '#7b0030' },
  { region: 'India',     count: 37, lat: 20.59,  lng: 78.96,  color: '#fec800' },
  { region: 'Singapore', count: 11, lat: 1.35,   lng: 103.82, color: '#7b0030' },
];

const INV_NS = [
  { type: 'NS', hostname: 'ns1.pnb.bank.in',       ip: '103.109.224.1',  ipv6: '2001:0db8:pnb:10', ttl: 3600 },
  { type: 'NS', hostname: 'ns2.pnb.bank.in',       ip: '103.109.224.2',  ipv6: '2001:0db8:pnb:11', ttl: 3600 },
  { type: 'NS', hostname: 'ns3.pnb.bank.in',       ip: '103.109.224.3',  ipv6: '2001:0db8:pnb:12', ttl: 3600 },
  { type: 'A',  hostname: 'netbanking.pnb.bank.in', ip: '103.109.224.11', ipv6: '2001:0db8::0011',  ttl: 300  },
  { type: 'MX', hostname: 'mail.pnb.bank.in',       ip: '103.109.224.10', ipv6: '2001:0db8::0010',  ttl: 300  },
];

const INV_ACTIVITY = [
  { type: 'error',   msg: 'Scan completed: 8 assets — 2 critical vulnerabilities found',     time: '10 min ago' },
  { type: 'warning', msg: 'Weak cipher detected: vpn.pnb.bank.in (TLS 1.0 + DES)',          time: '1 hr ago'   },
  { type: 'warning', msg: 'Certificate expiring soon: api.pnb.bank.in (< 30 days)',          time: '3 hrs ago'  },
  { type: 'success', msg: 'New asset discovered: portal.pnb.bank.in',                        time: '5 hrs ago'  },
  { type: 'info',    msg: 'PQC label issued: gateway.pnb.bank.in — Tier 2 (PQC Transition)', time: '6 hrs ago'  },
];

let invFiltered = [...INV_ASSETS];
let invCharts = {};
let invMap = null;

/* ─── switchTab hook: init new tabs when first visited ─── */
const _origSwitchTab = typeof switchTab === 'function' ? switchTab : null;
switchTab = function(tab) {
  if (_origSwitchTab) _origSwitchTab(tab);
  if (tab === 'inventory')    setTimeout(invInit, 100);
  if (tab === 'discovery')    setTimeout(discInit, 150);
  if (tab === 'cyberrating')  setTimeout(crInit, 100);
  if (tab === 'reporting')    setTimeout(repInit, 100);
};

function invInit() {
  const liveData = window.enterpriseDashboardData;
  const liveScan = window.scanData || null;          // set globally in app state

  /* ── 1. INV_ASSETS from enterprise domain/ssl/ip items ── */
  if (liveData) {
    const domainItems = liveData.domains?.items || [];
    const sslItems    = liveData.ssl?.items    || [];
    const ipItems     = liveData.ip?.items     || [];
    if (domainItems.length > 0) {
      const liveAssets = domainItems.map(item => {
        const host     = item.domain_name || item.hostname || item.name || '';
        const matchSsl = sslItems.find(s => s.common_name === host || s.common_name === ('*.' + host.split('.').slice(1).join('.')));
        const matchIp  = ipItems.find(ip => ip.ip_address === item.ip_address);
        return {
          name:       host,
          url:        'https://' + host,
          ipv4:       item.ip_address || item.ip || matchIp?.ip_address || '',
          ipv6:       '',
          type:       item.asset_type === 'api' ? 'API' : item.asset_type === 'vpn' ? 'Gateway' : 'Web App',
          owner:      'IT',
          risk:       item.pqc_status === 'CRITICALLY_VULNERABLE' ? 'critical'
                    : item.pqc_status === 'QUANTUM_VULNERABLE'    ? 'high'
                    : item.pqc_status === 'PQC_TRANSITION'        ? 'medium' : 'low',
          certStatus: item.cert_days_left < 0 ? 'Expired' : item.cert_days_left < 30 ? 'Expiring' : 'Valid',
          keyLength:  item.public_key_bits ? item.public_key_bits + '-bit' : '—',
          lastScan:   item.detection_date || item.scanned_at || 'just now',
          cipher:     item.cipher_suite || matchSsl?.negotiated_cipher || '—',
          tls:        item.tls_version  || '—',
          ca:         item.certificate_authority || item.issuer || matchSsl?.certificate_authority || '—',
          company:    item.company_name || item.company || matchIp?.company || '—',
        };
      }).filter(a => a.name);
      if (liveAssets.length > 0) INV_ASSETS = liveAssets;
    }

    /* ── 2. NAMESERVER RECORDS from ip / domain items ── */
    const ipItems2 = liveData.ip?.items || [];
    if (ipItems2.length > 0) {
      const nsRecords = ipItems2.slice(0, 6).map(item => ({
        type:     item.record_type || 'A',
        hostname: item.hostname || item.domain_name || item.ip_address || '—',
        ip:       item.ip_address || '—',
        ipv6:     item.ipv6_address || '',
        ttl:      item.ttl || 300,
      }));
      invRenderNS(nsRecords);
    } else {
      // fallback: derive NS-style rows from domain items
      const domItems = liveData.domains?.items || [];
      if (domItems.length > 0) {
        const derived = domItems.slice(0, 6).map(d => ({
          type:     'A',
          hostname: d.domain_name || d.hostname || d.name || '—',
          ip:       d.ip_address  || d.ip  || '—',
          ipv6:     '',
          ttl:      300,
        }));
        invRenderNS(derived);
      } else {
        invRenderNS(INV_NS);   // demo fallback
      }
    }

    /* ── 3. GEOGRAPHIC DISTRIBUTION from ip items ── */
    const allIps = liveData.ip?.items || [];
    if (allIps.length > 0) {
      // Group by country/region field; fall back to cloud provider
      const regionMap = {};
      allIps.forEach(ip => {
        const region = ip.country || ip.region || ip.cloud_provider || ip.location || 'Unknown';
        if (!regionMap[region]) regionMap[region] = { count: 0, lat: ip.lat || 20, lng: ip.lng || 80 };
        regionMap[region].count++;
      });
      const palette = ['#7b0030', '#fec800', '#2563eb', '#16a34a', '#7c3aed', '#d97706'];
      const liveGeo = Object.entries(regionMap)
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 6)
        .map(([region, data], i) => ({
          region,
          count: data.count,
          lat:   data.lat,
          lng:   data.lng,
          color: palette[i % palette.length],
        }));
      if (liveGeo.length > 0) {
        invRenderMap(liveGeo);
        invRenderGeo(liveGeo);
      } else {
        invRenderMap(INV_GEO);
        invRenderGeo(INV_GEO);
      }
    } else {
      invRenderMap(INV_GEO);
      invRenderGeo(INV_GEO);
    }
  } else {
    invRenderNS(INV_NS);
    invRenderMap(INV_GEO);
    invRenderGeo(INV_GEO);
  }

  /* ── 4. CRYPTO & SECURITY — always from INV_ASSETS (updated above) ── */
  invFiltered = [...INV_ASSETS];
  invRenderStats();
  invRenderCharts();
  invRenderTable();
  invRenderCrypto();

  /* ── 5. RECENT SCANS & ACTIVITY — built from live scan results ── */
  const liveActivity = _buildActivityFromScan(liveScan, liveData);
  invRenderActivity(liveActivity);
}

/* ── Build activity feed entries from real scan data ── */
function _buildActivityFromScan(scan, enterprise) {
  const events = [];
  const now    = new Date();
  const ago    = mins => mins < 60 ? mins + ' min ago' : Math.round(mins / 60) + ' hr ago';

  if (!scan && !enterprise) return INV_ACTIVITY;  // nothing scanned yet

  // Scan completion summary
  if (scan) {
    const total    = scan.total_assets || 0;
    const critical = scan.critically_vulnerable || 0;
    const vuln     = scan.quantum_vulnerable     || 0;
    const domain   = document.getElementById('domainInput')?.value || '';
    events.push({
      type: critical > 0 ? 'error' : vuln > 0 ? 'warning' : 'success',
      msg:  `Scan complete${domain ? ' — ' + domain : ''}: ${total} asset${total !== 1 ? 's' : ''} · ${critical} critical, ${vuln} vulnerable`,
      time: 'just now',
    });

    // Per-asset findings from scan results
    const results = scan.results || [];
    results.forEach(r => {
      const host   = r.hostname || r.host || '';
      const status = r.q_score?.status || '';
      const tls    = r.tls_version || r.tls?.version || '';
      const cipher = r.cipher_suite || r.tls?.cipher_suite || '';

      if (status === 'CRITICALLY_VULNERABLE') {
        events.push({ type: 'error',   msg: `Critical vulnerability: ${host} — quantum-unsafe key exchange`, time: 'just now' });
      } else if (status === 'QUANTUM_VULNERABLE') {
        events.push({ type: 'warning', msg: `Quantum-vulnerable: ${host} (${cipher || tls || 'legacy cipher'})`, time: 'just now' });
      } else if (status === 'PQC_TRANSITION') {
        events.push({ type: 'info',    msg: `PQC transition detected: ${host} — partial post-quantum support`, time: 'just now' });
      } else if (status === 'FULLY_QUANTUM_SAFE') {
        events.push({ type: 'success', msg: `Quantum-safe asset: ${host} — full PQC key exchange`, time: 'just now' });
      }
      if (tls === '1.0' || tls === '1.1') {
        events.push({ type: 'error',   msg: `Deprecated TLS ${tls} detected: ${host}`, time: 'just now' });
      }
    });

    // Remediation items as activity entries
    const roadmap = scan.remediation_roadmap || [];
    roadmap.slice(0, 3).forEach(item => {
      const priority = (item.priority || '').toLowerCase();
      events.push({
        type: priority === 'critical' ? 'error' : priority === 'high' ? 'warning' : 'info',
        msg:  `Remediation: ${item.action || item.description || item.title || 'Review required'}`,
        time: 'just now',
      });
    });
  }

  // Enterprise-level signals
  if (enterprise) {
    const sslItems = enterprise.ssl?.items || [];
    sslItems.forEach(cert => {
      const host = cert.common_name || cert.hostname || '';
      if (cert.days_until_expiry < 0) {
        events.push({ type: 'error',   msg: `Expired certificate: ${host}`, time: 'just now' });
      } else if (cert.days_until_expiry < 30) {
        events.push({ type: 'warning', msg: `Certificate expiring in ${cert.days_until_expiry}d: ${host}`, time: 'just now' });
      }
    });

    const cyberTier = enterprise.cyber?.tier || enterprise.cyber?.display_tier || '';
    if (cyberTier) {
      events.push({ type: 'info', msg: `Enterprise cyber rating computed: ${cyberTier}`, time: 'just now' });
    }
  }

  // De-duplicate by message prefix and cap at 8 entries
  const seen = new Set();
  return events.filter(e => {
    const key = e.msg.slice(0, 50);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 8);
}

/* ─── Stats (6 cards) ─── */
function invRenderStats() {
  const el = document.getElementById('invStatsGrid');
  if (!el) return;
  const total    = INV_ASSETS.length;
  const webApps  = INV_ASSETS.filter(a => a.type === 'Web App').length;
  const apis     = INV_ASSETS.filter(a => a.type === 'API').length;
  const servers  = INV_ASSETS.filter(a => a.type === 'Server').length;
  const expiring = INV_ASSETS.filter(a => a.certStatus === 'Expiring' || a.certStatus === 'Expired').length;
  const highRisk = INV_ASSETS.filter(a => a.risk === 'critical' || a.risk === 'high').length;

  const card = (label, val, sub, borderColor, valColor = 'var(--text-primary)') =>
    `<div style="background:var(--surface);border-radius:8px;padding:14px 16px;border-left:4px solid ${borderColor};box-shadow:0 1px 4px rgba(0,0,0,0.06);">
       <div style="font-size:0.58rem;font-weight:800;text-transform:uppercase;letter-spacing:0.12em;color:var(--text-secondary);margin-bottom:4px;">${label}</div>
       <div style="font-size:1.6rem;font-weight:900;color:${valColor};line-height:1;">${val}</div>
       <div style="font-size:0.62rem;color:var(--text-secondary);margin-top:2px;">${sub}</div>
     </div>`;

  el.innerHTML =
    card('Total Assets',         total,    'Monitored',        'var(--primary)') +
    card('Public Web Apps',      webApps,  'Internet-facing',  '#2563eb') +
    card('APIs',                 apis,     'Endpoints',        '#7c3aed') +
    card('Servers',              servers,  'Infrastructure',   '#0891b2') +
    card('Expiring Certs',       expiring, 'Action required',  '#d97706', '#d97706') +
    card('High Risk Assets',     highRisk, 'Critical/High',    '#dc2626', '#dc2626');
}

/* ─── Charts ─── */
function invRenderCharts() {
  const brandRed  = '#7b0030';
  const brandGold = '#fec800';
  const colors4   = [brandRed, '#dc2626', '#d97706', '#16a34a'];
  const colorsRisk = ['#dc2626', '#ea580c', '#d97706', '#16a34a'];

  function makeChart(id, type, labels, data, colors, opts = {}) {
    const canvas = document.getElementById(id);
    if (!canvas) return;
    if (invCharts[id]) { invCharts[id].destroy(); }
    invCharts[id] = new Chart(canvas, {
      type,
      data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: type === 'bar' ? 0 : 2, borderColor: '#fff', borderRadius: type === 'bar' ? 4 : 0 }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom', labels: { font: { size: 9, weight: '700' }, padding: 8, boxWidth: 10 } } },
        scales: type === 'bar' ? { y: { beginAtZero: true, ticks: { font: { size: 9 } }, grid: { color: 'rgba(0,0,0,0.05)' } }, x: { ticks: { font: { size: 9 } }, grid: { display: false } } } : {},
        ...opts,
      }
    });
  }

  const typeCounts = ['Web App', 'API', 'Server', 'Gateway'].map(t => INV_ASSETS.filter(a => a.type === t).length);
  makeChart('invChartAssetType', 'doughnut', ['Web Apps', 'APIs', 'Servers', 'Gateways'], typeCounts, [brandRed, '#dc2626', '#d97706', '#2563eb']);

  const riskCounts = ['critical', 'high', 'medium', 'low'].map(r => INV_ASSETS.filter(a => a.risk === r).length);
  makeChart('invChartRisk', 'bar', ['Critical', 'High', 'Medium', 'Low'], riskCounts, colorsRisk);

  makeChart('invChartCertExpiry', 'bar', ['0–30d', '30–60d', '60–90d', '>90d'], [3, 4, 2, 84], ['#dc2626', '#d97706', '#ca8a04', '#16a34a']);

  const ipv6Count = INV_ASSETS.filter(a => a.ipv6 && a.ipv6.length > 0).length;
  makeChart('invChartIPVersion', 'doughnut', ['IPv4 only', 'IPv6 enabled'], [INV_ASSETS.length - ipv6Count, ipv6Count], [brandRed, brandGold]);
}

/* ─── Table ─── */
function invApplyFilters() {
  const q    = (document.getElementById('invSearch')?.value || '').toLowerCase();
  const type = document.getElementById('invFilterType')?.value || '';
  const risk = document.getElementById('invFilterRisk')?.value || '';
  invFiltered = INV_ASSETS.filter(a => {
    const mq = !q || a.name.toLowerCase().includes(q) || a.ipv4.includes(q) || a.type.toLowerCase().includes(q);
    const mt = !type || a.type === type;
    const mr = !risk || a.risk === risk;
    return mq && mt && mr;
  });
  invRenderTable();
}

function invRenderTable() {
  const tbody = document.getElementById('invAssetTableBody');
  if (!tbody) return;
  if (!invFiltered.length) {
    tbody.innerHTML = `<tr><td colspan="10" style="padding:24px;text-align:center;color:var(--text-secondary);font-size:0.8rem;">No assets match your filters.</td></tr>`;
    return;
  }
  const riskBadge = r => {
    const cfg = { critical: ['#dc2626','#fef2f2'], high: ['#ea580c','#fff7ed'], medium: ['#d97706','#fffbeb'], low: ['#16a34a','#f0fdf4'] };
    const [fg, bg] = cfg[r] || ['#666','#f5f5f5'];
    return `<span style="background:${bg};color:${fg};font-size:0.58rem;font-weight:800;padding:2px 8px;border-radius:999px;text-transform:uppercase;letter-spacing:0.06em;">${r}</span>`;
  };
  const certBadge = s => {
    const cfg = { Valid: ['#16a34a','check_circle'], Expiring: ['#d97706','warning'], Expired: ['#dc2626','error'] };
    const [color, icon] = cfg[s] || ['#666','help'];
    return `<span style="color:${color};font-size:0.7rem;display:inline-flex;align-items:center;gap:3px;font-weight:700;"><span class="material-symbols-outlined" style="font-size:13px;">${icon}</span>${s}</span>`;
  };
  const keyBadge = k => {
    const bits = parseInt(k);
    const color = bits >= 4096 ? '#16a34a' : bits >= 2048 ? '#d97706' : '#dc2626';
    return `<span style="background:${color}18;color:${color};font-size:0.62rem;font-weight:800;padding:1px 6px;border-radius:4px;font-family:monospace;">${k}</span>`;
  };
  tbody.innerHTML = invFiltered.map(a => `
    <tr style="border-bottom:1px solid var(--border);transition:background 0.15s;" onmouseover="this.style.background='var(--surface)'" onmouseout="this.style.background=''">
      <td style="padding:10px 12px;font-weight:700;color:var(--primary);white-space:nowrap;max-width:180px;overflow:hidden;text-overflow:ellipsis;" title="${a.name}">${a.name}</td>
      <td style="padding:10px 12px;font-size:0.7rem;color:#2563eb;white-space:nowrap;"><a href="${a.url}" target="_blank" style="color:#2563eb;text-decoration:none;">${a.url.replace('https://','')}</a></td>
      <td style="padding:10px 12px;font-family:monospace;font-size:0.72rem;white-space:nowrap;">${a.ipv4}</td>
      <td style="padding:10px 12px;font-family:monospace;font-size:0.68rem;color:var(--text-secondary);white-space:nowrap;max-width:140px;overflow:hidden;text-overflow:ellipsis;" title="${a.ipv6}">${a.ipv6 || '<span style="color:var(--text-secondary);opacity:0.5;">—</span>'}</td>
      <td style="padding:10px 12px;font-size:0.75rem;white-space:nowrap;">${a.type}</td>
      <td style="padding:10px 12px;font-size:0.75rem;white-space:nowrap;">${a.owner}</td>
      <td style="padding:10px 12px;white-space:nowrap;">${riskBadge(a.risk)}</td>
      <td style="padding:10px 12px;white-space:nowrap;">${certBadge(a.certStatus)}</td>
      <td style="padding:10px 12px;white-space:nowrap;">${keyBadge(a.keyLength)}</td>
      <td style="padding:10px 12px;font-size:0.72rem;color:var(--text-secondary);white-space:nowrap;">${a.lastScan}</td>
    </tr>`).join('');
}

/* ─── Nameserver Records ─── */
function invRenderNS(records) {
  const el = document.getElementById('invNSRecords');
  if (!el) return;
  el.innerHTML = records.map(r => `
    <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 10px;background:var(--surface);border-radius:6px;border:1px solid var(--border);">
      <div>
        <div style="font-size:0.6rem;font-weight:800;text-transform:uppercase;color:var(--text-secondary);">${r.type}</div>
        <div style="font-size:0.72rem;font-family:monospace;font-weight:600;color:var(--text-primary);">${r.hostname}</div>
        <div style="font-size:0.62rem;color:var(--text-secondary);">${r.ip} · TTL ${r.ttl}</div>
      </div>
      <span class="material-symbols-outlined" style="font-size:14px;color:#16a34a;">check_circle</span>
    </div>`).join('');
}

async function invResolveDomain() {
  const domain = document.getElementById('invDomainResolve')?.value.trim();
  if (!domain) return;
  invRenderNS([
    { type: 'A',  hostname: domain,        ip: '34.12.11.45', ipv6: '', ttl: 300 },
    { type: 'NS', hostname: 'ns1.'+domain, ip: '192.0.2.10',  ipv6: '', ttl: 3600 },
  ]);
}

/* ─── Crypto Overview ─── */
function invRenderCrypto() {
  const tbody = document.getElementById('invCryptoBody');
  if (!tbody) return;
  const keyColor = k => { const b = parseInt(k); return b >= 4096 ? '#16a34a' : b >= 2048 ? '#d97706' : '#dc2626'; };
  const cipherWeak = c => c.includes('3DES') || c.includes('DES') || c.includes('RC4');
  tbody.innerHTML = INV_ASSETS.slice(0, 5).map(a => `
    <tr style="border-bottom:1px solid var(--border);">
      <td style="padding:5px 8px;font-size:0.68rem;font-weight:700;color:var(--primary);white-space:nowrap;max-width:100px;overflow:hidden;text-overflow:ellipsis;" title="${a.name}">${a.name.split('.')[0]}</td>
      <td style="padding:5px 8px;"><span style="background:${keyColor(a.keyLength)}18;color:${keyColor(a.keyLength)};font-size:0.6rem;font-weight:800;padding:1px 5px;border-radius:3px;font-family:monospace;">${a.keyLength}</span></td>
      <td style="padding:5px 8px;font-size:0.62rem;font-family:monospace;color:${cipherWeak(a.cipher) ? '#dc2626' : 'var(--text-primary)'};font-weight:${cipherWeak(a.cipher) ? '800' : '400'};max-width:120px;overflow:hidden;text-overflow:ellipsis;" title="${a.cipher}">${a.cipher.substring(0,18)}…</td>
      <td style="padding:5px 8px;font-size:0.68rem;font-weight:700;">${a.tls}</td>
      <td style="padding:5px 8px;font-size:0.68rem;color:var(--text-secondary);">${a.ca}</td>
    </tr>`).join('');
}

/* ─── Leaflet Map ─── */
function invRenderMap(geoData) {
  const data = geoData || INV_GEO;
  const el = document.getElementById('invLeafletMap');
  if (!el || typeof L === 'undefined') return;
  if (invMap) { invMap.remove(); invMap = null; }
  invMap = L.map('invLeafletMap', { zoomControl: false, attributionControl: false }).setView([20, 20], 1);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 10 }).addTo(invMap);
  data.forEach(g => {
    const icon = L.divIcon({
      className: '',
      html: `<div style="background:${g.color};width:12px;height:12px;border-radius:50%;border:2px solid #fff;box-shadow:0 0 0 3px ${g.color}44;"></div>`,
      iconSize: [12, 12], iconAnchor: [6, 6]
    });
    L.marker([g.lat, g.lng], { icon })
      .bindPopup(`<strong>${g.region}</strong><br/>${g.count} assets`, { maxWidth: 120 })
      .addTo(invMap);
  });
}

/* ─── Geo Stats ─── */
function invRenderGeo(geoData) {
  const data = geoData || INV_GEO;
  const el = document.getElementById('invGeoStats');
  if (!el) return;
  el.innerHTML = data.map(g =>
    `<div style="text-align:center;">
       <div style="font-size:0.58rem;font-weight:800;text-transform:uppercase;color:var(--text-secondary);">${g.region}</div>
       <div style="font-size:0.9rem;font-weight:900;color:var(--primary);">${g.count}</div>
     </div>`).join('');
}

/* ─── Activity Feed ─── */
function invRenderActivity(activityData) {
  const data = activityData || INV_ACTIVITY;
  const el = document.getElementById('invActivityFeed');
  if (!el) return;
  const cfg = {
    success: { color:'#16a34a', bg:'#f0fdf4', icon:'check_circle' },
    error:   { color:'#dc2626', bg:'#fef2f2', icon:'error' },
    warning: { color:'#d97706', bg:'#fffbeb', icon:'warning' },
    info:    { color:'#2563eb', bg:'#eff6ff', icon:'info' },
  };
  if (!data.length) {
    el.innerHTML = `<div style="color:var(--text-secondary);font-size:0.78rem;padding:12px 0;">No activity yet — run a scan to populate this feed.</div>`;
    return;
  }
  el.innerHTML = data.map(a => {
    const c = cfg[a.type] || cfg.info;
    return `<div style="display:flex;gap:10px;padding:10px 12px;background:${c.bg};border-left:3px solid ${c.color};border-radius:6px;">
      <span class="material-symbols-outlined" style="font-size:15px;color:${c.color};margin-top:1px;">${c.icon}</span>
      <div style="flex:1;">
        <div style="font-size:0.78rem;font-weight:600;color:var(--text-primary);">${a.msg}</div>
        <div style="font-size:0.65rem;color:var(--text-secondary);margin-top:2px;">${a.time}</div>
      </div>
    </div>`;
  }).join('');
}

/* ─── Scan All / Export ─── */
function invScanAll() {
  if (typeof showToast === 'function') showToast('Scanning all assets…', 'info');
  setTimeout(() => {
    invRenderActivity();
    if (typeof showToast === 'function') showToast('Scan complete — ' + INV_ASSETS.length + ' assets analyzed', 'success');
  }, 1500);
}

function invExportCSV() {
  const headers = ['Asset Name','URL','IPv4','IPv6','Type','Owner','Risk','Cert Status','Key Length','Last Scan'];
  const rows = INV_ASSETS.map(a => [a.name, a.url, a.ipv4, a.ipv6, a.type, a.owner, a.risk, a.certStatus, a.keyLength, a.lastScan]);
  const csv = [headers, ...rows].map(r => r.map(c => `"${c}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url; link.download = 'asset-inventory.csv'; link.click();
  URL.revokeObjectURL(url);
  if (typeof showToast === 'function') showToast('CSV exported', 'success');
}

/* ═══════════════════════════════════════════════════════════════
   ASSET DISCOVERY TAB — Phase 3
   ═══════════════════════════════════════════════════════════════ */

const DISC_DEMO = {
  domains: [
    { detectionDate:'2026-03-10', domain:'www.cos.pnb.bank.in',    registrationDate:'2019-04-12', registrar:'NIXI', company:'PNB',  status:'Confirmed' },
    { detectionDate:'2026-03-11', domain:'proxy.pnb.bank.in',      registrationDate:'2020-08-01', registrar:'NIXI', company:'PNB',  status:'Confirmed' },
    { detectionDate:'2026-03-15', domain:'ibps.pnb.bank.in',       registrationDate:'2021-02-14', registrar:'NIXI', company:'PNB',  status:'New'       },
    { detectionDate:'2026-03-18', domain:'netbanking.pnb.bank.in', registrationDate:'2018-11-03', registrar:'NIXI', company:'PNB',  status:'Confirmed' },
    { detectionDate:'2026-03-20', domain:'api.pnb.bank.in',        registrationDate:'2022-06-20', registrar:'NIXI', company:'PNB',  status:'New'       },
    { detectionDate:'2026-03-22', domain:'cdn.pnb.bank.in',        registrationDate:'2020-01-09', registrar:'NIXI', company:'PNB',  status:'FP'        },
    { detectionDate:'2026-03-25', domain:'mobile.pnb.bank.in',     registrationDate:'2023-03-30', registrar:'NIXI', company:'PNB',  status:'New'       },
  ],
  ssl: [
    { detectionDate:'2026-03-10', fingerprint:'A1:B2:C3:D4:E5', validFrom:'2025-01-01', commonName:'*.pnb.bank.in',    company:'PNB', ca:'DigiCert',    status:'Confirmed' },
    { detectionDate:'2026-03-12', fingerprint:'F6:G7:H8:I9:J0', validFrom:'2025-06-15', commonName:'api.pnb.bank.in',  company:'PNB', ca:'Let\'s Encrypt', status:'New'    },
    { detectionDate:'2026-03-14', fingerprint:'K1:L2:M3:N4:O5', validFrom:'2024-03-20', commonName:'legacy.pnb.bank.in',company:'PNB',ca:'COMODO',       status:'FP'        },
    { detectionDate:'2026-03-16', fingerprint:'P6:Q7:R8:S9:T0', validFrom:'2025-09-01', commonName:'netbanking.pnb',    company:'PNB', ca:'Entrust',     status:'Confirmed' },
    { detectionDate:'2026-03-20', fingerprint:'U1:V2:W3:X4:Y5', validFrom:'2026-01-10', commonName:'mobile.pnb.bank.in',company:'PNB',ca:'DigiCert',     status:'New'       },
  ],
  ip: [
    { detectionDate:'2026-03-10', ip:'103.107.224.11', ports:'443,80,22', subnet:'103.107.224.0/24', asn:'AS9829', netname:'BSNL-NIB',   location:'Mumbai, IN',    company:'PNB',  status:'Confirmed' },
    { detectionDate:'2026-03-11', ip:'103.107.224.29', ports:'443,8443',  subnet:'103.107.224.0/24', asn:'AS9829', netname:'BSNL-NIB',   location:'Delhi, IN',     company:'PNB',  status:'Confirmed' },
    { detectionDate:'2026-03-15', ip:'40.101.72.212',  ports:'443,80',    subnet:'40.101.72.0/24',   asn:'AS8075', netname:'MSFT-GFS',   location:'Virginia, USA', company:'Azure',status:'New'       },
    { detectionDate:'2026-03-18', ip:'34.12.11.45',    ports:'443',       subnet:'34.12.0.0/16',     asn:'AS15169',netname:'GOOGLE',      location:'Iowa, USA',     company:'GCP',  status:'New'       },
    { detectionDate:'2026-03-22', ip:'35.11.44.10',    ports:'25,587,993',subnet:'35.11.0.0/16',     asn:'AS15169',netname:'GOOGLE',      location:'Oregon, USA',   company:'GCP',  status:'FP'        },
  ],
  software: [
    { detectionDate:'2026-03-10', product:'Apache httpd',   version:'2.4.51', type:'Web Server', port:80,   host:'103.107.224.11', company:'PNB',  status:'Confirmed' },
    { detectionDate:'2026-03-12', product:'OpenSSL',        version:'1.1.1t', type:'Crypto Lib', port:443,  host:'103.107.224.29', company:'PNB',  status:'Confirmed' },
    { detectionDate:'2026-03-14', product:'nginx',          version:'1.18.0', type:'Web Server', port:80,   host:'40.101.72.212',  company:'Azure',status:'New'       },
    { detectionDate:'2026-03-16', product:'OpenSSH',        version:'7.4',    type:'SSH Server', port:22,   host:'103.107.224.11', company:'PNB',  status:'New'       },
    { detectionDate:'2026-03-18', product:'MySQL',          version:'5.7.39', type:'Database',   port:3306, host:'34.12.11.45',    company:'GCP',  status:'FP'        },
    { detectionDate:'2026-03-20', product:'Spring Boot',    version:'2.7.9',  type:'Framework',  port:8080, host:'103.107.224.29', company:'PNB',  status:'New'       },
  ],
};

let discCurrentTab = 'domains';
let discCurrentFilter = 'All';
let discVisNet = null;

function discInit() {
  // Try to use live data if available; normalize field names to match the table renderer
  const live = window.adState?.data;
  if (live) {
    const today = new Date().toISOString().slice(0,10);
    if (live.domains?.length) {
      DISC_DEMO.domains = live.domains.map(d => ({
        detectionDate:    d.detection_date || today,
        domain:           d.domain_name || d.hostname || d.domain || d.name || '',
        registrationDate: d.registration_date || '—',
        registrar:        d.registrar || 'Live DNS/CT Discovery',
        company:          d.company_name || d.company || '—',
        status:           d.pqc_status === 'CRITICALLY_VULNERABLE' ? 'FP'
                        : d.pqc_status === 'PQC_TRANSITION'        ? 'Confirmed' : 'New',
        // preserve original fields for other uses
        ...d,
      }));
    }
    if (live.ssl?.length) {
      DISC_DEMO.ssl = live.ssl.map(d => ({
        detectionDate: d.detection_date || today,
        fingerprint:   d.ssl_sha_fingerprint || d.serial_number || '—',
        validFrom:     d.valid_from || d.not_before || '—',
        commonName:    d.common_name || d.hostname || d.subject || '',
        company:       d.company_name || d.company || '—',
        ca:            d.certificate_authority || d.issuer || '—',
        status:        d.cert_days_left < 0 ? 'FP' : d.cert_days_left < 30 ? 'New' : 'Confirmed',
        ...d,
      }));
    }
    if (live.ip?.length) {
      DISC_DEMO.ip = live.ip.map(d => ({
        detectionDate: d.detection_date || today,
        ip:            d.ip_address || d.ip || '',
        ports:         Array.isArray(d.ports) ? d.ports.join(',') : (d.ports || '443'),
        subnet:        d.subnet || '—',
        asn:           d.asn || '—',
        netname:       d.cloud_display_name || d.netname || '—',
        location:      d.location || (d.pool === 'cloud' ? (d.cloud_display_name || 'Cloud') : 'On-Premises'),
        company:       d.company || d.company_name || (d.pool === 'cloud' ? (d.cloud_display_name || 'Cloud') : '—'),
        status:        'Confirmed',
        ...d,
      }));
    }
    if (live.software?.length) {
      DISC_DEMO.software = live.software.map(d => ({
        detectionDate: d.detection_date || today,
        product:       d.product || d.name || '—',
        version:       d.version || d.tls_version || '—',
        type:          d.type    || 'TLS Stack',
        port:          d.port || 443,
        host:          d.host || d.hostname || '—',
        company:       d.company_name || d.company || '—',
        status:        'Confirmed',
        ...d,
      }));
    }
  }
  discRenderStats();
  discUpdateCounts();
  discRenderTable();
  discRenderNetwork();
}

function discRenderStats() {
  const el = document.getElementById('discStatsGrid');
  if (!el) return;
  const total = DISC_DEMO.domains.length + DISC_DEMO.ssl.length + DISC_DEMO.ip.length + DISC_DEMO.software.length;
  const cards = [
    { label:'Total Discovered', value: total,                    color:'var(--primary)' },
    { label:'Domains',          value: DISC_DEMO.domains.length,  color:'#16a34a' },
    { label:'SSL Certs',        value: DISC_DEMO.ssl.length,      color:'#2563eb' },
    { label:'IPs / Subnets',    value: DISC_DEMO.ip.length,       color:'#0891b2' },
  ];
  el.innerHTML = cards.map(c => `
    <div class="card" style="padding:16px;text-align:center;">
      <div style="font-size:1.8rem;font-weight:900;color:${c.color};">${c.value}</div>
      <div style="font-size:0.62rem;font-weight:700;text-transform:uppercase;color:var(--text-secondary);margin-top:4px;">${c.label}</div>
    </div>`).join('');
}

function discUpdateCounts() {
  ['domains','ssl','ip','software'].forEach(k => {
    const el = document.getElementById(`discTabCount-${k}`);
    if (el) el.textContent = (DISC_DEMO[k] || []).length;
  });
}

function discSwitchTab(tab) {
  discCurrentTab = tab;
  discCurrentFilter = 'All';
  document.querySelectorAll('.disc-subtab').forEach(b => b.classList.remove('disc-subtab--active'));
  const btn = document.getElementById(`discTab-${tab}`);
  if (btn) btn.classList.add('disc-subtab--active');
  document.querySelectorAll('.disc-filter').forEach(b => b.classList.remove('disc-filter--active'));
  const fb = document.getElementById('discFilter-All');
  if (fb) fb.classList.add('disc-filter--active');
  discRenderTable();
}

function discSetFilter(filter) {
  discCurrentFilter = filter;
  document.querySelectorAll('.disc-filter').forEach(b => b.classList.remove('disc-filter--active'));
  const fb = document.getElementById(`discFilter-${filter}`);
  if (fb) fb.classList.add('disc-filter--active');
  discRenderTable();
}

function discApplyFilters() { discRenderTable(); }

function discGetFiltered() {
  const search = (document.getElementById('discSearch')?.value || '').toLowerCase();
  const from   = document.getElementById('discDateFrom')?.value || '';
  const to     = document.getElementById('discDateTo')?.value   || '';
  let data = DISC_DEMO[discCurrentTab] || [];
  if (discCurrentFilter !== 'All') data = data.filter(r => r.status === discCurrentFilter);
  if (search) data = data.filter(r => JSON.stringify(r).toLowerCase().includes(search));
  if (from)   data = data.filter(r => (r.detectionDate || '') >= from);
  if (to)     data = data.filter(r => (r.detectionDate || '') <= to);
  return data;
}

const DISC_STATUS_COLORS = { New:'#2563eb', Confirmed:'#16a34a', FP:'#6b7280' };
function discStatusBadge(s) {
  const c = DISC_STATUS_COLORS[s] || '#6b7280';
  return `<span style="background:${c}18;color:${c};padding:2px 7px;border-radius:4px;font-size:0.65rem;font-weight:700;">${s}</span>`;
}

function discRenderTable() {
  const wrap = document.getElementById('discTableWrap');
  if (!wrap) return;
  const data = discGetFiltered();
  if (!data.length) {
    wrap.innerHTML = `<div style="padding:32px;text-align:center;color:var(--text-secondary);font-size:0.82rem;">No records match the current filter.</div>`;
    return;
  }

  let headers = [], rows = '';
  if (discCurrentTab === 'domains') {
    headers = ['Detection Date','Domain Name','Registration Date','Registrar','Company','Status'];
    rows = data.map(r => `<tr>
      <td style="padding:8px 12px;font-size:0.72rem;color:var(--text-secondary);">${r.detectionDate}</td>
      <td style="padding:8px 12px;font-weight:600;color:var(--primary);">${r.domain}</td>
      <td style="padding:8px 12px;font-size:0.72rem;">${r.registrationDate}</td>
      <td style="padding:8px 12px;font-size:0.72rem;">${r.registrar}</td>
      <td style="padding:8px 12px;font-size:0.72rem;">${r.company}</td>
      <td style="padding:8px 12px;">${discStatusBadge(r.status)}</td>
    </tr>`).join('');
  } else if (discCurrentTab === 'ssl') {
    headers = ['Detection Date','Fingerprint','Valid From','Common Name','Company','CA','Status'];
    rows = data.map(r => `<tr>
      <td style="padding:8px 12px;font-size:0.72rem;color:var(--text-secondary);">${r.detectionDate}</td>
      <td style="padding:8px 12px;font-family:monospace;font-size:0.68rem;">${r.fingerprint}</td>
      <td style="padding:8px 12px;font-size:0.72rem;">${r.validFrom}</td>
      <td style="padding:8px 12px;font-weight:600;color:var(--primary);">${r.commonName}</td>
      <td style="padding:8px 12px;font-size:0.72rem;">${r.company}</td>
      <td style="padding:8px 12px;font-size:0.72rem;">${r.ca}</td>
      <td style="padding:8px 12px;">${discStatusBadge(r.status)}</td>
    </tr>`).join('');
  } else if (discCurrentTab === 'ip') {
    headers = ['Detection Date','IP Address','Ports','Subnet','ASN','Netname','Location','Status'];
    rows = data.map(r => `<tr>
      <td style="padding:8px 12px;font-size:0.72rem;color:var(--text-secondary);">${r.detectionDate}</td>
      <td style="padding:8px 12px;font-family:monospace;font-weight:600;">${r.ip}</td>
      <td style="padding:8px 12px;font-family:monospace;font-size:0.68rem;">${r.ports}</td>
      <td style="padding:8px 12px;font-family:monospace;font-size:0.68rem;">${r.subnet}</td>
      <td style="padding:8px 12px;font-size:0.68rem;">${r.asn}</td>
      <td style="padding:8px 12px;font-size:0.68rem;">${r.netname}</td>
      <td style="padding:8px 12px;font-size:0.72rem;">${r.location}</td>
      <td style="padding:8px 12px;">${discStatusBadge(r.status)}</td>
    </tr>`).join('');
  } else {
    headers = ['Detection Date','Product','Version','Type','Port','Host','Company','Status'];
    rows = data.map(r => `<tr>
      <td style="padding:8px 12px;font-size:0.72rem;color:var(--text-secondary);">${r.detectionDate}</td>
      <td style="padding:8px 12px;font-weight:600;">${r.product}</td>
      <td style="padding:8px 12px;font-family:monospace;font-size:0.68rem;">${r.version}</td>
      <td style="padding:8px 12px;font-size:0.72rem;">${r.type}</td>
      <td style="padding:8px 12px;font-family:monospace;font-size:0.72rem;">${r.port}</td>
      <td style="padding:8px 12px;font-family:monospace;font-size:0.68rem;">${r.host}</td>
      <td style="padding:8px 12px;font-size:0.72rem;">${r.company}</td>
      <td style="padding:8px 12px;">${discStatusBadge(r.status)}</td>
    </tr>`).join('');
  }

  wrap.innerHTML = `<table style="width:100%;border-collapse:collapse;font-size:0.78rem;">
    <thead><tr style="border-bottom:2px solid var(--border);background:var(--surface);">
      ${headers.map(h => `<th style="padding:8px 12px;text-align:left;font-size:0.6rem;font-weight:800;text-transform:uppercase;letter-spacing:0.08em;color:var(--text-secondary);white-space:nowrap;">${h}</th>`).join('')}
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function discRenderNetwork() {
  const rawNodes = window.enterpriseDashboardData?.graph?.nodes || [];
  const rawEdges = window.enterpriseDashboardData?.graph?.edges || [];
  if (!rawNodes.length) {
    // Build a simple network from disc demo data
    const demoNodes = [
      ...DISC_DEMO.domains.slice(0,5).map((d,i) => ({ id:`d${i}`, label:(d.domain||d.hostname||'').split('.')[0], type:'domain', display_tier:'Standard' })),
      ...DISC_DEMO.ip.slice(0,4).map((d,i) => ({ id:`ip${i}`, label:d.ip, type:'ip', display_tier:'PQC_TRANSITION' })),
      ...DISC_DEMO.ssl.slice(0,3).map((d,i) => ({ id:`ssl${i}`, label:(d.commonName||d.hostname||'').substring(0,12), type:'ssl', display_tier:'Confirmed' })),
    ];
    const demoEdges = demoNodes.slice(1).map((n,i) => ({ source: demoNodes[0].id, target: n.id }));
    discVisNet = buildVisNetwork('discNetworkGraph', demoNodes, demoEdges);
  } else {
    discVisNet = buildVisNetwork('discNetworkGraph', rawNodes, rawEdges);
  }
}

/* ═══════════════════════════════════════════════════════════════
   CYBER RATING TAB — Phase 6
   ═══════════════════════════════════════════════════════════════ */

const CR_DEMO_URLS = [
  { url:'netbanking.pnb.bank.in',  score:820, tier:'Elite-PQC'  },
  { url:'auth.pnb.bank.in',        score:780, tier:'Elite-PQC'  },
  { url:'api.pnb.bank.in',         score:640, tier:'Standard'   },
  { url:'gateway.pnb.bank.in',     score:590, tier:'Standard'   },
  { url:'portal.pnb.bank.in',      score:480, tier:'Standard'   },
  { url:'mail.pnb.bank.in',        score:370, tier:'Legacy'      },
  { url:'cdn.pnb.bank.in',         score:310, tier:'Legacy'      },
  { url:'legacy.pnb.bank.in',      score:120, tier:'Critical'    },
  { url:'vpn.pnb.bank.in',         score:95,  tier:'Critical'    },
];

const CR_TIER_COLORS = { 'Elite-PQC':'#16a34a', 'Standard':'#0891b2', 'Legacy':'#d97706', 'Critical':'#dc2626' };

function crInit() {
  // Try to use live cyber data
  const live = window.enterpriseDashboardData?.cyber;
  let score = 0, tier = 'Standard', urls = CR_DEMO_URLS;
  if (live) {
    score = live.enterprise_score || live.score || 0;
    tier  = live.display_tier || live.tier || 'Standard';
    if (live.url_scores && live.url_scores.length) {
      urls = live.url_scores.map(u => ({ url: u.url || u.host, score: u.score || u.pqc_score || 0, tier: u.display_tier || u.tier || 'Standard' }));
    }
  } else {
    score = Math.round(urls.reduce((s,u) => s + u.score, 0) / urls.length);
  }
  crRenderScore(score, tier);
  crRenderCounts(urls);
  crRenderUrlTable(urls);
}

function crTierColor(t) { return CR_TIER_COLORS[t] || '#6b7280'; }

function crRenderScore(score, tier) {
  const el = document.getElementById('crScore');
  const badge = document.getElementById('crTierBadge');
  if (el) el.textContent = score || '—';
  if (badge) {
    const c = crTierColor(tier);
    badge.textContent = tier;
    badge.style.cssText = `background:${c}18;color:${c};padding:4px 14px;border-radius:999px;font-size:0.72rem;font-weight:700;`;
  }
}

function crRenderCounts(urls) {
  const counts = { 'Elite-PQC':0, 'Standard':0, 'Legacy':0, 'Critical':0 };
  urls.forEach(u => { if (counts[u.tier] !== undefined) counts[u.tier]++; });
  const ids = { 'Elite-PQC':'crTier1Count', 'Standard':'crTier2Count', 'Legacy':'crTier3Count', 'Critical':'crCritCount' };
  Object.entries(ids).forEach(([tier, id]) => {
    const el = document.getElementById(id);
    if (el) el.textContent = counts[tier];
  });
}

function crRenderUrlTable(urls) {
  const tbody = document.getElementById('crUrlTable');
  if (!tbody) return;
  const sorted = [...urls].sort((a,b) => b.score - a.score);
  tbody.innerHTML = sorted.map(u => {
    const c = crTierColor(u.tier);
    const pct = Math.min(100, Math.round(u.score / 10));
    return `<tr style="border-bottom:1px solid var(--border);">
      <td style="padding:8px 10px;font-size:0.75rem;font-weight:500;">${u.url}</td>
      <td style="padding:8px 10px;text-align:right;">
        <div style="display:flex;align-items:center;gap:8px;justify-content:flex-end;">
          <div style="flex:1;height:6px;background:var(--border);border-radius:3px;min-width:60px;">
            <div style="height:6px;width:${pct}%;background:${c};border-radius:3px;"></div>
          </div>
          <span style="font-weight:700;font-size:0.82rem;">${u.score}</span>
        </div>
      </td>
      <td style="padding:8px 10px;text-align:center;"><span style="background:${c}18;color:${c};padding:2px 8px;border-radius:4px;font-size:0.65rem;font-weight:700;">${u.tier}</span></td>
      <td style="padding:8px 10px;text-align:center;font-size:1.1rem;color:${u.tier === 'Elite-PQC' ? '#16a34a' : '#dc2626'};">${u.tier === 'Elite-PQC' ? '✓' : '✗'}</td>
    </tr>`;
  }).join('');
}

/* ═══════════════════════════════════════════════════════════════
   REPORTING TAB — Phase 7
   ═══════════════════════════════════════════════════════════════ */

function repInit() {
  // Populate exec preview with live data if available
  repUpdateExecPreview();
}

function repSelectType(type) {
  ['scheduled','ondemand','executive'].forEach(t => {
    const card = document.getElementById(`repCard-${t}`);
    const form = document.getElementById(`repForm-${t}`);
    if (card) card.style.borderColor = t === type ? 'var(--primary)' : 'transparent';
    if (form) form.style.display = t === type ? 'block' : 'none';
  });
}

function repSchedule() {
  const type  = document.getElementById('repSchedType')?.value || 'Executive Summary';
  const freq  = document.getElementById('repSchedFreq')?.value || 'Weekly';
  const email = document.getElementById('repSchedEmail')?.value || '';
  const date  = document.getElementById('repSchedDate')?.value || '';
  if (!email) { if (typeof showToast === 'function') showToast('Please enter a delivery email', 'error'); return; }
  if (typeof showToast === 'function') showToast(`"${type}" report scheduled ${freq.toLowerCase()}${date ? ' from ' + date : ''}. Delivery to ${email}`, 'success');
}

function repGenerateOnDemand() {
  const type   = document.getElementById('repOdType')?.value   || 'Executive';
  const format = document.getElementById('repOdFormat')?.value || 'PDF';
  const email  = document.getElementById('repOdEmail')?.value  || '';

  if (typeof showToast === 'function') showToast(`Generating ${type} report as ${format}…`, 'info');

  const data = window.enterpriseDashboardData || {};
  const home = data.home || {};
  const cyber = data.cyber || {};
  const domains = (data.domains?.items || []);
  const ssl = (data.ssl?.items || []);
  const ip = (data.ip?.items || []);
  const software = (data.software?.items || []);

  const ts = new Date().toISOString().slice(0, 10);
  const safeName = type.replace(/\s+/g, '_');
  const filename = `Q_ARMOR_${safeName}_Report_${ts}`;

  if (format === 'JSON') {
    const payload = { generated: new Date().toISOString(), type, home, cyber, domains, ssl, ip, software };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    _triggerDownload(blob, filename + '.json');
    if (typeof showToast === 'function') showToast(`${type} JSON report downloaded.`, 'success');
    return;
  }

  if (format === 'CSV') {
    const rows = [['Type', 'Name/Host', 'Detection Date', 'Status', 'Company']];
    domains.forEach(d => rows.push(['Domain', d.domain_name || '', d.detection_date || '', d.pqc_status || '', d.company_name || '']));
    ssl.forEach(d => rows.push(['SSL', d.common_name || '', d.detection_date || '', d.certificate_authority || '', d.company_name || '']));
    ip.forEach(d => rows.push(['IP', d.ip_address || '', d.detection_date || '', d.cloud_display_name || d.pool || '', d.company || '']));
    software.forEach(d => rows.push(['Software', (d.product || '') + ' ' + (d.version || ''), d.detection_date || '', d.pqc_status || '', d.company_name || '']));
    const csv = rows.map(r => r.map(v => '"' + String(v).replace(/"/g, '""') + '"').join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    _triggerDownload(blob, filename + '.csv');
    if (typeof showToast === 'function') showToast(`${type} CSV report downloaded.`, 'success');
    return;
  }

  // PDF — use the same export path as Executive Report
  if (typeof exportAssessment === 'function') {
    exportAssessment();
  } else {
    const fname = filename + '.pdf';
    try {
      openPrintableAssessmentReport(fname);
      if (typeof showToast === 'function') showToast(`${type} PDF report ready — use browser print dialog to save.`, 'success');
    } catch (e) {
      if (typeof showToast === 'function') showToast('PDF export failed: ' + e.message, 'error');
    }
  }
}

function _triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function repGenerateExec() {
  if (typeof exportAssessment === 'function') {
    exportAssessment();
  } else {
    if (typeof showToast === 'function') showToast('Run a scan first to generate an executive report.', 'info');
  }
}

function _updateOverviewCards_Cyber(cyber) {
    const score = cyber.enterprise_score ?? cyber.score ?? 0;
    setTextSafe('ovCyberScore', score || '—');

    // Tier counts from url_scores array if available
    const urls = cyber.url_scores || cyber.assets || [];
    const counts = { 'Elite-PQC': 0, 'Standard': 0, 'Legacy': 0, 'Critical': 0 };
    urls.forEach(u => {
        const t = u.display_tier || u.tier || '';
        if (counts[t] !== undefined) counts[t]++;
    });

    const tierLabels = { 'Elite-PQC': 'Elite', 'Standard': 'Std', 'Legacy': 'Legacy', 'Critical': 'Critical' };
    const tierMap    = { 'Elite-PQC': 'ovEliteCt', 'Standard': 'ovStdCt', 'Legacy': 'ovLegacyCt', 'Critical': 'ovCritCt' };
    Object.entries(tierMap).forEach(([tier, id]) => {
        const el = document.getElementById(id);
        if (el) el.textContent = counts[tier] ? `${counts[tier]} ${tierLabels[tier]}` : tierLabels[tier];
    });
}

function repUpdateExecPreview() {
  const el = document.getElementById('repExecPreview');
  if (!el) return;
  const cyber = window.enterpriseDashboardData?.cyber;
  const home  = window.enterpriseDashboardData?.home;
  const score = cyber?.enterprise_score || cyber?.score || '—';
  const tier  = cyber?.display_tier || cyber?.tier || '—';
  const domains = home?.asset_discovery_summary?.domain_count ?? home?.domain_count ?? '—';
  const pqcPct  = home?.posture_of_pqc?.pqc_adoption_pct ?? home?.pqc_adoption_pct ?? '—';
  el.innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px;">
      <div style="padding:12px;border:1px solid var(--border);border-radius:6px;">
        <div style="font-size:0.62rem;text-transform:uppercase;color:var(--text-secondary);font-weight:700;margin-bottom:4px;">Enterprise Score</div>
        <div style="font-size:1.4rem;font-weight:900;color:var(--primary);">${score}<span style="font-size:0.8rem;font-weight:400;color:var(--text-secondary);"> / 1000</span></div>
        <div style="font-size:0.72rem;color:var(--text-secondary);margin-top:2px;">Tier: ${tier}</div>
      </div>
      <div style="padding:12px;border:1px solid var(--border);border-radius:6px;">
        <div style="font-size:0.62rem;text-transform:uppercase;color:var(--text-secondary);font-weight:700;margin-bottom:4px;">Assets</div>
        <div style="font-size:1.4rem;font-weight:900;color:#0891b2;">${domains}</div>
        <div style="font-size:0.72rem;color:var(--text-secondary);margin-top:2px;">Domains scanned</div>
      </div>
    </div>
    <p style="font-size:0.82rem;color:var(--text-secondary);">PQC Adoption: <strong>${pqcPct}${typeof pqcPct === 'number' ? '%' : ''}</strong>. Click "Export Executive Report" to generate a full PDF with charts, findings, and remediation roadmap.</p>
  `;
}
