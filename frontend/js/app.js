/**
 * Q-ARMOR Dashboard Controller
 * Discovery and overview
 * PQC assessment, remediation, and NIST matrix
 * Tri-mode probing, history, and baseline
 * PQC classification + agility assessment + SQLite DB
 * Regression detection + CycloneDX 1.7 CBOM
 * PQC labeling + registry + FIPS attestation
 */

const API_BASE = '';

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
        ${type === 'error' ? 'background: rgba(255,71,87,0.15); color: #ff4757; border: 1px solid rgba(255,71,87,0.3);' : ''}
        ${type === 'success' ? 'background: rgba(0,255,136,0.15); color: #00ff88; border: 1px solid rgba(0,255,136,0.3);' : ''}
        ${type === 'info' ? 'background: rgba(0,212,255,0.15); color: #00d4ff; border: 1px solid rgba(0,212,255,0.3);' : ''}
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
let phase9Data = null;
let enterpriseDashboardData = null;

/* ─── API Calls ─── */
async function apiCall(endpoint, method = 'GET') {
    const resp = await fetch(`${API_BASE}${endpoint}`, { method });
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

    const assetSamples = document.getElementById('assetSamples');
    if (assetSamples) {
        const domainSample = domainItems.slice(0, 2).map(d => escHtml(d.domain_name || '—')).join(', ');
        const sslSample = sslItems.slice(0, 2).map(s => escHtml(s.common_name || s.ssl_sha_fingerprint || '—')).join(', ');
        const ipSample = ipItems.slice(0, 2).map(x => escHtml(x.ip_address || '—')).join(', ');
        const swSample = softwareItems.slice(0, 2).map(w => escHtml(`${w.product || '—'} ${w.version || ''}`.trim())).join(', ');

        assetSamples.innerHTML = `
            <div><strong>Domains:</strong> ${domainSample || '—'}</div>
            <div><strong>SSL:</strong> ${sslSample || '—'}</div>
            <div><strong>IP:</strong> ${ipSample || '—'}</div>
            <div><strong>Software:</strong> ${swSample || '—'}</div>
        `;
    }
}

function renderCyberPqcV2(cyber, heatmap, negotiation) {
    setTextSafe('cyberEnterpriseScore', formatCount(cyber.enterprise_score));
    setTextSafe('cyberTier', cyber.tier || '—');
    setTextSafe('cyberDisplayTier', cyber.display_tier || cyber.tier_label || '—');

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
    showLoading('Refreshing enterprise data APIs...');
    try {
        await loadEnterpriseDashboardData({ notifyOnError: true, forceRefresh: true });
        showToast('Enterprise dashboard APIs refreshed', 'success');
    } finally {
        hideLoading();
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

function showLoading(msg = 'Scanning cryptographic surface...') {
    const overlay = document.getElementById('loadingOverlay');
    overlay.querySelector('.loading-text').textContent = msg;
    overlay.classList.add('active');
}

function hideLoading() {
    document.getElementById('loadingOverlay').classList.remove('active');
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
        renderDashboard(scanData);
        document.getElementById('btnExportCBOM').disabled = false;
        const cdxaBtn = document.getElementById('btnExportCDXA');
        if (cdxaBtn) cdxaBtn.disabled = false;
        showToast(`Scan complete — ${scanData.total_assets} assets analyzed`, 'success');

        // Auto-fetch Phase 2 assessment
        fetchPhase2Assessment();

        // Auto-fetch Phase 6 tri-mode demo data
        fetchTrimodeDemoData();

        // Refresh new API-backed enterprise dashboard
        await loadEnterpriseDashboardData();
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
    showLoading(`Discovering assets for ${domain}...`);
    try {
        scanData = await apiCall(`/api/scan/domain/${encodeURIComponent(domain)}`, 'POST');
        renderDashboard(scanData);
        document.getElementById('btnExportCBOM').disabled = false;
        fetchPhase2Assessment();
        try {
            trimodeData = await apiCall('/api/scan/trimode/fingerprints');
            trimodeData.mode = 'live';
            trimodeData.total_assets = trimodeData.total || trimodeData.fingerprints?.length || 0;
            renderTrimode(trimodeData);
        } catch (trimodeError) {
            console.warn('Tri-mode refresh failed:', trimodeError);
        }
        await loadEnterpriseDashboardData();
        await syncOverviewWithLatestScan(true);
    } catch (e) {
        showToast('Scan failed: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
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
        renderDashboard(scanData);
        fetchPhase2Assessment();
        await loadEnterpriseDashboardData();
    } catch (e) {
        showToast('Probe failed: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

/* ─── CBOM Export ─── */
async function exportCBOM() {
    try {
        const resp = await fetch(`${API_BASE}/api/cbom/phase3/download`);
        if (!resp.ok) throw new Error(`HTTP Error ${resp.status}`);
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'qarmor-cbom.json';
        a.click();
        URL.revokeObjectURL(url);
        showToast('CBOM exported successfully', 'success');
    } catch (e) {
        showToast('Export failed: ' + e.message, 'error');
    }
}

/* ─── CDXA Export ─── */
async function exportCDXA() {
    try {
        const resp = await fetch(`${API_BASE}/api/attestation/download`);
        if (!resp.ok) throw new Error(`HTTP Error ${resp.status}`);
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'qarmor-attestation-cdxa.json';
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
        'COMPLIANT': { bg: 'rgba(0, 255, 136, 0.12)', color: '#00ff88' },
        'PARTIAL': { bg: 'rgba(0, 212, 255, 0.12)', color: '#00d4ff' },
        'NON_COMPLIANT': { bg: 'rgba(255, 71, 87, 0.12)', color: '#ff4757' },
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
        signedEl.style.color = data.signed ? '#a855f7' : '#ff4757';
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
        countBadge.style.color = '#00ff88';
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
    fetchPhase5Data();
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

function renderAssetTable(results) {
    const container = document.getElementById('assetTableContainer');
    document.getElementById('assetCount').textContent = `${results.length} assets`;

    if (!results.length) {
        container.innerHTML = `<div class="empty-state"><div class="empty-state-icon">🔍</div><div class="empty-state-title">No assets found</div></div>`;
        return;
    }

    const sorted = [...results].map(normalizeInventoryEntry).sort((a, b) => a.score - b.score);

    let html = `<table class="asset-table"><thead><tr>
        <th>Asset</th><th>Type</th><th>TLS</th><th>Cipher Suite</th><th>Key Exchange</th><th>Certificate</th><th>Q-Score</th><th>Status</th>
    </tr></thead><tbody>`;

    for (const row of sorted) {
        const statusClass = getStatusClass(row.status);
        const statusLabel = getStatusLabel(row.status);
        const scoreColor = getScoreColor(row.score || 0);

        html += `<tr>
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
        container.innerHTML = `<div class="empty-state"><div class="empty-state-icon">📋</div><div class="empty-state-title">No remediation needed</div></div>`;
        return;
    }

    const priorityMap = { 'P1_IMMEDIATE': 'P1', 'P2_SHORT_TERM': 'P2', 'P3_MEDIUM_TERM': 'P3', 'P4_STRATEGIC': 'P4' };
    const priorityLabel = { 'P1': 'Priority 1 — Immediate', 'P2': 'Priority 2 — Short Term', 'P3': 'Priority 3 — Medium Term', 'P4': 'Priority 4 — Strategic' };

    let html = '<div class="remediation-timeline">';
    for (const item of roadmap) {
        const p = priorityMap[item.priority] || 'P4';
        html += `
            <div class="remediation-item remediation-item--${p}">
                <div class="remediation-priority">${priorityLabel[p] || item.priority}</div>
                <div class="remediation-desc">${item.description}</div>
                <div class="remediation-timeframe">⏱ ${item.timeframe} · ${(item.affected_assets || []).length} asset(s)</div>
                <ul class="remediation-actions">
                    ${(item.specific_actions || []).map(a => `<li>${a}</li>`).join('')}
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
        <div class="label-card">
            <div class="label-header">Post-Quantum Cryptography Ready</div>
            <div class="label-asset">${l.asset}</div>
            <div class="label-detail">Algorithms: ${(l.algorithms || []).join(', ')}</div>
            <div class="label-detail">Standards: ${(l.standards || []).join(', ')}</div>
            <div class="label-detail">Valid until: ${l.valid_until}</div>
            <div class="label-id">${l.label_id}</div>
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
        1: { cls: 'cert-label--safe',     icon: '✅', borderColor: 'rgba(0, 255, 136, 0.3)', bg: 'rgba(0, 255, 136, 0.06)' },
        2: { cls: 'cert-label--ready',    icon: '🔶', borderColor: 'rgba(0, 212, 255, 0.3)', bg: 'rgba(0, 212, 255, 0.06)' },
        3: { cls: 'cert-label--noncompliant', icon: '❌', borderColor: 'rgba(255, 71, 87, 0.3)', bg: 'rgba(255, 71, 87, 0.06)' },
    };

    container.innerHTML = labels.map(l => {
        const cfg = tierConfig[l.tier] || tierConfig[3];
        return `<div class="label-card ${cfg.cls}" style="border-color: ${cfg.borderColor}; background: ${cfg.bg};">
            <div class="label-header" style="color: ${l.tier === 1 ? 'var(--accent-green)' : l.tier === 2 ? 'var(--accent-cyan)' : 'var(--accent-red)'}">
                ${cfg.icon} ${l.label}
            </div>
            <div class="label-asset">${l.target}:${l.port}</div>
            <div class="label-detail">TLS: ${l.tls_version || '—'} · KEX: ${l.key_exchange || '—'}</div>
            <div class="label-detail">Cert: ${l.certificate || '—'} · Risk: ${l.risk || '—'}</div>
            <div class="label-detail" style="margin-top: 4px; font-size: 0.68rem; color: var(--text-dim);">${l.reason}</div>
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
        { label: 'Vulnerable', value: agg.kex_vulnerable || 0, color: '#ff4757' },
        { label: 'Hybrid PQC', value: agg.kex_hybrid || 0, color: '#00d4ff' },
        { label: 'PQC Safe', value: agg.kex_pqc_safe || 0, color: '#00ff88' },
    ]);

    drawDonutChart('chartTLS', 'legendTLS', [
        { label: 'TLS Pass', value: agg.tls_pass || 0, color: '#00ff88' },
        { label: 'TLS Fail', value: agg.tls_fail || 0, color: '#ff4757' },
    ]);

    drawDonutChart('chartRisk', 'legendRisk', [
        { label: 'High Risk', value: agg.risk_high || 0, color: '#ff4757' },
        { label: 'Medium Risk', value: agg.risk_medium || 0, color: '#ffb300' },
        { label: 'Low Risk', value: agg.risk_low || 0, color: '#00ff88' },
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

    // Build tri-mode table
    const tbody = fps.map(fp => {
        const st = fp.q_score?.status || 'UNKNOWN';
        const cls = getStatusClass(st);
        const lbl = getStatusLabel(st);
        const score = fp.q_score?.total ?? '—';
        const scColor = getScoreColor(score);

        function probeCell(p) {
            if (!p) return '<span class="probe-err">—</span>';
            if (p.error) return `<span class="probe-err">${escHtml(p.error)}</span>`;
            const tls = p.tls_version || '—';
            const kex = p.key_exchange || '—';
            const cipher = p.cipher_suite || '—';
            const bits = p.cipher_bits ? `${p.cipher_bits}b` : '';

            let colorClass = 'probe-warn';
            if (tls.includes('1.3') && (kex.includes('ML-KEM') || kex.includes('MLKEM'))) colorClass = 'probe-ok';
            else if (tls.includes('1.1') || tls.includes('1.0') || kex === 'RSA') colorClass = 'probe-bad';

            return `<span class="${colorClass}">${tls} | ${kex} | ${bits}</span>`;
        }

        return `<tr>
            <td><strong>${escHtml(fp.hostname)}</strong><br><span style="color:var(--text-dim);font-size:0.7rem">${fp.asset_type || 'web'} :${fp.port}</span></td>
            <td><span class="status-badge status-badge--${cls}">${lbl}</span></td>
            <td style="color:${scColor}; font-weight:600;">${score}</td>
            <td class="probe-cell"><span class="probe-label">A</span> ${probeCell(fp.probe_a)}</td>
            <td class="probe-cell"><span class="probe-label">B</span> ${probeCell(fp.probe_b)}</td>
            <td class="probe-cell"><span class="probe-label">C</span> ${probeCell(fp.probe_c)}</td>
        </tr>`;
    }).join('');

    const container = document.getElementById('trimodeTableContainer');
    if (container) {
        container.innerHTML = `
            <table class="trimode-table">
                <thead><tr>
                    <th>Asset</th><th>Status</th><th>Q-Score</th>
                    <th>Probe A (PQC)</th><th>Probe B (TLS 1.3)</th><th>Probe C (Downgrade)</th>
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


/* ═══════════════════════════════════════════════════════════════════════════
   Phase 6: Historical Trends & Baseline
   ═══════════════════════════════════════════════════════════════════════════ */

async function loadHistory() {
    try {
        const [histResp, baseResp] = await Promise.all([
            apiCall('/api/scan/trimode/history'),
            apiCall('/api/scan/trimode/baseline'),
        ]);

        historyData = histResp;
        renderHistory(histResp);
        renderBaseline(baseResp);

        document.getElementById('historyEmpty').style.display = 'none';
        document.getElementById('historyContent').style.display = '';
    } catch (e) {
        showToast('Failed to load history: ' + e.message, 'error');
    }
}

async function loadLiveHistory() {
    showLoading('Loading scan history from database...');
    try {
        const scans = await apiCall('/api/db/scans?limit=50');
        if (!scans || !scans.length) {
            showToast('No scans in database yet — run a live scan first', 'info');
            hideLoading();
            return;
        }

        // Build weekly-style trend data from DB scans
        const weeks = scans.slice(0, 10).reverse().map((s, i) => ({
            week: i + 1,
            scan_date: s.scan_date,
            total_assets: s.total_assets || 0,
            quantum_safety_score: Math.round(100 - (s.avg_score || 50)),
            fully_quantum_safe: s.fully_safe || 0,
            pqc_transition: s.pqc_trans || 0,
            quantum_vulnerable: s.q_vuln || 0,
            critically_vulnerable: s.crit_vuln || 0,
            unknown: s.unknown || 0,
        }));

        const histData = { mode: 'live (DB)', weeks };
        historyData = histData;
        renderHistory(histData);

        // Show the latest scan results as baseline comparison
        const latest = scans[0];
        const previous = scans.length >= 2 ? scans[1] : null;
        renderLiveBaseline(latest, previous);

        document.getElementById('historyEmpty').style.display = 'none';
        document.getElementById('historyContent').style.display = '';
        showToast(`Loaded ${scans.length} scans from database`, 'success');
    } catch (e) {
        showToast('Failed to load DB history: ' + e.message, 'error');
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
            : `<span style="color:#ff4757;font-weight:600;">${val}</span>`;
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

function renderHistory(data) {
    if (!data || !data.weeks) return;
    const modeEl = document.getElementById('historyMode');
    if (modeEl) modeEl.textContent = data.mode || 'live';

    const maxScore = Math.max(...data.weeks.map(w => w.quantum_safety_score), 1);
    const rows = data.weeks.map(w => {
        const barW = Math.round((w.quantum_safety_score / 100) * 200);
        const date = w.scan_date ? new Date(w.scan_date).toLocaleDateString() : `Week ${w.week}`;
        return `<tr>
            <td>Week ${w.week}</td>
            <td>${date}</td>
            <td>${w.total_assets}</td>
            <td style="font-weight:600;color:var(--accent-green);">${w.quantum_safety_score} <span class="score-bar" style="width:${barW}px;"></span></td>
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
                    <th>Week</th><th>Date</th><th>Assets</th><th>Q-Safety Score</th>
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
        showToast(`Classified ${data.total_assets} assets (scan #${data.scan_id})`, 'success');
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
        showToast(`Classified ${data.total_assets} live assets for ${domain} (scan #${data.scan_id})`, 'success');
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

        html += `<tr>
            <td><span class="asset-hostname">${escHtml(a.hostname)}:${a.port}</span></td>
            <td><span class="asset-type">${a.asset_type || 'web'}</span></td>
            <td><span class="status-badge status-badge--${cls}">${lbl}</span></td>
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
        const scans = await apiCall('/api/db/scans?limit=20');
        dbScansData = scans;
        renderDbScans(scans);
    } catch (e) {
        console.warn('Failed to load DB scans:', e);
    }
}

function renderDbScans(scans) {
    const container = document.getElementById('p7DbScansContainer');
    if (!scans || !scans.length) {
        container.innerHTML = '<div class="empty-state"><div class="empty-state-desc">No scans stored yet</div></div>';
        return;
    }

    let html = `<table class="asset-table"><thead><tr>
        <th>ID</th><th>Date</th><th>Mode</th><th>Domain</th><th>Assets</th><th>Avg Score</th>
        <th>Safe</th><th>Trans</th><th>Vuln</th><th>Crit</th><th>Actions</th>
    </tr></thead><tbody>`;

    for (const s of scans) {
        const date = s.scan_date ? new Date(s.scan_date).toLocaleString() : '—';
        html += `<tr>
            <td style="font-weight:600;">#${s.id}</td>
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
                <button class="btn" style="font-size:0.7rem;padding:2px 8px;" onclick="viewScan(${s.id})">View</button>
                ${scans.length >= 2 ? `<button class="btn" style="font-size:0.7rem;padding:2px 8px;margin-left:4px;" onclick="compareScanPick(${s.id})">Compare</button>` : ''}
            </td>
        </tr>`;
    }

    html += '</tbody></table>';
    container.innerHTML = html;
}

async function viewScan(scanId) {
    showLoading(`Loading scan #${scanId}...`);
    try {
        const scan = await apiCall(`/api/db/scans/${scanId}`);
        if (scan.results_json) {
            try {
                const assets = JSON.parse(scan.results_json);
                renderP7Table(assets);
                renderP7Agility(assets);
            } catch { /* ignore parse failure */ }
        }
        showToast(`Loaded scan #${scanId}`, 'info');
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
    await compareTwoScans(scanId, other.id);
}

async function compareTwoScans(a, b) {
    showLoading(`Comparing scan #${a} vs #${b}...`);
    try {
        const delta = await apiCall(`/api/db/compare/${a}/${b}`);
        renderScanComparison(delta, a, b);
        showToast(`Comparison ready: scan #${a} vs #${b}`, 'success');
    } catch (e) {
        showToast('Comparison failed: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

function renderScanComparison(delta, idA, idB) {
    const container = document.getElementById('p7DbScansContainer');
    const a = delta.scan_a || {};
    const b = delta.scan_b || {};
    const d = delta.delta || {};

    function diffBadge(val) {
        if (val > 0) return `<span style="color:var(--accent-green);font-weight:600;">+${val}</span>`;
        if (val < 0) return `<span style="color:var(--accent-pink);font-weight:600;">${val}</span>`;
        return `<span style="color:var(--text-dim);">0</span>`;
    }

    container.innerHTML = `
        <div style="margin-bottom:12px;display:flex;align-items:center;gap:12px;">
            <strong style="color:var(--text-primary);">Scan #${idA} vs #${idB}</strong>
            <button class="btn" style="font-size:0.7rem;padding:2px 8px;" onclick="loadDbScans()">← Back to list</button>
        </div>
        <table class="asset-table"><thead><tr>
            <th>Metric</th><th>Scan #${idA}</th><th>Scan #${idB}</th><th>Delta</th>
        </tr></thead><tbody>
            <tr><td>Total Assets</td><td>${a.total_assets || 0}</td><td>${b.total_assets || 0}</td><td>${diffBadge(d.total_assets || 0)}</td></tr>
            <tr><td>Avg Score</td><td>${a.avg_score || 0}</td><td>${b.avg_score || 0}</td><td>${diffBadge(d.avg_score || 0)}</td></tr>
            <tr><td style="color:var(--status-safe)">Fully Safe</td><td>${a.fully_safe || 0}</td><td>${b.fully_safe || 0}</td><td>${diffBadge(d.fully_safe || 0)}</td></tr>
            <tr><td style="color:var(--status-transition)">PQC Transition</td><td>${a.pqc_trans || 0}</td><td>${b.pqc_trans || 0}</td><td>${diffBadge(d.pqc_trans || 0)}</td></tr>
            <tr><td style="color:var(--status-vulnerable)">Vulnerable</td><td>${a.q_vuln || 0}</td><td>${b.q_vuln || 0}</td><td>${diffBadge(d.q_vuln || 0)}</td></tr>
            <tr><td style="color:var(--status-critical)">Critical</td><td>${a.crit_vuln || 0}</td><td>${b.crit_vuln || 0}</td><td>${diffBadge(d.crit_vuln || 0)}</td></tr>
        </tbody></table>
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
        overallComp === 'PARTIALLY_COMPLIANT' ? '#ffaa00' : '#ff4757';

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
        const urgColor = r.urgency === 'HIGH' ? '#ff4757' : r.urgency === 'MEDIUM' ? '#ffaa00' : 'var(--text-dim)';
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
        const tierColor = l.tier === 1 ? 'var(--accent-green)' : l.tier === 2 ? 'var(--accent-cyan)' : '#ff4757';
        const tierName = l.tier === 1 ? 'Tier 1' : l.tier === 2 ? 'Tier 2' : 'Tier 3';
        html += `<tr>
            <td style="font-family:monospace;font-size:0.72rem;">${l.label_id || ''}</td>
            <td>${l.hostname || ''}</td>
            <td>${l.port || 443}</td>
            <td><span style="color:${tierColor};font-weight:700;">${tierName}</span></td>
            <td>${l.certification_title || ''}</td>
            <td><span style="display:inline-block;padding:2px 8px;border-radius:4px;background:${l.badge_color || '#333'};color:#fff;font-size:0.72rem;">${l.badge_icon || ''}</span></td>
            <td style="font-size:0.72rem;">${(l.nist_standards || []).join(', ')}</td>
            <td style="color:#ffaa00;font-size:0.75rem;">${l.primary_gap || '—'}</td>
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
            <div><strong style="color:${revocations > 0 ? '#ff4757' : 'var(--text-dim)'};">${revocations}</strong> auto-revocations triggered</div>
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
    badge.textContent = overallComp;
    badge.style.background = overallComp === 'COMPLIANT' ? 'rgba(0,255,136,0.12)' :
        overallComp === 'PARTIALLY_COMPLIANT' ? 'rgba(255,170,0,0.12)' : 'rgba(255,71,87,0.12)';
    badge.style.color = overallComp === 'COMPLIANT' ? 'var(--accent-green)' :
        overallComp === 'PARTIALLY_COMPLIANT' ? '#ffaa00' : '#ff4757';

    const decls = attestFull?.attestation?.declarations || {};
    const claims = decls.claims || [];

    let claimsHtml = '';
    for (const c of claims) {
        const statusColor = c.complianceStatus === 'COMPLIANT' ? 'var(--accent-green)' :
            c.complianceStatus === 'PARTIALLY_COMPLIANT' ? '#ffaa00' :
            c.complianceStatus === 'NOT_APPLICABLE' ? 'var(--text-dim)' : '#ff4757';
        claimsHtml += `<tr>
            <td style="font-weight:600;">${c.id || ''}</td>
            <td style="max-width:240px;">${c.title || ''}</td>
            <td><span style="color:${statusColor};font-weight:700;">${c.complianceStatus || ''}</span></td>
            <td>${c.coverage || ''}</td>
            <td style="font-size:0.75rem;color:var(--text-secondary);">${c.evidence || ''}</td>
        </tr>`;
    }

    container.innerHTML = `
        <div style="display:flex;gap:24px;margin-bottom:12px;font-size:0.82rem;">
            <div><strong>Serial:</strong> <code style="font-size:0.72rem;">${summary.serialNumber || ''}</code></div>
            <div><strong>Signed:</strong> <span style="color:${summary.signed ? 'var(--accent-green)' : '#ff4757'};">${summary.signed ? 'Ed25519 ✓' : 'No'}</span></div>
            <div><strong>Valid Until:</strong> ${summary.validUntil ? new Date(summary.validUntil).toLocaleDateString() : '—'}</div>
            <div><strong>Q-Safety:</strong> <span style="color:var(--accent-cyan);font-weight:700;">${summary.quantumSafetyScore || 0}/100</span></div>
            <div><strong>Mode:</strong> <span style="color:#ffaa00;">${summary.dataMode || 'live'}</span></div>
        </div>
        <table class="asset-table"><thead><tr>
            <th>FIPS Standard</th><th>Title</th><th>Status</th><th>Coverage</th><th>Evidence</th>
        </tr></thead><tbody>${claimsHtml}</tbody></table>
    `;
}

async function downloadPhase9CBOM() {
    try {
        const resp = await fetch(`${API_BASE}/api/phase9/cbom/download`);
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
        const resp = await fetch(`${API_BASE}/api/attestation/v2/download`);
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
    const raw = asset?.display_tier || asset?.pqc_status || asset?.status || asset || '';
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
    return Number(
        asset?.worst_case_score
        ?? asset?.worst_score
        ?? asset?.q_score
        ?? asset?.q_score?.total
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

async function fetchCbomLatest(forceRefresh = false) {
    if (!forceRefresh && latestCbomPayload) return latestCbomPayload;
    latestCbomPayload = await apiCall(buildContextEndpoint('/api/cbom/latest', forceRefresh));
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
    drawNet();
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

function renderNetworkGraphSection(graphPayload) {
    const mount = document.getElementById('networkVizMount');
    if (!mount) return;
    const nodes = Array.isArray(graphPayload.nodes) ? graphPayload.nodes : [];
    const edges = Array.isArray(graphPayload.edges) ? graphPayload.edges : [];

    if (!nodes.length) {
        mount.innerHTML = `${bannerHtml(graphPayload)}<div class="viz-state"><div class="viz-state-content"><div class="viz-state-title">No network data</div><div class="viz-state-copy">Run or refresh the enterprise pipeline to map related assets.</div></div></div>`;
        return;
    }

    mount.innerHTML = `
        ${bannerHtml(graphPayload)}
        <div id="graphControls" style="display:flex;align-items:center;gap:0.75rem;flex-wrap:wrap;margin-bottom:0.75rem">
            <span style="font-size:0.8rem;color:var(--text-secondary)">Filter:</span>
            <button class="graph-filter-btn active" data-filter="all" onclick="graphFilter('all', this)">All</button>
            <button class="graph-filter-btn" data-filter="elite" onclick="graphFilter('elite', this)">Elite-PQC</button>
            <button class="graph-filter-btn" data-filter="standard" onclick="graphFilter('standard', this)">Standard</button>
            <button class="graph-filter-btn" data-filter="vulnerable" onclick="graphFilter('vulnerable', this)">Vulnerable</button>
            <button class="graph-view-toggle" id="graphViewToggleBtn" type="button" onclick="toggleGraphView()" style="margin-left:auto">Switch to Table</button>
        </div>
        <div class="network-view-shell">
            <div id="networkCanvasWrap">
                <canvas id="networkCanvas" style="width:100%;height:420px;display:block;cursor:grab"></canvas>
            </div>
            <div id="networkTableWrap" style="display:none"></div>
        </div>
        <div id="networkTooltip" style="display:none;position:fixed;background:var(--bg-primary);border:0.0625rem solid var(--border-subtle);border-radius:0.5rem;padding:0.6rem 0.9rem;font-size:0.8rem;pointer-events:none;z-index:1000"></div>
    `;

    NET.nodes = nodes.map((node, index) => ({
        ...node,
        x: 320 + Math.cos(index / Math.max(nodes.length, 1) * Math.PI * 2) * 140,
        y: 210 + Math.sin(index / Math.max(nodes.length, 1) * Math.PI * 2) * 140,
        vx: 0,
        vy: 0,
    }));
    NET.edges = edges;
    NET.byId = new Map(NET.nodes.map((node) => [node.id, node]));
    NET.canvas = document.getElementById('networkCanvas');
    NET.ctx = NET.canvas?.getContext('2d') || null;
    NET.view = 'graph';
    NET.drag = null;

    resizeNetCanvas();
    for (let step = 0; step < 300; step += 1) netSimStep();
    drawNet();
    renderNetworkTable();

    if (NET.canvas) {
        NET.canvas.onmousedown = netMouseDown;
        NET.canvas.onmousemove = netMouseMove;
        NET.canvas.onmouseup = () => {
            NET.drag = null;
            NET.canvas.style.cursor = 'grab';
        };
        NET.canvas.onmouseleave = () => {
            NET.drag = null;
            NET.canvas.style.cursor = 'grab';
            const tooltip = document.getElementById('networkTooltip');
            if (tooltip) tooltip.style.display = 'none';
        };
    }

    if (!NET.resizeBound) {
        window.addEventListener('resize', resizeNetCanvas);
        NET.resizeBound = true;
    }
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
            <div class="gauge-name">${escHtml((asset.hostname || asset.name || '').replace('.bank.com', '').replace('.pnb.bank.in', ''))}</div>
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
                <div style="font-size:0.75rem;flex:1;color:var(--text-secondary)">${escHtml((asset.hostname || '').replace('.pnb.bank.in', '').replace('.bank.com', ''))}</div>
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
    const components = (cbom.components || []).filter((component) => component.type === 'cryptographic-asset');
    const summary = cbom.pqcSummary || {};
    const distribution = summary.distribution || {};
    const keyLengthDistribution = {};
    const tlsDistribution = {};
    const cipherUsage = [];

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

    return {
        stats: [
            { label: 'Total Applications', val: summary.totalAssets ?? components.length },
            { label: 'Sites Surveyed', val: summary.totalAssets ?? components.length },
            { label: 'Active Certificates', val: components.length },
            { label: 'Weak Cryptography', val: (distribution.quantumVulnerable || 0) + (distribution.criticallyVulnerable || 0), warn: true },
            { label: 'Certificate Issues', val: (cbom.vulnerabilities || []).length },
        ],
        keyLengthDistribution,
        tlsDistribution,
        cipherUsage: cipherUsage.sort((a, b) => b.count - a.count).slice(0, 8),
        applications: components.map((component) => ({
            name: component.name,
            key_length: component.cryptoProperties?.algorithmProperties?.keySize || '—',
            cipher: [component.cryptoProperties?.algorithmProperties?.keyExchange, component.cryptoProperties?.algorithmProperties?.authentication].filter(Boolean).join(' / ') || '—',
            certificate_authority: (component.nistStandardRefs || []).join(', ') || component.provenance?.source || '—',
        })),
    };
}

async function downloadCBOM(format) {
    try {
        let resp;
        if (format === 'cdxa') {
            resp = await fetch(`${API_BASE}/api/attestation/v2/download`);
            if (!resp.ok) resp = await fetch(`${API_BASE}/api/attestation/download`);
        } else {
            resp = await fetch(buildContextEndpoint('/api/cbom/latest'));
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
        mount.innerHTML = `
            ${bannerHtml(cbom)}
            <div id="cbomStats" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(9rem,1fr));gap:0.75rem;margin-bottom:1.25rem"></div>
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
            <div style="background:rgba(255,255,255,0.03);border:0.0625rem solid var(--border-subtle);border-radius:0.75rem;padding:1rem">
                <div style="font-size:0.8rem;font-weight:600;margin-bottom:0.75rem">Per-Application Detail</div>
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
                        ${['Application', 'Key Length', 'Cipher', 'Certificate Authority'].map((header) => `<th style="padding:0.5rem 0.75rem;text-align:left;font-size:0.75rem;color:var(--text-secondary);font-weight:600">${header}</th>`).join('')}
                    </tr>
                </thead>
                <tbody>
                    ${metrics.applications.map((app) => {
                        const rowClass = /DES|CBC|RC4/i.test(app.cipher) ? 'cbom-table-row-weak' : /MLKEM/i.test(app.cipher) ? 'cbom-table-row-pqc' : 'cbom-table-row-normal';
                        return `<tr class="${rowClass}">
                            <td style="padding:0.5rem 0.75rem;font-size:0.8rem">${escHtml(app.name || '')}</td>
                            <td style="padding:0.5rem 0.75rem;font-size:0.8rem">${escHtml(String(app.key_length || '—'))}</td>
                            <td style="padding:0.5rem 0.75rem;font-size:0.8rem;color:${cipherColor(app.cipher || '')}">${escHtml(app.cipher || '—')}</td>
                            <td style="padding:0.5rem 0.75rem;font-size:0.8rem">${escHtml(app.certificate_authority || '—')}</td>
                        </tr>`;
                    }).join('')}
                </tbody>
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
        const labels = scans.map((scan) => scan.label || `Scan ${scan.id || ''}`);
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

    try {
        const [
            home,
            domains,
            ssl,
            ip,
            software,
            graph,
            cyber,
            heatmap,
            negotiation,
        ] = await Promise.all([
            apiCall(buildEnterpriseEndpoint('/api/home/summary', context, forceRefresh)),
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
        assessmentNegotiationPolicies = negotiation.policies || {};

        renderEnterpriseNotice(home.demo_mode, home.data_notice);
        renderHomeSummaryV2(home);
        renderAssetDiscoveryV2(domains, ssl, ip, software, graph);
        renderCyberPqcV2(cyber, heatmap, negotiation);
        await syncOverviewWithLatestScan(forceRefresh);

        if (isTabActive('overview') || vizInit.network || vizInit.heatmap || vizInit.cyber || vizInit.gauges) {
            prepareOverviewVisualizations(forceRefresh);
        }

        if (vizInit.cbom && isTabActive('phase9')) {
            initCBOM(forceRefresh);
        }
    } catch (error) {
        console.warn('Enterprise data API fetch failed:', error);
        renderVizError('networkVizMount', 'Network graph failed', error.message, 'loadEnterpriseDashboardData({ notifyOnError: true, forceRefresh: true })');
        renderVizError('cyberVizMount', 'Cyber rating failed', error.message, 'loadEnterpriseDashboardData({ notifyOnError: true, forceRefresh: true })');
        renderVizError('heatmapVizMount', 'PQC posture failed', error.message, 'loadEnterpriseDashboardData({ notifyOnError: true, forceRefresh: true })');
        renderVizError('certVizMount', 'Certificate timeline failed', error.message, 'loadEnterpriseDashboardData({ notifyOnError: true, forceRefresh: true })');
        if (notifyOnError) showToast(`Failed to refresh enterprise APIs: ${error.message}`, 'error');
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

    if (tabName === 'phase9' && !vizInit.cbom) {
        vizInit.cbom = true;
        initCBOM();
    }

    if (tabName === 'history' && !vizInit.timeline && document.getElementById('historyContent')?.style.display !== 'none') {
        vizInit.timeline = true;
        initTimeline();
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
    if (isTabActive('overview') || vizInit.network || vizInit.heatmap || vizInit.cyber || vizInit.gauges) {
        await loadEnterpriseDashboardData({ notifyOnError: false, forceRefresh: true });
        await syncOverviewWithLatestScan(true);
    }
};

scanDomain = async function scanDomainInteractive() {
    await originalScanDomain();
    if (isTabActive('overview') || vizInit.network || vizInit.heatmap || vizInit.cyber || vizInit.gauges) {
        await loadEnterpriseDashboardData({ notifyOnError: false, forceRefresh: true });
        await syncOverviewWithLatestScan(true);
    }
};

scanSingleHost = async function scanSingleHostInteractive() {
    await originalScanSingleHost();
    if (isTabActive('overview') || vizInit.network || vizInit.heatmap || vizInit.cyber || vizInit.gauges) {
        await loadEnterpriseDashboardData({ notifyOnError: false, forceRefresh: true });
        await syncOverviewWithLatestScan(true);
    }
};

document.addEventListener('DOMContentLoaded', () => {
    ensureOverviewVizLoading();
    primeOverviewVisuals();
});
