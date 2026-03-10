/**
 * Q-ARMOR Dashboard Controller
 * Fetches scan data from the API and renders the interactive dashboard.
 */

const API_BASE = '';

/* ─── State ─── */
let scanData = null;

/* ─── API Calls ─── */
async function apiCall(endpoint, method = 'GET') {
    const resp = await fetch(`${API_BASE}${endpoint}`, { method });
    if (!resp.ok) throw new Error(`API error: ${resp.status}`);
    return resp.json();
}

function showLoading(msg = 'Scanning cryptographic surface...') {
    const overlay = document.getElementById('loadingOverlay');
    overlay.querySelector('.loading-text').textContent = msg;
    overlay.classList.add('active');
}

function hideLoading() {
    document.getElementById('loadingOverlay').classList.remove('active');
}

/* ─── Demo Scan ─── */
async function runDemoScan() {
    showLoading('Running demo scan on 15 simulated bank assets...');
    try {
        scanData = await apiCall('/api/scan/demo');
        renderDashboard(scanData);
        document.getElementById('btnExportCBOM').disabled = false;
    } catch (e) {
        alert('Scan failed: ' + e.message);
    } finally {
        hideLoading();
    }
}

/* ─── Domain Scan ─── */
async function scanDomain() {
    const domain = document.getElementById('domainInput').value.trim();
    if (!domain) { alert('Please enter a domain'); return; }
    showLoading(`Discovering assets for ${domain}...`);
    try {
        scanData = await apiCall(`/api/scan/domain/${encodeURIComponent(domain)}`, 'POST');
        renderDashboard(scanData);
        document.getElementById('btnExportCBOM').disabled = false;
    } catch (e) {
        alert('Scan failed: ' + e.message);
    } finally {
        hideLoading();
    }
}

/* ─── Single Host Scan ─── */
async function scanSingleHost() {
    const host = document.getElementById('singleHostInput').value.trim();
    if (!host) { alert('Please enter a hostname'); return; }
    showLoading(`Probing ${host}...`);
    try {
        const result = await apiCall(`/api/scan/single/${encodeURIComponent(host)}`);
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
    } catch (e) {
        alert('Probe failed: ' + e.message);
    } finally {
        hideLoading();
    }
}

/* ─── CBOM Export ─── */
async function exportCBOM() {
    try {
        const resp = await fetch(`${API_BASE}/api/cbom`);
        const data = await resp.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'qarmor-cbom-cyclonedx-1.6.json';
        a.click();
        URL.revokeObjectURL(url);
    } catch (e) {
        alert('Export failed: ' + e.message);
    }
}

/* ─── Render Dashboard ─── */
function renderDashboard(data) {
    renderStats(data);
    renderAssetTable(data.results || []);
    renderQScoreRing(data.average_q_score);
    renderDistBars(data);
    renderRemediation(data.remediation_roadmap || []);
    renderLabels(data.labels || []);
}

/* ─── Stats ─── */
function renderStats(data) {
    const total = data.total_assets || 0;
    animateNumber('statTotal', total);
    animateNumber('statSafe', data.fully_quantum_safe || 0);
    animateNumber('statTransition', data.pqc_transition || 0);
    animateNumber('statVulnerable', data.quantum_vulnerable || 0);
    animateNumber('statCritical', data.critically_vulnerable || 0);

    document.getElementById('statAvgScore').textContent = `Avg Q-Score: ${(data.average_q_score || 0).toFixed(1)}`;
    document.getElementById('statSafePct').textContent = total ? `${((data.fully_quantum_safe / total) * 100).toFixed(0)}%` : '—';
    document.getElementById('statTransitionPct').textContent = total ? `${((data.pqc_transition / total) * 100).toFixed(0)}%` : '—';
    document.getElementById('statVulnerablePct').textContent = total ? `${((data.quantum_vulnerable / total) * 100).toFixed(0)}%` : '—';
    document.getElementById('statCriticalPct').textContent = total ? `${((data.critically_vulnerable / total) * 100).toFixed(0)}%` : '—';
}

function animateNumber(id, target) {
    const el = document.getElementById(id);
    let current = 0;
    const step = Math.max(1, Math.floor(target / 20));
    const timer = setInterval(() => {
        current += step;
        if (current >= target) { current = target; clearInterval(timer); }
        el.textContent = current;
    }, 30);
}

/* ─── Asset Table ─── */
function renderAssetTable(results) {
    const container = document.getElementById('assetTableContainer');
    document.getElementById('assetCount').textContent = `${results.length} assets`;

    if (!results.length) {
        container.innerHTML = `<div class="empty-state"><div class="empty-state-icon">🔍</div><div class="empty-state-title">No assets found</div></div>`;
        return;
    }

    const sorted = [...results].sort((a, b) => (a.q_score?.total || 0) - (b.q_score?.total || 0));

    let html = `<table class="asset-table"><thead><tr>
        <th>Asset</th><th>Type</th><th>TLS</th><th>Key Exchange</th><th>Cert Algorithm</th><th>Q-Score</th><th>Status</th>
    </tr></thead><tbody>`;

    for (const r of sorted) {
        const asset = r.asset || {};
        const fp = r.fingerprint || {};
        const tls = fp.tls || {};
        const cert = fp.certificate || {};
        const q = r.q_score || {};

        const statusClass = getStatusClass(q.status);
        const statusLabel = getStatusLabel(q.status);
        const scoreColor = getScoreColor(q.total || 0);

        html += `<tr>
            <td><span class="asset-hostname">${asset.hostname || '?'}:${asset.port || 443}</span></td>
            <td><span class="asset-type">${asset.asset_type || 'web'}</span></td>
            <td>${tls.version || '—'}</td>
            <td>${tls.key_exchange || '—'}</td>
            <td style="font-size:0.75rem">${cert.signature_algorithm || cert.public_key_type || '—'}</td>
            <td>
                <div class="qscore-bar-container">
                    <div class="qscore-bar"><div class="qscore-bar-fill" style="width:${q.total || 0}%;background:${scoreColor}"></div></div>
                    <span class="qscore-value" style="color:${scoreColor}">${q.total || 0}</span>
                </div>
            </td>
            <td><span class="status-badge status-badge--${statusClass}">${statusLabel}</span></td>
        </tr>`;
    }

    html += '</tbody></table>';
    container.innerHTML = html;

    // Animate bar fills
    requestAnimationFrame(() => {
        container.querySelectorAll('.qscore-bar-fill').forEach(el => {
            const w = el.style.width;
            el.style.width = '0'; requestAnimationFrame(() => { el.style.width = w; });
        });
    });
}

/* ─── Q-Score Ring ─── */
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

/* ─── Distribution Bars ─── */
function renderDistBars(data) {
    const container = document.getElementById('distBars');
    const total = data.total_assets || 1;

    const bars = [
        { label: 'Quantum Safe', count: data.fully_quantum_safe || 0, color: 'var(--status-safe)' },
        { label: 'PQC Transition', count: data.pqc_transition || 0, color: 'var(--status-transition)' },
        { label: 'Vulnerable', count: data.quantum_vulnerable || 0, color: 'var(--status-vulnerable)' },
        { label: 'Critical', count: data.critically_vulnerable || 0, color: 'var(--status-critical)' },
    ];

    container.innerHTML = bars.map(b => `
        <div class="dist-bar-row">
            <span class="dist-bar-label">${b.label}</span>
            <div class="dist-bar-track"><div class="dist-bar-fill" style="width:${(b.count / total) * 100}%;background:${b.color}"></div></div>
            <span class="dist-bar-count" style="color:${b.color}">${b.count}</span>
        </div>
    `).join('');
}

/* ─── Remediation ─── */
function renderRemediation(roadmap) {
    const container = document.getElementById('remediationContainer');
    if (!roadmap.length) {
        container.innerHTML = `<div class="empty-state"><div class="empty-state-icon">📋</div><div class="empty-state-title">No remediation needed</div></div>`;
        return;
    }

    const priorityMap = {
        'P1_IMMEDIATE': 'P1',
        'P2_SHORT_TERM': 'P2',
        'P3_MEDIUM_TERM': 'P3',
        'P4_STRATEGIC': 'P4',
    };

    const priorityLabel = {
        'P1': 'Priority 1 — Immediate',
        'P2': 'Priority 2 — Short Term',
        'P3': 'Priority 3 — Medium Term',
        'P4': 'Priority 4 — Strategic',
    };

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

/* ─── Labels ─── */
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

/* ─── Helpers ─── */
function getStatusClass(status) {
    const map = {
        'FULLY_QUANTUM_SAFE': 'safe',
        'PQC_TRANSITION': 'transition',
        'QUANTUM_VULNERABLE': 'vulnerable',
        'CRITICALLY_VULNERABLE': 'critical',
    };
    return map[status] || 'vulnerable';
}

function getStatusLabel(status) {
    const map = {
        'FULLY_QUANTUM_SAFE': '✅ Quantum Safe',
        'PQC_TRANSITION': '🔶 PQC Transition',
        'QUANTUM_VULNERABLE': '⚠️ Vulnerable',
        'CRITICALLY_VULNERABLE': '🚨 Critical',
    };
    return map[status] || status;
}

function getScoreColor(score) {
    if (score >= 90) return 'var(--status-safe)';
    if (score >= 70) return 'var(--status-transition)';
    if (score >= 40) return 'var(--status-vulnerable)';
    return 'var(--status-critical)';
}
