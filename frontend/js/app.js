/**
 * Q-ARMOR Dashboard Controller
 * Phase 1: Scan data + overview
 * Phase 2: PQC Assessment, Remediation, NIST Matrix
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
        scanData = await apiCall('/api/scan/demo');
        renderDashboard(scanData);
        document.getElementById('btnExportCBOM').disabled = false;
        showToast(`Scan complete — ${scanData.total_assets} assets analyzed`, 'success');

        // Auto-fetch Phase 2 assessment
        fetchPhase2Assessment();
    } catch (e) {
        showToast('Scan failed: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

/* ─── Domain Scan ─── */
async function scanDomain() {
    const domain = document.getElementById('domainInput').value.trim();
    if (!domain) { showToast('Please enter a domain', 'info'); return; }
    showLoading(`Discovering assets for ${domain}...`);
    try {
        scanData = await apiCall(`/api/scan/domain/${encodeURIComponent(domain)}`, 'POST');
        renderDashboard(scanData);
        document.getElementById('btnExportCBOM').disabled = false;
        fetchPhase2Assessment();
    } catch (e) {
        showToast('Scan failed: ' + e.message, 'error');
    } finally {
        hideLoading();
    }
}

/* ─── Single Host Scan ─── */
async function scanSingleHost() {
    const host = document.getElementById('singleHostInput').value.trim();
    if (!host) { showToast('Please enter a hostname', 'info'); return; }
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
        fetchPhase2Assessment();
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
        a.download = 'qarmor-cbom-phase3.json';
        a.click();
        URL.revokeObjectURL(url);
        showToast('Phase 3 CBOM exported successfully', 'success');
    } catch (e) {
        showToast('Export failed: ' + e.message, 'error');
    }
}

/* ─── Phase 2: Fetch Assessment + Remediation ─── */
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
        console.warn('Phase 2 assessment fetch failed:', e);
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

    requestAnimationFrame(() => {
        container.querySelectorAll('.qscore-bar-fill').forEach(el => {
            const w = el.style.width;
            el.style.width = '0'; requestAnimationFrame(() => { el.style.width = w; });
        });
    });
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


/* ─── Phase 4: Certification Labels ─── */
async function fetchPhase4Labels() {
    try {
        const data = await apiCall('/api/labels/phase4');
        renderCertLabels(data);
    } catch (e) {
        console.warn('Phase 4 labels fetch failed:', e);
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
function drawDonutChart(canvasId, legendId, segments) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    const cx = w / 2;
    const cy = h / 2;
    const outerR = Math.min(cx, cy) - 10;
    const innerR = outerR * 0.58;

    ctx.clearRect(0, 0, w, h);

    const total = segments.reduce((s, seg) => s + seg.value, 0);
    if (total === 0) {
        ctx.beginPath();
        ctx.arc(cx, cy, outerR, 0, Math.PI * 2);
        ctx.arc(cx, cy, innerR, 0, Math.PI * 2, true);
        ctx.fillStyle = 'rgba(55, 65, 81, 0.3)';
        ctx.fill();
        ctx.fillStyle = '#6b7280';
        ctx.font = '600 14px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('No data', cx, cy);
        return;
    }

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

    // Center total
    ctx.fillStyle = '#f0f4f8';
    ctx.font = '800 28px "JetBrains Mono", monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(total, cx, cy - 6);
    ctx.fillStyle = '#6b7280';
    ctx.font = '500 10px Inter, sans-serif';
    ctx.fillText('TOTAL', cx, cy + 14);

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

    container.innerHTML = phases.map(phase => {
        const pCls = phaseClass[phase.priority] || 'P4';
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
            <div class="roadmap-phase-header">${phase.phase}</div>
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
