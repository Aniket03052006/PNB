const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, 'frontend');
const PORT = 3000;

const MIME = {
  '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
  '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.woff2': 'font/woff2',
};

// Mock API responses for preview (no backend needed)
const MOCK_API = {
  '/api/auth/me': { email: 'preview@pnb.in', role: 'Admin', name: 'Preview User' },
  '/api/home/summary': {
    demo_mode: true,
    data_notice: 'Preview mode',
    asset_discovery_summary: { domain_count: 42, ip_count: 187, subdomain_count: 93, cloud_asset_count: 11 },
    assets_inventory_summary: { ssl_cert_count: 38, software_count: 74, iot_device_count: 5, login_form_count: 12 },
    posture_of_pqc: { pqc_adoption_pct: 34.2, transition_pct: 28.5 },
    cbom_summary: { vulnerable_component_count: 23, weak_crypto_count: 15 }
  },
  '/api/assets/domains': { items: [
    { domain_name: 'netbanking.pnb.bank.in', hostname: 'netbanking.pnb.bank.in', detection_date: '2026-03-10', registration_date: '2018-11-03', registrar: 'NIXI', company_name: 'PNB', tls_version: '1.2', cipher_suite: 'ECDHE-RSA-AES256-GCM-SHA384', pqc_status: 'QUANTUM_VULNERABLE',    worst_case_score: 45, typical_score: 52, best_case_score: 60, ip_address: '103.109.224.11', cert_days_left: 180 },
    { domain_name: 'auth.pnb.bank.in',       hostname: 'auth.pnb.bank.in',       detection_date: '2026-03-11', registration_date: '2020-06-15', registrar: 'NIXI', company_name: 'PNB', tls_version: '1.3', cipher_suite: 'TLS_AES_256_GCM_SHA384',      pqc_status: 'PQC_TRANSITION',        worst_case_score: 68, typical_score: 72, best_case_score: 88, ip_address: '103.109.225.2',  cert_days_left: 270 },
    { domain_name: 'api.pnb.bank.in',        hostname: 'api.pnb.bank.in',        detection_date: '2026-03-12', registration_date: '2022-06-20', registrar: 'NIXI', company_name: 'PNB', tls_version: '1.3', cipher_suite: 'TLS_AES_256_GCM_SHA384',      pqc_status: 'PQC_TRANSITION',        worst_case_score: 65, typical_score: 70, best_case_score: 85, ip_address: '103.109.224.90', cert_days_left: 22  },
    { domain_name: 'gateway.pnb.bank.in',    hostname: 'gateway.pnb.bank.in',    detection_date: '2026-03-13', registration_date: '2019-04-12', registrar: 'NIXI', company_name: 'PNB', tls_version: '1.3', cipher_suite: 'ECDHE-RSA-AES256-GCM-SHA384', pqc_status: 'PQC_TRANSITION',        worst_case_score: 70, typical_score: 75, best_case_score: 90, ip_address: '103.109.225.1',  cert_days_left: 320 },
    { domain_name: 'legacy.pnb.bank.in',     hostname: 'legacy.pnb.bank.in',     detection_date: '2026-03-14', registration_date: '2015-08-22', registrar: 'NIXI', company_name: 'PNB', tls_version: '1.0', cipher_suite: 'TLS_RSA_WITH_3DES_EDE_CBC',   pqc_status: 'CRITICALLY_VULNERABLE', worst_case_score: 12, typical_score: 18, best_case_score: 22, ip_address: '40.101.72.212',  cert_days_left: -5  },
  ]},
  '/api/assets/ssl': { items: [
    { ssl_sha_fingerprint: 'a1b2c3d4e5f6a1b2c3d4', common_name: 'netbanking.pnb.bank.in', valid_from: '2025-01-15', detection_date: '2026-03-10', company_name: 'PNB', certificate_authority: 'DigiCert',       hostname: 'netbanking.pnb.bank.in', tls_version: '1.2', pqc_status: 'QUANTUM_VULNERABLE',    worst_case_score: 45, ip_address: '103.109.224.11', cert_days_left: 180, public_key_bits: 2048 },
    { ssl_sha_fingerprint: 'b2c3d4e5f6a7b2c3d4e5', common_name: 'auth.pnb.bank.in',       valid_from: '2025-06-01', detection_date: '2026-03-11', company_name: 'PNB', certificate_authority: 'Entrust',         hostname: 'auth.pnb.bank.in',       tls_version: '1.3', pqc_status: 'PQC_TRANSITION',        worst_case_score: 68, ip_address: '103.109.225.2',  cert_days_left: 270, public_key_bits: 4096 },
    { ssl_sha_fingerprint: 'c3d4e5f6a7b8c3d4e5f6', common_name: 'legacy.pnb.bank.in',     valid_from: '2024-03-20', detection_date: '2026-03-14', company_name: 'PNB', certificate_authority: 'COMODO',          hostname: 'legacy.pnb.bank.in',     tls_version: '1.0', pqc_status: 'CRITICALLY_VULNERABLE', worst_case_score: 12, ip_address: '40.101.72.212',  cert_days_left: -5,  public_key_bits: 1024 },
  ]},
  '/api/assets/ip': { items: [
    { ip_address: '103.109.224.11', ip: '103.109.224.11', hostname: 'netbanking.pnb.bank.in', detection_date: '2026-03-10', subnet: '103.109.224.0/24', asn: 'AS9829', netname: 'BSNL-NIB', location: 'Mumbai, IN',        company: 'PNB',   cloud_provider: 'self_hosted', cloud_display_name: 'Self-Hosted',     pool: 'self_hosted', is_cloud_hosted: false, ports: [443, 80], pqc_status: 'QUANTUM_VULNERABLE',    worst_case_score: 45 },
    { ip_address: '103.109.224.90', ip: '103.109.224.90', hostname: 'api.pnb.bank.in',        detection_date: '2026-03-12', subnet: '103.109.224.0/24', asn: 'AS9829', netname: 'BSNL-NIB', location: 'Delhi, IN',         company: 'PNB',   cloud_provider: 'self_hosted', cloud_display_name: 'Self-Hosted',     pool: 'self_hosted', is_cloud_hosted: false, ports: [443],     pqc_status: 'PQC_TRANSITION',        worst_case_score: 65 },
    { ip_address: '103.109.225.1',  ip: '103.109.225.1',  hostname: 'gateway.pnb.bank.in',    detection_date: '2026-03-13', subnet: '103.109.225.0/24', asn: 'AS9829', netname: 'BSNL-NIB', location: 'Bengaluru, IN',     company: 'PNB',   cloud_provider: 'self_hosted', cloud_display_name: 'Self-Hosted',     pool: 'self_hosted', is_cloud_hosted: false, ports: [443, 80], pqc_status: 'PQC_TRANSITION',        worst_case_score: 70 },
    { ip_address: '40.101.72.212',  ip: '40.101.72.212',  hostname: 'legacy.pnb.bank.in',     detection_date: '2026-03-14', subnet: '40.101.72.0/24',   asn: 'AS8075', netname: 'MSFT-GFS', location: 'Virginia, USA',     company: 'Azure', cloud_provider: 'azure',       cloud_display_name: 'Microsoft Azure', pool: 'cloud',       is_cloud_hosted: true,  ports: [443],     pqc_status: 'CRITICALLY_VULNERABLE', worst_case_score: 12 },
  ]},
  '/api/assets/software': { items: [
    { product: 'PQC TLS Stack',    version: 'TLS 1.3', type: 'CryptoProfile', port: 443, host: 'auth.pnb.bank.in',        hostname: 'auth.pnb.bank.in',        detection_date: '2026-03-11', company_name: 'PNB',   tls_version: '1.3', key_exchange: 'X25519MLKEM768', cipher_suite: 'TLS_AES_256_GCM_SHA384',      pqc_status: 'PQC_TRANSITION',        negotiated_cipher: 'TLS_AES_256_GCM_SHA384',      supported_ciphers: ['TLS_AES_256_GCM_SHA384','TLS_AES_128_GCM_SHA256'] },
    { product: 'Modern TLS Stack', version: 'TLS 1.2', type: 'CryptoProfile', port: 443, host: 'netbanking.pnb.bank.in', hostname: 'netbanking.pnb.bank.in', detection_date: '2026-03-10', company_name: 'PNB',   tls_version: '1.2', key_exchange: 'ECDH',          cipher_suite: 'ECDHE-RSA-AES256-GCM-SHA384',  pqc_status: 'QUANTUM_VULNERABLE',    negotiated_cipher: 'ECDHE-RSA-AES256-GCM-SHA384', supported_ciphers: ['ECDHE-RSA-AES256-GCM-SHA384','AES256-SHA256'] },
    { product: 'Legacy TLS Stack', version: 'TLS 1.0', type: 'CryptoProfile', port: 443, host: 'legacy.pnb.bank.in',     hostname: 'legacy.pnb.bank.in',     detection_date: '2026-03-14', company_name: 'Azure', tls_version: '1.0', key_exchange: 'RSA',           cipher_suite: 'TLS_RSA_WITH_3DES_EDE_CBC',    pqc_status: 'CRITICALLY_VULNERABLE', negotiated_cipher: 'TLS_RSA_WITH_3DES_EDE_CBC',   supported_ciphers: ['TLS_RSA_WITH_3DES_EDE_CBC','RC4-SHA'] },
  ]},
  '/api/assets/network-graph': { nodes: [
    { id: 'netbanking.pnb.bank.in', label: 'netbanking.pnb.bank.in', type: 'domain', pqc_status: 'QUANTUM_VULNERABLE',    worst_case_score: 45, ip_address: '103.109.224.11', cloud_provider: 'self_hosted', pool: 'self_hosted' },
    { id: 'auth.pnb.bank.in',       label: 'auth.pnb.bank.in',       type: 'domain', pqc_status: 'PQC_TRANSITION',        worst_case_score: 68, ip_address: '103.109.225.2',  cloud_provider: 'self_hosted', pool: 'self_hosted' },
    { id: 'legacy.pnb.bank.in',     label: 'legacy.pnb.bank.in',     type: 'domain', pqc_status: 'CRITICALLY_VULNERABLE', worst_case_score: 12, ip_address: '40.101.72.212',  cloud_provider: 'azure',       pool: 'cloud'       },
    { id: 'ip-103.109.224.11',      label: '103.109.224.11',          type: 'ip',     pqc_status: 'QUANTUM_VULNERABLE',    worst_case_score: 45, ip_address: '103.109.224.11', cloud_provider: 'self_hosted', pool: 'self_hosted' },
    { id: 'ip-40.101.72.212',       label: '40.101.72.212',           type: 'ip',     pqc_status: 'CRITICALLY_VULNERABLE', worst_case_score: 12, ip_address: '40.101.72.212',  cloud_provider: 'azure',       pool: 'cloud'       },
    { id: 'pool-cloud',             label: 'Cloud-Hosted',            type: 'pool',   pool: 'cloud' },
    { id: 'pool-self',              label: 'Self-Hosted',             type: 'pool',   pool: 'self_hosted' },
  ], edges: [
    { from: 'netbanking.pnb.bank.in', to: 'ip-103.109.224.11' },
    { from: 'auth.pnb.bank.in',       to: 'ip-103.109.224.11' },
    { from: 'legacy.pnb.bank.in',     to: 'ip-40.101.72.212'  },
    { from: 'ip-103.109.224.11',      to: 'pool-self'          },
    { from: 'ip-40.101.72.212',       to: 'pool-cloud'         },
  ]},
  '/api/cyber-rating': {
    enterprise_score: 612, tier: 'Standard', display_tier: 'Standard',
    url_scores: [
      { url: 'netbanking.pnb.bank.in', score: 820, display_tier: 'Elite-PQC' },
      { url: 'api.pnb.bank.in',        score: 640, display_tier: 'Standard'  },
      { url: 'mail.pnb.bank.in',       score: 370, display_tier: 'Legacy'    },
      { url: 'legacy.pnb.bank.in',     score: 120, display_tier: 'Critical'  },
    ]
  },
  '/api/pqc/heatmap': { grid: { pqc_ready: { strong:{count:12}, medium:{count:8}, weak:{count:3} }, transition: { strong:{count:5}, medium:{count:14}, weak:{count:9} }, legacy: { strong:{count:2}, medium:{count:7}, weak:{count:18} } } },
  '/api/pqc/negotiation': { policies: {} },
  '/api/auth/config': { supabase_url: null, anon_key: null, enabled: false },
};

// Dynamic mock handlers (pattern-matched, not exact-match)
function handleDynamicMock(urlPath, query, res) {
  // Reporting: /api/reporting/generate?report_type=...&format=...
  if (urlPath === '/api/reporting/generate') {
    const reportType = query.get('report_type') || 'executive';
    const fmt        = query.get('format')      || 'json';
    const payload = {
      report_type: reportType,
      format: fmt,
      generated_at: new Date().toISOString(),
      organization: 'Punjab National Bank',
      quantum_safety_score: 54,
      total_assets: 8,
      critical_count: 2,
      summary: `Q-ARMOR PQC Assessment Report — ${reportType.toUpperCase()}. ` +
               `PNB enterprise quantum safety score: 54/100. 2 critically vulnerable assets require immediate remediation.`,
      sections: {
        asset_discovery: { domain_count: 5, ip_count: 4, cloud_hosted: 1, self_hosted: 3 },
        pqc_posture:     { fully_quantum_safe: 0, pqc_transition: 3, quantum_vulnerable: 3, critically_vulnerable: 2 },
        cbom:            { total_components: 12, vulnerable: 5, weak_crypto: ['3DES','RC4','1024-bit RSA'] },
        recommendations: [
          'Upgrade legacy.pnb.bank.in from TLS 1.0 to TLS 1.3 immediately',
          'Replace 1024-bit RSA keys with 4096-bit or ECDSA P-384',
          'Deploy ML-KEM-768 hybrid key exchange on all endpoints',
          'Renew expiring certificate on api.pnb.bank.in',
        ],
      },
    };
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(payload));
    return true;
  }

  // Phase 9 demo: /api/phase9/demo
  if (urlPath === '/api/phase9/demo') {
    const labelList = [
      { label_id: 'LABEL-A1B2C3D4', hostname: 'auth.pnb.bank.in',       port: 443, tier: 2, certification_title: 'PQC_TRANSITION',        badge_color: '#FF6D00', badge_icon: '🔶', nist_standards: ['FIPS-203','FIPS-186-5'], algorithms_in_use: ['X25519MLKEM768','ECDSA-P256'], issued_at: new Date().toISOString(), valid_until: new Date(Date.now()+86400000*365).toISOString(), is_simulated: false },
      { label_id: 'LABEL-B2C3D4E5', hostname: 'gateway.pnb.bank.in',    port: 443, tier: 2, certification_title: 'PQC_TRANSITION',        badge_color: '#FF6D00', badge_icon: '🔶', nist_standards: ['FIPS-186-5'], algorithms_in_use: ['ECDHE-RSA','AES-256-GCM'], issued_at: new Date().toISOString(), valid_until: new Date(Date.now()+86400000*300).toISOString(), is_simulated: false },
      { label_id: 'LABEL-E5F6A7B8', hostname: 'legacy.pnb.bank.in',     port: 443, tier: 3, certification_title: 'CRITICALLY_VULNERABLE', badge_color: '#D50000', badge_icon: '❌', nist_standards: [], algorithms_in_use: ['RSA-1024','3DES'],             issued_at: new Date().toISOString(), valid_until: new Date(Date.now()+86400000*30).toISOString(),  is_simulated: false, primary_gap: 'TLS 1.0 + 1024-bit RSA', fix_in_days: 7  },
      { label_id: 'LABEL-C9D0E1F2', hostname: 'netbanking.pnb.bank.in', port: 443, tier: 3, certification_title: 'QUANTUM_VULNERABLE',    badge_color: '#D50000', badge_icon: '❌', nist_standards: [], algorithms_in_use: ['ECDHE-RSA','AES-256-GCM'],    issued_at: new Date().toISOString(), valid_until: new Date(Date.now()+86400000*90).toISOString(),  is_simulated: false, primary_gap: 'No PQC key exchange', fix_in_days: 90 },
      { label_id: 'LABEL-D0E1F2G3', hostname: 'api.pnb.bank.in',        port: 443, tier: 3, certification_title: 'QUANTUM_VULNERABLE',    badge_color: '#D50000', badge_icon: '❌', nist_standards: [], algorithms_in_use: ['ECDHE-RSA','AES-256-GCM'],    issued_at: new Date().toISOString(), valid_until: new Date(Date.now()+86400000*60).toISOString(),  is_simulated: false, primary_gap: 'Expiring cert + no PQC KEX', fix_in_days: 30 },
    ];
    const payload = {
      // labels sub-object (what renderPhase9 reads as data.labels)
      labels: {
        labels: labelList,
        total_assets: 5, tier_1_count: 0, tier_2_count: 2, tier_3_count: 3,
        tier_1_pct: 0, tier_2_pct: 40, tier_3_pct: 60,
        quantum_safety_score: 42,
        executive_summary: 'PNB has 0 fully quantum-safe assets. 2 assets are in PQC transition. 3 assets require immediate quantum remediation.',
        data_mode: 'preview',
      },
      // regression sub-object (what renderPhase9 reads as data.regression)
      regression: {
        new_assets: [
          { hostname: 'portal.pnb.bank.in', port: 443, urgency: 'MEDIUM', category: 'new_asset', description: 'New asset discovered since last scan', recommended_action: 'Schedule full PQC assessment' },
        ],
        score_regressions: [
          { hostname: 'legacy.pnb.bank.in', port: 443, urgency: 'HIGH', category: 'score_regression', description: 'Q-Score dropped: 22 → 12 (TLS downgrade detected)', previous_value: '22', current_value: '12', recommended_action: 'Upgrade TLS to 1.3 immediately' },
        ],
        missed_upgrades: [],
        total_findings: 2, data_mode: 'preview',
      },
      // attestation_summary and attestation
      attestation_summary: { overallCompliance: 'PARTIALLY_COMPLIANT', fips_203: false, fips_204: false, fips_205: false },
      attestation: {},
      registry: {},
      classification: { total_assets: 5 },
      data_mode: 'preview',
    };
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(payload));
    return true;
  }

  // Phase 8 regression: /api/phase8/regression/demo or /api/phase8/regression/live/*
  if (urlPath.startsWith('/api/phase8/regression')) {
    const payload = {
      new_assets: [{ hostname: 'portal.pnb.bank.in', port: 443, urgency: 'MEDIUM', category: 'new_asset', description: 'New asset discovered since last scan', recommended_action: 'Schedule full PQC assessment' }],
      score_regressions: [{ hostname: 'legacy.pnb.bank.in', port: 443, urgency: 'HIGH', category: 'score_regression', description: 'Score dropped from 22 → 12', previous_value: '22', current_value: '12', recommended_action: 'Upgrade TLS immediately' }],
      missed_upgrades: [],
      total_findings: 2, data_mode: 'preview',
    };
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(payload));
    return true;
  }

  // CBOM latest: /api/cbom/latest?mode=demo
  if (urlPath === '/api/cbom/latest') {
    const payload = {
      mode: query.get('mode') || 'demo',
      generated_at: new Date().toISOString(),
      pqcSummary: { totalAssets: 5, fullyQuantumSafe: 0, pqcTransition: 2, quantumVulnerable: 2, criticallyVulnerable: 1 },
      components: [
        { name: 'OpenSSL', version: '1.1.1t', type: 'crypto-library', algorithm: 'RSA-2048', quantum_safe: false, hosts: ['netbanking.pnb.bank.in'] },
        { name: 'TLS Stack', version: 'TLS 1.3', type: 'protocol', algorithm: 'X25519MLKEM768', quantum_safe: true, hosts: ['auth.pnb.bank.in'] },
        { name: 'Legacy TLS', version: 'TLS 1.0', type: 'protocol', algorithm: '3DES', quantum_safe: false, hosts: ['legacy.pnb.bank.in'] },
        { name: 'ECDSA P-256', version: '—', type: 'signature', algorithm: 'ECDSA-P256', quantum_safe: false, hosts: ['gateway.pnb.bank.in'] },
        { name: 'DigiCert CA', version: '—', type: 'certificate', algorithm: 'RSA-4096', quantum_safe: false, hosts: ['netbanking.pnb.bank.in', 'gateway.pnb.bank.in'] },
      ],
      weak_algorithms: ['RSA-2048', '3DES', 'ECDSA-P256', 'RSA-1024'],
    };
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(payload));
    return true;
  }

  // Scan endpoints
  if (urlPath === '/api/scan/demo') {
    const payload = { status: 'ok', message: 'Demo scan complete (preview mode)', total_assets: 5, demo_mode: true };
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(payload));
    return true;
  }

  // /api/scan/latest — return 404 in preview (no scan run yet)
  if (urlPath === '/api/scan/latest') {
    res.writeHead(404, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify({ detail: 'No scan available in preview mode' }));
    return true;
  }

  // Domain scan: /api/scan/domain/{domain}
  if (urlPath.startsWith('/api/scan/domain/')) {
    const domain = decodeURIComponent(urlPath.replace('/api/scan/domain/', ''));
    const mockResults = MOCK_API['/api/assets/domains'].items.map(d => ({
      hostname: d.hostname, port: 443, tls_version: d.tls_version,
      cipher_suite: d.cipher_suite, pqc_status: d.pqc_status,
      q_score: d.worst_case_score, key_exchange: 'ECDHE',
    }));
    const payload = {
      status: 'ok', message: `Scan complete for ${domain} (preview mode)`,
      total_assets: mockResults.length, demo_mode: false, mode: 'live',
      results: mockResults, domain: domain,
    };
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(payload));
    return true;
  }

  // Single host scan: /api/scan/host/*
  if (urlPath.startsWith('/api/scan/host/')) {
    const host = decodeURIComponent(urlPath.replace('/api/scan/host/', ''));
    const payload = {
      status: 'ok', hostname: host, port: 443, tls_version: 'TLSv1.3',
      cipher_suite: 'TLS_AES_256_GCM_SHA384', key_exchange: 'X25519',
      pqc_status: 'QUANTUM_VULNERABLE', q_score: 52,
    };
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(payload));
    return true;
  }

  // Tri-mode fingerprints
  if (urlPath === '/api/scan/trimode/fingerprints') {
    const payload = {
      total: 5, mode: 'live',
      fingerprints: MOCK_API['/api/assets/domains'].items.map(d => ({
        hostname: d.hostname, port: 443, mode: 'live',
        probe_a: { tls_version: 'TLSv1.3', cipher_suite: 'TLS_AES_256_GCM_SHA384', key_exchange: 'X25519MLKEM768' },
        probe_b: { tls_version: d.tls_version === '1.3' ? 'TLSv1.3' : 'TLSv1.2', cipher_suite: d.cipher_suite, key_exchange: 'X25519' },
        probe_c: { tls_version: 'TLSv1.2', cipher_suite: 'ECDHE-RSA-AES256-GCM-SHA384', key_exchange: 'ECDHE' },
      })),
    };
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(payload));
    return true;
  }

  // Assessment endpoints
  if (urlPath === '/api/assess' || urlPath === '/api/assess/remediation') {
    const payload = {
      status: 'ok', total_assessed: 5,
      assessments: MOCK_API['/api/assets/domains'].items.map(d => ({
        hostname: d.hostname, port: 443, pqc_status: d.pqc_status,
        quantum_risk: d.pqc_status === 'CRITICALLY_VULNERABLE' ? 'HIGH' : d.pqc_status === 'PQC_TRANSITION' ? 'LOW' : 'MEDIUM',
        hndl_vulnerable: d.pqc_status !== 'PQC_TRANSITION' && d.pqc_status !== 'FULLY_QUANTUM_SAFE',
        dimensions: { tls: { score: 15, max: 20 }, kex: { score: 12, max: 30 }, cert: { score: 12, max: 20 }, cipher: { score: 10, max: 15 } },
        remediation: { priority: d.pqc_status === 'CRITICALLY_VULNERABLE' ? 'P1' : 'P2', actions: ['Upgrade to TLS 1.3', 'Deploy ML-KEM-768 hybrid key exchange'] },
      })),
    };
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(payload));
    return true;
  }

  return false;
}

http.createServer((req, res) => {
  const fullUrl = new URL(req.url, 'http://localhost');
  const urlPath = fullUrl.pathname;
  const query   = fullUrl.searchParams;

  // Dynamic mocks first (pattern-matched)
  if (handleDynamicMock(urlPath, query, res)) return;

  // Exact-match mock API endpoints
  if (MOCK_API[urlPath]) {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(MOCK_API[urlPath]));
    return;
  }

  // Redirect root to dashboard
  const filePath = path.join(ROOT, urlPath === '/' ? 'dashboard.html' : urlPath);
  const ext = path.extname(filePath);
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found: ' + urlPath); return; }
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'text/plain' });
    res.end(data);
  });
}).listen(PORT, () => console.log(`Serving on http://localhost:${PORT}`));
