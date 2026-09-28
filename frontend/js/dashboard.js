/**
 * SOC Threat Intelligence Dashboard Logic
 * Charts, Metrics, Filtering, Pagination, and Indicator Search Modal
 */

let charts = {};
let currentThreatsPage = 1;
const pageSize = 20;

document.addEventListener('DOMContentLoaded', async () => {
  await loadDashboardMetrics();
  await initializeCharts();
  await loadThreatsTable();
  setupEventListeners();
});

function setupEventListeners() {
  // Search Form
  const searchForm = document.getElementById('iocSearchForm');
  if (searchForm) {
    searchForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const input = document.getElementById('iocSearchInput');
      if (input && input.value.trim()) {
        await executeIocSearch(input.value.trim());
      }
    });
  }

  // Filter change handlers
  ['filterCategory', 'filterSeverity', 'filterIndicatorType', 'filterStatus', 'sortBy'].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener('change', () => {
        currentThreatsPage = 1;
        loadThreatsTable();
      });
    }
  });

  // Pagination buttons
  const prevBtn = document.getElementById('prevPageBtn');
  const nextBtn = document.getElementById('nextPageBtn');
  if (prevBtn) {
    prevBtn.addEventListener('click', () => {
      if (currentThreatsPage > 1) {
        currentThreatsPage--;
        loadThreatsTable();
      }
    });
  }
  if (nextBtn) {
    nextBtn.addEventListener('click', () => {
      currentThreatsPage++;
      loadThreatsTable();
    });
  }
}

async function loadDashboardMetrics() {
  try {
    const stats = await API.getStats();
    document.getElementById('metricTotalThreats').textContent = (stats.total_threats || 0).toLocaleString();
    document.getElementById('metricCriticalThreats').textContent = (stats.critical_threats || 0).toLocaleString();
    document.getElementById('metricHighThreats').textContent = (stats.high_threats || 0).toLocaleString();
    document.getElementById('metricActiveIndicators').textContent = (stats.active_indicators || 0).toLocaleString();
    document.getElementById('metricOpenInvestigations').textContent = (stats.open_investigations || 0).toLocaleString();
    document.getElementById('metricAvgConfidence').textContent = `${stats.average_confidence || 0}%`;
    document.getElementById('metricTrackedVulns').textContent = (stats.vulnerabilities_tracked || 0).toLocaleString();
    document.getElementById('metricActiveAlerts').textContent = (stats.active_alerts || 0).toLocaleString();
  } catch (err) {
    console.error('Failed to load stats:', err);
  }
}

async function initializeCharts() {
  try {
    const trends = await API.getTrends();
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.font.family = "'Inter', sans-serif";

    // 1. Threats Over Time (Line Chart)
    const ctxTime = document.getElementById('chartThreatsOverTime')?.getContext('2d');
    if (ctxTime && trends.threats_over_time) {
      const gradient = ctxTime.createLinearGradient(0, 0, 0, 300);
      gradient.addColorStop(0, 'rgba(6, 182, 212, 0.4)');
      gradient.addColorStop(1, 'rgba(6, 182, 212, 0.0)');

      charts.time = new Chart(ctxTime, {
        type: 'line',
        data: {
          labels: trends.threats_over_time.map(d => d.period),
          datasets: [{
            label: 'Threat Ingestions',
            data: trends.threats_over_time.map(d => d.count),
            borderColor: '#06b6d4',
            backgroundColor: gradient,
            borderWidth: 2.5,
            fill: true,
            tension: 0.35,
            pointBackgroundColor: '#06b6d4',
            pointRadius: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            y: { grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true },
            x: { grid: { display: false } }
          }
        }
      });
    }

    // 2. Threats by Severity (Donut Chart)
    const ctxSev = document.getElementById('chartThreatsBySeverity')?.getContext('2d');
    if (ctxSev && trends.threats_by_severity) {
      charts.severity = new Chart(ctxSev, {
        type: 'doughnut',
        data: {
          labels: Object.keys(trends.threats_by_severity),
          datasets: [{
            data: Object.values(trends.threats_by_severity),
            backgroundColor: ['#ef4444', '#f97316', '#eab308', '#10b981', '#06b6d4'],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: 'bottom', labels: { boxWidth: 12 } } },
          cutout: '68%'
        }
      });
    }

    // 3. Threats by Category (Bar Chart)
    const ctxCat = document.getElementById('chartThreatsByCategory')?.getContext('2d');
    if (ctxCat && trends.threats_by_category) {
      charts.category = new Chart(ctxCat, {
        type: 'bar',
        data: {
          labels: trends.threats_by_category.map(d => d.category),
          datasets: [{
            label: 'Threat Count',
            data: trends.threats_by_category.map(d => d.count),
            backgroundColor: 'rgba(59, 130, 246, 0.75)',
            borderRadius: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { color: 'rgba(255,255,255,0.05)' } },
            y: { grid: { display: false } }
          }
        }
      });
    }

    // 4. IOC Type Distribution (Pie Chart)
    const ctxIoc = document.getElementById('chartIocDistribution')?.getContext('2d');
    if (ctxIoc && trends.ioc_distribution) {
      charts.ioc = new Chart(ctxIoc, {
        type: 'pie',
        data: {
          labels: Object.keys(trends.ioc_distribution),
          datasets: [{
            data: Object.values(trends.ioc_distribution),
            backgroundColor: ['#3b82f6', '#06b6d4', '#8b5cf6', '#10b981', '#ec4899', '#f59e0b'],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: 'right', labels: { boxWidth: 10 } } }
        }
      });
    }

    // 5. Top MITRE ATT&CK Tactics (Bar Chart)
    const ctxAttack = document.getElementById('chartAttackTactics')?.getContext('2d');
    if (ctxAttack && trends.attack_tactics) {
      charts.attack = new Chart(ctxAttack, {
        type: 'bar',
        data: {
          labels: trends.attack_tactics.map(d => d.tactic),
          datasets: [{
            label: 'Techniques Mapped',
            data: trends.attack_tactics.map(d => d.count),
            backgroundColor: 'rgba(139, 92, 246, 0.75)',
            borderRadius: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            y: { grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true },
            x: { grid: { display: false } }
          }
        }
      });
    }

    // 6. Risk Score Distribution (Histogram)
    const ctxRisk = document.getElementById('chartRiskDistribution')?.getContext('2d');
    if (ctxRisk && trends.risk_distribution) {
      charts.risk = new Chart(ctxRisk, {
        type: 'bar',
        data: {
          labels: Object.keys(trends.risk_distribution),
          datasets: [{
            label: 'Threat Count',
            data: Object.values(trends.risk_distribution),
            backgroundColor: ['#06b6d4', '#10b981', '#eab308', '#f97316', '#ef4444'],
            borderRadius: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            y: { grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true },
            x: { grid: { display: false } }
          }
        }
      });
    }

    // 7. Confidence Score Distribution
    const ctxConf = document.getElementById('chartConfidenceDistribution')?.getContext('2d');
    if (ctxConf && trends.confidence_distribution) {
      charts.conf = new Chart(ctxConf, {
        type: 'doughnut',
        data: {
          labels: Object.keys(trends.confidence_distribution),
          datasets: [{
            data: Object.values(trends.confidence_distribution),
            backgroundColor: ['#64748b', '#3b82f6', '#10b981'],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: 'bottom', labels: { boxWidth: 10 } } },
          cutout: '60%'
        }
      });
    }

    // 8. Vulnerabilities by Severity
    const ctxVuln = document.getElementById('chartVulnsBySeverity')?.getContext('2d');
    if (ctxVuln && trends.vulns_by_severity) {
      charts.vuln = new Chart(ctxVuln, {
        type: 'doughnut',
        data: {
          labels: Object.keys(trends.vulns_by_severity),
          datasets: [{
            data: Object.values(trends.vulns_by_severity),
            backgroundColor: ['#ef4444', '#f97316', '#eab308', '#10b981'],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: 'bottom', labels: { boxWidth: 10 } } },
          cutout: '65%'
        }
      });
    }

    // 9. Top Threat Categories Radar/Polar
    const ctxTopCat = document.getElementById('chartTopCategories')?.getContext('2d');
    if (ctxTopCat && trends.top_categories) {
      charts.topCat = new Chart(ctxTopCat, {
        type: 'polarArea',
        data: {
          labels: trends.top_categories.map(d => d.category),
          datasets: [{
            data: trends.top_categories.map(d => d.count),
            backgroundColor: [
              'rgba(6, 182, 212, 0.65)',
              'rgba(59, 130, 246, 0.65)',
              'rgba(139, 92, 246, 0.65)',
              'rgba(239, 68, 68, 0.65)',
              'rgba(249, 115, 22, 0.65)'
            ],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: 'right', labels: { boxWidth: 10 } } }
        }
      });
    }

    // 10. Threat Status Distribution
    const ctxStatus = document.getElementById('chartStatusDistribution')?.getContext('2d');
    if (ctxStatus && trends.threat_status_distribution) {
      charts.status = new Chart(ctxStatus, {
        type: 'doughnut',
        data: {
          labels: Object.keys(trends.threat_status_distribution),
          datasets: [{
            data: Object.values(trends.threat_status_distribution),
            backgroundColor: ['#3b82f6', '#facc15', '#34d399', '#94a3b8', '#c084fc'],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: 'bottom', labels: { boxWidth: 10 } } },
          cutout: '65%'
        }
      });
    }

  } catch (err) {
    console.error('Failed to initialize charts:', err);
  }
}

async function loadThreatsTable() {
  const tbody = document.getElementById('threatsTableBody');
  if (!tbody) return;

  tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; padding: 2rem;"><i class="fas fa-spinner fa-spin"></i> Loading threat intelligence feed...</td></tr>`;

  const category = document.getElementById('filterCategory')?.value || '';
  const severity = document.getElementById('filterSeverity')?.value || '';
  const indicatorType = document.getElementById('filterIndicatorType')?.value || '';
  const status = document.getElementById('filterStatus')?.value || '';
  const sortBy = document.getElementById('sortBy')?.value || 'last_seen';

  try {
    const data = await API.getThreats({
      category,
      severity,
      indicator_type: indicatorType,
      status,
      sort_by: sortBy,
      order: 'desc',
      page: currentThreatsPage,
      page_size: pageSize
    });

    if (!data.threats || data.threats.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; padding: 2rem; color: var(--text-dim);">No threat indicators match the selected criteria.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.threats.map(t => {
      const sevClass = `badge-${t.severity.toLowerCase()}`;
      const statusClass = `status-${t.status.toLowerCase()}`;
      const shortSeen = t.last_seen ? t.last_seen.split('T')[0] : 'N/A';
      const cleanInd = t.indicator_value ? (t.indicator_value.length > 32 ? t.indicator_value.substring(0, 30) + '...' : t.indicator_value) : 'N/A';

      return `
        <tr>
          <td><a href="/threat-details.html?id=${encodeURIComponent(t.threat_id)}" style="color:var(--accent-cyan); font-weight:600; text-decoration:none;">${t.threat_id}</a></td>
          <td style="font-weight:600; color:#fff;">${t.threat_name}</td>
          <td><span style="font-size:0.75rem; color:var(--text-muted);">${t.category}</span></td>
          <td><span class="indicator-mono" title="${t.indicator_value}">${cleanInd}</span></td>
          <td><span class="badge ${sevClass}">${t.severity}</span></td>
          <td><span class="score-pill" style="color: ${getRiskColor(t.risk_score)}">${t.risk_score}/100</span></td>
          <td><span style="font-size:0.8rem; font-family:'JetBrains Mono';">${t.confidence_score}%</span></td>
          <td><span class="status-tag ${statusClass}">${t.status}</span></td>
          <td><a href="/threat-details.html?id=${encodeURIComponent(t.threat_id)}" class="btn-secondary" style="padding:0.3rem 0.6rem; font-size:0.75rem;"><i class="fas fa-search-plus"></i> Triage</a></td>
        </tr>
      `;
    }).join('');

    // Update pagination labels
    const pageIndicator = document.getElementById('pageIndicator');
    if (pageIndicator) {
      pageIndicator.textContent = `Page ${data.page} of ${data.total_pages} (${data.total_records.toLocaleString()} total)`;
    }

    const prevBtn = document.getElementById('prevPageBtn');
    const nextBtn = document.getElementById('nextPageBtn');
    if (prevBtn) prevBtn.disabled = (data.page <= 1);
    if (nextBtn) nextBtn.disabled = (data.page >= data.total_pages);

  } catch (err) {
    console.error('Error loading threats table:', err);
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; padding: 2rem; color: #ef4444;"><i class="fas fa-exclamation-triangle"></i> Failed to retrieve threats. Check server logs.</td></tr>`;
  }
}

function getRiskColor(score) {
  if (score >= 81) return '#ef4444';
  if (score >= 61) return '#f97316';
  if (score >= 41) return '#eab308';
  if (score >= 21) return '#10b981';
  return '#06b6d4';
}

async function executeIocSearch(query) {
  const modal = document.getElementById('iocModal');
  const modalContent = document.getElementById('iocModalBody');
  if (!modal || !modalContent) return;

  modalContent.innerHTML = `<div style="text-align:center; padding: 3rem;"><i class="fas fa-spinner fa-spin fa-2x" style="color:var(--accent-cyan);"></i><p style="margin-top:1rem;">Performing passive database lookup for '${query}'...</p></div>`;
  modal.classList.add('show');

  try {
    const data = await API.searchIndicator(query);
    const sevClass = `badge-${data.severity.toLowerCase()}`;
    const riskColor = getRiskColor(data.risk_score);

    modalContent.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:1.5rem; flex-wrap:wrap; gap:1rem;">
        <div>
          <span style="font-size:0.75rem; text-transform:uppercase; letter-spacing:0.08em; color:var(--accent-cyan); font-weight:700;">Enriched Threat Dossier</span>
          <h3 style="font-size:1.4rem; color:#fff; font-family:'JetBrains Mono'; margin-top:0.25rem;">${data.normalized_value}</h3>
          <p style="color:var(--text-dim); font-size:0.8rem; margin-top:0.2rem;"><i class="fas fa-shield-alt"></i> ${data.defensive_notice}</p>
        </div>
        <div style="display:flex; gap:0.5rem; align-items:center;">
          <span class="badge ${sevClass}">${data.severity}</span>
          <span class="status-tag status-${(data.status||'').toLowerCase()}">${data.status}</span>
        </div>
      </div>

      <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:1rem; margin-bottom:1.5rem;">
        <div style="background:var(--bg-card); padding:1rem; border-radius:var(--radius-sm); border:1px solid var(--border-color);">
          <div style="font-size:0.75rem; color:var(--text-dim);">INDICATOR TYPE</div>
          <div style="font-weight:700; color:#fff; margin-top:0.25rem;">${data.indicator_type}</div>
        </div>
        <div style="background:var(--bg-card); padding:1rem; border-radius:var(--radius-sm); border:1px solid var(--border-color);">
          <div style="font-size:0.75rem; color:var(--text-dim);">DEMO DATASET MATCH</div>
          <div style="font-weight:700; color:${data.known_in_demo_dataset ? '#34d399':'#94a3b8'}; margin-top:0.25rem;">
            ${data.known_in_demo_dataset ? 'YES (Confirmed Ingestion)' : 'NO (Unobserved)'}
          </div>
        </div>
        <div style="background:var(--bg-card); padding:1rem; border-radius:var(--radius-sm); border:1px solid var(--border-color);">
          <div style="font-size:0.75rem; color:var(--text-dim);">RISK SCORE</div>
          <div style="font-weight:800; font-size:1.3rem; color:${riskColor};">${data.risk_score}/100</div>
        </div>
        <div style="background:var(--bg-card); padding:1rem; border-radius:var(--radius-sm); border:1px solid var(--border-color);">
          <div style="font-size:0.75rem; color:var(--text-dim);">CONFIDENCE SCORE</div>
          <div style="font-weight:800; font-size:1.3rem; color:#60a5fa;">${data.confidence_score}%</div>
        </div>
      </div>

      <div style="margin-bottom:1.25rem;">
        <h4 style="font-size:0.95rem; color:#fff; margin-bottom:0.5rem;"><i class="fas fa-info-circle" style="color:var(--accent-cyan);"></i> Syntactic Format Analysis</h4>
        <div style="background:var(--bg-primary); padding:0.85rem; border-radius:var(--radius-sm); font-size:0.85rem; color:var(--text-muted); border-left:3px solid var(--accent-cyan);">
          <strong>Status:</strong> ${data.syntactic_validation.valid ? 'Valid Syntax Structure' : 'Invalid Syntax Format'}<br>
          <strong>Notes:</strong> ${data.syntactic_validation.validation_notes}
        </div>
      </div>

      ${data.mitre_mapping && data.mitre_mapping.length > 0 ? `
        <div style="margin-bottom:1.25rem;">
          <h4 style="font-size:0.95rem; color:#fff; margin-bottom:0.5rem;"><i class="fas fa-crosshairs" style="color:var(--accent-purple);"></i> MITRE ATT&CK Mapping</h4>
          <div style="display:flex; flex-wrap:wrap; gap:0.5rem;">
            ${data.mitre_mapping.map(m => `
              <span style="background:rgba(139, 92, 246, 0.15); border:1px solid rgba(139, 92, 246, 0.3); color:#c084fc; padding:0.35rem 0.75rem; border-radius:4px; font-size:0.8rem; font-weight:600;">
                ${m.tactic} &rarr; ${m.technique}
              </span>
            `).join('')}
          </div>
        </div>
      ` : ''}

      <div style="margin-bottom:1.25rem;">
        <h4 style="font-size:0.95rem; color:#fff; margin-bottom:0.5rem;"><i class="fas fa-shield-alt" style="color:#10b981;"></i> Recommended Defensive Actions</h4>
        <ul style="padding-left:1.25rem; font-size:0.85rem; color:var(--text-muted); line-height:1.6;">
          ${data.defensive_recommendations.map(r => `<li>${r}</li>`).join('')}
        </ul>
      </div>

      ${data.threat_id ? `
        <div style="margin-top:1.5rem; text-align:right;">
          <a href="/threat-details.html?id=${encodeURIComponent(data.threat_id)}" class="btn-primary" style="display:inline-flex;">
            <i class="fas fa-microscope"></i> Open Full SOC Investigation
          </a>
        </div>
      ` : ''}
    `;
  } catch (err) {
    modalContent.innerHTML = `<div style="text-align:center; padding: 2rem; color:#ef4444;"><i class="fas fa-exclamation-circle fa-2x"></i><p style="margin-top:0.75rem;">Error searching indicator: ${err.message}</p></div>`;
  }
}

function closeIocModal() {
  const modal = document.getElementById('iocModal');
  if (modal) modal.classList.remove('show');
}
