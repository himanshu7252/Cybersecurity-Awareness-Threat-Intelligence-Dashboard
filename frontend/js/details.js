/**
 * SOC Threat Investigation View Logic
 * Displays threat dossier, timeline, ATT&CK, correlated indicators, and analyst notes.
 */

let currentThreatId = null;

document.addEventListener('DOMContentLoaded', async () => {
  const urlParams = new URLSearchParams(window.location.search);
  currentThreatId = urlParams.get('id') || 'THR-2026-001';
  await loadThreatDetails(currentThreatId);
  setupNoteForm();
});

async function loadThreatDetails(threatId) {
  const container = document.getElementById('detailsContainer');
  if (!container) return;

  try {
    const [threat, correlation] = await Promise.all([
      API.getThreatById(threatId),
      API.getThreatCorrelation(threatId)
    ]);

    currentThreatId = threat.threat_id;
    document.title = `Investigation: ${threat.threat_id} - SOC Dashboard`;

    // Render threat header & basic metrics
    document.getElementById('detailThreatId').textContent = threat.threat_id;
    document.getElementById('detailThreatName').textContent = threat.threat_name;
    document.getElementById('detailCategory').textContent = threat.category;

    const sevBadge = document.getElementById('detailSeverityBadge');
    if (sevBadge) {
      sevBadge.className = `badge badge-${threat.severity.toLowerCase()}`;
      sevBadge.textContent = threat.severity;
    }

    const statusBadge = document.getElementById('detailStatusBadge');
    if (statusBadge) {
      statusBadge.className = `status-tag status-${threat.status.toLowerCase()}`;
      statusBadge.textContent = threat.status;
    }

    document.getElementById('detailRiskScore').textContent = `${threat.risk_score}/100`;
    document.getElementById('detailConfidence').textContent = `${threat.confidence_score}%`;
    document.getElementById('detailFirstSeen').textContent = threat.first_seen.replace('T', ' ').replace('Z', ' UTC');
    document.getElementById('detailLastSeen').textContent = threat.last_seen.replace('T', ' ').replace('Z', ' UTC');
    document.getElementById('detailDescription').textContent = threat.description || 'No description provided.';
    
    // Source & Reliability
    const src = threat.source_reliability;
    document.getElementById('detailSource').textContent = `${threat.source_name} (${src.grade} – ${src.label})`;

    // Indicators Table
    const indTbody = document.getElementById('indicatorsTableBody');
    if (indTbody && threat.indicators) {
      indTbody.innerHTML = threat.indicators.map(i => `
        <tr>
          <td><span class="badge badge-info">${i.indicator_type}</span></td>
          <td><span class="indicator-mono">${i.indicator_value}</span></td>
          <td>${i.first_seen ? i.first_seen.split('T')[0] : 'N/A'}</td>
          <td>${i.last_seen ? i.last_seen.split('T')[0] : 'N/A'}</td>
        </tr>
      `).join('');
    }

    // ATT&CK Mappings
    const attackContainer = document.getElementById('attackMappingsContainer');
    if (attackContainer && threat.attack_mappings) {
      attackContainer.innerHTML = threat.attack_mappings.map(m => `
        <div style="background: rgba(139, 92, 246, 0.12); border: 1px solid rgba(139, 92, 246, 0.3); border-radius: var(--radius-sm); padding: 0.85rem 1.25rem;">
          <div style="font-size:0.75rem; text-transform:uppercase; color:#c084fc; font-weight:700;">TACTIC: ${m.tactic}</div>
          <div style="font-size:1.05rem; font-weight:700; color:#fff; margin-top:0.25rem;">${m.technique}</div>
          <div style="font-size:0.8rem; color:var(--text-muted); margin-top:0.35rem;">Framework Reference ID: ${m.technique_id_optional || 'Documented Behavior'}</div>
        </div>
      `).join('');
    }

    // Recommended Actions
    const actionsList = document.getElementById('recommendedActionsList');
    if (actionsList && threat.recommended_actions) {
      actionsList.innerHTML = threat.recommended_actions.map(a => `<li>${a}</li>`).join('');
    }

    // Timeline Rendering
    const timelineList = document.getElementById('threatTimeline');
    if (timelineList && correlation && correlation.timeline) {
      timelineList.innerHTML = correlation.timeline.map(t => `
        <div class="timeline-item">
          <div class="timeline-dot"></div>
          <div class="timeline-header">
            <span class="timeline-title">${t.stage}</span>
            <span class="timeline-time">${t.timestamp.replace('T', ' ').replace('Z', '')}</span>
          </div>
          <div class="timeline-desc">${t.event}</div>
        </div>
      `).join('');
    }

    // Correlated Cluster
    const clusterContainer = document.getElementById('clusterContainer');
    if (clusterContainer && correlation && correlation.correlated_threats) {
      document.getElementById('clusterTitle').textContent = `${correlation.cluster_name} (${correlation.cluster_size} items)`;
      clusterContainer.innerHTML = correlation.correlated_threats.map(c => `
        <div style="background:var(--bg-secondary); border:1px solid var(--border-color); border-radius:var(--radius-sm); padding:0.85rem; display:flex; justify-content:space-between; align-items:center;">
          <div>
            <div style="font-size:0.85rem; font-weight:700; color:#fff;">${c.threat_name}</div>
            <div style="font-size:0.78rem; font-family:'JetBrains Mono'; color:var(--accent-cyan); margin-top:0.2rem;">${c.indicator_value} (${c.indicator_type})</div>
          </div>
          <a href="/threat-details.html?id=${encodeURIComponent(c.threat_id)}" class="btn-secondary" style="font-size:0.75rem; padding:0.25rem 0.6rem;">Investigate</a>
        </div>
      `).join('');
    }

    // Analyst Notes
    renderAnalystNotes(threat.analyst_notes || []);

  } catch (err) {
    console.error('Failed to load threat details:', err);
    if (container) {
      container.innerHTML = `<div style="text-align:center; padding: 4rem; color:#ef4444;"><i class="fas fa-exclamation-triangle fa-2x"></i><p style="margin-top:1rem;">Failed to load threat '${threatId}': ${err.message}</p></div>`;
    }
  }
}

function renderAnalystNotes(notes) {
  const notesContainer = document.getElementById('analystNotesList');
  if (!notesContainer) return;

  if (notes.length === 0) {
    notesContainer.innerHTML = `<div style="color:var(--text-dim); font-size:0.85rem; padding:0.5rem 0;">No analyst notes recorded yet. Add observations below.</div>`;
    return;
  }

  notesContainer.innerHTML = notes.map(n => `
    <div style="background:var(--bg-secondary); border-left:3px solid var(--accent-cyan); padding:0.85rem 1rem; border-radius:4px; margin-bottom:0.75rem;">
      <div style="display:flex; justify-content:space-between; font-size:0.78rem; color:var(--text-dim); margin-bottom:0.35rem;">
        <span style="font-weight:700; color:var(--text-main);"><i class="fas fa-user-shield"></i> ${n.analyst_name}</span>
        <span style="font-family:'JetBrains Mono';">${n.created_at ? n.created_at.replace('T', ' ').replace('Z', '') : ''}</span>
      </div>
      <div style="font-size:0.88rem; color:var(--text-muted); line-height:1.4;">${n.note}</div>
    </div>
  `).join('');
}

function setupNoteForm() {
  const form = document.getElementById('addNoteForm');
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const analystInput = document.getElementById('analystNameInput');
    const noteInput = document.getElementById('noteTextInput');

    if (!noteInput || !noteInput.value.trim() || !currentThreatId) return;

    const btn = form.querySelector('button[type="submit"]');
    if (btn) btn.disabled = true;

    try {
      await API.addThreatNote(currentThreatId, analystInput?.value || 'SOC Analyst', noteInput.value.trim());
      noteInput.value = '';
      // Reload details
      await loadThreatDetails(currentThreatId);
    } catch (err) {
      alert(`Error adding note: ${err.message}`);
    } finally {
      if (btn) btn.disabled = false;
    }
  });
}
