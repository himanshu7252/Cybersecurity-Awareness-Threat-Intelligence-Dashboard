/**
 * Cybersecurity Awareness Center Logic
 * Renders 15 defensive educational modules, category filters, and detailed guide modals.
 */

let allModules = [];

document.addEventListener('DOMContentLoaded', async () => {
  await loadModules();
  setupFilterHandlers();
});

async function loadModules() {
  const container = document.getElementById('modulesContainer');
  if (!container) return;

  try {
    allModules = await API.getAwarenessModules();
    renderModules(allModules);
  } catch (err) {
    container.innerHTML = `<div style="text-align:center; padding:3rem; color:#ef4444;"><i class="fas fa-exclamation-triangle fa-2x"></i><p style="margin-top:1rem;">Failed to load awareness modules: ${err.message}</p></div>`;
  }
}

function renderModules(modules) {
  const container = document.getElementById('modulesContainer');
  if (!container) return;

  if (modules.length === 0) {
    container.innerHTML = `<div style="grid-column: 1/-1; text-align:center; padding:3rem; color:var(--text-dim);">No awareness modules match the search criteria.</div>`;
    return;
  }

  container.innerHTML = modules.map(m => `
    <div class="module-card">
      <div>
        <div class="module-meta">
          <span class="module-category">${m.category}</span>
          <span class="module-time"><i class="far fa-clock"></i> ${m.estimated_read_time}</span>
        </div>
        <h3 class="module-title">${m.title}</h3>
        <p class="module-excerpt">${m.what_is_it.substring(0, 140)}...</p>
      </div>
      <div style="margin-top:1.5rem; display:flex; justify-content:space-between; align-items:center;">
        <span class="badge badge-info" style="font-size:0.68rem;">${m.difficulty}</span>
        <button class="btn-secondary" onclick="openModuleModal('${m.module_id}')" style="cursor:pointer;">
          <i class="fas fa-book-reader"></i> Learn Defense
        </button>
      </div>
    </div>
  `).join('');
}

function setupFilterHandlers() {
  const searchInput = document.getElementById('moduleSearchInput');
  const catSelect = document.getElementById('moduleCategorySelect');

  function applyFilters() {
    const term = (searchInput?.value || '').toLowerCase().trim();
    const cat = catSelect?.value || '';

    const filtered = allModules.filter(m => {
      const matchCat = (!cat || m.category.toLowerCase() === cat.toLowerCase());
      const matchTerm = (!term || 
        m.title.toLowerCase().includes(term) || 
        m.what_is_it.toLowerCase().includes(term) ||
        m.category.toLowerCase().includes(term)
      );
      return matchCat && matchTerm;
    });

    renderModules(filtered);
  }

  if (searchInput) searchInput.addEventListener('input', applyFilters);
  if (catSelect) catSelect.addEventListener('change', applyFilters);
}

function openModuleModal(moduleId) {
  const mod = allModules.find(m => m.module_id === moduleId);
  if (!mod) return;

  const modal = document.getElementById('moduleDetailModal');
  const body = document.getElementById('moduleModalBody');
  if (!modal || !body) return;

  const warningSigns = Array.isArray(mod.warning_signs) ? mod.warning_signs : JSON.parse(mod.warning_signs || '[]');
  const safePractices = Array.isArray(mod.safe_practices) ? mod.safe_practices : JSON.parse(mod.safe_practices || '[]');

  body.innerHTML = `
    <div style="margin-bottom:1.5rem;">
      <span style="font-size:0.75rem; text-transform:uppercase; color:var(--accent-cyan); font-weight:700;">${mod.category} &bull; ${mod.difficulty} &bull; ${mod.estimated_read_time}</span>
      <h2 style="font-size:1.6rem; color:#fff; font-weight:800; margin-top:0.35rem;">${mod.title}</h2>
    </div>

    <div style="margin-bottom:1.5rem;">
      <h4 style="color:#fff; font-size:1rem; margin-bottom:0.4rem;"><i class="fas fa-question-circle" style="color:var(--accent-cyan);"></i> What is it?</h4>
      <p style="color:var(--text-muted); font-size:0.92rem; line-height:1.6;">${mod.what_is_it}</p>
    </div>

    <div style="margin-bottom:1.5rem;">
      <h4 style="color:#fff; font-size:1rem; margin-bottom:0.4rem;"><i class="fas fa-exclamation-triangle" style="color:var(--sev-high);"></i> Why does it matter?</h4>
      <p style="color:var(--text-muted); font-size:0.92rem; line-height:1.6;">${mod.why_it_matters}</p>
    </div>

    <div style="margin-bottom:1.5rem; background:rgba(239, 68, 68, 0.08); border:1px solid rgba(239, 68, 68, 0.2); padding:1.25rem; border-radius:var(--radius-sm);">
      <h4 style="color:#f87171; font-size:0.95rem; font-weight:700; margin-bottom:0.6rem;"><i class="fas fa-bell"></i> Critical Warning Signs</h4>
      <ul style="padding-left:1.25rem; font-size:0.88rem; color:var(--text-main); line-height:1.6;">
        ${warningSigns.map(w => `<li>${w}</li>`).join('')}
      </ul>
    </div>

    <div style="margin-bottom:1.5rem; background:rgba(16, 185, 129, 0.08); border:1px solid rgba(16, 185, 129, 0.2); padding:1.25rem; border-radius:var(--radius-sm);">
      <h4 style="color:#34d399; font-size:0.95rem; font-weight:700; margin-bottom:0.6rem;"><i class="fas fa-shield-alt"></i> Safe Defensive Practices</h4>
      <ul style="padding-left:1.25rem; font-size:0.88rem; color:var(--text-main); line-height:1.6;">
        ${safePractices.map(s => `<li>${s}</li>`).join('')}
      </ul>
    </div>

    <div style="background:var(--bg-primary); border-left:4px solid var(--accent-cyan); padding:1.25rem; border-radius:var(--radius-sm);">
      <h4 style="color:#fff; font-size:0.95rem; font-weight:700; margin-bottom:0.5rem;"><i class="fas fa-ambulance" style="color:var(--accent-cyan);"></i> What to do if something happens?</h4>
      <p style="color:var(--text-muted); font-size:0.9rem; line-height:1.6;">${mod.incident_guidance}</p>
    </div>

    <div style="margin-top:2rem; text-align:right;">
      <a href="/quiz.html" class="btn-primary" style="display:inline-flex;">
        <i class="fas fa-tasks"></i> Test Your Knowledge in Quiz
      </a>
    </div>
  `;

  modal.classList.add('show');
}

function closeModuleModal() {
  const modal = document.getElementById('moduleDetailModal');
  if (modal) modal.classList.remove('show');
}
