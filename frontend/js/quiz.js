/**
 * Security Awareness Quiz Engine Logic
 * 32 questions across 10 categories, real-time evaluation,
 * awareness scoring, category breakdown, and personalized recommendations.
 */

let quizQuestions = [];
const userAnswers = {};

document.addEventListener('DOMContentLoaded', async () => {
  await loadQuiz();
  setupQuizSubmission();
});

async function loadQuiz() {
  const container = document.getElementById('quizQuestionsContainer');
  if (!container) return;

  try {
    quizQuestions = await API.getQuizQuestions(false);
    document.getElementById('totalQuestionsCount').textContent = quizQuestions.length;
    renderQuizQuestions();
  } catch (err) {
    container.innerHTML = `<div style="text-align:center; padding:3rem; color:#ef4444;"><i class="fas fa-exclamation-triangle fa-2x"></i><p style="margin-top:1rem;">Failed to load quiz questions: ${err.message}</p></div>`;
  }
}

function renderQuizQuestions() {
  const container = document.getElementById('quizQuestionsContainer');
  if (!container) return;

  container.innerHTML = quizQuestions.map((q, idx) => `
    <div class="question-card" id="q_card_${q.id}">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
        <span class="question-category"><i class="fas fa-tag"></i> ${q.category}</span>
        <span style="font-size:0.75rem; color:var(--text-dim); font-family:'JetBrains Mono';">Question ${idx + 1} of ${quizQuestions.length}</span>
      </div>
      <div class="question-text">${q.question}</div>
      <div class="options-list">
        ${q.options.map((opt, oIdx) => {
          const letter = opt.substring(0, 1);
          return `
            <div class="option-item" onclick="selectOption(${q.id}, '${letter}')" id="opt_${q.id}_${letter}">
              <span class="option-letter">${letter}</span>
              <span class="option-text">${opt.substring(2).trim()}</span>
            </div>
          `;
        }).join('')}
      </div>
    </div>
  `).join('');
}

function selectOption(questionId, letter) {
  userAnswers[questionId] = letter;

  // Visual selection state
  ['A', 'B', 'C', 'D'].forEach(l => {
    const el = document.getElementById(`opt_${questionId}_${l}`);
    if (el) el.classList.remove('selected');
  });
  const selectedEl = document.getElementById(`opt_${questionId}_${letter}`);
  if (selectedEl) selectedEl.classList.add('selected');

  updateProgressBar();
}

function updateProgressBar() {
  const answered = Object.keys(userAnswers).length;
  const total = quizQuestions.length;
  const pct = Math.round((answered / total) * 100);

  const fill = document.getElementById('quizProgressFill');
  const countLabel = document.getElementById('answeredQuestionsCount');
  if (fill) fill.style.width = `${pct}%`;
  if (countLabel) countLabel.textContent = answered;
}

function setupQuizSubmission() {
  const submitBtn = document.getElementById('submitQuizBtn');
  if (!submitBtn) return;

  submitBtn.addEventListener('click', async () => {
    const answeredCount = Object.keys(userAnswers).length;
    if (answeredCount < quizQuestions.length) {
      const confirmIncomplete = confirm(`You have answered ${answeredCount} of ${quizQuestions.length} questions. Are you sure you want to submit?`);
      if (!confirmIncomplete) return;
    }

    submitBtn.disabled = true;
    submitBtn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Evaluating Responses...`;

    try {
      const result = await API.submitQuiz(userAnswers, 'student_user_1');
      renderQuizResults(result);
    } catch (err) {
      alert(`Submission error: ${err.message}`);
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<i class="fas fa-paper-plane"></i> Submit Assessment`;
    }
  });
}

function renderQuizResults(result) {
  // Hide quiz questions & progress
  document.getElementById('quizFormSection').style.display = 'none';

  // Show result section
  const resSection = document.getElementById('quizResultsSection');
  if (!resSection) return;
  resSection.style.display = 'block';

  // Header & score
  document.getElementById('resultOverallScore').textContent = `${result.overall_score}%`;
  document.getElementById('resultGrade').textContent = result.grade;
  document.getElementById('resultAnswerStats').textContent = `${result.correct_answers} of ${result.total_questions} questions answered correctly`;

  // Grade color
  const scoreCard = document.getElementById('resultScoreCard');
  if (result.overall_score >= 81) scoreCard.style.borderColor = '#10b981';
  else if (result.overall_score >= 61) scoreCard.style.borderColor = '#06b6d4';
  else if (result.overall_score >= 41) scoreCard.style.borderColor = '#eab308';
  else scoreCard.style.borderColor = '#ef4444';

  // Category breakdown
  const catContainer = document.getElementById('categoryBreakdownContainer');
  if (catContainer && result.category_scores) {
    catContainer.innerHTML = Object.entries(result.category_scores).map(([cat, score]) => {
      const color = score >= 80 ? '#10b981' : (score >= 60 ? '#eab308' : '#ef4444');
      return `
        <div style="margin-bottom:1rem;">
          <div style="display:flex; justify-content:space-between; font-size:0.85rem; margin-bottom:0.25rem;">
            <span style="font-weight:600; color:#fff;">${cat}</span>
            <span style="font-family:'JetBrains Mono'; font-weight:700; color:${color};">${score}%</span>
          </div>
          <div style="width:100%; height:8px; background:var(--bg-secondary); border-radius:4px; overflow:hidden;">
            <div style="width:${score}%; height:100%; background:${color}; border-radius:4px;"></div>
          </div>
        </div>
      `;
    }).join('');
  }

  // Personalized Recommendations
  const recContainer = document.getElementById('recommendationsContainer');
  if (recContainer && result.recommendations) {
    if (result.recommendations.length === 0) {
      recContainer.innerHTML = `<div style="background:rgba(16, 185, 129, 0.1); border:1px solid rgba(16, 185, 129, 0.3); border-radius:var(--radius-sm); padding:1rem; color:#34d399;"><i class="fas fa-check-circle"></i> Exceptional security awareness across all evaluated categories! No immediate remedial modules required.</div>`;
    } else {
      recContainer.innerHTML = result.recommendations.map(r => `
        <div style="background:var(--bg-secondary); border:1px solid var(--border-color); border-left:4px solid ${r.score_percent < 60 ? '#ef4444':'#eab308'}; border-radius:var(--radius-sm); padding:1rem; margin-bottom:0.75rem; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
          <div>
            <div style="font-size:0.75rem; color:${r.score_percent < 60 ? '#f87171':'#facc15'}; font-weight:700; text-transform:uppercase;">${r.urgency} &bull; ${r.category} (${r.score_percent}%)</div>
            <div style="font-size:0.9rem; color:var(--text-main); margin-top:0.2rem;">${r.recommendation}</div>
          </div>
          <a href="/awareness.html" class="btn-secondary" style="font-size:0.8rem; padding:0.4rem 0.8rem;"><i class="fas fa-book"></i> Open Module</a>
        </div>
      `).join('');
    }
  }

  // Detailed Question Review
  const reviewContainer = document.getElementById('detailedReviewContainer');
  if (reviewContainer && result.detailed_results) {
    reviewContainer.innerHTML = result.detailed_results.map((r, i) => `
      <div style="background:var(--bg-card); border:1px solid ${r.is_correct ? 'rgba(16, 185, 129, 0.2)':'rgba(239, 68, 68, 0.2)'}; border-radius:var(--radius-sm); padding:1.25rem; margin-bottom:1rem;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
          <span style="font-size:0.75rem; color:var(--accent-cyan); font-weight:700;">${r.category}</span>
          <span class="badge ${r.is_correct ? 'badge-low':'badge-critical'}">${r.is_correct ? 'Correct' : 'Incorrect'}</span>
        </div>
        <div style="font-weight:600; color:#fff; font-size:0.95rem; margin-bottom:0.75rem;">${i+1}. ${r.question}</div>
        <div style="font-size:0.85rem; color:var(--text-muted); margin-bottom:0.4rem;">
          <strong>Your Answer:</strong> <span style="font-family:'JetBrains Mono'; font-weight:700; color:${r.is_correct ? '#34d399':'#f87171'}">${r.user_answer || 'Unanswered'}</span>
          &bull; <strong>Correct:</strong> <span style="font-family:'JetBrains Mono'; font-weight:700; color:#34d399;">${r.correct_answer}</span>
        </div>
        <div style="background:var(--bg-primary); padding:0.75rem; border-radius:4px; font-size:0.82rem; color:var(--text-dim); line-height:1.5;">
          <strong>Defensive Rationale:</strong> ${r.explanation}
        </div>
      </div>
    `).join('');
  }

  window.scrollTo({ top: 0, behavior: 'smooth' });
}
