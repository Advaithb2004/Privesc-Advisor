const input = document.querySelector('#input');
const out = document.querySelector('#out');

function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function pct(v) { return `${Math.round(Number(v || 0) * 100)}%`; }
function riskClass(label) { return String(label || '').toLowerCase(); }

function toggleCard(id) {
  const card = document.getElementById(id);
  if (!card) return;
  card.classList.toggle('open');
  const button = card.querySelector('.expand-btn');
  if (button) button.textContent = card.classList.contains('open') ? 'Hide details' : 'View details';
}
window.toggleCard = toggleCard;

document.querySelector('#file').onchange = e => {
  const f = e.target.files[0];
  if (!f) return;
  const r = new FileReader();
  r.onload = () => input.value = r.result;
  r.readAsText(f);
};

document.querySelector('#sample').onclick = () => {
  input.value = `Ubuntu 16.04\nLinux target 4.4.0-21-generic\nUser: www-data\n\nSudo permissions:\n(root) NOPASSWD: /usr/bin/find\n\nSUID files:\n-rwsr-xr-x root root /usr/bin/find\n\nFile capabilities:\n/usr/bin/python3 = cap_setuid+ep\n\n/usr/bin/pkexec\nCVE-2021-4034 PwnKit\n`;
};

document.querySelector('#go').onclick = async () => {
  out.innerHTML = '<div class="loading">Analyzing target configuration…</div>';
  try {
    const r = await fetch('/api/analyze', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({raw_text: input.value})
    });
    const d = await r.json();
    if (!r.ok || d.error) throw new Error(d.error || 'Analysis failed');
    render(d);
  } catch (err) {
    out.innerHTML = `<div class="error">Analysis failed: ${esc(err.message)}</div>`;
  }
};

function render(d) {
  const active = d.active_features || [];
  const recommendations = d.recommendations || [];
  const risk = d.risk || {score:0,label:'LOW'};

  const chips = active.map(f => `<span class="chip">${esc(f)}</span>`).join('');
  const shapRows = (d.shap || []).map(s => {
    const val = Number(s.value || 0);
    const width = Math.min(100, Math.max(4, Math.abs(val) * 100));
    const positive = val >= 0;
    return `<div class="shap-row"><div class="shap-label"><span>${esc(s.feature)}</span><b>${val.toFixed(3)}</b></div><div class="shap-track"><span class="shap-bar ${positive ? 'positive' : 'negative'}" style="width:${width}%"></span></div></div>`;
  }).join('');

  // Use one shared scale across all recommendations. Per-card normalization made
  // different SHAP explanations look almost identical even when their values differed.
  const allPathShap = recommendations.flatMap(r => (r.shap || []).map(s => Math.abs(Number(s.value || 0))));
  const sharedShapMax = Math.max(0.000001, ...allPathShap);

  const cards = recommendations.map((x, idx) => {
    const id = `rec-${idx}`;
    const steps = (x.steps || []).map((s, i) => `
      <div class="step">
        <span class="step-num">${i + 1}</span>
        <div class="step-content"><div class="step-title">${esc(s[0])}</div><pre><code>${esc(s[1])}</code></pre></div>
      </div>`).join('');
    const mitigations = (x.mitigations || []).map(m => `<li>✓ ${esc(m)}</li>`).join('');
    const cve = x.cve ? `<span class="tag purple">${esc(x.cve)}</span>` : '';
    const evidence = x.evidence ? `<span class="evidence">Evidence: ${esc(x.evidence)}</span>` : '';
    // Each card uses its own class-specific SHAP values from the API.
    const pathShapValues = x.shap || [];
    const shapForPath = pathShapValues.slice(0, 5).map(s => {
      const v = Number(s.value || 0);
      // Same axis for every card makes magnitude differences visible.
      const width = Math.max(1, Math.min(100, Math.abs(v) / sharedShapMax * 100));
      const sign = v > 0 ? '+' : '';
      return `<div class="path-shap"><div><span>${esc(s.feature)}</span><b>${sign}${v.toFixed(4)}</b></div><div class="mini-track"><span class="${v >= 0 ? 'positive' : 'negative'}" style="width:${width}%"></span></div></div>`;
    }).join('');

    return `
      <article class="recommendation" id="${id}">
        <div class="rec-head">
          <div class="rank">#${x.rank}</div>
          <div class="rec-title"><h2>${esc(x.name)}</h2><div class="tags"><span class="tag category">${esc(x.category)}</span><span class="tag detection">● ${esc(x.detection)} DETECTION</span><span class="tag novelty">✦ ${esc(x.novelty)} NOVELTY</span>${cve}<span class="tag complexity">⚙ ${esc(x.complexity)}</span>${evidence}</div></div>
          <div class="prob"><strong>${pct(x.probability)}</strong><small>SUCCESS PROB.</small></div>
          <button class="expand-btn" onclick="toggleCard('${id}')">View details</button>
        </div>
        <div class="collapsed-desc">${esc(x.description)}</div>
        <div class="details">
          <div class="detail-top">
            <section class="exploit-panel">
              <h3>📋 EXPLOITATION CHAIN</h3>
              ${steps || '<p>No command guide available for this path.</p>'}
            </section>
            <section class="shap-panel">
              <h3>🧠 SHAP EXPLANATION — WHY THIS PATH?</h3>
              <p class="muted">Class-specific feature contributions for ${esc(x.name)}. Positive values support this class; negative values oppose it.</p>
              ${shapForPath || '<p class="muted">No feature attribution available for this class.</p>'}
              <div class="score-line"><span>Recommendation score</span><b>${pct(x.score)}</b></div>
            </section>
          </div>
          <div class="detail-bottom">
            <section><h3>🛡 MITIGATIONS</h3><ul class="mitigations">${mitigations}</ul></section>
            <section><h3>📊 PATH DETAILS</h3><div class="path-details"><div><span>Category</span><b>${esc(x.category)}</b></div><div><span>Complexity</span><b>${esc(x.complexity)}</b></div><div><span>Detection Risk</span><b>${esc(x.detection)}</b></div><div><span>Novelty</span><b>${esc(x.novelty)}</b></div><div><span>CVE</span><b>${esc(x.cve || 'N/A')}</b></div><div><span>Confidence Score</span><b>${pct(x.probability)}</b></div></div></section>
          </div>
          <div class="lab-note">Commands are displayed for authorized lab/CTF testing. PrivEsc Advisor does not execute exploit commands.</div>
        </div>
      </article>`;
  }).join('');

  const cvResults = d.cv_results || {};
  const holdoutResults = d.evaluation_results || {};
  const modelNames = [...new Set([...Object.keys(cvResults), ...Object.keys(holdoutResults)])];
  const metricPct = v => `${(Number(v || 0) * 100).toFixed(2)}%`;
  const evaluationRows = modelNames.map(name => {
    const cv = cvResults[name] || {};
    const test = holdoutResults[name] || {};
    const cvAcc = cv.accuracy || {};
    const cvF1 = cv.f1_weighted || {};
    return `<tr><td>${esc(name)}</td><td>${metricPct(cvAcc.mean)}</td><td>${metricPct(cvF1.mean)}</td><td>${metricPct(test.accuracy)}</td><td>${metricPct(test.precision)}</td><td>${metricPct(test.recall)}</td><td>${metricPct(test.f1)}</td></tr>`;
  }).join('');
  const evaluationPanel = modelNames.length ? `<section class="global-shap evaluation-panel"><h2>📈 Model Validation: ${Number(d.cv_folds || 0)}-Fold Stratified Cross-Validation</h2><p>Cross-validation scores are averaged over folds from the training split. Hold-out metrics are measured separately on the reserved test split.</p><div class="evaluation-scroll"><table class="evaluation-table"><thead><tr><th>Model</th><th>CV Accuracy</th><th>CV Weighted F1</th><th>Test Accuracy</th><th>Test Precision</th><th>Test Recall</th><th>Test F1</th></tr></thead><tbody>${evaluationRows}</tbody></table></div></section>` : '';

  out.innerHTML = `
    <div class="system-bar">
      <span>OS ${esc(d.metadata?.os || 'Unknown')}</span><span>KERNEL ${esc(d.metadata?.kernel || 'Unknown')}</span><span>HOST ${esc(d.metadata?.hostname || 'Unknown')}</span><span>USER ${esc(d.metadata?.current_user || 'Unknown')}</span>
    </div>
    <div class="risk-card">
      <div class="risk-ring ${riskClass(risk.label)}"><strong>${risk.score}%</strong><small>${esc(risk.label)}</small></div>
      <div class="risk-main"><h1>System Risk: ${esc(risk.label)}</h1><p>${active.length} active findings detected · ${recommendations.length} escalation paths identified</p><div class="chips">${chips || '<span class="muted">No active findings</span>'}</div></div>
      <div class="risk-side"><b>${recommendations.length} paths ranked</b><span>SHAP attributed</span></div>
    </div>
    <div class="model-strip">Model: ${esc(d.model || 'Unknown')} · Dataset: ${d.dataset_rows || 0} scenarios · Classes: ${d.class_count || 0}</div>
    <div class="cards">${cards || '<div class="empty-state">No supported privilege escalation path was detected.</div>'}</div>
    ${evaluationPanel}
    <section class="global-shap"><h2>🧠 Global SHAP Feature Attribution</h2><p>Feature contribution for the model prediction. Positive values support the predicted class; negative values move away from it.</p>${shapRows || '<p class="muted">No SHAP values available.</p>'}</section>`;
}
