const $ = id => document.getElementById(id);
let lastAnalysis = null;
const API_BASE = window.location.protocol === 'file:' ? 'http://127.0.0.1:8000' : '';
const api = path => `${API_BASE}${path}`;
let selectedRecommendation = null;
let currentSlide = 1;

function showSlide(number) {
  currentSlide = number < 1 ? 3 : number > 3 ? 1 : number;
  document.querySelectorAll('[data-slide]').forEach(element => element.classList.toggle('active', Number(element.dataset.slide) === currentSlide));
  const indicator = $('slide-current');
  if (indicator) indicator.textContent = String(currentSlide).padStart(2, '0');
  document.querySelectorAll('.slide-dot').forEach(dot => dot.classList.toggle('active', Number(dot.dataset.goSlide) === currentSlide));
  document.body.classList.add('deck-ready');
  window.scrollTo({top: 0, behavior: 'smooth'});
}

function updateStats(rows) {
  $('stat-scans').textContent = rows.length;
  $('stat-findings').textContent = rows.reduce((total, row) => total + (row.finding_categories || []).length + (row.injection_signals || []).length, 0);
}

async function loadPolicies() {
  try {
    const response = await fetch(api('/api/policies'));
    if (!response.ok) throw new Error(`Gateway returned ${response.status}`);
    const policies = await response.json();
    $('policy').innerHTML = policies.map(p => `<option value="${p.id}">${p.name}</option>`).join('');
  } catch (error) {
    showError('Gateway is offline. Start it with: uvicorn app.main:app --reload, then open http://127.0.0.1:8000');
  }
}

function showError(message) {
  let banner = $('app-error');
  if (!banner) {
    banner = document.createElement('div');
    banner.id = 'app-error';
    document.querySelector('.workspace-grid').before(banner);
  }
  banner.textContent = message;
  banner.style.cssText = 'display:block;margin:0 0 18px;padding:14px 16px;border:1px solid #9b4a36;background:#3b1f1a;color:#ffb09a;font:12px DM Mono,monospace;line-height:1.5';
}

function showAnalysis(data, upstream = null) {
  lastAnalysis = data;
  selectedRecommendation = data.recommendations?.[0]?.id || null;
  const badge = $('decision');
  badge.textContent = data.decision.toUpperCase();
  badge.className = `pill ${data.decision === 'block' ? 'danger' : data.decision === 'review' ? 'warn' : ''}`;
  $('summary').innerHTML = `<strong>${data.risk_level.toUpperCase()} risk</strong><br>${data.findings.length} sensitive finding(s), ${data.injection_signals.length} injection signal(s).`;
  const findings = data.findings.map(f => `<div class="finding"><span><strong>${f.label}</strong><br><small>${f.category} · ${Math.round(f.confidence * 100)}% confidence · ${f.preview}</small></span><span class="meta">${f.action}</span></div>`).join('');
  const signals = data.injection_signals.length ? `<div class="finding"><span><strong>Prompt injection signals</strong><br><small>${data.injection_signals.join(', ')}</small></span><span class="meta">detected</span></div>` : '';
  const recommendations = (data.recommendations || []).map((item, index) => `<label class="recommendation ${index === 0 ? 'selected' : ''}"><input type="radio" name="recommendation" value="${item.id}" ${index === 0 ? 'checked' : ''}><span class="recommendation-copy"><strong>${item.title}</strong><small>${item.description}</small><code>${escapeHtml(item.prompt)}</code></span><span class="recommendation-check">✓</span></label>`).join('');
  const override = data.decision === 'block' ? '<button id="override" class="primary">Approve once and send protected prompt</button>' : '';
  $('details').innerHTML = `${signals}${findings}<div class="protected"><span class="meta">PROTECTED PAYLOAD</span><br>${escapeHtml(data.protected_prompt)}</div><div class="recommendation-heading"><span class="meta">RECOMMENDED SAFE PROMPTS</span><span>Choose one to continue</span></div><div class="recommendations">${recommendations}</div>${override}${upstream ? `<div class="protected"><span class="meta">MODEL RESPONSE · ${upstream.provider}</span><br>${escapeHtml(upstream.content || '')}</div><button id="chatgpt-handoff" class="chatgpt-button">↗ Open selected prompt in ChatGPT</button>` : ''}`;
  document.querySelectorAll('input[name="recommendation"]').forEach(input => input.onchange = () => { selectedRecommendation = input.value; document.querySelectorAll('.recommendation').forEach(card => card.classList.toggle('selected', card.querySelector('input').checked)); });
  if ($('override')) $('override').onclick = () => submit(true, true);
  if ($('chatgpt-handoff')) $('chatgpt-handoff').onclick = () => handoffToChatGPT(getSelectedPrompt());
  $('results-panel').scrollIntoView({behavior: 'smooth', block: 'nearest'});
}

function getSelectedPrompt() {
  const recommendation = (lastAnalysis?.recommendations || []).find(item => item.id === selectedRecommendation);
  return recommendation?.prompt || lastAnalysis?.protected_prompt || $('prompt').value.trim();
}

function handoffToChatGPT(prompt) {
  const url = `https://chatgpt.com/?q=${encodeURIComponent(prompt)}`;
  window.open(url, '_blank', 'noopener,noreferrer');
  if (navigator.clipboard) navigator.clipboard.writeText(prompt).catch(() => {});
}

async function submit(send, reviewOverride = false) {
  const prompt = send && lastAnalysis ? getSelectedPrompt() : $('prompt').value.trim();
  if (!prompt) return;
  $('analyze').disabled = true; $('send').disabled = true;
  $('decision').textContent = 'SCANNING…'; $('decision').className = 'pill';
  const payload = {prompt, policy_id: $('policy').value, application_id: $('application').value, user_id: 'demo-user', ...(send ? {review_override: reviewOverride} : {})};
  const endpoint = send ? '/api/requests' : '/api/analyze';
  try {
    const response = await fetch(api(endpoint), {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || `Gateway returned ${response.status}`);
    if (send) {
      showAnalysis(data.analysis, data.upstream);
      handoffToChatGPT(getSelectedPrompt());
    } else showAnalysis(data);
    await loadAudit();
  } catch (error) {
    showError(`Request failed: ${error.message}. Make sure the FastAPI gateway is running at http://127.0.0.1:8000.`);
    $('decision').textContent = 'ERROR'; $('decision').className = 'pill danger';
  } finally {
    $('analyze').disabled = false; $('send').disabled = false;
  }
}

function escapeHtml(value) { return value.replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[ch])); }
async function loadAudit() {
  let rows = [];
  try { rows = await fetch(api('/api/audit')).then(r => r.json()); } catch (_) { return; }
  updateStats(rows);
  $('audit-table').innerHTML = rows.length ? rows.map(r => `<div class="audit-row"><span>${new Date(r.timestamp).toLocaleString()}</span><strong>${r.event}</strong><span>${r.decision}</span><span class="meta">${(r.finding_categories || []).join(', ') || 'No findings'}${r.injection_signals?.length ? ' · injection' : ''}</span></div>`).join('') : 'No events yet.';
}
document.querySelectorAll('[data-example]').forEach(button => button.onclick = () => { $('prompt').value = button.dataset.example; $('prompt').focus(); });
$('analyze').onclick = () => submit(false); $('send').onclick = () => submit(true); $('refresh').onclick = loadAudit; loadPolicies(); loadAudit();
const heroPrompt = $('hero-prompt');
const heroPromptError = $('hero-prompt-error');
const enterGateway = $('enter-gateway');
if (enterGateway) enterGateway.onclick = () => {
  const value = heroPrompt?.value.trim() || '';
  if (!value) {
    if (heroPromptError) heroPromptError.textContent = 'Add a prompt first to enter the secure gateway.';
    heroPrompt?.focus();
    return;
  }
  $('prompt').value = value;
  if (heroPromptError) heroPromptError.textContent = '';
  showSlide(2);
  $('prompt').focus();
};
if (heroPrompt) heroPrompt.addEventListener('input', () => { if (heroPromptError) heroPromptError.textContent = ''; });
document.querySelectorAll('.slide-prev').forEach(button => button.onclick = () => showSlide(currentSlide - 1));
document.querySelectorAll('.slide-next').forEach(button => button.onclick = () => showSlide(currentSlide + 1));
document.querySelectorAll('.slide-dot').forEach(button => button.onclick = () => showSlide(Number(button.dataset.goSlide)));
document.querySelectorAll('nav a').forEach(link => link.onclick = event => { event.preventDefault(); showSlide(link.getAttribute('href') === '#workspace' ? 2 : 2); });
document.addEventListener('keydown', event => { if (event.key === 'ArrowRight') showSlide(currentSlide + 1); if (event.key === 'ArrowLeft') showSlide(currentSlide - 1); });
document.querySelectorAll('.slide-content[data-slide="1"], .slide-content[data-slide="3"]').forEach(slide => slide.addEventListener('mousemove', event => { const x = ((event.clientX / window.innerWidth) - .5) * 16; const y = ((event.clientY / window.innerHeight) - .5) * 8; slide.style.backgroundPosition = `calc(50% + ${x}px) calc(50% + ${y}px)`; }));
showSlide(1);
