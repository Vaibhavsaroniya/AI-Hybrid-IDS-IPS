// ==========================================================
// AMBIENT NETWORK-TOPOLOGY BACKGROUND (signature element)
// Slow-moving nodes with faint connecting lines when close.
// Purely decorative, respects prefers-reduced-motion.
// ==========================================================

function initAmbientCanvas() {
  const canvas = document.getElementById('ambient-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  let w, h, nodes;

  function resize() {
    w = canvas.width = window.innerWidth;
    h = canvas.height = window.innerHeight;
  }

  function makeNodes() {
    const count = Math.round((w * h) / 42000);
    nodes = Array.from({ length: count }, () => ({
      x: Math.random() * w,
      y: Math.random() * h,
      vx: (Math.random() - 0.5) * 0.15,
      vy: (Math.random() - 0.5) * 0.15,
    }));
  }

  function tick() {
    ctx.clearRect(0, 0, w, h);
    for (const n of nodes) {
      n.x += n.vx;
      n.y += n.vy;
      if (n.x < 0 || n.x > w) n.vx *= -1;
      if (n.y < 0 || n.y > h) n.vy *= -1;
    }
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[i].x - nodes[j].x;
        const dy = nodes[i].y - nodes[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 130) {
          ctx.strokeStyle = `rgba(69, 224, 216, ${0.12 * (1 - dist / 130)})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(nodes[i].x, nodes[i].y);
          ctx.lineTo(nodes[j].x, nodes[j].y);
          ctx.stroke();
        }
      }
    }
    for (const n of nodes) {
      ctx.fillStyle = 'rgba(69, 224, 216, 0.5)';
      ctx.beginPath();
      ctx.arc(n.x, n.y, 1.4, 0, Math.PI * 2);
      ctx.fill();
    }
    if (!reduceMotion) requestAnimationFrame(tick);
  }

  resize();
  makeNodes();
  window.addEventListener('resize', () => { resize(); makeNodes(); });
  tick();
}

// ==========================================================
// SHARED HELPERS
// ==========================================================

const API = '/api';

async function getJSON(path) {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return res.json();
}

function severityLevel(sev) {
  const s = (sev || 'NONE').toUpperCase();
  return ['HIGH', 'MEDIUM', 'LOW', 'NONE'].includes(s) ? s : 'NONE';
}

function timeAgo(iso) {
  if (!iso) return '';
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return `${Math.max(0, Math.round(diff))}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  return `${Math.round(diff / 3600)}h ago`;
}

function animateCount(el, target) {
  const start = parseInt(el.dataset.value || '0', 10);
  const diff = target - start;
  if (diff === 0) return;
  const duration = 500;
  const startTime = performance.now();
  function step(now) {
    const progress = Math.min(1, (now - startTime) / duration);
    const value = Math.round(start + diff * progress);
    el.textContent = value.toLocaleString();
    if (progress < 1) requestAnimationFrame(step);
    else el.dataset.value = target;
  }
  requestAnimationFrame(step);
}

// ==========================================================
// OVERVIEW PAGE
// ==========================================================

let severityChart, timelineChart;

async function refreshSummary() {
  const s = await getJSON(`${API}/summary`);
  animateCount(document.getElementById('metric-total'), s.total);
  animateCount(document.getElementById('metric-normal'), s.normal);
  animateCount(document.getElementById('metric-suspicious'), s.suspicious);
  animateCount(document.getElementById('metric-threat'), s.threat);

  const pill = document.getElementById('status-pill');
  const label = document.getElementById('status-label');
  if (s.capturing) {
    pill.classList.remove('idle');
    label.textContent = 'CAPTURING';
  } else {
    pill.classList.add('idle');
    label.textContent = 'IDLE';
  }
}

async function refreshAlerts() {
  const alerts = await getJSON(`${API}/alerts?limit=40`);
  const feed = document.getElementById('alert-feed');
  const badge = document.getElementById('alert-count-badge');
  badge.textContent = alerts.length;

  if (alerts.length === 0) {
    feed.innerHTML = `<div class="empty-state">No alerts yet — all clear.</div>`;
    return;
  }

  feed.innerHTML = alerts.map(a => {
    const sev = severityLevel(a.severity);
    return `
      <div class="alert-item">
        <div class="alert-bar ${sev}"></div>
        <div class="alert-main">
          <span class="sev-badge ${sev}">${sev}</span>
          <div class="alert-endpoints">${a.source} &rarr; ${a.destination || '—'}</div>
          <div class="alert-reason">${a.rule_alerts && a.rule_alerts !== 'None' ? a.rule_alerts : a.ai_prediction || 'Threat pattern detected'}</div>
        </div>
        <div class="alert-meta">${timeAgo(a.time)}</div>
      </div>
    `;
  }).join('');
}

async function refreshTopOffenders() {
  const data = await getJSON(`${API}/top-offenders?limit=8`);
  const el = document.getElementById('top-offenders');
  if (data.length === 0) {
    el.innerHTML = `<div class="empty-state">No offending sources yet.</div>`;
    return;
  }
  const max = Math.max(...data.map(d => d.count));
  el.innerHTML = data.map(d => `
    <div class="offender-row">
      <span>${d.source}</span>
      <div class="offender-bar-track">
        <div class="offender-bar-fill" style="width:${(d.count / max) * 100}%"></div>
      </div>
      <span>${d.count}</span>
    </div>
  `).join('');
}

async function refreshSeverityChart() {
  const data = await getJSON(`${API}/charts/severity`);
  const labels = ['NONE', 'LOW', 'MEDIUM', 'HIGH'];
  const values = labels.map(l => data[l] || 0);
  const colors = ['#56637a', '#60a5fa', '#f5a623', '#f0455a'];

  if (!severityChart) {
    const ctx = document.getElementById('severity-chart');
    severityChart = new Chart(ctx, {
      type: 'doughnut',
      data: { labels, datasets: [{ data: values, backgroundColor: colors, borderWidth: 0 }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        cutout: '68%',
        plugins: { legend: { position: 'right', labels: { color: '#8b98ac', font: { family: 'JetBrains Mono', size: 11 }, boxWidth: 10 } } },
      },
    });
  } else {
    severityChart.data.datasets[0].data = values;
    severityChart.update();
  }
}

async function refreshTimelineChart() {
  const data = await getJSON(`${API}/charts/timeline?minutes=30`);

  if (!timelineChart) {
    const ctx = document.getElementById('timeline-chart');
    timelineChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: data.labels,
        datasets: [
          { label: 'Normal', data: data.normal, borderColor: '#34d399', backgroundColor: 'rgba(52,211,153,0.08)', fill: true, tension: 0.35, pointRadius: 0, borderWidth: 1.5 },
          { label: 'Suspicious', data: data.suspicious, borderColor: '#f5a623', backgroundColor: 'rgba(245,166,35,0.08)', fill: true, tension: 0.35, pointRadius: 0, borderWidth: 1.5 },
          { label: 'Threat', data: data.threat, borderColor: '#f0455a', backgroundColor: 'rgba(240,69,90,0.1)', fill: true, tension: 0.35, pointRadius: 0, borderWidth: 1.5 },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        interaction: { mode: 'index', intersect: false },
        scales: {
          x: { ticks: { color: '#56637a', font: { family: 'JetBrains Mono', size: 10 }, maxTicksLimit: 6 }, grid: { color: 'rgba(255,255,255,0.03)' } },
          y: { ticks: { color: '#56637a', font: { family: 'JetBrains Mono', size: 10 } }, grid: { color: 'rgba(255,255,255,0.03)' }, beginAtZero: true },
        },
        plugins: { legend: { position: 'top', align: 'end', labels: { color: '#8b98ac', font: { family: 'JetBrains Mono', size: 10 }, boxWidth: 8 } } },
      },
    });
  } else {
    timelineChart.data.labels = data.labels;
    timelineChart.data.datasets[0].data = data.normal;
    timelineChart.data.datasets[1].data = data.suspicious;
    timelineChart.data.datasets[2].data = data.threat;
    timelineChart.update();
  }
}

async function pollOverview() {
  try {
    await Promise.all([
      refreshSummary(), refreshAlerts(), refreshTopOffenders(),
      refreshSeverityChart(), refreshTimelineChart(),
    ]);
  } catch (e) {
    console.error('Poll failed', e);
  }
}

function initOverviewPage() {
  pollOverview();
  setInterval(pollOverview, 3000);
}

// ==========================================================
// EVENT LOG PAGE
// ==========================================================

let currentPage = 1;
const PAGE_SIZE = 50;

async function loadEvents() {
  const severity = document.getElementById('filter-severity').value;
  const source = document.getElementById('filter-source').value;

  const params = new URLSearchParams({ page: currentPage, page_size: PAGE_SIZE });
  if (severity && severity !== 'ALL') params.set('severity', severity);
  if (source) params.set('source', source);

  const data = await getJSON(`${API}/events?${params.toString()}`);
  const tbody = document.getElementById('events-tbody');

  if (data.events.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" class="empty-state">No events match these filters.</td></tr>`;
  } else {
    tbody.innerHTML = data.events.map(e => `
      <tr>
        <td>${e.Time}</td>
        <td>${e.Source}</td>
        <td>${e.Destination}</td>
        <td>${e.Protocol}</td>
        <td>${e['Destination Port']}</td>
        <td>${e['AI Prediction']}</td>
        <td><span class="sev-badge ${severityLevel(e.Severity)}">${severityLevel(e.Severity)}</span></td>
        <td>${e['Rule Alerts']}</td>
        <td>${e['Final Decision']}</td>
      </tr>
    `).join('');
  }

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE));
  document.getElementById('page-info').textContent = `Page ${data.page} of ${totalPages} — ${data.total.toLocaleString()} events`;
  document.getElementById('prev-page').disabled = currentPage <= 1;
  document.getElementById('next-page').disabled = currentPage >= totalPages;
}

function initHistoryPage() {
  loadEvents();

  document.getElementById('filter-severity').addEventListener('change', () => { currentPage = 1; loadEvents(); });
  document.getElementById('filter-source').addEventListener('input', debounce(() => { currentPage = 1; loadEvents(); }, 350));
  document.getElementById('prev-page').addEventListener('click', () => { currentPage--; loadEvents(); });
  document.getElementById('next-page').addEventListener('click', () => { currentPage++; loadEvents(); });

  setInterval(() => { if (currentPage === 1) loadEvents(); }, 5000);
}

function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

// ==========================================================
// BOOT
// ==========================================================

document.addEventListener('DOMContentLoaded', () => {
  initAmbientCanvas();
  const page = document.body.dataset.page;
  if (page === 'overview') initOverviewPage();
  if (page === 'history') initHistoryPage();
});
