// State variables
let currentSequence = 0;
let isFetching = false;
let selectedIp = null;
let pollTimer = null;

// DOM Elements
const errorBar = document.getElementById('error-bar');
const statsTotal = document.getElementById('stats-total');
const statsIps = document.getElementById('stats-ips');
const statsHigh = document.getElementById('stats-high');
const statsMedium = document.getElementById('stats-medium');
const statsLow = document.getElementById('stats-low');

const attackersTbody = document.getElementById('attackers-tbody');
const feedTbody = document.getElementById('feed-tbody');

const detailPanel = document.getElementById('detail-panel');
const detailEmpty = document.getElementById('detail-empty');
const detailIp = document.getElementById('detail-ip');
const detailBadge = document.getElementById('detail-badge');
const detailSummary = document.getElementById('detail-summary');
const detailTools = document.getElementById('detail-tools');
const detailUsernames = document.getElementById('detail-usernames');
const detailPasswords = document.getElementById('detail-passwords');
const detailPaths = document.getElementById('detail-paths');
const detailTimeline = document.getElementById('detail-timeline');

// Valid levels map to safe CSS classes
const BADGE_CLASSES = {
  High: 'badge-High',
  Medium: 'badge-Medium',
  Low: 'badge-Low',
  None: 'badge-None'
};

function getBadgeClass(level) {
  return BADGE_CLASSES[level] || 'badge-None';
}

function formatDate(isoString) {
  if (!isoString) return '';
  try {
    return new Date(isoString).toLocaleString();
  } catch (e) {
    return isoString;
  }
}

async function fetchJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function renderStats(stats) {
  statsTotal.textContent = stats.total_events || 0;
  statsIps.textContent = stats.unique_ips || 0;
  statsHigh.textContent = stats.levels.High || 0;
  statsMedium.textContent = stats.levels.Medium || 0;
  statsLow.textContent = stats.levels.Low || 0;
}

function createTableCell(text, title = null) {
  const td = document.createElement('td');
  td.textContent = text;
  if (title) {
    td.setAttribute('title', title);
  }
  return td;
}

function renderAttackers(attackers) {
  attackersTbody.textContent = ''; // Fast clear (safe)
  
  if (!attackers || attackers.length === 0) {
    const tr = document.createElement('tr');
    tr.className = 'empty-state';
    const td = document.createElement('td');
    td.setAttribute('colspan', '6');
    td.textContent = 'No attackers yet.';
    tr.appendChild(td);
    attackersTbody.appendChild(tr);
    return;
  }

  attackers.forEach(a => {
    const tr = document.createElement('tr');
    tr.className = 'clickable-row';
    if (a.ip === selectedIp) {
      tr.classList.add('selected-row');
    }
    tr.addEventListener('click', () => selectAttacker(a.ip));

    const tdIp = createTableCell(a.ip);
    
    const tdLevel = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = 'badge ' + getBadgeClass(a.level);
    badge.textContent = a.level || 'None';
    tdLevel.appendChild(badge);

    const tdScore = createTableCell(a.score);
    const tdEvents = createTableCell(a.total_events);
    const tdSeen = createTableCell(formatDate(a.last_seen), a.last_seen);
    const tdSummary = createTableCell(a.summary);

    tr.appendChild(tdIp);
    tr.appendChild(tdLevel);
    tr.appendChild(tdScore);
    tr.appendChild(tdEvents);
    tr.appendChild(tdSeen);
    tr.appendChild(tdSummary);
    
    attackersTbody.appendChild(tr);
  });
}

function renderFeed(events) {
  feedTbody.textContent = '';
  
  if (!events || events.length === 0) {
    const tr = document.createElement('tr');
    tr.className = 'empty-state';
    const td = document.createElement('td');
    td.setAttribute('colspan', '6');
    td.textContent = 'No events yet.';
    tr.appendChild(td);
    feedTbody.appendChild(tr);
    return;
  }

  events.forEach(e => {
    const tr = document.createElement('tr');
    tr.appendChild(createTableCell(formatDate(e.timestamp), e.timestamp));
    tr.appendChild(createTableCell(e.source_ip));
    tr.appendChild(createTableCell(e.protocol));
    tr.appendChild(createTableCell(e.port));
    tr.appendChild(createTableCell(e.method || ''));
    
    let detail = e.path || '';
    if (e.username) detail += (detail ? ' ' : '') + `u:${e.username}`;
    if (e.password) detail += (detail ? ' ' : '') + `p:${e.password}`;
    tr.appendChild(createTableCell(detail));
    
    feedTbody.appendChild(tr);
  });
}

async function selectAttacker(ip) {
  if (selectedIp === ip) return;
  selectedIp = ip;
  
  // Update highlight visually before next polling cycle
  const rows = attackersTbody.querySelectorAll('tr');
  rows.forEach(r => {
    const rowIp = r.firstElementChild?.textContent;
    if (rowIp === ip) r.classList.add('selected-row');
    else r.classList.remove('selected-row');
  });

  await fetchSelectedAttackerDetails();
}

function renderList(container, items, formatFn) {
  container.textContent = '';
  if (!items || items.length === 0) {
    const li = document.createElement('li');
    li.textContent = '-';
    container.appendChild(li);
    return;
  }
  items.forEach(item => {
    const li = document.createElement('li');
    li.textContent = formatFn(item);
    container.appendChild(li);
  });
}

async function fetchSelectedAttackerDetails() {
  if (!selectedIp) {
    detailPanel.classList.add('hidden');
    detailEmpty.classList.remove('hidden');
    return;
  }

  // Validate IP format
  if (!/^[a-fA-F0-9.:]+$/.test(selectedIp)) {
    return;
  }

  try {
    const data = await fetchJson(`/api/attackers/${encodeURIComponent(selectedIp)}`);
    
    detailEmpty.classList.add('hidden');
    detailPanel.classList.remove('hidden');

    detailIp.textContent = selectedIp;
    
    const level = data.assessment?.level || 'None';
    detailBadge.textContent = level;
    detailBadge.className = 'badge ' + getBadgeClass(level);

    detailSummary.textContent = data.assessment?.summary || 'No data';
    detailTools.textContent = (data.assessment?.tool_hints || []).join(', ') || 'None';

    renderList(detailUsernames, data.profile?.top_usernames, x => `${x.username} (${x.count})`);
    renderList(detailPasswords, data.profile?.top_passwords, x => `${x.password} (${x.count})`);
    renderList(detailPaths, data.profile?.paths_probed, x => `${x.path} (${x.count})`);

    // Render Timeline
    detailTimeline.textContent = '';
    const timeline = data.timeline || [];
    if (timeline.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.setAttribute('colspan', '5');
      td.textContent = 'No events.';
      tr.appendChild(td);
      detailTimeline.appendChild(tr);
    } else {
      timeline.forEach(e => {
        const tr = document.createElement('tr');
        tr.appendChild(createTableCell(formatDate(e.timestamp), e.timestamp));
        tr.appendChild(createTableCell(e.protocol));
        tr.appendChild(createTableCell(e.port));
        tr.appendChild(createTableCell(e.method || ''));
        tr.appendChild(createTableCell(e.detail || ''));
        detailTimeline.appendChild(tr);
      });
    }

  } catch (err) {
    console.error('Error fetching details:', err);
    // Do not crash, keep showing what we have or blank out
  }
}

async function pollCycle() {
  if (isFetching || document.hidden) return;
  isFetching = true;
  currentSequence++;
  const seq = currentSequence;

  try {
    const [stats, attackers, events] = await Promise.all([
      fetchJson('/api/stats'),
      fetchJson('/api/attackers'),
      fetchJson('/api/events')
    ]);

    if (seq !== currentSequence) return; // Stale

    errorBar.classList.add('hidden');

    renderStats(stats);
    renderAttackers(attackers);
    renderFeed(events);

    if (selectedIp) {
      await fetchSelectedAttackerDetails();
    }
  } catch (err) {
    if (seq === currentSequence) {
      errorBar.classList.remove('hidden');
    }
  } finally {
    if (seq === currentSequence) {
      isFetching = false;
      // Schedule next poll ONLY after this one finishes
      scheduleNext();
    }
  }
}

function scheduleNext() {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(() => {
    pollCycle();
  }, 3000);
}

// Restart cycle immediately if tab becomes visible
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) {
    clearTimeout(pollTimer);
    isFetching = false; // Reset state if it was hung
    pollCycle();
  }
});

// Initial kick-off
pollCycle();
