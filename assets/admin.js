(() => {
  'use strict';
  const root = document.querySelector('.ayig-wrap');
  if (!root) return;
  const boxes = [...root.querySelectorAll('.ayig-select')];
  const masters = [...root.querySelectorAll('.ayig-select-all')];
  const counter = root.querySelector('.ayig-count');
  function sync() {
    const selected = boxes.filter(x => x.checked).length;
    if (counter) counter.textContent = `${selected} selected`;
    masters.forEach(m => { m.checked = boxes.length > 0 && selected === boxes.length; m.indeterminate = selected > 0 && selected < boxes.length; });
  }
  masters.forEach(m => m.addEventListener('change', () => { boxes.forEach(b => b.checked = m.checked); sync(); }));
  boxes.forEach(b => b.addEventListener('change', sync));
  const highlight = root.querySelector('#ayig-highlight');
  if (highlight) {
    const set = () => root.classList.toggle('ayig-no-highlight', !highlight.checked);
    highlight.addEventListener('change', set); set();
  }
  root.querySelectorAll('[data-confirm]').forEach(button => button.closest('form')?.addEventListener('submit', e => {
    if (!window.confirm(button.dataset.confirm)) e.preventDefault();
  }));
  const bulk = root.querySelector('#ayig-bulk-form');
  if (bulk) bulk.addEventListener('submit', e => {
    const selected = boxes.filter(x => x.checked).length;
    if (!selected) { e.preventDefault(); window.alert('Select at least one file.'); return; }
    if (selected > 200) { e.preventDefault(); window.alert('Select up to 200 files per action.'); return; }
    const op = bulk.querySelector('select[name=operation]')?.value;
    if (op === 'delete' && !window.confirm(`Permanently delete ${selected} quarantined files? This cannot be undone.`)) e.preventDefault();
    else if (op === 'quarantine' && !window.confirm(`Quarantine ${selected} selected files?`)) e.preventDefault();
  });
  root.querySelectorAll('form.ayig-inline-form').forEach(form => {
    if (form.querySelector('input[name=operation]')?.value !== 'scan') return;
    form.addEventListener('submit', () => {
      const overlay = document.createElement('div'); overlay.className = 'ayig-scanning';
      overlay.setAttribute('role', 'status'); overlay.innerHTML = '<span class="ayig-spinner" aria-hidden="true"></span><strong>Scanning uploads…</strong><span>Please keep this tab open. Results will appear when the scan finishes.</span>';
      document.body.appendChild(overlay); const btn = form.querySelector('button'); if (btn) {btn.disabled=true;btn.textContent='Scanning…';}
    });
  });
  sync();
})();
