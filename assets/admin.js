(() => {
  'use strict';
  const root = document.querySelector('.ayig-wrap');
  if (!root) return;
  const boxes = [...root.querySelectorAll('.ayig-select')];
  const masters = [...root.querySelectorAll('.ayig-select-all')];
  const counters = [...root.querySelectorAll('.ayig-count')];
  function sync() {
    const selected = boxes.filter(x => x.checked).length;
    counters.forEach(c => {c.textContent = `${selected} selected`;});
    masters.forEach(m => { m.checked = boxes.length > 0 && selected === boxes.length; m.indeterminate = selected > 0 && selected < boxes.length; });
  }
  masters.forEach(m => m.addEventListener('change', () => { boxes.forEach(b => b.checked = m.checked); sync(); }));
  boxes.forEach(b => b.addEventListener('change', sync));
  const topOperation = root.querySelector('#ayig-bulk-form select[name=operation]');
  const bottomOperation = root.querySelector('.ayig-bottom-operation');
  if (topOperation && bottomOperation) {
    bottomOperation.value = topOperation.value;
    topOperation.addEventListener('change', () => { bottomOperation.value = topOperation.value; });
    bottomOperation.addEventListener('change', () => { topOperation.value = bottomOperation.value; });
  }
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
      overlay.setAttribute('role', 'status'); overlay.innerHTML = `<span class="ayig-spinner" aria-hidden="true"></span><strong>Scanning ${form.querySelector('input[name=tab]')?.value === 'site' ? 'site' : 'uploads'}…</strong><span>Please keep this tab open. Results will appear when the scan finishes.</span>`;
      document.body.appendChild(overlay); const btn = form.querySelector('button'); if (btn) {btn.disabled=true;btn.textContent='Scanning…';}
    });
  });
  const needleInput=root.querySelector('#ayig-name-filter');
  const pathMode=root.querySelector('#ayig-match-path');
  const matchCount=root.querySelector('#ayig-matches');
  function matchingBoxes(){
    const q=needleInput?.value.trim().toLowerCase();
    if(!q)return [];
    return boxes.filter(box=>{
      const file=box.closest('tr')?.querySelector('.ayig-path')?.textContent||'';
      const source=pathMode?.checked?file:file.split(/[\\/]/).pop();
      return source.toLowerCase().includes(q);
    });
  }
  function showMatches(){if(matchCount)matchCount.textContent=needleInput?.value.trim()?`${matchingBoxes().length} matching`:'';}
  [needleInput,pathMode].forEach(el=>el?.addEventListener('input',showMatches));
  root.querySelector('#ayig-select-match')?.addEventListener('click',()=>{matchingBoxes().forEach(b=>{b.checked=true;});sync();});
  root.querySelector('#ayig-unselect-match')?.addEventListener('click',()=>{matchingBoxes().forEach(b=>{b.checked=false;});sync();});
  root.querySelectorAll('.ayig-copy').forEach(b=>b.addEventListener('click',async()=>{
    const path=b.dataset.copy||'';
    try{await navigator.clipboard.writeText(path);b.textContent='Copied!';setTimeout(()=>b.textContent='Copy path',1300);}
    catch(e){window.prompt('Copy file path:',path);}
  }));
  sync();
})();
