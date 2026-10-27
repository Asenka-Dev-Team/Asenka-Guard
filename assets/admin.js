(() => {
  'use strict';
  const root = document.querySelector('.ayig-wrap');
  if (!root) return;
  const boxes = [...root.querySelectorAll('.ayig-select')];
  const masters = [...root.querySelectorAll('.ayig-select-all')];
  const counters = [...root.querySelectorAll('.ayig-count')];
  function sync() {
    const selected = boxes.filter(x => x.checked).length;
    counters.forEach(c => {c.textContent = `${selected} selected`;}); boxes.forEach(b=>b.closest('tr')?.classList.toggle('ayig-selected',b.checked));
    masters.forEach(m => { m.checked = boxes.length > 0 && selected === boxes.length; m.indeterminate = selected > 0 && selected < boxes.length; });
  }
  masters.forEach(m => m.addEventListener('change', () => { boxes.forEach(b => {if(!b.closest('tr')?.hidden)b.checked = m.checked;}); sync(); }));
  // Standard Shift+click range selection; range follows visible row order.
  let lastClicked = null;
  boxes.forEach(b => {
    b.addEventListener('click', event => {
      const visible = boxes.filter(box => !box.closest('tr')?.hidden);
      if (event.shiftKey && lastClicked && visible.includes(lastClicked) && visible.includes(b)) {
        const start = visible.indexOf(lastClicked), end = visible.indexOf(b);
        for (let i = Math.min(start, end); i <= Math.max(start, end); i++) visible[i].checked = b.checked;
      }
      lastClicked = b;
      sync();
    });
    b.addEventListener('change', sync);
  });
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
      document.body.appendChild(overlay); document.documentElement.classList.add('ayig-scan-locked'); document.body.classList.add('ayig-scan-locked'); const btn = form.querySelector('button'); if (btn) {btn.disabled=true;btn.textContent='Scanning…';}
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
  const typeFilter=root.querySelector('#ayig-filter-type'), changeFilter=root.querySelector('#ayig-filter-change');
  const imageTypes=['JPG','JPEG','PNG','GIF','WEBP','AVIF','BMP','ICO'];
  function applyFilters(){
    root.querySelectorAll('.ayig-table tbody tr:not(.ayig-empty-row)').forEach(tr=>{
      const type=tr.querySelector('td[data-label="Type"]')?.textContent.trim().toUpperCase()||'';
      const typeMatch=!typeFilter||typeFilter.value==='all'||(typeFilter.value==='php'&&/^(PHP[0-9]?|PHTML|PHT|PHAR)$/.test(type))||(typeFilter.value==='image'&&imageTypes.includes(type));
      const changeMatch=!changeFilter||changeFilter.value==='all'||tr.dataset.change===changeFilter.value;
      tr.hidden=!(typeMatch&&changeMatch);if(tr.hidden){const b=tr.querySelector('.ayig-select');if(b)b.checked=false;}
    });sync();
  }
  typeFilter?.addEventListener('change',applyFilters);changeFilter?.addEventListener('change',applyFilters);

  // Latest scan change lists are derived from the saved findings; no filesystem reads here.
  const changeModal = root.querySelector('#ayig-change-modal');
  if (changeModal) {
    let lastFocus = null;
    const heading = changeModal.querySelector('#ayig-change-modal-title');
    const list = changeModal.querySelector('.ayig-change-list');
    const closeButton = changeModal.querySelector('.ayig-change-close');
    function closeChangeModal() {
      changeModal.hidden = true;
      document.removeEventListener('keydown', modalKeys);
      lastFocus?.focus();
    }
    function modalKeys(event) {
      if (event.key === 'Escape') {event.preventDefault(); closeChangeModal();}
      if (event.key === 'Tab') {
        const focusable = [...changeModal.querySelectorAll('button, a[href]')].filter(el => !el.disabled);
        if (!focusable.length) return;
        const first = focusable[0], last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) {event.preventDefault(); last.focus();}
        else if (!event.shiftKey && document.activeElement === last) {event.preventDefault(); first.focus();}
      }
    }
    root.querySelectorAll('.ayig-change-open').forEach(button => button.addEventListener('click', () => {
      const type = button.dataset.changeModal === 'changed' ? 'changed' : 'new';
      const source = root.querySelector(`.ayig-change-data[data-change="${type}"] ul`);
      heading.textContent = type === 'new' ? 'New files — latest scan' : 'Changed files — latest scan';
      list.replaceChildren();
      if (source?.children.length) list.appendChild(source.cloneNode(true));
      else {const p = document.createElement('p'); p.textContent = `No ${type} active files to display. They may have been ignored or quarantined since the scan.`; list.appendChild(p);}
      lastFocus = button;
      changeModal.hidden = false;
      closeButton.focus();
      document.addEventListener('keydown', modalKeys);
    }));
    changeModal.querySelectorAll('.ayig-change-close').forEach(button => button.addEventListener('click', closeChangeModal));
    changeModal.addEventListener('click', event => {if (event.target === changeModal) closeChangeModal();});
  }
  sync();
})();
