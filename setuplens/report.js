(() => {
  'use strict';
  const cards = [...document.querySelectorAll('.finding')];
  const buttons = [...document.querySelectorAll('[data-filter]')];
  const search = document.getElementById('search');
  let priority = 'all';
  const update = () => {
    const query = search.value.trim().toLowerCase();
    let shown = 0;
    cards.forEach(card => {
      const match = (priority === 'all' || card.dataset.priority === priority) && card.textContent.toLowerCase().includes(query);
      card.hidden = !match;
      if (match) shown++;
    });
    document.getElementById('count').textContent = `${shown} of ${cards.length} findings`;
    document.getElementById('empty').hidden = shown !== 0;
  };
  buttons.forEach(button => button.addEventListener('click', () => {
    priority = button.dataset.filter;
    buttons.forEach(other => {
      const selected = other === button;
      other.classList.toggle('selected', selected);
      other.setAttribute('aria-pressed', String(selected));
    });
    update();
  }));
  search.addEventListener('input', update);
  document.getElementById('print').addEventListener('click', () => window.print());
})();
