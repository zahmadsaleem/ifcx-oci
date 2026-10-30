'use strict';
// View/edit is selected before choosing an application. Saving belongs to that application.
window.SubsoilOpenArtifactUI = async (container, credential, repository, reference, current = () => true) => {
  container.classList.add('application-controls');
  container.hidden = true;
  container.replaceChildren();
  const response = await fetch('/open-artifact/applications?' + new URLSearchParams({ repository, reference }), {
    headers: { Authorization: 'Bearer ' + await credential() }, credentials: 'omit', cache: 'no-store'
  });
  if (!response.ok) throw Error('Couldn’t find an application for these files. Please try again.');
  const data = await response.json();
  if (!current() || !data.applications.length) return;
  const menu = document.createElement('div'), message = document.createElement('p');
  menu.className = 'application-menu';
  menu.setAttribute('popover', 'auto');
  menu.setAttribute('role', 'menu');
  message.setAttribute('role', 'status');
  container.append(menu, message);
  let attempt = 0, activeTrigger;
  const triggers = [];
  function busy(value) {
    for (const button of [...triggers, ...menu.querySelectorAll('button')]) button.disabled = value;
  }
  async function launch(app, intent) {
    const ticket = ++attempt;
    busy(true);
    message.textContent = 'Opening…';
    try {
      const launched = await fetch('/open-artifact/launches', { method: 'POST',
        headers: { Authorization: 'Bearer ' + await credential(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...app.launches[intent], application_id: app.id, repository, reference: data.digest }),
        credentials: 'same-origin', cache: 'no-store' });
      if (!launched.ok) throw Error('Couldn’t open this app. Please try again.');
      const result = await launched.json();
      if (current() && ticket === attempt) location.assign(result.launch_url);
    } catch (error) {
      if (current() && ticket === attempt) message.textContent = error instanceof TypeError
        ? 'Couldn’t connect. Check your connection and try again.' : error.message;
    } finally {
      if (ticket === attempt) busy(false);
    }
  }
  for (const intent of ['view', 'edit']) {
    const apps = data.applications.filter(app => app.launches[intent]);
    if (!apps.length) continue;
    const trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.textContent = intent === 'view' ? 'Open with…' : 'Edit with…';
    if (apps.length > 1) {
      trigger.setAttribute('aria-haspopup', 'menu');
      trigger.setAttribute('aria-expanded', 'false');
    }
    trigger.onclick = () => {
      if (!current()) return;
      message.textContent = '';
      if (apps.length === 1) { launch(apps[0], intent); return; }
      if (menu.matches(':popover-open')) { menu.hidePopover(); return; }
      activeTrigger = trigger;
      menu.setAttribute('aria-label', intent === 'view' ? 'Open with' : 'Edit with');
      menu.replaceChildren(...apps.map(app => {
        const button = document.createElement('button');
        button.type = 'button';
        button.setAttribute('role', 'menuitem');
        button.textContent = app.name;
        button.onclick = () => { menu.hidePopover(); launch(app, intent); };
        return button;
      }));
      menu.showPopover();
      const anchor = trigger.getBoundingClientRect(), bounds = menu.getBoundingClientRect();
      menu.style.left = Math.max(8, Math.min(anchor.left, innerWidth - bounds.width - 8)) + 'px';
      menu.style.top = (anchor.bottom + 4 + bounds.height <= innerHeight - 8
        ? anchor.bottom + 4 : Math.max(8, anchor.top - bounds.height - 4)) + 'px';
      trigger.setAttribute('aria-expanded', 'true');
      menu.querySelector('button').focus();
    };
    triggers.push(trigger);
    container.insertBefore(trigger, menu);
  }
  menu.ontoggle = event => {
    if (event.newState === 'closed' && activeTrigger) activeTrigger.setAttribute('aria-expanded', 'false');
  };
  menu.onkeydown = event => {
    const items = [...menu.querySelectorAll('button')], index = items.indexOf(document.activeElement);
    if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
      event.preventDefault();
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? items.length - 1
        : (index + (event.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length;
      items[next].focus();
    } else if (event.key === 'Escape') {
      event.preventDefault(); menu.hidePopover(); activeTrigger.focus();
    } else if (event.key === 'Tab') { menu.hidePopover(); activeTrigger.focus(); }
  };
  container.hidden = false;
};
