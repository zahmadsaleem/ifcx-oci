'use strict';
// Shared controls for the registry's file browser and expiring share page.
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
  const heading = document.createElement('h3');
  heading.textContent = 'Open with…';
  const form = document.createElement('form'), select = document.createElement('select');
  select.setAttribute('aria-label', 'Application and access');
  const choices = [];
  for (const app of data.applications) {
    for (const intent of app.intents) {
      const choice = { app, intent }, option = document.createElement('option');
      option.value = String(choices.length);
      option.textContent = app.name + (intent === 'view' ? ' · View' : app.publish ? ' · Edit and save a new version' : ' · Edit');
      choices.push(choice);
      select.append(option);
    }
  }
  function field(text, value, type = 'text') {
    const label = document.createElement('label'), input = document.createElement('input');
    label.append(document.createTextNode(text + ' '), input);
    input.type = type;
    input.value = value;
    input.required = true;
    return { label, input };
  }
  const destination = document.createElement('fieldset'), legend = document.createElement('legend');
  legend.textContent = 'Save new versions';
  const folder = field('Folder', repository), names = field('Version names', 'review-*');
  destination.append(legend, folder.label, names.label);
  const duration = field('Access in minutes', '15', 'number');
  duration.input.min = '1';
  duration.input.max = '480';
  const note = document.createElement('p');
  note.textContent = 'You’ll approve the application’s access before it opens. Changed files are saved as new versions.';
  const message = document.createElement('p');
  message.setAttribute('role', 'status');
  const button = document.createElement('button');
  button.type = 'submit';
  button.textContent = 'Open';
  function update() {
    const choice = choices[Number(select.value)];
    destination.hidden = destination.disabled = choice.intent !== 'edit' || !choice.app.publish;
  }
  select.onchange = update;
  update();
  form.append(select, destination, duration.label, note, button, message);
  form.onsubmit = async event => {
    event.preventDefault();
    if (!current()) return;
    button.disabled = true;
    message.textContent = 'Opening application…';
    try {
      const choice = choices[Number(select.value)];
      const request = { application_id: choice.app.id, repository, reference: data.digest,
        intent: choice.intent, ttl: Number(duration.input.value) * 60 };
      if (!destination.disabled) request.publish = { repository: folder.input.value.trim(), allowed_tags: [names.input.value.trim()] };
      const launched = await fetch('/open-artifact/launches', { method: 'POST',
        headers: { Authorization: 'Bearer ' + await credential(), 'Content-Type': 'application/json' },
        body: JSON.stringify(request), credentials: 'same-origin', cache: 'no-store' });
      if (!launched.ok) throw Error('This application could not be opened with the requested access. Check the folder and version names, or ask your project team for help.');
      const launch = await launched.json();
      if (current()) location.assign(launch.launch_url);
    } catch (error) {
      if (current()) {
        message.textContent = error instanceof TypeError ? 'Couldn’t connect. Check your connection and try again.' : error.message;
        button.disabled = false;
      }
    }
  };
  container.append(heading, form);
  container.hidden = false;
};
