'use strict';
(() => {
  const client = 'subsoil-explorer';
  const refreshKey = 'subsoil.explorer.refresh';
  const loginKey = 'subsoil.explorer.login';
  const $ = id => document.getElementById(id);
  const redirect = location.origin + '/explore';
  const tokens = new Map();
  const manifests = new Map();
  const pageSize = 20;
  let session, renewing, selection = 0, nextCursor;
  let view = readView(), repositoryView, tagsView;

  function status(message, error = false) {
    $('status').textContent = message;
    $('status').classList.toggle('error', error);
  }

  function signedIn(value) {
    $('browser').hidden = $('refresh').hidden = $('sign-out').hidden = !value;
    $('sign-in').hidden = value;
    $('account').textContent = value ? session.subject : '';
    $('breadcrumbs').hidden = !value;
  }

  function forget() {
    sessionStorage.removeItem(refreshKey);
    session = undefined;
    tokens.clear();
    manifests.clear();
    selection++;
    $('repositories').replaceChildren();
    $('tags').replaceChildren();
    $('artifact').hidden = true;
    $('metadata').replaceChildren();
    $('files').replaceChildren();
    $('manifest').textContent = $('reference').textContent = '';
    signedIn(false);
  }

  async function run(action) {
    try { await action(); }
    catch (error) { status(error.message || 'The registry could not be reached.', true); }
  }

  async function post(path, fields) {
    return fetch(path, {
      method: 'POST', body: new URLSearchParams(fields), credentials: 'omit', cache: 'no-store'
    });
  }

  async function accept(response) {
    if (!response.ok) {
      forget();
      throw Error('Your session could not be opened. Please sign in again.');
    }
    const value = await response.json();
    sessionStorage.setItem(refreshKey, value.refresh_token);
    session = { ...value, deadline: Date.now() + value.expires_in * 1000 };
    tokens.clear();
    signedIn(true);
  }

  async function root() {
    if (session && Date.now() < session.deadline - 30000) return session.access_token;
    if (!renewing) renewing = (async () => {
      const token = sessionStorage.getItem(refreshKey);
      if (!token) { forget(); throw Error('Please sign in to browse the registry.'); }
      await accept(await post('/oauth/token', { grant_type: 'refresh_token', client_id: client, refresh_token: token }));
    })().finally(() => { renewing = undefined; });
    await renewing;
    return session.access_token;
  }

  async function request(path, repo, retry = true) {
    const access = await root();
    let token = access;
    if (repo) {
      let scoped = tokens.get(repo);
      if (!scoped || Date.now() > scoped.deadline - 10000) {
        const response = await fetch('/token?scope=' + encodeURIComponent('repository:' + repo + ':pull'), {
          headers: { Authorization: 'Bearer ' + access }, credentials: 'omit', cache: 'no-store'
        });
        if (!response.ok) throw Error('Access to this repository could not be opened.');
        const value = await response.json();
        scoped = { token: value.access_token, deadline: Date.now() + value.expires_in * 1000 };
        tokens.set(repo, scoped);
      }
      token = scoped.token;
    }
    const response = await fetch(path, {
      headers: { Authorization: 'Bearer ' + token }, credentials: 'omit', cache: 'no-store'
    });
    if (response.status === 401 && retry) {
      session.deadline = 0;
      tokens.clear();
      return request(path, repo, false);
    }
    if (!response.ok) throw Error(response.status === 403 ? 'You do not have access to this artifact.' : 'Artifact unavailable (' + response.status + ').');
    return response;
  }

  function readView() {
    const query = new URLSearchParams(location.search);
    return { repo: query.get('repo') || '', tag: query.get('tag') || '', query: query.get('q') || '',
      cursors: history.state?.explorer?.cursors || [query.get('last') || ''] };
  }

  function fresh(repo = '', tag = '') {
    return { repo, tag, query: '', cursors: [''] };
  }

  function viewUrl(value) {
    const query = new URLSearchParams();
    if (value.repo) query.set('repo', value.repo);
    if (value.tag) query.set('tag', value.tag);
    if (value.query) query.set('q', value.query);
    if (value.cursors.at(-1)) query.set('last', value.cursors.at(-1));
    return '/explore' + (query.size ? '?' + query : '');
  }

  function navigate(value, replace = false) {
    if (!view.repo && value.repo) repositoryView = view;
    if (view.repo && !view.tag && value.tag) tagsView = view;
    view = value;
    history[replace ? 'replaceState' : 'pushState']({ explorer: view }, '', viewUrl(view));
    return run(renderView);
  }

  function link(text, value) {
    const anchor = document.createElement('a');
    anchor.textContent = text;
    anchor.href = viewUrl(value);
    anchor.onclick = event => {
      if (event.button || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      event.preventDefault();
      navigate(value);
    };
    return anchor;
  }

  const path = repo => '/v2/' + repo.split('/').map(encodeURIComponent).join('/');

  async function manifestFor(repo, tag) {
    const key = repo + ':' + tag;
    if (!manifests.has(key)) manifests.set(key, (async () => {
      const response = await request(path(repo) + '/manifests/' + encodeURIComponent(tag), repo);
      return { manifest: await response.json(), digest: response.headers.get('docker-content-digest'),
        publisher: response.headers.get('subsoil-registry-publisher'), pushed: response.headers.get('subsoil-registry-pushed-at') };
    })().catch(error => { manifests.delete(key); throw error; }));
    return manifests.get(key);
  }

  function totalSize(manifest) {
    return [manifest.config, ...(manifest.layers || [])].filter(Boolean).reduce((sum, file) => sum + file.size, 0);
  }

  async function renderView() {
    const ticket = ++selection;
    const current = view;
    $('page-title').textContent = current.tag || current.repo || 'Repositories';
    $('page-caption').textContent = current.tag ? current.repo : current.repo ? 'Tags · Published versions of this repository' : 'Browse the artifacts in your registry.';
    document.title = (current.tag ? current.tag + ' · ' : '') + (current.repo || 'Repositories') + ' · Subsoil';
    const crumbs = [link('Repositories', repositoryView || fresh())];
    if (current.repo) crumbs.push(document.createTextNode('/'), link(current.repo, tagsView?.repo === current.repo ? tagsView : fresh(current.repo)));
    if (current.tag) crumbs.push(document.createTextNode('/'), document.createTextNode(current.tag));
    $('breadcrumbs').replaceChildren(...crumbs);
    $('breadcrumbs').hidden = !current.repo;
    $('listing').hidden = Boolean(current.tag);
    $('artifact').hidden = true;
    if (current.tag) { await openArtifact(current.repo, current.tag, ticket); return; }
    manifests.clear();
    const kind = current.repo ? 'tags' : 'repositories';
    $('search-label').textContent = 'Search ' + kind;
    $('search').placeholder = 'Search ' + kind + '…';
    $('search').value = current.query;
    $('repositories').replaceChildren();
    $('tags').replaceChildren();
    $('repositories').hidden = Boolean(current.repo);
    $('tags-table').hidden = !current.repo;
    $('empty').hidden = true;
    $('previous').disabled = $('next').disabled = true;
    $('page-summary').textContent = 'Loading…';
    status('');
    const query = new URLSearchParams({ n: pageSize, last: current.cursors.at(-1), q: current.query });
    const response = await request((current.repo ? path(current.repo) + '/tags/list' : '/v2/_catalog') + '?' + query, current.repo);
    const value = await response.json();
    if (ticket !== selection) return;
    const entries = value[kind] || [];
    nextCursor = response.headers.has('link') ? entries.at(-1) : undefined;
    $('previous').disabled = current.cursors.length < 2;
    $('next').disabled = !nextCursor;
    const label = entries.length === 1 ? (current.repo ? 'tag' : 'repository') : kind;
    $('page-summary').textContent = entries.length + ' ' + label + ' on this page';
    $('empty').hidden = entries.length > 0;
    $('empty-title').textContent = current.query ? 'No matching ' + kind : 'No ' + kind + ' available';
    $('empty-caption').textContent = current.query ? 'Try a different search.' : 'Published artifacts you can access will appear here.';
    if (!current.repo) {
      $('repositories').replaceChildren(...entries.map(repo => {
        const item = document.createElement('li');
        const anchor = link('', fresh(repo));
        const mark = document.createElement('span'), name = document.createElement('span'), action = document.createElement('span');
        mark.className = 'repository-mark';
        mark.textContent = '▦';
        mark.setAttribute('aria-hidden', 'true');
        name.textContent = repo;
        action.className = 'row-action';
        action.textContent = 'View tags →';
        anchor.append(mark, name, action);
        item.append(anchor);
        return item;
      }));
      return;
    }
    const queue = entries.map(tag => {
      const row = document.createElement('tr');
      const name = document.createElement('td'), digest = document.createElement('td'), published = document.createElement('td'), size = document.createElement('td');
      name.append(link(tag, fresh(current.repo, tag)));
      const publisher = document.createElement('small');
      name.append(publisher);
      digest.textContent = 'Loading…';
      size.className = 'size';
      row.append(name, digest, published, size);
      $('tags').append(row);
      return { tag, digest, published, size, publisher };
    });
    // Only inspect this page, with bounded concurrency; never crawl other pages.
    await Promise.all(Array.from({ length: 4 }, async () => {
      while (queue.length && ticket === selection) {
        const row = queue.shift();
        try {
          const item = await manifestFor(current.repo, row.tag);
          if (ticket !== selection) return;
          const code = document.createElement('code');
          code.textContent = item.digest ? item.digest.replace('sha256:', '').slice(0, 12) : 'Not recorded';
          code.title = item.digest || '';
          row.digest.replaceChildren(code);
          row.publisher.textContent = item.publisher ? 'by ' + item.publisher : '';
          row.published.textContent = item.pushed ? new Date(Number(item.pushed) * 1000).toLocaleDateString() : 'Not recorded';
          row.size.textContent = bytes(totalSize(item.manifest));
        } catch (error) {
          if (ticket !== selection) return;
          row.digest.textContent = 'Unavailable';
          row.digest.title = error.message;
        }
      }
    }));
  }

  function bytes(size) {
    if (!Number.isFinite(size)) return 'Unknown';
    if (size < 1024) return size + ' B';
    if (size < 1024 ** 2) return (size / 1024).toFixed(1) + ' KB';
    if (size < 1024 ** 3) return (size / 1024 ** 2).toFixed(1) + ' MB';
    return (size / 1024 ** 3).toFixed(1) + ' GB';
  }

  async function openArtifact(repo, tag, ticket) {
    $('artifact').hidden = true;
    status('Loading artifact…');
    const { manifest, digest, pushed, publisher } = await manifestFor(repo, tag);
    if (ticket !== selection) return;
    const files = [manifest.config, ...(manifest.layers || [])].filter(Boolean);
    const metadata = [
      ['Artifact type', manifest.artifactType || manifest.config?.mediaType || manifest.mediaType],
      ['Published by', publisher || 'Not recorded'],
      ['Published', pushed ? new Date(Number(pushed) * 1000).toLocaleString() : 'Not recorded'],
      ['Digest', digest || 'Not available'],
      ['Total size', bytes(totalSize(manifest))]
    ];
    $('artifact-title').textContent = manifest.annotations?.['org.opencontainers.image.title'] || tag;
    $('metadata').replaceChildren(...metadata.flatMap(([name, value]) => {
      const dt = document.createElement('dt'), dd = document.createElement('dd');
      dt.textContent = name;
      dd.textContent = value || 'Not specified';
      return [dt, dd];
    }));
    $('reference').textContent = location.host + '/' + repo + (digest ? '@' + digest : ':' + tag);
    $('copy').textContent = 'Copy reference';
    $('file-count').textContent = files.length;
    $('files').replaceChildren(...files.map((file, index) => {
      const row = document.createElement('tr');
      const name = document.createElement('td'), type = document.createElement('td'), size = document.createElement('td');
      name.textContent = file.annotations?.['org.opencontainers.image.title'] || (index === 0 ? 'Config' : 'Layer ' + index);
      const detail = document.createElement('small');
      detail.textContent = file.digest;
      name.append(detail);
      type.textContent = file.mediaType;
      size.textContent = bytes(file.size);
      size.className = 'size';
      row.append(name, type, size);
      return row;
    }));
    $('manifest').textContent = JSON.stringify(manifest, null, 2);
    $('artifact').hidden = false;
    status('');
  }

  const base64 = bytes => btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
  const random = () => base64(crypto.getRandomValues(new Uint8Array(32)));

  $('sign-in').onclick = () => run(async () => {
    if (!crypto.subtle) throw Error('Sign-in requires HTTPS or a localhost connection.');
    const response = await fetch('/oauth/config', { credentials: 'omit', cache: 'no-store' });
    if (!response.ok) throw Error('Sign-in is currently unavailable.');
    const config = await response.json();
    const url = new URL(config.authorization_endpoint);
    if (url.origin !== location.origin) throw Error('Open ' + url.origin + '/explore to sign in.');
    const verifier = random(), state = random();
    const challenge = base64(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
    sessionStorage.setItem(loginKey, JSON.stringify({ verifier, state, created: Date.now(), view }));
    url.search = new URLSearchParams({ response_type: 'code', client_id: client, redirect_uri: redirect,
      scope: 'subsoil:session', state, code_challenge: challenge, code_challenge_method: 'S256' });
    location.assign(url);
  });

  $('sign-out').onclick = () => run(async () => {
    // Finish any rotating refresh before revoking its latest credential.
    if (renewing) await renewing;
    const token = sessionStorage.getItem(refreshKey);
    if (token) {
      const response = await post('/oauth/revoke', { client_id: client, token });
      if (!response.ok) throw Error('Sign-out failed. Please try again.');
    }
    forget();
    status('Signed out.');
  });
  $('refresh').onclick = () => { manifests.clear(); run(renderView); };
  $('repositories-nav').onclick = event => { event.preventDefault(); navigate(fresh()); };
  $('search-form').onsubmit = event => {
    event.preventDefault();
    navigate({ ...view, query: $('search').value.trim(), cursors: [''] });
  };
  $('previous').onclick = () => navigate({ ...view, cursors: view.cursors.slice(0, -1) });
  $('next').onclick = () => { if (nextCursor) navigate({ ...view, cursors: [...view.cursors, nextCursor] }); };
  window.addEventListener('popstate', () => { view = readView(); if (session) run(renderView); });
  $('copy').onclick = () => run(async () => {
    await navigator.clipboard.writeText($('reference').textContent);
    $('copy').textContent = 'Copied';
  });

  run(async () => {
    const query = new URLSearchParams(location.search);
    if (query.has('code') || query.has('error')) {
      history.replaceState(null, '', '/explore');
      const pending = JSON.parse(sessionStorage.getItem(loginKey) || 'null');
      sessionStorage.removeItem(loginKey);
      if (!pending || pending.state !== query.get('state') || Date.now() - pending.created > 300000) {
        throw Error('Sign-in could not be verified. Please try again.');
      }
      if (query.has('error')) { status('Sign-in cancelled.'); return; }
      await accept(await post('/oauth/token', { grant_type: 'authorization_code', client_id: client,
        redirect_uri: redirect, code: query.get('code'), code_verifier: pending.verifier }));
      view = pending.view || fresh();
    } else if (sessionStorage.getItem(refreshKey)) await root();
    else return;
    history.replaceState({ explorer: view }, '', viewUrl(view));
    await renderView();
  });
})();
