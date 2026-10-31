import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import vm from 'node:vm';

const source = await readFile(new URL('../src/registry/explorer.js', import.meta.url), 'utf8');
const content = Buffer.from('a public file');
const digest = 'sha256:' + createHash('sha256').update(content).digest('hex');

function browser({ artifact = false, privateRegistry = false, savedLogin = false } = {}) {
  const elements = new Map(), storage = new Map(), requests = [], downloads = [], blobs = [];
  let downloadedContent = content;
  if (savedLogin) storage.set('subsoil.explorer.refresh', 'saved-refresh');
  class Element {
    constructor(tag = 'div') {
      this.tagName = tag;
      this.children = [];
      this.hidden = false;
      this.textContent = '';
      this.classList = { toggle() {}, add() {} };
    }
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this.children = children; }
    setAttribute(name, value) { this[name] = value; }
    click() { if (this.tagName === 'a') downloads.push({ name: this.download, href: this.href }); }
  }
  class BrowserURL extends URL {
    static createObjectURL(blob) { blobs.push(blob); return 'blob:verified-download'; }
    static revokeObjectURL() {}
  }
  const context = {
    URL: BrowserURL, URLSearchParams, Response, Blob, crypto: webcrypto,
    TextEncoder, btoa, setTimeout: callback => callback(),
    location: new URL('https://registry.example/explore' + (artifact ? '?repo=public/model&tag=issued' : '')),
    history: { state: null, replaceState(state) { this.state = state; }, pushState(state) { this.state = state; } },
    document: {
      getElementById(id) { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); },
      createElement: tag => new Element(tag), createTextNode: text => ({ textContent: text })
    },
    sessionStorage: {
      getItem: key => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, value),
      removeItem: key => storage.delete(key)
    },
    fetch: async (path, options = {}) => {
      requests.push({ path, options });
      if (path === '/oauth/revoke') return Response.json({});
      if (path === '/oauth/token') return Response.json({
        subject: 'reader', access_token: 'account-root', refresh_token: 'rotated-refresh', expires_in: 900
      });
      if (path.startsWith('/token?')) {
        if (privateRegistry) return new Response('', { status: 401 });
        return Response.json({ authorization_type: 'public', access_token: 'public-read', expires_in: 900 });
      }
      if (path.startsWith('/v2/_catalog')) return Response.json({ repositories: ['public/model'] });
      if (path.includes('/manifests/')) return Response.json({
        layers: [{ mediaType: 'text/plain', digest, size: content.length,
          annotations: { 'org.opencontainers.image.title': 'files/example.txt' } }]
      }, { headers: { 'docker-content-digest': 'sha256:manifest' } });
      if (path.includes('/blobs/')) return new Response(downloadedContent);
      throw Error('Unexpected request: ' + path);
    },
    addEventListener() {},
    SubsoilOpenArtifactUI: async () => {}
  };
  context.window = context;
  // Match the initial HTML state for controls changed by the script.
  for (const id of ['browser', 'refresh', 'sign-out', 'artifact', 'open-with']) context.document.getElementById(id).hidden = true;
  vm.runInNewContext(source, context);
  return { elements, storage, requests, downloads, blobs, corrupt: value => { downloadedContent = value; } };
}

async function until(predicate) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (predicate()) return;
    await new Promise(resolve => setTimeout(resolve, 2));
  }
  assert.fail('Browser did not reach the expected state');
}

test('signed-out visitors browse public folders without persisting tokens', async () => {
  const b = browser();
  await until(() => b.elements.get('repositories')?.children.length === 1);
  assert.equal(b.elements.get('browser').hidden, false);
  assert.equal(b.elements.get('sign-in').hidden, false);
  assert.equal(b.elements.get('sign-out').hidden, true);
  assert.equal(b.elements.get('page-title').textContent, 'Public files');
  assert.equal(b.storage.size, 0);
  assert.equal(b.requests[0].options.headers, undefined);
  assert.equal(b.requests[0].options.credentials, 'omit');
  assert.equal(b.requests[1].options.headers.Authorization, 'Bearer public-read');
  assert.equal(b.requests[1].options.redirect, 'error');
});

test('a private registry keeps the sign-in screen', async () => {
  const b = browser({ privateRegistry: true });
  await until(() => b.elements.get('status')?.textContent.includes('Sign in'));
  assert.equal(b.elements.get('browser').hidden, true);
  assert.equal(b.elements.get('sign-in').hidden, false);
  assert.equal(b.requests.length, 1);
  assert.equal(b.storage.size, 0);
});

test('public downloads verify bytes and reject corrupt or incorrectly sized files', async () => {
  const b = browser({ artifact: true });
  await until(() => b.elements.get('artifact').hidden === false);
  const download = b.elements.get('files').children[0].children[3].children[0];
  assert.equal(download.textContent, 'Download');
  assert.equal(b.elements.get('open-with').hidden, true);
  assert.equal(b.elements.get('share-caption').textContent, 'Anyone can view this public version.');
  await download.onclick();
  assert.equal(b.downloads[0].name, 'example.txt');
  assert.deepEqual(Buffer.from(await b.blobs[0].arrayBuffer()), content);
  assert.equal(b.requests.find(request => request.path.includes('repository%3A')).options.headers.Authorization, undefined);
  b.corrupt(Buffer.alloc(content.length, 0));
  await download.onclick();
  assert.match(b.elements.get('status').textContent, /doesn’t match the published version/);
  assert.equal(b.downloads.length, 1);
  b.corrupt(Buffer.alloc(content.length + 1, 0));
  await download.onclick();
  assert.match(b.elements.get('status').textContent, /size doesn’t match/);
  assert.equal(b.downloads.length, 1);
  assert.equal(download.disabled, false);
  assert.equal(b.storage.size, 0);
});

test('signing out revokes the account session and returns to public browsing', async () => {
  const b = browser({ savedLogin: true });
  await until(() => b.elements.get('repositories')?.children.length === 1);
  assert.equal(b.elements.get('sign-in').hidden, true);
  assert.equal(b.elements.get('sign-out').hidden, false);
  await b.elements.get('sign-out').onclick();
  assert.equal(b.elements.get('page-title').textContent, 'Public files');
  assert.equal(b.elements.get('browser').hidden, false);
  assert.equal(b.elements.get('sign-in').hidden, false);
  assert.equal(b.elements.get('sign-out').hidden, true);
  assert.equal(b.storage.size, 0);
  assert.equal(b.requests.filter(request => request.path === '/oauth/revoke').length, 1);
});
