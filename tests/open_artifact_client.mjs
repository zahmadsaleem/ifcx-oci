import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const source = await readFile(new URL('../src/registry/open_artifact_client.js', import.meta.url), 'utf8');
const sdk = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
const issuer = 'https://registry.example.com';
const callback = 'https://editor.example.com/callback';
const requestId = 'a'.repeat(32);
const key = 'open-artifact.pkce';

function environment() {
  const storage = new Map(), requests = [];
  let assigned;
  globalThis.sessionStorage = {
    getItem: key => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, value),
    removeItem: key => storage.delete(key)
  };
  function navigate(url) {
    globalThis.location = new URL(url, callback);
    location.assign = url => { assigned = url.toString(); };
  }
  navigate(callback);
  globalThis.history = { replaceState: (_state, _title, url) => navigate(url) };
  const config = { issuer, client_id: 'editor', open_artifact_protocol: 'open-artifact/1',
    authorization_endpoint: issuer + '/oauth/authorize', token_endpoint: '/oauth/token', redirect_uris: [callback] };
  globalThis.fetch = async (url, options = {}) => {
    url = url.toString();
    requests.push({ url, options, browserUrl: location.href });
    if (url.startsWith(issuer + '/oauth/config?')) return Response.json(config);
    if (url === issuer + '/oauth/token') return Response.json({ access_token: 'limited-root', refresh_token: 'rotated-refresh',
      open_artifact: { protocol: 'open-artifact/1', source: { registry: issuer, digest: 'sha256:content' } } });
    if (url.startsWith(issuer + '/token?')) return Response.json({ access_token: 'repository-token' });
    throw Error('Unexpected request: ' + url);
  };
  return { storage, requests, config, navigate, assigned: () => assigned };
}

async function begin(env) {
  await sdk.beginLaunch({ issuer, requestId, clientId: 'editor', redirectUri: callback });
  return JSON.parse(env.storage.get(key));
}

test('PKCE launch validates callback, removes credentials from URL, and exchanges scoped tokens', async () => {
  const env = environment(), pending = await begin(env);
  const authorization = new URL(env.assigned());
  assert.equal(authorization.searchParams.get('launch_request'), requestId);
  assert.equal(authorization.searchParams.get('code_challenge_method'), 'S256');
  const expected = Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pending.verifier))).toString('base64url');
  assert.equal(authorization.searchParams.get('code_challenge'), expected);
  env.navigate(callback + '?' + new URLSearchParams({ code: 'single-use-code', state: pending.state, iss: issuer }));
  const session = await sdk.finishLaunch();
  assert.equal(session.issuer, issuer);
  assert.equal(env.storage.has(key), false);
  assert.equal(location.href, callback);
  const exchange = env.requests.find(request => request.url === issuer + '/oauth/token');
  assert.equal(exchange.options.body.get('code_verifier'), pending.verifier);
  assert.equal(exchange.options.credentials, 'omit');
  assert.equal(exchange.options.redirect, 'error');
  assert.equal(exchange.browserUrl, callback);
  const token = await sdk.repositoryToken(session, 'project/model', ['pull', 'push']);
  assert.equal(token.access_token, 'repository-token');
  const repository = env.requests.at(-1);
  assert.equal(new URL(repository.url).searchParams.get('scope'), 'repository:project/model:pull,push');
  assert.equal(repository.options.headers.Authorization, 'Bearer limited-root');
  const renewed = await sdk.renewLaunch(session);
  assert.equal(renewed.refresh_token, 'rotated-refresh');
  assert.equal(renewed.open_artifact.source.registry, issuer);
});

test('callback rejects mismatched issuer, state, path, expiry, and duplicate parameters before token exchange', async () => {
  for (const bad of ['issuer', 'state', 'path', 'expired', 'duplicate-code', 'duplicate-state', 'duplicate-issuer']) {
    const env = environment(), pending = await begin(env);
    const query = new URLSearchParams({ code: 'code', state: pending.state, iss: issuer });
    if (bad === 'issuer') query.set('iss', 'https://other.example');
    if (bad === 'state') query.set('state', 'unexpected');
    if (bad.startsWith('duplicate-')) query.append({ 'duplicate-code': 'code', 'duplicate-state': 'state', 'duplicate-issuer': 'iss' }[bad], 'duplicate');
    if (bad === 'expired') {
      pending.created -= 300001;
      env.storage.set(key, JSON.stringify(pending));
    }
    env.navigate((bad === 'path' ? 'https://editor.example.com/other' : callback) + '?' + query);
    await assert.rejects(sdk.finishLaunch(), undefined, bad);
    assert.equal(env.requests.some(request => request.url === issuer + '/oauth/token'), false, bad);
    assert.equal(env.storage.has(key), false, bad);
    assert.equal(new URL(location.href).search, '', bad);
  }
});

test('configuration cannot redirect authorization or token exchange to another origin', async () => {
  for (const field of ['authorization_endpoint', 'token_endpoint']) {
    const env = environment();
    env.config[field] = 'https://other.example/endpoint';
    await assert.rejects(begin(env));
    assert.equal(env.storage.has(key), false);
    assert.equal(env.assigned(), undefined);
  }
  environment();
  await assert.rejects(sdk.beginLaunch({ issuer: 'http://remote.example', requestId, clientId: 'editor', redirectUri: callback }));
});
