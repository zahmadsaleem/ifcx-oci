// Reference browser client for open-artifact/1. Credentials stay in application memory.
const pendingKey = 'open-artifact.pkce';
const base64 = bytes => btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
const random = () => base64(crypto.getRandomValues(new Uint8Array(32)));

function registryOrigin(issuer) {
  const url = new URL(issuer);
  const loopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw Error('Choose a trusted HTTPS registry or a local development registry.');
  }
  return url.origin;
}

async function configFor(issuer, clientId) {
  const response = await fetch(issuer + '/oauth/config?client_id=' + encodeURIComponent(clientId), { credentials: 'omit', cache: 'no-store', redirect: 'error' });
  if (!response.ok) throw Error('This application is not registered. Ask the registry owner for help.');
  const config = await response.json();
  if (config.issuer !== issuer || config.client_id !== clientId || config.open_artifact_protocol !== 'open-artifact/1') throw Error('The registry returned an unexpected configuration.');
  for (const field of ['authorization_endpoint', 'token_endpoint']) {
    const endpoint = new URL(config[field], issuer);
    if (endpoint.origin !== issuer || endpoint.username || endpoint.password || endpoint.hash) throw Error('The registry returned an unexpected endpoint.');
  }
  return config;
}

// Call only after the host application has accepted this issuer as a trusted registry.
export async function beginLaunch({ issuer, requestId, clientId, redirectUri }) {
  issuer = registryOrigin(issuer);
  const config = await configFor(issuer, clientId);
  const callback = new URL(redirectUri);
  if (callback.origin !== location.origin || !config.redirect_uris.includes(redirectUri)) throw Error('Choose a registered callback in this application.');
  if (!/^[a-f0-9]{32}$/.test(requestId)) throw Error('This opening request is invalid. Return to the shared files and try again.');
  const verifier = random(), state = random();
  const challenge = base64(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
  sessionStorage.setItem(pendingKey, JSON.stringify({ issuer, requestId, clientId, redirectUri, verifier, state, created: Date.now() }));
  const url = new URL(config.authorization_endpoint, issuer);
  url.search = new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: redirectUri,
    scope: 'subsoil:session', state, code_challenge_method: 'S256', code_challenge: challenge, launch_request: requestId });
  location.assign(url);
}

export async function finishLaunch() {
  const stored = sessionStorage.getItem(pendingKey);
  const url = new URL(location.href), query = url.searchParams;
  sessionStorage.removeItem(pendingKey);
  const ambiguous = ['code', 'state', 'iss', 'error'].some(key => query.getAll(key).length > 1);
  const code = query.get('code'), state = query.get('state'), issuer = query.get('iss'), error = query.get('error');
  for (const key of ['code', 'state', 'iss', 'error']) query.delete(key);
  history.replaceState(null, '', url.pathname + (query.size ? '?' + query : '') + url.hash);
  if (!stored) throw Error('Return to the shared files and open this application again.');
  if (ambiguous) throw Error('The opening response is ambiguous. Please try again.');
  const pending = JSON.parse(stored);
  const callback = new URL(pending.redirectUri);
  if (location.origin !== callback.origin || location.pathname !== callback.pathname || state !== pending.state
      || Date.now() - pending.created > 300000 || Date.now() < pending.created) throw Error('This opening request expired or could not be verified. Please try again.');
  if (error) throw Error('Opening was cancelled. Return to the shared files to try again.');
  if (!code || issuer !== pending.issuer) throw Error('The opening response came from an unexpected registry.');
  const config = await configFor(pending.issuer, pending.clientId);
  const response = await fetch(new URL(config.token_endpoint, pending.issuer), { method: 'POST',
    body: new URLSearchParams({ grant_type: 'authorization_code', client_id: pending.clientId,
      redirect_uri: pending.redirectUri, code, code_verifier: pending.verifier }), credentials: 'omit', cache: 'no-store', redirect: 'error' });
  if (!response.ok) throw Error('Access could not be approved. Return to the shared files and try again.');
  const session = await response.json();
  if (session.open_artifact?.protocol !== 'open-artifact/1' || session.open_artifact.source.registry !== pending.issuer) throw Error('The registry returned an unexpected opening context.');
  return { issuer: pending.issuer, clientId: pending.clientId, ...session };
}

export async function repositoryToken(session, repository, actions = ['pull']) {
  const url = new URL('/token', session.issuer);
  url.searchParams.set('scope', 'repository:' + repository + ':' + actions.join(','));
  const response = await fetch(url, { headers: { Authorization: 'Bearer ' + session.access_token }, credentials: 'omit', cache: 'no-store', redirect: 'error' });
  if (!response.ok) throw Error('Access has ended. Open the shared files again to continue.');
  return response.json();
}

export async function renewLaunch(session) {
  const response = await fetch(session.issuer + '/oauth/token', { method: 'POST',
    body: new URLSearchParams({ grant_type: 'refresh_token', client_id: session.clientId, refresh_token: session.refresh_token }),
    credentials: 'omit', cache: 'no-store', redirect: 'error' });
  if (!response.ok) throw Error('Access has ended. Open the shared files again to continue.');
  return { ...session, ...await response.json() };
}
