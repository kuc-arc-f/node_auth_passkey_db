// ---------- base64url <-> ArrayBuffer ----------
const toBuf = (s) => {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=');
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)).buffer;
};
const toB64u = (buf) => {
  let bin = '';
  new Uint8Array(buf).forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

// ---------- helpers ----------
const $ = (id) => document.getElementById(id);
const msg = (text, kind = '') => {
  $('msg').textContent = text;
  $('msg').className = kind;
};

async function api(path, body) {
  const res = await fetch(path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `エラー (${res.status})`);
  return data;
}

async function run(button, fn) {
  button.disabled = true;
  msg('');
  try {
    await fn();
  } catch (err) {
    msg(
      err.name === 'NotAllowedError'
        ? 'キャンセルされたか、時間切れになりました。'
        : err.name === 'InvalidStateError'
          ? 'この端末ではすでに登録済みです。'
          : err.message,
      'error',
    );
  } finally {
    button.disabled = false;
  }
}

// ---------- WebAuthn ----------
async function createPasskey(username) {
  const opts = await api('/api/register/options', { username });
  const cred = await navigator.credentials.create({
    publicKey: {
      ...opts,
      challenge: toBuf(opts.challenge),
      user: { ...opts.user, id: toBuf(opts.user.id) },
      excludeCredentials: (opts.excludeCredentials ?? []).map((c) => ({ ...c, id: toBuf(c.id) })),
    },
  });
  return api('/api/register/verify', {
    id: cred.id,
    rawId: toB64u(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: toB64u(cred.response.clientDataJSON),
      attestationObject: toB64u(cred.response.attestationObject),
      transports: cred.response.getTransports?.() ?? [],
    },
  });
}

async function signIn() {
  const opts = await api('/api/login/options', {});
  const cred = await navigator.credentials.get({
    publicKey: {
      ...opts,
      challenge: toBuf(opts.challenge),
      allowCredentials: (opts.allowCredentials ?? []).map((c) => ({ ...c, id: toBuf(c.id) })),
    },
  });
  const r = cred.response;
  return api('/api/login/verify', {
    id: cred.id,
    rawId: toB64u(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: toB64u(r.clientDataJSON),
      authenticatorData: toB64u(r.authenticatorData),
      signature: toB64u(r.signature),
      userHandle: r.userHandle ? toB64u(r.userHandle) : undefined,
    },
  });
}

// ---------- UI ----------
const fmt = (d) => (d ? new Date(d).toLocaleString('ja-JP') : '未使用');

async function render() {
  const { user } = await api('/api/me');
  $('guest').hidden = !!user;
  $('member').hidden = !user;
  if (!user) return;

  $('who').textContent = user.username;
  const { passkeys } = await api('/api/passkeys');
  $('keys').replaceChildren(
    ...passkeys.map((k) => {
      const li = document.createElement('li');
      li.textContent = `${k.device_type === 'multiDevice' ? '同期 Passkey' : 'この端末の Passkey'}（作成: ${fmt(k.created_at)}）`;
      const small = document.createElement('small');
      small.textContent = `最終使用: ${fmt(k.last_used_at)}`;
      li.append(small);
      return li;
    }),
  );
}

if (!window.PublicKeyCredential) {
  msg('このブラウザは Passkey (WebAuthn) に対応していません。', 'error');
} else {
  $('login').onclick = (e) =>
    run(e.currentTarget, async () => {
      await signIn();
      await render();
    });
  $('register').onclick = (e) =>
    run(e.currentTarget, async () => {
      await createPasskey($('username').value.trim());
      await render();
      msg('登録してログインしました。', 'ok');
    });
  $('add').onclick = (e) =>
    run(e.currentTarget, async () => {
      await createPasskey($('who').textContent);
      await render();
      msg('Passkey を追加しました。', 'ok');
    });
  $('logout').onclick = (e) =>
    run(e.currentTarget, async () => {
      await api('/api/logout', {});
      await render();
    });
}

render().catch((err) => msg(err.message, 'error'));
