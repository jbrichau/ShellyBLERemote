import { BleClient } from '@capacitor-community/bluetooth-le';
import { SecureStoragePlugin } from 'capacitor-secure-storage-plugin';

// ── Shelly Gen2+ BLE RPC UUIDs ──────────────────────────────────────────────
const SVC_UUID    = '5f6d4f53-5f52-5043-5f53-56435f49445f';
const DATA_UUID   = '5f6d4f53-5f52-5043-5f64-6174615f5f5f';
const TX_CTL_UUID = '5f6d4f53-5f52-5043-5f74-785f63746c5f';
const RX_CTL_UUID = '5f6d4f53-5f52-5043-5f72-785f63746c5f';

const CHUNK         = 20;
const RPC_TIMEOUT   = 10_000;
const TX_DELAY      = 200;
const POLL_INTERVAL = 150;

// ── State ────────────────────────────────────────────────────────────────────
let deviceId       = null;
let nextId         = 1;
let busy           = false;
let autoTimer      = null;
let storedPassword = null;
let pwdResolve     = null;

const PWD_KEY = 'shelly_device_password';

async function loadKeychainPassword() {
  try {
    const { value } = await SecureStoragePlugin.get({ key: PWD_KEY });
    if (value) { storedPassword = value; updateLockUI(); }
  } catch { /* nothing stored yet */ }
}

async function persistPassword(pwd) {
  try {
    if (pwd) await SecureStoragePlugin.set({ key: PWD_KEY, value: pwd });
    else      await SecureStoragePlugin.remove({ key: PWD_KEY });
  } catch (e) { log(`Keychain error: ${e.message}`, 'warn'); }
}

// ── Authentication ────────────────────────────────────────────────────────────
// Shelly Gen2+ RPC digest auth (simplified HTTP Digest, MD5-based).
//
// To enable auth on the device, run once while connected (no password yet):
//   sendRpc('Shelly.SetAuth', { user: 'admin', pass: 'yourpassword' })
// To disable:
//   sendRpc('Shelly.SetAuth', { user: 'admin', pass: '' })

async function sha256hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function computeAuth(realm, nonce, nc, password) {
  const username = 'admin';
  const cnonce   = Math.floor(Math.random() * 0xFFFFFFFF).toString(16).padStart(8, '0');
  const nc_hex   = nc.toString(16).padStart(8, '0');
  const ha1      = await sha256hex(`${username}:${realm}:${password}`);
  const ha2      = await sha256hex('dummy_method:dummy_uri');
  // RFC 2617 qop=auth: ha1:nonce:nc:cnonce:auth:ha2
  const response = await sha256hex(`${ha1}:${nonce}:${nc_hex}:${cnonce}:auth:${ha2}`);
  return { realm, username, nonce, cnonce, nc: nc_hex, response, algorithm: 'SHA-256' };
}

// Returns the password string, or null if the user cancelled.
function promptPassword(message = 'Enter device password') {
  return new Promise(resolve => {
    pwdResolve = resolve;
    document.getElementById('pwdMessage').textContent = message;
    document.getElementById('pwdInput').value = '';
    document.getElementById('pwdModal').style.display = 'flex';
    document.getElementById('pwdInput').focus();
  });
}

// ── BLE transport (raw send + poll response) ─────────────────────────────────

async function writeChar(charUUID, dataView) {
  try {
    await BleClient.write(deviceId, SVC_UUID, charUUID, dataView);
  } catch {
    await BleClient.writeWithoutResponse(deviceId, SVC_UUID, charUUID, dataView);
  }
}

async function transport(payload) {
  const text  = JSON.stringify(payload);
  log(`→ ${text}`, 'info');
  const bytes = new TextEncoder().encode(text);

  // Signal request length to TX_CTL (4-byte big-endian)
  const lenView = new DataView(new ArrayBuffer(4));
  lenView.setUint32(0, bytes.length, false);
  await writeChar(TX_CTL_UUID, lenView);
  await delay(TX_DELAY);

  // Write request data in ≤20-byte chunks to DATA
  for (let i = 0; i < bytes.length; i += CHUNK) {
    await writeChar(DATA_UUID, new DataView(bytes.slice(i, i + CHUNK).buffer));
    if (i + CHUNK < bytes.length) await delay(10);
  }

  // Poll RX_CTL until device signals the response is ready
  const deadline = Date.now() + RPC_TIMEOUT;
  await delay(300);

  while (Date.now() < deadline) {
    let respLen = 0;
    try {
      const ctlVal = await BleClient.read(deviceId, SVC_UUID, RX_CTL_UUID);
      if (ctlVal.byteLength >= 4) {
        respLen = ctlVal.getUint32(0, false);
        if (respLen > 65536) respLen = ctlVal.getUint32(0, true);
      }
    } catch {
      await delay(POLL_INTERVAL);
      continue;
    }

    if (respLen > 0 && respLen <= 65536) {
      log(`← ${respLen} bytes incoming`, 'info');
      let rxBuf = new Uint8Array(0);
      const readDeadline = Date.now() + 3000;

      while (rxBuf.length < respLen && Date.now() < readDeadline) {
        const dataVal = await BleClient.read(deviceId, SVC_UUID, DATA_UUID);
        const chunk   = new Uint8Array(dataVal.buffer, dataVal.byteOffset, dataVal.byteLength);
        if (chunk.length === 0) break;
        const merged = new Uint8Array(rxBuf.length + chunk.length);
        merged.set(rxBuf);
        merged.set(chunk, rxBuf.length);
        rxBuf = merged;
        if (rxBuf.length < respLen) await delay(20);
      }

      const responseText = new TextDecoder().decode(rxBuf.slice(0, Math.min(respLen, rxBuf.length)));
      log(`← ${responseText}`, 'info');
      return JSON.parse(responseText);
    }

    await delay(POLL_INTERVAL);
  }

  throw new Error('Response timeout');
}

// ── RPC with auth retry ───────────────────────────────────────────────────────

async function sendRpc(method, params = {}) {
  if (!deviceId) throw new Error('Not connected');
  if (busy) throw new Error('Device is busy');
  busy = true;

  try {
    // First attempt (without auth, or with cached password)
    const id      = nextId++;
    const payload = { id, src: 'shelly-app', method, params };
    if (storedPassword) {
      // We don't know realm/nonce yet; send without auth first so the device
      // can challenge us if needed. If the device has auth enabled it will 401.
      // Alternatively, if we already know the device accepts our password from
      // a previous successful call, we still need the challenge nonce each time.
    }

    let response = await transport(payload);

    if (response.error?.code === 401) {
      // Shelly Gen3 embeds the auth challenge as a JSON string in error.message
      let challenge = response.www_auth;
      if (!challenge && response.error?.message) {
        try { challenge = JSON.parse(response.error.message); } catch {}
      }

      const realm = challenge?.realm ?? response.src;
      const nonce = challenge?.nonce;
      const nc    = challenge?.nc ?? 1;

      log(`← 401 realm="${realm}" nonce=${nonce}`, 'warn');
      if (!realm || nonce === undefined) throw new Error('Auth challenge missing realm/nonce');

      if (!storedPassword) {
        storedPassword = await promptPassword('Device is password-protected. Enter password:');
        if (!storedPassword) throw new Error('Authentication cancelled');
        await persistPassword(storedPassword);
        updateLockUI();
      }

      const auth         = await computeAuth(realm, nonce, nc, storedPassword);
      const retryId      = nextId++;
      const retryPayload = { id: retryId, src: 'shelly-app', method, params, auth };
      response           = await transport(retryPayload);

      if (response.error?.code === 401) {
        storedPassword = null;
        await persistPassword(null);
        updateLockUI();
        throw new Error('Incorrect password. Tap the lock to try again.');
      }
    }

    return response;
  } finally {
    busy = false;
  }
}

// ── High-level commands ───────────────────────────────────────────────────────

async function setDevicePassword() {
  const newPwd = await promptPassword('New device password (leave empty to disable auth):');
  if (newPwd === null) return; // cancelled

  try {
    const res = await sendRpc('Shelly.SetAuth', { user: 'admin', pass: newPwd });
    if (res.result !== undefined) {
      storedPassword = newPwd || null;
      await persistPassword(storedPassword);
      updateLockUI();
      log(newPwd ? 'Device auth enabled and password stored' : 'Device auth disabled', 'success');
    } else if (res.error) {
      log(`SetAuth error: ${res.error.message ?? JSON.stringify(res.error)}`, 'error');
    }
  } catch (e) {
    log(`SetAuth error: ${e.message}`, 'error');
  }
}

async function refreshStatus() {
  if (busy) return;
  try {
    const sw = await sendRpc('Switch.GetStatus', { id: 0 });
    if (sw.result !== undefined) {
      setBadge('outputBadge', sw.result.output ? 'ON' : 'OFF', sw.result.output);
    } else if (sw.error) {
      log(`Switch.GetStatus: ${sw.error.message ?? JSON.stringify(sw.error)}`, 'warn');
    }

    const inp = await sendRpc('Input.GetStatus', { id: 0 });
    if (inp.result !== undefined) {
      setBadge('inputBadge', inp.result.state ? 'PRESSED' : 'RELEASED', inp.result.state);
    } else if (inp.error) {
      log(`Input.GetStatus: ${inp.error.message ?? JSON.stringify(inp.error)}`, 'warn');
    }
  } catch (e) {
    log(`Refresh error: ${e.message}`, 'error');
  }
}

async function setSwitch(on) {
  if (busy) return;
  try {
    const res = await sendRpc('Switch.Set', { id: 0, on });
    if (res.result !== undefined) {
      log(`Relay turned ${on ? 'ON' : 'OFF'} (was ${res.result.was_on ? 'ON' : 'OFF'})`, 'success');
      await refreshStatus();
    } else if (res.error) {
      log(`Switch.Set error: ${res.error.message ?? JSON.stringify(res.error)}`, 'error');
    }
  } catch (e) {
    log(`Error: ${e.message}`, 'error');
  }
}

async function toggleSwitch() {
  if (busy) return;
  try {
    const res = await sendRpc('Switch.Toggle', { id: 0 });
    if (res.result !== undefined) {
      log('Relay toggled', 'success');
      await refreshStatus();
    } else if (res.error) {
      log(`Switch.Toggle error: ${res.error.message ?? JSON.stringify(res.error)}`, 'error');
    }
  } catch (e) {
    log(`Error: ${e.message}`, 'error');
  }
}

// ── Connection ────────────────────────────────────────────────────────────────

async function toggleConnect() {
  if (deviceId) await disconnect();
  else          await connect();
}

async function connect() {
  setConnState('connecting', 'Initializing Bluetooth…');
  document.getElementById('connectBtn').disabled = true;

  try {
    await BleClient.initialize();
    setConnState('connecting', 'Scanning for Shelly devices…');

    const device = await BleClient.requestDevice({ namePrefix: 'Shelly' });

    setConnState('connecting', 'Connecting…');
    await BleClient.connect(device.deviceId, onDisconnected);
    deviceId = device.deviceId;

    setConnState('connected', 'Connected');
    document.getElementById('deviceSub').textContent = device.name ?? 'Unknown device';
    document.getElementById('connectBtn').textContent = 'Disconnect';
    document.getElementById('connectBtn').disabled    = false;
    document.getElementById('statusCard').style.display  = 'block';
    document.getElementById('controlCard').style.display = 'block';

    log(`Connected to ${device.name ?? 'device'}`, 'success');
    await refreshStatus();

  } catch (e) {
    log(`Connection failed: ${e.message}`, 'error');
    setConnState('', 'Not connected');
    document.getElementById('connectBtn').disabled = false;
    deviceId = null;
  }
}

async function disconnect() {
  if (deviceId) {
    try { await BleClient.disconnect(deviceId); } catch {}
  }
  onDisconnected();
}

function onDisconnected() {
  stopAutoRefresh();
  document.getElementById('autoRefresh').checked = false;
  busy     = false;
  deviceId = null;

  setConnState('', 'Disconnected');
  document.getElementById('connectBtn').textContent  = 'Connect';
  document.getElementById('connectBtn').disabled     = false;
  document.getElementById('deviceSub').textContent   = '';
  document.getElementById('statusCard').style.display  = 'none';
  document.getElementById('controlCard').style.display = 'none';
  setBadge('outputBadge', '—', null);
  setBadge('inputBadge',  '—', null);
  log('Disconnected', 'warn');
}

// ── Auto-refresh ──────────────────────────────────────────────────────────────

function toggleAutoRefresh() {
  const on = document.getElementById('autoRefresh').checked;
  if (on) autoTimer = setInterval(refreshStatus, 2000);
  else    stopAutoRefresh();
}

function stopAutoRefresh() {
  clearInterval(autoTimer);
  autoTimer = null;
}

// ── Password modal handlers ───────────────────────────────────────────────────

function openPasswordModal() {
  // If a password is stored, let the user clear or change it
  const message = storedPassword
    ? 'Change password (leave empty to clear):'
    : 'Enter device password:';
  document.getElementById('pwdMessage').textContent = message;
  document.getElementById('pwdInput').value = '';
  document.getElementById('pwdModal').style.display = 'flex';
  document.getElementById('pwdInput').focus();
}

window.submitPassword = function () {
  const val = document.getElementById('pwdInput').value.trim();
  document.getElementById('pwdModal').style.display = 'none';

  if (pwdResolve) {
    // Called from an auth challenge inside sendRpc
    pwdResolve(val || null);
    pwdResolve = null;
  } else {
    // Called from the lock button (proactive setup)
    storedPassword = val || null;
    persistPassword(storedPassword);
    updateLockUI();
    log(storedPassword ? 'Password saved to Keychain' : 'Password cleared', 'info');
  }
};

window.cancelPassword = function () {
  document.getElementById('pwdModal').style.display = 'none';
  if (pwdResolve) {
    pwdResolve(null);
    pwdResolve = null;
  }
};

// Allow Enter key in password field to submit
document.addEventListener('DOMContentLoaded', () => {
  loadKeychainPassword();
  document.getElementById('pwdInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') window.submitPassword();
    if (e.key === 'Escape') window.cancelPassword();
  });
});

// ── UI helpers ────────────────────────────────────────────────────────────────

function updateLockUI() {
  const btn = document.getElementById('lockBtn');
  if (storedPassword) {
    btn.textContent = 'Auth: ON';
    btn.classList.add('lock-on');
  } else {
    btn.textContent = 'Set Auth';
    btn.classList.remove('lock-on');
  }
}

function setConnState(cls, text) {
  const dot = document.getElementById('dot');
  dot.className = cls ? `dot ${cls}` : 'dot';
  document.getElementById('connLabel').textContent = text;
}

function setBadge(id, text, on) {
  const el = document.getElementById(id);
  el.textContent = text;
  el.className = on === true ? 'badge on' : on === false ? 'badge off' : 'badge unknown';
}

function log(msg, type = 'info') {
  const box = document.getElementById('logBox');
  const p   = document.createElement('p');
  p.className   = type;
  const t = new Date().toLocaleTimeString([], { hour12: false });
  p.textContent = `[${t}] ${msg}`;
  box.appendChild(p);
  box.scrollTop = box.scrollHeight;
  while (box.children.length > 200) box.removeChild(box.firstChild);
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Expose to HTML onclick handlers ──────────────────────────────────────────
window.toggleConnect     = toggleConnect;
window.setSwitch         = setSwitch;
window.toggleSwitch      = toggleSwitch;
window.refreshStatus     = refreshStatus;
window.toggleAutoRefresh = toggleAutoRefresh;
window.openPasswordModal = openPasswordModal;
window.setDevicePassword = setDevicePassword;
