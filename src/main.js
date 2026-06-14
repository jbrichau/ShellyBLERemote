import { BleClient } from '@capacitor-community/bluetooth-le';
import { SecureStoragePlugin } from 'capacitor-secure-storage-plugin';

// ── Shelly BLE RPC UUIDs ─────────────────────────────────────────────────────
const SVC_UUID    = '5f6d4f53-5f52-5043-5f53-56435f49445f';
const DATA_UUID   = '5f6d4f53-5f52-5043-5f64-6174615f5f5f';
const TX_CTL_UUID = '5f6d4f53-5f52-5043-5f74-785f63746c5f';
const RX_CTL_UUID = '5f6d4f53-5f52-5043-5f72-785f63746c5f';

const CHUNK = 20, RPC_TIMEOUT = 10_000, TX_DELAY = 200, POLL_INTERVAL = 150;

// ── State ────────────────────────────────────────────────────────────────────
let deviceId       = null;
let connState      = 'disconnected';
let nextId         = 1;
let busy           = false;
let storedPassword = null;
let pwdResolve     = null;

const PWD_KEY = 'shelly_device_password';
const DEV_KEY = 'shelly_device';

// ── Startup ──────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
  await loadKeychainPassword();

  const saved = getSavedDevice();
  if (saved) {
    updateDeviceLabel(saved.name);
    await autoConnect(saved);
  } else {
    setBtnState('disconnected', 'Tap to pair');
  }

  document.getElementById('pwdInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') window.submitPassword();
    if (e.key === 'Escape') window.cancelPassword();
  });
});

// ── Device persistence (localStorage) ────────────────────────────────────────

function getSavedDevice() {
  try { return JSON.parse(localStorage.getItem(DEV_KEY)); } catch { return null; }
}

function saveDevice(id, name) {
  localStorage.setItem(DEV_KEY, JSON.stringify({ id, name }));
}

function clearSavedDevice() {
  localStorage.removeItem(DEV_KEY);
}

function updateDeviceLabel(name) {
  document.getElementById('deviceLabel').textContent = name || '';
}

// ── BLE connection ────────────────────────────────────────────────────────────

async function autoConnect(saved) {
  setBtnState('connecting', 'Connecting…');
  try {
    await BleClient.initialize();
    await BleClient.connect(saved.id, onDisconnected);
    deviceId = saved.id;
    setBtnState('connected', 'Tap to open · close');
    log(`Connected to ${saved.name}`, 'success');
  } catch {
    log('Auto-connect failed — tap to retry', 'warn');
    setBtnState('disconnected', 'Tap to connect');
  }
}

async function connect() {
  setBtnState('connecting', 'Scanning…');
  try {
    await BleClient.initialize();
    const device = await BleClient.requestDevice({ namePrefix: 'Shelly' });
    setBtnState('connecting', 'Connecting…');
    await BleClient.connect(device.deviceId, onDisconnected);
    deviceId = device.deviceId;
    const name = device.name ?? 'Shelly device';
    saveDevice(deviceId, name);
    updateDeviceLabel(name);
    setBtnState('connected', 'Tap to open · close');
    log(`Connected to ${name}`, 'success');
  } catch (e) {
    log(`Connection failed: ${e.message}`, 'error');
    setBtnState('disconnected', getSavedDevice() ? 'Tap to connect' : 'Tap to pair');
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
  deviceId = null;
  busy     = false;
  setBtnState('disconnected', getSavedDevice() ? 'Tap to connect' : 'Tap to pair');
  log('Disconnected', 'warn');
}

// ── Main button ───────────────────────────────────────────────────────────────

async function handleGarageBtn() {
  if (connState === 'connecting') return;
  if (connState === 'connected') {
    await triggerGarage();
  } else {
    await connect();
  }
}

async function triggerGarage() {
  if (busy) return;
  flashBtn();
  try {
    const res = await sendRpc('Switch.Toggle', { id: 0 });
    if (res.result !== undefined) {
      log('Triggered', 'success');
    } else if (res.error) {
      log(`Error: ${res.error.message}`, 'error');
    }
  } catch (e) {
    log(`Error: ${e.message}`, 'error');
  }
}

function flashBtn() {
  const btn = document.getElementById('garageBtn');
  btn.classList.add('triggered');
  setTimeout(() => btn.classList.remove('triggered'), 400);
}

// ── UI state ──────────────────────────────────────────────────────────────────

function setBtnState(state, label) {
  connState = state;
  document.getElementById('garageBtn').className = `garage-btn ${state}`;
  document.getElementById('btnLabel').textContent = label;
}

// ── Settings sheet ────────────────────────────────────────────────────────────

function openSettings() {
  const saved = getSavedDevice();
  document.getElementById('settingDeviceName').textContent = saved?.name ?? 'None';
  document.getElementById('forgetDeviceBtn').style.display = saved ? 'block' : 'none';
  document.getElementById('settingAuthStatus').textContent = storedPassword ? 'Set ✓' : 'None';
  document.getElementById('settingsPanel').classList.add('open');
}

function closeSettings() {
  document.getElementById('settingsPanel').classList.remove('open');
}

function handleOverlayClick(e) {
  if (e.target === document.getElementById('settingsPanel')) closeSettings();
}

function toggleLog() {
  document.getElementById('logBox').classList.toggle('visible');
}

async function forgetDevice() {
  clearSavedDevice();
  updateDeviceLabel('');
  closeSettings();
  await disconnect();
  log('Device forgotten', 'info');
}

async function pairNewDevice() {
  closeSettings();
  if (deviceId) await disconnect();
  await connect();
}

function changeAppPassword() {
  closeSettings();
  const msg = storedPassword ? 'New password (leave empty to clear):' : 'Enter device password:';
  document.getElementById('pwdMessage').textContent = msg;
  document.getElementById('pwdInput').value = '';
  document.getElementById('pwdModal').style.display = 'flex';
  document.getElementById('pwdInput').focus();
}

async function setDevicePassword() {
  closeSettings();
  const newPwd = await promptPassword('New device password (empty to disable auth):');
  if (newPwd === null) return;
  try {
    const res = await sendRpc('Shelly.SetAuth', { user: 'admin', pass: newPwd });
    if (res.result !== undefined) {
      storedPassword = newPwd || null;
      await persistPassword(storedPassword);
      log(newPwd ? 'Device password updated' : 'Device auth disabled', 'success');
    } else if (res.error) {
      log(`SetAuth error: ${res.error.message}`, 'error');
    }
  } catch (e) {
    log(`SetAuth error: ${e.message}`, 'error');
  }
}

// ── Password modal ────────────────────────────────────────────────────────────

function promptPassword(message) {
  return new Promise(resolve => {
    pwdResolve = resolve;
    document.getElementById('pwdMessage').textContent = message;
    document.getElementById('pwdInput').value = '';
    document.getElementById('pwdModal').style.display = 'flex';
    document.getElementById('pwdInput').focus();
  });
}

window.submitPassword = function () {
  const val = document.getElementById('pwdInput').value.trim();
  document.getElementById('pwdModal').style.display = 'none';

  if (pwdResolve) {
    // Auth challenge or setDevicePassword flow
    pwdResolve(val || null);
    pwdResolve = null;
  } else {
    // changeAppPassword flow (no resolver — update directly)
    storedPassword = val || null;
    persistPassword(storedPassword);
    log(storedPassword ? 'Password saved to Keychain' : 'Password cleared', 'info');
  }
};

window.cancelPassword = function () {
  document.getElementById('pwdModal').style.display = 'none';
  if (pwdResolve) { pwdResolve(null); pwdResolve = null; }
};

// ── Keychain ──────────────────────────────────────────────────────────────────

async function loadKeychainPassword() {
  try {
    const { value } = await SecureStoragePlugin.get({ key: PWD_KEY });
    if (value) storedPassword = value;
  } catch {}
}

async function persistPassword(pwd) {
  try {
    if (pwd) await SecureStoragePlugin.set({ key: PWD_KEY, value: pwd });
    else      await SecureStoragePlugin.remove({ key: PWD_KEY });
  } catch (e) { log(`Keychain error: ${e.message}`, 'warn'); }
}

// ── Auth (Shelly Gen3 SHA-256 digest) ────────────────────────────────────────

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
  const response = await sha256hex(`${ha1}:${nonce}:${nc_hex}:${cnonce}:auth:${ha2}`);
  return { realm, username, nonce, cnonce, nc: nc_hex, response, algorithm: 'SHA-256' };
}

// ── BLE transport ─────────────────────────────────────────────────────────────

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

  const lenView = new DataView(new ArrayBuffer(4));
  lenView.setUint32(0, bytes.length, false);
  await writeChar(TX_CTL_UUID, lenView);
  await delay(TX_DELAY);

  for (let i = 0; i < bytes.length; i += CHUNK) {
    await writeChar(DATA_UUID, new DataView(bytes.slice(i, i + CHUNK).buffer));
    if (i + CHUNK < bytes.length) await delay(10);
  }

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
      let rxBuf = new Uint8Array(0);
      const readDeadline = Date.now() + 3000;

      while (rxBuf.length < respLen && Date.now() < readDeadline) {
        const dataVal = await BleClient.read(deviceId, SVC_UUID, DATA_UUID);
        const chunk   = new Uint8Array(dataVal.buffer, dataVal.byteOffset, dataVal.byteLength);
        if (chunk.length === 0) break;
        const merged  = new Uint8Array(rxBuf.length + chunk.length);
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
    const id      = nextId++;
    const payload = { id, src: 'shelly-app', method, params };
    let response  = await transport(payload);

    if (response.error?.code === 401) {
      let challenge = response.www_auth;
      if (!challenge && response.error?.message) {
        try { challenge = JSON.parse(response.error.message); } catch {}
      }

      const realm = challenge?.realm ?? response.src;
      const nonce = challenge?.nonce;
      const nc    = challenge?.nc ?? 1;

      if (!realm || nonce === undefined) throw new Error('Auth challenge missing realm/nonce');

      if (!storedPassword) {
        storedPassword = await promptPassword('Device is password-protected. Enter password:');
        if (!storedPassword) throw new Error('Authentication cancelled');
        await persistPassword(storedPassword);
      }

      const auth         = await computeAuth(realm, nonce, nc, storedPassword);
      const retryId      = nextId++;
      const retryPayload = { id: retryId, src: 'shelly-app', method, params, auth };
      response           = await transport(retryPayload);

      if (response.error?.code === 401) {
        storedPassword = null;
        await persistPassword(null);
        throw new Error('Incorrect password — update it in Settings.');
      }
    }

    return response;
  } finally {
    busy = false;
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function log(msg, type = 'info') {
  const box = document.getElementById('logBox');
  const p   = document.createElement('p');
  p.className   = type;
  p.textContent = `[${new Date().toLocaleTimeString([], { hour12: false })}] ${msg}`;
  box.appendChild(p);
  box.scrollTop = box.scrollHeight;
  while (box.children.length > 200) box.removeChild(box.firstChild);
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Expose to HTML ────────────────────────────────────────────────────────────
window.handleGarageBtn    = handleGarageBtn;
window.openSettings       = openSettings;
window.closeSettings      = closeSettings;
window.handleOverlayClick = handleOverlayClick;
window.toggleLog          = toggleLog;
window.forgetDevice       = forgetDevice;
window.pairNewDevice      = pairNewDevice;
window.changeAppPassword  = changeAppPassword;
window.setDevicePassword  = setDevicePassword;
