<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue';
import { api, type Identity } from '../api';
import { attempt, notify } from '../toast';

const identities = ref<Identity[]>([]);
const busy = ref(false);
const form = reactive({ role: 'customer', tenant: '', cookieName: 'sid', cookieValue: '', bearer: '', liveness: '' });

// Desktop app exposes window.secscan.captureLogin for one-click login capture.
const desktop = (window as any).secscan?.desktop === true;
const loginUrl = ref('');

async function load() { try { identities.value = await api.identities(); } catch { /* auth */ } }
onMounted(load);

async function captureViaLogin() {
  if (!loginUrl.value.trim()) return notify('enter the site URL to log in to', true);
  if (!form.role.trim()) return notify('set a role first', true);
  busy.value = true;
  const r = await (window as any).secscan.captureLogin({ url: loginUrl.value.trim(), role: form.role.trim(), tenant: form.tenant.trim() || null });
  busy.value = false;
  if (r?.error) return notify(r.error, true);
  if (r?.identities) { identities.value = r.identities; notify('login captured'); }
}

async function add() {
  if (!form.role.trim()) return notify('role is required', true);
  if (!form.cookieValue.trim() && !form.bearer.trim()) return notify('paste a session cookie value or a bearer token', true);
  busy.value = true;
  const body: any = { role: form.role.trim(), tenant: form.tenant.trim() || null, liveness: form.liveness.trim() || undefined };
  if (form.cookieValue.trim()) body.cookies = { [form.cookieName.trim() || 'sid']: form.cookieValue.trim() };
  if (form.bearer.trim()) body.bearer = form.bearer.trim();
  const r = await attempt(() => api.captureIdentity(body), 'test account added');
  busy.value = false;
  if (r) { identities.value = r.identities; form.cookieValue = ''; form.bearer = ''; }
}
</script>

<template>
  <div>
    <div class="page-head"><div><h1>Test accounts</h1><p>Add two or more logins so the scanner can test object-level authorization (IDOR / cross-tenant). Secrets stay server-side; only the role/tenant key is ever shown.</p></div></div>

    <div v-if="desktop" class="card accent-border" style="margin-bottom: 16px">
      <h3>Log in &amp; capture <span class="chip accent">desktop</span></h3>
      <p class="sub">Set the role/tenant below, enter the site, and sign in — a window opens; when you close it, the session is captured as a test account. No cookie copying. Do this for two accounts to enable IDOR.</p>
      <div class="row" style="gap: 8px; margin-top: 10px">
        <input v-model="loginUrl" placeholder="https://yoursite.com/login" style="flex: 1" />
        <button class="btn primary" :disabled="busy" @click="captureViaLogin">{{ busy ? 'Waiting for login…' : 'Log in & capture' }}</button>
      </div>
    </div>

    <div class="card" style="margin-bottom: 16px">
      <h3>How to get a session cookie<span v-if="desktop" class="hint"> (manual alternative)</span></h3>
      <ol class="sub" style="margin: 8px 0 0; padding-left: 18px; line-height: 1.8">
        <li>Log in to the target site as the test account in your browser.</li>
        <li>Open DevTools (F12) → <b>Application</b> → <b>Cookies</b> → pick the site.</li>
        <li>Find the session cookie (often <code>sid</code>, <code>session</code>, <code>connect.sid</code>, <code>JSESSIONID</code>…), copy its <b>name</b> and <b>value</b> below.</li>
        <li>Add a <b>second</b> account the same way (different user, or different tenant) — IDOR needs two.</li>
      </ol>
    </div>

    <div class="grid cols-2">
      <div class="card">
        <h3>Add a test account</h3>
        <div class="field-row">
          <div><label>Role</label><input v-model="form.role" placeholder="customer" /></div>
          <div><label>Tenant (optional)</label><input v-model="form.tenant" placeholder="t1" /></div>
        </div>
        <div class="field-row">
          <div><label>Cookie name</label><input v-model="form.cookieName" placeholder="sid" /></div>
          <div><label>Cookie value</label><input v-model="form.cookieValue" placeholder="paste the session value" /></div>
        </div>
        <label>…or a Bearer token (optional)</label>
        <input v-model="form.bearer" placeholder="eyJ… (if the site uses Authorization: Bearer)" />
        <label>Liveness URL (optional)</label>
        <input v-model="form.liveness" placeholder="https://site/api/me — a 2xx-only-while-logged-in URL" />
        <div class="row end" style="margin-top: 12px"><button class="btn primary" :disabled="busy" @click="add">Add account</button></div>
      </div>

      <div class="card pad-0">
        <div style="padding: 14px 16px"><h3 style="margin: 0">Loaded accounts</h3></div>
        <table v-if="identities.length">
          <thead><tr><th>Role</th><th>Tenant</th><th>Key</th></tr></thead>
          <tbody><tr v-for="(i, k) in identities" :key="k"><td>{{ i.role }}</td><td>{{ i.tenant ?? '—' }}</td><td class="mono">{{ i.sessionRef }}</td></tr></tbody>
        </table>
        <div v-else class="empty" style="padding: 16px">No accounts yet. Add two to enable IDOR/cross-tenant testing, then run a scan.</div>
      </div>
    </div>
  </div>
</template>
