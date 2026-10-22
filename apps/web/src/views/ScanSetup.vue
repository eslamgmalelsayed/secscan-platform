<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { api, type Flow, type GrantSummary, type Identity } from '../api';
import { attempt, notify } from '../toast';

const emit = defineEmits<{ 'open-scan': [id: string] }>();

const grants = ref<GrantSummary[]>([]);
const identities = ref<Identity[]>([]);
const flows = ref<Flow[]>([]);
const running = ref(false);

const form = reactive({
  grantId: '', engagementId: '', client: '', rootUrl: '',
  importKind: 'har' as 'har' | 'openapi', importText: '', capturedAsRole: '', capturedAsTenant: '', baseUrl: '',
  tokens: '',
});
const activeGrants = computed(() => grants.value.filter((g) => g.status === 'active'));

async function load() {
  const g = await attempt(() => api.grants.list());
  if (g) grants.value = g;
  try { identities.value = await api.identities(); } catch { /* auth */ }
}
onMounted(load);

async function importFlows() {
  if (form.importText.trim().length < 2) return notify('paste a HAR or OpenAPI document first', true);
  const body = form.importKind === 'har'
    ? { kind: 'har', text: form.importText, capturedAsRole: form.capturedAsRole || undefined, capturedAsTenant: form.capturedAsTenant || undefined }
    : { kind: 'openapi', text: form.importText, capturedAsRole: form.capturedAsRole || undefined, baseUrl: form.baseUrl || undefined };
  const r = await attempt(() => api.flows.import(body), undefined);
  if (r) { flows.value = r.flows; notify(`imported ${r.count} flow(s)`); }
}

async function run() {
  if (!form.grantId) return notify('pick an active grant', true);
  if (!flows.value.length) return notify('import at least one flow', true);
  const engagementId = form.engagementId || `eng-${form.grantId}`;
  // create a minimal engagement so the report has a header
  const g = grants.value.find((x) => x.grantId === form.grantId);
  await attempt(() => api.engagements.create({
    id: engagementId, client: form.client || form.grantId, preparedBy: 'SecScan',
    assets: (g?.targets ?? []).map((t) => t.host), environment: g?.targets?.[0]?.scheme === 'http' ? 'staging' : 'production',
    authorizationRef: form.grantId,
    window: { start: g?.notBefore ?? new Date().toISOString(), end: g?.notAfter ?? new Date().toISOString() },
    methodology: { ar: 'اختبار صلاحيات حتمي وفحوصات غير مدمّرة', en: 'Deterministic authorization testing and non-destructive checks' },
    limitations: { ar: 'ضمن النطاق المصرّح به فقط', en: 'Authorized scope only' },
  }), undefined);

  running.value = true;
  const scan = await attempt(() => api.scans.run({
    engagementId, grantId: form.grantId, flows: flows.value, identities: identities.value,
    rootUrl: form.rootUrl || undefined,
    tokens: form.tokens.split(/\s+/).map((t) => t.trim()).filter(Boolean),
  }), 'scan complete');
  running.value = false;
  if (scan) emit('open-scan', scan.id);
}
</script>

<template>
  <div>
    <div class="page-head"><div><h1>Scan setup</h1><p>Pick an authorized grant, import the recorded flows, and run.</p></div></div>

    <div v-if="!activeGrants.length" class="card empty">
      No <b>active</b> grant yet. Finish <a>Authorization</a> first (verify ownership → owner sign-off → approve).
    </div>

    <template v-else>
      <div class="grid cols-2">
        <div class="card">
          <h3>Target</h3>
          <label>Active grant</label>
          <select v-model="form.grantId">
            <option value="" disabled>select a grant…</option>
            <option v-for="g in activeGrants" :key="g.grantId" :value="g.grantId">{{ g.grantId }} — {{ (g.targets ?? []).map((t) => t.host).join(', ') }}</option>
          </select>
          <div class="field-row">
            <div><label>Engagement id</label><input v-model="form.engagementId" placeholder="auto: eng-<grant>" /></div>
            <div><label>Client name</label><input v-model="form.client" placeholder="for the report header" /></div>
          </div>
          <label>Root URL for the scorecard (optional)</label>
          <input v-model="form.rootUrl" placeholder="defaults to the grant's first target" />
          <label>JWTs to analyze (optional, whitespace-separated)</label>
          <textarea v-model="form.tokens" style="min-height: 60px" placeholder="eyJ…"></textarea>
        </div>

        <div class="card">
          <h3>Test identities</h3>
          <p class="sub">Loaded at boot from <code>SECSCAN_IDENTITIES_FILE</code> (secrets stay server-side).</p>
          <table v-if="identities.length">
            <thead><tr><th>Role</th><th>Tenant</th><th>Key</th></tr></thead>
            <tbody><tr v-for="(i, k) in identities" :key="k"><td>{{ i.role }}</td><td>{{ i.tenant ?? '—' }}</td><td class="mono">{{ i.sessionRef }}</td></tr></tbody>
          </table>
          <div v-else class="empty" style="padding: 14px">No identities loaded — the scan runs anonymously (public surface only).</div>
        </div>
      </div>

      <div class="card" style="margin-top: 16px">
        <h3>Flows</h3>
        <p class="sub">Import a HAR capture or an OpenAPI document. Session cookies/bearers are stripped; identities are applied at send time.</p>
        <div class="field-row">
          <div><label>Source</label><select v-model="form.importKind"><option value="har">HAR</option><option value="openapi">OpenAPI</option></select></div>
          <div><label>Captured as role</label><input v-model="form.capturedAsRole" placeholder="customer" /></div>
        </div>
        <div class="field-row">
          <div v-if="form.importKind === 'har'"><label>Captured as tenant</label><input v-model="form.capturedAsTenant" placeholder="t1 (optional)" /></div>
          <div v-else><label>Base URL override</label><input v-model="form.baseUrl" placeholder="https://staging.example.com" /></div>
        </div>
        <label>Paste {{ form.importKind.toUpperCase() }}</label>
        <textarea v-model="form.importText" :placeholder="form.importKind === 'har' ? '{ \&quot;log\&quot;: { \&quot;entries\&quot;: [ … ] } }' : '{ \&quot;openapi\&quot;: \&quot;3.0.0\&quot;, \&quot;paths\&quot;: { … } }'"></textarea>
        <div class="row between" style="margin-top: 12px">
          <button class="btn" @click="importFlows">Import flows</button>
          <span class="chip" :class="flows.length ? 'ok' : ''">{{ flows.length }} flow(s) ready</span>
        </div>
        <table v-if="flows.length" style="margin-top: 12px">
          <thead><tr><th>Method</th><th>URL</th><th>Role</th><th>Auth?</th></tr></thead>
          <tbody><tr v-for="(f, i) in flows.slice(0, 20)" :key="i"><td>{{ f.method }}</td><td class="mono">{{ f.url }}</td><td>{{ f.capturedAsRole ?? '—' }}</td><td>{{ f.requiresAuth ? 'yes' : '' }}</td></tr></tbody>
        </table>
      </div>

      <div class="row end" style="margin-top: 16px">
        <button class="btn primary" :disabled="running || !form.grantId || !flows.length" @click="run">{{ running ? 'Scanning…' : 'Run scan' }}</button>
      </div>
    </template>
  </div>
</template>
