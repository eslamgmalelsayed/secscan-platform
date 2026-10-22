<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue';
import { api, type AuditEntry, type GrantSummary } from '../api';
import { attempt, notify } from '../toast';

const grants = ref<GrantSummary[]>([]);
const audit = ref<Record<string, AuditEntry[]>>({});
const openAudit = ref<string | null>(null);

// --- create grant form ---
const form = reactive({
  grantId: '', host: '', scheme: 'https', port: '', proof: 'dns_txt',
  hours: 24, allowStateChanging: false,
});
// --- owner sign-off (OTP) state, per grant ---
const sign = reactive<Record<string, { party: string; email: string; statement: string; challengeId?: string; code: string }>>({});

async function load() {
  const g = await attempt(() => api.grants.list());
  if (g) grants.value = g;
}
onMounted(load);

function ensureSign(id: string) {
  if (!sign[id]) sign[id] = { party: '', email: '', statement: 'I own these systems and authorize this test.', code: '' };
  return sign[id];
}

async function create() {
  if (!form.grantId || !form.host) return notify('grant id and host are required', true);
  const now = Date.now();
  const grant = {
    grantId: form.grantId,
    targets: [{ host: form.host, scheme: form.scheme, port: form.port ? Number(form.port) : null }],
    ownershipProof: form.proof, ownershipToken: `secscan-verify-${form.grantId}`,
    chain: [{ party: 'requester', email: 'requester@local', role: 'requester', signedAt: new Date(now).toISOString(), statement: 'requesting authorized test' }],
    notBefore: new Date(now - 60_000).toISOString(),
    notAfter: new Date(now + form.hours * 3_600_000).toISOString(),
    allowStateChanging: form.allowStateChanging, status: 'pending_owner',
  };
  const r = await attempt(() => api.grants.create(grant), `grant ${form.grantId} created`);
  if (r) { form.grantId = ''; form.host = ''; await load(); }
}

const act = async (fn: () => Promise<unknown>, ok: string) => { if (await attempt(fn, ok)) await load(); };

async function requestCode(id: string) {
  const s = ensureSign(id);
  const r = await attempt(() => api.grants.ownerSignRequest(id, { party: s.party, email: s.email, statement: s.statement }),
    'code emailed to the owner (check the mailbox / Mailpit)');
  if (r) s.challengeId = r.challengeId;
}
async function confirmCode(id: string) {
  const s = ensureSign(id);
  if (!s.challengeId) return;
  if (await attempt(() => api.grants.ownerSignConfirm(id, s.challengeId!, s.code), 'owner signature confirmed')) {
    delete sign[id]; await load();
  }
}
async function manualSign(id: string) {
  await act(() => api.grants.ownerSign(id, { party: 'lab-owner', email: 'owner@lab.local', role: 'system_owner', signedAt: new Date().toISOString(), statement: 'lab manual sign-off' }), 'owner signed (manual, lab)');
}
async function toggleAudit(id: string) {
  if (openAudit.value === id) { openAudit.value = null; return; }
  const a = await attempt(() => api.grants.audit(id));
  if (a) { audit.value[id] = a; openAudit.value = id; }
}
</script>

<template>
  <div>
    <div class="page-head">
      <div><h1>Authorization</h1><p>The gate. A grant must be ownership-verified, owner-signed and admin-approved before any scan.</p></div>
      <button class="btn sm" @click="load">Refresh</button>
    </div>

    <div class="grid cols-2">
      <div class="card">
        <h3>New grant</h3>
        <p class="sub">Define the target and window. Status starts as <code>pending_owner</code>.</p>
        <label>Grant id</label>
        <input v-model="form.grantId" placeholder="acme-staging-oct" />
        <div class="field-row">
          <div><label>Target host</label><input v-model="form.host" placeholder="app.example.com" /></div>
          <div><label>Scheme</label><select v-model="form.scheme"><option>https</option><option>http</option></select></div>
        </div>
        <div class="field-row">
          <div><label>Port (optional)</label><input v-model="form.port" placeholder="any" /></div>
          <div><label>Ownership proof</label><select v-model="form.proof"><option value="dns_txt">DNS TXT</option><option value="http_token">/.well-known file</option><option value="meta_tag">meta tag</option></select></div>
        </div>
        <div class="field-row">
          <div><label>Window (hours)</label><input v-model.number="form.hours" type="number" min="1" /></div>
          <div><label>State-changing replay</label><select v-model="form.allowStateChanging"><option :value="false">off (safe)</option><option :value="true">on (staging only)</option></select></div>
        </div>
        <div class="row end" style="margin-top: 14px"><button class="btn primary" @click="create">Create grant</button></div>
      </div>

      <div class="card">
        <h3>How sign-off works</h3>
        <ul class="hint" style="padding-left: 18px; line-height: 1.9">
          <li><b>Ownership</b> — automatic proof (DNS TXT / well-known file / meta tag). Lab targets without a mailbox use the admin <i>manual</i> button.</li>
          <li><b>Owner sign-off</b> — a one-time code is emailed to a mailbox on the target's own domain; enter it to sign. The server writes the owner link itself.</li>
          <li><b>Approve</b> — an admin confirms. Only then does the grant become <code>active</code>.</li>
        </ul>
        <p class="hint">Admin actions (manual ownership, manual sign, approve, revoke) need the admin token set in the sidebar.</p>
      </div>
    </div>

    <h2 style="margin: 24px 0 12px">Grants</h2>
    <div v-if="!grants.length" class="card empty">No grants yet.</div>

    <div v-for="g in grants" :key="g.grantId" class="card" style="margin-bottom: 14px">
      <div class="row between">
        <div>
          <h3 style="display: inline">{{ g.grantId }}</h3>
          <span class="chip" :class="g.status === 'active' ? 'ok' : g.status === 'revoked' ? 'bad' : 'warn'" style="margin-left: 8px">{{ g.status }}</span>
        </div>
        <div class="row" style="gap: 6px">
          <span class="chip" :class="g.ownershipVerified ? 'ok' : ''">ownership {{ g.ownershipVerified ? '✓' : '—' }}</span>
          <span class="chip" :class="g.ownerSigned ? 'ok' : ''">owner {{ g.ownerSigned ? '✓' : '—' }}</span>
          <span class="chip" :class="g.adminApproved ? 'ok' : ''">approved {{ g.adminApproved ? '✓' : '—' }}</span>
        </div>
      </div>
      <div class="kv" style="margin-top: 10px">
        <b>Targets</b><span class="mono">{{ (g.targets ?? []).map((t) => `${t.scheme}://${t.host}${t.port ? ':' + t.port : ''}`).join(', ') }}</span>
        <b>Window</b><span class="mono">{{ g.notBefore?.slice(0, 16).replace('T', ' ') }} → {{ g.notAfter?.slice(0, 16).replace('T', ' ') }}</span>
      </div>

      <div class="row" style="margin-top: 14px; gap: 8px">
        <button class="btn sm" @click="act(() => api.grants.ownership(g.grantId), 'ownership verified')" :disabled="g.ownershipVerified">Verify ownership</button>
        <button class="btn sm" @click="act(() => api.grants.ownershipManual(g.grantId), 'ownership recorded (manual)')" :disabled="g.ownershipVerified">Manual (admin)</button>
        <button class="btn sm primary" @click="act(() => api.grants.approve(g.grantId), 'approved')" :disabled="g.adminApproved">Approve (admin)</button>
        <button class="btn sm danger" @click="act(() => api.grants.revoke(g.grantId), 'revoked')" :disabled="g.status === 'revoked'">Revoke</button>
        <button class="btn sm" @click="toggleAudit(g.grantId)">{{ openAudit === g.grantId ? 'Hide' : 'Audit' }}</button>
      </div>

      <!-- owner sign-off (OTP) -->
      <div v-if="!g.ownerSigned" class="card" style="margin-top: 14px; background: var(--bg-2)">
        <h3 style="font-size: 13px">Owner sign-off</h3>
        <div class="field-row">
          <div><label>Owner name</label><input v-model="ensureSign(g.grantId).party" placeholder="Jane Owner" /></div>
          <div><label>Owner email (on target domain)</label><input v-model="ensureSign(g.grantId).email" placeholder="owner@example.com" /></div>
        </div>
        <label>Statement</label>
        <input v-model="ensureSign(g.grantId).statement" />
        <div class="row" style="margin-top: 10px; gap: 8px">
          <button class="btn sm" @click="requestCode(g.grantId)">Email code</button>
          <template v-if="sign[g.grantId]?.challengeId">
            <input v-model="sign[g.grantId].code" placeholder="code" style="max-width: 140px" />
            <button class="btn sm primary" @click="confirmCode(g.grantId)">Confirm</button>
          </template>
          <button class="btn sm" @click="manualSign(g.grantId)">Manual sign (admin · lab)</button>
        </div>
      </div>

      <ul v-if="openAudit === g.grantId" class="timeline" style="margin-top: 14px">
        <li v-for="(e, i) in audit[g.grantId]" :key="i"><span class="t">{{ e.at?.slice(0, 19).replace('T', ' ') }}</span><span><b>{{ e.action }}</b> <span class="hint">· {{ e.actor }}{{ e.detail ? ' · ' + e.detail : '' }}</span></span></li>
      </ul>
    </div>
  </div>
</template>
