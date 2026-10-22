<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { api, type Health, type ScanSummary } from '../api';
import { attempt, notify } from '../toast';

defineProps<{ health: Health | null }>();
const emit = defineEmits<{ go: [view: 'overview' | 'grants' | 'scan' | 'results']; 'open-scan': [id: string] }>();

const scans = ref<ScanSummary[]>([]);
const identityCount = ref<number | null>(null);
const quickUrl = ref('');
const quickBusy = ref(false);

async function load() {
  const s = await attempt(() => api.scans.list());
  if (s) scans.value = s;
  try { identityCount.value = (await api.identities()).length; } catch { /* auth may be required */ }
}
onMounted(load);

async function runQuick() {
  if (!quickUrl.value.trim()) return;
  quickBusy.value = true;
  const scan = await attempt(() => api.scans.quick(quickUrl.value.trim()), 'quick scan done');
  quickBusy.value = false;
  if (scan) { quickUrl.value = ''; load(); emit('open-scan', scan.id); }
}

const msg = ref('');
async function broadcast() {
  if (!msg.value.trim()) return;
  const r = await attempt(() => api.messages.broadcast(msg.value.trim()));
  if (r) { notify(`sent to ${r.delivered} device(s)`); msg.value = ''; }
}
</script>

<template>
  <div>
    <div class="page-head">
      <div>
        <h1>Overview</h1>
        <p>Local console for authorized web/API security testing.</p>
      </div>
      <button class="btn primary" @click="emit('go', 'scan')">New scan</button>
    </div>

    <div class="grid cols-4" style="margin-bottom: 16px">
      <div class="card stat">
        <span class="l">API</span>
        <span class="n"><span class="chip" :class="health ? 'ok' : 'bad'">{{ health ? 'online' : 'unreachable' }}</span></span>
      </div>
      <div class="card stat">
        <span class="l">Targets</span>
        <span class="n"><span class="chip" :class="health?.legalResolved ? 'warn' : 'accent'">{{ health?.legalResolved ? 'external unlocked' : 'lab only' }}</span></span>
      </div>
      <div class="card stat">
        <span class="l">Test identities</span>
        <span class="n">{{ identityCount ?? health?.identities ?? '—' }}</span>
      </div>
      <div class="card stat">
        <span class="l">Scans</span>
        <span class="n">{{ scans.length }}</span>
      </div>
    </div>

    <div v-if="health?.devTrust" class="card accent-border" style="margin-bottom: 16px">
      <h3>Quick scan <span class="chip accent">dev-trust</span></h3>
      <p class="sub">Paste a URL you own — SecScan crawls its public surface and runs the non-destructive suite in one step. Add test identities (<code>SECSCAN_IDENTITIES_FILE</code>) to cover logged-in pages and turn on the IDOR engine.</p>
      <div class="row" style="gap: 8px; margin-top: 10px">
        <input v-model="quickUrl" placeholder="https://localhost:3000/" style="flex: 1" @keyup.enter="runQuick" />
        <button class="btn primary" :disabled="quickBusy || !quickUrl.trim()" @click="runQuick">{{ quickBusy ? 'Scanning…' : 'Scan' }}</button>
      </div>
    </div>

    <div class="card" style="margin-bottom: 16px">
      <h3>Broadcast to devices</h3>
      <p class="sub">Open <code>/display</code> on any device (phone, tablet, TV browser) on the network, then send a message — it pops on every open receiver. Run with <code>SECSCAN_HOST=0.0.0.0</code> so other devices can reach it.</p>
      <div class="row" style="gap: 8px; margin-top: 10px">
        <input v-model="msg" placeholder="message to show on your devices" style="flex: 1" @keyup.enter="broadcast" />
        <button class="btn" :disabled="!msg.trim()" @click="broadcast">Send</button>
        <a class="btn sm" href="/display" target="_blank">Open receiver</a>
      </div>
    </div>

    <div class="card" style="margin-bottom: 16px">
      <h3>Workflow</h3>
      <p class="sub">Authorization is the gate — no scan runs without a verified, owner-signed, admin-approved grant.</p>
      <div class="steps">
        <button class="s cur" @click="emit('go', 'grants')"><b>1</b> Authorization</button>
        <button class="s" @click="emit('go', 'scan')"><b>2</b> Scan setup</button>
        <button class="s" @click="emit('go', 'results')"><b>3</b> Results &amp; reports</button>
      </div>
      <p class="hint" style="margin-top: 12px" v-if="health">
        Owner sign-off by email: <b>{{ health.ownerEmailSignOff ? 'enabled' : 'disabled (manual admin path only)' }}</b>.
        Admin token: <b>{{ health.adminTokenRequired ? 'required' : 'open (local dev)' }}</b>.
        API token: <b>{{ health.apiTokenRequired ? 'required' : 'open (local dev)' }}</b>.
      </p>
    </div>

    <div class="card pad-0">
      <div class="row between" style="padding: 16px 18px 0">
        <h3 style="margin: 0">Recent scans</h3>
        <button class="btn sm" @click="load">Refresh</button>
      </div>
      <table v-if="scans.length">
        <thead><tr><th>Scan</th><th>Status</th><th>Confirmed</th><th>Review</th><th>Not tested</th><th>Created</th></tr></thead>
        <tbody>
          <tr v-for="s in scans" :key="s.id" style="cursor: pointer" @click="emit('open-scan', s.id)">
            <td class="mono">{{ s.id }}</td>
            <td><span class="chip" :class="s.status === 'done' ? 'ok' : s.status === 'failed' ? 'bad' : 'warn'">{{ s.status }}</span></td>
            <td>{{ s.confirmed }}</td>
            <td>{{ s.review }}</td>
            <td>{{ s.notTested }}</td>
            <td class="mono">{{ s.createdAt?.slice(0, 19).replace('T', ' ') ?? '—' }}</td>
          </tr>
        </tbody>
      </table>
      <div v-else class="empty">No scans yet. Start from <a @click="emit('go', 'grants')">Authorization</a>.</div>
    </div>
  </div>
</template>
