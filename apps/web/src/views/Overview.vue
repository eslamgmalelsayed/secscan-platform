<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { api, type Health, type ScanSummary } from '../api';
import { attempt } from '../toast';

defineProps<{ health: Health | null }>();
const emit = defineEmits<{ go: [view: 'overview' | 'grants' | 'scan' | 'results']; 'open-scan': [id: string] }>();

const scans = ref<ScanSummary[]>([]);
const identityCount = ref<number | null>(null);

async function load() {
  const s = await attempt(() => api.scans.list());
  if (s) scans.value = s;
  try { identityCount.value = (await api.identities()).length; } catch { /* auth may be required */ }
}
onMounted(load);
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
