<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { api, settings, saveSettings } from './api';
import Overview from './views/Overview.vue';
import Grants from './views/Grants.vue';
import ScanSetup from './views/ScanSetup.vue';
import Results from './views/Results.vue';
import { toast } from './toast';

type View = 'overview' | 'grants' | 'scan' | 'results';
const view = ref<View>('overview');
const health = ref<{ ok: boolean; legalResolved: boolean; adminTokenRequired: boolean; identities: number } | null>(null);
const apiDown = ref(false);
const selectedScan = ref<string | null>(null);

async function refreshHealth() {
  try { health.value = await api.health(); apiDown.value = false; }
  catch { apiDown.value = true; }
}
onMounted(() => { refreshHealth(); setInterval(refreshHealth, 10_000); });

function openScan(id: string) { selectedScan.value = id; view.value = 'results'; }

const nav: { id: View; label: string; step: number }[] = [
  { id: 'overview', label: 'Overview', step: 0 },
  { id: 'grants', label: 'Authorization', step: 1 },
  { id: 'scan', label: 'Scan setup', step: 2 },
  { id: 'results', label: 'Results & reports', step: 3 },
];
</script>

<template>
  <div class="layout">
    <aside class="sidebar">
      <div class="brand">
        <div class="logo"></div>
        <div><b>SecScan</b><small>local console</small></div>
      </div>
      <nav class="nav">
        <button v-for="n in nav" :key="n.id" :class="{ active: view === n.id }" @click="view = n.id">
          <span class="step">{{ n.step || '•' }}</span>{{ n.label }}
        </button>
      </nav>
      <div class="card" style="margin-top: 18px; padding: 12px">
        <label style="margin-top: 0">Actor (for the audit log)</label>
        <input v-model="settings.actor" @change="saveSettings()" />
        <label>Admin token <span v-if="health?.adminTokenRequired" class="chip warn">required</span></label>
        <input v-model="settings.adminToken" type="password" placeholder="SECSCAN_ADMIN_TOKEN" @change="saveSettings()" />
      </div>
      <div class="foot">
        <div class="row" style="gap: 6px">
          <span class="chip" :class="apiDown ? 'bad' : 'ok'">{{ apiDown ? 'API unreachable' : 'API online' }}</span>
        </div>
        <div v-if="health" style="margin-top: 8px">
          <span class="chip" :class="health.legalResolved ? 'warn' : 'accent'">{{ health.legalResolved ? 'external targets unlocked' : 'lab allow-list only' }}</span>
        </div>
      </div>
    </aside>

    <main class="main">
      <Overview v-if="view === 'overview'" :health="health" @go="(v: View) => view = v" @open-scan="openScan" />
      <Grants v-else-if="view === 'grants'" />
      <ScanSetup v-else-if="view === 'scan'" @open-scan="openScan" />
      <Results v-else :scan-id="selectedScan" @select="(id: string) => selectedScan = id" />
    </main>

    <div v-if="toast.msg" class="toast" :class="{ err: toast.err }">{{ toast.msg }}</div>
  </div>
</template>
