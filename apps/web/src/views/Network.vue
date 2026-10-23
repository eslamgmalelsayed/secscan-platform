<script setup lang="ts">
import { ref } from 'vue';
import { api, type AgentAudit } from '../api';
import { attempt, notify } from '../toast';

const emit = defineEmits<{ 'open-scan': [id: string] }>();
const audit = ref<AgentAudit | null>(null);
const busy = ref(false);
const scanningPort = ref('');
const cidr = ref('');

// Scan a discovered device's service directly (discover -> scan handoff).
async function scanService(host: string, port: number) {
  const scheme = port === 443 || port === 8443 ? 'https' : 'http';
  const url = `${scheme}://${host}:${port}/`;
  scanningPort.value = `${host}:${port}`;
  const scan = await attempt(() => api.scans.quick(url), `scanning ${url}`);
  scanningPort.value = '';
  if (scan) { notify(`scan started for ${url}`); emit('open-scan', scan.id); }
}

async function run() {
  busy.value = true;
  const r = await attempt(() => api.agent.audit(cidr.value.trim() || undefined), 'network audit done');
  busy.value = false;
  if (r) audit.value = r;
}
const sevClass = (s: string) => (s === 'critical' || s === 'high' ? 'bad' : s === 'medium' ? 'warn' : '');
</script>

<template>
  <div>
    <div class="page-head">
      <div><h1>Network (agent)</h1><p>Audits the network the app is running on — your own LAN. Non-destructive: device discovery, ARP-spoof detection, WiFi posture.</p></div>
      <div class="row" style="gap: 8px">
        <input v-model="cidr" placeholder="auto (e.g. 192.168.1.0/24)" style="width: 220px" />
        <button class="btn primary" :disabled="busy" @click="run">{{ busy ? 'Scanning…' : 'Scan my network' }}</button>
      </div>
    </div>

    <div v-if="!audit" class="card empty">Run the agent to list devices and check ARP + WiFi. Runs on the machine hosting the app (desktop or <code>npm run serve</code>), not the browser.</div>

    <template v-else>
      <div class="grid cols-4" style="margin-bottom: 16px">
        <div class="card stat"><span class="l">Platform</span><span class="n" style="font-size: 18px">{{ audit.platform }}</span></div>
        <div class="card stat"><span class="l">Devices</span><span class="n">{{ audit.devices.length }}</span></div>
        <div class="card stat"><span class="l">ARP entries</span><span class="n">{{ audit.arpEntries }}</span></div>
        <div class="card stat"><span class="l">Network issues</span><span class="n">{{ audit.network.length + audit.wifiFindings.length }}</span></div>
      </div>

      <div class="grid cols-2">
        <div class="card pad-0">
          <div style="padding: 14px 16px"><h3 style="margin: 0">Devices on {{ audit.cidr ?? 'the LAN' }}</h3></div>
          <table v-if="audit.devices.length">
            <thead><tr><th>Host</th><th>Open ports — click to scan the service</th></tr></thead>
            <tbody><tr v-for="d in audit.devices" :key="d.host">
              <td class="mono">{{ d.host }}</td>
              <td><button v-for="p in d.ports" :key="p" class="btn sm" style="margin: 2px 4px 2px 0" :disabled="scanningPort === `${d.host}:${p}`" @click="scanService(d.host, p)">{{ scanningPort === `${d.host}:${p}` ? 'scanning…' : p }}</button></td>
            </tr></tbody>
          </table>
          <div v-else class="empty">No devices with open ports found.</div>
        </div>

        <div class="card">
          <h3>WiFi posture</h3>
          <p class="sub">{{ audit.wifi.ssid ? `SSID: ${audit.wifi.ssid}` : 'No WiFi info' }}<span v-if="audit.wifi.security"> · {{ audit.wifi.security }}</span></p>
          <div v-if="!audit.wifiFindings.length && !audit.network.length" class="chip ok" style="margin-top: 8px">no issues found</div>
        </div>
      </div>

      <template v-if="audit.network.length || audit.wifiFindings.length">
        <h2 style="margin: 20px 0 10px">Findings</h2>
        <div v-for="(f, i) in [...audit.network, ...audit.wifiFindings]" :key="i" class="finding">
          <div class="head"><div><span class="sev" :class="sevClass(f.severity)">{{ f.severity }}</span> <b style="margin-left: 8px">{{ f.title }}</b></div></div>
          <div class="body"><div>{{ f.detail }}</div></div>
        </div>
      </template>
    </template>
  </div>
</template>
