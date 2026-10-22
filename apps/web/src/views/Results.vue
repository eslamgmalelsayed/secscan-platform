<script setup lang="ts">
import { onMounted, ref, watch } from 'vue';
import { api, type Finding, type ScanRecord, type ScanSummary } from '../api';
import { attempt } from '../toast';

const props = defineProps<{ scanId: string | null }>();
const emit = defineEmits<{ select: [id: string] }>();

const scans = ref<ScanSummary[]>([]);
const scan = ref<ScanRecord | null>(null);
const open = ref<Set<string>>(new Set());
const reportLang = ref<'ar' | 'en'>('ar');
const report = ref<string>('');

async function loadList() { const s = await attempt(() => api.scans.list()); if (s) scans.value = s; }
async function loadScan(id: string) {
  report.value = '';
  const s = await attempt(() => api.scans.get(id));
  scan.value = s;
}
async function loadReport() {
  if (!props.scanId) return;
  const r = await attempt(() => api.scans.report(props.scanId!, reportLang.value));
  if (r) report.value = r.markdown;
}
function toggle(id: string) { const o = new Set(open.value); o.has(id) ? o.delete(id) : o.add(id); open.value = o; }

onMounted(() => { loadList(); if (props.scanId) loadScan(props.scanId); });
watch(() => props.scanId, (id) => { report.value = ''; if (id) loadScan(id); else scan.value = null; });
watch(reportLang, () => { if (report.value) loadReport(); });

const sev = (f: Finding) => f.severity;
</script>

<template>
  <div>
    <div class="page-head"><div><h1>Results &amp; reports</h1><p>Confirmed findings go to the report; everything else waits for human review.</p></div>
      <button class="btn sm" @click="loadList">Refresh</button>
    </div>

    <div class="grid" style="grid-template-columns: 280px 1fr; align-items: start">
      <div class="card pad-0">
        <div style="padding: 14px 16px"><h3 style="margin: 0">Scans</h3></div>
        <table v-if="scans.length">
          <tbody>
            <tr v-for="s in scans" :key="s.id" :style="{ cursor: 'pointer', background: s.id === scanId ? 'rgba(76,201,240,.08)' : '' }" @click="emit('select', s.id)">
              <td>
                <div class="mono" style="font-size: 11.5px">{{ s.id }}</div>
                <div style="margin-top: 4px"><span class="chip" :class="s.status === 'done' ? 'ok' : s.status === 'failed' ? 'bad' : 'warn'">{{ s.status }}</span>
                  <span class="chip" style="margin-left: 4px">{{ s.confirmed }} confirmed</span></div>
              </td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">No scans.</div>
      </div>

      <div>
        <div v-if="!scan" class="card empty">Select a scan on the left.</div>
        <template v-else>
          <div class="grid cols-4" style="margin-bottom: 16px">
            <div class="card stat"><span class="l">Status</span><span class="n"><span class="chip" :class="scan.status === 'done' ? 'ok' : 'bad'">{{ scan.status }}</span></span></div>
            <div class="card stat"><span class="l">Confirmed</span><span class="n">{{ scan.findings.length }}</span></div>
            <div class="card stat"><span class="l">Needs review</span><span class="n">{{ scan.review?.length ?? 0 }}</span></div>
            <div class="card stat"><span class="l">Not tested</span><span class="n">{{ scan.notTested.length }}</span></div>
          </div>

          <div class="card" style="margin-bottom: 16px">
            <div class="row between"><h3 style="margin: 0">Report</h3>
              <div class="row" style="gap: 6px">
                <button class="btn sm" :class="{ primary: reportLang === 'ar' }" @click="reportLang = 'ar'">عربي</button>
                <button class="btn sm" :class="{ primary: reportLang === 'en' }" @click="reportLang = 'en'">English</button>
                <button class="btn sm" @click="loadReport">Generate</button>
              </div>
            </div>
            <pre v-if="report" :class="{ rtl: reportLang === 'ar' }" style="margin-top: 12px">{{ report }}</pre>
            <p v-else class="hint" style="margin-top: 10px">Generate the bilingual report (Markdown) for this scan.</p>
          </div>

          <h2 style="margin: 20px 0 10px">Confirmed findings</h2>
          <div v-if="!scan.findings.length" class="card empty">No confirmed findings.</div>
          <div v-for="f in scan.findings" :key="f.id" class="finding">
            <div class="head" @click="toggle(f.id)">
              <div><span class="sev" :class="sev(f)">{{ f.severity }}</span> <b style="margin-left: 8px">{{ f.title.en }}</b></div>
              <div class="row" style="gap: 6px"><span v-if="f.cvss" class="chip">CVSS {{ f.cvss.score }}</span><span class="chip">{{ f.confidence }}</span></div>
            </div>
            <div class="meta">{{ f.asset }}{{ f.location ? ' · ' + f.location : '' }}</div>
            <div v-if="open.has(f.id)" class="body">
              <div dir="rtl" style="text-align: right">{{ f.title.ar }}</div>
              <div><b>Description</b><br>{{ f.description.en }}</div>
              <div><b>Impact</b><br>{{ f.impact.en }}</div>
              <div><b>Remediation</b><br>{{ f.remediation.en }}</div>
              <div><b>Evidence</b><br><span v-for="(e, i) in f.evidence" :key="i" class="mono" style="display: block">{{ e.label ? e.label + ': ' : '' }}{{ e.content }}</span></div>
              <div><b>References</b><br><span v-for="(c, i) in f.controls" :key="i" class="chip" style="margin: 2px 4px 2px 0">{{ c.framework }} {{ c.control }}</span></div>
            </div>
          </div>

          <template v-if="scan.review?.length">
            <h2 style="margin: 24px 0 10px">Needs human review</h2>
            <div v-for="f in scan.review" :key="f.id" class="finding">
              <div class="head" @click="toggle(f.id)">
                <div><span class="sev" :class="sev(f)">{{ f.severity }}</span> <b style="margin-left: 8px">{{ f.title.en }}</b></div>
                <div class="row" style="gap: 6px"><span v-if="f.cvss" class="chip">CVSS {{ f.cvss.score }}</span><span class="chip warn">{{ f.confidence }}</span></div>
              </div>
              <div class="meta">{{ f.asset }}{{ f.location ? ' · ' + f.location : '' }}</div>
              <div v-if="open.has(f.id)" class="body">
                <div><b>Why review</b><br>{{ f.description.en }}</div>
                <div><b>Remediation</b><br>{{ f.remediation.en }}</div>
              </div>
            </div>
          </template>

          <template v-if="scan.notTested.length">
            <h2 style="margin: 24px 0 10px">What was not tested</h2>
            <div class="card"><ul class="hint" style="margin: 0; padding-left: 18px"><li v-for="(n, i) in scan.notTested" :key="i" class="mono">{{ n }}</li></ul></div>
          </template>
        </template>
      </div>
    </div>
  </div>
</template>
