<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import {
  coverage,
  domains,
  importFormats,
  type Operation,
  type Outcome,
  type Project,
  type Role,
} from '@secscan/shared';
import { call } from '../api';
import { notify } from '../toast';

const projects = ref<{ id: string; name: string }[]>([]);
const project = ref<Project | null>(null);
const busy = ref(false),
  showNew = ref(false),
  caseId = ref(''),
  asset = ref('');
const name = ref(''),
  assets = ref(''),
  authorization = ref(''),
  expires = ref('');
const title = ref(''),
  expected = ref(''),
  domain = ref<(typeof domains)[number]>('Web/API');
const context = ref(''),
  evidence = ref(''),
  baseline = ref(''),
  outcome = ref<Outcome>('inconclusive');
const reviewerNote = ref(''),
  assignee = ref(''),
  member = ref(''),
  role = ref<Exclude<Role, 'owner'> | 'remove'>('reader');
const format = ref<Extract<Operation, { type: 'import' }>['format']>('openapi'),
  file = ref<File | null>(null);
const attachmentFile = ref<File | null>(null);
const reportId = ref(''),
  lang = ref<'ar' | 'en'>('ar');
const current = computed(() => project.value?.cases.find((c) => c.id === caseId.value));
const latest = computed(() => current.value?.observations.at(-1));
const counts = computed(() => coverage(project.value?.cases ?? []));
const snapshot = computed(() => project.value?.reports.find((r) => r.id === reportId.value));
const importHint = computed(
  () =>
    ({
      sarif: 'SARIF 2.1.0 JSON report',
      openapi: 'OpenAPI 3 JSON document',
      s3: 'GetPublicAccessBlock JSON response',
      wifi: 'WiFi snapshot from secscan wifi',
      iam: 'AWS IAM policy document JSON',
      https: 'HTTPS origin snapshot from scripts/posture.mjs',
      cyclonedx: 'CycloneDX JSON with vulnerabilities',
      secscan: 'SecScan evidence bundle JSON',
      android: 'Decoded AndroidManifest.xml',
      ios: 'Info.plist JSON snapshot from scripts/apple-snapshot.py',
      isolation: 'Paired observation JSON from the guest isolation check',
    })[format.value],
);

async function run(task: () => Promise<void>) {
  if (busy.value) return;
  busy.value = true;
  try {
    await task();
  } catch (e) {
    notify(e instanceof Error ? e.message : String(e), true);
  } finally {
    busy.value = false;
  }
}
async function list() {
  projects.value = await call('GET', '/assessments');
}
function resetNotes() {
  evidence.value = '';
  baseline.value = '';
  reviewerNote.value = '';
  assignee.value = '';
  attachmentFile.value = null;
  context.value = '';
  outcome.value = 'inconclusive';
  file.value = null;
}
function chooseCase(id: string) {
  caseId.value = id;
  resetNotes();
}
async function open(id: string) {
  const p = await call<Project>('GET', '/assessments/' + id);
  project.value = p;
  asset.value = p.assets[0];
  chooseCase(p.cases[0]?.id ?? '');
  reportId.value = p.reports.at(-1)?.id ?? '';
  showNew.value = false;
}
async function create() {
  const p = await call<Project>('POST', '/assessments', {
    name: name.value,
    assets: assets.value
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean),
    authorization: authorization.value,
    expires: new Date(expires.value).toISOString(),
  });
  await list();
  await open(p.id);
  name.value = '';
  assets.value = '';
  authorization.value = '';
}
async function change(action: Operation) {
  const p = project.value!;
  project.value = await call<Project>('POST', '/assessments/' + p.id, { revision: p.revision, action });
}
async function plan() {
  await change({
    type: 'plan',
    cases: [{ domain: domain.value, asset: asset.value, title: title.value, expected: expected.value }],
  });
  chooseCase(
    project.value!.cases.find(
      (c) =>
        c.title === title.value &&
        c.expected === expected.value &&
        c.asset === asset.value &&
        c.domain === domain.value,
    )!.id,
  );
  title.value = '';
  expected.value = '';
}
async function observe() {
  if (attachmentFile.value && attachmentFile.value.size > 64000)
    throw new Error('Text evidence limit is 64 KB');
  const attachment = await attachmentFile.value?.text();
  await change({
    attachment,
    type: 'observe',
    caseId: caseId.value,
    context: context.value,
    evidence: evidence.value,
    baseline: baseline.value || undefined,
    outcome: outcome.value,
  });
  resetNotes();
  attachmentFile.value = null;
}
async function downloadAttachment(hash: string) {
  const p = project.value!;
  const { url } = await call<{ url: string }>('POST', '/assessments/' + p.id + '/attachments/' + hash, {});
  await open(p.id);
  const link = document.createElement('a');
  link.href = url;
  link.rel = 'noreferrer';
  link.click();
}
async function review(approve: boolean) {
  await change({
    type: 'review',
    caseId: caseId.value,
    observationId: latest.value!.id,
    approve,
    reason: reviewerNote.value,
    assignee: assignee.value || undefined,
  });
  resetNotes();
}
async function importFile() {
  if (!file.value || file.value.size > 900000) throw new Error('Choose a file under 900 KB');
  const text = await file.value.text();
  let data: unknown;
  if (format.value === 'android') {
    const xml = new DOMParser().parseFromString(text, 'application/xml');
    if (xml.doctype || xml.documentElement.localName !== 'manifest' || xml.querySelector('parsererror'))
      throw new Error('Expected a decoded Android manifest');
    const app = xml.querySelector('manifest > application');
    if (!app) throw new Error('Manifest has no application element');
    const flag = (key: string) => {
      const value = app.getAttributeNS('http://schemas.android.com/apk/res/android', key);
      return value === 'true' ? true : value === 'false' ? false : undefined;
    };
    data = {
      packageName: xml.documentElement.getAttribute('package'),
      debuggable: flag('debuggable'),
      usesCleartextTraffic: flag('usesCleartextTraffic'),
    };
  } else data = JSON.parse(text);
  await change({ type: 'import', format: format.value, asset: asset.value, context: context.value, data });
  caseId.value ||= project.value?.cases[0]?.id ?? '';
  notify(project.value?.history.at(-1)?.action ?? 'Import complete');
}
async function publish() {
  await change({ type: 'publish' });
  reportId.value = project.value!.reports.at(-1)!.id;
}
function printReport() {
  window.print();
}
onMounted(() =>
  run(async () => {
    await list();
    if (projects.value[0]) await open(projects.value[0].id);
    else showNew.value = true;
  }),
);
</script>

<template>
  <section class="assessment">
    <div class="page-head">
      <div>
        <h1>Assessment projects</h1>
        <p>Scope, coverage, evidence and reviewed reports.</p>
      </div>
      <button class="btn" @click="showNew = !showNew">{{ showNew ? 'Close form' : 'New project' }}</button>
    </div>
    <fieldset :disabled="busy">
      <form v-if="showNew" class="card" @submit.prevent="run(create)">
        <h2>Create project</h2>
        <label>Project name<input v-model="name" required /></label>
        <label>Assets in scope · one per line<textarea v-model="assets" required></textarea></label>
        <label>Authorization reference<input v-model="authorization" required /></label>
        <label>Authorization expires<input v-model="expires" type="datetime-local" required /></label>
        <button class="btn primary">Create project</button>
      </form>
      <label v-if="projects.length"
        >Project<select
          :value="project?.id"
          @change="run(() => open(($event.target as HTMLSelectElement).value))"
        >
          <option v-for="p in projects" :key="p.id" :value="p.id">{{ p.name }}</option>
        </select></label
      >
      <template v-if="project">
        <button class="btn sm" @click="run(() => open(project!.id))">Reload project</button>
        <p class="mono">Project ID · {{ project.id }}</p>
        <p>
          {{ project.authorization }} · Expires {{ new Date(project.expires).toLocaleString() }} · Revision
          {{ project.revision }}
        </p>
        <div class="grid cols-4">
          <div v-for="(n, key) in counts" :key="key" class="card stat">
            <span class="l">{{ key }}</span><span class="n">{{ n }}</span>
          </div>
        </div>
        <label
          >Asset for new cases and imports<select v-model="asset">
            <option v-for="a in project.assets" :key="a">{{ a }}</option>
          </select></label
        >
        <div class="grid cols-2">
          <form class="card" @submit.prevent="run(plan)">
            <h3>Plan a test case</h3>
            <label
              >Domain<select v-model="domain">
                <option v-for="d in domains" :key="d">{{ d }}</option>
              </select></label
            >
            <label>Case title<input v-model="title" required /></label
            ><label>Expected behavior<textarea v-model="expected" required></textarea></label>
            <button class="btn">Add case</button>
          </form>
          <form class="card" @submit.prevent="run(importFile)">
            <h3>Import evidence or coverage</h3>
            <label
              >Format<select v-model="format">
                <option v-for="f in importFormats" :key="f">
                  {{ f }}
                </option>
              </select></label
            >
            <label
              >{{ importHint
              }}<input
                type="file"
                required
                @change="file = ($event.target as HTMLInputElement).files?.[0] ?? null"
            /></label>
            <label>Build, commit or measurement reference<input v-model="context" required /></label
            ><button class="btn">Import file</button>
          </form>
        </div>
        <div v-if="project.cases.length" class="card">
          <label
            >Test case<select
              :value="caseId"
              @change="chooseCase(($event.target as HTMLSelectElement).value)"
            >
              <option v-for="c in project.cases" :value="c.id" :key="c.id">
                {{ c.asset }} · {{ c.title }} · {{ c.state }}
              </option>
            </select></label
          >
          <template v-if="current"
            ><h3>{{ current.title }}</h3>
            <p>{{ current.expected }}</p>
            <p v-if="current.assignee">Remediation owner · {{ current.assignee }}</p>
            <details v-for="o in current.observations" :key="o.id">
              <summary>
                {{ o.context }} · {{ o.outcome }} ·
                {{ o.review ? (o.review.approve ? 'approved' : 'returned') : 'awaiting review' }}
              </summary>
              <p>{{ o.evidence }}</p>
              <p v-if="o.baseline">{{ o.baseline }}</p>
              <button v-if="o.attachment" class="btn" @click="run(() => downloadAttachment(o.attachment!))">
                Download attached evidence
              </button>
              <p>{{ o.actor }} · {{ o.at }} · {{ o.review?.reason }}</p>
            </details>
            <form @submit.prevent="run(observe)">
              <h3>Record observation or retest</h3>
              <label>Build and test context<input v-model="context" required /></label
              ><label
                >Outcome<select v-model="outcome">
                  <option>inconclusive</option>
                  <option>fail</option>
                  <option>pass</option>
                </select></label
              >
              <label
                >Evidence summary · omit credentials<textarea v-model="evidence" required></textarea>
              </label>
              <label
                >Optional text attachment · requires configured bucket<input
                  type="file"
                  accept=".txt,text/plain"
                  @change="attachmentFile = ($event.target as HTMLInputElement).files?.[0] ?? null"
              /></label>
              <label>Positive control evidence for closure<input v-model="baseline" /></label
              ><button class="btn">Save observation</button>
            </form>
            <form v-if="latest && !latest.review" @submit.prevent="run(() => review(true))">
              <h3>Review latest observation</h3>
              <label>Decision rationale<input v-model="reviewerNote" required /></label
              ><label>Remediation owner<input v-model="assignee" /></label>
              <button class="btn primary">Approve</button>
              <button
                class="btn"
                type="button"
                :disabled="!reviewerNote.trim()"
                @click="run(() => review(false))"
              >
                Return for evidence
              </button>
            </form>
          </template>
        </div>
        <details class="card">
          <summary>Project access</summary>
          <p>Owner · {{ project.owner }}</p>
          <p v-for="m in project.members" :key="m.name">{{ m.name }} · {{ m.role }}</p>
          <form
            @submit.prevent="
              run(() => change({ type: 'member', name: member, role: role === 'remove' ? null : role }))
            "
          >
            <label>Named API identity<input v-model="member" required /></label>
            <label
              >Role<select v-model="role">
                <option>reader</option>
                <option>tester</option>
                <option>reviewer</option>
                <option>remove</option>
              </select></label
            ><button class="btn">Update access</button>
          </form>
        </details>
        <details class="card">
          <summary>Audit history</summary>
          <p v-for="(h, i) in project.history" :key="i">{{ h.at }} · {{ h.actor }} · {{ h.action }}</p>
        </details>
        <div class="card">
          <h3>Report snapshots</h3>
          <button class="btn" @click="run(publish)">Publish snapshot</button>
          <template v-if="project.reports.length"
            ><label
              >Snapshot<select v-model="reportId">
                <option v-for="r in project.reports" :key="r.id" :value="r.id">
                  {{ r.at }} · rev {{ r.revision }}
                </option>
              </select></label
            >
            <label
              >Report language<select v-model="lang">
                <option value="ar">العربية</option>
                <option value="en">English</option>
              </select></label
            >
            <button class="btn" @click="printReport">Print / save PDF</button></template
          >
        </div>
      </template>
    </fieldset>
    <article v-if="snapshot" class="snapshot card" :dir="lang === 'ar' ? 'rtl' : 'ltr'" :lang="lang">
      {{ snapshot[lang] }}
    </article>
  </section>
</template>
<style scoped>
fieldset {
  border: 0;
  padding: 0;
  margin: 0;
  min-width: 0;
}
.assessment .card,
.assessment form button {
  margin-top: 12px;
}
.assessment label input,
.assessment label select,
.assessment label textarea {
  display: block;
  width: 100%;
}
.snapshot {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.assessment details summary {
  cursor: pointer;
}
@media print {
  .assessment fieldset,
  .assessment .page-head {
    display: none;
  }
  .snapshot {
    border: 0;
    color: #111;
    background: white;
  }
}
</style>
<style>
@media print {
  body:has(.assessment) .sidebar,
  body:has(.assessment) .toast {
    display: none;
  }
  body:has(.assessment) .layout,
  body:has(.assessment) .main {
    display: block;
    padding: 0;
    margin: 0;
    width: 100%;
  }
}
</style>
