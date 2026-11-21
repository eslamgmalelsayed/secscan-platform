import { readFile } from 'node:fs/promises';
// An operator pushes one completed measurement to a specific project.
const [origin, projectId, format, asset, context, path] = process.argv.slice(2);
if (!origin || !projectId || !format || !asset || !context || !path)
  throw new Error('Expected API origin, project UUID, format, asset, build/context and JSON file');
const base = new URL(origin);
if (
  base.username ||
  base.password ||
  base.pathname !== '/' ||
  base.search ||
  base.hash ||
  (base.protocol !== 'https:' &&
    !(base.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(base.hostname)))
)
  throw new Error('Use an HTTPS origin or loopback');
if (!/^[a-f0-9-]{36}$/.test(projectId)) throw new Error('Invalid project UUID');
const token = process.env.SECSCAN_PROJECT_TOKEN;
if (!token) throw new Error('Set SECSCAN_PROJECT_TOKEN for a project tester');
const source = await readFile(path, 'utf8');
if (Buffer.byteLength(source) > 900000) throw new Error('Maximum import size is 900 KB');
const data = JSON.parse(source);
const endpoint = new URL('/api/assessments/' + projectId, base);
const headers = { authorization: 'Bearer ' + token, 'content-type': 'application/json' };
const options = { headers, redirect: 'error', signal: AbortSignal.timeout(10000) };
const current = await fetch(endpoint, options);
if (!current.ok) throw new Error('Could not load project: HTTP ' + current.status);
const { revision } = await current.json();
const result = await fetch(endpoint, {
  ...options,
  method: 'POST',
  body: JSON.stringify({ revision, action: { type: 'import', format, asset, context, data } }),
});
if (!result.ok) throw new Error('Import rejected: HTTP ' + result.status);
console.log('Recorded project revision ' + (await result.json()).revision);
