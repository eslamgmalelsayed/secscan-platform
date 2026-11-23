import { auditWifiPosture } from '@secscan/engine';
import { BadRequestException } from '@nestjs/common';
import { z } from 'zod';
import type { CaseInput, Outcome, Operation } from '@secscan/shared';
type Import = Extract<Operation, { type: 'import' }>;
export type Imported = CaseInput & { outcome?: Outcome; evidence?: string };
const flag = z.boolean().optional();
const sarif = z.object({
  version: z.literal('2.1.0'),
  runs: z.array(
    z.object({
      tool: z.object({ driver: z.object({ name: z.string().min(1) }) }),
      results: z
        .array(
          z.object({
            ruleId: z.string().optional(),
            message: z.object({ text: z.string().optional() }),
            locations: z
              .array(
                z.object({
                  physicalLocation: z
                    .object({
                      artifactLocation: z.object({ uri: z.string().optional() }).optional(),
                      region: z.object({ startLine: z.number().int().positive().optional() }).optional(),
                    })
                    .optional(),
                }),
              )
              .optional(),
          }),
        )
        .optional(),
    }),
  ),
});
export function importCases(input: Import): Imported[] {
  const { asset, data } = input;
  if (input.format === 'openapi') {
    const spec = z
      .object({ openapi: z.string().regex(/^3\./), paths: z.record(z.record(z.unknown())) })
      .parse(data);
    return Object.entries(spec.paths).flatMap(([path, ops]) =>
      Object.keys(ops)
        .filter((method) => /^(get|head|post|put|delete|patch|options|trace)$/.test(method))
        .map((method) => ({
          asset,
          domain: 'Web/API' as const,
          title: method.toUpperCase() + ' ' + path,
          expected: 'Review this operation against the documented access policy.',
        })),
    );
  }
  if (input.format === 'sarif')
    return sarif.parse(data).runs.flatMap((run) =>
      (run.results ?? []).map((r) => {
        const p = r.locations?.[0]?.physicalLocation;
        const location =
          (p?.artifactLocation?.uri ?? 'unspecified') +
          (p?.region?.startLine ? '#' + p.region.startLine : '');
        return {
          asset,
          domain: 'Code',
          title: (r.ruleId ?? 'Unclassified') + ' · ' + location,
          expected: 'Review the static analyzer warning in the identified revision.',
          outcome: 'inconclusive',
          evidence: run.tool.driver.name + ' · ' + (r.message.text ?? 'Result supplied without message text'),
        };
      }),
    );
  if (input.format === 's3') {
    const bucket = z.object({ Bucket: z.string().optional() }).parse(data).Bucket;
    if (bucket && bucket !== asset) throw new BadRequestException('Asset must match snapshot bucket');
    const config = z
      .object({
        PublicAccessBlockConfiguration: z.object({
          BlockPublicAcls: flag,
          IgnorePublicAcls: flag,
          BlockPublicPolicy: flag,
          RestrictPublicBuckets: flag,
        }),
      })
      .parse(data).PublicAccessBlockConfiguration;
    return ['BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets'].map(
      (name) => {
        const value = config[name as keyof typeof config];
        return {
          asset,
          domain: 'Cloud/IAM',
          title: 'S3 · ' + name,
          expected: 'Bucket-level setting enabled.',
          outcome: value === undefined ? 'inconclusive' : value ? 'pass' : 'fail',
          evidence: name + ' = ' + String(value ?? 'not supplied'),
        };
      },
    );
  }
  if (input.format === 'ios') {
    const app = z
      .object({
        bundle: z.string().min(1),
        build: z.string(),
        allowsArbitraryLoads: z.boolean().nullish(),
        exceptionDomains: z.array(z.string()),
      })
      .parse(data);
    return [
      {
        asset,
        domain: 'iOS',
        title: app.bundle + ' · ATS global exception',
        expected: 'Release configuration does not declare global arbitrary loads.',
        outcome: app.allowsArbitraryLoads === true ? 'fail' : 'pass',
        evidence:
          'Build ' + app.build + ' · NSAllowsArbitraryLoads=' + String(app.allowsArbitraryLoads ?? 'absent'),
      },
      {
        asset,
        domain: 'iOS',
        title: app.bundle + ' · ATS domain exceptions',
        expected: 'Review per-domain transport exceptions.',
        outcome: app.exceptionDomains.length ? 'inconclusive' : 'pass',
        evidence: app.exceptionDomains.join(', ') || 'No exception domains declared.',
      },
    ];
  }
  if (input.format === 'android') {
    const m = z
      .object({ packageName: z.string().min(1), debuggable: flag, usesCleartextTraffic: flag })
      .parse(data);
    return (['debuggable', 'usesCleartextTraffic'] as const).map((key) => ({
      asset,
      domain: 'Android',
      title: m.packageName + ' · ' + key,
      expected: 'Release manifest explicitly disables ' + key + '.',
      outcome: m[key] === undefined ? 'inconclusive' : m[key] ? 'fail' : 'pass',
      evidence: key + ' = ' + String(m[key] ?? 'unspecified'),
    }));
  }
  if (input.format === 'wifi') {
    const snap = z
      .object({
        at: z.string().datetime(),
        platform: z.string(),
        wifi: z.object({
          ssid: z.string().optional(),
          bssid: z.string().optional(),
          security: z.string().optional(),
          wps: flag,
        }),
      })
      .parse(data);
    const issue = auditWifiPosture(snap.wifi);
    return [
      {
        asset,
        domain: 'Network/WiFi',
        title: 'Connected WiFi security posture',
        expected: 'Selected wireless settings satisfy the configured posture checks.',
        outcome: !snap.wifi.security ? 'inconclusive' : issue.length ? 'fail' : 'pass',
        evidence: [
          snap.at,
          snap.platform,
          snap.wifi.ssid,
          snap.wifi.bssid,
          snap.wifi.security,
          ...issue.map((i) => i.title),
        ]
          .filter(Boolean)
          .join(' · '),
      },
    ];
  }
  if (input.format === 'iam') {
    const strings = z.union([z.string(), z.array(z.string())]).optional();
    const statement = z.object({
      Sid: z.string().optional(),
      Effect: z.enum(['Allow', 'Deny']),
      Action: strings,
      Resource: strings,
      Condition: z.unknown().optional(),
    });
    const policy = z.object({ Statement: z.union([statement, z.array(statement)]) }).parse(data);
    const rows = Array.isArray(policy.Statement) ? policy.Statement : [policy.Statement];
    return rows.map((r, i) => {
      const actions = [r.Action ?? []].flat(),
        resources = [r.Resource ?? []].flat();
      const broad =
        r.Effect === 'Allow' && actions.includes('*') && resources.includes('*') && r.Condition === undefined;
      return {
        asset,
        domain: 'Cloud/IAM',
        title: 'IAM statement ' + (r.Sid ?? String(i + 1)),
        expected: 'Review identity policy statements for unconditional wildcard access.',
        outcome: broad ? 'fail' : 'inconclusive',
        evidence: broad
          ? 'Unconditional Allow with Action=* and Resource=* in the supplied statement.'
          : 'This rule found no unconditional double wildcard. Effective permissions require further review.',
      };
    });
  }
  if (input.format === 'https') {
    const m = z
      .object({
        origin: z.string().url(),
        at: z.string().datetime(),
        status: z.number().int(),
        tls: z.string(),
        headers: z.record(z.string().nullable()),
      })
      .parse(data);
    if (asset !== m.origin) throw new BadRequestException('Asset must match snapshot origin');
    const measured = m.status >= 200 && m.status < 300;
    const result: Imported[] = Object.entries(m.headers)
      .filter(([name]) =>
        ['content-security-policy', 'strict-transport-security', 'x-content-type-options'].includes(name),
      )
      .map(([name, value]) => ({
        asset,
        domain: 'Web/API',
        title: name + ' on ' + asset,
        expected: 'Header is present on the selected response.',
        outcome: measured ? (value ? 'pass' : 'fail') : 'inconclusive',
        evidence: m.at + ' · HTTP ' + m.status + ' · ' + (value || 'missing'),
      }));
    result.push({
      asset,
      domain: 'Web/API',
      title: 'Negotiated TLS version',
      expected: 'This connection negotiated TLS 1.2 or later.',
      outcome: ['TLSv1.2', 'TLSv1.3'].includes(m.tls) ? 'pass' : 'fail',
      evidence: m.at + ' · ' + m.tls,
    });
    return result;
  }
  if (input.format === 'cyclonedx') {
    const bom = z
      .object({
        bomFormat: z.literal('CycloneDX'),
        components: z.array(z.object({ name: z.string(), version: z.string().optional() })),
        vulnerabilities: z
          .array(z.object({ id: z.string(), affects: z.array(z.object({ ref: z.string() })).optional() }))
          .optional(),
      })
      .parse(data);
    return (bom.vulnerabilities ?? []).map((v) => ({
      asset,
      domain: 'Code',
      title: v.id,
      expected: 'Verify affected component and version against this build.',
      outcome: 'inconclusive',
      evidence: 'Affected references: ' + (v.affects?.map((a) => a.ref).join(', ') || 'unspecified'),
    }));
  }
  if (input.format === 'secscan') {
    const row = z.object({
      asset: z.string(),
      id: z.string(),
      location: z.string().optional(),
      title: z.object({ en: z.string() }),
      confidence: z.string(),
    });
    const pack = z
      .object({
        scan: z.object({ id: z.string(), status: z.string() }),
        findings: z.array(row),
        review: z.array(row).optional(),
      })
      .parse(data);
    return [...pack.findings, ...(pack.review ?? [])]
      .filter((r) => r.asset === asset)
      .map((r) => ({
        asset,
        domain: 'Web/API',
        title: r.title.en + ' · ' + (r.location ?? r.id),
        expected: 'Review imported evidence for this scoped asset.',
        outcome: 'inconclusive',
        evidence:
          pack.scan.id + ' · ' + pack.scan.status + ' · ' + r.id + ' · source confidence ' + r.confidence,
      }));
  }
  if (input.format === 'isolation') {
    const probe = z
      .object({
        service: z.string().min(1),
        baseline: z.enum(['reachable', 'unavailable']),
        guest: z.enum(['same-service-reachable', 'verified-policy-deny', 'unknown']),
        evidence: z.string().min(1),
      })
      .parse(data);
    return [
      {
        asset,
        domain: 'Network/WiFi',
        title: 'Guest isolation · ' + probe.service,
        expected: 'Guest segment cannot access the internal reference service.',
        outcome:
          probe.baseline !== 'reachable' || probe.guest === 'unknown'
            ? 'inconclusive'
            : probe.guest === 'verified-policy-deny'
              ? 'pass'
              : 'fail',
        evidence: [probe.baseline, probe.guest, probe.evidence].join(' · '),
      },
    ];
  }
  throw new BadRequestException('Unsupported import');
}
