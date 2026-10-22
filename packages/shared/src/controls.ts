/**
 * Central control mapping: finding category -> indicative framework references
 * (ECC / OWASP / CWE / ASVS / ISO 27001 / NIST CSF). One source of truth so
 * every package tags findings the same way. These are INDICATIVE aids, never a
 * compliance claim (see @secscan/report disclaimer).
 */
import type { ControlRef } from './finding';

export type FindingCategory =
  | 'access_control' | 'function_level' | 'missing_auth' | 'mass_assignment'
  | 'injection' | 'xss' | 'open_redirect' | 'csrf' | 'rate_limit'
  | 'cors' | 'security_header' | 'insecure_cookie' | 'tls' | 'info_disclosure'
  | 'secret_exposure' | 'jwt';

const M: Record<FindingCategory, ControlRef[]> = {
  access_control: refs('2-2 / 2-10', 'API1:2023', 'CWE-639', 'V4.1', 'A.8.3', 'PR.AC'),
  function_level: refs('2-2 / 2-10', 'API5:2023', 'CWE-285', 'V4.1', 'A.8.3', 'PR.AC'),
  missing_auth: refs('2-2', 'API2:2023', 'CWE-306', 'V2.1', 'A.8.5', 'PR.AC'),
  mass_assignment: refs('2-2', 'API3:2023', 'CWE-915', 'V5.1', 'A.8.28', 'PR.DS'),
  csrf: refs('2-2', 'A01:2021', 'CWE-352', 'V4.2', 'A.8.3', 'PR.AC'),
  rate_limit: refs('2-2', 'API4:2023', 'CWE-770', 'V11.1', 'A.8.6', 'PR.IP'),
  injection: refs('2-15', 'A03:2021', 'CWE-89', 'V5.3', 'A.8.28', 'PR.DS'),
  xss: refs('2-15', 'A03:2021', 'CWE-79', 'V5.3', 'A.8.28', 'PR.DS'),
  open_redirect: refs('2-15', 'A01:2021', 'CWE-601', 'V5.1', 'A.8.26', 'PR.DS'),
  cors: refs('2-15', 'A05:2021', 'CWE-942', 'V14.4', 'A.8.26', 'PR.DS'),
  security_header: refs('2-15', 'A05:2021', 'CWE-693', 'V14.4', 'A.8.26', 'PR.IP'),
  insecure_cookie: refs('2-15 / 2-2', 'A05:2021', 'CWE-614', 'V3.4', 'A.8.24', 'PR.DS'),
  tls: refs('2-9', 'A02:2021', 'CWE-319', 'V9.1', 'A.8.24', 'PR.DS'),
  info_disclosure: refs('2-15', 'A05:2021', 'CWE-200', 'V14.3', 'A.8.11', 'PR.DS'),
  secret_exposure: refs('2-15', 'A05:2021', 'CWE-200', 'V14.3', 'A.8.12', 'PR.DS'),
  jwt: refs('2-2', 'API2:2023', 'CWE-347', 'V3.5', 'A.8.5', 'PR.AC'),
};

function refs(ecc: string, owasp: string, cwe: string, asvs: string, iso: string, nist: string): ControlRef[] {
  return [
    { framework: 'NCA ECC-2:2024', control: `${ecc} (indicative, not a compliance claim)` },
    { framework: 'OWASP', control: owasp },
    { framework: 'CWE', control: cwe },
    { framework: 'OWASP ASVS 4.0', control: asvs },
    { framework: 'ISO/IEC 27001:2022', control: iso },
    { framework: 'NIST CSF', control: nist },
  ];
}

export function controlsFor(category: FindingCategory): ControlRef[] {
  return (M[category] ?? M.info_disclosure).map((c) => ({ ...c }));
}
