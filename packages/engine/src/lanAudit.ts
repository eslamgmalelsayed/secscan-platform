/**
 * LAN / WiFi audit logic for the on-network agent — PURE, testable functions.
 *
 * The agent (a Node process on a machine on the network) gathers OS state —
 * `arp -a`, `nmcli`/`netsh`/`airport` — and passes the text here. These parse
 * and judge it: ARP-spoofing signs on YOUR network, and the WiFi's crypto
 * posture. Non-destructive and authorized by ownership (you run the agent on
 * your own network). No attack on anyone else's gear: detection and posture only.
 */

export interface ArpEntry { ip: string; mac: string }

const MAC_RE = /([0-9a-f]{2}[:-]){5}[0-9a-f]{2}/i;
const IP_RE = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/;

/** Parse `arp -a` output across Linux / macOS / Windows formats. */
export function parseArpTable(text: string): ArpEntry[] {
  const out: ArpEntry[] = [];
  for (const line of text.split('\n')) {
    const ip = line.match(IP_RE)?.[1];
    const mac = line.match(MAC_RE)?.[0];
    if (ip && mac && !/incomplete|00-00-00-00-00-00|00:00:00:00:00:00|ff-ff-ff-ff-ff-ff|ff:ff:ff:ff:ff:ff/i.test(line)) {
      out.push({ ip, mac: mac.toLowerCase().replace(/-/g, ':') });
    }
  }
  return out;
}

export interface LanFinding {
  kind: 'arp_spoof' | 'arp_duplicate' | 'wifi_open' | 'wifi_weak_crypto' | 'wifi_wps';
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  detail: string;
}

/**
 * ARP-spoofing signs on the local network:
 *  - the gateway IP resolving to more than one MAC (someone is impersonating it),
 *  - one MAC claiming many IPs (a classic poisoner fanning out).
 */
export function detectArpSpoof(entries: ArpEntry[], gatewayIp?: string): LanFinding[] {
  const out: LanFinding[] = [];
  const macsByIp = new Map<string, Set<string>>();
  const ipsByMac = new Map<string, Set<string>>();
  for (const e of entries) {
    (macsByIp.get(e.ip) ?? macsByIp.set(e.ip, new Set()).get(e.ip)!).add(e.mac);
    (ipsByMac.get(e.mac) ?? ipsByMac.set(e.mac, new Set()).get(e.mac)!).add(e.ip);
  }
  if (gatewayIp) {
    const gwMacs = macsByIp.get(gatewayIp);
    if (gwMacs && gwMacs.size > 1) out.push({ kind: 'arp_spoof', severity: 'critical', title: 'Gateway ARP spoofing detected', detail: `the gateway ${gatewayIp} maps to ${gwMacs.size} MACs (${[...gwMacs].join(', ')}) — someone is likely impersonating the router (MITM/net-cut)` });
  }
  for (const [mac, ips] of ipsByMac) {
    if (ips.size >= 4) out.push({ kind: 'arp_duplicate', severity: 'high', title: 'One MAC claims many IPs', detail: `${mac} answers for ${ips.size} addresses — a sign of ARP poisoning on the LAN` });
  }
  return out;
}

export interface WifiInfo { ssid?: string; bssid?: string; security?: string; wps?: boolean }

function knownSecurity(value: string | undefined): string | undefined {
  return value && /^(?:WPA[123]?|WEP|Open|None|OWE|SAE)(?:$|[\s/-])/i.test(value) ? value : undefined;
}

/** Only the connected interface can supply evidence about this connection. */
export function parseWifiSecurity(text: string): WifiInfo {
  const lines = text.trim().split(/\r?\n/);
  if (lines.some(line => /^(yes|no):/.test(line))) {
    const active = lines.filter(line => line.startsWith('yes:'));
    if (active.length !== 1) return {};
    // Split on unescaped separators: NetworkManager escapes both ':' and '\\'.
    const parts = active[0].match(/(?:^|:)((?:\\.|[^:\\])*)/g)?.map((field, i) =>
      (i ? field.slice(1) : field).replace(/\\(.)/g, '$1'));
    if (!parts || (parts.length !== 3 && parts.length !== 4)) return {};
    const security = parts.at(-1);
    return { ssid: parts[1], bssid: parts.length === 4 ? parts[2] : undefined,
      security: security === '' || security === '--' ? 'Open' : knownSecurity(security) };
  }
  const field = (name: string) => {
    const matches = [...text.matchAll(new RegExp('^\\s*(?:' + name + ')\\s*[:=]\\s*([^\\r\\n]+)', 'gim'))];
    return matches.length === 1 ? matches[0][1].trim().replace(/^"|"$/g, '') : undefined;
  };
  const ssid = field('SSID|ESSID');
  // netsh reports an associated interface as "connected"; macOS airport as "running".
  const state = field('State')?.toLowerCase();
  if (!ssid || ssid === '--' || (state && state !== 'connected' && state !== 'running')) return {};
  const cipher = field('Cipher');
  return { ssid, bssid: field('BSSID|AP BSSID'), security: cipher && /^WEP/i.test(cipher) ? 'WEP' : knownSecurity(field('Security|Authentication|Auth|link auth')),
    wps: /^(on|enabled|configured)$/i.test(field('WPS') ?? '') || undefined };
}

/** Judge the WiFi crypto posture of the network the agent is on. */
export function auditWifiPosture(info: WifiInfo): LanFinding[] {
  const out: LanFinding[] = [];
  const s = (info.security ?? '').toUpperCase();
  const where = info.ssid ? ` on '${info.ssid}'` : '';
  if (/OPEN|NONE/.test(s) || info.security === 'Open') out.push({ kind: 'wifi_open', severity: 'high', title: 'Open WiFi (no encryption)', detail: `the network${where} does not encrypt the WiFi link` });
  else if (/WEP/.test(s)) out.push({ kind: 'wifi_weak_crypto', severity: 'high', title: 'WEP encryption (broken)', detail: `the network${where} uses WEP, which is trivially crackable` });
  else if (/WPA(?!2|3)/.test(s) || s === 'WPA') out.push({ kind: 'wifi_weak_crypto', severity: 'medium', title: 'Legacy WPA (TKIP) encryption', detail: `the network${where} uses legacy WPA — upgrade to WPA2/WPA3` });
  else if (/WPA2/.test(s) && !/WPA3/.test(s)) out.push({ kind: 'wifi_weak_crypto', severity: 'low', title: 'WPA2 without WPA3', detail: `the network${where} is WPA2-only — enable WPA3 where supported` });
  if (info.wps) out.push({ kind: 'wifi_wps', severity: 'medium', title: 'WPS enabled', detail: `WPS${where} is on — the 8-digit PIN is brute-forceable; disable it` });
  return out;
}
