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

export interface WifiInfo { ssid?: string; security?: string; wps?: boolean }

/** Extract SSID + security from nmcli / netsh / airport output (best-effort). */
export function parseWifiSecurity(text: string): WifiInfo {
  const info: WifiInfo = {};
  const ssid = text.match(/(?:^|\n)\s*(?:SSID|ESSID)\s*[:=]?\s*"?([^"\n]+?)"?\s*(?:\n|$)/i)?.[1]?.trim();
  if (ssid && ssid !== '--') info.ssid = ssid;
  const sec = text.match(/(?:security|authentication|auth)\s*[:=]?\s*([^\n]+)/i)?.[1]?.trim()
    ?? (/\bWPA3\b/i.test(text) ? 'WPA3' : /\bWPA2\b/i.test(text) ? 'WPA2' : /\bWPA\b/i.test(text) ? 'WPA' : /\bWEP\b/i.test(text) ? 'WEP' : /\b(open|none)\b/i.test(text) ? 'Open' : undefined);
  if (sec) info.security = sec;
  if (/wps\s*[:=]?\s*(on|enabled|configured)/i.test(text)) info.wps = true;
  return info;
}

/** Judge the WiFi crypto posture of the network the agent is on. */
export function auditWifiPosture(info: WifiInfo): LanFinding[] {
  const out: LanFinding[] = [];
  const s = (info.security ?? '').toUpperCase();
  const where = info.ssid ? ` on '${info.ssid}'` : '';
  if (/OPEN|NONE/.test(s) || info.security === 'Open') out.push({ kind: 'wifi_open', severity: 'high', title: 'Open WiFi (no encryption)', detail: `the network${where} uses no link encryption — all traffic is sniffable` });
  else if (/WEP/.test(s)) out.push({ kind: 'wifi_weak_crypto', severity: 'high', title: 'WEP encryption (broken)', detail: `the network${where} uses WEP, which is trivially crackable` });
  else if (/WPA(?!2|3)/.test(s) || s === 'WPA') out.push({ kind: 'wifi_weak_crypto', severity: 'medium', title: 'Legacy WPA (TKIP) encryption', detail: `the network${where} uses legacy WPA — upgrade to WPA2/WPA3` });
  else if (/WPA2/.test(s) && !/WPA3/.test(s)) out.push({ kind: 'wifi_weak_crypto', severity: 'low', title: 'WPA2 without WPA3', detail: `the network${where} is WPA2-only — enable WPA3 where supported` });
  if (info.wps) out.push({ kind: 'wifi_wps', severity: 'medium', title: 'WPS enabled', detail: `WPS${where} is on — the 8-digit PIN is brute-forceable; disable it` });
  return out;
}
