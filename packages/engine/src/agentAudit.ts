/**
 * The on-network agent's audit, as one reusable function (Node-only).
 *
 * Runs where the server runs — the user's machine in desktop / serve mode — and
 * gathers: devices on the local subnet (non-destructive connect scan), ARP
 * table + spoofing signs, and the WiFi crypto posture. The CLI `agent` command
 * and the API `/agent/audit` endpoint both call this, so the console and the
 * terminal show the same thing. Audits a network you own; never attacks others'.
 */
import { execSync } from 'node:child_process';
import { discoverSubnet, localSubnetCidr } from './services';
import { parseArpTable, detectArpSpoof, parseWifiSecurity, auditWifiPosture, type LanFinding, type WifiInfo } from './lanAudit';

export interface AgentAuditResult {
  platform: string;
  cidr?: string;
  devices: { host: string; ports: number[] }[];
  arpEntries: number;
  gateway?: string;
  network: LanFinding[];   // ARP-spoof findings
  wifi: WifiInfo;
  wifiFindings: LanFinding[];
}

export interface AgentAuditOptions {
  cidr?: string;
  gateway?: string;
  timeoutMs?: number;
  /** Skip the subnet device sweep (fast ARP+WiFi only). */
  skipDevices?: boolean;
}

function sh(cmd: string): string {
  try { return execSync(cmd, { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 8000 }); } catch { return ''; }
}
function wifiCommand(): string {
  if (process.platform === 'darwin') return sh('/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I') || sh('system_profiler SPAirPortDataType');
  if (process.platform === 'win32') return sh('netsh wlan show interfaces');
  return sh('nmcli -t -f ACTIVE,SSID,SECURITY dev wifi') || sh('iwconfig');
}

export async function runAgentAudit(opts: AgentAuditOptions = {}): Promise<AgentAuditResult> {
  const cidr = opts.cidr ?? localSubnetCidr();
  const devices = !opts.skipDevices && cidr
    ? await discoverSubnet(cidr, { timeoutMs: opts.timeoutMs ?? 800 }).catch(() => [])
    : [];

  const arpText = sh(process.platform === 'win32' ? 'arp -a' : 'arp -an');
  const entries = parseArpTable(arpText);
  const gateway = opts.gateway ?? entries.find((e) => /\.1$/.test(e.ip))?.ip;
  const network = detectArpSpoof(entries, gateway);

  const wifi = parseWifiSecurity(wifiCommand());
  const wifiFindings = auditWifiPosture(wifi);

  return { platform: process.platform, cidr, devices, arpEntries: entries.length, gateway, network, wifi, wifiFindings };
}
