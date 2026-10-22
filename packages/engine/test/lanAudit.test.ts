import { describe, it, expect } from 'vitest';
import { parseArpTable, detectArpSpoof, parseWifiSecurity, auditWifiPosture } from '../src';

describe('ARP table + spoof detection', () => {
  it('parses linux/mac/windows arp output', () => {
    const linux = '? (192.168.1.1) at aa:bb:cc:dd:ee:01 [ether] on wlan0\n? (192.168.1.5) at aa:bb:cc:dd:ee:05 [ether] on wlan0';
    const win = 'Interface: 192.168.1.10\n  192.168.1.1   aa-bb-cc-dd-ee-01   dynamic\n  192.168.1.255 ff-ff-ff-ff-ff-ff   static';
    expect(parseArpTable(linux)).toHaveLength(2);
    const w = parseArpTable(win);
    expect(w).toEqual([{ ip: '192.168.1.1', mac: 'aa:bb:cc:dd:ee:01' }]); // broadcast dropped
  });

  it('flags the gateway resolving to two MACs (spoofing)', () => {
    const entries = parseArpTable('? (192.168.1.1) at aa:bb:cc:dd:ee:01 on w\n? (192.168.1.1) at de:ad:be:ef:00:99 on w');
    const f = detectArpSpoof(entries, '192.168.1.1');
    expect(f.some((x) => x.kind === 'arp_spoof' && x.severity === 'critical')).toBe(true);
  });

  it('flags one MAC claiming many IPs', () => {
    const lines = [1, 2, 3, 4, 5].map((n) => `? (192.168.1.${n}) at de:ad:be:ef:00:99 on w`).join('\n');
    const f = detectArpSpoof(parseArpTable(lines));
    expect(f.some((x) => x.kind === 'arp_duplicate')).toBe(true);
  });

  it('is quiet on a clean table', () => {
    const entries = parseArpTable('? (192.168.1.1) at aa:bb:cc:dd:ee:01 on w\n? (192.168.1.2) at aa:bb:cc:dd:ee:02 on w');
    expect(detectArpSpoof(entries, '192.168.1.1')).toEqual([]);
  });
});

describe('WiFi posture', () => {
  it('parses nmcli and flags an open network', () => {
    const info = parseWifiSecurity('SSID: CoffeeShop\nSECURITY: Open\n');
    expect(info.ssid).toBe('CoffeeShop');
    expect(auditWifiPosture(info).some((f) => f.kind === 'wifi_open')).toBe(true);
  });
  it('flags WEP and WPS', () => {
    expect(auditWifiPosture(parseWifiSecurity('ESSID:"Home"\nAuth: WEP\nWPS: enabled')).map((f) => f.kind).sort())
      .toEqual(['wifi_weak_crypto', 'wifi_wps']);
  });
  it('rates WPA2-only as low and is clean-ish on WPA3', () => {
    expect(auditWifiPosture({ security: 'WPA2' })[0].severity).toBe('low');
    expect(auditWifiPosture({ security: 'WPA3' })).toEqual([]);
  });
});
