import { describe, it, expect } from 'vitest';
import { parsePe, analyzeWindowsBinary } from '../src';

/** Build a minimal PE32 buffer with a chosen DllCharacteristics + cert size. */
function pe(dllChar: number, certSize = 0): Buffer {
  const peOff = 0x80;
  const buf = Buffer.alloc(0x200);
  buf.writeUInt16LE(0x5a4d, 0);            // "MZ"
  buf.writeUInt32LE(peOff, 0x3c);          // e_lfanew
  buf.writeUInt32LE(0x00004550, peOff);    // "PE\0\0"
  const opt = peOff + 24;
  buf.writeUInt16LE(0x10b, opt);           // PE32 magic
  buf.writeUInt16LE(dllChar, opt + 0x46);  // DllCharacteristics
  buf.writeUInt32LE(16, opt + 0x5c);       // NumberOfRvaAndSizes (>4)
  const certOff = opt + 0x60 + 4 * 8;      // data dir index 4
  buf.writeUInt32LE(0x1000, certOff);      // cert RVA
  buf.writeUInt32LE(certSize, certOff + 4);// cert Size
  return buf;
}

describe('Windows binary resilience (PE parse)', () => {
  it('flags missing ASLR, DEP, CFG and unsigned on a bare binary', () => {
    const { info, findings } = analyzeWindowsBinary(pe(0x0000, 0));
    expect(info.isPE).toBe(true);
    expect(info.aslr).toBe(false);
    expect(info.dep).toBe(false);
    expect(info.signed).toBe(false);
    const titles = findings.map((f) => f.title.en);
    expect(titles.some((t) => t.includes('ASLR'))).toBe(true);
    expect(titles.some((t) => t.includes('DEP'))).toBe(true);
    expect(titles.some((t) => t.includes('not code-signed'))).toBe(true);
  });

  it('is clean on a hardened, signed binary', () => {
    const hardened = 0x0040 | 0x0100 | 0x4000; // ASLR + DEP + CFG
    const { info, findings } = analyzeWindowsBinary(pe(hardened, 0x2000));
    expect(info.aslr && info.dep && info.cfg && info.signed).toBe(true);
    expect(findings).toHaveLength(0);
  });

  it('returns no findings for a non-PE file', () => {
    expect(analyzeWindowsBinary(Buffer.from('not a pe')).findings).toEqual([]);
    expect(parsePe(Buffer.from('not a pe')).isPE).toBe(false);
  });
});
