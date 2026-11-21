import { link, mkdir, readFile, readdir, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { Project } from '@secscan/shared';
import type { ProjectStore } from '../core/assessment';

const uuid = /^[a-f0-9-]{36}$/;
function hasCode(err: unknown, code: string) {
  return (err as NodeJS.ErrnoException).code === code;
}

/** Atomically publish a complete revision. Concurrent writers compete for the same link. */
export class FileProjects implements ProjectStore {
  constructor(private root: string) {}
  async get(id: string): Promise<Project | undefined> {
    if (!uuid.test(id)) return undefined;
    const dir = join(this.root, id);
    try {
      const names = (await readdir(dir)).filter((n) => /^\d{12}\.json$/.test(n)).sort();
      if (!names.length) return undefined;
      return JSON.parse(await readFile(join(dir, names[names.length - 1]), 'utf8'));
    } catch (e) {
      if (hasCode(e, 'ENOENT')) return undefined;
      throw e;
    }
  }
  async list() {
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    const projects: Project[] = [];
    for (const id of await readdir(this.root)) {
      const project = await this.get(id);
      if (project) projects.push(project);
    }
    return projects;
  }
  async save(project: Project, previous: number) {
    if (!uuid.test(project.id) || project.revision !== previous + 1) return false;
    const dir = join(this.root, project.id);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    if (((await this.get(project.id))?.revision ?? 0) !== previous) return false;
    const tmp = join(dir, randomUUID() + '.tmp');
    await writeFile(tmp, JSON.stringify(project), { mode: 0o600, flag: 'wx', flush: true });
    try {
      await link(tmp, join(dir, String(project.revision).padStart(12, '0') + '.json'));
      return true;
    } catch (e) {
      if (hasCode(e, 'EEXIST')) return false;
      throw e;
    } finally {
      await unlink(tmp);
    }
  }
}
