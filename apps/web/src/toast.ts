import { reactive } from 'vue';

export const toast = reactive({ msg: '', err: false });
let timer: ReturnType<typeof setTimeout> | undefined;

export function notify(msg: string, err = false) {
  toast.msg = msg; toast.err = err;
  clearTimeout(timer);
  timer = setTimeout(() => { toast.msg = ''; }, err ? 7000 : 3500);
}

/** Run an API call, surface its error as a toast, return null on failure. */
export async function attempt<T>(fn: () => Promise<T>, okMsg?: string): Promise<T | null> {
  try {
    const r = await fn();
    if (okMsg) notify(okMsg);
    return r;
  } catch (e: any) {
    notify(e?.message ?? String(e), true);
    return null;
  }
}
