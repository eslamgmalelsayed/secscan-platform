import { ref } from 'vue';
import { UserManager, WebStorageStateStore } from 'oidc-client-ts';

export const projectLoginEnabled = ref(false);
export const projectUser = ref('');
let manager: UserManager | undefined;
export async function setupProjectLogin() {
  const response = await fetch('/api/project-login');
  if (!response.ok) return;
  const config = await response.json();
  if (!config.issuer || !config.clientId) return;
  manager = new UserManager({
    authority: config.issuer,
    client_id: config.clientId,
    redirect_uri: location.origin + '/',
    response_type: 'code',
    scope: config.scope,
    resource: config.audience,
    automaticSilentRenew: false,
    userStore: new WebStorageStateStore({ store: sessionStorage }),
  });
  projectLoginEnabled.value = true;
  const params = new URLSearchParams(location.search);
  if (params.has('state') && (params.has('code') || params.has('error'))) {
    try {
      await manager.signinRedirectCallback();
    } finally {
      history.replaceState({}, '', location.pathname);
    }
  }
  const user = await manager.getUser();
  if (user && !user.expired) projectUser.value = user.profile.name ?? user.profile.sub;
}
export async function projectToken() {
  const user = await manager?.getUser();
  return user && !user.expired ? user.access_token : undefined;
}
export async function login() {
  await manager?.signinRedirect();
}
export async function logout() {
  await manager?.removeUser();
  projectUser.value = '';
}
