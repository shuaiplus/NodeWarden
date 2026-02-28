import { useEffect, useMemo, useState } from 'preact/hooks';
import { Link, Route, Switch, useLocation } from 'wouter';
import { useQuery } from '@tanstack/react-query';
import { CircleHelp, LogOut, Settings as SettingsIcon, Shield, ShieldUser, Vault } from 'lucide-preact';
import AuthViews from '@/components/AuthViews';
import ConfirmDialog from '@/components/ConfirmDialog';
import ToastHost from '@/components/ToastHost';
import VaultPage from '@/components/VaultPage';
import SettingsPage from '@/components/SettingsPage';
import AdminPage from '@/components/AdminPage';
import HelpPage from '@/components/HelpPage';
import {
  changeMasterPassword,
  createFolder,
  createCipher,
  createAuthedFetch,
  createInvite,
  deleteAllInvites,
  deleteCipher,
  deleteUser,
  deriveLoginHash,
  bulkMoveCiphers,
  getCiphers,
  getFolders,
  getProfile,
  getSetupStatus,
  getTotpStatus,
  getWebConfig,
  listAdminInvites,
  listAdminUsers,
  loadSession,
  loginWithPassword,
  registerAccount,
  revokeInvite,
  saveSession,
  setTotp,
  setUserStatus,
  updateCipher,
  unlockVaultKey,
  updateProfile,
  verifyMasterPassword,
} from '@/lib/api';
import { base64ToBytes, decryptBw, decryptStr } from '@/lib/crypto';
import type { AppPhase, Cipher, Folder, Profile, SessionState, ToastMessage, VaultDraft } from '@/lib/types';

interface PendingTotp {
  email: string;
  passwordHash: string;
  masterKey: Uint8Array;
}

export default function App() {
  const [location, navigate] = useLocation();
  const [phase, setPhase] = useState<AppPhase>('loading');
  const [session, setSessionState] = useState<SessionState | null>(null);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [defaultKdfIterations, setDefaultKdfIterations] = useState(600000);
  const [setupRegistered, setSetupRegistered] = useState(true);

  const [loginValues, setLoginValues] = useState({ email: '', password: '' });
  const [registerValues, setRegisterValues] = useState({
    name: '',
    email: '',
    password: '',
    password2: '',
    inviteCode: '',
  });
  const [unlockPassword, setUnlockPassword] = useState('');
  const [pendingTotp, setPendingTotp] = useState<PendingTotp | null>(null);
  const [totpCode, setTotpCode] = useState('');

  const [disableTotpOpen, setDisableTotpOpen] = useState(false);
  const [disableTotpPassword, setDisableTotpPassword] = useState('');

  const [confirm, setConfirm] = useState<{
    title: string;
    message: string;
    danger?: boolean;
    showIcon?: boolean;
    onConfirm: () => void;
  } | null>(null);

  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const [decryptedFolders, setDecryptedFolders] = useState<Folder[]>([]);
  const [decryptedCiphers, setDecryptedCiphers] = useState<Cipher[]>([]);

  function setSession(next: SessionState | null) {
    setSessionState(next);
    saveSession(next);
  }

  function pushToast(type: ToastMessage['type'], text: string) {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    setToasts((prev) => [...prev.slice(-3), { id, type, text }]);
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((x) => x.id !== id));
    }, 4500);
  }

  const authedFetch = useMemo(
    () =>
      createAuthedFetch(
        () => session,
        (next) => {
          setSession(next);
          if (!next) {
            setProfile(null);
            setPhase(setupRegistered ? 'login' : 'register');
          }
        }
      ),
    [session, setupRegistered]
  );

  useEffect(() => {
    let mounted = true;
    (async () => {
      const [setup, config] = await Promise.all([getSetupStatus(), getWebConfig()]);
      if (!mounted) return;
      setSetupRegistered(setup.registered);
      setDefaultKdfIterations(Number(config.defaultKdfIterations || 600000));

      const loaded = loadSession();
      if (!loaded) {
        setPhase(setup.registered ? 'login' : 'register');
        return;
      }
      setSession(loaded);

      try {
        const profileResp = await getProfile(
          createAuthedFetch(
            () => loaded,
            (next) => {
              if (!next) return;
              setSession(next);
            }
          )
        );
        if (!mounted) return;
        setProfile(profileResp);
        setPhase('locked');
      } catch {
        setSession(null);
        setPhase(setup.registered ? 'login' : 'register');
      }
    })();

    return () => {
      mounted = false;
    };
  }, []);

  async function finalizeLogin(tokenAccess: string, tokenRefresh: string, email: string, masterKey: Uint8Array) {
    const baseSession: SessionState = { accessToken: tokenAccess, refreshToken: tokenRefresh, email };
    const tempFetch = createAuthedFetch(
      () => baseSession,
      () => {}
    );
    const profileResp = await getProfile(tempFetch);
    const keys = await unlockVaultKey(profileResp.key, masterKey);
    const nextSession = { ...baseSession, ...keys };
    setSession(nextSession);
    setProfile(profileResp);
    setPendingTotp(null);
    setTotpCode('');
    setPhase('app');
    if (location === '/' || location === '/login' || location === '/register' || location === '/lock') {
      navigate('/vault');
    }
    pushToast('success', 'Login success');
  }

  async function handleLogin() {
    if (!loginValues.email || !loginValues.password) {
      pushToast('error', 'Please input email and password');
      return;
    }
    try {
      const derived = await deriveLoginHash(loginValues.email, loginValues.password, defaultKdfIterations);
      const token = await loginWithPassword(loginValues.email, derived.hash);
      if ('access_token' in token && token.access_token) {
        await finalizeLogin(token.access_token, token.refresh_token, loginValues.email.toLowerCase(), derived.masterKey);
        return;
      }
      const tokenError = token as { TwoFactorProviders?: unknown; error_description?: string; error?: string };
      if (tokenError.TwoFactorProviders) {
        setPendingTotp({
          email: loginValues.email.toLowerCase(),
          passwordHash: derived.hash,
          masterKey: derived.masterKey,
        });
        setTotpCode('');
        return;
      }
      pushToast('error', tokenError.error_description || tokenError.error || 'Login failed');
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : 'Login failed');
    }
  }

  async function handleTotpVerify() {
    if (!pendingTotp) return;
    if (!totpCode.trim()) {
      pushToast('error', 'Please input TOTP code');
      return;
    }
    const token = await loginWithPassword(pendingTotp.email, pendingTotp.passwordHash, totpCode.trim());
    if ('access_token' in token && token.access_token) {
      await finalizeLogin(token.access_token, token.refresh_token, pendingTotp.email, pendingTotp.masterKey);
      return;
    }
    const tokenError = token as { error_description?: string; error?: string };
    pushToast('error', tokenError.error_description || tokenError.error || 'TOTP verify failed');
  }

  async function handleRegister() {
    if (!registerValues.email || !registerValues.password) {
      pushToast('error', 'Please input email and password');
      return;
    }
    if (registerValues.password.length < 12) {
      pushToast('error', 'Master password must be at least 12 chars');
      return;
    }
    if (registerValues.password !== registerValues.password2) {
      pushToast('error', 'Passwords do not match');
      return;
    }
    const resp = await registerAccount({
      email: registerValues.email.toLowerCase(),
      name: registerValues.name.trim(),
      password: registerValues.password,
      inviteCode: registerValues.inviteCode.trim(),
      fallbackIterations: defaultKdfIterations,
    });
    if (!resp.ok) {
      pushToast('error', resp.message);
      return;
    }
    setLoginValues({ email: registerValues.email.toLowerCase(), password: '' });
    setPhase('login');
    pushToast('success', 'Registration succeeded. Please sign in.');
  }

  async function handleUnlock() {
    if (!session || !profile) return;
    if (!unlockPassword) {
      pushToast('error', 'Please input master password');
      return;
    }
    try {
      const derived = await deriveLoginHash(profile.email || session.email, unlockPassword, defaultKdfIterations);
      const keys = await unlockVaultKey(profile.key, derived.masterKey);
      setSession({ ...session, ...keys });
      setUnlockPassword('');
      setPhase('app');
      if (location === '/' || location === '/lock') navigate('/vault');
      pushToast('success', 'Unlocked');
    } catch {
      pushToast('error', 'Unlock failed. Master password is incorrect.');
    }
  }

  function handleLock() {
    if (!session) return;
    const nextSession = { ...session };
    delete nextSession.symEncKey;
    delete nextSession.symMacKey;
    setSession(nextSession);
    setPhase('locked');
    navigate('/lock');
  }

  function logoutNow() {
    setConfirm(null);
    setSession(null);
    setProfile(null);
    setPendingTotp(null);
    setPhase(setupRegistered ? 'login' : 'register');
    navigate('/login');
  }

  function handleLogout() {
    setConfirm({
      title: 'Log Out',
      message: 'Are you sure you want to log out?',
      showIcon: false,
      onConfirm: () => {
        logoutNow();
      },
    });
  }

  const ciphersQuery = useQuery({
    queryKey: ['ciphers', session?.accessToken],
    queryFn: () => getCiphers(authedFetch),
    enabled: phase === 'app' && !!session?.symEncKey && !!session?.symMacKey,
  });
  const foldersQuery = useQuery({
    queryKey: ['folders', session?.accessToken],
    queryFn: () => getFolders(authedFetch),
    enabled: phase === 'app' && !!session?.symEncKey && !!session?.symMacKey,
  });
  const usersQuery = useQuery({
    queryKey: ['admin-users', session?.accessToken],
    queryFn: () => listAdminUsers(authedFetch),
    enabled: phase === 'app' && profile?.role === 'admin',
  });
  const invitesQuery = useQuery({
    queryKey: ['admin-invites', session?.accessToken],
    queryFn: () => listAdminInvites(authedFetch),
    enabled: phase === 'app' && profile?.role === 'admin',
  });
  const totpStatusQuery = useQuery({
    queryKey: ['totp-status', session?.accessToken],
    queryFn: () => getTotpStatus(authedFetch),
    enabled: phase === 'app' && !!session?.accessToken,
  });

  useEffect(() => {
    if (!session?.symEncKey || !session?.symMacKey) {
      setDecryptedFolders([]);
      setDecryptedCiphers([]);
      return;
    }
    if (!foldersQuery.data || !ciphersQuery.data) return;

    let active = true;
    (async () => {
      try {
        const encKey = base64ToBytes(session.symEncKey!);
        const macKey = base64ToBytes(session.symMacKey!);
        const decryptField = async (
          value: string | null | undefined,
          fieldEnc: Uint8Array = encKey,
          fieldMac: Uint8Array = macKey
        ): Promise<string> => {
          if (!value || typeof value !== 'string') return '';
          try {
            return await decryptStr(value, fieldEnc, fieldMac);
          } catch {
            // Backward-compatibility: some records may already be plain text.
            return value;
          }
        };

        const folders = await Promise.all(
          foldersQuery.data.map(async (folder) => ({
            ...folder,
            decName: await decryptField(folder.name, encKey, macKey),
          }))
        );

        const ciphers = await Promise.all(
          ciphersQuery.data.map(async (cipher) => {
            let itemEnc = encKey;
            let itemMac = macKey;
            if (cipher.key) {
              try {
                const itemKey = await decryptBw(cipher.key, encKey, macKey);
                itemEnc = itemKey.slice(0, 32);
                itemMac = itemKey.slice(32, 64);
              } catch {
                // keep user key when item key decrypt fails
              }
            }

            const nextCipher: Cipher = {
              ...cipher,
              decName: await decryptField(cipher.name || '', itemEnc, itemMac),
              decNotes: await decryptField(cipher.notes || '', itemEnc, itemMac),
            };
            if (cipher.login) {
              nextCipher.login = {
                ...cipher.login,
                decUsername: await decryptField(cipher.login.username || '', itemEnc, itemMac),
                decPassword: await decryptField(cipher.login.password || '', itemEnc, itemMac),
                decTotp: await decryptField(cipher.login.totp || '', itemEnc, itemMac),
                uris: await Promise.all(
                  (cipher.login.uris || []).map(async (u) => ({
                    ...u,
                    decUri: await decryptField(u.uri || '', itemEnc, itemMac),
                  }))
                ),
              };
            }
            if (cipher.card) {
              nextCipher.card = {
                ...cipher.card,
                decCardholderName: await decryptField(cipher.card.cardholderName || '', itemEnc, itemMac),
                decNumber: await decryptField(cipher.card.number || '', itemEnc, itemMac),
                decBrand: await decryptField(cipher.card.brand || '', itemEnc, itemMac),
                decExpMonth: await decryptField(cipher.card.expMonth || '', itemEnc, itemMac),
                decExpYear: await decryptField(cipher.card.expYear || '', itemEnc, itemMac),
                decCode: await decryptField(cipher.card.code || '', itemEnc, itemMac),
              };
            }
            if (cipher.identity) {
              nextCipher.identity = {
                ...cipher.identity,
                decTitle: await decryptField(cipher.identity.title || '', itemEnc, itemMac),
                decFirstName: await decryptField(cipher.identity.firstName || '', itemEnc, itemMac),
                decMiddleName: await decryptField(cipher.identity.middleName || '', itemEnc, itemMac),
                decLastName: await decryptField(cipher.identity.lastName || '', itemEnc, itemMac),
                decUsername: await decryptField(cipher.identity.username || '', itemEnc, itemMac),
                decCompany: await decryptField(cipher.identity.company || '', itemEnc, itemMac),
                decSsn: await decryptField(cipher.identity.ssn || '', itemEnc, itemMac),
                decPassportNumber: await decryptField(cipher.identity.passportNumber || '', itemEnc, itemMac),
                decLicenseNumber: await decryptField(cipher.identity.licenseNumber || '', itemEnc, itemMac),
                decEmail: await decryptField(cipher.identity.email || '', itemEnc, itemMac),
                decPhone: await decryptField(cipher.identity.phone || '', itemEnc, itemMac),
                decAddress1: await decryptField(cipher.identity.address1 || '', itemEnc, itemMac),
                decAddress2: await decryptField(cipher.identity.address2 || '', itemEnc, itemMac),
                decAddress3: await decryptField(cipher.identity.address3 || '', itemEnc, itemMac),
                decCity: await decryptField(cipher.identity.city || '', itemEnc, itemMac),
                decState: await decryptField(cipher.identity.state || '', itemEnc, itemMac),
                decPostalCode: await decryptField(cipher.identity.postalCode || '', itemEnc, itemMac),
                decCountry: await decryptField(cipher.identity.country || '', itemEnc, itemMac),
              };
            }
            if (cipher.sshKey) {
              nextCipher.sshKey = {
                ...cipher.sshKey,
                decPrivateKey: await decryptField(cipher.sshKey.privateKey || '', itemEnc, itemMac),
                decPublicKey: await decryptField(cipher.sshKey.publicKey || '', itemEnc, itemMac),
                decFingerprint: await decryptField(cipher.sshKey.fingerprint || '', itemEnc, itemMac),
              };
            }
            if (cipher.fields) {
              nextCipher.fields = await Promise.all(
                cipher.fields.map(async (field) => ({
                  ...field,
                  decName: await decryptField(field.name || '', itemEnc, itemMac),
                  decValue: await decryptField(field.value || '', itemEnc, itemMac),
                }))
              );
            }
            return nextCipher;
          })
        );

        if (!active) return;
        setDecryptedFolders(folders);
        setDecryptedCiphers(ciphers);
      } catch (error) {
        if (!active) return;
        pushToast('error', error instanceof Error ? error.message : 'Decrypt failed');
      }
    })();

    return () => {
      active = false;
    };
  }, [session?.symEncKey, session?.symMacKey, foldersQuery.data, ciphersQuery.data]);

  async function saveProfileAction(name: string, email: string) {
    try {
      const updated = await updateProfile(authedFetch, { name: name.trim(), email: email.trim().toLowerCase() });
      setProfile(updated);
      pushToast('success', 'Profile updated');
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : 'Save profile failed');
    }
  }

  async function changePasswordAction(currentPassword: string, nextPassword: string, nextPassword2: string) {
    if (!profile) return;
    if (!currentPassword || !nextPassword) {
      pushToast('error', 'Current/new password is required');
      return;
    }
    if (nextPassword.length < 12) {
      pushToast('error', 'New password must be at least 12 chars');
      return;
    }
    if (nextPassword !== nextPassword2) {
      pushToast('error', 'New passwords do not match');
      return;
    }
    try {
      await changeMasterPassword(authedFetch, {
        email: profile.email,
        currentPassword,
        newPassword: nextPassword,
        currentIterations: defaultKdfIterations,
        profileKey: profile.key,
      });
      handleLogout();
      pushToast('success', 'Master password changed. Please login again.');
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : 'Change password failed');
    }
  }

  async function enableTotpAction(secret: string, token: string) {
    if (!secret.trim() || !token.trim()) {
      pushToast('error', 'Secret and code are required');
      return;
    }
    try {
      await setTotp(authedFetch, { enabled: true, secret: secret.trim(), token: token.trim() });
      pushToast('success', 'TOTP enabled');
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : 'Enable TOTP failed');
    }
  }

  async function disableTotpAction() {
    if (!profile) return;
    if (!disableTotpPassword) {
      pushToast('error', 'Please input master password');
      return;
    }
    try {
      const derived = await deriveLoginHash(profile.email, disableTotpPassword, defaultKdfIterations);
      await setTotp(authedFetch, { enabled: false, masterPasswordHash: derived.hash });
      if (profile?.id) localStorage.removeItem(`nodewarden.totp.secret.${profile.id}`);
      setDisableTotpOpen(false);
      setDisableTotpPassword('');
      await totpStatusQuery.refetch();
      pushToast('success', 'TOTP disabled');
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : 'Disable TOTP failed');
    }
  }

  async function refreshVault() {
    await Promise.all([ciphersQuery.refetch(), foldersQuery.refetch()]);
    pushToast('success', 'Vault synced');
  }

  async function createVaultItem(draft: VaultDraft) {
    if (!session) return;
    try {
      await createCipher(authedFetch, session, draft);
      await Promise.all([ciphersQuery.refetch(), foldersQuery.refetch()]);
      pushToast('success', 'Item created');
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : 'Create item failed');
      throw error;
    }
  }

  async function updateVaultItem(cipher: Cipher, draft: VaultDraft) {
    if (!session) return;
    try {
      await updateCipher(authedFetch, session, cipher, draft);
      await Promise.all([ciphersQuery.refetch(), foldersQuery.refetch()]);
      pushToast('success', 'Item updated');
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : 'Update item failed');
      throw error;
    }
  }

  async function deleteVaultItem(cipher: Cipher) {
    try {
      await deleteCipher(authedFetch, cipher.id);
      await Promise.all([ciphersQuery.refetch(), foldersQuery.refetch()]);
      pushToast('success', 'Item deleted');
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : 'Delete item failed');
      throw error;
    }
  }

  async function bulkDeleteVaultItems(ids: string[]) {
    try {
      for (const id of ids) {
        await deleteCipher(authedFetch, id);
      }
      await Promise.all([ciphersQuery.refetch(), foldersQuery.refetch()]);
      pushToast('success', 'Deleted selected items');
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : 'Bulk delete failed');
      throw error;
    }
  }

  async function bulkMoveVaultItems(ids: string[], folderId: string | null) {
    try {
      await bulkMoveCiphers(authedFetch, ids, folderId);
      await Promise.all([ciphersQuery.refetch(), foldersQuery.refetch()]);
      pushToast('success', 'Moved selected items');
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : 'Bulk move failed');
      throw error;
    }
  }

  async function verifyMasterPasswordAction(email: string, password: string) {
    const derived = await deriveLoginHash(email, password, defaultKdfIterations);
    await verifyMasterPassword(authedFetch, derived.hash);
  }

  async function createFolderAction(name: string) {
    const folderName = name.trim();
    if (!folderName) {
      pushToast('error', 'Folder name is required');
      return;
    }
    try {
      await createFolder(authedFetch, folderName);
      await foldersQuery.refetch();
      pushToast('success', 'Folder created');
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : 'Create folder failed');
      throw error;
    }
  }

  useEffect(() => {
    if (phase === 'app' && location === '/') navigate('/vault');
  }, [phase, location, navigate]);

  if (phase === 'loading') {
    return (
      <>
        <div className="loading-screen">Loading NodeWarden...</div>
        <ToastHost toasts={toasts} onClose={(id) => setToasts((prev) => prev.filter((x) => x.id !== id))} />
      </>
    );
  }

  if (phase === 'register' || phase === 'login' || phase === 'locked') {
    return (
      <>
        <AuthViews
          mode={phase}
          loginValues={loginValues}
          registerValues={registerValues}
          unlockPassword={unlockPassword}
          emailForLock={profile?.email || session?.email || ''}
          onChangeLogin={setLoginValues}
          onChangeRegister={setRegisterValues}
          onChangeUnlock={setUnlockPassword}
          onSubmitLogin={() => void handleLogin()}
          onSubmitRegister={() => void handleRegister()}
          onSubmitUnlock={() => void handleUnlock()}
          onGotoLogin={() => setPhase('login')}
          onGotoRegister={() => setPhase('register')}
          onLogout={logoutNow}
        />
        <ToastHost toasts={toasts} onClose={(id) => setToasts((prev) => prev.filter((x) => x.id !== id))} />

        <ConfirmDialog
          open={!!pendingTotp}
          title="Two-step verification"
          message="Password is already verified."
          confirmText="Verify"
          cancelText="Cancel"
          showIcon={false}
          onConfirm={() => void handleTotpVerify()}
          onCancel={() => {
            setPendingTotp(null);
            setTotpCode('');
          }}
        >
          <label className="field">
            <span>TOTP Code</span>
            <input className="input" value={totpCode} onInput={(e) => setTotpCode((e.currentTarget as HTMLInputElement).value)} />
          </label>
        </ConfirmDialog>
      </>
    );
  }

  return (
    <>
      <div className="app-page">
        <div className="app-shell">
          <header className="topbar">
            <div className="brand">
              <Shield size={20} className="brand-icon" />
              <span>NodeWarden</span>
            </div>
            <div className="topbar-actions">
              <div className="user-chip">
                <ShieldUser size={16} />
                <span>{profile?.email}</span>
              </div>
              <button type="button" className="btn btn-secondary small" onClick={() => navigate('/settings')}>
                <Shield size={14} className="btn-icon" /> Account Security
              </button>
              <button type="button" className="btn btn-secondary small" onClick={handleLogout}>
                <LogOut size={14} className="btn-icon" /> Sign Out
              </button>
            </div>
          </header>

          <div className="app-main">
            <aside className="app-side">
              <Link href="/vault" className={`side-link ${location === '/vault' ? 'active' : ''}`}>
                <Vault size={16} />
                <span>My Vault</span>
              </Link>
              {profile?.role === 'admin' && (
                <Link href="/admin" className={`side-link ${location === '/admin' ? 'active' : ''}`}>
                  <ShieldUser size={16} />
                  <span>Admin Panel</span>
                </Link>
              )}
              <Link href="/settings" className={`side-link ${location === '/settings' ? 'active' : ''}`}>
                <SettingsIcon size={16} />
                <span>System Settings</span>
              </Link>
              <Link href="/help" className={`side-link ${location === '/help' ? 'active' : ''}`}>
                <CircleHelp size={16} />
                <span>Support Center</span>
              </Link>
            </aside>
            <main className="content">
              <Switch>
                <Route path="/vault">
                  <VaultPage
                    ciphers={decryptedCiphers}
                    folders={decryptedFolders}
                    loading={ciphersQuery.isFetching || foldersQuery.isFetching}
                    emailForReprompt={profile?.email || session?.email || ''}
                    onRefresh={refreshVault}
                    onCreate={createVaultItem}
                    onUpdate={updateVaultItem}
                    onDelete={deleteVaultItem}
                    onBulkDelete={bulkDeleteVaultItems}
                    onBulkMove={bulkMoveVaultItems}
                    onVerifyMasterPassword={verifyMasterPasswordAction}
                    onNotify={pushToast}
                    onCreateFolder={createFolderAction}
                  />
                </Route>
                <Route path="/settings">
                  {profile && (
                    <SettingsPage
                      profile={profile}
                      totpEnabled={!!totpStatusQuery.data?.enabled}
                      onSaveProfile={saveProfileAction}
                      onChangePassword={changePasswordAction}
                      onEnableTotp={async (secret, token) => {
                        await enableTotpAction(secret, token);
                        await totpStatusQuery.refetch();
                      }}
                      onOpenDisableTotp={() => setDisableTotpOpen(true)}
                    />
                  )}
                </Route>
                <Route path="/admin">
                  <AdminPage
                    currentUserId={profile?.id || ''}
                    users={usersQuery.data || []}
                    invites={invitesQuery.data || []}
                    onRefresh={() => {
                      void usersQuery.refetch();
                      void invitesQuery.refetch();
                    }}
                    onCreateInvite={async (hours) => {
                      await createInvite(authedFetch, hours);
                      await invitesQuery.refetch();
                      pushToast('success', 'Invite created');
                    }}
                    onDeleteAllInvites={async () => {
                      setConfirm({
                        title: 'Delete all invites',
                        message: 'Delete all invite codes (active/inactive)?',
                        danger: true,
                        onConfirm: () => {
                          setConfirm(null);
                          void (async () => {
                            await deleteAllInvites(authedFetch);
                            await invitesQuery.refetch();
                            pushToast('success', 'All invites deleted');
                          })();
                        },
                      });
                    }}
                    onToggleUserStatus={async (userId, status) => {
                      await setUserStatus(authedFetch, userId, status === 'active' ? 'banned' : 'active');
                      await usersQuery.refetch();
                      pushToast('success', 'User status updated');
                    }}
                    onDeleteUser={async (userId) => {
                      setConfirm({
                        title: 'Delete user',
                        message: 'Delete this user and all user data?',
                        danger: true,
                        onConfirm: () => {
                          setConfirm(null);
                          void (async () => {
                            await deleteUser(authedFetch, userId);
                            await usersQuery.refetch();
                            pushToast('success', 'User deleted');
                          })();
                        },
                      });
                    }}
                    onRevokeInvite={async (code) => {
                      await revokeInvite(authedFetch, code);
                      await invitesQuery.refetch();
                      pushToast('success', 'Invite revoked');
                    }}
                  />
                </Route>
                <Route path="/help">
                  <HelpPage />
                </Route>
              </Switch>
            </main>
          </div>
        </div>
      </div>

      <ConfirmDialog
        open={!!confirm}
        title={confirm?.title || ''}
        message={confirm?.message || ''}
        danger={confirm?.danger}
        showIcon={confirm?.showIcon}
        onConfirm={() => confirm?.onConfirm()}
        onCancel={() => setConfirm(null)}
      />

      <ConfirmDialog
        open={disableTotpOpen}
        title="Disable TOTP"
        message="Enter master password to disable two-step verification."
        confirmText="Disable TOTP"
        cancelText="Cancel"
        danger
        showIcon={false}
        onConfirm={() => void disableTotpAction()}
        onCancel={() => {
          setDisableTotpOpen(false);
          setDisableTotpPassword('');
        }}
      >
        <label className="field">
          <span>Master Password</span>
          <input
            className="input"
            type="password"
            value={disableTotpPassword}
            onInput={(e) => setDisableTotpPassword((e.currentTarget as HTMLInputElement).value)}
          />
        </label>
      </ConfirmDialog>

      <ToastHost toasts={toasts} onClose={(id) => setToasts((prev) => prev.filter((x) => x.id !== id))} />
    </>
  );
}
