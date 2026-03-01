import { useEffect, useMemo, useState } from 'preact/hooks';
import { Link, Route, Switch, useLocation } from 'wouter';
import { useQuery } from '@tanstack/react-query';
import { ArrowUpDown, Cloud, Lock, LogOut, Send as SendIcon, Settings as SettingsIcon, Shield, ShieldUser, Vault } from 'lucide-preact';
import AuthViews from '@/components/AuthViews';
import ConfirmDialog from '@/components/ConfirmDialog';
import ToastHost from '@/components/ToastHost';
import VaultPage from '@/components/VaultPage';
import SendsPage from '@/components/SendsPage';
import PublicSendPage from '@/components/PublicSendPage';
import RecoverTwoFactorPage from '@/components/RecoverTwoFactorPage';
import JwtWarningPage from '@/components/JwtWarningPage';
import SettingsPage from '@/components/SettingsPage';
import SecurityDevicesPage from '@/components/SecurityDevicesPage';
import AdminPage from '@/components/AdminPage';
import HelpPage from '@/components/HelpPage';
import ImportExportPage from '@/components/ImportExportPage';
import {
  changeMasterPassword,
  createFolder,
  createCipher,
  createAuthedFetch,
  createInvite,
  createSend,
  deleteAllInvites,
  deleteCipher,
  deleteSend,
  deleteUser,
  deriveLoginHash,
  bulkMoveCiphers,
  getCiphers,
  getFolders,
  getProfile,
  getAuthorizedDevices,
  getSetupStatus,
  getSends,
  getTotpStatus,
  getTotpRecoveryCode,
  getWebConfig,
  listAdminInvites,
  listAdminUsers,
  loadSession,
  loginWithPassword,
  registerAccount,
  recoverTwoFactor,
  revokeInvite,
  revokeAuthorizedDeviceTrust,
  revokeAllAuthorizedDeviceTrust,
  saveSession,
  setTotp,
  setUserStatus,
  deleteAuthorizedDevice,
  updateCipher,
  updateSend,
  buildSendShareKey,
  unlockVaultKey,
  verifyMasterPassword,
} from '@/lib/api';
import { base64ToBytes, decryptBw, decryptStr, hkdf } from '@/lib/crypto';
import { t } from '@/lib/i18n';
import type { AppPhase, AuthorizedDevice, Cipher, Folder, Profile, Send, SendDraft, SessionState, ToastMessage, VaultDraft } from '@/lib/types';

interface PendingTotp {
  email: string;
  passwordHash: string;
  masterKey: Uint8Array;
}

type JwtUnsafeReason = 'missing' | 'default' | 'too_short';

const SEND_KEY_SALT = 'bitwarden-send';
const SEND_KEY_PURPOSE = 'send';

function buildPublicSendUrl(origin: string, accessId: string, keyPart: string): string {
  return `${origin}/#/send/${accessId}/${keyPart}`;
}

async function deriveSendKeyParts(sendKeyMaterial: Uint8Array): Promise<{ enc: Uint8Array; mac: Uint8Array }> {
  if (sendKeyMaterial.length >= 64) {
    return { enc: sendKeyMaterial.slice(0, 32), mac: sendKeyMaterial.slice(32, 64) };
  }
  const derived = await hkdf(sendKeyMaterial, SEND_KEY_SALT, SEND_KEY_PURPOSE, 64);
  return { enc: derived.slice(0, 32), mac: derived.slice(32, 64) };
}

export default function App() {
  const [location, navigate] = useLocation();
  const [phase, setPhase] = useState<AppPhase>('loading');
  const [session, setSessionState] = useState<SessionState | null>(null);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [defaultKdfIterations, setDefaultKdfIterations] = useState(600000);
  const [setupRegistered, setSetupRegistered] = useState(true);
  const [jwtWarning, setJwtWarning] = useState<{ reason: JwtUnsafeReason; minLength: number } | null>(null);

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
  const [rememberDevice, setRememberDevice] = useState(true);

  const [disableTotpOpen, setDisableTotpOpen] = useState(false);
  const [disableTotpPassword, setDisableTotpPassword] = useState('');
  const [recoverValues, setRecoverValues] = useState({ email: '', password: '', recoveryCode: '' });

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
  const [decryptedSends, setDecryptedSends] = useState<Send[]>([]);

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
      const jwtUnsafeReason = config.jwtUnsafeReason || null;
      if (jwtUnsafeReason) {
        setJwtWarning({
          reason: jwtUnsafeReason,
          minLength: Number(config.jwtSecretMinLength || 32),
        });
        setSession(null);
        setProfile(null);
        setPhase('login');
        return;
      }
      setJwtWarning(null);

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
    pushToast('success', t('txt_login_success'));
  }

  async function handleLogin() {
    if (!loginValues.email || !loginValues.password) {
      pushToast('error', t('txt_please_input_email_and_password'));
      return;
    }
    try {
      const derived = await deriveLoginHash(loginValues.email, loginValues.password, defaultKdfIterations);
      const token = await loginWithPassword(loginValues.email, derived.hash, { useRememberToken: true });
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
        setRememberDevice(true);
        return;
      }
      pushToast('error', tokenError.error_description || tokenError.error || t('txt_login_failed'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_login_failed'));
    }
  }

  async function handleTotpVerify() {
    if (!pendingTotp) return;
    if (!totpCode.trim()) {
      pushToast('error', t('txt_please_input_totp_code'));
      return;
    }
    const token = await loginWithPassword(pendingTotp.email, pendingTotp.passwordHash, {
      totpCode: totpCode.trim(),
      rememberDevice,
    });
    if ('access_token' in token && token.access_token) {
      await finalizeLogin(token.access_token, token.refresh_token, pendingTotp.email, pendingTotp.masterKey);
      return;
    }
    const tokenError = token as { error_description?: string; error?: string };
    pushToast('error', tokenError.error_description || tokenError.error || t('txt_totp_verify_failed'));
  }

  async function handleRecoverTwoFactorSubmit() {
    const email = recoverValues.email.trim().toLowerCase();
    const password = recoverValues.password;
    const recoveryCode = recoverValues.recoveryCode.trim();
    if (!email || !password || !recoveryCode) {
      pushToast('error', t('txt_email_password_and_recovery_code_are_required'));
      return;
    }
    try {
      const derived = await deriveLoginHash(email, password, defaultKdfIterations);
      const recovered = await recoverTwoFactor(email, derived.hash, recoveryCode);
      const token = await loginWithPassword(email, derived.hash, { useRememberToken: false });
      if ('access_token' in token && token.access_token) {
        await finalizeLogin(token.access_token, token.refresh_token, email, derived.masterKey);
        if (recovered.newRecoveryCode) {
          pushToast('success', t('txt_text_2fa_recovered_new_recovery_code_code', { code: recovered.newRecoveryCode }));
        } else {
          pushToast('success', t('txt_text_2fa_recovered'));
        }
        return;
      }
      pushToast('error', t('txt_recovered_but_auto_login_failed_please_sign_in'));
      navigate('/login');
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_recover_2fa_failed'));
    }
  }

  async function handleRegister() {
    if (!registerValues.email || !registerValues.password) {
      pushToast('error', t('txt_please_input_email_and_password'));
      return;
    }
    if (registerValues.password.length < 12) {
      pushToast('error', t('txt_master_password_must_be_at_least_12_chars'));
      return;
    }
    if (registerValues.password !== registerValues.password2) {
      pushToast('error', t('txt_passwords_do_not_match'));
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
    pushToast('success', t('txt_registration_succeeded_please_sign_in'));
  }

  async function handleUnlock() {
    if (!session || !profile) return;
    if (!unlockPassword) {
      pushToast('error', t('txt_please_input_master_password'));
      return;
    }
    try {
      const derived = await deriveLoginHash(profile.email || session.email, unlockPassword, defaultKdfIterations);
      const keys = await unlockVaultKey(profile.key, derived.masterKey);
      setSession({ ...session, ...keys });
      setUnlockPassword('');
      setPhase('app');
      if (location === '/' || location === '/lock') navigate('/vault');
      pushToast('success', t('txt_unlocked'));
    } catch {
      pushToast('error', t('txt_unlock_failed_master_password_is_incorrect'));
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
      title: t('txt_log_out'),
      message: t('txt_are_you_sure_you_want_to_log_out'),
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
  const sendsQuery = useQuery({
    queryKey: ['sends', session?.accessToken],
    queryFn: () => getSends(authedFetch),
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
  const authorizedDevicesQuery = useQuery({
    queryKey: ['authorized-devices', session?.accessToken],
    queryFn: () => getAuthorizedDevices(authedFetch),
    enabled: phase === 'app' && !!session?.accessToken,
  });

  useEffect(() => {
    if (!session?.symEncKey || !session?.symMacKey) {
      setDecryptedFolders([]);
      setDecryptedCiphers([]);
      setDecryptedSends([]);
      return;
    }
    if (!foldersQuery.data || !ciphersQuery.data || !sendsQuery.data) return;

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

        const sends = await Promise.all(
          sendsQuery.data.map(async (send) => {
            const nextSend: Send = { ...send };
            try {
              if (send.key) {
                const sendKeyRaw = await decryptBw(send.key, encKey, macKey);
                const derived = await deriveSendKeyParts(sendKeyRaw);
                nextSend.decName = await decryptField(send.name || '', derived.enc, derived.mac);
                nextSend.decNotes = await decryptField(send.notes || '', derived.enc, derived.mac);
                nextSend.decText = await decryptField(send.text?.text || '', derived.enc, derived.mac);
                if (send.file?.fileName) {
                  const decFileName = await decryptField(send.file.fileName, derived.enc, derived.mac);
                  nextSend.file = {
                    ...(send.file || {}),
                    fileName: decFileName || send.file.fileName,
                  };
                }
                const shareKey = await buildSendShareKey(send.key, session.symEncKey!, session.symMacKey!);
                nextSend.decShareKey = shareKey;
                nextSend.shareUrl = buildPublicSendUrl(window.location.origin, send.accessId, shareKey);
              } else {
                nextSend.decName = '';
                nextSend.decNotes = '';
                nextSend.decText = '';
              }
            } catch {
              nextSend.decName = t('txt_decrypt_failed');
            }
            return nextSend;
          })
        );

        if (!active) return;
        setDecryptedFolders(folders);
        setDecryptedCiphers(ciphers);
        setDecryptedSends(sends);
      } catch (error) {
        if (!active) return;
        pushToast('error', error instanceof Error ? error.message : t('txt_decrypt_failed_2'));
      }
    })();

    return () => {
      active = false;
    };
  }, [session?.symEncKey, session?.symMacKey, foldersQuery.data, ciphersQuery.data, sendsQuery.data]);

  async function changePasswordAction(currentPassword: string, nextPassword: string, nextPassword2: string) {
    if (!profile) return;
    if (!currentPassword || !nextPassword) {
      pushToast('error', t('txt_current_new_password_is_required'));
      return;
    }
    if (nextPassword.length < 12) {
      pushToast('error', t('txt_new_password_must_be_at_least_12_chars'));
      return;
    }
    if (nextPassword !== nextPassword2) {
      pushToast('error', t('txt_new_passwords_do_not_match'));
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
      pushToast('success', t('txt_master_password_changed_please_login_again'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_change_password_failed'));
    }
  }

  async function enableTotpAction(secret: string, token: string) {
    if (!secret.trim() || !token.trim()) {
      pushToast('error', t('txt_secret_and_code_are_required'));
      return;
    }
    try {
      await setTotp(authedFetch, { enabled: true, secret: secret.trim(), token: token.trim() });
      pushToast('success', t('txt_totp_enabled'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_enable_totp_failed'));
    }
  }

  async function disableTotpAction() {
    if (!profile) return;
    if (!disableTotpPassword) {
      pushToast('error', t('txt_please_input_master_password'));
      return;
    }
    try {
      const derived = await deriveLoginHash(profile.email, disableTotpPassword, defaultKdfIterations);
      await setTotp(authedFetch, { enabled: false, masterPasswordHash: derived.hash });
      if (profile?.id) localStorage.removeItem(`nodewarden.totp.secret.${profile.id}`);
      setDisableTotpOpen(false);
      setDisableTotpPassword('');
      await totpStatusQuery.refetch();
      pushToast('success', t('txt_totp_disabled'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_disable_totp_failed'));
    }
  }

  async function refreshVault() {
    await Promise.all([ciphersQuery.refetch(), foldersQuery.refetch(), sendsQuery.refetch()]);
    pushToast('success', t('txt_vault_synced'));
  }

  async function refreshAuthorizedDevices() {
    await authorizedDevicesQuery.refetch();
  }

  async function revokeDeviceTrustAction(device: AuthorizedDevice) {
    await revokeAuthorizedDeviceTrust(authedFetch, device.identifier);
    await authorizedDevicesQuery.refetch();
    pushToast('success', t('txt_device_authorization_revoked'));
  }

  async function revokeAllDeviceTrustAction() {
    await revokeAllAuthorizedDeviceTrust(authedFetch);
    await authorizedDevicesQuery.refetch();
    pushToast('success', t('txt_all_device_authorizations_revoked'));
  }

  async function removeDeviceAction(device: AuthorizedDevice) {
    await deleteAuthorizedDevice(authedFetch, device.identifier);
    await authorizedDevicesQuery.refetch();
    pushToast('success', t('txt_device_removed'));
  }

  async function createVaultItem(draft: VaultDraft) {
    if (!session) return;
    try {
      await createCipher(authedFetch, session, draft);
      await Promise.all([ciphersQuery.refetch(), foldersQuery.refetch()]);
      pushToast('success', t('txt_item_created'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_create_item_failed'));
      throw error;
    }
  }

  async function updateVaultItem(cipher: Cipher, draft: VaultDraft) {
    if (!session) return;
    try {
      await updateCipher(authedFetch, session, cipher, draft);
      await Promise.all([ciphersQuery.refetch(), foldersQuery.refetch()]);
      pushToast('success', t('txt_item_updated'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_update_item_failed'));
      throw error;
    }
  }

  async function deleteVaultItem(cipher: Cipher) {
    try {
      await deleteCipher(authedFetch, cipher.id);
      await Promise.all([ciphersQuery.refetch(), foldersQuery.refetch()]);
      pushToast('success', t('txt_item_deleted'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_delete_item_failed'));
      throw error;
    }
  }

  async function bulkDeleteVaultItems(ids: string[]) {
    try {
      for (const id of ids) {
        await deleteCipher(authedFetch, id);
      }
      await Promise.all([ciphersQuery.refetch(), foldersQuery.refetch()]);
      pushToast('success', t('txt_deleted_selected_items'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_bulk_delete_failed'));
      throw error;
    }
  }

  async function bulkMoveVaultItems(ids: string[], folderId: string | null) {
    try {
      await bulkMoveCiphers(authedFetch, ids, folderId);
      await Promise.all([ciphersQuery.refetch(), foldersQuery.refetch()]);
      pushToast('success', t('txt_moved_selected_items'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_bulk_move_failed'));
      throw error;
    }
  }

  async function getRecoveryCodeAction(masterPassword: string): Promise<string> {
    if (!profile) throw new Error(t('txt_profile_unavailable'));
    const normalized = String(masterPassword || '');
    if (!normalized) throw new Error(t('txt_master_password_is_required'));
    const derived = await deriveLoginHash(profile.email, normalized, defaultKdfIterations);
    const code = await getTotpRecoveryCode(authedFetch, derived.hash);
    if (!code) throw new Error(t('txt_recovery_code_is_empty'));
    return code;
  }

  async function createSendItem(draft: SendDraft, autoCopyLink: boolean) {
    if (!session) return;
    try {
      const created = await createSend(authedFetch, session, draft);
      await sendsQuery.refetch();
      if (autoCopyLink && created.key && session.symEncKey && session.symMacKey) {
        const keyPart = await buildSendShareKey(created.key, session.symEncKey, session.symMacKey);
        const shareUrl = buildPublicSendUrl(window.location.origin, created.accessId, keyPart);
        await navigator.clipboard.writeText(shareUrl);
      }
      pushToast('success', t('txt_send_created'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_create_send_failed'));
      throw error;
    }
  }

  async function updateSendItem(send: Send, draft: SendDraft, autoCopyLink: boolean) {
    if (!session) return;
    try {
      const updated = await updateSend(authedFetch, session, send, draft);
      await sendsQuery.refetch();
      if (autoCopyLink && updated.key && session.symEncKey && session.symMacKey) {
        const keyPart = await buildSendShareKey(updated.key, session.symEncKey, session.symMacKey);
        const shareUrl = buildPublicSendUrl(window.location.origin, updated.accessId, keyPart);
        await navigator.clipboard.writeText(shareUrl);
      }
      pushToast('success', t('txt_send_updated'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_update_send_failed'));
      throw error;
    }
  }

  async function deleteSendItem(send: Send) {
    try {
      await deleteSend(authedFetch, send.id);
      await sendsQuery.refetch();
      pushToast('success', t('txt_send_deleted'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_delete_send_failed'));
      throw error;
    }
  }

  async function bulkDeleteSendItems(ids: string[]) {
    try {
      for (const id of ids) {
        await deleteSend(authedFetch, id);
      }
      await sendsQuery.refetch();
      pushToast('success', t('txt_deleted_selected_sends'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_bulk_delete_sends_failed'));
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
      pushToast('error', t('txt_folder_name_is_required'));
      return;
    }
    try {
      await createFolder(authedFetch, folderName);
      await foldersQuery.refetch();
      pushToast('success', t('txt_folder_created'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_create_folder_failed'));
      throw error;
    }
  }

  const hashPathRaw = typeof window !== 'undefined' ? window.location.hash || '' : '';
  const hashPath = hashPathRaw.startsWith('#') ? hashPathRaw.slice(1) : hashPathRaw;
  const effectiveLocation = hashPath.startsWith('/send/') || hashPath === '/recover-2fa' ? hashPath : location;
  const publicSendMatch = effectiveLocation.match(/^\/send\/([^/]+)(?:\/([^/]+))?\/?$/i);
  const isRecoverTwoFactorRoute = effectiveLocation === '/recover-2fa';
  const isPublicSendRoute = !!publicSendMatch;

  useEffect(() => {
    if (phase === 'app' && location === '/' && !isPublicSendRoute) navigate('/vault');
  }, [phase, location, isPublicSendRoute, navigate]);

  if (jwtWarning) {
    return <JwtWarningPage reason={jwtWarning.reason} minLength={jwtWarning.minLength} />;
  }

  if (publicSendMatch) {
    return (
      <>
        <PublicSendPage accessId={decodeURIComponent(publicSendMatch[1])} keyPart={publicSendMatch[2] ? decodeURIComponent(publicSendMatch[2]) : null} />
        <ToastHost toasts={toasts} onClose={(id) => setToasts((prev) => prev.filter((x) => x.id !== id))} />
      </>
    );
  }

  if (isRecoverTwoFactorRoute && phase !== 'app') {
    return (
      <>
        <RecoverTwoFactorPage
          values={recoverValues}
          onChange={setRecoverValues}
          onSubmit={() => void handleRecoverTwoFactorSubmit()}
          onCancel={() => {
            setRecoverValues({ email: '', password: '', recoveryCode: '' });
            navigate('/login');
          }}
        />
        <ToastHost toasts={toasts} onClose={(id) => setToasts((prev) => prev.filter((x) => x.id !== id))} />
      </>
    );
  }

  if (phase === 'loading') {
    return (
      <>
        <div className="loading-screen">{t('txt_loading_nodewarden')}</div>
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
          title={t('txt_two_step_verification')}
          message={t('txt_password_is_already_verified')}
          confirmText={t('txt_verify')}
          cancelText={t('txt_cancel')}
          showIcon={false}
          onConfirm={() => void handleTotpVerify()}
          onCancel={() => {
            setPendingTotp(null);
            setTotpCode('');
            setRememberDevice(true);
          }}
          afterActions={(
            <div className="dialog-extra">
              <div className="dialog-divider" />
              <button
                type="button"
                className="btn btn-secondary dialog-btn"
                onClick={() => {
                  setPendingTotp(null);
                  setTotpCode('');
                  setRememberDevice(true);
                  navigate('/recover-2fa');
                }}
              >
                {t('txt_use_recovery_code')}
              </button>
            </div>
          )}
        >
          <label className="field">
            <span>{t('txt_totp_code')}</span>
            <input className="input" value={totpCode} onInput={(e) => setTotpCode((e.currentTarget as HTMLInputElement).value)} />
          </label>
          <label className="check-line" style={{ marginBottom: 0 }}>
            <input type="checkbox" checked={rememberDevice} onChange={(e) => setRememberDevice((e.currentTarget as HTMLInputElement).checked)} />
            <span>{t('txt_trust_this_device_for_30_days')}</span>
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
              <img src="/logo-64.png" alt="NodeWarden logo" className="brand-logo" />
              <span>NodeWarden</span>
            </div>
            <div className="topbar-actions">
              <div className="user-chip">
                <ShieldUser size={16} />
                <span>{profile?.email}</span>
              </div>
              <button type="button" className="btn btn-secondary small" onClick={handleLock}>
                <Lock size={14} className="btn-icon" /> {t('txt_lock')}
              </button>
              <button type="button" className="btn btn-secondary small" onClick={handleLogout}>
                <LogOut size={14} className="btn-icon" /> {t('txt_sign_out')}
              </button>
            </div>
          </header>

          <div className="app-main">
            <aside className="app-side">
              <Link href="/vault" className={`side-link ${location === '/vault' ? 'active' : ''}`}>
                <Vault size={16} />
                <span>{t('nav_my_vault')}</span>
              </Link>
              <Link href="/sends" className={`side-link ${location === '/sends' ? 'active' : ''}`}>
                <SendIcon size={16} />
                <span>{t('nav_sends')}</span>
              </Link>
              {profile?.role === 'admin' && (
                <Link href="/admin" className={`side-link ${location === '/admin' ? 'active' : ''}`}>
                  <ShieldUser size={16} />
                  <span>{t('nav_admin_panel')}</span>
                </Link>
              )}
              <Link href="/settings" className={`side-link ${location === '/settings' ? 'active' : ''}`}>
                <SettingsIcon size={16} />
                <span>{t('nav_account_settings')}</span>
              </Link>
              <Link href="/security/devices" className={`side-link ${location === '/security/devices' ? 'active' : ''}`}>
                <Shield size={16} />
                <span>{t('nav_device_management')}</span>
              </Link>
              <Link href="/help" className={`side-link ${location === '/help' ? 'active' : ''}`}>
                <Cloud size={16} />
                <span>{t('nav_backup_strategy')}</span>
              </Link>
              <Link href="/help/import-export" className={`side-link ${location === '/help/import-export' ? 'active' : ''}`}>
                <ArrowUpDown size={14} />
                <span>{t('nav_import_export')}</span>
              </Link>
            </aside>
            <main className="content">
              <Switch>
                <Route path="/sends">
                  <SendsPage
                    sends={decryptedSends}
                    loading={sendsQuery.isFetching}
                    onRefresh={refreshVault}
                    onCreate={createSendItem}
                    onUpdate={updateSendItem}
                    onDelete={deleteSendItem}
                    onBulkDelete={bulkDeleteSendItems}
                    onNotify={pushToast}
                  />
                </Route>
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
                      onChangePassword={changePasswordAction}
                      onEnableTotp={async (secret, token) => {
                        await enableTotpAction(secret, token);
                        await totpStatusQuery.refetch();
                      }}
                      onOpenDisableTotp={() => setDisableTotpOpen(true)}
                      onGetRecoveryCode={getRecoveryCodeAction}
                      onNotify={pushToast}
                    />
                  )}
                </Route>
                <Route path="/security/devices">
                  <SecurityDevicesPage
                    devices={authorizedDevicesQuery.data || []}
                    loading={authorizedDevicesQuery.isFetching}
                    onRefresh={() => void refreshAuthorizedDevices()}
                    onRevokeTrust={(device) => {
                      setConfirm({
                        title: t('txt_revoke_device_authorization'),
                        message: t('txt_revoke_30_day_totp_trust_for_name', { name: device.name }),
                        danger: true,
                        onConfirm: () => {
                          setConfirm(null);
                          void revokeDeviceTrustAction(device);
                        },
                      });
                    }}
                    onRemoveDevice={(device) => {
                      setConfirm({
                        title: t('txt_remove_device'),
                        message: t('txt_remove_device_name_and_clear_its_2fa_trust', { name: device.name }),
                        danger: true,
                        onConfirm: () => {
                          setConfirm(null);
                          void removeDeviceAction(device);
                        },
                      });
                    }}
                    onRevokeAll={() => {
                      setConfirm({
                        title: t('txt_revoke_all_trusted_devices'),
                        message: t('txt_revoke_30_day_totp_trust_from_all_devices'),
                        danger: true,
                        onConfirm: () => {
                          setConfirm(null);
                          void revokeAllDeviceTrustAction();
                        },
                      });
                    }}
                  />
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
                      pushToast('success', t('txt_invite_created'));
                    }}
                    onDeleteAllInvites={async () => {
                      setConfirm({
                        title: t('txt_delete_all_invites'),
                        message: t('txt_delete_all_invite_codes_active_inactive'),
                        danger: true,
                        onConfirm: () => {
                          setConfirm(null);
                          void (async () => {
                            await deleteAllInvites(authedFetch);
                            await invitesQuery.refetch();
                            pushToast('success', t('txt_all_invites_deleted'));
                          })();
                        },
                      });
                    }}
                    onToggleUserStatus={async (userId, status) => {
                      await setUserStatus(authedFetch, userId, status === 'active' ? 'banned' : 'active');
                      await usersQuery.refetch();
                      pushToast('success', t('txt_user_status_updated'));
                    }}
                    onDeleteUser={async (userId) => {
                      setConfirm({
                        title: t('txt_delete_user'),
                        message: t('txt_delete_this_user_and_all_user_data'),
                        danger: true,
                        onConfirm: () => {
                          setConfirm(null);
                          void (async () => {
                            await deleteUser(authedFetch, userId);
                            await usersQuery.refetch();
                            pushToast('success', t('txt_user_deleted'));
                          })();
                        },
                      });
                    }}
                    onRevokeInvite={async (code) => {
                      await revokeInvite(authedFetch, code);
                      await invitesQuery.refetch();
                      pushToast('success', t('txt_invite_revoked'));
                    }}
                  />
                </Route>
                <Route path="/help/import-export">
                  <ImportExportPage />
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
        title={t('txt_disable_totp')}
        message={t('txt_enter_master_password_to_disable_two_step_verification')}
        confirmText={t('txt_disable_totp')}
        cancelText={t('txt_cancel')}
        danger
        showIcon={false}
        onConfirm={() => void disableTotpAction()}
        onCancel={() => {
          setDisableTotpOpen(false);
          setDisableTotpPassword('');
        }}
      >
        <label className="field">
          <span>{t('txt_master_password')}</span>
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
