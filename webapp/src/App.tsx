import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { useLocation } from 'wouter';
import { useQuery } from '@tanstack/react-query';
import AppAuthenticatedShell from '@/components/AppAuthenticatedShell';
import AppGlobalOverlays, { type AppConfirmState } from '@/components/AppGlobalOverlays';
import AuthViews from '@/components/AuthViews';
import PublicSendPage from '@/components/PublicSendPage';
import RecoverTwoFactorPage from '@/components/RecoverTwoFactorPage';
import JwtWarningPage from '@/components/JwtWarningPage';
import {
  createAuthedFetch,
  getAuthorizedDevices,
  getCurrentDeviceIdentifier,
  getTotpStatus,
  saveSession,
} from '@/lib/api/auth';
import { listAdminInvites, listAdminUsers } from '@/lib/api/admin';
import { buildSendShareKey, getSends } from '@/lib/api/send';
import {
  getCiphers,
  getFolders,
  updateFolder,
} from '@/lib/api/vault';
import { silentlyRepairBackupSettingsIfNeeded } from '@/lib/backup-settings-repair';
import { base64ToBytes, decryptBw, decryptStr } from '@/lib/crypto';
import {
  buildPublicSendUrl,
  deriveSendKeyParts,
  looksLikeCipherString,
  parseSignalRTextFrames,
  readInviteCodeFromUrl,
} from '@/lib/app-support';
import {
  bootstrapAppSession,
  type CompletedLogin,
  readInitialAppBootstrapState,
  performPasswordLogin,
  performRecoverTwoFactorLogin,
  performRegistration,
  performTotpLogin,
  performUnlock,
  type JwtUnsafeReason,
  type PendingTotp,
} from '@/lib/app-auth';
import useAccountSecurityActions from '@/hooks/useAccountSecurityActions';
import useAdminActions from '@/hooks/useAdminActions';
import useBackupActions from '@/hooks/useBackupActions';
import useVaultSendActions from '@/hooks/useVaultSendActions';
import { useToastManager } from '@/hooks/useToastManager';
import { t } from '@/lib/i18n';
import { APP_NOTIFY_EVENT, type AppNotifyDetail } from '@/lib/app-notify';
import type { AppPhase, Cipher, Folder as VaultFolder, Profile, Send, SessionState } from '@/lib/types';

const IMPORT_ROUTE = '/help/import-export';
const IMPORT_ROUTE_PATHS = [IMPORT_ROUTE, '/tools/import', '/tools/import-export', '/tools/import-data', '/import', '/import-export'] as const;
const IMPORT_ROUTE_ALIASES: ReadonlySet<string> = new Set(IMPORT_ROUTE_PATHS.filter((path) => path !== IMPORT_ROUTE));
const SETTINGS_HOME_ROUTE = '/settings';
const SETTINGS_ACCOUNT_ROUTE = '/settings/account';
const SIGNALR_RECORD_SEPARATOR = String.fromCharCode(0x1e);
const SIGNALR_UPDATE_TYPE_SYNC_VAULT = 5;
const SIGNALR_UPDATE_TYPE_LOG_OUT = 11;
const SIGNALR_UPDATE_TYPE_DEVICE_STATUS = 12;

export default function App() {
  const initialBootstrap = useMemo(() => readInitialAppBootstrapState(), []);
  const initialInviteCode = useMemo(() => readInviteCodeFromUrl(), []);
  const [pendingAuthAction, setPendingAuthAction] = useState<'login' | 'register' | 'unlock' | null>(null);
  const [location, navigate] = useLocation();
  const [phase, setPhase] = useState<AppPhase>(initialBootstrap.phase);
  const [session, setSessionState] = useState<SessionState | null>(initialBootstrap.session);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [defaultKdfIterations, setDefaultKdfIterations] = useState(initialBootstrap.defaultKdfIterations);
  const [jwtWarning, setJwtWarning] = useState<{ reason: JwtUnsafeReason; minLength: number } | null>(initialBootstrap.jwtWarning);

  const [loginValues, setLoginValues] = useState({ email: '', password: '' });
  const [registerValues, setRegisterValues] = useState({
    name: '',
    email: '',
    password: '',
    password2: '',
    inviteCode: initialInviteCode,
  });
  const [inviteCodeFromUrl, setInviteCodeFromUrl] = useState(initialInviteCode);
  const [unlockPassword, setUnlockPassword] = useState('');
  const [pendingTotp, setPendingTotp] = useState<PendingTotp | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [rememberDevice, setRememberDevice] = useState(true);

  const [disableTotpOpen, setDisableTotpOpen] = useState(false);
  const [disableTotpPassword, setDisableTotpPassword] = useState('');
  const [recoverValues, setRecoverValues] = useState({ email: '', password: '', recoveryCode: '' });

  const [confirm, setConfirm] = useState<AppConfirmState | null>(null);
  const [mobileLayout, setMobileLayout] = useState(false);
  const [decryptedFolders, setDecryptedFolders] = useState<VaultFolder[]>([]);
  const [decryptedCiphers, setDecryptedCiphers] = useState<Cipher[]>([]);
  const [decryptedSends, setDecryptedSends] = useState<Send[]>([]);
  const sessionRef = useRef<SessionState | null>(initialBootstrap.session);
  const migratedPlainFolderIdsRef = useRef<Set<string>>(new Set());
  const silentRefreshVaultRef = useRef<() => Promise<void>>(async () => {});
  const refreshAuthorizedDevicesRef = useRef<() => Promise<void>>(async () => {});
  const repairAttemptRef = useRef<string>('');
  const { toasts, pushToast, removeToast } = useToastManager();

  useEffect(() => {
    const handleAppNotify = (event: Event) => {
      const detail = (event as CustomEvent<AppNotifyDetail>).detail;
      if (!detail?.text) return;
      pushToast(detail.type, detail.text);
    };

    window.addEventListener(APP_NOTIFY_EVENT, handleAppNotify as EventListener);
    return () => window.removeEventListener(APP_NOTIFY_EVENT, handleAppNotify as EventListener);
  }, [pushToast]);

  useEffect(() => {
    const syncInviteFromUrl = () => {
      setInviteCodeFromUrl(readInviteCodeFromUrl());
    };
    syncInviteFromUrl();
    window.addEventListener('hashchange', syncInviteFromUrl);
    window.addEventListener('popstate', syncInviteFromUrl);
    return () => {
      window.removeEventListener('hashchange', syncInviteFromUrl);
      window.removeEventListener('popstate', syncInviteFromUrl);
    };
  }, []);

  useEffect(() => {
    if (!inviteCodeFromUrl) return;
    setRegisterValues((prev) => (prev.inviteCode === inviteCodeFromUrl ? prev : { ...prev, inviteCode: inviteCodeFromUrl }));
  }, [inviteCodeFromUrl]);

  useEffect(() => {
    if (!inviteCodeFromUrl) return;
    if (phase === 'locked' || phase === 'app') return;
    setPhase('register');
    if (location !== '/register') navigate('/register');
    if (typeof window !== 'undefined' && typeof window.history?.replaceState === 'function') {
      window.history.replaceState(null, '', '/register');
    }
    setInviteCodeFromUrl('');
  }, [inviteCodeFromUrl, phase, location, navigate]);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return;
    const media = window.matchMedia('(max-width: 900px)');
    const sync = () => setMobileLayout(media.matches);
    sync();
    if (typeof media.addEventListener === 'function') {
      media.addEventListener('change', sync);
      return () => media.removeEventListener('change', sync);
    }
    media.addListener(sync);
    return () => media.removeListener(sync);
  }, []);

  function setSession(next: SessionState | null) {
    sessionRef.current = next;
    setSessionState(next);
    saveSession(next);
  }

  const authedFetch = useMemo(
    () =>
      createAuthedFetch(
        () => session,
        (next) => {
          setSession(next);
          if (!next) {
            setProfile(null);
            setPhase('login');
          }
        }
      ),
    [session]
  );
  const importAuthedFetch = useMemo(
    () => async (input: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers || {});
      headers.set('X-NodeWarden-Import', '1');
      return authedFetch(input, { ...init, headers });
    },
    [authedFetch]
  );
  const backupActions = useBackupActions({
    authedFetch,
    onImported: () => {
      window.setTimeout(() => {
        logoutNow();
      }, 200);
    },
    onRestored: () => {
      window.setTimeout(() => {
        logoutNow();
      }, 200);
    },
  });

  useEffect(() => {
    let mounted = true;
    (async () => {
      const boot = await bootstrapAppSession();
      if (!mounted) return;
      setDefaultKdfIterations(boot.defaultKdfIterations);
      setJwtWarning(boot.jwtWarning);
      setSession(boot.session);
      setProfile(boot.profile);
      setPhase(boot.phase);
    })();

    return () => {
      mounted = false;
    };
  }, []);

  async function finalizeLogin(login: CompletedLogin) {
    setSession(login.session);
    setProfile(login.profile);
    setPendingTotp(null);
    setTotpCode('');
    setPhase('app');
    if (location === '/' || location === '/login' || location === '/register' || location === '/lock') {
      navigate('/vault');
    }
    pushToast('success', t('txt_login_success'));
    void (async () => {
      try {
        const hydratedProfile = await login.profilePromise;
        if (sessionRef.current?.accessToken !== login.session.accessToken) return;
        setProfile(hydratedProfile);
      } catch {
        // Keep the in-memory transient profile for the current session.
      }
    })();
  }

  async function handleLogin() {
    if (pendingAuthAction) return;
    if (!loginValues.email || !loginValues.password) {
      pushToast('error', t('txt_please_input_email_and_password'));
      return;
    }
    setPendingAuthAction('login');
    try {
      const result = await performPasswordLogin(loginValues.email, loginValues.password, defaultKdfIterations);
      if (result.kind === 'success') {
        await finalizeLogin(result.login);
        return;
      }
      if (result.kind === 'totp') {
        setPendingTotp(result.pendingTotp);
        setTotpCode('');
        setRememberDevice(true);
        return;
      }
      pushToast('error', result.message || t('txt_login_failed'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_login_failed'));
    } finally {
      setPendingAuthAction(null);
    }
  }

  async function handleTotpVerify() {
    if (!pendingTotp) return;
    if (!totpCode.trim()) {
      pushToast('error', t('txt_please_input_totp_code'));
      return;
    }
    try {
      const login = await performTotpLogin(pendingTotp, totpCode, rememberDevice);
      await finalizeLogin(login);
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_totp_verify_failed'));
    }
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
      const recovered = await performRecoverTwoFactorLogin(email, password, recoveryCode, defaultKdfIterations);
      if (recovered.login) {
        await finalizeLogin(recovered.login);
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
    if (pendingAuthAction) return;
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
    setPendingAuthAction('register');
    try {
      const resp = await performRegistration({
        email: registerValues.email,
        name: registerValues.name,
        password: registerValues.password,
        inviteCode: registerValues.inviteCode,
        fallbackIterations: defaultKdfIterations,
      });
      if (!resp.ok) {
        pushToast('error', resp.message);
        return;
      }
      setLoginValues({ email: registerValues.email.toLowerCase(), password: '' });
      setPhase('login');
      navigate('/login');
      pushToast('success', t('txt_registration_succeeded_please_sign_in'));
    } finally {
      setPendingAuthAction(null);
    }
  }

  async function handleUnlock() {
    if (pendingAuthAction) return;
    if (!session || !profile) return;
    if (!unlockPassword) {
      pushToast('error', t('txt_please_input_master_password'));
      return;
    }
    setPendingAuthAction('unlock');
    try {
      const nextSession = await performUnlock(session, profile, unlockPassword, defaultKdfIterations);
      setSession(nextSession);
      setUnlockPassword('');
      setPhase('app');
      if (location === '/' || location === '/lock') navigate('/vault');
      pushToast('success', t('txt_unlocked'));
    } catch {
      pushToast('error', t('txt_unlock_failed_master_password_is_incorrect'));
    } finally {
      setPendingAuthAction(null);
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
    setPhase('login');
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

  function renderPassiveOverlays() {
    return (
      <AppGlobalOverlays
        toasts={toasts}
        onCloseToast={removeToast}
        confirm={null}
        onCancelConfirm={() => {}}
        pendingTotpOpen={false}
        totpCode=""
        rememberDevice={false}
        onTotpCodeChange={() => {}}
        onRememberDeviceChange={() => {}}
        onConfirmTotp={() => {}}
        onCancelTotp={() => {}}
        onUseRecoveryCode={() => {}}
        disableTotpOpen={false}
        disableTotpPassword=""
        onDisableTotpPasswordChange={() => {}}
        onConfirmDisableTotp={() => {}}
        onCancelDisableTotp={() => {}}
      />
    );
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
    if (phase !== 'app' || !session?.accessToken || !session?.symEncKey || !session?.symMacKey) return;
    if (!profile?.role || profile.role !== 'admin') return;
    if (repairAttemptRef.current === session.accessToken) return;

    repairAttemptRef.current = session.accessToken;
    void silentlyRepairBackupSettingsIfNeeded(session, profile);
  }, [phase, session?.accessToken, session?.symEncKey, session?.symMacKey, profile]);

  useEffect(() => {
    if (session?.accessToken) return;
    repairAttemptRef.current = '';
  }, [session?.accessToken]);

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
                fido2Credentials: Array.isArray(cipher.login.fido2Credentials)
                  ? cipher.login.fido2Credentials.map((credential) => ({ ...credential }))
                  : null,
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
              const encryptedFingerprint = cipher.sshKey.keyFingerprint || cipher.sshKey.fingerprint || '';
              nextCipher.sshKey = {
                ...cipher.sshKey,
                decPrivateKey: await decryptField(cipher.sshKey.privateKey || '', itemEnc, itemMac),
                decPublicKey: await decryptField(cipher.sshKey.publicKey || '', itemEnc, itemMac),
                keyFingerprint: encryptedFingerprint || null,
                fingerprint: encryptedFingerprint || null,
                decFingerprint: await decryptField(encryptedFingerprint, itemEnc, itemMac),
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
            if (Array.isArray(cipher.attachments)) {
              nextCipher.attachments = await Promise.all(
                cipher.attachments.map(async (attachment) => ({
                  ...attachment,
                  decFileName: await decryptField(attachment.fileName || '', itemEnc, itemMac),
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

  useEffect(() => {
    if (!session?.symEncKey || !session?.symMacKey || !foldersQuery.data?.length) return;
    let cancelled = false;
    (async () => {
      const pending = foldersQuery.data.filter((folder) => {
        if (!folder?.id || !folder?.name) return false;
        if (migratedPlainFolderIdsRef.current.has(folder.id)) return false;
        return !looksLikeCipherString(String(folder.name));
      });
      if (!pending.length) return;
      for (const folder of pending) {
        try {
          await updateFolder(authedFetch, session, folder.id, String(folder.name));
          migratedPlainFolderIdsRef.current.add(folder.id);
        } catch {
          // keep silent; web still supports plaintext fallback display
        }
      }
      if (!cancelled) await foldersQuery.refetch();
    })();
    return () => {
      cancelled = true;
    };
  }, [session?.symEncKey, session?.symMacKey, foldersQuery.data, authedFetch]);

  async function refreshVaultSilently() {
    await Promise.all([ciphersQuery.refetch(), foldersQuery.refetch(), sendsQuery.refetch()]);
  }

  silentRefreshVaultRef.current = refreshVaultSilently;

  useEffect(() => {
    if (phase !== 'app' || !session?.accessToken || !session?.symEncKey || !session?.symMacKey) return;

    let disposed = false;
    let socket: WebSocket | null = null;
    let reconnectTimer: number | null = null;
    let reconnectAttempts = 0;

    const clearReconnectTimer = () => {
      if (reconnectTimer !== null) {
        window.clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
    };

    const scheduleReconnect = () => {
      if (disposed) return;
      clearReconnectTimer();
      const delay = Math.min(10000, 1000 * Math.max(1, reconnectAttempts + 1));
      reconnectAttempts += 1;
      reconnectTimer = window.setTimeout(() => {
        reconnectTimer = null;
        connect();
      }, delay);
    };

    const connect = () => {
      if (disposed) return;
      try {
        const hubUrl = new URL('/notifications/hub', window.location.origin);
        hubUrl.searchParams.set('access_token', session.accessToken);
        hubUrl.protocol = hubUrl.protocol === 'https:' ? 'wss:' : 'ws:';
        socket = new WebSocket(hubUrl.toString());
      } catch {
        scheduleReconnect();
        return;
      }

      socket.addEventListener('open', () => {
        reconnectAttempts = 0;
        void refreshAuthorizedDevicesRef.current();
        try {
          socket?.send(`{"protocol":"json","version":1}${SIGNALR_RECORD_SEPARATOR}`);
        } catch {
          socket?.close();
        }
      });

      socket.addEventListener('message', (event) => {
        if (disposed) return;
        if (typeof event.data !== 'string') return;

        const frames = parseSignalRTextFrames(event.data);
        for (const frame of frames) {
          if (frame.type !== 1 || frame.target !== 'ReceiveMessage') continue;
          const updateType = Number(frame.arguments?.[0]?.Type || 0);
          if (updateType === SIGNALR_UPDATE_TYPE_LOG_OUT) {
            logoutNow();
            return;
          }
          if (updateType === SIGNALR_UPDATE_TYPE_DEVICE_STATUS) {
            void refreshAuthorizedDevicesRef.current();
            continue;
          }
          if (updateType !== SIGNALR_UPDATE_TYPE_SYNC_VAULT) continue;
          const contextId = String(frame.arguments?.[0]?.ContextId || '').trim();
          if (contextId && contextId === getCurrentDeviceIdentifier()) continue;
          void silentRefreshVaultRef.current();
        }
      });

      socket.addEventListener('close', () => {
        socket = null;
        void refreshAuthorizedDevicesRef.current();
        scheduleReconnect();
      });

      socket.addEventListener('error', () => {
        try {
          socket?.close();
        } catch {
          // ignore close races
        }
      });
    };

    connect();

    return () => {
      disposed = true;
      clearReconnectTimer();
      if (socket && socket.readyState === WebSocket.OPEN) {
        try {
          socket.close();
        } catch {
          // ignore close races
        }
      }
    };
  }, [phase, session?.accessToken, session?.symEncKey, session?.symMacKey]);

  const vaultSendActions = useVaultSendActions({
    authedFetch,
    importAuthedFetch,
    session,
    profile,
    defaultKdfIterations,
    encryptedCiphers: ciphersQuery.data,
    encryptedFolders: foldersQuery.data,
    refetchCiphers: ciphersQuery.refetch,
    refetchFolders: foldersQuery.refetch,
    refetchSends: sendsQuery.refetch,
    onNotify: pushToast,
  });
  const accountSecurityActions = useAccountSecurityActions({
    authedFetch,
    profile,
    defaultKdfIterations,
    disableTotpPassword,
    clearDisableTotpDialog: () => {
      setDisableTotpOpen(false);
      setDisableTotpPassword('');
    },
    onLogoutNow: logoutNow,
    onNotify: pushToast,
    onSetConfirm: setConfirm,
    refetchTotpStatus: totpStatusQuery.refetch,
    refetchAuthorizedDevices: authorizedDevicesQuery.refetch,
  });
  const adminActions = useAdminActions({
    authedFetch,
    onNotify: pushToast,
    onSetConfirm: setConfirm,
    refetchUsers: usersQuery.refetch,
    refetchInvites: invitesQuery.refetch,
  });

  refreshAuthorizedDevicesRef.current = async () => {
    await authorizedDevicesQuery.refetch();
  };

  const hashPathRaw = typeof window !== 'undefined' ? window.location.hash || '' : '';
  const hashPath = hashPathRaw.startsWith('#') ? hashPathRaw.slice(1) : hashPathRaw;
  const hashPathOnly = String(hashPath || '').split('?')[0].split('#')[0];
  const trimmedHashPath = hashPathOnly.replace(/^\/+/, '').replace(/\/+$/, '');
  const normalizedHashPath = trimmedHashPath ? `/${trimmedHashPath}` : '/';
  const isImportHashRoute = IMPORT_ROUTE_ALIASES.has(normalizedHashPath);
  const effectiveLocation = hashPath.startsWith('/send/') || hashPath === '/recover-2fa' ? hashPath : location;
  const publicSendMatch = effectiveLocation.match(/^\/send\/([^/]+)(?:\/([^/]+))?\/?$/i);
  const isRecoverTwoFactorRoute = effectiveLocation === '/recover-2fa';
  const isPublicSendRoute = !!publicSendMatch;
  const isImportRoute = location === IMPORT_ROUTE || IMPORT_ROUTE_ALIASES.has(location);
  const showSidebarToggle = mobileLayout && (location === '/vault' || location === '/sends');
  const sidebarToggleTitle = location === '/vault' ? t('txt_folders') : t('txt_type');
  const mobilePrimaryRoute =
    location === '/sends'
      ? '/sends'
      : location === '/vault/totp'
        ? '/vault/totp'
        : location === '/vault'
          ? '/vault'
          : '/settings';
  const currentPageTitle = (() => {
    if (location === '/vault/totp') return t('txt_verification_code');
    if (location === '/sends') return t('nav_sends');
    if (location === '/admin') return t('nav_admin_panel');
    if (location === '/security/devices') return t('nav_device_management');
    if (location === '/help') return t('nav_backup_strategy');
    if (isImportRoute) return t('nav_import_export');
    if (location === SETTINGS_ACCOUNT_ROUTE) return t('nav_account_settings');
    if (location === SETTINGS_HOME_ROUTE) return t('txt_settings');
    return t('nav_my_vault');
  })();

  useEffect(() => {
    if (phase === 'app' && location === '/' && !isPublicSendRoute) navigate('/vault');
  }, [phase, location, isPublicSendRoute, navigate]);

  useEffect(() => {
    if (phase === 'app' && isImportHashRoute && location !== IMPORT_ROUTE) {
      navigate(IMPORT_ROUTE);
    }
  }, [phase, isImportHashRoute, location, navigate]);

  useEffect(() => {
    if (phase === 'app' && profile?.role !== 'admin' && location === '/help') {
      navigate('/vault');
    }
  }, [phase, profile?.role, location, navigate]);

  useEffect(() => {
    if (phase === 'app' && !mobileLayout && location === SETTINGS_HOME_ROUTE) {
      navigate(SETTINGS_ACCOUNT_ROUTE);
    }
  }, [phase, mobileLayout, location, navigate]);

  const mainRoutesProps = {
    profile,
    session,
    mobileLayout,
    importRoute: IMPORT_ROUTE,
    settingsHomeRoute: SETTINGS_HOME_ROUTE,
    settingsAccountRoute: SETTINGS_ACCOUNT_ROUTE,
    decryptedCiphers,
    decryptedFolders,
    decryptedSends,
    ciphersLoading: ciphersQuery.isFetching,
    foldersLoading: foldersQuery.isFetching,
    sendsLoading: sendsQuery.isFetching,
    users: usersQuery.data || [],
    invites: invitesQuery.data || [],
    totpEnabled: !!totpStatusQuery.data?.enabled,
    authorizedDevices: authorizedDevicesQuery.data || [],
    authorizedDevicesLoading: authorizedDevicesQuery.isFetching,
    onNavigate: navigate,
    onLogout: handleLogout,
    onNotify: pushToast,
    onImport: vaultSendActions.importVault,
    onImportEncryptedRaw: vaultSendActions.importEncryptedRaw,
    onExport: vaultSendActions.exportVault,
    onCreateVaultItem: vaultSendActions.createVaultItem,
    onUpdateVaultItem: vaultSendActions.updateVaultItem,
    onDeleteVaultItem: vaultSendActions.deleteVaultItem,
    onBulkDeleteVaultItems: vaultSendActions.bulkDeleteVaultItems,
    onBulkPermanentDeleteVaultItems: vaultSendActions.bulkPermanentDeleteVaultItems,
    onBulkRestoreVaultItems: vaultSendActions.bulkRestoreVaultItems,
    onBulkMoveVaultItems: vaultSendActions.bulkMoveVaultItems,
    onVerifyMasterPassword: vaultSendActions.verifyMasterPassword,
    onCreateFolder: vaultSendActions.createFolder,
    onDeleteFolder: vaultSendActions.deleteFolder,
    onBulkDeleteFolders: vaultSendActions.bulkDeleteFolders,
    onDownloadVaultAttachment: vaultSendActions.downloadVaultAttachment,
    downloadingAttachmentKey: vaultSendActions.downloadingAttachmentKey,
    attachmentDownloadPercent: vaultSendActions.attachmentDownloadPercent,
    uploadingAttachmentName: vaultSendActions.uploadingAttachmentName,
    attachmentUploadPercent: vaultSendActions.attachmentUploadPercent,
    onRefreshVault: vaultSendActions.refreshVault,
    onCreateSend: vaultSendActions.createSend,
    onUpdateSend: vaultSendActions.updateSend,
    onDeleteSend: vaultSendActions.deleteSend,
    onBulkDeleteSends: vaultSendActions.bulkDeleteSends,
    uploadingSendFileName: vaultSendActions.uploadingSendFileName,
    sendUploadPercent: vaultSendActions.sendUploadPercent,
    onChangePassword: accountSecurityActions.changePassword,
    onEnableTotp: async (secret: string, token: string) => {
      await accountSecurityActions.enableTotp(secret, token);
      await totpStatusQuery.refetch();
    },
    onOpenDisableTotp: () => setDisableTotpOpen(true),
    onGetRecoveryCode: accountSecurityActions.getRecoveryCode,
    onRefreshAuthorizedDevices: accountSecurityActions.refreshAuthorizedDevices,
    onRevokeDeviceTrust: accountSecurityActions.openRevokeDeviceTrust,
    onRemoveDevice: accountSecurityActions.openRemoveDevice,
    onRevokeAllDeviceTrust: accountSecurityActions.openRevokeAllDeviceTrust,
    onRemoveAllDevices: accountSecurityActions.openRemoveAllDevices,
    onRefreshAdmin: adminActions.refreshAdmin,
    onCreateInvite: adminActions.createInvite,
    onDeleteAllInvites: adminActions.deleteAllInvites,
    onToggleUserStatus: adminActions.toggleUserStatus,
    onDeleteUser: adminActions.deleteUser,
    onRevokeInvite: adminActions.revokeInvite,
    onExportBackup: backupActions.exportBackup,
    onImportBackup: backupActions.importBackup,
    onLoadBackupSettings: backupActions.loadSettings,
    onSaveBackupSettings: backupActions.saveSettings,
    onRunRemoteBackup: backupActions.runRemoteBackup,
    onListRemoteBackups: backupActions.listRemoteBackups,
    onDownloadRemoteBackup: backupActions.downloadRemoteBackup,
    onDeleteRemoteBackup: backupActions.deleteRemoteBackup,
    onRestoreRemoteBackup: backupActions.restoreRemoteBackup,
  };

  if (jwtWarning) {
    return <JwtWarningPage reason={jwtWarning.reason} minLength={jwtWarning.minLength} />;
  }

  if (publicSendMatch) {
    return (
      <>
        <PublicSendPage accessId={decodeURIComponent(publicSendMatch[1])} keyPart={publicSendMatch[2] ? decodeURIComponent(publicSendMatch[2]) : null} />
        {renderPassiveOverlays()}
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
        {renderPassiveOverlays()}
      </>
    );
  }

  if (phase === 'register' || phase === 'login' || phase === 'locked') {
    return (
      <>
        <AuthViews
          mode={phase}
          pendingAction={pendingAuthAction}
          unlockReady={!!profile}
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
          onGotoLogin={() => {
            setPhase('login');
            navigate('/login');
          }}
          onGotoRegister={() => {
            if (inviteCodeFromUrl) {
              setRegisterValues((prev) => ({ ...prev, inviteCode: inviteCodeFromUrl }));
            }
            setPhase('register');
            navigate('/register');
          }}
          onLogout={logoutNow}
        />
        <AppGlobalOverlays
          toasts={toasts}
          onCloseToast={removeToast}
          confirm={null}
          onCancelConfirm={() => {}}
          pendingTotpOpen={!!pendingTotp}
          totpCode={totpCode}
          rememberDevice={rememberDevice}
          onTotpCodeChange={setTotpCode}
          onRememberDeviceChange={setRememberDevice}
          onConfirmTotp={() => void handleTotpVerify()}
          onCancelTotp={() => {
            setPendingTotp(null);
            setTotpCode('');
            setRememberDevice(true);
          }}
          onUseRecoveryCode={() => {
            setPendingTotp(null);
            setTotpCode('');
            setRememberDevice(true);
            navigate('/recover-2fa');
          }}
          disableTotpOpen={false}
          disableTotpPassword=""
          onDisableTotpPasswordChange={() => {}}
          onConfirmDisableTotp={() => {}}
          onCancelDisableTotp={() => {}}
        />
      </>
    );
  }

  return (
    <>
      <AppAuthenticatedShell
        profile={profile}
        location={location}
        mobilePrimaryRoute={mobilePrimaryRoute}
        currentPageTitle={currentPageTitle}
        showSidebarToggle={showSidebarToggle}
        sidebarToggleTitle={sidebarToggleTitle}
        settingsAccountRoute={SETTINGS_ACCOUNT_ROUTE}
        importRoute={IMPORT_ROUTE}
        isImportRoute={isImportRoute}
        onLock={handleLock}
        onLogout={handleLogout}
        mainRoutesProps={mainRoutesProps}
      />

      <AppGlobalOverlays
        toasts={toasts}
        onCloseToast={removeToast}
        confirm={confirm}
        onCancelConfirm={() => setConfirm(null)}
        pendingTotpOpen={false}
        totpCode=""
        rememberDevice={false}
        onTotpCodeChange={() => {}}
        onRememberDeviceChange={() => {}}
        onConfirmTotp={() => {}}
        onCancelTotp={() => {}}
        onUseRecoveryCode={() => {}}
        disableTotpOpen={disableTotpOpen}
        disableTotpPassword={disableTotpPassword}
        onDisableTotpPasswordChange={setDisableTotpPassword}
        onConfirmDisableTotp={() => void accountSecurityActions.disableTotp()}
        onCancelDisableTotp={() => {
          setDisableTotpOpen(false);
          setDisableTotpPassword('');
        }}
      />
    </>
  );
}
