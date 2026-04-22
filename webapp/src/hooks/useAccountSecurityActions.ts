import { useMemo } from 'preact/hooks';
import {
  changeMasterPassword,
  deleteAllAuthorizedDevices,
  deleteAuthorizedDevice,
  deriveLoginHash,
  getCurrentDeviceIdentifier,
  getApiKey,
  getTotpRecoveryCode,
  rotateApiKey,
  revokeAuthorizedDeviceTrust,
  revokeAllAuthorizedDeviceTrust,
  setTotp,
  updateAuthorizedDeviceName,
  updateProfile,
} from '@/lib/api/auth';
import { t } from '@/lib/i18n';
import type { AppConfirmState } from '@/components/AppGlobalOverlays';
import type { AuthedFetch } from '@/lib/api/shared';
import type { AuthorizedDevice, Profile } from '@/lib/types';

type Notify = (type: 'success' | 'error' | 'warning', text: string) => void;

interface UseAccountSecurityActionsOptions {
  authedFetch: AuthedFetch;
  profile: Profile | null;
  defaultKdfIterations: number;
  disableTotpPassword: string;
  clearDisableTotpDialog: () => void;
  onLogoutNow: () => void;
  onNotify: Notify;
  onProfileUpdated: (profile: Profile) => void;
  onSetConfirm: (next: AppConfirmState | null) => void;
  refetchTotpStatus: () => Promise<unknown>;
  refetchAuthorizedDevices: () => Promise<unknown>;
}

export default function useAccountSecurityActions(options: UseAccountSecurityActionsOptions) {
  const {
    authedFetch,
    profile,
    defaultKdfIterations,
    disableTotpPassword,
    clearDisableTotpDialog,
    onLogoutNow,
    onNotify,
    onProfileUpdated,
    onSetConfirm,
    refetchTotpStatus,
    refetchAuthorizedDevices,
  } = options;

  return useMemo(
    () => ({
      async changePassword(currentPassword: string, nextPassword: string, nextPassword2: string) {
        if (!profile) return;
        if (!currentPassword || !nextPassword) {
          onNotify('error', t('txt_current_new_password_is_required'));
          return;
        }
        if (nextPassword.length < 12) {
          onNotify('error', t('txt_new_password_must_be_at_least_12_chars'));
          return;
        }
        if (nextPassword !== nextPassword2) {
          onNotify('error', t('txt_new_passwords_do_not_match'));
          return;
        }
        onSetConfirm({
          title: t('txt_change_master_password'),
          message: t('txt_change_password_confirm_and_sign_out_all_devices'),
          danger: true,
          onConfirm: () => {
            onSetConfirm(null);
            void (async () => {
              try {
                await changeMasterPassword(authedFetch, {
                  email: profile.email,
                  currentPassword,
                  newPassword: nextPassword,
                  currentIterations: defaultKdfIterations,
                  profileKey: profile.key,
                });
                onNotify('success', t('txt_master_password_changed_signing_out_everywhere'));
                onLogoutNow();
              } catch (error) {
                onNotify('error', error instanceof Error ? error.message : t('txt_change_password_failed'));
              }
            })();
          },
        });
      },

      async savePasswordHint(masterPasswordHint: string) {
        if (!profile) return;
        const normalized = String(masterPasswordHint || '').trim();
        if (normalized.length > 120) {
          onNotify('error', t('txt_password_hint_too_long'));
          return;
        }
        try {
          const nextProfile = await updateProfile(authedFetch, { masterPasswordHint: normalized });
          onProfileUpdated(nextProfile);
          onNotify('success', t('txt_profile_updated'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_save_profile_failed'));
        }
      },

      async enableTotp(secret: string, token: string) {
        if (!secret.trim() || !token.trim()) {
          const error = new Error(t('txt_secret_and_code_are_required'));
          onNotify('error', error.message);
          throw error;
        }
        try {
          await setTotp(authedFetch, { enabled: true, secret: secret.trim(), token: token.trim() });
          onNotify('success', t('txt_totp_enabled'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_enable_totp_failed'));
          throw error;
        }
      },

      async disableTotp() {
        if (!profile) return;
        if (!disableTotpPassword) {
          onNotify('error', t('txt_please_input_master_password'));
          return;
        }
        try {
          const derived = await deriveLoginHash(profile.email, disableTotpPassword, defaultKdfIterations);
          await setTotp(authedFetch, { enabled: false, masterPasswordHash: derived.hash });
          if (profile.id) localStorage.removeItem(`nodewarden.totp.secret.${profile.id}`);
          clearDisableTotpDialog();
          await refetchTotpStatus();
          onNotify('success', t('txt_totp_disabled'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_disable_totp_failed'));
        }
      },

      async getRecoveryCode(masterPassword: string): Promise<string> {
        if (!profile) throw new Error(t('txt_profile_unavailable'));
        const normalized = String(masterPassword || '');
        if (!normalized) throw new Error(t('txt_master_password_is_required'));
        const derived = await deriveLoginHash(profile.email, normalized, defaultKdfIterations);
        const code = await getTotpRecoveryCode(authedFetch, derived.hash);
        if (!code) throw new Error(t('txt_recovery_code_is_empty'));
        return code;
      },

      async getApiKey(masterPassword: string): Promise<string> {
        if (!profile) throw new Error(t('txt_profile_unavailable'));
        const normalized = String(masterPassword || '');
        if (!normalized) throw new Error(t('txt_master_password_is_required'));
        const derived = await deriveLoginHash(profile.email, normalized, defaultKdfIterations);
        const key = await getApiKey(authedFetch, derived.hash);
        if (!key) throw new Error(t('txt_api_key_is_empty'));
        return key;
      },

      async rotateApiKey(masterPassword: string): Promise<string> {
        if (!profile) throw new Error(t('txt_profile_unavailable'));
        const normalized = String(masterPassword || '');
        if (!normalized) throw new Error(t('txt_master_password_is_required'));
        const derived = await deriveLoginHash(profile.email, normalized, defaultKdfIterations);
        const key = await rotateApiKey(authedFetch, derived.hash);
        if (!key) throw new Error(t('txt_api_key_is_empty'));
        return key;
      },

      async refreshAuthorizedDevices() {
        await refetchAuthorizedDevices();
      },

      async renameAuthorizedDevice(device: AuthorizedDevice, name: string) {
        const normalized = String(name || '').trim();
        if (!normalized) {
          onNotify('error', t('txt_device_note_required'));
          return;
        }
        try {
          await updateAuthorizedDeviceName(authedFetch, device.identifier, normalized);
          await refetchAuthorizedDevices();
          onNotify('success', t('txt_device_note_updated'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_update_device_note_failed'));
        }
      },

      openRevokeDeviceTrust(device: AuthorizedDevice) {
        onSetConfirm({
          title: t('txt_revoke_device_authorization'),
          message: t('txt_revoke_30_day_totp_trust_for_name', { name: device.name }),
          danger: true,
          onConfirm: () => {
            onSetConfirm(null);
            void (async () => {
              try {
                await revokeAuthorizedDeviceTrust(authedFetch, device.identifier);
                await refetchAuthorizedDevices();
                onNotify('success', t('txt_device_authorization_revoked'));
              } catch (error) {
                onNotify('error', error instanceof Error ? error.message : t('txt_revoke_device_trust_failed'));
              }
            })();
          },
        });
      },

      openRemoveDevice(device: AuthorizedDevice) {
        onSetConfirm({
          title: t('txt_remove_device'),
          message: t('txt_remove_device_and_sign_out_name', { name: device.name }),
          danger: true,
          onConfirm: () => {
            onSetConfirm(null);
            void (async () => {
              try {
                await deleteAuthorizedDevice(authedFetch, device.identifier);
                if (device.identifier === getCurrentDeviceIdentifier()) {
                  onNotify('success', t('txt_device_removed'));
                  onLogoutNow();
                  return;
                }
                await refetchAuthorizedDevices();
                onNotify('success', t('txt_device_removed'));
              } catch (error) {
                onNotify('error', error instanceof Error ? error.message : t('txt_remove_device_failed'));
              }
            })();
          },
        });
      },

      openRevokeAllDeviceTrust() {
        onSetConfirm({
          title: t('txt_revoke_all_trusted_devices'),
          message: t('txt_revoke_30_day_totp_trust_from_all_devices'),
          danger: true,
          onConfirm: () => {
            onSetConfirm(null);
            void (async () => {
              try {
                await revokeAllAuthorizedDeviceTrust(authedFetch);
                await refetchAuthorizedDevices();
                onNotify('success', t('txt_all_device_authorizations_revoked'));
              } catch (error) {
                onNotify('error', error instanceof Error ? error.message : t('txt_revoke_all_device_trust_failed'));
              }
            })();
          },
        });
      },

      openRemoveAllDevices() {
        onSetConfirm({
          title: t('txt_remove_all_devices'),
          message: t('txt_remove_all_devices_and_sign_out_all_sessions'),
          danger: true,
          onConfirm: () => {
            onSetConfirm(null);
            void (async () => {
              try {
                await deleteAllAuthorizedDevices(authedFetch);
                onNotify('success', t('txt_all_devices_removed'));
                onLogoutNow();
              } catch (error) {
                onNotify('error', error instanceof Error ? error.message : t('txt_remove_all_devices_failed'));
              }
            })();
          },
        });
      },
    }),
    [
      authedFetch,
      clearDisableTotpDialog,
      defaultKdfIterations,
      disableTotpPassword,
      onLogoutNow,
      onNotify,
      onProfileUpdated,
      onSetConfirm,
      profile,
      refetchAuthorizedDevices,
      refetchTotpStatus,
    ]
  );
}
