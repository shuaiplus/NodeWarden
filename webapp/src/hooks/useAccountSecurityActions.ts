import { useMemo } from 'preact/hooks';
import {
  changeMasterPassword,
  deleteAllAuthorizedDevices,
  deleteAuthorizedDevice,
  deriveLoginHash,
  getCurrentDeviceIdentifier,
  getTotpRecoveryCode,
  revokeAuthorizedDeviceTrust,
  revokeAllAuthorizedDeviceTrust,
  setTotp,
  setYubikey,
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
  refetchYubikeyStatus: () => Promise<unknown>;
  onYubikeyStatusUpdated: (next: { enabled: boolean; publicIds: string[]; nfc: boolean }) => void;
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
    refetchYubikeyStatus,
    onYubikeyStatusUpdated,
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

      async bindYubikey(otp: string, nfc: boolean) {
        const normalized = String(otp || '').trim();
        if (!normalized) {
          onNotify('error', t('txt_please_input_yubikey_otp'));
          return;
        }
        try {
          const nextStatus = await setYubikey(authedFetch, { enabled: true, otp: normalized, nfc });
          onYubikeyStatusUpdated(nextStatus);
          onNotify('success', t('txt_yubikey_bound'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_yubikey_bind_failed'));
          throw error;
        }
      },

      openUnbindYubikey(publicId: string, masterPassword: string) {
        const normalizedPublicId = String(publicId || '').trim().toLowerCase();
        onSetConfirm({
          title: t('txt_unbind_yubikey'),
          message: t('txt_unbind_yubikey_confirm_message', { publicId: normalizedPublicId }),
          danger: true,
          onConfirm: () => {
            onSetConfirm(null);
            void (async () => {
              try {
                await unbindYubikey(normalizedPublicId, masterPassword);
              } catch (error) {
                onNotify('error', error instanceof Error ? error.message : t('txt_unbind_yubikey_failed'));
              }
            })();
          },
        });
      },

      openDisableYubikey(masterPassword: string) {
        onSetConfirm({
          title: t('txt_disable_yubikey'),
          message: t('txt_disable_yubikey_confirm_message'),
          danger: true,
          onConfirm: () => {
            onSetConfirm(null);
            void (async () => {
              try {
                await disableYubikey(masterPassword);
              } catch (error) {
                onNotify('error', error instanceof Error ? error.message : t('txt_disable_yubikey_failed'));
              }
            })();
          },
        });
      },

      async unbindYubikey(publicId: string, masterPassword: string) {
        if (!profile) throw new Error(t('txt_profile_unavailable'));
        const normalizedPublicId = String(publicId || '').trim().toLowerCase();
        const normalizedPassword = String(masterPassword || '').trim();
        if (!normalizedPublicId || !normalizedPassword) {
          throw new Error(t('txt_master_password_is_required'));
        }
        const derived = await deriveLoginHash(profile.email, normalizedPassword, defaultKdfIterations);
        const nextStatus = await setYubikey(authedFetch, {
          removePublicId: normalizedPublicId,
          masterPasswordHash: derived.hash,
        });
        onYubikeyStatusUpdated(nextStatus);
      },

      async disableYubikey(masterPassword: string) {
        if (!profile) throw new Error(t('txt_profile_unavailable'));
        const normalized = String(masterPassword || '').trim();
        if (!normalized) throw new Error(t('txt_master_password_is_required'));
        const derived = await deriveLoginHash(profile.email, normalized, defaultKdfIterations);
        const nextStatus = await setYubikey(authedFetch, {
          enabled: false,
          masterPasswordHash: derived.hash,
        });
        onYubikeyStatusUpdated(nextStatus);
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
      onYubikeyStatusUpdated,
      refetchAuthorizedDevices,
      refetchYubikeyStatus,
      refetchTotpStatus,
    ]
  );
}
