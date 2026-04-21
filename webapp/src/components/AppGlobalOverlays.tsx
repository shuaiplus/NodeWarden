import ConfirmDialog from '@/components/ConfirmDialog';
import ToastHost from '@/components/ToastHost';
import { t } from '@/lib/i18n';
import type { ToastMessage } from '@/lib/types';

export interface AppConfirmState {
  title: string;
  message: string;
  danger?: boolean;
  showIcon?: boolean;
  confirmText?: string;
  cancelText?: string;
  hideCancel?: boolean;
  onConfirm: () => void;
}

interface AppGlobalOverlaysProps {
  toasts: ToastMessage[];
  onCloseToast: (id: string) => void;
  confirm: AppConfirmState | null;
  onCancelConfirm: () => void;
  pendingTotpOpen: boolean;
  totpCode: string;
  twoFactorProvider: '0' | '3';
  twoFactorHasTotp: boolean;
  twoFactorHasYubikey: boolean;
  rememberDevice: boolean;
  onTotpCodeChange: (value: string) => void;
  onTwoFactorProviderChange: (value: '0' | '3') => void;
  onRememberDeviceChange: (checked: boolean) => void;
  onConfirmTotp: () => void;
  onCancelTotp: () => void;
  onUseRecoveryCode: () => void;
  totpSubmitting: boolean;
  disableTotpOpen: boolean;
  disableTotpPassword: string;
  onDisableTotpPasswordChange: (value: string) => void;
  onConfirmDisableTotp: () => void;
  onCancelDisableTotp: () => void;
  disableTotpSubmitting: boolean;
}

export default function AppGlobalOverlays(props: AppGlobalOverlaysProps) {
  return (
    <>
      <ConfirmDialog
        open={!!props.confirm}
        title={props.confirm?.title || ''}
        message={props.confirm?.message || ''}
        danger={props.confirm?.danger}
        showIcon={props.confirm?.showIcon}
        confirmText={props.confirm?.confirmText}
        cancelText={props.confirm?.cancelText}
        hideCancel={props.confirm?.hideCancel}
        onConfirm={() => props.confirm?.onConfirm()}
        onCancel={props.onCancelConfirm}
      />

      <ConfirmDialog
        open={props.pendingTotpOpen}
        title={t('txt_two_step_verification')}
        message={t('txt_password_is_already_verified')}
        confirmText={t('txt_verify')}
        cancelText={t('txt_cancel')}
        showIcon={false}
        confirmDisabled={props.totpSubmitting}
        cancelDisabled={props.totpSubmitting}
        onConfirm={props.onConfirmTotp}
        onCancel={props.onCancelTotp}
        afterActions={(
          <div className="dialog-extra">
            <div className="dialog-divider" />
            <button type="button" className="btn btn-secondary dialog-btn" disabled={props.totpSubmitting} onClick={props.onUseRecoveryCode}>
              {t('txt_use_recovery_code')}
            </button>
          </div>
        )}
      >
        {(props.twoFactorHasTotp && props.twoFactorHasYubikey) && (
          <label className="field">
            <span>{t('txt_two_factor_method')}</span>
            <select
              className="input"
              value={props.twoFactorProvider}
              onChange={(e) => props.onTwoFactorProviderChange((e.currentTarget as HTMLSelectElement).value === '3' ? '3' : '0')}
            >
              <option value="0">{t('txt_totp_code')}</option>
              <option value="3">{t('txt_yubikey_otp')}</option>
            </select>
          </label>
        )}
        <label className="field">
          <span>{props.twoFactorProvider === '3' ? t('txt_yubikey_otp') : t('txt_totp_code')}</span>
          <input className="input" value={props.totpCode} autoComplete="one-time-code" onInput={(e) => props.onTotpCodeChange((e.currentTarget as HTMLInputElement).value)} />
        </label>
        <label className="check-line" style={{ marginBottom: 0 }}>
          <input type="checkbox" checked={props.rememberDevice} onChange={(e) => props.onRememberDeviceChange((e.currentTarget as HTMLInputElement).checked)} />
          <span>{t('txt_trust_this_device_for_30_days')}</span>
        </label>
      </ConfirmDialog>

      <ConfirmDialog
        open={props.disableTotpOpen}
        title={t('txt_disable_totp')}
        message={t('txt_enter_master_password_to_disable_two_step_verification')}
        confirmText={t('txt_disable_totp')}
        cancelText={t('txt_cancel')}
        danger
        showIcon={false}
        confirmDisabled={props.disableTotpSubmitting}
        cancelDisabled={props.disableTotpSubmitting}
        onConfirm={props.onConfirmDisableTotp}
        onCancel={props.onCancelDisableTotp}
      >
        <label className="field">
          <span>{t('txt_master_password')}</span>
          <input className="input" type="password" autoComplete="current-password" value={props.disableTotpPassword} onInput={(e) => props.onDisableTotpPasswordChange((e.currentTarget as HTMLInputElement).value)} />
        </label>
      </ConfirmDialog>

      <ToastHost toasts={props.toasts} onClose={props.onCloseToast} />
    </>
  );
}
