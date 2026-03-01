import type { ComponentChildren } from 'preact';
import { t } from '@/lib/i18n';

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  message: string;
  showIcon?: boolean;
  confirmText?: string;
  cancelText?: string;
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  children?: ComponentChildren;
  afterActions?: ComponentChildren;
}

export default function ConfirmDialog(props: ConfirmDialogProps) {
  if (!props.open) return null;
  return (
    <div className="dialog-mask">
      <div className="dialog-card">
        <h3 className="dialog-title">{props.title}</h3>
        <div className="dialog-message">{props.message}</div>
        {props.children}
        <button
          type="button"
          className={`btn ${props.danger ? 'btn-danger' : 'btn-primary'} dialog-btn`}
          onClick={props.onConfirm}
        >
          {props.confirmText || t('txt_yes')}
        </button>
        <button type="button" className="btn btn-secondary dialog-btn" onClick={props.onCancel}>
          {props.cancelText || t('txt_no')}
        </button>
        {props.afterActions}
      </div>
    </div>
  );
}
