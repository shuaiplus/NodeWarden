import type { ComponentChildren } from 'preact';
import { Check, X } from 'lucide-preact';
import { t } from '@/lib/i18n';

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  message: string;
  showIcon?: boolean;
  confirmText?: string;
  cancelText?: string;
  danger?: boolean;
  hideCancel?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  children?: ComponentChildren;
  afterActions?: ComponentChildren;
}

export default function ConfirmDialog(props: ConfirmDialogProps) {
  if (!props.open) return null;
  return (
    <div className="dialog-mask">
      <form
        className="dialog-card"
        onSubmit={(e) => {
          e.preventDefault();
          props.onConfirm();
        }}
      >
        <h3 className="dialog-title">{props.title}</h3>
        <div className="dialog-message">{props.message}</div>
        {props.children}
        <button
          type="submit"
          className={`btn ${props.danger ? 'btn-danger' : 'btn-primary'} dialog-btn`}
        >
          <Check size={14} className="btn-icon" />
          {props.confirmText || t('txt_yes')}
        </button>
        {!props.hideCancel && (
          <button type="button" className="btn btn-secondary dialog-btn" onClick={props.onCancel}>
            <X size={14} className="btn-icon" />
            {props.cancelText || t('txt_no')}
          </button>
        )}
        {props.afterActions}
      </form>
    </div>
  );
}
