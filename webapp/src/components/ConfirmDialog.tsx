import { useEffect, useState } from 'preact/hooks';
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
  hideCancel?: boolean;
  confirmDisabled?: boolean;
  cancelDisabled?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  children?: ComponentChildren;
  afterActions?: ComponentChildren;
}

export default function ConfirmDialog(props: ConfirmDialogProps) {
  const [present, setPresent] = useState(props.open);
  const [closing, setClosing] = useState(false);

  useEffect(() => {
    if (props.open) {
      setPresent(true);
      setClosing(false);
      return;
    }
    if (!present) return;
    setClosing(true);
    const timer = window.setTimeout(() => {
      setPresent(false);
      setClosing(false);
    }, 240);
    return () => window.clearTimeout(timer);
  }, [props.open, present]);

  if (!present) return null;
  return (
    <div className={`dialog-mask ${props.open && !closing ? 'open' : ''} ${closing ? 'closing' : ''}`}>
      <form
        className={`dialog-card ${props.open && !closing ? 'open' : ''} ${closing ? 'closing' : ''}`}
        onSubmit={(e) => {
          e.preventDefault();
          if (props.confirmDisabled || closing) return;
          props.onConfirm();
        }}
      >
        <h3 className="dialog-title">{props.title}</h3>
        <div className="dialog-message">{props.message}</div>
        {props.children}
        <button
          type="submit"
          className={`btn ${props.danger ? 'btn-danger' : 'btn-primary'} dialog-btn`}
          disabled={props.confirmDisabled}
        >
          {props.confirmText || t('txt_yes')}
        </button>
        {!props.hideCancel && (
          <button
            type="button"
            className="btn btn-secondary dialog-btn"
            disabled={props.cancelDisabled}
            onClick={() => {
              if (props.cancelDisabled) return;
              props.onCancel();
            }}
          >
            {props.cancelText || t('txt_no')}
          </button>
        )}
        {props.afterActions}
      </form>
    </div>
  );
}
