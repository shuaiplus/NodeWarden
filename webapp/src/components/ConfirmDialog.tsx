import { createPortal } from 'preact/compat';
import { useEffect, useState } from 'preact/hooks';
import type { ComponentChildren } from 'preact';
import { TriangleAlert } from 'lucide-preact';
import { t } from '@/lib/i18n';

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  message: string;
  variant?: 'default' | 'warning';
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

function incrementDialogBodyLock() {
  if (typeof document === 'undefined') return;
  const body = document.body;
  const nextCount = Number(body.dataset.dialogCount || '0') + 1;
  body.dataset.dialogCount = String(nextCount);
  body.classList.add('dialog-open');
}

function decrementDialogBodyLock() {
  if (typeof document === 'undefined') return;
  const body = document.body;
  const nextCount = Math.max(0, Number(body.dataset.dialogCount || '0') - 1);
  if (nextCount === 0) {
    delete body.dataset.dialogCount;
    body.classList.remove('dialog-open');
    return;
  }
  body.dataset.dialogCount = String(nextCount);
}

export function useDialogLifecycle(active: boolean, onCancel?: (() => void) | null) {
  useEffect(() => {
    if (!active) return;
    incrementDialogBodyLock();
    return () => decrementDialogBodyLock();
  }, [active]);

  useEffect(() => {
    if (!active || !onCancel || typeof window === 'undefined') return;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      onCancel();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [active, onCancel]);
}

export default function ConfirmDialog(props: ConfirmDialogProps) {
  const [present, setPresent] = useState(props.open);
  const [closing, setClosing] = useState(false);
  const canDismiss = !props.cancelDisabled && !closing && !props.hideCancel;

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

  useDialogLifecycle(present, canDismiss ? props.onCancel : null);

  if (!present || typeof document === 'undefined') return null;
  return createPortal((
    <div
      className={`dialog-mask ${props.variant === 'warning' ? 'warning' : ''} ${props.open && !closing ? 'open' : ''} ${closing ? 'closing' : ''}`}
      onClick={(event) => {
        if (event.target !== event.currentTarget || !canDismiss) return;
        props.onCancel();
      }}
    >
      <form
        className={`dialog-card ${props.variant === 'warning' ? 'warning' : ''} ${props.open && !closing ? 'open' : ''} ${closing ? 'closing' : ''}`}
        role="dialog"
        aria-modal="true"
        aria-label={props.title}
        onSubmit={(e) => {
          e.preventDefault();
          if (props.confirmDisabled || closing) return;
          props.onConfirm();
        }}
      >
        {props.variant === 'warning' ? (
          <>
            <div className="dialog-warning-strip" aria-hidden="true" />
            <div className="dialog-warning-head">
              <div className="dialog-warning-badge" aria-hidden="true">
                <TriangleAlert size={24} />
              </div>
              <div className="dialog-warning-kicker">{t('txt_warning')}</div>
            </div>
          </>
        ) : null}
        <h3 className="dialog-title">{props.title}</h3>
        <div className={`dialog-message ${props.variant === 'warning' ? 'warning' : ''}`}>{props.message}</div>
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
  ), document.body);
}
