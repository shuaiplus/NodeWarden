import { useEffect, useRef, useState } from 'preact/hooks';
import { t } from '@/lib/i18n';

interface BackupIncludeAttachmentsFieldProps {
  checked: boolean;
  disabled?: boolean;
  showHelp?: boolean;
  showLabel?: boolean;
  onChange: (checked: boolean) => void;
}

export function BackupIncludeAttachmentsField(props: BackupIncludeAttachmentsFieldProps) {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;

    function handlePointerDown(event: PointerEvent) {
      if (!wrapRef.current?.contains(event.target as Node)) {
        setOpen(false);
      }
    }

    document.addEventListener('pointerdown', handlePointerDown);
    return () => document.removeEventListener('pointerdown', handlePointerDown);
  }, [open]);

  return (
    <div className="backup-option-field">
      <label className="backup-option-label">
        <input
          type="checkbox"
          checked={props.checked}
          disabled={props.disabled}
          onInput={(event) => props.onChange((event.currentTarget as HTMLInputElement).checked)}
        />
        {props.showLabel !== false ? <span>{t('txt_backup_include_attachments')}</span> : null}
      </label>
      {props.showHelp !== false ? (
        <div ref={wrapRef} className={`backup-help-wrap ${open ? 'open' : ''}`}>
          <button
            type="button"
            className="backup-help-trigger"
            aria-label={t('txt_backup_include_attachments_help_button')}
            aria-expanded={open ? 'true' : 'false'}
            onClick={() => setOpen((current) => !current)}
          >
            ?
          </button>
          <div className="backup-help-bubble" role="tooltip">
            {t('txt_backup_include_attachments_help')}
          </div>
        </div>
      ) : null}
    </div>
  );
}
