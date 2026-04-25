import type { JSX, RefObject } from 'preact';
import { CheckCheck, Download, GripVertical, Paperclip, Plus, RefreshCw, Star, StarOff, Trash2, Upload, X } from 'lucide-preact';
import { useEffect, useRef, useState } from 'preact/hooks';
import {
  closestCenter,
  DndContext,
  type DragEndEvent,
  type DragStartEvent,
  PointerSensor,
  TouchSensor,
  useSensor,
  useSensors,
} from '@dnd-kit/core';
import {
  SortableContext,
  arrayMove,
  useSortable,
  verticalListSortingStrategy,
} from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import type { Cipher, Folder, VaultDraft, VaultDraftField } from '@/lib/types';
import { t } from '@/lib/i18n';
import {
  CREATE_TYPE_OPTIONS,
  cipherTypeLabel,
  createEmptyLoginUri,
  formatAttachmentSize,
  formatHistoryTime,
  toBooleanFieldValue,
  WEBSITE_MATCH_OPTIONS,
} from '@/components/vault/vault-page-helpers';

interface VaultEditorProps {
  draft: VaultDraft;
  isCreating: boolean;
  busy: boolean;
  folders: Folder[];
  selectedCipher: Cipher | null;
  editExistingAttachments: Array<any>;
  removedAttachmentIds: Record<string, boolean>;
  removedAttachmentCount: number;
  attachmentQueue: File[];
  attachmentInputRef: RefObject<HTMLInputElement>;
  localError: string;
  downloadingAttachmentKey: string;
  attachmentDownloadPercent: number | null;
  uploadingAttachmentName: string;
  attachmentUploadPercent: number | null;
  onUpdateDraft: (patch: Partial<VaultDraft>) => void;
  onSeedSshDefaults: (force?: boolean) => void;
  onUpdateSshPublicKey: (value: string) => void;
  onUpdateDraftLoginUri: (index: number, value: string) => void;
  onUpdateDraftLoginUriMatch: (index: number, value: number | null) => void;
  onReorderDraftLoginUri: (fromIndex: number, toIndex: number) => void;
  onRequestDeleteLoginPasskey: (index: number) => void;
  onQueueAttachmentFiles: (list: FileList | null) => void;
  onToggleExistingAttachmentRemoval: (attachmentId: string) => void;
  onRemoveQueuedAttachment: (index: number) => void;
  onDownloadAttachment: (cipher: Cipher, attachmentId: string) => void;
  onPatchDraftCustomField: (index: number, patch: Partial<VaultDraftField>) => void;
  onUpdateDraftCustomFields: (fields: VaultDraftField[]) => void;
  onOpenFieldModal: () => void;
  onSave: () => void;
  onCancel: () => void;
  onDeleteSelected: () => void;
}

interface SortableWebsiteRowProps {
  id: string;
  uriEntry: VaultDraft['loginUris'][number];
  index: number;
  canRemove: boolean;
  isDragging: boolean;
  onUpdateUri: (index: number, value: string) => void;
  onUpdateMatch: (index: number, value: number | null) => void;
  onRemove: (index: number) => void;
}

function SortableWebsiteRow(props: SortableWebsiteRowProps) {
  const { attributes, listeners, setActivatorNodeRef, setNodeRef, transform, transition, isDragging } = useSortable({
    id: props.id,
  });
  const dragButtonAttributes = attributes as JSX.HTMLAttributes<HTMLButtonElement>;

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
  };

  return (
    <div
      ref={setNodeRef}
      style={style}
      className={`website-row${isDragging || props.isDragging ? ' is-dragging' : ''}`}
    >
      <button
        type="button"
        ref={setActivatorNodeRef}
        className="btn btn-secondary small website-drag-btn"
        title={t('txt_drag_to_reorder')}
        aria-label={t('txt_drag_to_reorder')}
        {...dragButtonAttributes}
        {...listeners}
      >
        <GripVertical size={14} className="btn-icon" />
      </button>
      <input
        className="input"
        value={props.uriEntry.uri}
        onInput={(e) => props.onUpdateUri(props.index, (e.currentTarget as HTMLInputElement).value)}
      />
      <select
        className="input website-match-select"
        value={props.uriEntry.match == null ? '' : String(props.uriEntry.match)}
        onInput={(e) => {
          const raw = (e.currentTarget as HTMLSelectElement).value;
          props.onUpdateMatch(props.index, raw === '' ? null : Number(raw));
        }}
      >
        {WEBSITE_MATCH_OPTIONS.map((option) => (
          <option key={`website-match-${String(option.value)}`} value={option.value == null ? '' : String(option.value)}>
            {option.label}
          </option>
        ))}
      </select>
      {props.canRemove && (
        <button type="button" className="btn btn-secondary small" onClick={() => props.onRemove(props.index)}>
          <X size={14} className="btn-icon" />
          {t('txt_remove')}
        </button>
      )}
    </div>
  );
}

export default function VaultEditor(props: VaultEditorProps) {
  const uriIdSeedRef = useRef(0);
  const [uriItemIds, setUriItemIds] = useState<string[]>([]);
  const [activeUriId, setActiveUriId] = useState<string | null>(null);
  const sensors = useSensors(
    useSensor(PointerSensor, {
      activationConstraint: {
        distance: 6,
      },
    }),
    useSensor(TouchSensor, {
      activationConstraint: {
        delay: 120,
        tolerance: 8,
      },
    }),
  );

  const createUriId = () => `login-uri-${uriIdSeedRef.current++}`;

  useEffect(() => {
    setUriItemIds((prev) => {
      if (prev.length === props.draft.loginUris.length) return prev;
      if (prev.length < props.draft.loginUris.length) {
        return [...prev, ...Array.from({ length: props.draft.loginUris.length - prev.length }, () => createUriId())];
      }
      return prev.slice(0, props.draft.loginUris.length);
    });
  }, [props.draft.loginUris.length]);

  useEffect(() => {
    setUriItemIds(props.draft.loginUris.map(() => createUriId()));
    setActiveUriId(null);
  }, [props.draft.id, props.isCreating]);

  const formatDownloadLabel = (attachmentId: string) => {
    const downloadKey = `${props.selectedCipher?.id || ''}:${attachmentId}`;
    if (props.downloadingAttachmentKey !== downloadKey) return t('txt_download');
    return props.attachmentDownloadPercent == null
      ? t('txt_downloading')
      : t('txt_downloading_percent', { percent: props.attachmentDownloadPercent });
  };
  const uploadLabel =
    props.attachmentUploadPercent == null
      ? t('txt_uploading_attachment_named', { name: props.uploadingAttachmentName || t('txt_attachment') })
      : t('txt_uploading_attachment_named_percent', {
          name: props.uploadingAttachmentName || t('txt_attachment'),
          percent: props.attachmentUploadPercent,
        });

  const addLoginUri = () => {
    setUriItemIds((prev) => [...prev, createUriId()]);
    props.onUpdateDraft({ loginUris: [...props.draft.loginUris, createEmptyLoginUri()] });
  };

  const removeLoginUri = (index: number) => {
    setUriItemIds((prev) => prev.filter((_, itemIndex) => itemIndex !== index));
    props.onUpdateDraft({ loginUris: props.draft.loginUris.filter((_, itemIndex) => itemIndex !== index) });
  };

  const handleWebsiteDragStart = (event: DragStartEvent) => {
    setActiveUriId(String(event.active.id));
  };

  const handleWebsiteDragEnd = (event: DragEndEvent) => {
    const activeId = String(event.active.id);
    const overId = event.over ? String(event.over.id) : null;
    setActiveUriId(null);
    if (!overId || activeId === overId) return;
    const fromIndex = uriItemIds.indexOf(activeId);
    const toIndex = uriItemIds.indexOf(overId);
    if (fromIndex === -1 || toIndex === -1 || fromIndex === toIndex) return;
    setUriItemIds((prev) => arrayMove(prev, fromIndex, toIndex));
    props.onReorderDraftLoginUri(fromIndex, toIndex);
  };

  return (
    <>
      <div className="card">
        <div className="section-head">
          <h3 className="detail-title">{props.isCreating ? t('txt_new_type_header', { type: cipherTypeLabel(props.draft.type) }) : t('txt_edit_type_header', { type: cipherTypeLabel(props.draft.type) })}</h3>
          <button type="button" className={`btn btn-secondary small ${props.draft.favorite ? 'star-on' : ''}`} onClick={() => props.onUpdateDraft({ favorite: !props.draft.favorite })}>
            {props.draft.favorite ? <Star size={14} className="btn-icon" /> : <StarOff size={14} className="btn-icon" />}
            {t('txt_favorite')}
          </button>
        </div>
        <div className="field-grid">
          <label className="field">
            <span>{t('txt_type')}</span>
            <select
              className="input"
              value={props.draft.type}
              disabled={!props.isCreating}
              onInput={(e) => {
                const nextType = Number((e.currentTarget as HTMLSelectElement).value);
                props.onUpdateDraft({ type: nextType });
                if (nextType === 5) props.onSeedSshDefaults();
              }}
            >
              {CREATE_TYPE_OPTIONS.map((option) => (
                <option key={option.type} value={option.type}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>{t('txt_folder')}</span>
            <select className="input" value={props.draft.folderId} onInput={(e) => props.onUpdateDraft({ folderId: (e.currentTarget as HTMLSelectElement).value })}>
              <option value="">{t('txt_no_folder')}</option>
              {props.folders.map((folder) => (
                <option key={folder.id} value={folder.id}>
                  {folder.decName || folder.name || folder.id}
                </option>
              ))}
            </select>
          </label>
        </div>
        <label className="field">
          <span>{t('txt_name')}</span>
          <input className="input" value={props.draft.name} onInput={(e) => props.onUpdateDraft({ name: (e.currentTarget as HTMLInputElement).value })} />
        </label>
      </div>

      {props.draft.type === 1 && (
        <div className="card">
          <h4>{t('txt_login_credentials')}</h4>
          <div className="field-grid">
            <label className="field">
              <span>{t('txt_username')}</span>
              <input className="input" value={props.draft.loginUsername} onInput={(e) => props.onUpdateDraft({ loginUsername: (e.currentTarget as HTMLInputElement).value })} />
            </label>
            <label className="field">
              <span>{t('txt_password')}</span>
              <input className="input" value={props.draft.loginPassword} onInput={(e) => props.onUpdateDraft({ loginPassword: (e.currentTarget as HTMLInputElement).value })} />
            </label>
          </div>
          <label className="field">
            <span>{t('txt_totp_secret')}</span>
            <input className="input" value={props.draft.loginTotp} onInput={(e) => props.onUpdateDraft({ loginTotp: (e.currentTarget as HTMLInputElement).value })} />
          </label>
          <div className="section-head">
            <h4>{t('txt_websites')}</h4>
            <button type="button" className="btn btn-secondary small" onClick={addLoginUri}>
              <Plus size={14} className="btn-icon" /> {t('txt_add_website')}
            </button>
          </div>
          <DndContext sensors={sensors} collisionDetection={closestCenter} onDragStart={handleWebsiteDragStart} onDragEnd={handleWebsiteDragEnd}>
            <SortableContext items={uriItemIds} strategy={verticalListSortingStrategy}>
              {props.draft.loginUris.map((uriEntry, index) => (
                <SortableWebsiteRow
                  key={uriItemIds[index] ?? `uri-${index}`}
                  id={uriItemIds[index] ?? `uri-fallback-${index}`}
                  uriEntry={uriEntry}
                  index={index}
                  canRemove={props.draft.loginUris.length > 1}
                  isDragging={activeUriId === uriItemIds[index]}
                  onUpdateUri={props.onUpdateDraftLoginUri}
                  onUpdateMatch={props.onUpdateDraftLoginUriMatch}
                  onRemove={removeLoginUri}
                />
              ))}
            </SortableContext>
          </DndContext>
          {props.draft.loginFido2Credentials.length > 0 && (
            <>
              <div className="section-head passkeys-section-head">
                <h4>{t('txt_passkeys')}</h4>
              </div>
              <div className="attachment-list">
                {props.draft.loginFido2Credentials.map((credential, index) => {
                  const createdAt = String(credential?.creationDate || '').trim();
                  const label = createdAt
                    ? t('txt_passkey_created_at_value', { value: formatHistoryTime(createdAt) })
                    : t('txt_passkey');
                  return (
                    <div key={`login-passkey-${index}`} className="attachment-row">
                      <div className="attachment-main">
                        <div className="attachment-text">
                          <strong>{t('txt_passkey')}</strong>
                          <span>{label}</span>
                        </div>
                      </div>
                      <div className="kv-actions">
                        <button
                          type="button"
                          className="btn btn-secondary small"
                          disabled={props.busy}
                          onClick={() => props.onRequestDeleteLoginPasskey(index)}
                        >
                          <X size={14} className="btn-icon" />
                          {t('txt_remove')}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </div>
      )}

      {props.draft.type === 3 && (
        <div className="card">
          <h4>{t('txt_card_details')}</h4>
          <div className="field-grid">
            <label className="field"><span>{t('txt_cardholder_name')}</span><input className="input" value={props.draft.cardholderName} onInput={(e) => props.onUpdateDraft({ cardholderName: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_number')}</span><input className="input" value={props.draft.cardNumber} onInput={(e) => props.onUpdateDraft({ cardNumber: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_brand')}</span><input className="input" value={props.draft.cardBrand} onInput={(e) => props.onUpdateDraft({ cardBrand: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_security_code_cvv')}</span><input className="input" value={props.draft.cardCode} onInput={(e) => props.onUpdateDraft({ cardCode: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_expiry_month')}</span><input className="input" value={props.draft.cardExpMonth} onInput={(e) => props.onUpdateDraft({ cardExpMonth: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_expiry_year')}</span><input className="input" value={props.draft.cardExpYear} onInput={(e) => props.onUpdateDraft({ cardExpYear: (e.currentTarget as HTMLInputElement).value })} /></label>
          </div>
        </div>
      )}

      {props.draft.type === 4 && (
        <div className="card">
          <h4>{t('txt_identity_details')}</h4>
          <div className="field-grid">
            <label className="field"><span>{t('txt_title')}</span><input className="input" value={props.draft.identTitle} onInput={(e) => props.onUpdateDraft({ identTitle: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_first_name')}</span><input className="input" value={props.draft.identFirstName} onInput={(e) => props.onUpdateDraft({ identFirstName: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_middle_name')}</span><input className="input" value={props.draft.identMiddleName} onInput={(e) => props.onUpdateDraft({ identMiddleName: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_last_name')}</span><input className="input" value={props.draft.identLastName} onInput={(e) => props.onUpdateDraft({ identLastName: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_username')}</span><input className="input" value={props.draft.identUsername} onInput={(e) => props.onUpdateDraft({ identUsername: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_company')}</span><input className="input" value={props.draft.identCompany} onInput={(e) => props.onUpdateDraft({ identCompany: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_ssn')}</span><input className="input" value={props.draft.identSsn} onInput={(e) => props.onUpdateDraft({ identSsn: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_passport_number')}</span><input className="input" value={props.draft.identPassportNumber} onInput={(e) => props.onUpdateDraft({ identPassportNumber: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_license_number')}</span><input className="input" value={props.draft.identLicenseNumber} onInput={(e) => props.onUpdateDraft({ identLicenseNumber: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_email')}</span><input className="input" value={props.draft.identEmail} onInput={(e) => props.onUpdateDraft({ identEmail: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_phone')}</span><input className="input" value={props.draft.identPhone} onInput={(e) => props.onUpdateDraft({ identPhone: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_address_1')}</span><input className="input" value={props.draft.identAddress1} onInput={(e) => props.onUpdateDraft({ identAddress1: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_address_2')}</span><input className="input" value={props.draft.identAddress2} onInput={(e) => props.onUpdateDraft({ identAddress2: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_address_3')}</span><input className="input" value={props.draft.identAddress3} onInput={(e) => props.onUpdateDraft({ identAddress3: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_city_town')}</span><input className="input" value={props.draft.identCity} onInput={(e) => props.onUpdateDraft({ identCity: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_state_province')}</span><input className="input" value={props.draft.identState} onInput={(e) => props.onUpdateDraft({ identState: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_postal_code')}</span><input className="input" value={props.draft.identPostalCode} onInput={(e) => props.onUpdateDraft({ identPostalCode: (e.currentTarget as HTMLInputElement).value })} /></label>
            <label className="field"><span>{t('txt_country')}</span><input className="input" value={props.draft.identCountry} onInput={(e) => props.onUpdateDraft({ identCountry: (e.currentTarget as HTMLInputElement).value })} /></label>
          </div>
        </div>
      )}

      {props.draft.type === 5 && (
        <div className="card">
          <div className="section-head">
            <h4>{t('txt_ssh_key')}</h4>
            <button
              type="button"
              className="btn btn-secondary small"
              disabled={!props.isCreating}
              onClick={() => props.onSeedSshDefaults(true)}
            >
              <RefreshCw size={14} className="btn-icon" /> {t('txt_regenerate')}
            </button>
          </div>
          <label className="field">
            <span>{t('txt_private_key')}</span>
            <textarea
              className="input textarea"
              value={props.draft.sshPrivateKey}
              disabled={!props.isCreating}
              onInput={(e) => props.onUpdateDraft({ sshPrivateKey: (e.currentTarget as HTMLTextAreaElement).value })}
            />
          </label>
          <label className="field">
            <span>{t('txt_public_key')}</span>
            <textarea
              className="input textarea"
              value={props.draft.sshPublicKey}
              disabled={!props.isCreating}
              onInput={(e) => props.onUpdateSshPublicKey((e.currentTarget as HTMLTextAreaElement).value)}
            />
          </label>
          <label className="field">
            <span>{t('txt_fingerprint')}</span>
            <input className="input input-readonly" value={props.draft.sshFingerprint} readOnly />
          </label>
        </div>
      )}

      <div className="card">
        <div className="section-head attachment-head">
          <h4>{t('txt_attachments')}</h4>
          <button
            type="button"
            className="btn btn-secondary small attachment-add-btn"
            disabled={props.busy}
            onClick={() => props.attachmentInputRef.current?.click()}
            title={t('txt_upload_attachments')}
            aria-label={t('txt_upload_attachments')}
          >
            <Plus size={14} className="btn-icon" />
          </button>
        </div>
        {!!props.uploadingAttachmentName && <div className="detail-sub">{uploadLabel}</div>}
        {!props.isCreating && props.selectedCipher && props.editExistingAttachments.length > 0 && (
          <div className="attachment-list">
            {props.editExistingAttachments.map((attachment) => {
              const attachmentId = String(attachment?.id || '').trim();
              if (!attachmentId) return null;
              const removed = !!props.removedAttachmentIds[attachmentId];
              const fileName = String(attachment.decFileName || attachment.fileName || attachmentId).trim() || attachmentId;
              return (
                <div key={`edit-attachment-${attachmentId}`} className={`attachment-row ${removed ? 'is-removed' : ''}`}>
                  <div className="attachment-main">
                    <Paperclip size={14} />
                    <div className="attachment-text">
                      <strong className="value-ellipsis" title={fileName}>{fileName}</strong>
                      <span>{formatAttachmentSize(attachment)}</span>
                    </div>
                  </div>
                  <div className="kv-actions">
                    <button
                      type="button"
                      className="btn btn-secondary small"
                      disabled={props.busy || removed || props.downloadingAttachmentKey === `${props.selectedCipher?.id || ''}:${attachmentId}`}
                      onClick={() => props.onDownloadAttachment(props.selectedCipher as Cipher, attachmentId)}
                    >
                      <Download size={14} className="btn-icon" /> {formatDownloadLabel(attachmentId)}
                    </button>
                    <button type="button" className="btn btn-secondary small" disabled={props.busy} onClick={() => props.onToggleExistingAttachmentRemoval(attachmentId)}>
                      <X size={14} className="btn-icon" />
                      {removed ? t('txt_cancel') : t('txt_remove')}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
        {!!props.removedAttachmentCount && <div className="detail-sub">{t('txt_marked_for_removal_count', { count: props.removedAttachmentCount })}</div>}
        <input
          ref={props.attachmentInputRef}
          type="file"
          className="attachment-file-input"
          multiple
          disabled={props.busy}
          onChange={(e) => {
            const input = e.currentTarget as HTMLInputElement;
            props.onQueueAttachmentFiles(input.files);
            input.value = '';
          }}
        />
        {!!props.attachmentQueue.length && (
          <div className="attachment-list">
            <div className="attachment-queue-title">{t('txt_new_attachments')}</div>
            {props.attachmentQueue.map((file, index) => (
              <div key={`queued-attachment-${index}-${file.name}`} className="attachment-row">
                <div className="attachment-main">
                  <Upload size={14} />
                  <div className="attachment-text">
                    <strong className="value-ellipsis" title={file.name}>{file.name}</strong>
                    <span>{formatAttachmentSize({ size: file.size })}</span>
                  </div>
                </div>
                <div className="kv-actions">
                  <button type="button" className="btn btn-secondary small" disabled={props.busy} onClick={() => props.onRemoveQueuedAttachment(index)}>
                    <X size={14} className="btn-icon" />
                    {t('txt_remove')}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="card">
        <h4>{t('txt_additional_options')}</h4>
        <label className="field">
          <span>{t('txt_notes')}</span>
          <textarea className="input textarea" value={props.draft.notes} onInput={(e) => props.onUpdateDraft({ notes: (e.currentTarget as HTMLTextAreaElement).value })} />
        </label>
        <label className="check-line">
          <input type="checkbox" checked={props.draft.reprompt} onInput={(e) => props.onUpdateDraft({ reprompt: (e.currentTarget as HTMLInputElement).checked })} />
          {t('txt_master_password_reprompt')}
        </label>
        <div className="section-head">
          <h4>{t('txt_custom_fields')}</h4>
          <button type="button" className="btn btn-secondary small" onClick={props.onOpenFieldModal}>
            <Plus size={14} className="btn-icon" /> {t('txt_add_field')}
          </button>
        </div>
        {props.draft.customFields
          .map((field, originalIndex) => ({ field, originalIndex }))
          .filter((entry) => entry.field.type !== 3)
          .map(({ field, originalIndex }) => (
            <div key={`field-${originalIndex}`} className="custom-field-card">
              <label className="field custom-field-label">
                <span>{t('txt_field_label')}</span>
                <input className="input" value={field.label} onInput={(e) => props.onPatchDraftCustomField(originalIndex, { label: (e.currentTarget as HTMLInputElement).value })} />
              </label>
              <div className="custom-field-body">
                <div className="custom-field-value">
                  {field.type === 2 ? (
                    <label className="check-line cf-check custom-field-check">
                      <input
                        type="checkbox"
                        checked={toBooleanFieldValue(field.value)}
                        onInput={(e) => props.onPatchDraftCustomField(originalIndex, { value: (e.currentTarget as HTMLInputElement).checked ? 'true' : 'false' })}
                      />
                      <span>{toBooleanFieldValue(field.value) ? t('txt_checked') : t('txt_unchecked')}</span>
                    </label>
                  ) : (
                    <input className="input" value={field.value} onInput={(e) => props.onPatchDraftCustomField(originalIndex, { value: (e.currentTarget as HTMLInputElement).value })} />
                  )}
                </div>
                <button type="button" className="btn btn-secondary small custom-field-remove" onClick={() => props.onUpdateDraftCustomFields(props.draft.customFields.filter((_, i) => i !== originalIndex))}>
                  <X size={14} className="btn-icon" />
                  {t('txt_remove')}
                </button>
              </div>
            </div>
          ))}
      </div>

      <div className="detail-actions">
        <div className="actions">
          <button type="button" className="btn btn-primary" disabled={props.busy} onClick={props.onSave}>
            <CheckCheck size={14} className="btn-icon" />
            {t('txt_confirm')}
          </button>
          <button type="button" className="btn btn-secondary" disabled={props.busy} onClick={props.onCancel}>
            <X size={14} className="btn-icon" />
            {t('txt_cancel')}
          </button>
        </div>
        {!props.isCreating && props.selectedCipher && (
          <button type="button" className="btn btn-danger" disabled={props.busy} onClick={props.onDeleteSelected}>
            <Trash2 size={14} className="btn-icon" />
            {t('txt_delete')}
          </button>
        )}
      </div>
      {props.localError && <div className="local-error">{props.localError}</div>}
    </>
  );
}
