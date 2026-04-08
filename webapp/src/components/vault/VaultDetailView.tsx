import { useState } from 'preact/hooks';
import { Archive, Clipboard, Download, Eye, EyeOff, ExternalLink, Paperclip, Pencil, RotateCcw, Trash2 } from 'lucide-preact';
import type { Cipher } from '@/lib/types';
import { t } from '@/lib/i18n';
import {
  TOTP_PERIOD_SECONDS,
  TOTP_RING_CIRCUMFERENCE,
  copyToClipboard,
  formatAttachmentSize,
  formatHistoryTime,
  formatTotp,
  maskSecret,
  openUri,
  parseFieldType,
  toBooleanFieldValue,
} from '@/components/vault/vault-page-helpers';

interface VaultDetailViewProps {
  selectedCipher: Cipher;
  repromptApprovedCipherId: string | null;
  showPassword: boolean;
  totpLive: { code: string; remain: number } | null;
  hiddenFieldVisibleMap: Record<number, boolean>;
  folderName: (id: string | null | undefined) => string;
  downloadingAttachmentKey: string;
  attachmentDownloadPercent: number | null;
  onOpenReprompt: () => void;
  onToggleShowPassword: () => void;
  onToggleHiddenField: (index: number) => void;
  onDownloadAttachment: (cipher: Cipher, attachmentId: string) => void;
  onStartEdit: () => void;
  onDelete: (cipher: Cipher) => void;
  onArchive: (cipher: Cipher) => void | Promise<void>;
  onUnarchive: (cipher: Cipher) => void | Promise<void>;
}

export default function VaultDetailView(props: VaultDetailViewProps) {
  const selectedAttachments = Array.isArray(props.selectedCipher.attachments) ? props.selectedCipher.attachments : [];
  const [showSshPrivateKey, setShowSshPrivateKey] = useState(false);
  const isArchived = !!(props.selectedCipher.archivedDate || (props.selectedCipher as { archivedAt?: string | null }).archivedAt);
  const formatDownloadLabel = (attachmentId: string) => {
    const downloadKey = `${props.selectedCipher.id}:${attachmentId}`;
    if (props.downloadingAttachmentKey !== downloadKey) return t('txt_download');
    return props.attachmentDownloadPercent == null
      ? t('txt_downloading')
      : t('txt_downloading_percent', { percent: props.attachmentDownloadPercent });
  };

  return (
    <>
      {Number(props.selectedCipher.reprompt || 0) === 1 && props.repromptApprovedCipherId !== props.selectedCipher.id && (
        <div className="card">
          <h4>{t('txt_master_password_reprompt_2')}</h4>
          <div className="detail-sub">{t('txt_this_item_requires_master_password_every_time_before_viewing_details')}</div>
          <div className="actions" style={{ marginTop: '10px' }}>
            <button type="button" className="btn btn-primary" onClick={props.onOpenReprompt}>
              <Eye size={14} className="btn-icon" /> {t('txt_unlock_details')}
            </button>
          </div>
        </div>
      )}
      {(Number(props.selectedCipher.reprompt || 0) !== 1 || props.repromptApprovedCipherId === props.selectedCipher.id) && (
        <>
          <div className="card">
            <h3 className="detail-title">{props.selectedCipher.decName || t('txt_no_name')}</h3>
            <div className="detail-sub">{props.folderName(props.selectedCipher.folderId)}</div>
            {isArchived && <div className="list-badge" style={{ marginTop: '8px', width: 'fit-content' }}>{t('txt_archived')}</div>}
          </div>

          {props.selectedCipher.login && (
            <div className="card">
              <h4>{t('txt_login_credentials')}</h4>
              <div className="kv-row">
                <span className="kv-label">{t('txt_username')}</span>
                <div className="kv-main">
                  <strong className="value-ellipsis" title={props.selectedCipher.login.decUsername || ''}>{props.selectedCipher.login.decUsername || ''}</strong>
                </div>
                <div className="kv-actions">
                  <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(props.selectedCipher.login?.decUsername || '')}>
                    <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                  </button>
                </div>
              </div>
              <div className="kv-row">
                <span className="kv-label">{t('txt_password')}</span>
                <div className="kv-main">
                  <strong>{props.showPassword ? props.selectedCipher.login.decPassword || '' : maskSecret(props.selectedCipher.login.decPassword || '')}</strong>
                </div>
                <div className="kv-actions">
                  <button type="button" className="btn btn-secondary small" onClick={props.onToggleShowPassword}>
                    {props.showPassword ? <EyeOff size={14} className="btn-icon" /> : <Eye size={14} className="btn-icon" />}
                    {props.showPassword ? t('txt_hide') : t('txt_reveal')}
                  </button>
                  <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(props.selectedCipher.login?.decPassword || '')}>
                    <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                  </button>
                </div>
              </div>
              {!!props.selectedCipher.login.decTotp && (
                <div className="kv-row">
                  <span className="kv-label">{t('txt_totp')}</span>
                  <div className="kv-main">
                    <div className="totp-inline">
                      <strong>{props.totpLive ? formatTotp(props.totpLive.code) : t('txt_text_3')}</strong>
                      <div
                        className="totp-timer"
                        title={t('txt_refresh_in_seconds_s', { seconds: props.totpLive ? props.totpLive.remain : 0 })}
                        aria-label={t('txt_refresh_in_seconds_s', { seconds: props.totpLive ? props.totpLive.remain : 0 })}
                      >
                        <svg viewBox="0 0 36 36" className="totp-ring" role="presentation" aria-hidden="true">
                          <circle className="totp-ring-track" cx="18" cy="18" r="15.9155" />
                          <circle
                            className="totp-ring-progress"
                            cx="18"
                            cy="18"
                            r="15.9155"
                            style={{
                              strokeDasharray: `${TOTP_RING_CIRCUMFERENCE} ${TOTP_RING_CIRCUMFERENCE}`,
                              strokeDashoffset: String(
                                TOTP_RING_CIRCUMFERENCE -
                                  TOTP_RING_CIRCUMFERENCE *
                                    (Math.max(0, Math.min(TOTP_PERIOD_SECONDS, props.totpLive?.remain ?? 0)) / TOTP_PERIOD_SECONDS)
                              ),
                            }}
                          />
                        </svg>
                        <span className="totp-timer-value">{props.totpLive ? props.totpLive.remain : 0}</span>
                      </div>
                    </div>
                  </div>
                  <div className="kv-actions">
                    <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(props.totpLive?.code || '')}>
                      <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {(props.selectedCipher.login?.uris || []).length > 0 && (
            <div className="card">
              <h4>{t('txt_autofill_options')}</h4>
              {(props.selectedCipher.login?.uris || []).map((uri, index) => {
                const value = uri.decUri || uri.uri || '';
                if (!value.trim()) return null;
                return (
                  <div key={`view-uri-${index}`} className="kv-row">
                    <span className="kv-label">{t('txt_website')}</span>
                    <div className="kv-main">
                      <strong className="value-ellipsis" title={value}>{value}</strong>
                    </div>
                    <div className="kv-actions">
                      <button type="button" className="btn btn-secondary small" onClick={() => openUri(value)}>
                        <ExternalLink size={14} className="btn-icon" /> {t('txt_open')}
                      </button>
                      <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(value)}>
                        <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {props.selectedCipher.card && (
            <div className="card">
              <h4>{t('txt_card_details')}</h4>
              <div className="kv-line"><span>{t('txt_cardholder_name')}</span><strong>{props.selectedCipher.card.decCardholderName || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_number')}</span><strong>{props.selectedCipher.card.decNumber || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_brand')}</span><strong>{props.selectedCipher.card.decBrand || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_expiry')}</span><strong>{`${props.selectedCipher.card.decExpMonth || ''}/${props.selectedCipher.card.decExpYear || ''}`}</strong></div>
              <div className="kv-line"><span>{t('txt_security_code')}</span><strong>{props.selectedCipher.card.decCode || ''}</strong></div>
            </div>
          )}

          {props.selectedCipher.identity && (
            <div className="card">
              <h4>{t('txt_identity_details')}</h4>
              <div className="kv-line"><span>{t('txt_name')}</span><strong>{`${props.selectedCipher.identity.decFirstName || ''} ${props.selectedCipher.identity.decLastName || ''}`.trim()}</strong></div>
              <div className="kv-line"><span>{t('txt_username')}</span><strong>{props.selectedCipher.identity.decUsername || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_email')}</span><strong>{props.selectedCipher.identity.decEmail || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_phone')}</span><strong>{props.selectedCipher.identity.decPhone || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_company')}</span><strong>{props.selectedCipher.identity.decCompany || ''}</strong></div>
              <div className="kv-line"><span>{t('txt_address')}</span><strong>{[props.selectedCipher.identity.decAddress1, props.selectedCipher.identity.decAddress2, props.selectedCipher.identity.decAddress3, props.selectedCipher.identity.decCity, props.selectedCipher.identity.decState, props.selectedCipher.identity.decPostalCode, props.selectedCipher.identity.decCountry].filter(Boolean).join(', ')}</strong></div>
            </div>
          )}

          {props.selectedCipher.sshKey && (
            <div className="card">
              <h4>{t('txt_ssh_key')}</h4>
              <div className="kv-row">
                <span className="kv-label">{t('txt_private_key')}</span>
                <div className="kv-main">
                  <strong
                    className="value-ellipsis"
                    title={showSshPrivateKey ? props.selectedCipher.sshKey.decPrivateKey || '' : maskSecret(props.selectedCipher.sshKey.decPrivateKey || '')}
                  >
                    {showSshPrivateKey ? props.selectedCipher.sshKey.decPrivateKey || '' : maskSecret(props.selectedCipher.sshKey.decPrivateKey || '')}
                  </strong>
                </div>
                <div className="kv-actions">
                  <button type="button" className="btn btn-secondary small" onClick={() => setShowSshPrivateKey((value) => !value)}>
                    {showSshPrivateKey ? <EyeOff size={14} className="btn-icon" /> : <Eye size={14} className="btn-icon" />}
                    {showSshPrivateKey ? t('txt_hide') : t('txt_reveal')}
                  </button>
                  <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(props.selectedCipher.sshKey?.decPrivateKey || '')}>
                    <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                  </button>
                </div>
              </div>
              <div className="kv-row">
                <span className="kv-label">{t('txt_public_key')}</span>
                <div className="kv-main">
                  <strong className="value-ellipsis" title={props.selectedCipher.sshKey.decPublicKey || ''}>
                    {props.selectedCipher.sshKey.decPublicKey || ''}
                  </strong>
                </div>
                <div className="kv-actions">
                  <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(props.selectedCipher.sshKey?.decPublicKey || '')}>
                    <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                  </button>
                </div>
              </div>
              <div className="kv-row">
                <span className="kv-label">{t('txt_fingerprint')}</span>
                <div className="kv-main">
                  <strong className="value-ellipsis" title={props.selectedCipher.sshKey.decFingerprint || ''}>
                    {props.selectedCipher.sshKey.decFingerprint || ''}
                  </strong>
                </div>
                <div className="kv-actions">
                  <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(props.selectedCipher.sshKey?.decFingerprint || '')}>
                    <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                  </button>
                </div>
              </div>
            </div>
          )}

          {!!(props.selectedCipher.decNotes || '').trim() && (
            <div className="card">
              <h4>{t('txt_notes')}</h4>
              <div className="notes">{props.selectedCipher.decNotes || ''}</div>
            </div>
          )}

          {(props.selectedCipher.fields || []).some((x) => parseFieldType(x.type) !== 3) && (
            <div className="card">
              <h4>{t('txt_custom_fields')}</h4>
              {(props.selectedCipher.fields || [])
                .filter((x) => parseFieldType(x.type) !== 3)
                .map((field, index) => {
                  const fieldType = parseFieldType(field.type);
                  const fieldName = field.decName || t('txt_field');
                  const rawValue = field.decValue || '';
                  const isHiddenVisible = !!props.hiddenFieldVisibleMap[index];
                  if (fieldType === 2) {
                    const checked = toBooleanFieldValue(rawValue);
                    return (
                      <div key={`view-field-${index}`} className="custom-field-card">
                        <div className="custom-field-label">{fieldName}</div>
                        <div className="custom-field-body">
                          <div className="custom-field-value">
                            <label className="check-line cf-check view custom-field-check">
                              <input type="checkbox" checked={checked} disabled />
                              <span className="boolean-text value-ellipsis" title={checked ? t('txt_checked') : t('txt_unchecked')}>
                                {checked ? t('txt_checked') : t('txt_unchecked')}
                              </span>
                            </label>
                          </div>
                          <div className="kv-actions">
                            <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(rawValue)}>
                              <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                            </button>
                          </div>
                        </div>
                      </div>
                    );
                  }
                  return (
                    <div key={`view-field-${index}`} className="custom-field-card">
                      <div className="custom-field-label" title={fieldName}>{fieldName}</div>
                      <div className="custom-field-body">
                        <div className="custom-field-value">
                          <strong className="value-ellipsis" title={fieldType === 1 && !isHiddenVisible ? '' : rawValue}>
                            {fieldType === 1 && !isHiddenVisible ? maskSecret(rawValue) : rawValue}
                          </strong>
                        </div>
                        <div className="kv-actions">
                        {fieldType === 1 && (
                          <button type="button" className="btn btn-secondary small" onClick={() => props.onToggleHiddenField(index)}>
                            {isHiddenVisible ? <EyeOff size={14} className="btn-icon" /> : <Eye size={14} className="btn-icon" />}
                            {isHiddenVisible ? t('txt_hide') : t('txt_reveal')}
                          </button>
                        )}
                        <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(rawValue)}>
                          <Clipboard size={14} className="btn-icon" /> {t('txt_copy')}
                        </button>
                        </div>
                      </div>
                    </div>
                  );
                })}
            </div>
          )}

          {selectedAttachments.some((attachment) => String(attachment?.id || '').trim()) && (
            <div className="card">
              <h4>{t('txt_attachments')}</h4>
              <div className="attachment-list">
                {selectedAttachments.map((attachment) => {
                  const attachmentId = String(attachment?.id || '').trim();
                  if (!attachmentId) return null;
                  const fileName = String(attachment.decFileName || attachment.fileName || attachmentId).trim() || attachmentId;
                  return (
                    <div key={`view-attachment-${attachmentId}`} className="attachment-row">
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
                          disabled={props.downloadingAttachmentKey === `${props.selectedCipher.id}:${attachmentId}`}
                          onClick={() => props.onDownloadAttachment(props.selectedCipher, attachmentId)}
                        >
                          <Download size={14} className="btn-icon" /> {formatDownloadLabel(attachmentId)}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {(props.selectedCipher.creationDate || props.selectedCipher.revisionDate) && (
            <div className="card">
              <h4>{t('txt_item_history')}</h4>
              <div className="detail-sub">{t('txt_last_edited_value', { value: formatHistoryTime(props.selectedCipher.revisionDate) })}</div>
              <div className="detail-sub">{t('txt_created_value', { value: formatHistoryTime(props.selectedCipher.creationDate) })}</div>
            </div>
          )}

          <div className="detail-actions">
            <div className="actions">
              <button type="button" className="btn btn-secondary" onClick={props.onStartEdit}>
                <Pencil size={14} className="btn-icon" /> {t('txt_edit')}
              </button>
              {isArchived ? (
                <button type="button" className="btn btn-secondary" onClick={() => void props.onUnarchive(props.selectedCipher)}>
                  <RotateCcw size={14} className="btn-icon" /> {t('txt_unarchive')}
                </button>
              ) : (
                <button type="button" className="btn btn-secondary" onClick={() => void props.onArchive(props.selectedCipher)}>
                  <Archive size={14} className="btn-icon" /> {t('txt_archive')}
                </button>
              )}
            </div>
            <button type="button" className="btn btn-danger" onClick={() => props.onDelete(props.selectedCipher)}>
              <Trash2 size={14} className="btn-icon" /> {t('txt_delete')}
            </button>
          </div>
        </>
      )}
    </>
  );
}
