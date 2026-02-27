import { useEffect, useMemo, useState } from 'preact/hooks';
import ConfirmDialog from '@/components/ConfirmDialog';
import { calcTotpNow } from '@/lib/crypto';
import type { Cipher, CustomFieldType, Folder, VaultDraft, VaultDraftField } from '@/lib/types';

interface VaultPageProps {
  ciphers: Cipher[];
  folders: Folder[];
  loading: boolean;
  onRefresh: () => Promise<void>;
  onCreate: (draft: VaultDraft) => Promise<void>;
  onUpdate: (cipher: Cipher, draft: VaultDraft) => Promise<void>;
  onDelete: (cipher: Cipher) => Promise<void>;
  onBulkDelete: (ids: string[]) => Promise<void>;
  onBulkMove: (ids: string[], folderId: string | null) => Promise<void>;
}

type TypeFilter = 'all' | 'favorite' | 'login' | 'card' | 'identity' | 'note' | 'ssh';

interface TypeOption {
  type: number;
  label: string;
}

const CREATE_TYPE_OPTIONS: TypeOption[] = [
  { type: 1, label: 'Login' },
  { type: 3, label: 'Card' },
  { type: 4, label: 'Identity' },
  { type: 2, label: 'Note' },
  { type: 5, label: 'SSH Key' },
];

const FIELD_TYPE_OPTIONS: Array<{ value: CustomFieldType; label: string }> = [
  { value: 0, label: 'Text' },
  { value: 1, label: 'Hidden' },
  { value: 2, label: 'Boolean' },
  { value: 3, label: 'Linked' },
];

function cipherTypeKey(type: number): TypeFilter {
  if (type === 1) return 'login';
  if (type === 3) return 'card';
  if (type === 4) return 'identity';
  if (type === 2) return 'note';
  return 'ssh';
}

function cipherTypeLabel(type: number): string {
  if (type === 1) return 'Login';
  if (type === 3) return 'Card';
  if (type === 4) return 'Identity';
  if (type === 2) return 'Secure Note';
  if (type === 5) return 'SSH Key';
  return 'Item';
}

function typeIconText(type: number): string {
  if (type === 1) return 'L';
  if (type === 3) return 'C';
  if (type === 4) return 'I';
  if (type === 2) return 'N';
  if (type === 5) return 'S';
  return 'V';
}

function parseFieldType(value: number | string | null | undefined): CustomFieldType {
  if (value === 1 || value === 2 || value === 3) return value;
  if (value === '1' || String(value).toLowerCase() === 'hidden') return 1;
  if (value === '2' || String(value).toLowerCase() === 'boolean') return 2;
  if (value === '3' || String(value).toLowerCase() === 'linked') return 3;
  return 0;
}

function fieldTypeLabel(type: CustomFieldType): string {
  const found = FIELD_TYPE_OPTIONS.find((x) => x.value === type);
  return found ? found.label : 'Text';
}

function firstCipherUri(cipher: Cipher): string {
  const uris = cipher.login?.uris || [];
  for (const uri of uris) {
    const raw = uri.decUri || uri.uri || '';
    if (raw.trim()) return raw.trim();
  }
  return '';
}

function hostFromUri(uri: string): string {
  if (!uri.trim()) return '';
  try {
    const normalized = /^https?:\/\//i.test(uri) ? uri : `https://${uri}`;
    return new URL(normalized).hostname || '';
  } catch {
    return '';
  }
}

function createEmptyDraft(type: number): VaultDraft {
  return {
    type,
    name: '',
    folderId: '',
    notes: '',
    reprompt: false,
    loginUsername: '',
    loginPassword: '',
    loginTotp: '',
    loginUris: [''],
    cardholderName: '',
    cardNumber: '',
    cardBrand: '',
    cardExpMonth: '',
    cardExpYear: '',
    cardCode: '',
    identTitle: '',
    identFirstName: '',
    identMiddleName: '',
    identLastName: '',
    identUsername: '',
    identCompany: '',
    identSsn: '',
    identPassportNumber: '',
    identLicenseNumber: '',
    identEmail: '',
    identPhone: '',
    identAddress1: '',
    identAddress2: '',
    identAddress3: '',
    identCity: '',
    identState: '',
    identPostalCode: '',
    identCountry: '',
    sshPrivateKey: '',
    sshPublicKey: '',
    sshFingerprint: '',
    customFields: [],
  };
}

function draftFromCipher(cipher: Cipher): VaultDraft {
  const draft = createEmptyDraft(Number(cipher.type || 1));
  draft.id = cipher.id;
  draft.name = cipher.decName || '';
  draft.folderId = cipher.folderId || '';
  draft.notes = cipher.decNotes || '';
  draft.reprompt = Number(cipher.reprompt || 0) === 1;

  if (cipher.login) {
    draft.loginUsername = cipher.login.decUsername || '';
    draft.loginPassword = cipher.login.decPassword || '';
    draft.loginTotp = cipher.login.decTotp || '';
    draft.loginUris = (cipher.login.uris || []).map((x) => x.decUri || x.uri || '');
    if (!draft.loginUris.length) draft.loginUris = [''];
  }
  if (cipher.card) {
    draft.cardholderName = cipher.card.decCardholderName || '';
    draft.cardNumber = cipher.card.decNumber || '';
    draft.cardBrand = cipher.card.decBrand || '';
    draft.cardExpMonth = cipher.card.decExpMonth || '';
    draft.cardExpYear = cipher.card.decExpYear || '';
    draft.cardCode = cipher.card.decCode || '';
  }
  if (cipher.identity) {
    draft.identTitle = cipher.identity.decTitle || '';
    draft.identFirstName = cipher.identity.decFirstName || '';
    draft.identMiddleName = cipher.identity.decMiddleName || '';
    draft.identLastName = cipher.identity.decLastName || '';
    draft.identUsername = cipher.identity.decUsername || '';
    draft.identCompany = cipher.identity.decCompany || '';
    draft.identSsn = cipher.identity.decSsn || '';
    draft.identPassportNumber = cipher.identity.decPassportNumber || '';
    draft.identLicenseNumber = cipher.identity.decLicenseNumber || '';
    draft.identEmail = cipher.identity.decEmail || '';
    draft.identPhone = cipher.identity.decPhone || '';
    draft.identAddress1 = cipher.identity.decAddress1 || '';
    draft.identAddress2 = cipher.identity.decAddress2 || '';
    draft.identAddress3 = cipher.identity.decAddress3 || '';
    draft.identCity = cipher.identity.decCity || '';
    draft.identState = cipher.identity.decState || '';
    draft.identPostalCode = cipher.identity.decPostalCode || '';
    draft.identCountry = cipher.identity.decCountry || '';
  }
  if (cipher.sshKey) {
    draft.sshPrivateKey = cipher.sshKey.decPrivateKey || '';
    draft.sshPublicKey = cipher.sshKey.decPublicKey || '';
    draft.sshFingerprint = cipher.sshKey.decFingerprint || '';
  }
  draft.customFields = (cipher.fields || []).map((field) => ({
    type: parseFieldType(field.type),
    label: field.decName || '',
    value: field.decValue || '',
  }));

  return draft;
}

function matchesTypeFilter(cipher: Cipher, typeFilter: TypeFilter): boolean {
  if (typeFilter === 'all') return true;
  if (typeFilter === 'favorite') return !!cipher.favorite;
  return cipherTypeKey(Number(cipher.type || 1)) === typeFilter;
}

function maskSecret(value: string): string {
  if (!value) return '';
  return '*'.repeat(Math.max(8, Math.min(24, value.length)));
}

function formatTotp(code: string): string {
  if (!code || code.length < 6) return code;
  return `${code.slice(0, 3)} ${code.slice(3, 6)}`;
}

function VaultListIcon({ cipher }: { cipher: Cipher }) {
  const uri = firstCipherUri(cipher);
  const host = hostFromUri(uri);
  const [errored, setErrored] = useState(false);
  if (host && !errored) {
    return (
      <img
        className="list-icon"
        src={`/icons/${host}/icon.png`}
        alt=""
        loading="lazy"
        onError={() => setErrored(true)}
      />
    );
  }
  return <span className="list-icon-fallback">{typeIconText(Number(cipher.type || 1))}</span>;
}

function copyToClipboard(value: string): void {
  if (!value.trim()) return;
  void navigator.clipboard.writeText(value);
}

function openUri(raw: string): void {
  const value = raw.trim();
  if (!value) return;
  const url = /^https?:\/\//i.test(value) ? value : `https://${value}`;
  window.open(url, '_blank', 'noopener');
}

export default function VaultPage(props: VaultPageProps) {
  const [searchInput, setSearchInput] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [searchComposing, setSearchComposing] = useState(false);
  const [typeFilter, setTypeFilter] = useState<TypeFilter>('all');
  const [folderFilter, setFolderFilter] = useState<string>('all');
  const [selectedCipherId, setSelectedCipherId] = useState('');
  const [selectedMap, setSelectedMap] = useState<Record<string, boolean>>({});
  const [showPassword, setShowPassword] = useState(false);
  const [createMenuOpen, setCreateMenuOpen] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [draft, setDraft] = useState<VaultDraft | null>(null);
  const [fieldModalOpen, setFieldModalOpen] = useState(false);
  const [fieldType, setFieldType] = useState<CustomFieldType>(0);
  const [fieldLabel, setFieldLabel] = useState('');
  const [fieldValue, setFieldValue] = useState('');
  const [localError, setLocalError] = useState('');
  const [pendingDelete, setPendingDelete] = useState<Cipher | null>(null);
  const [bulkDeleteOpen, setBulkDeleteOpen] = useState(false);
  const [moveOpen, setMoveOpen] = useState(false);
  const [moveFolderId, setMoveFolderId] = useState('__none__');
  const [totpLive, setTotpLive] = useState<{ code: string; remain: number } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (searchComposing) return;
    const timer = window.setTimeout(() => setSearchQuery(searchInput.trim().toLowerCase()), 90);
    return () => window.clearTimeout(timer);
  }, [searchInput, searchComposing]);

  const filteredCiphers = useMemo(() => {
    return props.ciphers.filter((cipher) => {
      if (!matchesTypeFilter(cipher, typeFilter)) return false;
      if (folderFilter === 'none' && cipher.folderId) return false;
      if (folderFilter !== 'none' && folderFilter !== 'all' && cipher.folderId !== folderFilter) return false;
      if (!searchQuery) return true;
      const name = (cipher.decName || '').toLowerCase();
      const username = (cipher.login?.decUsername || '').toLowerCase();
      const uri = firstCipherUri(cipher).toLowerCase();
      return name.includes(searchQuery) || username.includes(searchQuery) || uri.includes(searchQuery);
    });
  }, [props.ciphers, folderFilter, typeFilter, searchQuery]);

  useEffect(() => {
    if (isCreating) return;
    if (!filteredCiphers.length) {
      if (selectedCipherId) setSelectedCipherId('');
      return;
    }
    if (!selectedCipherId || !filteredCiphers.some((x) => x.id === selectedCipherId)) {
      setSelectedCipherId(filteredCiphers[0].id);
    }
  }, [filteredCiphers, selectedCipherId, isCreating]);

  const selectedCipher = useMemo(
    () => props.ciphers.find((x) => x.id === selectedCipherId) || null,
    [props.ciphers, selectedCipherId]
  );

  useEffect(() => {
    const raw = selectedCipher?.login?.decTotp || '';
    if (!raw) {
      setTotpLive(null);
      return;
    }
    let stopped = false;
    let timer = 0;
    const tick = async () => {
      try {
        const now = await calcTotpNow(raw);
        if (!stopped) setTotpLive(now);
      } catch {
        if (!stopped) setTotpLive(null);
      }
    };
    void tick();
    timer = window.setInterval(() => void tick(), 1000);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [selectedCipher?.id, selectedCipher?.login?.decTotp]);

  const selectedCount = useMemo(
    () => Object.values(selectedMap).reduce((sum, v) => sum + (v ? 1 : 0), 0),
    [selectedMap]
  );

  function folderName(id: string | null | undefined): string {
    if (!id) return 'No Folder';
    const folder = props.folders.find((x) => x.id === id);
    return folder?.decName || folder?.name || id;
  }

  function listSubtitle(cipher: Cipher): string {
    if (Number(cipher.type || 1) === 1) {
      return cipher.login?.decUsername || firstCipherUri(cipher) || '';
    }
    return cipherTypeLabel(Number(cipher.type || 1));
  }

  function startCreate(type: number): void {
    setDraft(createEmptyDraft(type));
    setIsCreating(true);
    setIsEditing(true);
    setCreateMenuOpen(false);
    setSelectedCipherId('');
    setShowPassword(false);
    setLocalError('');
  }

  function startEdit(): void {
    if (!selectedCipher) return;
    setDraft(draftFromCipher(selectedCipher));
    setIsCreating(false);
    setIsEditing(true);
    setShowPassword(false);
    setLocalError('');
  }

  function cancelEdit(): void {
    setDraft(null);
    setIsEditing(false);
    setIsCreating(false);
    setLocalError('');
  }

  function updateDraft(patch: Partial<VaultDraft>): void {
    setDraft((prev) => (prev ? { ...prev, ...patch } : prev));
  }

  function updateDraftCustomFields(nextFields: VaultDraftField[]): void {
    setDraft((prev) => (prev ? { ...prev, customFields: nextFields } : prev));
  }

  function updateDraftLoginUri(index: number, value: string): void {
    setDraft((prev) => {
      if (!prev) return prev;
      const next = [...prev.loginUris];
      next[index] = value;
      return { ...prev, loginUris: next };
    });
  }

  async function saveDraft(): Promise<void> {
    if (!draft) return;
    if (!draft.name.trim()) {
      setLocalError('Item name is required.');
      return;
    }
    setBusy(true);
    try {
      if (isCreating) {
        await props.onCreate(draft);
      } else if (selectedCipher) {
        await props.onUpdate(selectedCipher, draft);
      }
      setIsCreating(false);
      setIsEditing(false);
      setDraft(null);
      setLocalError('');
    } finally {
      setBusy(false);
    }
  }

  async function deleteSelected(): Promise<void> {
    if (!pendingDelete) return;
    setBusy(true);
    try {
      await props.onDelete(pendingDelete);
      setPendingDelete(null);
      cancelEdit();
    } finally {
      setBusy(false);
    }
  }

  async function confirmBulkDelete(): Promise<void> {
    const ids = Object.entries(selectedMap)
      .filter(([, selected]) => selected)
      .map(([id]) => id);
    if (!ids.length) return;
    setBusy(true);
    try {
      await props.onBulkDelete(ids);
      setSelectedMap({});
      setBulkDeleteOpen(false);
    } finally {
      setBusy(false);
    }
  }

  async function confirmBulkMove(): Promise<void> {
    const ids = Object.entries(selectedMap)
      .filter(([, selected]) => selected)
      .map(([id]) => id);
    if (!ids.length) return;
    const folderId = moveFolderId === '__none__' ? null : moveFolderId;
    setBusy(true);
    try {
      await props.onBulkMove(ids, folderId);
      setSelectedMap({});
      setMoveOpen(false);
    } finally {
      setBusy(false);
    }
  }

  async function syncVault(): Promise<void> {
    setBusy(true);
    try {
      await props.onRefresh();
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="vault-grid">
        <aside className="sidebar">
          <div className="sidebar-block">
            <div className="sidebar-title">Search</div>
            <input
              className="search-input"
              placeholder="Search vault"
              value={searchInput}
              onInput={(e) => setSearchInput((e.currentTarget as HTMLInputElement).value)}
              onCompositionStart={() => setSearchComposing(true)}
              onCompositionEnd={(e) => {
                setSearchComposing(false);
                setSearchInput((e.currentTarget as HTMLInputElement).value);
              }}
            />
          </div>

          <div className="sidebar-block">
            <div className="sidebar-title">Types</div>
            <button type="button" className={`tree-btn ${typeFilter === 'all' ? 'active' : ''}`} onClick={() => setTypeFilter('all')}>
              All Items
            </button>
            <button type="button" className={`tree-btn ${typeFilter === 'favorite' ? 'active' : ''}`} onClick={() => setTypeFilter('favorite')}>
              Favorites
            </button>
            <button type="button" className={`tree-btn ${typeFilter === 'login' ? 'active' : ''}`} onClick={() => setTypeFilter('login')}>
              Login
            </button>
            <button type="button" className={`tree-btn ${typeFilter === 'card' ? 'active' : ''}`} onClick={() => setTypeFilter('card')}>
              Card
            </button>
            <button type="button" className={`tree-btn ${typeFilter === 'identity' ? 'active' : ''}`} onClick={() => setTypeFilter('identity')}>
              Identity
            </button>
            <button type="button" className={`tree-btn ${typeFilter === 'note' ? 'active' : ''}`} onClick={() => setTypeFilter('note')}>
              Note
            </button>
            <button type="button" className={`tree-btn ${typeFilter === 'ssh' ? 'active' : ''}`} onClick={() => setTypeFilter('ssh')}>
              SSH Key
            </button>
          </div>

          <div className="sidebar-block">
            <div className="sidebar-title">Folders</div>
            <button type="button" className={`tree-btn ${folderFilter === 'all' ? 'active' : ''}`} onClick={() => setFolderFilter('all')}>
              All
            </button>
            <button type="button" className={`tree-btn ${folderFilter === 'none' ? 'active' : ''}`} onClick={() => setFolderFilter('none')}>
              No Folder
            </button>
            {props.folders.map((folder) => (
              <button
                key={folder.id}
                type="button"
                className={`tree-btn ${folderFilter === folder.id ? 'active' : ''}`}
                onClick={() => setFolderFilter(folder.id)}
              >
                {folder.decName || folder.name || folder.id}
              </button>
            ))}
          </div>
        </aside>

        <section className="list-col">
          <div className="toolbar actions">
            <button type="button" className="btn btn-secondary small" disabled={busy || props.loading} onClick={() => void syncVault()}>
              Sync
            </button>
            <button
              type="button"
              className="btn btn-secondary small"
              disabled={!selectedCount || busy}
              onClick={() => {
                setMoveFolderId('__none__');
                setMoveOpen(true);
              }}
            >
              Move
            </button>
            <button type="button" className="btn btn-danger small" disabled={!selectedCount || busy} onClick={() => setBulkDeleteOpen(true)}>
              Delete ({selectedCount})
            </button>
            <button
              type="button"
              className="btn btn-secondary small"
              disabled={!filteredCiphers.length}
              onClick={() => {
                const map: Record<string, boolean> = {};
                for (const cipher of filteredCiphers) map[cipher.id] = true;
                setSelectedMap(map);
              }}
            >
              Select All
            </button>
            <button type="button" className="btn btn-secondary small" onClick={() => setSelectedMap({})}>
              Cancel
            </button>
            <div className="create-menu-wrap">
              <button type="button" className="btn btn-primary small" onClick={() => setCreateMenuOpen((x) => !x)}>
                + Add
              </button>
              {createMenuOpen && (
                <div className="create-menu">
                  {CREATE_TYPE_OPTIONS.map((option) => (
                    <button key={option.type} type="button" className="create-menu-item" onClick={() => startCreate(option.type)}>
                      {option.label}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="list-panel">
            {filteredCiphers.map((cipher) => (
              <div key={cipher.id} className={`list-item ${selectedCipherId === cipher.id ? 'active' : ''}`}>
                <input
                  type="checkbox"
                  className="row-check"
                  checked={!!selectedMap[cipher.id]}
                  onInput={(e) =>
                    setSelectedMap((prev) => ({
                      ...prev,
                      [cipher.id]: (e.currentTarget as HTMLInputElement).checked,
                    }))
                  }
                />
                <button type="button" className="row-main" onClick={() => setSelectedCipherId(cipher.id)}>
                  <div className="list-icon-wrap">
                    <VaultListIcon cipher={cipher} />
                  </div>
                  <div className="list-text">
                    <span className="list-title">{cipher.decName || '(No Name)'}</span>
                    <span className="list-sub">{listSubtitle(cipher)}</span>
                  </div>
                </button>
              </div>
            ))}
            {!filteredCiphers.length && <div className="empty">No items</div>}
          </div>
        </section>

        <section className="detail-col">
          {isEditing && draft && (
            <>
              <div className="card">
                <h3 className="detail-title">{isCreating ? `New ${cipherTypeLabel(draft.type)}` : `Edit ${cipherTypeLabel(draft.type)}`}</h3>
                <div className="field-grid">
                  <label className="field">
                    <span>Type</span>
                    <select
                      className="input"
                      value={draft.type}
                      disabled={!isCreating}
                      onInput={(e) => updateDraft({ type: Number((e.currentTarget as HTMLSelectElement).value) })}
                    >
                      {CREATE_TYPE_OPTIONS.map((option) => (
                        <option key={option.type} value={option.type}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="field">
                    <span>Folder</span>
                    <select
                      className="input"
                      value={draft.folderId}
                      onInput={(e) => updateDraft({ folderId: (e.currentTarget as HTMLSelectElement).value })}
                    >
                      <option value="">No Folder</option>
                      {props.folders.map((folder) => (
                        <option key={folder.id} value={folder.id}>
                          {folder.decName || folder.name || folder.id}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>
                <label className="field">
                  <span>Name</span>
                  <input className="input" value={draft.name} onInput={(e) => updateDraft({ name: (e.currentTarget as HTMLInputElement).value })} />
                </label>
              </div>

              {draft.type === 1 && (
                <div className="card">
                  <h4>Login Credentials</h4>
                  <div className="field-grid">
                    <label className="field">
                      <span>Username</span>
                      <input className="input" value={draft.loginUsername} onInput={(e) => updateDraft({ loginUsername: (e.currentTarget as HTMLInputElement).value })} />
                    </label>
                    <label className="field">
                      <span>Password</span>
                      <input className="input" value={draft.loginPassword} onInput={(e) => updateDraft({ loginPassword: (e.currentTarget as HTMLInputElement).value })} />
                    </label>
                  </div>
                  <label className="field">
                    <span>TOTP Secret</span>
                    <input className="input" value={draft.loginTotp} onInput={(e) => updateDraft({ loginTotp: (e.currentTarget as HTMLInputElement).value })} />
                  </label>
                  <div className="section-head">
                    <h4>Websites</h4>
                    <button type="button" className="btn btn-secondary small" onClick={() => updateDraft({ loginUris: [...draft.loginUris, ''] })}>
                      + Add Website
                    </button>
                  </div>
                  {draft.loginUris.map((uri, index) => (
                    <div key={`uri-${index}`} className="uri-row">
                      <input className="input" value={uri} onInput={(e) => updateDraftLoginUri(index, (e.currentTarget as HTMLInputElement).value)} />
                      {draft.loginUris.length > 1 && (
                        <button
                          type="button"
                          className="btn btn-secondary small"
                          onClick={() => updateDraft({ loginUris: draft.loginUris.filter((_, i) => i !== index) })}
                        >
                          Remove
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {draft.type === 3 && (
                <div className="card">
                  <h4>Card Details</h4>
                  <div className="field-grid">
                    <label className="field">
                      <span>Cardholder Name</span>
                      <input className="input" value={draft.cardholderName} onInput={(e) => updateDraft({ cardholderName: (e.currentTarget as HTMLInputElement).value })} />
                    </label>
                    <label className="field">
                      <span>Number</span>
                      <input className="input" value={draft.cardNumber} onInput={(e) => updateDraft({ cardNumber: (e.currentTarget as HTMLInputElement).value })} />
                    </label>
                    <label className="field">
                      <span>Brand</span>
                      <input className="input" value={draft.cardBrand} onInput={(e) => updateDraft({ cardBrand: (e.currentTarget as HTMLInputElement).value })} />
                    </label>
                    <label className="field">
                      <span>Security Code (CVV)</span>
                      <input className="input" value={draft.cardCode} onInput={(e) => updateDraft({ cardCode: (e.currentTarget as HTMLInputElement).value })} />
                    </label>
                    <label className="field">
                      <span>Expiry Month</span>
                      <input className="input" value={draft.cardExpMonth} onInput={(e) => updateDraft({ cardExpMonth: (e.currentTarget as HTMLInputElement).value })} />
                    </label>
                    <label className="field">
                      <span>Expiry Year</span>
                      <input className="input" value={draft.cardExpYear} onInput={(e) => updateDraft({ cardExpYear: (e.currentTarget as HTMLInputElement).value })} />
                    </label>
                  </div>
                </div>
              )}

              {draft.type === 4 && (
                <div className="card">
                  <h4>Identity Details</h4>
                  <div className="field-grid">
                    <label className="field"><span>Title</span><input className="input" value={draft.identTitle} onInput={(e) => updateDraft({ identTitle: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>First Name</span><input className="input" value={draft.identFirstName} onInput={(e) => updateDraft({ identFirstName: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>Middle Name</span><input className="input" value={draft.identMiddleName} onInput={(e) => updateDraft({ identMiddleName: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>Last Name</span><input className="input" value={draft.identLastName} onInput={(e) => updateDraft({ identLastName: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>Username</span><input className="input" value={draft.identUsername} onInput={(e) => updateDraft({ identUsername: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>Company</span><input className="input" value={draft.identCompany} onInput={(e) => updateDraft({ identCompany: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>SSN</span><input className="input" value={draft.identSsn} onInput={(e) => updateDraft({ identSsn: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>Passport Number</span><input className="input" value={draft.identPassportNumber} onInput={(e) => updateDraft({ identPassportNumber: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>License Number</span><input className="input" value={draft.identLicenseNumber} onInput={(e) => updateDraft({ identLicenseNumber: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>Email</span><input className="input" value={draft.identEmail} onInput={(e) => updateDraft({ identEmail: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>Phone</span><input className="input" value={draft.identPhone} onInput={(e) => updateDraft({ identPhone: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>Address 1</span><input className="input" value={draft.identAddress1} onInput={(e) => updateDraft({ identAddress1: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>Address 2</span><input className="input" value={draft.identAddress2} onInput={(e) => updateDraft({ identAddress2: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>Address 3</span><input className="input" value={draft.identAddress3} onInput={(e) => updateDraft({ identAddress3: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>City / Town</span><input className="input" value={draft.identCity} onInput={(e) => updateDraft({ identCity: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>State / Province</span><input className="input" value={draft.identState} onInput={(e) => updateDraft({ identState: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>Postal Code</span><input className="input" value={draft.identPostalCode} onInput={(e) => updateDraft({ identPostalCode: (e.currentTarget as HTMLInputElement).value })} /></label>
                    <label className="field"><span>Country</span><input className="input" value={draft.identCountry} onInput={(e) => updateDraft({ identCountry: (e.currentTarget as HTMLInputElement).value })} /></label>
                  </div>
                </div>
              )}
              {draft.type === 5 && (
                <div className="card">
                  <h4>SSH Key</h4>
                  <label className="field">
                    <span>Private Key</span>
                    <textarea className="input textarea" value={draft.sshPrivateKey} onInput={(e) => updateDraft({ sshPrivateKey: (e.currentTarget as HTMLTextAreaElement).value })} />
                  </label>
                  <label className="field">
                    <span>Public Key</span>
                    <textarea className="input textarea" value={draft.sshPublicKey} onInput={(e) => updateDraft({ sshPublicKey: (e.currentTarget as HTMLTextAreaElement).value })} />
                  </label>
                  <label className="field">
                    <span>Fingerprint</span>
                    <input className="input" value={draft.sshFingerprint} onInput={(e) => updateDraft({ sshFingerprint: (e.currentTarget as HTMLInputElement).value })} />
                  </label>
                </div>
              )}

              <div className="card">
                <h4>Additional Options</h4>
                <label className="field">
                  <span>Notes</span>
                  <textarea className="input textarea" value={draft.notes} onInput={(e) => updateDraft({ notes: (e.currentTarget as HTMLTextAreaElement).value })} />
                </label>
                <label className="check-line">
                  <input type="checkbox" checked={draft.reprompt} onInput={(e) => updateDraft({ reprompt: (e.currentTarget as HTMLInputElement).checked })} />
                  Master password reprompt
                </label>
                <div className="section-head">
                  <h4>Custom Fields</h4>
                  <button type="button" className="btn btn-secondary small" onClick={() => setFieldModalOpen(true)}>
                    + Add Field
                  </button>
                </div>
                {draft.customFields.map((field, index) => (
                  <div key={`field-${index}`} className="uri-row">
                    <input className="input" value={field.label} readOnly />
                    <input className="input" value={field.value} readOnly />
                    <span className="field-type-pill">{fieldTypeLabel(field.type)}</span>
                    <button
                      type="button"
                      className="btn btn-secondary small"
                      onClick={() => updateDraftCustomFields(draft.customFields.filter((_, i) => i !== index))}
                    >
                      Remove
                    </button>
                  </div>
                ))}
              </div>

              <div className="detail-actions">
                <div className="actions">
                  <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void saveDraft()}>
                    Confirm
                  </button>
                  <button type="button" className="btn btn-secondary" disabled={busy} onClick={cancelEdit}>
                    Cancel
                  </button>
                </div>
                {!isCreating && selectedCipher && (
                  <button type="button" className="btn btn-danger" disabled={busy} onClick={() => setPendingDelete(selectedCipher)}>
                    Delete
                  </button>
                )}
              </div>
              {localError && <div className="local-error">{localError}</div>}
            </>
          )}

          {!isEditing && selectedCipher && (
            <>
              <div className="card">
                <h3 className="detail-title">{selectedCipher.decName || '(No Name)'}</h3>
                <div className="detail-sub">{folderName(selectedCipher.folderId)}</div>
              </div>

              {selectedCipher.login && (
                <div className="card">
                  <h4>Login Credentials</h4>
                  <div className="kv-line">
                    <span>Username</span>
                    <div className="actions">
                      <strong>{selectedCipher.login.decUsername || ''}</strong>
                      <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(selectedCipher.login?.decUsername || '')}>
                        Copy
                      </button>
                    </div>
                  </div>
                  <div className="kv-line">
                    <span>Password</span>
                    <div className="actions">
                      <strong>{showPassword ? selectedCipher.login.decPassword || '' : maskSecret(selectedCipher.login.decPassword || '')}</strong>
                      <button type="button" className="btn btn-secondary small" onClick={() => setShowPassword((v) => !v)}>
                        {showPassword ? 'Hide' : 'Reveal'}
                      </button>
                      <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(selectedCipher.login?.decPassword || '')}>
                        Copy
                      </button>
                    </div>
                  </div>
                  {!!selectedCipher.login.decTotp && (
                    <div className="kv-line">
                      <span>TOTP</span>
                      <div className="actions">
                        <strong>{totpLive ? formatTotp(totpLive.code) : '------'}</strong>
                        <span className="detail-sub">Refresh in: {totpLive ? `${totpLive.remain}s` : '--'}</span>
                        <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(totpLive?.code || '')}>
                          Copy
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {(selectedCipher.login?.uris || []).length > 0 && (
                <div className="card">
                  <h4>Autofill Options</h4>
                  {(selectedCipher.login?.uris || []).map((uri, index) => {
                    const value = uri.decUri || uri.uri || '';
                    if (!value.trim()) return null;
                    return (
                      <div key={`view-uri-${index}`} className="kv-line">
                        <span>Website</span>
                        <div className="actions">
                          <strong>{value}</strong>
                          <button type="button" className="btn btn-secondary small" onClick={() => openUri(value)}>
                            Open
                          </button>
                          <button type="button" className="btn btn-secondary small" onClick={() => copyToClipboard(value)}>
                            Copy
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              {selectedCipher.card && (
                <div className="card">
                  <h4>Card Details</h4>
                  <div className="kv-line"><span>Cardholder Name</span><strong>{selectedCipher.card.decCardholderName || ''}</strong></div>
                  <div className="kv-line"><span>Number</span><strong>{selectedCipher.card.decNumber || ''}</strong></div>
                  <div className="kv-line"><span>Brand</span><strong>{selectedCipher.card.decBrand || ''}</strong></div>
                  <div className="kv-line"><span>Expiry</span><strong>{`${selectedCipher.card.decExpMonth || ''}/${selectedCipher.card.decExpYear || ''}`}</strong></div>
                  <div className="kv-line"><span>Security Code</span><strong>{selectedCipher.card.decCode || ''}</strong></div>
                </div>
              )}

              {selectedCipher.identity && (
                <div className="card">
                  <h4>Identity Details</h4>
                  <div className="kv-line"><span>Name</span><strong>{`${selectedCipher.identity.decFirstName || ''} ${selectedCipher.identity.decLastName || ''}`.trim()}</strong></div>
                  <div className="kv-line"><span>Username</span><strong>{selectedCipher.identity.decUsername || ''}</strong></div>
                  <div className="kv-line"><span>Email</span><strong>{selectedCipher.identity.decEmail || ''}</strong></div>
                  <div className="kv-line"><span>Phone</span><strong>{selectedCipher.identity.decPhone || ''}</strong></div>
                  <div className="kv-line"><span>Company</span><strong>{selectedCipher.identity.decCompany || ''}</strong></div>
                  <div className="kv-line"><span>Address</span><strong>{[selectedCipher.identity.decAddress1, selectedCipher.identity.decAddress2, selectedCipher.identity.decAddress3, selectedCipher.identity.decCity, selectedCipher.identity.decState, selectedCipher.identity.decPostalCode, selectedCipher.identity.decCountry].filter(Boolean).join(', ')}</strong></div>
                </div>
              )}

              {selectedCipher.sshKey && (
                <div className="card">
                  <h4>SSH Key</h4>
                  <div className="kv-line"><span>Private Key</span><strong>{maskSecret(selectedCipher.sshKey.decPrivateKey || '')}</strong></div>
                  <div className="kv-line"><span>Public Key</span><strong>{selectedCipher.sshKey.decPublicKey || ''}</strong></div>
                  <div className="kv-line"><span>Fingerprint</span><strong>{selectedCipher.sshKey.decFingerprint || ''}</strong></div>
                </div>
              )}

              <div className="card">
                <h4>Notes</h4>
                <div className="notes">{selectedCipher.decNotes || ''}</div>
              </div>

              {(selectedCipher.fields || []).length > 0 && (
                <div className="card">
                  <h4>Custom Fields</h4>
                  {(selectedCipher.fields || []).map((field, index) => (
                    <div key={`view-field-${index}`} className="kv-line">
                      <span>{field.decName || 'Field'}</span>
                      <strong>{field.decValue || ''}</strong>
                    </div>
                  ))}
                </div>
              )}

              <div className="detail-actions">
                <div className="actions">
                  <button type="button" className="btn btn-secondary" onClick={startEdit}>
                    Edit
                  </button>
                </div>
                <button type="button" className="btn btn-danger" onClick={() => setPendingDelete(selectedCipher)}>
                  Delete
                </button>
              </div>
            </>
          )}

          {!isEditing && !selectedCipher && <div className="empty card">Select an item</div>}
        </section>
      </div>

      <ConfirmDialog
        open={fieldModalOpen}
        title="Add Field"
        message="Configure custom field values."
        confirmText="Add"
        cancelText="Cancel"
        onConfirm={() => {
          if (!draft) return;
          if (!fieldLabel.trim()) {
            setLocalError('Field label is required.');
            return;
          }
          updateDraftCustomFields([
            ...draft.customFields,
            {
              type: fieldType,
              label: fieldLabel.trim(),
              value: fieldValue,
            },
          ]);
          setFieldModalOpen(false);
          setFieldType(0);
          setFieldLabel('');
          setFieldValue('');
          setLocalError('');
        }}
        onCancel={() => {
          setFieldModalOpen(false);
          setFieldType(0);
          setFieldLabel('');
          setFieldValue('');
        }}
      >
        <label className="field">
          <span>Field Type</span>
          <select className="input" value={fieldType} onInput={(e) => setFieldType(Number((e.currentTarget as HTMLSelectElement).value) as CustomFieldType)}>
            {FIELD_TYPE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Field Label</span>
          <input className="input" value={fieldLabel} onInput={(e) => setFieldLabel((e.currentTarget as HTMLInputElement).value)} />
        </label>
        <label className="field">
          <span>Field Value</span>
          <input className="input" value={fieldValue} onInput={(e) => setFieldValue((e.currentTarget as HTMLInputElement).value)} />
        </label>
      </ConfirmDialog>

      <ConfirmDialog
        open={!!pendingDelete}
        title="Delete Item"
        message="Are you sure you want to delete this item?"
        danger
        onConfirm={() => void deleteSelected()}
        onCancel={() => setPendingDelete(null)}
      />

      <ConfirmDialog
        open={bulkDeleteOpen}
        title="Delete Selected Items"
        message={`Are you sure you want to delete ${selectedCount} selected items?`}
        danger
        onConfirm={() => void confirmBulkDelete()}
        onCancel={() => setBulkDeleteOpen(false)}
      />

      <ConfirmDialog
        open={moveOpen}
        title="Move Selected Items"
        message="Choose destination folder."
        confirmText="Move"
        cancelText="Cancel"
        onConfirm={() => void confirmBulkMove()}
        onCancel={() => setMoveOpen(false)}
      >
        <label className="field">
          <span>Folder</span>
          <select className="input" value={moveFolderId} onInput={(e) => setMoveFolderId((e.currentTarget as HTMLSelectElement).value)}>
            <option value="__none__">No Folder</option>
            {props.folders.map((folder) => (
              <option key={folder.id} value={folder.id}>
                {folder.decName || folder.name || folder.id}
              </option>
            ))}
          </select>
        </label>
      </ConfirmDialog>
    </>
  );
}
