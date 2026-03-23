import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import VaultDialogs from '@/components/vault/VaultDialogs';
import VaultDetailView from '@/components/vault/VaultDetailView';
import VaultEditor from '@/components/vault/VaultEditor';
import VaultListPanel from '@/components/vault/VaultListPanel';
import VaultSidebar from '@/components/vault/VaultSidebar';
import {
  MOBILE_LAYOUT_QUERY,
  VAULT_LIST_OVERSCAN,
  VAULT_LIST_ROW_HEIGHT,
  VAULT_SORT_STORAGE_KEY,
  cipherTypeKey,
  cipherTypeLabel,
  createEmptyDraft,
  creationTimeValue,
  draftFromCipher,
  buildCipherDuplicateSignature,
  firstCipherUri,
  firstPasskeyCreationTime,
  isCipherVisibleInArchive,
  isCipherVisibleInNormalVault,
  isCipherVisibleInTrash,
  sortTimeValue,
  type SidebarFilter,
  type VaultSortMode,
} from '@/components/vault/vault-page-helpers';
import { calcTotpNow } from '@/lib/crypto';
import { computeSshFingerprint, generateDefaultSshKeyMaterial } from '@/lib/ssh';
import { ChevronLeft } from 'lucide-preact';
import type { Cipher, CustomFieldType, Folder, VaultDraft, VaultDraftField } from '@/lib/types';
import { t } from '@/lib/i18n';

interface VaultPageProps {
  ciphers: Cipher[];
  folders: Folder[];
  loading: boolean;
  emailForReprompt: string;
  onRefresh: () => Promise<void>;
  onCreate: (draft: VaultDraft, attachments?: File[]) => Promise<void>;
  onUpdate: (cipher: Cipher, draft: VaultDraft, options?: { addFiles?: File[]; removeAttachmentIds?: string[] }) => Promise<void>;
  onDelete: (cipher: Cipher) => Promise<void>;
  onArchive: (cipher: Cipher) => Promise<void>;
  onUnarchive: (cipher: Cipher) => Promise<void>;
  onBulkDelete: (ids: string[]) => Promise<void>;
  onBulkPermanentDelete: (ids: string[]) => Promise<void>;
  onBulkRestore: (ids: string[]) => Promise<void>;
  onBulkArchive: (ids: string[]) => Promise<void>;
  onBulkUnarchive: (ids: string[]) => Promise<void>;
  onBulkMove: (ids: string[], folderId: string | null) => Promise<void>;
  onVerifyMasterPassword: (email: string, password: string) => Promise<void>;
  onNotify: (type: 'success' | 'error' | 'warning', text: string) => void;
  onCreateFolder: (name: string) => Promise<void>;
  onDeleteFolder: (folderId: string) => Promise<void>;
  onBulkDeleteFolders: (folderIds: string[]) => Promise<void>;
  onDownloadAttachment: (cipher: Cipher, attachmentId: string) => Promise<void>;
  downloadingAttachmentKey: string;
  attachmentDownloadPercent: number | null;
  uploadingAttachmentName: string;
  attachmentUploadPercent: number | null;
}


export default function VaultPage(props: VaultPageProps) {
  const [searchInput, setSearchInput] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [searchComposing, setSearchComposing] = useState(false);
  const [sortMode, setSortMode] = useState<VaultSortMode>('edited');
  const [sortMenuOpen, setSortMenuOpen] = useState(false);
  const [sidebarFilter, setSidebarFilter] = useState<SidebarFilter>({ kind: 'all' });
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
  const [pendingArchive, setPendingArchive] = useState<Cipher | null>(null);
  const [pendingDelete, setPendingDelete] = useState<Cipher | null>(null);
  const [bulkArchiveOpen, setBulkArchiveOpen] = useState(false);
  const [bulkDeleteOpen, setBulkDeleteOpen] = useState(false);
  const [moveOpen, setMoveOpen] = useState(false);
  const [moveFolderId, setMoveFolderId] = useState('__none__');
  const [createFolderOpen, setCreateFolderOpen] = useState(false);
  const [newFolderName, setNewFolderName] = useState('');
  const [pendingDeleteFolder, setPendingDeleteFolder] = useState<Folder | null>(null);
  const [deleteAllFoldersOpen, setDeleteAllFoldersOpen] = useState(false);
  const [totpLive, setTotpLive] = useState<{ code: string; remain: number } | null>(null);
  const [hiddenFieldVisibleMap, setHiddenFieldVisibleMap] = useState<Record<number, boolean>>({});
  const [attachmentQueue, setAttachmentQueue] = useState<File[]>([]);
  const [removedAttachmentIds, setRemovedAttachmentIds] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState(false);
  const [repromptOpen, setRepromptOpen] = useState(false);
  const [repromptPassword, setRepromptPassword] = useState('');
  const [repromptApprovedCipherId, setRepromptApprovedCipherId] = useState<string | null>(null);
  const [isMobileLayout, setIsMobileLayout] = useState(false);
  const [mobilePanel, setMobilePanel] = useState<'list' | 'detail' | 'edit'>('list');
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const createMenuRef = useRef<HTMLDivElement | null>(null);
  const sortMenuRef = useRef<HTMLDivElement | null>(null);
  const attachmentInputRef = useRef<HTMLInputElement | null>(null);
  const listPanelRef = useRef<HTMLDivElement | null>(null);
  const sshSeedTicketRef = useRef(0);
  const sshFingerprintTicketRef = useRef(0);
  const [listScrollTop, setListScrollTop] = useState(0);
  const [listViewportHeight, setListViewportHeight] = useState(0);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return;
    const media = window.matchMedia(MOBILE_LAYOUT_QUERY);
    const sync = () => setIsMobileLayout(media.matches);
    sync();
    if (typeof media.addEventListener === 'function') {
      media.addEventListener('change', sync);
      return () => media.removeEventListener('change', sync);
    }
    media.addListener(sync);
    return () => media.removeListener(sync);
  }, []);

  useEffect(() => {
    const onToggleSidebar = () => {
      setMobileSidebarOpen((open) => !open);
    };
    window.addEventListener('nodewarden:toggle-sidebar', onToggleSidebar);
    return () => window.removeEventListener('nodewarden:toggle-sidebar', onToggleSidebar);
  }, []);

  useEffect(() => {
    const onQuickAdd = () => {
      startCreate(1);
    };
    window.addEventListener('nodewarden:add-item', onQuickAdd);
    return () => window.removeEventListener('nodewarden:add-item', onQuickAdd);
  }, []);

  useEffect(() => {
    try {
      const saved = String(localStorage.getItem(VAULT_SORT_STORAGE_KEY) || '').trim() as VaultSortMode;
      if (saved === 'edited' || saved === 'created' || saved === 'name') {
        setSortMode(saved);
      }
    } catch {
      // ignore storage read failures
    }
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem(VAULT_SORT_STORAGE_KEY, sortMode);
    } catch {
      // ignore storage write failures
    }
  }, [sortMode]);

  useEffect(() => {
    const node = listPanelRef.current;
    if (!node) return;
    const updateSize = () => setListViewportHeight(node.clientHeight || 0);
    updateSize();
    const resizeObserver = new ResizeObserver(updateSize);
    resizeObserver.observe(node);
    return () => resizeObserver.disconnect();
  }, []);

  useEffect(() => {
    const onPointerDown = (event: Event) => {
      if (!createMenuOpen) return;
      const target = event.target as Node | null;
      if (createMenuRef.current && target && !createMenuRef.current.contains(target)) {
        setCreateMenuOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setCreateMenuOpen(false);
    };
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [createMenuOpen]);

  useEffect(() => {
    const onPointerDown = (event: Event) => {
      if (!sortMenuOpen) return;
      const target = event.target as Node | null;
      if (sortMenuRef.current && target && !sortMenuRef.current.contains(target)) {
        setSortMenuOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setSortMenuOpen(false);
    };
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [sortMenuOpen]);

  useEffect(() => {
    setRepromptApprovedCipherId(null);
    setRepromptPassword('');
    setRepromptOpen(false);
  }, [selectedCipherId]);

  useEffect(() => {
    if (!isMobileLayout) {
      setMobilePanel('list');
      setMobileSidebarOpen(false);
      return;
    }
    if (isEditing) {
      setMobilePanel('edit');
    } else if (!selectedCipherId) {
      setMobilePanel('list');
    }
  }, [isMobileLayout, isEditing, selectedCipherId]);

  useEffect(() => {
    if (searchComposing) return;
    const timer = window.setTimeout(() => setSearchQuery(searchInput.trim().toLowerCase()), 90);
    return () => window.clearTimeout(timer);
  }, [searchInput, searchComposing]);

  useEffect(() => {
    if (!isEditing || !draft || draft.type !== 5) return;
    void recalculateSshFingerprint(draft.sshPublicKey);
  }, [isEditing, draft?.id, draft?.type]);

  const duplicateSignatureCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const cipher of props.ciphers) {
      if (!isCipherVisibleInNormalVault(cipher)) continue;
      const signature = buildCipherDuplicateSignature(cipher);
      counts.set(signature, (counts.get(signature) || 0) + 1);
    }
    return counts;
  }, [props.ciphers]);

  const filteredCiphers = useMemo(() => {
    const next = props.ciphers.filter((cipher) => {
      if (sidebarFilter.kind === 'trash') {
        if (!isCipherVisibleInTrash(cipher)) return false;
      } else if (sidebarFilter.kind === 'archive') {
        if (!isCipherVisibleInArchive(cipher)) return false;
      } else {
        if (!isCipherVisibleInNormalVault(cipher)) return false;
        if (sidebarFilter.kind === 'duplicates' && (duplicateSignatureCounts.get(buildCipherDuplicateSignature(cipher)) || 0) < 2) {
          return false;
        }
        if (sidebarFilter.kind === 'favorite' && !cipher.favorite) return false;
        if (sidebarFilter.kind === 'type' && cipherTypeKey(Number(cipher.type || 1)) !== sidebarFilter.value) return false;
        if (sidebarFilter.kind === 'folder') {
          if (sidebarFilter.folderId === null) {
            if (cipher.folderId) return false;
          } else if (cipher.folderId !== sidebarFilter.folderId) {
            return false;
          }
        }
      }
      if (!searchQuery) return true;
      const name = (cipher.decName || '').toLowerCase();
      const username = (cipher.login?.decUsername || '').toLowerCase();
      const uri = firstCipherUri(cipher).toLowerCase();
      return name.includes(searchQuery) || username.includes(searchQuery) || uri.includes(searchQuery);
    });

    next.sort((a, b) => {
      if (sortMode === 'edited') {
        const diff = sortTimeValue(b) - sortTimeValue(a);
        if (diff !== 0) return diff;
      } else if (sortMode === 'created') {
        const diff = creationTimeValue(b) - creationTimeValue(a);
        if (diff !== 0) return diff;
      } else {
        const nameDiff = String(a.decName || a.name || '').localeCompare(String(b.decName || b.name || ''), undefined, {
          sensitivity: 'base',
          numeric: true,
        });
        if (nameDiff !== 0) return nameDiff;
      }

      return String(a.id || '').localeCompare(String(b.id || ''));
    });

    return next;
  }, [props.ciphers, sidebarFilter, searchQuery, sortMode, duplicateSignatureCounts]);

  const sidebarFilterKey = useMemo(() => {
    if (sidebarFilter.kind === 'folder') return `folder:${sidebarFilter.folderId ?? 'none'}`;
    if (sidebarFilter.kind === 'type') return `type:${sidebarFilter.value}`;
    return sidebarFilter.kind;
  }, [sidebarFilter]);

  useEffect(() => {
    setListScrollTop(0);
    listPanelRef.current?.scrollTo({ top: 0 });
  }, [searchQuery, sortMode, sidebarFilterKey]);

  useEffect(() => {
    if (sidebarFilter.kind === 'duplicates' && sortMode !== 'name') {
      setSortMode('name');
    }
  }, [sidebarFilter.kind, sortMode]);

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
  const virtualRange = useMemo(() => {
    if (!filteredCiphers.length) {
      return { start: 0, end: 0, padTop: 0, padBottom: 0 };
    }
    const viewport = Math.max(listViewportHeight, VAULT_LIST_ROW_HEIGHT * 8);
    const visibleCount = Math.ceil(viewport / VAULT_LIST_ROW_HEIGHT);
    const start = Math.max(0, Math.floor(listScrollTop / VAULT_LIST_ROW_HEIGHT) - VAULT_LIST_OVERSCAN);
    const end = Math.min(filteredCiphers.length, start + visibleCount + VAULT_LIST_OVERSCAN * 2);
    return {
      start,
      end,
      padTop: start * VAULT_LIST_ROW_HEIGHT,
      padBottom: Math.max(0, (filteredCiphers.length - end) * VAULT_LIST_ROW_HEIGHT),
    };
  }, [filteredCiphers.length, listScrollTop, listViewportHeight]);
  const visibleCiphers = useMemo(
    () => filteredCiphers.slice(virtualRange.start, virtualRange.end),
    [filteredCiphers, virtualRange.start, virtualRange.end]
  );
  const passkeyCreatedAt = firstPasskeyCreationTime(selectedCipher);
  const selectedAttachments = useMemo(
    () => (Array.isArray(selectedCipher?.attachments) ? selectedCipher.attachments : []),
    [selectedCipher]
  );
  const editExistingAttachments = useMemo(
    () =>
      selectedAttachments.filter((attachment) => {
        const id = String(attachment?.id || '').trim();
        return !!id;
      }),
    [selectedAttachments]
  );
  const removedAttachmentCount = useMemo(() => Object.values(removedAttachmentIds).filter(Boolean).length, [removedAttachmentIds]);

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
  const totalCipherCount = filteredCiphers.length;

function folderName(id: string | null | undefined): string {
  if (!id) return t('txt_no_folder');
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
    setAttachmentQueue([]);
    setRemovedAttachmentIds({});
    if (isMobileLayout) setMobilePanel('edit');
    setMobileSidebarOpen(false);
    if (type === 5) void seedSshDefaults();
  }

  function startEdit(): void {
    if (!selectedCipher) return;
    setDraft(draftFromCipher(selectedCipher));
    setIsCreating(false);
    setIsEditing(true);
    setShowPassword(false);
    setLocalError('');
    setAttachmentQueue([]);
    setRemovedAttachmentIds({});
    if (isMobileLayout) setMobilePanel('edit');
    setMobileSidebarOpen(false);
  }

  function cancelEdit(): void {
    const returnToDetail = isMobileLayout && !isCreating && !!selectedCipher;
    setDraft(null);
    setIsEditing(false);
    setIsCreating(false);
    setLocalError('');
    setAttachmentQueue([]);
    setRemovedAttachmentIds({});
    if (isMobileLayout) setMobilePanel(returnToDetail ? 'detail' : 'list');
  }

  function updateDraft(patch: Partial<VaultDraft>): void {
    setDraft((prev) => (prev ? { ...prev, ...patch } : prev));
  }

  async function seedSshDefaults(force = false): Promise<void> {
    const ticket = ++sshSeedTicketRef.current;
    try {
      const generated = await generateDefaultSshKeyMaterial();
      if (ticket !== sshSeedTicketRef.current) return;
      setDraft((prev) => {
        if (!prev || prev.type !== 5) return prev;
        if (!force && (prev.sshPrivateKey.trim() || prev.sshPublicKey.trim())) return prev;
        return {
          ...prev,
          sshPrivateKey: generated.privateKey,
          sshPublicKey: generated.publicKey,
          sshFingerprint: generated.fingerprint,
        };
      });
    } catch {
      // Browser may not support Ed25519 generation; user can still paste keys manually.
    }
  }

  async function recalculateSshFingerprint(publicKey: string): Promise<void> {
    const ticket = ++sshFingerprintTicketRef.current;
    const fingerprint = await computeSshFingerprint(publicKey);
    if (ticket !== sshFingerprintTicketRef.current) return;
    setDraft((prev) => {
      if (!prev || prev.type !== 5) return prev;
      if (prev.sshPublicKey !== publicKey) return prev;
      if (prev.sshFingerprint === fingerprint) return prev;
      return { ...prev, sshFingerprint: fingerprint };
    });
  }

  function updateSshPublicKey(nextValue: string): void {
    setDraft((prev) => {
      if (!prev || prev.type !== 5) return prev;
      return { ...prev, sshPublicKey: nextValue };
    });
    void recalculateSshFingerprint(nextValue);
  }

  function updateDraftCustomFields(nextFields: VaultDraftField[]): void {
    setDraft((prev) => (prev ? { ...prev, customFields: nextFields } : prev));
  }

  function patchDraftCustomField(index: number, patch: Partial<VaultDraftField>): void {
    setDraft((prev) => {
      if (!prev) return prev;
      const next = [...prev.customFields];
      next[index] = { ...next[index], ...patch };
      return { ...prev, customFields: next };
    });
  }

  function updateDraftLoginUri(index: number, value: string): void {
    setDraft((prev) => {
      if (!prev) return prev;
      const next = [...prev.loginUris];
      next[index] = value;
      return { ...prev, loginUris: next };
    });
  }

  function queueAttachmentFiles(list: FileList | null): void {
    if (!list || !list.length) return;
    const next = Array.from(list).filter((file) => file && file.size >= 0);
    if (!next.length) return;
    setAttachmentQueue((prev) => [...prev, ...next]);
  }

  function removeQueuedAttachment(index: number): void {
    setAttachmentQueue((prev) => prev.filter((_, i) => i !== index));
  }

  function toggleExistingAttachmentRemoval(attachmentId: string): void {
    const id = String(attachmentId || '').trim();
    if (!id) return;
    setRemovedAttachmentIds((prev) => {
      const next = { ...prev };
      if (next[id]) delete next[id];
      else next[id] = true;
      return next;
    });
  }

  async function saveDraft(): Promise<void> {
    if (!draft) return;
    let nextDraft = draft;
    if (nextDraft.type === 5) {
      const computedFingerprint = await computeSshFingerprint(nextDraft.sshPublicKey);
      if (computedFingerprint !== nextDraft.sshFingerprint) {
        nextDraft = { ...nextDraft, sshFingerprint: computedFingerprint };
        setDraft(nextDraft);
      }
    }
    if (!nextDraft.name.trim()) {
      setLocalError(t('txt_item_name_is_required'));
      return;
    }
    setBusy(true);
    try {
      if (isCreating) {
        await props.onCreate(nextDraft, attachmentQueue);
      } else if (selectedCipher) {
        const removeAttachmentIds = Object.keys(removedAttachmentIds).filter((id) => !!removedAttachmentIds[id]);
        await props.onUpdate(selectedCipher, nextDraft, {
          addFiles: attachmentQueue,
          removeAttachmentIds,
        });
      }
      setIsCreating(false);
      setIsEditing(false);
      setDraft(null);
      setLocalError('');
      setAttachmentQueue([]);
      setRemovedAttachmentIds({});
      if (isMobileLayout) setMobilePanel('detail');
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
      if (isMobileLayout) setMobilePanel('list');
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
      if (sidebarFilter.kind === 'trash') {
        await props.onBulkPermanentDelete(ids);
      } else {
        await props.onBulkDelete(ids);
      }
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

  async function verifyReprompt(): Promise<void> {
    if (!selectedCipher) return;
    if (!repromptPassword) {
      props.onNotify('error', t('txt_master_password_is_required_2'));
      return;
    }
    setBusy(true);
    try {
      await props.onVerifyMasterPassword(props.emailForReprompt, repromptPassword);
      setRepromptApprovedCipherId(selectedCipher.id);
      setRepromptOpen(false);
      setRepromptPassword('');
    } catch (error) {
      props.onNotify('error', error instanceof Error ? error.message : t('txt_unlock_failed'));
    } finally {
      setBusy(false);
    }
  }

  async function confirmCreateFolder(): Promise<void> {
    if (!newFolderName.trim()) {
      props.onNotify('error', t('txt_folder_name_is_required'));
      return;
    }
    setBusy(true);
    try {
      await props.onCreateFolder(newFolderName);
      setCreateFolderOpen(false);
      setNewFolderName('');
    } finally {
      setBusy(false);
    }
  }

  async function confirmDeleteFolder(): Promise<void> {
    if (!pendingDeleteFolder) return;
    setBusy(true);
    try {
      await props.onDeleteFolder(pendingDeleteFolder.id);
      if (sidebarFilter.kind === 'folder' && sidebarFilter.folderId === pendingDeleteFolder.id) {
        setSidebarFilter({ kind: 'all' });
      }
      setPendingDeleteFolder(null);
    } finally {
      setBusy(false);
    }
  }

  async function confirmBulkRestore(): Promise<void> {
    const ids = Object.entries(selectedMap)
      .filter(([, selected]) => selected)
      .map(([id]) => id);
    if (!ids.length) return;
    setBusy(true);
    try {
      await props.onBulkRestore(ids);
      setSelectedMap({});
    } finally {
      setBusy(false);
    }
  }

  async function confirmArchiveSelected(): Promise<void> {
    if (!pendingArchive) return;
    setBusy(true);
    try {
      await props.onArchive(pendingArchive);
      setPendingArchive(null);
      if (isMobileLayout && selectedCipherId === pendingArchive.id) {
        setMobilePanel('list');
      }
    } finally {
      setBusy(false);
    }
  }

  async function handleUnarchiveSelected(cipher: Cipher): Promise<void> {
    setBusy(true);
    try {
      await props.onBulkUnarchive([cipher.id]);
      setSelectedMap((prev) => {
        const next = { ...prev };
        delete next[cipher.id];
        return next;
      });
    } finally {
      setBusy(false);
    }
  }

  async function confirmBulkArchive(): Promise<void> {
    const ids = Object.entries(selectedMap)
      .filter(([, selected]) => selected)
      .map(([id]) => id);
    if (!ids.length) return;
    setBusy(true);
    try {
      await props.onBulkArchive(ids);
      setSelectedMap({});
      setBulkArchiveOpen(false);
    } finally {
      setBusy(false);
    }
  }

  async function confirmBulkUnarchive(): Promise<void> {
    const ids = Object.entries(selectedMap)
      .filter(([, selected]) => selected)
      .map(([id]) => id);
    if (!ids.length) return;
    setBusy(true);
    try {
      await props.onBulkUnarchive(ids);
      setSelectedMap({});
    } finally {
      setBusy(false);
    }
  }

  async function confirmDeleteAllFolders(): Promise<void> {
    if (!props.folders.length) return;
    setBusy(true);
    try {
      await props.onBulkDeleteFolders(props.folders.map((folder) => folder.id));
      if (sidebarFilter.kind === 'folder') {
        setSidebarFilter({ kind: 'all' });
      }
      setDeleteAllFoldersOpen(false);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className={`vault-grid ${isMobileLayout ? `mobile-panel-${mobilePanel}` : ''}`}>
        {isMobileLayout && mobileSidebarOpen && <div className="mobile-sidebar-mask" onClick={() => setMobileSidebarOpen(false)} />}
        <VaultSidebar
          folders={props.folders}
          sidebarFilter={sidebarFilter}
          busy={busy}
          isMobileLayout={isMobileLayout}
          mobileSidebarOpen={mobileSidebarOpen}
          onCloseMobileSidebar={() => setMobileSidebarOpen(false)}
          onChangeFilter={setSidebarFilter}
          onOpenDeleteAllFolders={() => setDeleteAllFoldersOpen(true)}
          onOpenCreateFolder={() => setCreateFolderOpen(true)}
          onOpenDeleteFolder={setPendingDeleteFolder}
        />

        <VaultListPanel
          busy={busy}
          loading={props.loading}
          searchInput={searchInput}
          sortMode={sortMode}
          sortMenuOpen={sortMenuOpen}
          selectedCount={selectedCount}
          totalCipherCount={totalCipherCount}
          filteredCiphers={filteredCiphers}
          visibleCiphers={visibleCiphers}
          virtualRange={virtualRange}
          selectedCipherId={selectedCipherId}
          selectedMap={selectedMap}
          sidebarFilter={sidebarFilter}
          createMenuOpen={createMenuOpen}
          createMenuRef={createMenuRef}
          sortMenuRef={sortMenuRef}
          listPanelRef={listPanelRef}
          onSearchInput={setSearchInput}
          onSearchCompositionStart={() => setSearchComposing(true)}
          onSearchCompositionEnd={(value) => {
            setSearchComposing(false);
            setSearchInput(value);
          }}
          onToggleSortMenu={() => setSortMenuOpen((open) => !open)}
          onSelectSortMode={(value) => {
            setSortMode(value);
            setSortMenuOpen(false);
          }}
          onSyncVault={() => void syncVault()}
          onOpenBulkDelete={() => setBulkDeleteOpen(true)}
          onSelectDuplicates={() => {
            const map: Record<string, boolean> = {};
            const seen = new Set<string>();
            for (const cipher of filteredCiphers) {
              const signature = buildCipherDuplicateSignature(cipher);
              if (seen.has(signature)) {
                map[cipher.id] = true;
                continue;
              }
              seen.add(signature);
            }
            setSelectedMap(map);
          }}
          onSelectAll={() => {
            const map: Record<string, boolean> = {};
            for (const cipher of filteredCiphers) map[cipher.id] = true;
            setSelectedMap(map);
          }}
          onToggleCreateMenu={() => setCreateMenuOpen((open) => !open)}
          onStartCreate={startCreate}
          onBulkRestore={() => void confirmBulkRestore()}
          onBulkArchive={() => setBulkArchiveOpen(true)}
          onBulkUnarchive={() => void confirmBulkUnarchive()}
          onOpenMove={() => {
            setMoveFolderId('__none__');
            setMoveOpen(true);
          }}
          onClearSelection={() => setSelectedMap({})}
          onScroll={setListScrollTop}
          onToggleSelected={(cipherId, checked) =>
            setSelectedMap((prev) => ({
              ...prev,
              [cipherId]: checked,
            }))
          }
          onSelectCipher={(cipherId) => {
            if (isEditing || isCreating) {
              cancelEdit();
            }
            setSelectedCipherId(cipherId);
            setRepromptApprovedCipherId(null);
            if (isMobileLayout) setMobilePanel('detail');
            setMobileSidebarOpen(false);
          }}
          listSubtitle={listSubtitle}
        />

        <section className={`detail-col ${isMobileLayout ? 'mobile-detail-sheet' : ''} ${isMobileLayout && mobilePanel !== 'list' ? 'open' : ''}`}>
          {isMobileLayout && mobilePanel !== 'list' && (
            <div className="mobile-panel-head">
              <button
                type="button"
                className="btn btn-secondary small mobile-panel-back"
                onClick={() => {
                  if (isEditing) cancelEdit();
                  else setMobilePanel('list');
                }}
              >
                <ChevronLeft size={14} className="btn-icon" />
                {t('txt_back')}
              </button>
            </div>
          )}
          {isEditing && draft && (
            <VaultEditor
              draft={draft}
              isCreating={isCreating}
              busy={busy}
              folders={props.folders}
              selectedCipher={selectedCipher}
              editExistingAttachments={editExistingAttachments}
              removedAttachmentIds={removedAttachmentIds}
              removedAttachmentCount={removedAttachmentCount}
              attachmentQueue={attachmentQueue}
              attachmentInputRef={attachmentInputRef}
              localError={localError}
              onUpdateDraft={updateDraft}
              onSeedSshDefaults={(force) => void seedSshDefaults(force)}
              onUpdateSshPublicKey={updateSshPublicKey}
              onUpdateDraftLoginUri={updateDraftLoginUri}
              onQueueAttachmentFiles={queueAttachmentFiles}
              onToggleExistingAttachmentRemoval={toggleExistingAttachmentRemoval}
              onRemoveQueuedAttachment={removeQueuedAttachment}
              onDownloadAttachment={(cipher, attachmentId) => void props.onDownloadAttachment(cipher, attachmentId)}
              downloadingAttachmentKey={props.downloadingAttachmentKey}
              attachmentDownloadPercent={props.attachmentDownloadPercent}
              uploadingAttachmentName={props.uploadingAttachmentName}
              attachmentUploadPercent={props.attachmentUploadPercent}
              onPatchDraftCustomField={patchDraftCustomField}
              onUpdateDraftCustomFields={updateDraftCustomFields}
              onOpenFieldModal={() => setFieldModalOpen(true)}
              onSave={() => void saveDraft()}
              onCancel={cancelEdit}
              onDeleteSelected={() => selectedCipher && setPendingDelete(selectedCipher)}
            />
          )}

          {!isEditing && selectedCipher && (
            <VaultDetailView
              selectedCipher={selectedCipher}
              repromptApprovedCipherId={repromptApprovedCipherId}
              showPassword={showPassword}
              totpLive={totpLive}
              passkeyCreatedAt={passkeyCreatedAt}
              hiddenFieldVisibleMap={hiddenFieldVisibleMap}
              folderName={folderName}
              onOpenReprompt={() => setRepromptOpen(true)}
              onToggleShowPassword={() => setShowPassword((value) => !value)}
              onToggleHiddenField={(index) => setHiddenFieldVisibleMap((prev) => ({ ...prev, [index]: !prev[index] }))}
              onDownloadAttachment={(cipher, attachmentId) => void props.onDownloadAttachment(cipher, attachmentId)}
              downloadingAttachmentKey={props.downloadingAttachmentKey}
              attachmentDownloadPercent={props.attachmentDownloadPercent}
              onStartEdit={startEdit}
              onDelete={setPendingDelete}
              onArchive={(cipher) => setPendingArchive(cipher)}
              onUnarchive={(cipher) => void handleUnarchiveSelected(cipher)}
            />
          )}

          {!isEditing && !selectedCipher && <div className="empty card">{t('txt_select_an_item')}</div>}
        </section>
      </div>

      <VaultDialogs
        fieldModalOpen={fieldModalOpen}
        fieldType={fieldType}
        fieldLabel={fieldLabel}
        fieldValue={fieldValue}
        archiveConfirmOpen={!!pendingArchive}
        bulkArchiveOpen={bulkArchiveOpen}
        pendingDeleteOpen={!!pendingDelete}
        bulkDeleteOpen={bulkDeleteOpen}
        sidebarTrashMode={sidebarFilter.kind === 'trash'}
        selectedCount={selectedCount}
        moveOpen={moveOpen}
        moveFolderId={moveFolderId}
        folders={props.folders}
        createFolderOpen={createFolderOpen}
        newFolderName={newFolderName}
        pendingDeleteFolder={pendingDeleteFolder}
        deleteAllFoldersOpen={deleteAllFoldersOpen}
        repromptOpen={repromptOpen}
        repromptPassword={repromptPassword}
        onConfirmAddField={() => {
          if (!draft) return;
          if (!fieldLabel.trim()) {
            setLocalError(t('txt_field_label_is_required'));
            return;
          }
          updateDraftCustomFields([
            ...draft.customFields,
            {
              type: fieldType,
              label: fieldLabel.trim(),
              value: fieldType === 2 ? (fieldValue === 'true' ? 'true' : 'false') : fieldValue,
            },
          ]);
          setFieldModalOpen(false);
          setFieldType(0);
          setFieldLabel('');
          setFieldValue('');
          setLocalError('');
        }}
        onCancelFieldModal={() => {
          setFieldModalOpen(false);
          setFieldType(0);
          setFieldLabel('');
          setFieldValue('');
        }}
        onFieldTypeChange={setFieldType}
        onFieldLabelChange={setFieldLabel}
        onFieldValueChange={setFieldValue}
        onConfirmArchive={() => void confirmArchiveSelected()}
        onCancelArchive={() => setPendingArchive(null)}
        onConfirmBulkArchive={() => void confirmBulkArchive()}
        onCancelBulkArchive={() => setBulkArchiveOpen(false)}
        onConfirmDelete={() => void deleteSelected()}
        onCancelDelete={() => setPendingDelete(null)}
        onConfirmBulkDelete={() => void confirmBulkDelete()}
        onCancelBulkDelete={() => setBulkDeleteOpen(false)}
        onConfirmMove={() => void confirmBulkMove()}
        onCancelMove={() => setMoveOpen(false)}
        onMoveFolderIdChange={setMoveFolderId}
        onConfirmCreateFolder={() => void confirmCreateFolder()}
        onCancelCreateFolder={() => {
          setCreateFolderOpen(false);
          setNewFolderName('');
        }}
        onNewFolderNameChange={setNewFolderName}
        onConfirmDeleteFolder={() => void confirmDeleteFolder()}
        onCancelDeleteFolder={() => setPendingDeleteFolder(null)}
        onConfirmDeleteAllFolders={() => void confirmDeleteAllFolders()}
        onCancelDeleteAllFolders={() => setDeleteAllFoldersOpen(false)}
        onConfirmReprompt={() => void verifyReprompt()}
        onCancelReprompt={() => {
          setRepromptOpen(false);
          setRepromptPassword('');
        }}
        onRepromptPasswordChange={setRepromptPassword}
      />
    </>
  );
}





