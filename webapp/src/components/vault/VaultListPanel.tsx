import type { RefObject } from 'preact';
import { Archive, ArrowUpDown, Check, CheckCheck, FolderInput, Plus, RefreshCw, RotateCcw, Trash2, X } from 'lucide-preact';
import type { Cipher } from '@/lib/types';
import { t } from '@/lib/i18n';
import {
  CREATE_TYPE_OPTIONS,
  CreateTypeIcon,
  VAULT_SORT_OPTIONS,
  VaultListIcon,
  type SidebarFilter,
  type VaultSortMode,
} from '@/components/vault/vault-page-helpers';

interface VirtualRange {
  start: number;
  end: number;
  padTop: number;
  padBottom: number;
}

interface VaultListPanelProps {
  busy: boolean;
  loading: boolean;
  searchInput: string;
  sortMode: VaultSortMode;
  sortMenuOpen: boolean;
  selectedCount: number;
  totalCipherCount: number;
  filteredCiphers: Cipher[];
  visibleCiphers: Cipher[];
  virtualRange: VirtualRange;
  selectedCipherId: string;
  selectedMap: Record<string, boolean>;
  sidebarFilter: SidebarFilter;
  createMenuOpen: boolean;
  createMenuRef: RefObject<HTMLDivElement>;
  sortMenuRef: RefObject<HTMLDivElement>;
  listPanelRef: RefObject<HTMLDivElement>;
  onSearchInput: (value: string) => void;
  onSearchCompositionStart: () => void;
  onSearchCompositionEnd: (value: string) => void;
  onToggleSortMenu: () => void;
  onSelectSortMode: (value: VaultSortMode) => void;
  onSyncVault: () => void;
  onOpenBulkDelete: () => void;
  onSelectDuplicates: () => void;
  onSelectAll: () => void;
  onToggleCreateMenu: () => void;
  onStartCreate: (type: number) => void;
  onBulkRestore: () => void;
  onBulkArchive: () => void;
  onBulkUnarchive: () => void;
  onOpenMove: () => void;
  onClearSelection: () => void;
  onScroll: (top: number) => void;
  onToggleSelected: (cipherId: string, checked: boolean) => void;
  onSelectCipher: (cipherId: string) => void;
  listSubtitle: (cipher: Cipher) => string;
}

export default function VaultListPanel(props: VaultListPanelProps) {
  return (
    <section className="list-col">
      <div className="list-head">
        <input
          className="search-input"
          placeholder={t('txt_search_your_secure_vault')}
          value={props.searchInput}
          onInput={(e) => props.onSearchInput((e.currentTarget as HTMLInputElement).value)}
          onCompositionStart={props.onSearchCompositionStart}
          onCompositionEnd={(e) => props.onSearchCompositionEnd((e.currentTarget as HTMLInputElement).value)}
        />
        <div className="sort-menu-wrap" ref={props.sortMenuRef}>
          <button
            type="button"
            className={`btn btn-secondary small sort-trigger ${props.sortMenuOpen ? 'active' : ''}`}
            aria-label={t('txt_sort')}
            title={t('txt_sort')}
            onClick={props.onToggleSortMenu}
          >
            <ArrowUpDown size={14} className="btn-icon" />
          </button>
          {props.sortMenuOpen && (
            <div className="sort-menu">
              {VAULT_SORT_OPTIONS.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  className={`sort-menu-item ${props.sortMode === option.value ? 'active' : ''}`}
                  onClick={() => props.onSelectSortMode(option.value)}
                >
                  <span>{option.label}</span>
                  {props.sortMode === option.value ? <Check size={14} /> : <span className="sort-menu-check-placeholder" />}
                </button>
              ))}
            </div>
          )}
        </div>
        <div className="list-count" title={t('txt_total_items_count', { count: props.totalCipherCount })}>
          {t('txt_total_items_count', { count: props.totalCipherCount })}
        </div>
        <button type="button" className="btn btn-secondary small list-icon-btn" disabled={props.busy || props.loading} onClick={props.onSyncVault}>
          <RefreshCw size={14} className="btn-icon" /> {t('txt_sync_vault')}
        </button>
      </div>
      <div className="toolbar actions">
        <button type="button" className="btn btn-danger small" disabled={!props.selectedCount || props.busy} onClick={props.onOpenBulkDelete}>
          <Trash2 size={14} className="btn-icon" /> {props.sidebarFilter.kind === 'trash' ? t('txt_delete_permanently') : t('txt_delete_selected')}
        </button>
        {props.sidebarFilter.kind === 'duplicates' && (
          <button type="button" className="btn btn-secondary small" disabled={!props.filteredCiphers.length || props.busy} onClick={props.onSelectDuplicates}>
            <Check size={14} className="btn-icon" /> {t('txt_select_duplicate_items')}
          </button>
        )}
        <button type="button" className="btn btn-secondary small" disabled={!props.filteredCiphers.length} onClick={props.onSelectAll}>
          <CheckCheck size={14} className="btn-icon" /> {t('txt_select_all')}
        </button>
        <div className="create-menu-wrap mobile-fab-wrap" ref={props.createMenuRef}>
          <button
            type="button"
            className="btn btn-primary small mobile-fab-trigger"
            aria-label={t('txt_add')}
            title={t('txt_add')}
            onClick={props.onToggleCreateMenu}
          >
            <Plus size={14} className="btn-icon" />
          </button>
          {props.createMenuOpen && (
            <div className="create-menu">
              {CREATE_TYPE_OPTIONS.map((option) => (
                <button key={option.type} type="button" className="create-menu-item" onClick={() => props.onStartCreate(option.type)}>
                  <CreateTypeIcon type={option.type} />
                  <span>{option.label}</span>
                </button>
              ))}
            </div>
          )}
        </div>
        {props.selectedCount > 0 && props.sidebarFilter.kind === 'trash' && (
          <button type="button" className="btn btn-secondary small" disabled={props.busy} onClick={props.onBulkRestore}>
            <RefreshCw size={14} className="btn-icon" /> {t('txt_restore')}
          </button>
        )}
        {props.selectedCount > 0 && props.sidebarFilter.kind === 'archive' && (
          <button type="button" className="btn btn-secondary small" disabled={props.busy} onClick={props.onBulkUnarchive}>
            <RotateCcw size={14} className="btn-icon" /> {t('txt_unarchive')}
          </button>
        )}
        {props.selectedCount > 0 && props.sidebarFilter.kind !== 'trash' && props.sidebarFilter.kind !== 'archive' && props.sidebarFilter.kind !== 'duplicates' && (
          <button type="button" className="btn btn-secondary small" disabled={props.busy} onClick={props.onBulkArchive}>
            <Archive size={14} className="btn-icon" /> {t('txt_archive_selected')}
          </button>
        )}
        {props.selectedCount > 0 && props.sidebarFilter.kind !== 'trash' && props.sidebarFilter.kind !== 'archive' && props.sidebarFilter.kind !== 'duplicates' && (
          <button type="button" className="btn btn-secondary small" disabled={props.busy} onClick={props.onOpenMove}>
            <FolderInput size={14} className="btn-icon" /> {t('txt_move')}
          </button>
        )}
        {props.selectedCount > 0 && (
          <button type="button" className="btn btn-secondary small" onClick={props.onClearSelection}>
            <X size={14} className="btn-icon" /> {t('txt_cancel')}
          </button>
        )}
      </div>

      <div className="list-panel" ref={props.listPanelRef} onScroll={(event) => props.onScroll((event.currentTarget as HTMLDivElement).scrollTop)}>
        {!!props.filteredCiphers.length && (
          <div style={{ paddingTop: `${props.virtualRange.padTop}px`, paddingBottom: `${props.virtualRange.padBottom}px` }}>
            {props.visibleCiphers.map((cipher) => (
              <div key={cipher.id} className={`list-item ${props.selectedCipherId === cipher.id ? 'active' : ''}`}>
                <input
                  type="checkbox"
                  className="row-check"
                  checked={!!props.selectedMap[cipher.id]}
                  onInput={(e) => props.onToggleSelected(cipher.id, (e.currentTarget as HTMLInputElement).checked)}
                />
                <button type="button" className="row-main" onClick={() => props.onSelectCipher(cipher.id)}>
                  <div className="list-icon-wrap">
                    <VaultListIcon cipher={cipher} />
                  </div>
                  <div className="list-text">
                    <span className="list-title" title={cipher.decName || t('txt_no_name')}>
                      <span className="list-title-text">{cipher.decName || t('txt_no_name')}</span>
                    </span>
                    <span className="list-sub" title={props.listSubtitle(cipher)}>{props.listSubtitle(cipher)}</span>
                  </div>
                </button>
              </div>
            ))}
          </div>
        )}
        {!props.filteredCiphers.length && <div className="empty">{t('txt_no_items')}</div>}
      </div>
    </section>
  );
}
