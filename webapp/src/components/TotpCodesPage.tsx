import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { Clipboard, Globe, GripVertical } from 'lucide-preact';
import {
  closestCenter,
  DndContext,
  type DragEndEvent,
  PointerSensor,
  TouchSensor,
  useSensor,
  useSensors,
} from '@dnd-kit/core';
import {
  arrayMove,
  rectSortingStrategy,
  SortableContext,
  useSortable,
} from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import { copyTextToClipboard as copyTextWithFeedback } from '@/lib/clipboard';
import { calcTotpNow } from '@/lib/crypto';
import { t } from '@/lib/i18n';
import type { Cipher } from '@/lib/types';
import { isCipherVisibleInNormalVault, websiteIconUrl } from '@/components/vault/vault-page-helpers';

interface TotpCodesPageProps {
  ciphers: Cipher[];
  loading: boolean;
  onNotify: (type: 'success' | 'error', text: string) => void;
}

const TOTP_PERIOD_SECONDS = 30;
const TOTP_RING_RADIUS = 14;
const TOTP_RING_CIRCUMFERENCE = 2 * Math.PI * TOTP_RING_RADIUS;
const TOTP_ORDER_STORAGE_KEY = 'nodewarden.totp-order';
const failedIconHosts = new Set<string>();

function formatTotp(code: string): string {
  if (!code) return code;
  if (code.length === 5) return `${code.slice(0, 2)} ${code.slice(2)}`;
  if (code.length < 6) return code;
  return `${code.slice(0, 3)} ${code.slice(3, 6)}`;
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

function TotpListIcon({ cipher }: { cipher: Cipher }) {
  const uri = firstCipherUri(cipher);
  const host = hostFromUri(uri);
  const [errored, setErrored] = useState(() => (host ? failedIconHosts.has(host) : false));
  if (host && !errored) {
    return (
      <img
        className="list-icon"
        src={websiteIconUrl(host)}
        alt=""
        loading="lazy"
        referrerPolicy="no-referrer"
        onError={() => {
          failedIconHosts.add(host);
          setErrored(true);
        }}
      />
    );
  }
  return (
    <span className="list-icon-fallback">
      <Globe size={18} />
    </span>
  );
}

interface SortableTotpRowProps {
  cipher: Cipher;
  live: { code: string; remain: number } | null;
  onCopy: (value: string) => void;
}

function SortableTotpRow(props: SortableTotpRowProps) {
  const { attributes, listeners, setActivatorNodeRef, setNodeRef, transform, transition, isDragging } = useSortable({
    id: props.cipher.id,
  });

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
  };

  const name = props.cipher.decName || props.cipher.name || t('txt_no_name');
  const username = props.cipher.login?.decUsername || '';

  return (
    <div ref={setNodeRef} style={style} className={`totp-code-row${isDragging ? ' is-dragging' : ''}`}>
      <button
        type="button"
        ref={setActivatorNodeRef}
        className="btn btn-secondary small totp-drag-btn"
        title={t('txt_drag_to_reorder')}
        aria-label={t('txt_drag_to_reorder')}
        {...attributes}
        {...listeners}
      >
        <GripVertical size={14} className="btn-icon" />
      </button>
      <div className="totp-code-info">
        <div className="list-icon-wrap">
          <TotpListIcon cipher={props.cipher} />
        </div>
        <div className="totp-code-meta">
          <div className="totp-code-name" title={name}>{name}</div>
          <div className="totp-code-username" title={username}>{username || t('txt_no_username')}</div>
        </div>
      </div>
      <div className="totp-code-main">
        <strong>{props.live ? formatTotp(props.live.code) : t('txt_text_3')}</strong>
        <div
          className="totp-timer"
          title={t('txt_refresh_in_seconds_s', { seconds: props.live ? props.live.remain : 0 })}
          aria-label={t('txt_refresh_in_seconds_s', { seconds: props.live ? props.live.remain : 0 })}
        >
          <svg viewBox="0 0 36 36" className="totp-ring" role="presentation" aria-hidden="true">
            <circle className="totp-ring-track" cx="18" cy="18" r={TOTP_RING_RADIUS} />
            <circle
              className="totp-ring-progress"
              cx="18"
              cy="18"
              r={TOTP_RING_RADIUS}
              style={{
                strokeDasharray: `${TOTP_RING_CIRCUMFERENCE} ${TOTP_RING_CIRCUMFERENCE}`,
                strokeDashoffset: String(
                  TOTP_RING_CIRCUMFERENCE -
                    TOTP_RING_CIRCUMFERENCE *
                      (Math.max(0, Math.min(TOTP_PERIOD_SECONDS, props.live?.remain ?? 0)) / TOTP_PERIOD_SECONDS)
                ),
              }}
            />
          </svg>
          <span className="totp-timer-value">{props.live ? props.live.remain : 0}</span>
        </div>
        <button type="button" className="btn btn-secondary small totp-copy-btn" onClick={() => props.onCopy(props.live?.code || '')} aria-label={t('txt_copy')}>
          <Clipboard size={14} className="btn-icon" />
        </button>
      </div>
    </div>
  );
}

export default function TotpCodesPage(props: TotpCodesPageProps) {
  const [totpMap, setTotpMap] = useState<Record<string, { code: string; remain: number } | null>>({});
  const [columnCount, setColumnCount] = useState(1);
  const [orderedIds, setOrderedIds] = useState<string[]>(() => {
    if (typeof window === 'undefined') return [];
    try {
      const parsed = JSON.parse(String(window.localStorage.getItem(TOTP_ORDER_STORAGE_KEY) || '[]'));
      return Array.isArray(parsed) ? parsed.map((id) => String(id || '').trim()).filter(Boolean) : [];
    } catch {
      return [];
    }
  });
  const listRef = useRef<HTMLDivElement | null>(null);
  const hasLoadedTotpItemsRef = useRef(false);
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

  async function copyToClipboard(value: string): Promise<void> {
    await copyTextWithFeedback(value, { successMessage: t('txt_code_copied') });
  }

  const baseTotpItems = useMemo(
    () =>
      props.ciphers
        .filter((cipher) => isCipherVisibleInNormalVault(cipher) && !!cipher.login?.decTotp)
        .sort((a, b) => {
          const nameA = (a.decName || a.name || '').trim().toLowerCase();
          const nameB = (b.decName || b.name || '').trim().toLowerCase();
          return nameA.localeCompare(nameB);
        }),
    [props.ciphers]
  );

  const totpItems = useMemo(() => {
    if (!baseTotpItems.length) return [];
    const orderMap = new Map(orderedIds.map((id, index) => [id, index]));
    return [...baseTotpItems].sort((a, b) => {
      const orderA = orderMap.get(a.id);
      const orderB = orderMap.get(b.id);
      if (orderA != null && orderB != null) return orderA - orderB;
      if (orderA != null) return -1;
      if (orderB != null) return 1;
      const nameA = (a.decName || a.name || '').trim().toLowerCase();
      const nameB = (b.decName || b.name || '').trim().toLowerCase();
      return nameA.localeCompare(nameB);
    });
  }, [baseTotpItems, orderedIds]);

  useEffect(() => {
    if (!baseTotpItems.length) return;
    hasLoadedTotpItemsRef.current = true;
    const validIds = new Set(baseTotpItems.map((cipher) => cipher.id));
    setOrderedIds((prev) => {
      const filtered = prev.filter((id) => validIds.has(id));
      const missing = baseTotpItems.map((cipher) => cipher.id).filter((id) => !filtered.includes(id));
      const next = [...filtered, ...missing];
      if (next.length === prev.length && next.every((id, index) => id === prev[index])) return prev;
      return next;
    });
  }, [baseTotpItems]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    if (!hasLoadedTotpItemsRef.current) return;
    try {
      window.localStorage.setItem(TOTP_ORDER_STORAGE_KEY, JSON.stringify(orderedIds));
    } catch {
      // ignore storage write failures
    }
  }, [orderedIds]);

  useEffect(() => {
    if (!totpItems.length) {
      setTotpMap({});
      return;
    }
    let stopped = false;
    let timer = 0;
    const tick = async () => {
      const entries = await Promise.all(
        totpItems.map(async (cipher) => {
          try {
            const next = await calcTotpNow(cipher.login?.decTotp || '');
            return [cipher.id, next] as const;
          } catch {
            return [cipher.id, null] as const;
          }
        })
      );
      if (!stopped) setTotpMap(Object.fromEntries(entries));
    };
    void tick();
    timer = window.setInterval(() => void tick(), 1000);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [totpItems]);

  useEffect(() => {
    const element = listRef.current;
    if (!element) return;

    const gap = 10;
    const minCardWidth = 320;
    const maxColumns = 4;

    const updateColumns = () => {
      const width = element.clientWidth;
      if (!width) return;
      const next = Math.max(1, Math.min(maxColumns, Math.floor((width + gap) / (minCardWidth + gap))));
      setColumnCount(next);
    };

    updateColumns();
    const observer = new ResizeObserver(() => updateColumns());
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const handleDragEnd = (event: DragEndEvent) => {
    const activeId = String(event.active.id);
    const overId = event.over ? String(event.over.id) : null;
    if (!overId || activeId === overId) return;
    const fromIndex = orderedIds.indexOf(activeId);
    const toIndex = orderedIds.indexOf(overId);
    if (fromIndex === -1 || toIndex === -1 || fromIndex === toIndex) return;
    setOrderedIds((prev) => arrayMove(prev, fromIndex, toIndex));
  };

  return (
    <div className="totp-codes-page">
      <div className="card">
        <div className="section-head">
          <h3 className="detail-title">{t('txt_verification_code')}</h3>
        </div>
        <div
          ref={listRef}
          className="totp-codes-list"
          style={{ '--totp-columns': String(columnCount) } as Record<string, string>}
        >
          {!totpItems.length && !props.loading && <div className="empty">{t('txt_no_verification_codes')}</div>}
          <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
            <SortableContext items={totpItems.map((cipher) => cipher.id)} strategy={rectSortingStrategy}>
              {totpItems.map((cipher) => (
                <SortableTotpRow
                  key={cipher.id}
                  cipher={cipher}
                  live={totpMap[cipher.id] || null}
                  onCopy={(value) => void copyToClipboard(value)}
                />
              ))}
            </SortableContext>
          </DndContext>
        </div>
      </div>
    </div>
  );
}
