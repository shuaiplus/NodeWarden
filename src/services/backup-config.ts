import type { Env, User } from '../types';
import { StorageService } from './storage';
import {
  type BackupSettingsPortableEnvelope,
  decryptBackupSettingsRuntime,
  encryptBackupSettingsEnvelope,
  parseBackupSettingsEnvelope,
} from './backup-settings-crypto';
import {
  BACKUP_DEFAULT_INTERVAL_HOURS,
  BACKUP_DEFAULT_START_TIME,
  BACKUP_DEFAULT_TIMEZONE,
  type BackupDestinationConfig,
  type BackupDestinationRecord,
  type BackupDestinationType,
  type BackupRuntimeState,
  type BackupScheduleConfig,
  type BackupSettings,
  type E3BackupDestination,
  type WebDavBackupDestination,
  createBackupRandomId,
  createDefaultBackupDestinationName,
  createDefaultBackupScheduleConfig,
  createDefaultBackupSettings as createSharedDefaultBackupSettings,
} from '../../shared/backup-schema';

export const BACKUP_SETTINGS_CONFIG_KEY = 'backup.settings.v1';
export const BACKUP_SCHEDULER_WINDOW_MINUTES = 5;
const MAX_BACKUP_DESTINATIONS = 24;

export type {
  BackupDestinationConfig,
  BackupDestinationRecord,
  BackupDestinationType,
  BackupRuntimeState,
  BackupScheduleConfig,
  BackupSettings,
  E3BackupDestination,
  WebDavBackupDestination,
} from '../../shared/backup-schema';

export interface BackupSettingsInput {
  destinations?: unknown;
}

export interface BackupSettingsRepairState {
  needsRepair: boolean;
  portable: BackupSettingsPortableEnvelope | null;
}

function defaultScheduleConfig(timezone: string = 'UTC'): BackupScheduleConfig {
  return { ...createDefaultBackupScheduleConfig(assertValidTimeZone(timezone)) };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asTrimmedString(value: unknown): string {
  return String(value ?? '').trim();
}

function normalizePath(value: unknown): string {
  return asTrimmedString(value).replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
}

function assertValidTimeZone(timezone: string): string {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: timezone }).format(new Date());
    return timezone;
  } catch {
    throw new Error('Invalid backup timezone');
  }
}

function normalizeRetentionCount(value: unknown, fallback: number | null = 30): number | null {
  if (value === undefined) return fallback;
  if (value === null || String(value).trim() === '') return null;
  const count = Number(value);
  if (!Number.isInteger(count) || count < 1 || count > 1000) {
    throw new Error('Backup retention count must be between 1 and 1000');
  }
  return count;
}

function normalizeIntervalHours(value: unknown, fallback: number = BACKUP_DEFAULT_INTERVAL_HOURS): number {
  const raw = value === undefined || value === null || value === '' ? fallback : Number(value);
  if (!Number.isInteger(raw) || raw < 1 || raw > 99) {
    throw new Error('Backup interval hours must be between 1 and 99');
  }
  return raw;
}

function normalizeStartTime(value: unknown, fallback: string = BACKUP_DEFAULT_START_TIME): string {
  const raw = asTrimmedString(value) || fallback;
  const match = raw.match(/^(\d{1,2})(?::(\d{1,2}))?$/);
  if (!match) {
    throw new Error('Backup start time must be in HH:mm format');
  }
  const hour = Number(match[1]);
  const minute = Number(match[2] ?? '0');
  if (!Number.isInteger(hour) || !Number.isInteger(minute) || hour < 0 || hour > 23 || minute < 0 || minute > 59) {
    throw new Error('Backup start time must be in HH:mm format');
  }
  return `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`;
}

function normalizeE3Destination(value: unknown, allowIncomplete = false): E3BackupDestination {
  const source = isPlainObject(value) ? value : {};
  const endpoint = asTrimmedString(source.endpoint);
  const bucket = asTrimmedString(source.bucket);
  const accessKeyId = asTrimmedString(source.accessKeyId);
  const secretAccessKey = asTrimmedString(source.secretAccessKey);
  const region = asTrimmedString(source.region) || 'auto';
  const rootPath = normalizePath(source.rootPath);

  if (!allowIncomplete || endpoint) {
    if (!endpoint) throw new Error('E3 endpoint is required');
    if (!/^https?:\/\//i.test(endpoint)) throw new Error('E3 endpoint must start with http:// or https://');
  }
  if (!allowIncomplete || bucket) {
    if (!bucket) throw new Error('E3 bucket is required');
  }
  if (!allowIncomplete || accessKeyId) {
    if (!accessKeyId) throw new Error('E3 access key is required');
  }
  if (!allowIncomplete || secretAccessKey) {
    if (!secretAccessKey) throw new Error('E3 secret key is required');
  }

  return {
    endpoint: endpoint ? endpoint.replace(/\/+$/, '') : '',
    bucket,
    region,
    accessKeyId,
    secretAccessKey,
    rootPath,
  };
}

function normalizeWebDavDestination(value: unknown, allowIncomplete = false): WebDavBackupDestination {
  const source = isPlainObject(value) ? value : {};
  const baseUrl = asTrimmedString(source.baseUrl);
  const username = asTrimmedString(source.username);
  const password = String(source.password ?? '');
  const remotePath = normalizePath(source.remotePath);

  if (!allowIncomplete || baseUrl) {
    if (!baseUrl) throw new Error('WebDAV server URL is required');
    if (!/^https?:\/\//i.test(baseUrl)) throw new Error('WebDAV server URL must start with http:// or https://');
  }
  if (!allowIncomplete || username) {
    if (!username) throw new Error('WebDAV username is required');
  }
  if (!allowIncomplete || password) {
    if (!password) throw new Error('WebDAV password is required');
  }

  return {
    baseUrl: baseUrl ? baseUrl.replace(/\/+$/, '') : '',
    username,
    password,
    remotePath,
  };
}

function normalizeDestination(
  destinationType: BackupDestinationType,
  destination: unknown,
  allowIncomplete = false
): BackupDestinationConfig {
  if (destinationType === 'e3') return normalizeE3Destination(destination, allowIncomplete);
  return normalizeWebDavDestination(destination, allowIncomplete);
}

function normalizeRuntime(value: unknown): BackupRuntimeState {
  const source = isPlainObject(value) ? value : {};
  const asIso = (input: unknown): string | null => {
    const raw = asTrimmedString(input);
    if (!raw) return null;
    const date = new Date(raw);
    return Number.isFinite(date.getTime()) ? date.toISOString() : null;
  };
  const asMaybeNumber = (input: unknown): number | null => {
    if (input === null || input === undefined || input === '') return null;
    const n = Number(input);
    return Number.isFinite(n) && n >= 0 ? Math.floor(n) : null;
  };
  return {
    lastAttemptAt: asIso(source.lastAttemptAt),
    lastAttemptLocalDate: asTrimmedString(source.lastAttemptLocalDate) || null,
    lastSuccessAt: asIso(source.lastSuccessAt),
    lastErrorAt: asIso(source.lastErrorAt),
    lastErrorMessage: asTrimmedString(source.lastErrorMessage) || null,
    lastUploadedFileName: asTrimmedString(source.lastUploadedFileName) || null,
    lastUploadedSizeBytes: asMaybeNumber(source.lastUploadedSizeBytes),
    lastUploadedDestination: asTrimmedString(source.lastUploadedDestination) || null,
  };
}

function defaultDestinationName(type: BackupDestinationType, index: number): string {
  return createDefaultBackupDestinationName(type, index);
}

function getDestinationType(raw: unknown): BackupDestinationType {
  const value = asTrimmedString(raw);
  if (value === 'e3' || value === 'webdav') return value;
  throw new Error('Backup destination type is invalid');
}

function normalizeDestinationRecord(
  input: unknown,
  previousById: Map<string, BackupDestinationRecord>,
  index: number,
  fallbackTimezone: string
): BackupDestinationRecord {
  if (!isPlainObject(input)) {
    throw new Error('Backup destination is invalid');
  }

  const id = asTrimmedString(input.id) || createBackupRandomId();
  const type = getDestinationType(input.type);
  const previous = previousById.get(id);
  const runtime = previous?.runtime ? normalizeRuntime(previous.runtime) : normalizeRuntime(input.runtime);
  const name = asTrimmedString(input.name) || previous?.name || defaultDestinationName(type, index + 1);
  const scheduleSource = isPlainObject(input.schedule) ? input.schedule : {};
  const previousSchedule = previous?.schedule || defaultScheduleConfig(fallbackTimezone);
  const retentionSource = Object.prototype.hasOwnProperty.call(scheduleSource, 'retentionCount')
    ? scheduleSource.retentionCount
    : previousSchedule.retentionCount;
  const schedule: BackupScheduleConfig = {
    enabled: !!(scheduleSource.enabled ?? previousSchedule.enabled),
    intervalHours: normalizeIntervalHours(
      scheduleSource.intervalHours ?? previousSchedule.intervalHours,
      previousSchedule.intervalHours || BACKUP_DEFAULT_INTERVAL_HOURS
    ),
    startTime: normalizeStartTime(
      scheduleSource.startTime ?? previousSchedule.startTime,
      previousSchedule.startTime || BACKUP_DEFAULT_START_TIME
    ),
    timezone: assertValidTimeZone(asTrimmedString(scheduleSource.timezone ?? previousSchedule.timezone) || fallbackTimezone || BACKUP_DEFAULT_TIMEZONE),
    retentionCount: normalizeRetentionCount(retentionSource, previousSchedule.retentionCount),
  };

  const destination = normalizeDestination(type, input.destination, !schedule.enabled);

  return {
    id,
    name,
    type,
    includeAttachments: typeof input.includeAttachments === 'boolean'
      ? input.includeAttachments
      : previous?.includeAttachments ?? false,
    destination,
    schedule,
    runtime,
  };
}

function parseLegacyBackupSettings(rawValue: Record<string, unknown>, fallbackTimezone: string): BackupSettings {
  const legacyFrequency = asTrimmedString(rawValue.frequency).toLowerCase();
  const intervalHours = legacyFrequency === 'weekly'
    ? 24 * 7
    : legacyFrequency === 'monthly'
      ? 24 * 30
      : BACKUP_DEFAULT_INTERVAL_HOURS;
  const destinationTypeRaw = asTrimmedString(rawValue.destinationType);
  const destinationType: BackupDestinationType =
    destinationTypeRaw === 'e3' || destinationTypeRaw === 'webdav'
      ? destinationTypeRaw
      : 'webdav';
  const destination = {
    id: createBackupRandomId(),
    name: defaultDestinationName(destinationType, 1),
    type: destinationType,
    includeAttachments: false,
    destination: normalizeDestination(destinationType, rawValue.destination),
    schedule: {
      enabled: !!rawValue.enabled,
      intervalHours,
      startTime: BACKUP_DEFAULT_START_TIME,
      timezone: assertValidTimeZone(asTrimmedString(rawValue.timezone) || fallbackTimezone || BACKUP_DEFAULT_TIMEZONE),
      retentionCount: 30,
    },
    runtime: normalizeRuntime(rawValue.runtime),
  } satisfies BackupDestinationRecord;

  return {
    destinations: [destination],
  };
}

function parseDestinations(
  rawDestinations: unknown,
  previousById: Map<string, BackupDestinationRecord>,
  fallbackTimezone: string
): BackupDestinationRecord[] {
  if (!Array.isArray(rawDestinations)) {
    throw new Error('Backup destinations are invalid');
  }
  if (rawDestinations.length > MAX_BACKUP_DESTINATIONS) {
    throw new Error(`You can save up to ${MAX_BACKUP_DESTINATIONS} backup destinations`);
  }

  const destinations = rawDestinations.map((entry, index) => normalizeDestinationRecord(entry, previousById, index, fallbackTimezone));
  const ids = new Set<string>();
  for (const destination of destinations) {
    if (ids.has(destination.id)) {
      throw new Error('Backup destination ids must be unique');
    }
    ids.add(destination.id);
  }
  return destinations;
}

function mapDestinationsById(destinations: BackupDestinationRecord[]): Map<string, BackupDestinationRecord> {
  return new Map(destinations.map((destination) => [destination.id, destination]));
}

export function getDefaultBackupSettings(timezone: string = 'UTC'): BackupSettings {
  return createSharedDefaultBackupSettings(assertValidTimeZone(timezone));
}

export function parseBackupSettings(raw: string | null, fallbackTimezone: string = 'UTC'): BackupSettings {
  if (!raw) return getDefaultBackupSettings(fallbackTimezone);
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (Array.isArray(parsed.destinations)) {
      const globalTimezone = assertValidTimeZone(asTrimmedString(parsed.timezone) || fallbackTimezone || BACKUP_DEFAULT_TIMEZONE);
      const globalEnabled = !!parsed.enabled;
      const activeDestinationIdRaw = asTrimmedString(parsed.activeDestinationId);
      const globalFrequency = asTrimmedString(parsed.frequency).toLowerCase();
      const globalIntervalHours = globalFrequency === 'weekly'
        ? 24 * 7
        : globalFrequency === 'monthly'
          ? 24 * 30
          : BACKUP_DEFAULT_INTERVAL_HOURS;
      const previousById = new Map<string, BackupDestinationRecord>();
      const normalizedEntries = (parsed.destinations as unknown[]).map((entry) => {
        if (!isPlainObject(entry)) return entry;
        if (isPlainObject(entry.schedule)) return entry;
        const entryId = asTrimmedString(entry.id);
        const scheduleEnabled = globalEnabled && (!activeDestinationIdRaw || entryId === activeDestinationIdRaw);
        return {
          ...entry,
          schedule: {
            enabled: scheduleEnabled,
            intervalHours: globalIntervalHours,
            startTime: BACKUP_DEFAULT_START_TIME,
            timezone: globalTimezone,
            retentionCount: 30,
          },
        };
      });
      return {
        destinations: parseDestinations(normalizedEntries, previousById, fallbackTimezone),
      };
    }
    return parseLegacyBackupSettings(parsed, fallbackTimezone);
  } catch {
    return getDefaultBackupSettings(fallbackTimezone);
  }
}

export function normalizeBackupSettingsInput(
  input: BackupSettingsInput,
  previous: BackupSettings
): BackupSettings {
  if (!isPlainObject(input)) {
    throw new Error('Backup settings payload is invalid');
  }

  const previousById = mapDestinationsById(previous.destinations);
  const rawDestinations = input.destinations ?? previous.destinations;
  const destinations = parseDestinations(rawDestinations, previousById, BACKUP_DEFAULT_TIMEZONE);

  return {
    destinations,
  };
}

export function serializeBackupSettings(settings: BackupSettings): string {
  return JSON.stringify(settings);
}

export async function loadBackupSettings(storage: StorageService, env: Env, fallbackTimezone: string = 'UTC'): Promise<BackupSettings> {
  const raw = await storage.getConfigValue(BACKUP_SETTINGS_CONFIG_KEY);
  if (!raw) {
    const settings = getDefaultBackupSettings(fallbackTimezone);
    await saveBackupSettings(storage, env, settings);
    return settings;
  }

  const envelope = parseBackupSettingsEnvelope(raw);
  if (!envelope) {
    const settings = parseBackupSettings(raw, fallbackTimezone);
    await saveBackupSettings(storage, env, settings);
    return settings;
  }

  try {
    const decrypted = await decryptBackupSettingsRuntime(raw, env);
    return parseBackupSettings(decrypted, fallbackTimezone);
  } catch {
    throw new Error('Backup settings need administrator reactivation after restore');
  }
}

export async function saveBackupSettings(storage: StorageService, env: Env, settings: BackupSettings): Promise<void> {
  const users = await storage.getAllUsers();
  const hasPortableAdmins = users.some(
    (user) => user.role === 'admin' && user.status === 'active' && typeof user.publicKey === 'string' && user.publicKey.trim().length > 0
  );
  if (!hasPortableAdmins) {
    await storage.setConfigValue(BACKUP_SETTINGS_CONFIG_KEY, serializeBackupSettings(settings));
    return;
  }
  const encrypted = await encryptBackupSettingsEnvelope(serializeBackupSettings(settings), env, users);
  await storage.setConfigValue(BACKUP_SETTINGS_CONFIG_KEY, encrypted);
}

export async function normalizeImportedBackupSettings(storage: StorageService, env: Env, fallbackTimezone: string = 'UTC'): Promise<void> {
  const raw = await storage.getConfigValue(BACKUP_SETTINGS_CONFIG_KEY);
  if (!raw) return;
  const users = await storage.getAllUsers();
  const normalized = await normalizeImportedBackupSettingsValue(raw, env, users, fallbackTimezone);
  if (normalized !== null) {
    await storage.setConfigValue(BACKUP_SETTINGS_CONFIG_KEY, normalized);
  }
}

export async function normalizeImportedBackupSettingsValue(
  raw: string | null,
  env: Env,
  users: Pick<User, 'id' | 'publicKey' | 'role' | 'status'>[],
  fallbackTimezone: string = 'UTC'
): Promise<string | null> {
  if (!raw) return null;
  const envelope = parseBackupSettingsEnvelope(raw);
  if (envelope) {
    try {
      const decrypted = await decryptBackupSettingsRuntime(raw, env);
      const settings = parseBackupSettings(decrypted, fallbackTimezone);
      const hasPortableAdmins = users.some(
        (user) => user.role === 'admin' && user.status === 'active' && typeof user.publicKey === 'string' && user.publicKey.trim().length > 0
      );
      if (!hasPortableAdmins) {
        return serializeBackupSettings(settings);
      }
      return encryptBackupSettingsEnvelope(serializeBackupSettings(settings), env, users);
    } catch {
      // Keep imported portable recovery data intact until an admin signs in and repairs it.
      return raw;
    }
  }
  const settings = parseBackupSettings(raw, fallbackTimezone);
  const hasPortableAdmins = users.some(
    (user) => user.role === 'admin' && user.status === 'active' && typeof user.publicKey === 'string' && user.publicKey.trim().length > 0
  );
  if (!hasPortableAdmins) {
    return serializeBackupSettings(settings);
  }
  return encryptBackupSettingsEnvelope(serializeBackupSettings(settings), env, users);
}

export async function getBackupSettingsRepairState(storage: StorageService, env: Env, fallbackTimezone: string = 'UTC'): Promise<BackupSettingsRepairState> {
  const raw = await storage.getConfigValue(BACKUP_SETTINGS_CONFIG_KEY);
  if (!raw) {
    const settings = getDefaultBackupSettings(fallbackTimezone);
    await saveBackupSettings(storage, env, settings);
    return { needsRepair: false, portable: null };
  }

  const envelope = parseBackupSettingsEnvelope(raw);
  if (!envelope) {
    const settings = parseBackupSettings(raw, fallbackTimezone);
    await saveBackupSettings(storage, env, settings);
    return { needsRepair: false, portable: null };
  }

  try {
    await decryptBackupSettingsRuntime(raw, env);
    return { needsRepair: false, portable: null };
  } catch {
    return {
      needsRepair: true,
      portable: envelope.portable,
    };
  }
}

export async function repairBackupSettings(storage: StorageService, env: Env, settings: BackupSettings): Promise<void> {
  await saveBackupSettings(storage, env, settings);
}

export function findBackupDestination(
  settings: BackupSettings,
  destinationId: string | null | undefined
): BackupDestinationRecord | null {
  const normalizedId = asTrimmedString(destinationId);
  if (!normalizedId) return null;
  return settings.destinations.find((destination) => destination.id === normalizedId) || null;
}

export function requireBackupDestination(settings: BackupSettings, destinationId?: string | null): BackupDestinationRecord {
  const destination = destinationId ? findBackupDestination(settings, destinationId) : settings.destinations[0] || null;
  if (!destination) {
    throw new Error('Backup destination not found');
  }
  return destination;
}

function getDateTimeParts(date: Date, timezone: string): { year: string; month: string; day: string; hour: string; minute: string } {
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: timezone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  });
  const parts = formatter.formatToParts(date);
  const pick = (type: string): string => parts.find((part) => part.type === type)?.value || '';
  return {
    year: pick('year'),
    month: pick('month'),
    day: pick('day'),
    hour: pick('hour'),
    minute: pick('minute'),
  };
}

export function getBackupLocalDateKey(date: Date, timezone: string): string {
  const parts = getDateTimeParts(date, timezone);
  return `${parts.year}-${parts.month}-${parts.day}`;
}

export function getBackupLocalTime(date: Date, timezone: string): string {
  const parts = getDateTimeParts(date, timezone);
  return `${parts.hour}:${parts.minute}`;
}

function parseLocalDateKey(dateKey: string): { year: number; month: number; day: number } | null {
  const match = String(dateKey || '').match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (!Number.isInteger(year) || !Number.isInteger(month) || !Number.isInteger(day)) return null;
  return { year, month, day };
}

function getUtcDateForLocalTime(timezone: string, year: number, month: number, day: number, hour: number, minute: number): Date {
  const utcGuess = Date.UTC(year, month - 1, day, hour, minute, 0, 0);
  const actual = getDateTimeParts(new Date(utcGuess), timezone);
  const actualUtc = Date.UTC(
    Number(actual.year),
    Number(actual.month) - 1,
    Number(actual.day),
    Number(actual.hour),
    Number(actual.minute),
    0,
    0
  );
  const desiredUtc = Date.UTC(year, month - 1, day, hour, minute, 0, 0);
  return new Date(utcGuess - (actualUtc - desiredUtc));
}

function getBackupSlotStartsForLocalDay(
  dateKey: string,
  timezone: string,
  startTime: string,
  intervalHours: number
): Date[] {
  const parsedDate = parseLocalDateKey(dateKey);
  const parsedTime = normalizeStartTime(startTime).split(':').map((value) => Number(value));
  if (!parsedDate || parsedTime.length !== 2) return [];

  const [hour, minute] = parsedTime;
  const firstSlot = getUtcDateForLocalTime(timezone, parsedDate.year, parsedDate.month, parsedDate.day, hour, minute);
  const nextLocalDay = new Date(Date.UTC(parsedDate.year, parsedDate.month - 1, parsedDate.day, 0, 0, 0, 0));
  nextLocalDay.setUTCDate(nextLocalDay.getUTCDate() + 1);
  const nextDay = getUtcDateForLocalTime(
    timezone,
    nextLocalDay.getUTCFullYear(),
    nextLocalDay.getUTCMonth() + 1,
    nextLocalDay.getUTCDate(),
    0,
    0
  );
  const intervalMs = intervalHours * 60 * 60 * 1000;
  const slots: Date[] = [];

  for (let slotMs = firstSlot.getTime(); slotMs < nextDay.getTime(); slotMs += intervalMs) {
    slots.push(new Date(slotMs));
  }
  return slots;
}

export function isBackupDueNow(
  destination: BackupDestinationRecord,
  now: Date,
  windowMinutes: number = BACKUP_SCHEDULER_WINDOW_MINUTES
): boolean {
  if (!destination.schedule.enabled) return false;
  const toleranceMs = Math.max(1, windowMinutes) * 60 * 1000;
  const lastAttemptAt = destination.runtime.lastAttemptAt ? new Date(destination.runtime.lastAttemptAt) : null;
  const lastAttemptMs = lastAttemptAt && Number.isFinite(lastAttemptAt.getTime())
    ? lastAttemptAt.getTime()
    : Number.NEGATIVE_INFINITY;
  const localDateKey = getBackupLocalDateKey(now, destination.schedule.timezone);
  const slotStarts = getBackupSlotStartsForLocalDay(
    localDateKey,
    destination.schedule.timezone,
    destination.schedule.startTime,
    destination.schedule.intervalHours
  );

  for (const slotStart of slotStarts) {
    const slotStartMs = slotStart.getTime();
    if (now.getTime() < slotStartMs || now.getTime() >= slotStartMs + toleranceMs) continue;
    if (lastAttemptMs >= slotStartMs) return false;
    return true;
  }
  return false;
}
