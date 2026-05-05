import type { DomainRulesResponse } from '../types';
import { StorageService } from './storage';
import {
  BITWARDEN_GLOBAL_DOMAIN_RULE_TYPES,
  cloneBitwardenGlobalDomainRules,
} from './domain-rules-defaults';

const DOMAIN_RULES_CONFIG_PREFIX = 'settings.domains.v1:';
const DOMAIN_RULES_STANDARD_KEYS = new Set([
  'equivalentDomains',
  'EquivalentDomains',
  'globalEquivalentDomains',
  'GlobalEquivalentDomains',
  'excludedGlobalEquivalentDomains',
  'ExcludedGlobalEquivalentDomains',
  'object',
  'Object',
]);

interface StoredDomainRulesRecord {
  equivalentDomains: string[][];
  excludedGlobalEquivalentDomains: number[];
  passthrough: Record<string, unknown>;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function getAliasedValue(source: Record<string, unknown>, keys: string[]): unknown {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      return source[key];
    }
  }
  return undefined;
}

function normalizeDomainValue(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  return normalized || null;
}

function normalizeEquivalentDomains(
  value: unknown,
  options: { rejectInvalid: boolean }
): string[][] {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    if (options.rejectInvalid) throw new Error('equivalentDomains must be an array of domain groups');
    return [];
  }

  const groups: string[][] = [];
  for (const group of value) {
    if (!Array.isArray(group)) {
      if (options.rejectInvalid) throw new Error('equivalentDomains must be an array of domain groups');
      return [];
    }

    const deduped: string[] = [];
    const seen = new Set<string>();
    for (const entry of group) {
      const normalized = normalizeDomainValue(entry);
      if (!normalized) {
        if (options.rejectInvalid) throw new Error('each domain rule must be a non-empty string');
        return [];
      }
      if (seen.has(normalized)) continue;
      seen.add(normalized);
      deduped.push(normalized);
    }

    if (deduped.length === 0) {
      if (options.rejectInvalid) throw new Error('domain rule groups cannot be empty');
      return [];
    }

    groups.push(deduped);
  }

  return groups;
}

function normalizeExcludedGlobalEquivalentDomains(
  value: unknown,
  options: { rejectInvalid: boolean }
): number[] {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    if (options.rejectInvalid) throw new Error('excludedGlobalEquivalentDomains must be an array');
    return [];
  }

  const types: number[] = [];
  const seen = new Set<number>();
  for (const entry of value) {
    const type = typeof entry === 'number' ? entry : Number(entry);
    if (!Number.isInteger(type) || !BITWARDEN_GLOBAL_DOMAIN_RULE_TYPES.has(type)) {
      if (options.rejectInvalid) throw new Error('excludedGlobalEquivalentDomains contains an unknown global domain type');
      continue;
    }
    if (seen.has(type)) continue;
    seen.add(type);
    types.push(type);
  }
  return types;
}

function inferExcludedTypesFromGlobalDomainRules(
  value: unknown,
  options: { rejectInvalid: boolean }
): number[] {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    if (options.rejectInvalid) throw new Error('globalEquivalentDomains must be an array');
    return [];
  }

  const types: number[] = [];
  const seen = new Set<number>();
  for (const entry of value) {
    if (typeof entry === 'number' || typeof entry === 'string') {
      const type = Number(entry);
      if (!Number.isInteger(type) || !BITWARDEN_GLOBAL_DOMAIN_RULE_TYPES.has(type)) {
        if (options.rejectInvalid) throw new Error('globalEquivalentDomains contains an unknown global domain type');
        continue;
      }
      if (seen.has(type)) continue;
      seen.add(type);
      types.push(type);
      continue;
    }

    if (!isPlainObject(entry)) {
      if (options.rejectInvalid) throw new Error('globalEquivalentDomains must contain objects');
      continue;
    }

    const rawType = getAliasedValue(entry, ['type', 'Type']);
    const type = typeof rawType === 'number' ? rawType : Number(rawType);
    if (!Number.isInteger(type) || !BITWARDEN_GLOBAL_DOMAIN_RULE_TYPES.has(type)) {
      if (options.rejectInvalid) throw new Error('globalEquivalentDomains contains an unknown global domain type');
      continue;
    }

    const rawExcluded = getAliasedValue(entry, ['excluded', 'Excluded']);
    if (typeof rawExcluded !== 'boolean') {
      if (options.rejectInvalid) throw new Error('globalEquivalentDomains entries must include an excluded flag');
      continue;
    }

    if (!rawExcluded || seen.has(type)) continue;
    seen.add(type);
    types.push(type);
  }

  return types;
}

function buildStoredDomainRulesRecord(
  source: Record<string, unknown>,
  options: { rejectInvalid: boolean }
): StoredDomainRulesRecord {
  const passthrough: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(source)) {
    if (DOMAIN_RULES_STANDARD_KEYS.has(key)) continue;
    passthrough[key] = value;
  }

  const equivalentDomains = normalizeEquivalentDomains(
    getAliasedValue(source, ['equivalentDomains', 'EquivalentDomains']),
    options
  );

  const explicitExcludedValue = getAliasedValue(source, [
    'excludedGlobalEquivalentDomains',
    'ExcludedGlobalEquivalentDomains',
  ]);
  const hasExplicitExcludedTypes = explicitExcludedValue !== undefined;
  const explicitExcludedTypes = normalizeExcludedGlobalEquivalentDomains(
    explicitExcludedValue,
    options
  );

  const excludedGlobalEquivalentDomains = hasExplicitExcludedTypes
    ? explicitExcludedTypes
    : inferExcludedTypesFromGlobalDomainRules(
        getAliasedValue(source, ['globalEquivalentDomains', 'GlobalEquivalentDomains']),
        options
      );

  return {
    equivalentDomains,
    excludedGlobalEquivalentDomains,
    passthrough,
  };
}

function buildStoredDomainRulesPayload(record: StoredDomainRulesRecord): Record<string, unknown> {
  return {
    ...record.passthrough,
    equivalentDomains: record.equivalentDomains,
    excludedGlobalEquivalentDomains: record.excludedGlobalEquivalentDomains,
    object: 'domains',
    EquivalentDomains: record.equivalentDomains,
    ExcludedGlobalEquivalentDomains: record.excludedGlobalEquivalentDomains,
    Object: 'domains',
  };
}

function buildDomainRulesResponse(
  record: StoredDomainRulesRecord,
  options: { includeExcludedGlobalDomains: boolean }
): DomainRulesResponse {
  const globalEquivalentDomains = cloneBitwardenGlobalDomainRules(
    record.excludedGlobalEquivalentDomains,
    options.includeExcludedGlobalDomains
  );

  return {
    ...record.passthrough,
    equivalentDomains: record.equivalentDomains,
    globalEquivalentDomains,
    object: 'domains',
    EquivalentDomains: record.equivalentDomains,
    GlobalEquivalentDomains: globalEquivalentDomains,
    Object: 'domains',
  };
}

function createDefaultDomainRulesRecord(): StoredDomainRulesRecord {
  return {
    equivalentDomains: [],
    excludedGlobalEquivalentDomains: [],
    passthrough: {},
  };
}

function getDomainRulesConfigKey(userId: string): string {
  return `${DOMAIN_RULES_CONFIG_PREFIX}${userId}`;
}

export function createDefaultDomainRulesResponse(
  options: { includeExcludedGlobalDomains?: boolean } = {}
): DomainRulesResponse {
  return buildDomainRulesResponse(createDefaultDomainRulesRecord(), {
    includeExcludedGlobalDomains: options.includeExcludedGlobalDomains ?? true,
  });
}

export async function getDomainRulesForUser(
  storage: StorageService,
  userId: string,
  options: { includeExcludedGlobalDomains?: boolean } = {}
): Promise<DomainRulesResponse> {
  const includeExcludedGlobalDomains = options.includeExcludedGlobalDomains ?? true;
  const stored = await storage.getConfigValue(getDomainRulesConfigKey(userId));
  if (!stored) {
    return createDefaultDomainRulesResponse({ includeExcludedGlobalDomains });
  }

  try {
    const parsed = JSON.parse(stored) as unknown;
    if (!isPlainObject(parsed)) {
      return createDefaultDomainRulesResponse({ includeExcludedGlobalDomains });
    }
    const record = buildStoredDomainRulesRecord(parsed, { rejectInvalid: false });
    return buildDomainRulesResponse(record, { includeExcludedGlobalDomains });
  } catch {
    return createDefaultDomainRulesResponse({ includeExcludedGlobalDomains });
  }
}

export async function saveDomainRulesForUser(
  storage: StorageService,
  userId: string,
  payload: unknown
): Promise<DomainRulesResponse> {
  if (!isPlainObject(payload)) {
    throw new Error('domain rules payload must be a JSON object');
  }

  const record = buildStoredDomainRulesRecord(payload, { rejectInvalid: true });
  await storage.setConfigValue(
    getDomainRulesConfigKey(userId),
    JSON.stringify(buildStoredDomainRulesPayload(record))
  );
  await storage.updateRevisionDate(userId);
  return buildDomainRulesResponse(record, { includeExcludedGlobalDomains: true });
}
