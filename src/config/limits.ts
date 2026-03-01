export const LIMITS = {
  auth: {
    // Access token lifetime in seconds.
    // 访问令牌有效期（秒）。
    accessTokenTtlSeconds: 7200,
    // Refresh token lifetime in milliseconds.
    // 刷新令牌有效期（毫秒）。
    refreshTokenTtlMs: 30 * 24 * 60 * 60 * 1000,
    // Grace window for previous refresh token after rotation (ms).
    // 刷新令牌轮换后的旧令牌宽限窗口（毫秒）。
    refreshTokenOverlapGraceMs: 60 * 1000,
    // Refresh token random byte length.
    // 刷新令牌随机字节长度。
    refreshTokenRandomBytes: 32,
    // Attachment download token lifetime in seconds.
    // 附件下载令牌有效期（秒）。
    fileDownloadTokenTtlSeconds: 300,
    // Send access token lifetime in seconds.
    // Send 访问令牌有效期（秒）。
    sendAccessTokenTtlSeconds: 300,
    // Minimum required JWT secret length.
    // JWT 密钥最小长度要求。
    jwtSecretMinLength: 32,
    // Default PBKDF2 iterations for account creation/prelogin fallback.
    // 账户创建与预登录回退使用的默认 PBKDF2 迭代次数。
    defaultKdfIterations: 600000,
  },
  rateLimit: {
    // Max failed login attempts before temporary lock.
    // 触发临时锁定前允许的最大登录失败次数。
    loginMaxAttempts: 10,
    // Login lock duration in minutes.
    // 登录锁定时长（分钟）。
    loginLockoutMinutes: 2,
    // Write API request budget per minute.
    // 写操作 API 每分钟请求配额。
    apiWriteRequestsPerMinute: 120,
    // /api/sync read request budget per minute.
    // /api/sync 读请求每分钟配额。
    syncReadRequestsPerMinute: 1000,
    // /api/devices/knowndevice probe budget per IP per minute.
    // /api/devices/knowndevice 每 IP 每分钟探测配额。
    knownDeviceRequestsPerMinute: 10,
    // Public Send access budget per IP per minute.
    // 公共 Send 访问接口每 IP 每分钟配额。
    publicSendRequestsPerMinute: 60,
    // Fixed window size for API rate limiting in seconds.
    // API 限流固定窗口大小（秒）。
    apiWindowSeconds: 60,
    // Probability to run low-frequency cleanup on request path.
    // 在请求路径中触发低频清理的概率。
    cleanupProbability: 0.05,
    // Minimum interval between login-attempt cleanup runs.
    // 登录尝试表清理的最小间隔。
    loginIpCleanupIntervalMs: 10 * 60 * 1000,
    // Minimum interval between API-window cleanup runs.
    // API 窗口计数清理的最小间隔。
    apiWindowCleanupIntervalMs: 5 * 60 * 1000,
    // Retention window for login IP records.
    // 登录 IP 记录保留时长。
    loginIpRetentionMs: 30 * 24 * 60 * 60 * 1000,
    // Number of historical API windows to keep.
    // 保留的历史 API 窗口数量。
    apiWindowRetentionWindows: 120,
  },
  cleanup: {
    // Minimum interval between refresh-token cleanup runs.
    // refresh_token 表清理最小间隔。
    refreshTokenCleanupIntervalMs: 30 * 60 * 1000,
    // Minimum interval between used attachment token cleanup runs.
    // 已使用附件令牌表清理最小间隔。
    attachmentTokenCleanupIntervalMs: 10 * 60 * 1000,
    // Probability to trigger cleanup during requests.
    // 请求过程中触发清理的概率。
    cleanupProbability: 0.05,
  },
  attachment: {
    // Max attachment upload size in bytes.
    // 附件上传大小上限（字节）。
    maxFileSizeBytes: 100 * 1024 * 1024,
  },
  send: {
    // Max file size allowed for Send file uploads.
    // Send 文件上传大小上限。
    maxFileSizeBytes: 550_502_400,
    // Max days allowed between now and deletion date.
    // 允许的最远删除日期（距当前天数）。
    maxDeletionDays: 31,
  },
  pagination: {
    // Default page size when client does not specify pageSize.
    // 客户端未传 pageSize 时的默认分页大小。
    defaultPageSize: 100,
    // Hard maximum page size accepted by server.
    // 服务端允许的最大分页大小。
    maxPageSize: 500,
  },
  cors: {
    // Browser preflight cache max age in seconds.
    // 浏览器预检请求缓存时长（秒）。
    preflightMaxAgeSeconds: 86400,
  },
  cache: {
    // Icon proxy cache TTL in seconds.
    // 图标代理缓存时长（秒）。
    iconTtlSeconds: 604800,
    // In-memory /api/sync response cache TTL (milliseconds).
    // /api/sync 内存缓存有效期（毫秒）。
    syncResponseTtlMs: 30 * 1000,
    // Max in-memory /api/sync cache entries per isolate.
    // 每个 isolate 的 /api/sync 最大缓存条目数。
    syncResponseMaxEntries: 64,
  },
  performance: {
    // Max IDs per SQL batch when moving ciphers in bulk.
    // 批量移动密码项时每批 SQL 的最大 ID 数量。
    bulkMoveChunkSize: 200,
  },
  compatibility: {
    // Single source of truth for /config.version and /api/version.
    // /config.version 与 /api/version 的统一版本号来源。
    bitwardenServerVersion: '2026.1.0',
  },
} as const;
