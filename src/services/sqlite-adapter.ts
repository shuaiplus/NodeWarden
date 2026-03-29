import Database from 'better-sqlite3';

export class SqlitePreparedStatement implements D1PreparedStatement {
  constructor(
    private db: Database.Database,
    private query: string,
    private values: any[] = []
  ) {}

  bind(...values: any[]): D1PreparedStatement {
    return new SqlitePreparedStatement(this.db, this.query, values);
  }

  async first<T = unknown>(colName?: string): Promise<T | null> {
    const stmt = this.db.prepare(this.query);
    const result = stmt.get(...this.values) as any;
    if (result === undefined) return null;
    if (colName !== undefined) {
      return result[colName] ?? null;
    }
    return result as T;
  }

  async run<T = unknown>(): Promise<D1Result<T>> {
    const stmt = this.db.prepare(this.query);
    const info = stmt.run(...this.values);
    return {
      success: true,
      meta: {
        duration: 0,
        size_after: 0,
        rows_read: 0,
        rows_written: info.changes,
        last_row_id: Number(info.lastInsertRowid),
        changed_db: info.changes > 0,
        changes: info.changes,
      },
      results: [],
    };
  }

  async all<T = unknown>(): Promise<D1Result<T>> {
    const stmt = this.db.prepare(this.query);
    const results = stmt.all(...this.values) as T[];
    return {
      success: true,
      meta: {
        duration: 0,
        size_after: 0,
        rows_read: results.length,
        rows_written: 0,
        last_row_id: 0,
        changed_db: false,
        changes: 0,
      },
      results,
    };
  }

  raw<T = unknown[]>(options: { columnNames: true }): Promise<[string[], ...T[]]>;
  raw<T = unknown[]>(options?: { columnNames?: false }): Promise<T[]>;
  async raw<T = unknown[]>(options?: { columnNames?: boolean }): Promise<T[] | [string[], ...T[]]> {
    const stmt = this.db.prepare(this.query);
    stmt.raw(true);
    const results = stmt.all(...this.values) as T[];
    if (options?.columnNames) {
      const columns = stmt.columns().map(c => c.name);
      return [columns, ...results] as [string[], ...T[]];
    }
    return results;
  }
}

export class SqliteDatabase implements D1Database {
  private db: Database.Database;

  constructor(filename: string) {
    this.db = new Database(filename);
    this.db.pragma('journal_mode = WAL');
  }

  prepare(query: string): D1PreparedStatement {
    return new SqlitePreparedStatement(this.db, query);
  }

  dump(): Promise<ArrayBuffer> {
    throw new Error('dump() is not implemented in SQLite adapter');
  }

  async batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
    const results: D1Result<T>[] = [];
    
    const performBatch = this.db.transaction((stmts: SqlitePreparedStatement[]) => {
      for (const stmt of stmts) {
        // Access private fields using any
        const query = (stmt as any).query;
        const values = (stmt as any).values;
        const prepared = this.db.prepare(query);
        if (prepared.reader) {
          const rows = prepared.all(...values) as T[];
          results.push({
            success: true,
            meta: {
              duration: 0,
              size_after: 0,
              rows_read: rows.length,
              rows_written: 0,
              last_row_id: 0,
              changed_db: false,
              changes: 0,
            },
            results: rows,
          });
        } else {
          const info = prepared.run(...values);
          results.push({
            success: true,
            meta: {
              duration: 0,
              size_after: 0,
              rows_read: 0,
              rows_written: info.changes,
              last_row_id: Number(info.lastInsertRowid),
              changed_db: info.changes > 0,
              changes: info.changes,
            },
            results: [],
          });
        }
      }
    });

    performBatch(statements as unknown as SqlitePreparedStatement[]);
    return results;
  }

  async exec(query: string): Promise<D1ExecResult> {
    this.db.exec(query);
    return { count: 1, duration: 0 };
  }

  // Optional D1 properties
  withSession(): any {
    // Return self since we don't have distinct sessions in this simple adapter
    return this;
  }
}
