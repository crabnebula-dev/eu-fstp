/**
 * FSTP (ADR-016): an in-house least-recently-used cache. It replaces the
 * `lru-cache` npm package with the part PdfRef interning uses: `get`,
 * `set`, `clear` and `size`, bounded by `max` entries.
 */
export class LRUCache<K, V> {
  private readonly max: number;
  private readonly map = new Map<K, V>();

  constructor(options: { max: number }) {
    this.max = Math.max(1, Math.floor(options.max));
  }

  get size(): number {
    return this.map.size;
  }

  get(key: K): V | undefined {
    const value = this.map.get(key);

    if (value !== undefined) {
      // Move to the most recent end.
      this.map.delete(key);
      this.map.set(key, value);
    }

    return value;
  }

  set(key: K, value: V): this {
    this.map.delete(key);
    this.map.set(key, value);

    while (this.map.size > this.max) {
      const oldest = this.map.keys().next();

      if (oldest.done === true) {
        break;
      }

      this.map.delete(oldest.value);
    }

    return this;
  }

  clear(): void {
    this.map.clear();
  }
}
