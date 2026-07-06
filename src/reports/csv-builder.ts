export class CsvBuilder {
  /**
   * Escape a value for CSV output.
   * Wraps in double quotes if the value contains commas, newlines, or quotes.
   * Double quotes inside the value are escaped by doubling them.
   */
  private static escape(value: unknown): string {
    const s = String(value ?? '');
    if (s.includes(',') || s.includes('\n') || s.includes('"')) {
      return `"${s.replace(/"/g, '""')}"`;
    }
    return s;
  }

  /**
   * Convert an array of objects into CSV text.
   * The first object's keys are used as the header row.
   */
  static build(rows: Record<string, unknown>[]): string {
    if (!rows || rows.length === 0) {
      return '';
    }
    const headers = Object.keys(rows[0]);
    const lines: string[] = [];
    lines.push(headers.map(CsvBuilder.escape).join(','));
    for (const row of rows) {
      lines.push(headers.map((h) => CsvBuilder.escape(row[h])).join(','));
    }
    return lines.join('\n');
  }
}
