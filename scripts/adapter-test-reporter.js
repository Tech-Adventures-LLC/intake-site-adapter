import { tap } from 'node:test/reporters';
import { realpathSync } from 'node:fs';
import { resolve } from 'node:path';

// Node20 lacks per-file summary events. Only a real test with its own source
// location can satisfy a file; native empty-file harness passes cannot.
export default async function* adapterReporter(source) {
  const pending = new Set(process.argv.slice(1).map(file => realpathSync(file)));
  let incomplete = pending.size === 0;
  async function* checked() {
    for await (const event of source) {
      if (['test:pass', 'test:fail'].includes(event.type)) {
        const data = event.data;
        if (event.type === 'test:fail' || data.skip || data.todo) incomplete = true;
        else if (data.file && Number.isInteger(data.line) && data.details?.type !== 'suite' && resolve(data.name) !== resolve(data.file)) pending.delete(realpathSync(data.file));
      }
      yield event;
    }
  }
  yield* tap(checked());
  if (incomplete || pending.size) { process.exitCode = 1; yield '# Required adapter tests failed: missing declared tests, skipped, TODO, cancelled or failed tests.\n'; }
}
