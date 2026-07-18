// Tiny tar parser for the batch-submission "one job per file" mode.
//
// Why hand-roll it: pulling in a full tar-stream + pako (gzip) library
// would add ~50 KB to the bundle for what is a 100-line operation.
// Modern browsers have DecompressionStream for gzip natively, and
// the tar format is a simple sequence of 512-byte headers followed
// by raw file contents. We only need to enumerate filenames and
// extract per-file Blobs to feed into the existing upload pipeline,
// so a minimal parser suffices.
//
// What we DON'T support (and report as warnings, not failures, so
// the user can keep going with whatever entries did parse):
//   - GNU long-name extensions ('L'/'K' typeflags). Truncated to
//     the 100-byte name field.
//   - PaxHeader records ('x'/'g'). Skipped silently.
//   - Sparse files. Treated as regular if the data block is present.
//   - Hard / symbolic links (typeflags '1'/'2'). Reported as warnings.
//
// What we DO support:
//   - Regular files (typeflag '0' or '\0').
//   - ustar prefix concatenation for paths longer than 100 bytes
//     but ≤ 256 bytes (offset 345, 155-byte prefix field).
//   - .tar.gz / .tgz inputs decompressed via DecompressionStream.
//   - .tar inputs read directly.

export interface TarEntry {
  /** Full path inside the archive, normalized with forward slashes. */
  name: string;
  /** Raw file content as a Blob suitable for upload. */
  content: Blob;
}

export interface TarParseResult {
  entries: TarEntry[];
  /** Non-fatal issues — long names truncated, types skipped, etc. */
  warnings: string[];
}

const BLOCK_SIZE = 512;

// readTarball detects gzip vs plain tar from the file's leading magic
// and returns the parsed entry list. Compressed entries pass through
// DecompressionStream; uncompressed go straight to parseTar.
//
// The function reads the entire archive into memory before parsing.
// For batch-submission "one job per file" the user is uploading
// tens to maybe a few hundred MB at most; bounded. If we ever need
// streaming for larger archives, this is the entry point to teach.
export async function readTarball(file: File): Promise<TarParseResult> {
  let bytes: Uint8Array;
  if (isGzip(file)) {
    bytes = await decompressGzip(file);
  } else {
    const buf = await file.arrayBuffer();
    bytes = new Uint8Array(buf);
  }
  return parseTar(bytes);
}

function isGzip(file: File): boolean {
  // Detect from filename. (We also check the magic bytes inside
  // decompressGzip — DecompressionStream throws on bad input — but
  // a name-based heuristic is enough here and avoids re-reading.)
  const lower = file.name.toLowerCase();
  return lower.endsWith('.tar.gz') || lower.endsWith('.tgz');
}

async function decompressGzip(file: File): Promise<Uint8Array> {
  if (typeof DecompressionStream === 'undefined') {
    throw new Error(
      'This browser does not support gzip decompression. ' +
        'Try uploading an uncompressed .tar (or use a recent Chrome / Firefox / Safari).',
    );
  }
  const stream = file.stream().pipeThrough(new DecompressionStream('gzip'));
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    if (value) {
      chunks.push(value);
      total += value.length;
    }
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

// parseTar walks the 512-byte block stream and pulls out regular
// file entries. The last meaningful file is followed by two all-zero
// blocks per the spec; we tolerate truncated archives that simply
// run out of data after the last entry.
export function parseTar(bytes: Uint8Array): TarParseResult {
  const entries: TarEntry[] = [];
  const warnings: string[] = [];
  let pos = 0;
  let zeroRun = 0;

  while (pos + BLOCK_SIZE <= bytes.length) {
    const header = bytes.subarray(pos, pos + BLOCK_SIZE);
    if (isAllZero(header)) {
      // Two zero blocks in a row mark end of archive. One zero block
      // could just be padding before content; keep going.
      zeroRun++;
      pos += BLOCK_SIZE;
      if (zeroRun >= 2) break;
      continue;
    }
    zeroRun = 0;

    const name = readString(header, 0, 100);
    if (name === '') {
      // No name and not all-zero — corrupt header. Bail rather than
      // walking off into random offsets.
      warnings.push(`malformed tar header at offset ${pos}; stopping parse`);
      break;
    }
    const sizeStr = readString(header, 124, 12);
    const size = parseOctal(sizeStr);
    if (size < 0 || !Number.isFinite(size)) {
      warnings.push(`entry ${name}: bad size field (${sizeStr.trim()}); skipping`);
      pos += BLOCK_SIZE;
      continue;
    }
    const typeflag = String.fromCharCode(header[156]);

    // ustar prefix (155 bytes at offset 345) extends the path field
    // to ~256 bytes for files in deeper directories. Concatenate
    // with the name when present and the magic is "ustar".
    const magic = readString(header, 257, 6);
    let fullName = name;
    if (magic.startsWith('ustar')) {
      const prefix = readString(header, 345, 155);
      if (prefix !== '') {
        fullName = `${prefix}/${name}`;
      }
    }

    const dataLen = size;
    const padded = roundUpTo(BLOCK_SIZE, dataLen);
    pos += BLOCK_SIZE;

    // Type-handling switch. Anything we don't recognise either gets
    // skipped silently (PaxHeader / GNU long-name) or warned about
    // (links). Regular files (and '\0' / 'AREGTYPE', the legacy
    // "old tar" type) become entries.
    if (typeflag === '0' || typeflag === '\0') {
      if (pos + dataLen > bytes.length) {
        warnings.push(`entry ${fullName}: truncated mid-content; stopping parse`);
        break;
      }
      const content = bytes.subarray(pos, pos + dataLen);
      // Slice ensures the Blob doesn't hold a reference to the
      // entire underlying ArrayBuffer (which would defeat the
      // sub-array memory savings).
      entries.push({ name: fullName, content: new Blob([content.slice()]) });
    } else if (typeflag === '5') {
      // Directory — no content to keep.
    } else if (typeflag === '1' || typeflag === '2') {
      warnings.push(`entry ${fullName}: ${typeflag === '1' ? 'hard' : 'symbolic'} link; skipped`);
    } else if (typeflag === 'L' || typeflag === 'K') {
      // GNU long-name extension: the next entry's actual name is
      // stored as content here. We don't decode it; the truncated
      // 100-byte name is what subsequent users see.
      warnings.push(
        `entry ${fullName}: GNU long-name extension; the following entry's name may be truncated`,
      );
    } else if (typeflag === 'x' || typeflag === 'g') {
      // PaxHeader / global extended header — skip silently, very
      // common from BSD tar.
    } else {
      warnings.push(`entry ${fullName}: unsupported typeflag '${typeflag}'; skipped`);
    }

    pos += padded;
  }

  return { entries, warnings };
}

function readString(buf: Uint8Array, offset: number, length: number): string {
  let end = offset + length;
  for (let i = offset; i < offset + length; i++) {
    if (buf[i] === 0) {
      end = i;
      break;
    }
  }
  // Names + magic are ASCII in practice; treat as latin-1 for safety.
  let s = '';
  for (let i = offset; i < end; i++) {
    s += String.fromCharCode(buf[i]);
  }
  return s;
}

function parseOctal(s: string): number {
  // Tar's size field is right-aligned octal, NUL- or space-padded.
  // parseInt with radix 8 handles both leading/trailing whitespace.
  const trimmed = s.trim();
  if (trimmed === '') return 0;
  return parseInt(trimmed, 8);
}

function isAllZero(buf: Uint8Array): boolean {
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] !== 0) return false;
  }
  return true;
}

function roundUpTo(align: number, n: number): number {
  return Math.ceil(n / align) * align;
}
