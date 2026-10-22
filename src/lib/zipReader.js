/**
 * ExtensionLedger - Native Client-Side ZIP Reader
 * 100% self-contained, zero external dependencies.
 * Uses native web standards (DataView, DecompressionStream 'deflate-raw').
 * Runs securely in Chrome, Edge, and modern Node.js environments.
 */

const SIGNATURES = {
  LOCAL_FILE: 0x04034b50,
  CENTRAL_DIRECTORY: 0x02014b50,
  END_OF_CENTRAL_DIRECTORY: 0x06054b50
};

// Maximum decompressed file limit to prevent zip bombs (e.g. 50MB)
const MAX_TOTAL_UNCOMPRESSED_BYTES = 50 * 1024 * 1024;

export class ZipEntry {
  constructor(name, uncompressedSize, compressedSize, compressionMethod, localOffset, buffer) {
    this.name = name;
    this.uncompressedSize = uncompressedSize;
    this.compressedSize = compressedSize;
    this.compressionMethod = compressionMethod;
    this.localOffset = localOffset;
    this._buffer = buffer;
    this.isDirectory = name.endsWith('/');
  }

  /**
   * Decompress and read raw bytes
   * @returns {Promise<Uint8Array>}
   */
  async readBytes() {
    if (this.isDirectory || this.uncompressedSize === 0) {
      return new Uint8Array(0);
    }

    const view = new DataView(this._buffer.buffer, this._buffer.byteOffset, this._buffer.byteLength);
    const localSig = view.getUint32(this.localOffset, true);
    if (localSig !== SIGNATURES.LOCAL_FILE) {
      throw new Error(`Invalid local file header signature at offset ${this.localOffset}`);
    }

    const fileNameLen = view.getUint16(this.localOffset + 26, true);
    const extraLen = view.getUint16(this.localOffset + 28, true);
    const dataOffset = this.localOffset + 30 + fileNameLen + extraLen;

    const compressedSlice = this._buffer.subarray(dataOffset, dataOffset + this.compressedSize);

    if (this.compressionMethod === 0) {
      // Stored (uncompressed)
      return compressedSlice;
    } else if (this.compressionMethod === 8) {
      // Deflated
      const ds = new DecompressionStream('deflate-raw');
      const writer = ds.writable.getWriter();
      writer.write(compressedSlice);
      writer.close();
      const decompressedBuffer = await new Response(ds.readable).arrayBuffer();
      return new Uint8Array(decompressedBuffer);
    } else {
      throw new Error(`Unsupported compression method ${this.compressionMethod} for file: ${this.name}`);
    }
  }

  /**
   * Decompress and decode as UTF-8 text
   * @returns {Promise<string>}
   */
  async readText() {
    const bytes = await this.readBytes();
    const decoder = new TextDecoder('utf-8', { fatal: false });
    return decoder.decode(bytes);
  }
}

export class ZipArchive {
  /**
   * @param {Map<string, ZipEntry>} entries 
   */
  constructor(entries) {
    this.entries = entries;
  }

  /**
   * List all file paths in the archive
   * @returns {string[]}
   */
  getFileNames() {
    return Array.from(this.entries.keys()).filter(k => !this.entries.get(k).isDirectory);
  }

  /**
   * Get an entry by relative path
   * @param {string} path 
   * @returns {ZipEntry|undefined}
   */
  getEntry(path) {
    // Normalize path separators
    const normalized = path.replace(/\\/g, '/');
    return this.entries.get(normalized);
  }

  /**
   * Read manifest.json from extension archive
   * @returns {Promise<Object|null>}
   */
  async readManifest() {
    // Try exact root or first level folder manifest
    let entry = this.getEntry('manifest.json');
    if (!entry) {
      for (const [name, ent] of this.entries.entries()) {
        if (name.endsWith('/manifest.json') && name.split('/').length === 2) {
          entry = ent;
          break;
        }
      }
    }

    if (!entry) return null;
    const text = await entry.readText();
    return JSON.parse(text);
  }
}

/**
 * Parses a ZIP file buffer into an inspectable ZipArchive.
 * @param {ArrayBuffer|Uint8Array} inputBuffer 
 * @returns {Promise<ZipArchive>}
 */
export async function parseZip(inputBuffer) {
  const bytes = inputBuffer instanceof Uint8Array 
    ? inputBuffer 
    : new Uint8Array(inputBuffer);

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  // 1. Locate End of Central Directory (EOCD) signature from the end
  let eocdOffset = -1;
  const maxScan = Math.min(bytes.length, 65557 + 22);
  for (let i = bytes.length - 22; i >= bytes.length - maxScan; i--) {
    if (view.getUint32(i, true) === SIGNATURES.END_OF_CENTRAL_DIRECTORY) {
      eocdOffset = i;
      break;
    }
  }

  if (eocdOffset === -1) {
    throw new Error('Not a valid ZIP archive: End of Central Directory record not found');
  }

  const totalEntries = view.getUint16(eocdOffset + 10, true);
  const cdSize = view.getUint32(eocdOffset + 12, true);
  const cdOffset = view.getUint32(eocdOffset + 16, true);

  if (cdOffset + cdSize > bytes.length) {
    throw new Error('Corrupted ZIP: Central Directory extends past end of file');
  }

  let curOffset = cdOffset;
  const entries = new Map();
  let totalDecompressedSize = 0;
  const textDecoder = new TextDecoder('utf-8');

  for (let i = 0; i < totalEntries; i++) {
    const sig = view.getUint32(curOffset, true);
    if (sig !== SIGNATURES.CENTRAL_DIRECTORY) {
      break;
    }

    const compressionMethod = view.getUint16(curOffset + 10, true);
    const compressedSize = view.getUint32(curOffset + 20, true);
    const uncompressedSize = view.getUint32(curOffset + 24, true);
    const fileNameLen = view.getUint16(curOffset + 28, true);
    const extraLen = view.getUint16(curOffset + 30, true);
    const commentLen = view.getUint16(curOffset + 32, true);
    const localHeaderOffset = view.getUint32(curOffset + 42, true);

    const nameBytes = bytes.subarray(curOffset + 46, curOffset + 46 + fileNameLen);
    const fileName = textDecoder.decode(nameBytes).replace(/\\/g, '/');

    totalDecompressedSize += uncompressedSize;
    if (totalDecompressedSize > MAX_TOTAL_UNCOMPRESSED_BYTES) {
      throw new Error(`ZIP extraction halted: uncompressed size exceeds security threshold of ${MAX_TOTAL_UNCOMPRESSED_BYTES / 1024 / 1024} MB`);
    }

    const entry = new ZipEntry(
      fileName,
      uncompressedSize,
      compressedSize,
      compressionMethod,
      localHeaderOffset,
      bytes
    );

    entries.set(fileName, entry);
    curOffset += 46 + fileNameLen + extraLen + commentLen;
  }

  return new ZipArchive(entries);
}
