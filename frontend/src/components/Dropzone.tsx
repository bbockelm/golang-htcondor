'use client';

import { useCallback, useRef, useState } from 'react';

export interface DroppedFile {
  // Stable client-side ID so React can key + remove without a server roundtrip.
  id: string;
  file: File;
  // The name we'll send to the server. Defaults to file.name; users may
  // edit it inline (e.g. to match the submit-file's transfer_input_files).
  name: string;
  executable: boolean;
}

interface DropzoneProps {
  files: DroppedFile[];
  onChange: (files: DroppedFile[]) => void;
  disabled?: boolean;
}

// Small drag-and-drop file list. We avoid pulling react-dropzone for one
// component — the native HTML5 DnD API is enough and keeps the bundle
// small.
export function Dropzone({ files, onChange, disabled }: DropzoneProps) {
  const [hover, setHover] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const addFiles = useCallback(
    (incoming: FileList | File[]) => {
      const next: DroppedFile[] = [];
      const seen = new Set(files.map((f) => f.name));
      for (const file of Array.from(incoming)) {
        let name = file.name;
        let i = 1;
        while (seen.has(name)) {
          // Avoid collisions: foo.txt -> foo (1).txt
          const dot = file.name.lastIndexOf('.');
          name =
            dot > 0
              ? `${file.name.slice(0, dot)} (${i})${file.name.slice(dot)}`
              : `${file.name} (${i})`;
          i++;
        }
        seen.add(name);
        next.push({
          id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
          file,
          name,
          executable: false,
        });
      }
      onChange([...files, ...next]);
    },
    [files, onChange],
  );

  const onDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setHover(false);
    if (disabled) return;
    if (e.dataTransfer.files?.length) addFiles(e.dataTransfer.files);
  };

  return (
    <div className="space-y-3">
      <div
        onDragOver={(e) => {
          e.preventDefault();
          if (!disabled) setHover(true);
        }}
        onDragLeave={() => setHover(false)}
        onDrop={onDrop}
        onClick={() => !disabled && inputRef.current?.click()}
        className={`border-2 border-dashed rounded-lg px-6 py-8 text-center text-sm transition cursor-pointer ${
          disabled
            ? 'border-gray-200 bg-gray-50 text-gray-400 cursor-not-allowed'
            : hover
              ? 'border-brand-400 bg-brand-50 text-brand-700'
              : 'border-gray-300 bg-white text-gray-600 hover:border-gray-400'
        }`}
      >
        <p>Drag &amp; drop input files here, or click to browse.</p>
        <p className="text-xs text-gray-400 mt-1">
          Files will be spooled to the schedd and made available to your job.
        </p>
        <input
          ref={inputRef}
          type="file"
          multiple
          className="hidden"
          onChange={(e) => {
            if (e.target.files?.length) addFiles(e.target.files);
            e.target.value = '';
          }}
        />
      </div>

      {files.length > 0 && (
        <ul className="rounded border border-gray-200 bg-white divide-y divide-gray-100">
          {files.map((f) => (
            <li key={f.id} className="flex items-center gap-2 px-3 py-2 text-sm">
              <input
                value={f.name}
                onChange={(e) =>
                  onChange(
                    files.map((x) =>
                      x.id === f.id ? { ...x, name: e.target.value } : x,
                    ),
                  )
                }
                className="flex-1 min-w-0 rounded border border-transparent bg-transparent px-1 py-0.5 font-mono text-xs hover:border-gray-200 focus:border-gray-300 focus:outline-none"
              />
              <span className="text-xs text-gray-400 shrink-0">
                {humanSize(f.file.size)}
              </span>
              <label className="flex items-center gap-1 text-xs text-gray-600 shrink-0">
                <input
                  type="checkbox"
                  checked={f.executable}
                  onChange={(e) =>
                    onChange(
                      files.map((x) =>
                        x.id === f.id
                          ? { ...x, executable: e.target.checked }
                          : x,
                      ),
                    )
                  }
                />
                exec
              </label>
              <button
                type="button"
                onClick={() => onChange(files.filter((x) => x.id !== f.id))}
                className="text-xs text-red-600 hover:text-red-800 shrink-0"
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function humanSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}
