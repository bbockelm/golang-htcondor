'use client';

import { useEffect, useId, useRef, useState } from 'react';
import Link from 'next/link';

// RowMenu is a small "more actions" menu for a table row: a button that
// opens a list of links.
//
// Keyboard behaviour follows the WAI-ARIA menu button pattern, because a
// row of the jobs table is navigated with the keyboard as often as with a
// mouse: Enter, Space or ArrowDown opens it on the first item, ArrowUp on
// the last; the arrows move between items, Home and End jump; Escape
// closes it and returns focus to the button; Tab closes it and moves on.
// A click outside closes it too.

export interface RowMenuItem {
  label: string;
  href: string;
}

export function RowMenu({
  label,
  items,
  touch,
}: {
  label: string;
  items: RowMenuItem[];
  // A finger-sized button and items, for the card layout on phones and
  // tablets, where a 20px target is a miss as often as a hit.
  touch?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const itemRefs = useRef<(HTMLAnchorElement | null)[]>([]);
  // Which item to focus once the menu has rendered.
  const [focusIndex, setFocusIndex] = useState(0);
  const menuId = useId();

  useEffect(() => {
    if (!open) return;
    itemRefs.current[focusIndex]?.focus();
  }, [open, focusIndex]);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    return () => document.removeEventListener('mousedown', onDown);
  }, [open]);

  const openAt = (i: number) => {
    setFocusIndex(i);
    setOpen(true);
  };
  const close = (refocus: boolean) => {
    setOpen(false);
    if (refocus) buttonRef.current?.focus();
  };

  const onButtonKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      openAt(0);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      openAt(items.length - 1);
    }
  };

  const onMenuKey = (e: React.KeyboardEvent) => {
    const n = items.length;
    const move = (i: number) => {
      e.preventDefault();
      setFocusIndex(((i % n) + n) % n);
    };
    switch (e.key) {
      case 'ArrowDown':
        return move(focusIndex + 1);
      case 'ArrowUp':
        return move(focusIndex - 1);
      case 'Home':
        return move(0);
      case 'End':
        return move(n - 1);
      case 'Escape':
        e.preventDefault();
        return close(true);
      case 'Tab':
        return close(false);
    }
  };

  return (
    <div ref={wrapRef} className="relative inline-block text-left">
      <button
        ref={buttonRef}
        type="button"
        aria-label={label}
        title={label}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => (open ? close(false) : openAt(0))}
        onKeyDown={onButtonKey}
        className={`rounded-sm border border-gray-300 bg-white text-gray-600 hover:bg-gray-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 ${
          touch ? 'min-h-9 min-w-9 px-3 py-1.5 text-base leading-none' : 'px-1.5 py-0.5 text-xs leading-none'
        }`}
      >
        <span aria-hidden>⋯</span>
      </button>
      {open && (
        <div
          id={menuId}
          role="menu"
          aria-label={label}
          onKeyDown={onMenuKey}
          className="absolute right-0 z-20 mt-1 min-w-48 rounded-md border border-gray-200 bg-white py-1 text-left shadow-lg"
        >
          {items.map((item, i) => (
            <Link
              key={item.href}
              ref={(el) => {
                itemRefs.current[i] = el;
              }}
              href={item.href}
              role="menuitem"
              tabIndex={i === focusIndex ? 0 : -1}
              onClick={() => setOpen(false)}
              className={`block whitespace-nowrap px-3 text-sm text-gray-700 hover:bg-gray-100 focus:bg-gray-100 focus:outline-none ${touch ? 'py-3' : 'py-1.5'}`}
            >
              {item.label}
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
