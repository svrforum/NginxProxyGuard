import { useEffect, useRef, type KeyboardEvent } from 'react';

const FOCUSABLE = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[contenteditable="true"]',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

// A Tab press inside a nested dialog bubbles through every enclosing panel.
// Only the innermost panel may act on it.
const handledTabs = new WeakSet<Event>();

/**
 * Keeps keyboard focus inside a modal panel.
 *
 * On activation it remembers the element that had focus (usually the button
 * that opened the dialog) and moves focus to the panel, unless something
 * inside already took it (autoFocus). Tab and Shift+Tab wrap at the panel's
 * edges. On deactivation focus goes back to the remembered element.
 *
 * The wrap runs from a keydown handler on the panel itself, not on document,
 * so a dialog opened from inside another one handles its own Tab presses and
 * the outer one leaves them alone. Unlike <dialog>.showModal(), nothing is
 * moved to the top layer, so portaled tooltips and toasts keep working.
 *
 * Spread the result on the panel: ref={panelRef} tabIndex={-1} onKeyDown={onKeyDown}.
 */
export function useDialogFocus<T extends HTMLElement = HTMLDivElement>(active: boolean = true) {
  const panelRef = useRef<T>(null);

  useEffect(() => {
    if (!active) return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const panel = panelRef.current;
    if (panel && !panel.contains(document.activeElement)) {
      panel.focus({ preventScroll: true });
    }
    return () => {
      if (previous && previous.isConnected) previous.focus({ preventScroll: true });
    };
  }, [active]);

  const onKeyDown = (e: KeyboardEvent<T>) => {
    if (e.key !== 'Tab' || handledTabs.has(e.nativeEvent)) return;
    handledTabs.add(e.nativeEvent);
    const panel = panelRef.current;
    if (!panel) return;
    const items = Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
      (el) => el.getClientRects().length > 0,
    );
    if (items.length === 0) {
      e.preventDefault();
      panel.focus();
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    const current = document.activeElement;
    if (e.shiftKey) {
      if (current === first || current === panel) {
        e.preventDefault();
        last.focus();
      }
    } else if (current === last) {
      e.preventDefault();
      first.focus();
    }
  };

  return { panelRef, onKeyDown };
}
