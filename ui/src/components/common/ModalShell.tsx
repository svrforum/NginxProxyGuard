import { ReactNode, useEffect, useState } from 'react';
import { useEscapeKey } from '../../hooks/useEscapeKey';

interface ModalShellProps {
  /** Whether the modal is open. Drives enter/leave animation. */
  isOpen: boolean;
  /** Called on ESC, backdrop click, or close button. */
  onClose: () => void;
  /** Panel inner content (header/body/footer). Do NOT wrap in another overlay/panel. */
  children: ReactNode;
  /**
   * Extra classes for the panel — primarily width (e.g. "max-w-2xl").
   * Base panel already provides bg/rounded/shadow/border/animation; pass the
   * max-width here since the base intentionally omits it to avoid conflicts.
   */
  panelClassName?: string;
  /** Close when the backdrop (outside the panel) is clicked. Default true. */
  closeOnBackdrop?: boolean;
  /** Accessible name for the dialog (use when there is no visible title element). */
  ariaLabel?: string;
  /** id of the visible heading element that labels the dialog. */
  labelledById?: string;
}

const LEAVE_MS = 200;

/**
 * Shared modal wrapper: standardizes the overlay + panel, ESC handling,
 * backdrop-click close, dialog semantics, and a fade+scale enter/leave
 * animation across the whole app. Honors prefers-reduced-motion.
 *
 * Migration: replace the old `<div overlay><div panel>…</div></div>` markup
 * with `<ModalShell isOpen onClose panelClassName="max-w-2xl">…</ModalShell>`,
 * passing only the panel's INNER content as children.
 */
export function ModalShell({
  isOpen,
  onClose,
  children,
  panelClassName = 'max-w-lg',
  closeOnBackdrop = true,
  ariaLabel,
  labelledById,
}: ModalShellProps) {
  // `mounted` keeps the node in the DOM during the leave animation;
  // `visible` toggles the enter/leave transition classes one frame later.
  const [mounted, setMounted] = useState(isOpen);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setMounted(true);
      const id = requestAnimationFrame(() => setVisible(true));
      return () => cancelAnimationFrame(id);
    }
    setVisible(false);
    const timer = setTimeout(() => setMounted(false), LEAVE_MS);
    return () => clearTimeout(timer);
  }, [isOpen]);

  useEscapeKey(onClose, isOpen);

  if (!mounted) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={ariaLabel}
      aria-labelledby={labelledById}
      onMouseDown={(e) => {
        if (closeOnBackdrop && e.target === e.currentTarget) onClose();
      }}
      className={`fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm transition-opacity duration-200 motion-reduce:transition-none ${
        visible ? 'opacity-100' : 'opacity-0'
      }`}
    >
      <div
        onMouseDown={(e) => e.stopPropagation()}
        className={`m-4 w-full ${panelClassName} max-h-[90vh] overflow-y-auto rounded-lg border bg-white shadow-xl transition-all duration-200 dark:border-slate-700 dark:bg-slate-800 motion-reduce:transition-none motion-reduce:transform-none ${
          visible ? 'scale-100 opacity-100' : 'scale-95 opacity-0'
        }`}
      >
        {children}
      </div>
    </div>
  );
}

export default ModalShell;
