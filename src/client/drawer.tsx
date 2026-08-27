/** Accessible right-side drawer primitive for secondary portal workflows. */

import { X } from "lucide-react";
import { useEffect, useRef, type ReactNode } from "react";

interface DrawerProps {
  open: boolean;
  title: string;
  description?: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
}

export function Drawer({ open, title, description, onClose, children, footer }: DrawerProps) {
  const panelRef = useRef<HTMLElement>(null);

  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const scrollY = window.scrollY;
    const priorOverflow = document.body.style.overflow;
    const priorPosition = document.body.style.position;
    const priorTop = document.body.style.top;
    const priorWidth = document.body.style.width;
    const priorRootOverflow = document.documentElement.style.overflow;
    document.body.style.overflow = "hidden";
    document.body.style.position = "fixed";
    document.body.style.top = `-${scrollY}px`;
    document.body.style.width = "100%";
    document.documentElement.style.overflow = "hidden";
    const panel = panelRef.current;
    const focusable = () =>
      panel
        ? Array.from(
            panel.querySelectorAll<HTMLElement>(
              'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
            ),
          )
        : [];
    const preferredFocus = panel?.querySelector<HTMLElement>('[data-autofocus="true"]');
    requestAnimationFrame(() => (preferredFocus ?? focusable()[0])?.focus());
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab") return;
      const items = focusable();
      if (items.length === 0) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = priorOverflow;
      document.body.style.position = priorPosition;
      document.body.style.top = priorTop;
      document.body.style.width = priorWidth;
      document.documentElement.style.overflow = priorRootOverflow;
      window.scrollTo(0, scrollY);
      previous?.focus();
    };
  }, [onClose, open]);

  if (!open) return null;
  return (
    <div className="drawer-layer" role="presentation">
      <button aria-label="Close drawer" className="drawer-scrim" onClick={onClose} type="button" />
      <aside aria-describedby={description ? "drawer-description" : undefined} aria-labelledby="drawer-title" aria-modal="true" className="drawer" ref={panelRef} role="dialog">
        <header className="drawer-header">
          <div>
            <h2 id="drawer-title">{title}</h2>
            {description ? <p id="drawer-description">{description}</p> : null}
          </div>
          <button aria-label="Close" className="icon-button" onClick={onClose} type="button"><X aria-hidden="true" /></button>
        </header>
        <div className="drawer-body">{children}</div>
        {footer ? <footer className="drawer-footer">{footer}</footer> : null}
      </aside>
    </div>
  );
}
