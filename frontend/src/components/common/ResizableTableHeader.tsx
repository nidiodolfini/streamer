import React, { useEffect, useRef, useState } from 'react';

interface ResizableTableHeaderProps {
  label: string;
  width: number;
  minWidth: number;
  maxWidth: number;
  onResize: (width: number) => void;
  onAutoFit: () => void;
  children: React.ReactNode;
  className?: string;
  sort?: React.AriaAttributes['aria-sort'];
}

export const ResizableTableHeader: React.FC<ResizableTableHeaderProps> = ({
  label, width, minWidth, maxWidth, onResize, onAutoFit, children, className = '', sort,
}) => {
  const drag = useRef<{ pointerID: number; startX: number; width: number } | null>(null);
  const [dragging, setDragging] = useState(false);

  useEffect(() => {
    if (!dragging) return;
    const previousCursor = document.body.style.cursor;
    document.body.style.cursor = 'col-resize';
    return () => { document.body.style.cursor = previousCursor; };
  }, [dragging]);

  const resize = (value: number) => onResize(Math.round(Math.max(minWidth, Math.min(maxWidth, value))));

  const endDrag = (event: React.PointerEvent<HTMLDivElement>) => {
    if (drag.current?.pointerID !== event.pointerId) return;
    drag.current = null;
    setDragging(false);
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  };

  return (
    <th scope="col" aria-sort={sort} className={`relative ${className}`}>
      {children}
      <div
        data-column-resize
        role="separator"
        aria-orientation="vertical"
        aria-label={`Resize ${label}`}
        aria-valuemin={minWidth}
        aria-valuemax={maxWidth}
        aria-valuenow={width}
        aria-valuetext={`${width} pixels`}
        tabIndex={0}
        title="Drag to resize. Double-click or press Enter to fit content. Arrow keys adjust width."
        className={`absolute right-0 top-0 z-10 flex h-full w-2 cursor-col-resize touch-none items-center justify-center select-none hover:bg-rose-500/30 focus-visible:outline focus-visible:outline-2 focus-visible:outline-rose-400 ${dragging ? 'bg-rose-500/30' : ''}`}
        onPointerDown={(event) => {
          if (event.button !== 0) return;
          event.preventDefault();
          event.stopPropagation();
          drag.current = { pointerID: event.pointerId, startX: event.clientX, width };
          event.currentTarget.setPointerCapture(event.pointerId);
          setDragging(true);
        }}
        onPointerMove={(event) => {
          if (drag.current?.pointerID === event.pointerId) {
            resize(drag.current.width + event.clientX - drag.current.startX);
          }
        }}
        onPointerUp={endDrag}
        onPointerCancel={endDrag}
        onLostPointerCapture={endDrag}
        onClick={(event) => event.stopPropagation()}
        onDoubleClick={(event) => {
          event.preventDefault();
          event.stopPropagation();
          onAutoFit();
        }}
        onKeyDown={(event) => {
          const step = event.shiftKey ? 64 : 16;
          switch (event.key) {
            case 'ArrowLeft': resize(width - step); break;
            case 'ArrowRight': resize(width + step); break;
            case 'Home': resize(minWidth); break;
            case 'End': resize(maxWidth); break;
            case 'Enter': onAutoFit(); break;
            default: return;
          }
          event.preventDefault();
          event.stopPropagation();
        }}
      >
        <span className={`h-5 w-px ${dragging ? 'bg-rose-300' : 'bg-gray-600/70'}`} aria-hidden="true" />
      </div>
    </th>
  );
};

// Measure natural cell widths instead of the clipped text or current column
// size, so auto-fit can both expand and shrink a column (including mixed fonts).
export function measureTableColumn(table: HTMLTableElement, index: number): number {
  const cells = Array.from(table.rows)
    .map((row) => row.cells[index])
    .filter((cell) => cell && cell.colSpan === 1);
  const measuring = document.createElement('div');
  measuring.style.cssText = 'position:fixed;left:0;top:0;visibility:hidden;pointer-events:none;width:max-content';
  measuring.setAttribute('aria-hidden', 'true');
  for (const cell of cells) {
    const clone = cell.cloneNode(true) as HTMLElement;
    clone.style.display = 'block';
    clone.style.width = 'max-content';
    clone.style.maxWidth = 'none';
    clone.style.whiteSpace = 'nowrap';
    clone.style.font = getComputedStyle(cell).font;
    clone.querySelectorAll('[data-column-resize]').forEach((handle) => handle.remove());
    clone.querySelectorAll('.truncate').forEach((text) => text.classList.remove('truncate'));
    measuring.appendChild(clone);
  }
  document.body.appendChild(measuring);
  try {
    return Math.ceil(Math.max(0, ...Array.from(measuring.children, (cell) => cell.getBoundingClientRect().width))) + 2;
  } finally {
    measuring.remove();
  }
}
