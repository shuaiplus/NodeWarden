import type { ToastMessage } from '@/lib/types';

interface ToastHostProps {
  toasts: ToastMessage[];
  onClose: (id: string) => void;
}

export default function ToastHost({ toasts, onClose }: ToastHostProps) {
  if (!toasts.length) return null;
  return (
    <ul className="toast-stack">
      {toasts.map((toast) => (
        <li key={toast.id} className={`toast-item ${toast.type}`}>
          <div className="toast-text">{toast.text}</div>
          <button type="button" className="toast-close" onClick={() => onClose(toast.id)}>
            x
          </button>
          <div className="toast-progress" />
        </li>
      ))}
    </ul>
  );
}
