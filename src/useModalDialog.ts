import { useEffect, useRef } from 'react';

/**
 * 破坏性确认弹窗的键盘与焦点行为：
 * - 打开时把初始焦点放在「取消」上（最安全的默认；Enter/空格不会触发删除）；
 * - Esc 等同「取消」；
 * - Tab / Shift+Tab 在弹窗内循环（焦点陷阱），焦点跑不到背景的危险按钮上；
 * - 打开期间锁定背景滚动。
 *
 * 只处理「模态弹窗」这一个场景，不引第三方 dialog 库。
 *
 * @param open 弹窗是否打开
 * @param onCancel Esc / 焦点丢失兜底时调用（等同点「取消」）
 * @param dialogRef 弹窗根元素（role="dialog" 的那个）
 * @param cancelRef 「取消」按钮元素
 */
export function useModalDialog(
  open: boolean,
  onCancel: () => void,
  dialogRef: React.RefObject<HTMLElement | null>,
  cancelRef: React.RefObject<HTMLElement | null>,
) {
  // 用 ref 持有最新的 onCancel，避免调用方内联函数导致 effect 反复重挂。
  const onCancelRef = useRef(onCancel);
  onCancelRef.current = onCancel;

  useEffect(() => {
    if (!open) return;
    const dialog = dialogRef.current;
    if (!dialog) return;

    // 初始焦点 → 「取消」。
    cancelRef.current?.focus();

    // 键盘处理：Esc 取消；Tab 焦点陷阱。
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onCancelRef.current();
        return;
      }
      if (e.key !== 'Tab') return;
      const focusables = dialog.querySelectorAll<HTMLElement>(
        // 排除 disabled：删除确认弹窗的破坏性按钮常在忙碌时禁用，
        // 若把它算进 focusables，第一个/最后一个落在它上面时焦点陷阱会失效
        // （Tab 跑到已禁用元素上等于跑出弹窗）。
        'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      );
      if (focusables.length === 0) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      const active = document.activeElement as HTMLElement | null;
      if (e.shiftKey) {
        // Shift+Tab 在第一个上 → 跳到最后一个。
        if (active === first || !dialog.contains(active)) {
          e.preventDefault();
          last.focus();
        }
      } else if (active === last || !dialog.contains(active)) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', onKeyDown);

    // 背景滚动锁定（记住原值，关闭后恢复）。
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.body.style.overflow = previousOverflow;
    };
  }, [open, dialogRef, cancelRef]);
}
