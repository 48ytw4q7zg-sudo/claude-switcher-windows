import { useCallback, useEffect, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  AppWindow,
  CheckCircle2,
  Clock,
  Loader2,
  Pencil,
  Plus,
  ShieldAlert,
  Trash2,
} from 'lucide-react';
import { useModalDialog } from '../useModalDialog';
import type { DesktopProfile } from './types';
import { humanBytes } from './types';

function dateLabel(value?: string | null) {
  if (!value) return '从未';
  return new Date(value).toLocaleString('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

type Target =
  | { kind: 'switch'; profile: DesktopProfile }
  | { kind: 'delete'; profile: DesktopProfile; alsoFiles: boolean }
  | null;

export function DesktopProfiles() {
  const [profiles, setProfiles] = useState<DesktopProfile[]>([]);
  const [captureName, setCaptureName] = useState('');
  const [captureNotes, setCaptureNotes] = useState('');
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState('');
  const [target, setTarget] = useState<Target>(null);
  const [busy, setBusy] = useState<'list' | 'capture' | 'switch' | 'rename' | 'delete' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);

  const dialogRef = useRef<HTMLElement | null>(null);
  const cancelRef = useRef<HTMLButtonElement | null>(null);
  useModalDialog(target !== null, () => setTarget(null), dialogRef, cancelRef);

  const load = useCallback(async () => {
    setBusy('list');
    try {
      const list = await invoke<DesktopProfile[]>('list_desktop_profiles_cmd');
      setProfiles(list);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(null);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const capture = async () => {
    if (!captureName.trim()) return;
    setBusy('capture');
    setError(null);
    setWarnings([]);
    try {
      await invoke<DesktopProfile>('capture_desktop_profile_cmd', {
        name: captureName.trim(),
        notes: captureNotes.trim() || null,
      });
      setCaptureName('');
      setCaptureNotes('');
      await load();
    } catch (err) {
      // 后端要求 Desktop 完全退出；失败文本直接展示。
      setError(String(err));
    } finally {
      setBusy(null);
    }
  };

  const confirmTarget = async () => {
    const t = target;
    setTarget(null);
    if (!t) return;
    if (t.kind === 'switch') {
      setBusy('switch');
      setError(null);
      setWarnings([]);
      try {
        const result = await invoke<string[]>('switch_desktop_profile_cmd', { id: t.profile.id });
        setWarnings(result ?? []);
        await load();
      } catch (err) {
        setError(String(err));
      } finally {
        setBusy(null);
      }
    } else if (t.kind === 'delete') {
      setBusy('delete');
      setError(null);
      try {
        await invoke('delete_desktop_profile_cmd', { id: t.profile.id, alsoFiles: t.alsoFiles });
        await load();
      } catch (err) {
        setError(String(err));
      } finally {
        setBusy(null);
      }
    }
  };

  const startRename = (profile: DesktopProfile) => {
    setRenamingId(profile.id);
    setRenameValue(profile.name);
  };

  const submitRename = async (id: string) => {
    if (!renameValue.trim()) {
      setRenamingId(null);
      return;
    }
    setBusy('rename');
    setError(null);
    try {
      await invoke<DesktopProfile>('rename_desktop_profile_cmd', { id, name: renameValue.trim() });
      await load();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(null);
      setRenamingId(null);
    }
  };

  return (
    <section className="profiles">
      <div className="section-title">
        <h2>Claude Desktop 桌面版账号</h2>
        <span>{profiles.length} 个快照</span>
      </div>

      <div className="panel" style={{ marginBottom: 14 }}>
        <div className="panel-title">
          <AppWindow />
          <span>捕获当前桌面版为快照</span>
        </div>
        <p className="telemetry-intro">
          捕获前请<strong>完全退出 Claude Desktop</strong>（包括托盘图标），否则快照会不一致。
        </p>
        <div className="export-import-row" style={{ gridTemplateColumns: '1fr 1fr', marginBottom: 0 }}>
          <label style={{ marginTop: 0 }}>
            快照名称
            <input
              value={captureName}
              onChange={(e) => setCaptureName(e.target.value)}
              placeholder="例如 Desktop 主号"
            />
          </label>
          <label style={{ marginTop: 0 }}>
            备注（可选）
            <input
              value={captureNotes}
              onChange={(e) => setCaptureNotes(e.target.value)}
              placeholder="用途 / 来源"
            />
          </label>
        </div>
        <button
          className="primary wide"
          onClick={capture}
          disabled={busy !== null || !captureName.trim()}
          style={{ marginTop: 12 }}
        >
          {busy === 'capture' ? <Loader2 className="spin" /> : <Plus />}
          捕获当前桌面版
        </button>
      </div>

      {error && (
        <div className="inline-error" style={{ marginBottom: 12 }}>
          <ShieldAlert /> {error}
        </div>
      )}
      {warnings.length > 0 && (
        <div className="inline-warning" style={{ marginBottom: 12 }}>
          切换后提示：
          {warnings.map((w, i) => (
            <div key={i} style={{ marginTop: 4, fontSize: 12, fontWeight: 600 }}>
              · {w}
            </div>
          ))}
        </div>
      )}

      {profiles.length === 0 ? (
        <div className="empty">
          <AppWindow />
          <strong>还没有桌面版快照</strong>
          <span>先完全退出 Claude Desktop，再点上方「捕获当前桌面版」。</span>
        </div>
      ) : (
        <div className="profile-grid">
          {profiles.map((p) => (
            <article className="profile" key={p.id}>
              <div className="profile-head">
                <div>
                  {renamingId === p.id ? (
                    <input
                      autoFocus
                      value={renameValue}
                      onChange={(e) => setRenameValue(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') submitRename(p.id);
                        if (e.key === 'Escape') setRenamingId(null);
                      }}
                      onBlur={() => submitRename(p.id)}
                    />
                  ) : (
                    <strong>{p.name}</strong>
                  )}
                  <span>{p.notes || '无备注'}</span>
                </div>
              </div>
              <div className="mini-fields">
                <span>
                  <Clock /> 创建 {dateLabel(p.created_at)}
                </span>
                <span>
                  <Clock /> 最近切换 {dateLabel(p.last_switched_at)}
                </span>
                <span>
                  <AppWindow /> {humanBytes(p.size_bytes)}
                </span>
              </div>
              <div className="profile-actions">
                <button
                  className="primary"
                  onClick={() => setTarget({ kind: 'switch', profile: p })}
                  disabled={busy !== null}
                >
                  {busy === 'switch' ? <Loader2 className="spin" /> : <CheckCircle2 />}
                  切换到此账号
                </button>
                <button
                  className="ghost"
                  onClick={() => startRename(p)}
                  disabled={busy !== null}
                  title="重命名"
                >
                  <Pencil />
                </button>
                <button
                  className="danger"
                  onClick={() => setTarget({ kind: 'delete', profile: p, alsoFiles: false })}
                  disabled={busy !== null}
                  title="删除"
                >
                  <Trash2 />
                </button>
              </div>
            </article>
          ))}
        </div>
      )}

      {target && (
        <div className="modal-scrim" role="presentation">
          <section
            className="prepare-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="desktop-confirm-title"
            ref={dialogRef}
          >
            <div className="modal-title" id="desktop-confirm-title">
              {target.kind === 'switch' ? <CheckCircle2 /> : <Trash2 />}
              <div>
                <strong>
                  {target.kind === 'switch' ? '切换桌面版账号' : '删除桌面版快照'}
                </strong>
                <span>
                  {target.kind === 'switch'
                    ? `将把 Claude Desktop 登录态切到「${target.profile.name}」。建议先完全退出 Desktop。`
                    : `将删除快照「${target.profile.name}」。此操作不可恢复。`}
                </span>
              </div>
            </div>

            {target.kind === 'delete' && (
              <label className="link-mode-row" style={{ cursor: 'pointer', marginTop: 16 }}>
                <span>同时删除快照文件（{humanBytes(target.profile.size_bytes)}）</span>
                <input
                  type="checkbox"
                  checked={target.alsoFiles}
                  onChange={(e) =>
                    setTarget({ ...target, profile: target.profile, alsoFiles: e.target.checked })
                  }
                  style={{ width: 16, height: 16, flex: '0 0 auto' }}
                />
              </label>
            )}

            <div className="modal-actions">
              <button className="ghost" onClick={() => setTarget(null)} ref={cancelRef}>
                取消
              </button>
              <button
                className={target.kind === 'switch' ? 'primary' : 'danger wide'}
                onClick={confirmTarget}
                disabled={busy !== null}
              >
                {busy !== null ? <Loader2 className="spin" /> : null}
                {target.kind === 'switch' ? '确认切换' : '确认删除'}
              </button>
            </div>
          </section>
        </div>
      )}
    </section>
  );
}
