import { useCallback, useEffect, useMemo, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  Bot,
  BookOpen,
  FolderCog,
  Loader2,
  Power,
  ScrollText,
  Search,
  Terminal,
} from 'lucide-react';
import { useI18n } from '../i18n';

type Kind = 'skill' | 'command' | 'agent' | 'memory';

interface WorkspaceItem {
  kind: Kind;
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  path: string;
  is_directory: boolean;
}

const KIND_META: { kind: Kind; labelKey: string; icon: typeof Terminal }[] = [
  { kind: 'skill', labelKey: 'ws.skill', icon: FolderCog },
  { kind: 'command', labelKey: 'ws.command', icon: Terminal },
  { kind: 'agent', labelKey: 'ws.agent', icon: Bot },
  { kind: 'memory', labelKey: 'ws.memory', icon: BookOpen },
];

/**
 * 功能大全：Skills / 命令 / 子代理 / CLAUDE.md 管理。
 * 启用/停用通过重命名 .disabled 实现（原子可逆，不删内容）；
 * 停用项不会被 Claude Code 加载。
 */
export function WorkspacePanel() {
  const { t } = useI18n();
  const [items, setItems] = useState<WorkspaceItem[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');

  const load = useCallback(async () => {
    try {
      const result = await invoke<WorkspaceItem[]>('list_workspace_items');
      setItems(result);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const toggle = async (item: WorkspaceItem) => {
    const key = `${item.kind}:${item.id}`;
    setBusy(key);
    try {
      await invoke('set_workspace_item_enabled', {
        kind: item.kind,
        id: item.id,
        enabled: !item.enabled,
      });
      await load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  };

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter(
      (i) =>
        i.name.toLowerCase().includes(q) ||
        i.id.toLowerCase().includes(q) ||
        i.description.toLowerCase().includes(q),
    );
  }, [items, query]);

  return (
    <section className="profiles">
      <div className="section-title">
        <h2>{t('ws.title')}</h2>
        <span>
          {t('ws.count', {
            n: items.length,
            enabled: items.filter((i) => i.enabled).length,
          })}
        </span>
      </div>
      <div className="panel">
        <div className="panel-title">
          <ScrollText />
          <span>{t('ws.panel.title')}</span>
        </div>

        <div className="mcp-scope">
          <Search size={16} />
          <input
            placeholder={t('ws.search')}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>

        {KIND_META.map(({ kind, labelKey, icon: Icon }) => {
          const group = filtered.filter((i) => i.kind === kind);
          if (group.length === 0) return null;
          return (
            <div className="mcp-list" key={kind}>
              <div className="mcp-form-head">
                <Icon size={16} />
                <span>{t(labelKey)}（{group.length}）</span>
              </div>
              {group.map((item) => {
                const key = `${item.kind}:${item.id}`;
                return (
                  <div className="mcp-row" key={key}>
                    <div>
                      <strong>{item.name}</strong>
                      {item.description && <span className="mcp-target">{item.description}</span>}
                      <span className="mcp-env" title={item.path}>{item.path}</span>
                    </div>
                    <button
                      className={item.enabled ? 'ghost' : 'primary'}
                      onClick={() => toggle(item)}
                      disabled={busy === key}
                      title={item.enabled ? t('ws.disable') : t('ws.enable')}
                    >
                      {busy === key ? <Loader2 className="spin" /> : <Power />}
                      {item.enabled ? t('ws.disable') : t('ws.enable')}
                    </button>
                  </div>
                );
              })}
            </div>
          );
        })}

        {filtered.length === 0 && <p className="muted">{t('ws.empty')}</p>}
        {error && <div className="inline-error">{error}</div>}
      </div>
    </section>
  );
}
