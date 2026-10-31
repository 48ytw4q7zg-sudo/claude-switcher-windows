import { useCallback, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { AlertTriangle, Loader2, Plus, ShieldCheck, Trash2 } from 'lucide-react';
import { useI18n } from '../i18n';

interface PermissionRules {
  allow: string[];
  deny: string[];
  ask: string[];
}

interface HookEntry {
  event: string;
  matcher: string;
  command: string;
}

interface EditorData {
  permissions: PermissionRules;
  hooks: HookEntry[];
  settings_path: string;
  warnings: string[];
}

const LIST_FIELDS: { key: keyof PermissionRules; labelKey: string; hintKey: string }[] = [
  { key: 'allow', labelKey: 'perm.allow', hintKey: 'perm.allow.hint' },
  { key: 'deny', labelKey: 'perm.deny', hintKey: 'perm.deny.hint' },
  { key: 'ask', labelKey: 'perm.ask', hintKey: 'perm.ask.hint' },
];

const lines = (arr: string[]) => arr.join('\n');
const splitLines = (text: string) =>
  text.split('\n').map((s) => s.trim()).filter(Boolean);

/**
 * 功能大全：权限与钩子结构化编辑器。
 * 对 settings.json 的 permissions.allow/deny/ask 与 hooks 可视化编辑，
 * 保存走后端乐观并发；Windows 路径/cmd 包装提示在告警中给出。
 */
export function PermissionPanel() {
  const { t } = useI18n();
  const [data, setData] = useState<EditorData | null>(null);
  const [allowText, setAllowText] = useState('');
  const [denyText, setDenyText] = useState('');
  const [askText, setAskText] = useState('');
  const [hooks, setHooks] = useState<HookEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const load = useCallback(async () => {
    try {
      const result = await invoke<EditorData>('read_permission_editor');
      setData(result);
      setAllowText(lines(result.permissions.allow));
      setDenyText(lines(result.permissions.deny));
      setAskText(lines(result.permissions.ask));
      setHooks(result.hooks);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const addHook = () =>
    setHooks((prev) => [...prev, { event: 'PreToolUse', matcher: '', command: '' }]);

  const updateHook = (idx: number, patch: Partial<HookEntry>) =>
    setHooks((prev) => prev.map((h, i) => (i === idx ? { ...h, ...patch } : h)));

  const removeHook = (idx: number) =>
    setHooks((prev) => prev.filter((_, i) => i !== idx));

  const save = async () => {
    setBusy(true);
    setSaved(false);
    try {
      const permissions: PermissionRules = {
        allow: splitLines(allowText),
        deny: splitLines(denyText),
        ask: splitLines(askText),
      };
      await invoke('save_permission_editor', { permissions, hooks });
      await load();
      setSaved(true);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const textFor = (key: keyof PermissionRules) =>
    key === 'allow' ? allowText : key === 'deny' ? denyText : askText;
  const setterFor = (key: keyof PermissionRules) =>
    key === 'allow' ? setAllowText : key === 'deny' ? setDenyText : setAskText;

  return (
    <section className="profiles">
      <div className="section-title">
        <h2>{t('perm.title')}</h2>
        <span>settings.json</span>
      </div>
      <div className="panel">
        <div className="panel-title">
          <ShieldCheck />
          <span>{t('perm.panel.title')}</span>
        </div>

        {data?.settings_path && (
          <p className="mcp-env" title={data.settings_path}>{data.settings_path}</p>
        )}

        {data && data.warnings.length > 0 && (
          <div className="warnings compact">
            {data.warnings.map((w, i) => (
              <div key={`${i}-${w}`}>
                <AlertTriangle size={14} />
                {w}
              </div>
            ))}
          </div>
        )}

        <div className="runtime-grid" style={{ gridTemplateColumns: 'repeat(3, minmax(0,1fr))' }}>
          {LIST_FIELDS.map(({ key, labelKey, hintKey }) => (
            <label key={key}>
              <strong>{t(labelKey)}</strong>
              <em className="mcp-env">{t(hintKey)}（{t('perm.perLine')}）</em>
              <textarea
                rows={6}
                value={textFor(key)}
                onChange={(e) => setterFor(key)(e.target.value)}
                placeholder={t('perm.rule.placeholder')}
              />
            </label>
          ))}
        </div>

        <div className="mcp-form-head">
          <ShieldCheck size={16} />
          <span>{t('perm.hooks', { n: hooks.length })}</span>
        </div>
        <p className="mcp-env">{t('perm.hooks.note')}</p>
        <div className="mcp-list">
          {hooks.length === 0 && <p className="muted">{t('perm.noHooks')}</p>}
          {hooks.map((hook, idx) => (
            <div className="mcp-row" key={idx} style={{ flexWrap: 'wrap' }}>
              <input
                style={{ width: 130 }}
                value={hook.event}
                placeholder={t('perm.event')}
                onChange={(e) => updateHook(idx, { event: e.target.value })}
              />
              <input
                style={{ width: 130 }}
                value={hook.matcher}
                placeholder={t('perm.matcher')}
                onChange={(e) => updateHook(idx, { matcher: e.target.value })}
              />
              <input
                style={{ flex: 1, minWidth: 200 }}
                value={hook.command}
                placeholder={t('perm.command')}
                onChange={(e) => updateHook(idx, { command: e.target.value })}
              />
              <button className="danger" onClick={() => removeHook(idx)}>
                <Trash2 size={16} />
              </button>
            </div>
          ))}
        </div>

        <div className="modal-actions">
          <button className="ghost" onClick={addHook}>
            <Plus size={16} /> {t('perm.addHook')}
          </button>
          <button className="primary" onClick={save} disabled={busy}>
            {busy ? <Loader2 className="spin" /> : <ShieldCheck />}
            {t('perm.save')}
          </button>
        </div>

        {saved && <div className="inline-success">{t('perm.saved')}</div>}
        {error && <div className="inline-error">{error}</div>}
      </div>
    </section>
  );
}
