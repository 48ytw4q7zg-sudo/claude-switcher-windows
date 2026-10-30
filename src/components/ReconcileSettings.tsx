import { useCallback, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Loader2, UserPlus, UserRoundX } from 'lucide-react';
import type { AppConfig } from './types';

/**
 * H-6：切换前对账时的「自动收养」开关。
 * 检测到 store 里没有登记的 live 账号时：开启则自动新建为快照，关闭则只提示、
 * 不动账号库。默认开启。
 */
export function ReconcileSettings() {
  const [enabled, setEnabled] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const cfg = await invoke<AppConfig>('get_appconfig');
      setEnabled(cfg.auto_adopt_enabled ?? true);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const toggle = async () => {
    const next = !enabled;
    setBusy(true);
    setError(null);
    try {
      const cfg = await invoke<AppConfig>('set_auto_adopt', { enabled: next });
      setEnabled(cfg.auto_adopt_enabled ?? next);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="profiles">
      <div className="section-title">
        <h2>对账自动收养</h2>
        <span>{enabled ? '未登记账号自动收养' : '只提示，不自动新建'}</span>
      </div>
      <div className="panel">
        <div className="panel-title">
          {enabled ? <UserPlus /> : <UserRoundX />}
          <span>检测到未登记账号时的处理方式</span>
        </div>
        <p className="telemetry-intro">
          切换前会比对当前 live 账号与账号库：开启时未登记账号自动收养为快照，关闭时仅提示、
          由你手动处理，不会自动改动账号库。
        </p>
        <div className="quota-controls">
          <button
            className={enabled ? 'primary' : 'ghost'}
            onClick={toggle}
            disabled={busy}
          >
            {busy ? <Loader2 className="spin" /> : enabled ? <UserPlus /> : <UserRoundX />}
            {enabled ? '自动收养已开启' : '自动收养已关闭'}
          </button>
        </div>
        {error && <div className="inline-error">{error}</div>}
      </div>
    </section>
  );
}
