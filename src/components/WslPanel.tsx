import { useCallback, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Eraser, Loader2, RefreshCw, Terminal } from 'lucide-react';
import { useI18n } from '../i18n';

/** F-6：WSL 集成（实验功能，默认关闭）。 */
export function WslPanel() {
  const { t } = useI18n();
  const [enabled, setEnabled] = useState(false);
  const [distros, setDistros] = useState<string[]>([]);
  const [distro, setDistro] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const refreshDistros = useCallback(async () => {
    const list = await invoke<string[]>('list_wsl_distros');
    setDistros(list);
    if (list.length && !list.includes(distro)) setDistro(list[0]);
  }, [distro]);

  useEffect(() => {
    invoke<boolean>('set_wsl_integration_enabled', { enabled: false })
      .then(() => undefined)
      .catch(() => undefined);
    refreshDistros().catch((e) => setError(String(e)));
    // 仅在挂载时加载一次。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const run = useCallback(
    async (id: string, action: () => Promise<unknown>, success: string) => {
      setBusy(id);
      setError(null);
      try {
        await action();
        setNote(success);
      } catch (e) {
        setError(String(e));
      } finally {
        setBusy(null);
      }
    },
    [],
  );

  const toggle = async () => {
    const next = !enabled;
    setBusy('toggle');
    setError(null);
    try {
      const result = await invoke<boolean>('set_wsl_integration_enabled', {
        enabled: next,
      });
      setEnabled(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="profiles">
      <div className="section-title">
        <h2>{t('wsl.title')}</h2>
      </div>
      <div className="panel">
        <p className="telemetry-intro">{t('wsl.intro')}</p>
        <div className="quota-controls">
          <button
            className={enabled ? 'primary' : 'ghost'}
            disabled={busy !== null}
            onClick={toggle}
          >
            {busy === 'toggle' ? <Loader2 className="spin" /> : <Terminal />}
            {t('wsl.enable')}（{enabled ? 'ON' : 'OFF'}）
          </button>
        </div>

        <div className="node-bind">
          <select
            value={distro}
            onChange={(e) => setDistro(e.target.value)}
            disabled={!enabled || busy !== null}
          >
            {distros.map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </select>
          <button
            className="ghost"
            disabled={busy !== null}
            onClick={() =>
              run(
                'refresh',
                refreshDistros,
                t('wsl.refresh'),
              )
            }
          >
            <RefreshCw />
            {t('wsl.refresh')}
          </button>
        </div>

        <div className="quota-controls">
          <button
            className="primary"
            disabled={busy !== null || !enabled || !distro}
            onClick={() =>
              run(
                'write',
                () => invoke('write_wsl_credentials', { distro }),
                t('wsl.write'),
              )
            }
          >
            {busy === 'write' ? <Loader2 className="spin" /> : <Terminal />}
            {t('wsl.write')}
          </button>
          <button
            className="ghost"
            disabled={busy !== null || !distro}
            onClick={() =>
              run(
                'clear',
                () => invoke('clear_wsl_credentials', { distro }),
                t('wsl.clear'),
              )
            }
          >
            {busy === 'clear' ? <Loader2 className="spin" /> : <Eraser />}
            {t('wsl.clear')}
          </button>
        </div>
      </div>
      {note && <div className="inline-success">{note}</div>}
      {error && <div className="inline-error">{error}</div>}
    </section>
  );
}
