import { useCallback, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Globe, Loader2, Plug, Trash2 } from 'lucide-react';
import { useI18n } from '../i18n';

interface ProviderProfile {
  id: string;
  name: string;
  base_url: string;
  model_env: Record<string, string>;
  managed_env_keys: string[];
  created_at: string;
  updated_at: string;
}

/** 把每行 KEY=VALUE 解析成 map（忽略空行与无 '=' 的行）。 */
function parseModelEnv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf('=');
    if (eq <= 0) continue;
    out[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
  }
  return out;
}

/** F-5：第三方供应商管理。 */
export function ProviderPanel() {
  const { t } = useI18n();
  const [providers, setProviders] = useState<ProviderProfile[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [authToken, setAuthToken] = useState('');
  const [modelEnvText, setModelEnvText] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const [list, active] = await Promise.all([
      invoke<ProviderProfile[]>('list_providers'),
      invoke<string | null>('get_active_provider_id'),
    ]);
    setProviders(list);
    setActiveId(active ?? null);
  }, []);

  useEffect(() => {
    refresh().catch((e) => setError(String(e)));
  }, [refresh]);

  const run = useCallback(
    async (id: string, action: () => Promise<unknown>, success: string) => {
      setBusy(id);
      setError(null);
      try {
        await action();
        await refresh();
        setNote(success);
      } catch (e) {
        setError(String(e));
      } finally {
        setBusy(null);
      }
    },
    [refresh],
  );

  const canCreate = name.trim() && baseUrl.trim() && authToken.trim();

  return (
    <section className="profiles">
      <div className="section-title">
        <h2>{t('provider.title')}</h2>
      </div>
      <div className="panel">
        <p className="telemetry-intro">{t('provider.intro')}</p>

        {/* 新建表单 */}
        <div className="runtime-bind">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t('provider.name')}
          />
          <input
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder={t('provider.baseUrl')}
          />
          <input
            type="password"
            value={authToken}
            onChange={(e) => setAuthToken(e.target.value)}
            placeholder={t('provider.authToken')}
          />
        </div>
        <textarea
          className="model-env"
          rows={3}
          value={modelEnvText}
          onChange={(e) => setModelEnvText(e.target.value)}
          placeholder={t('provider.modelEnv')}
        />
        <div className="quota-controls">
          <button
            className="primary"
            disabled={busy !== null || !canCreate}
            onClick={() =>
              run(
                'create',
                () =>
                  invoke('create_provider', {
                    name,
                    baseUrl,
                    authToken,
                    modelEnv: parseModelEnv(modelEnvText),
                  }),
                t('provider.create'),
              )
            }
          >
            {busy === 'create' ? <Loader2 className="spin" /> : <Plug />}
            {t('provider.create')}
          </button>
        </div>

        {/* 供应商列表 */}
        <div className="provider-list">
          {providers.map((p) => (
            <article className="provider-row" key={p.id}>
              <div className="profile-head">
                <div>
                  <strong>{p.name}</strong>
                  <span>{p.base_url}</span>
                </div>
                {activeId === p.id && (
                  <span className="active-mark">{t('provider.active')}</span>
                )}
              </div>
              <div className="profile-actions">
                <button
                  className="primary"
                  disabled={busy !== null || activeId === p.id}
                  onClick={() =>
                    run(
                      `switch-${p.id}`,
                      () => invoke('switch_to_provider', { id: p.id }),
                      t('provider.switch'),
                    )
                  }
                >
                  {busy === `switch-${p.id}` ? <Loader2 className="spin" /> : <Globe />}
                  {t('provider.switch')}
                </button>
                <button
                  className="ghost"
                  disabled={busy !== null}
                  onClick={() =>
                    run(
                      `test-${p.id}`,
                      () =>
                        invoke('test_provider_connection', { baseUrl: p.base_url }),
                      t('provider.test'),
                    )
                  }
                >
                  {busy === `test-${p.id}` ? <Loader2 className="spin" /> : <Plug />}
                  {t('provider.test')}
                </button>
                <button
                  className="danger"
                  disabled={busy !== null}
                  onClick={() =>
                    run(
                      `delete-${p.id}`,
                      () => invoke('delete_provider', { id: p.id }),
                      t('provider.delete'),
                    )
                  }
                >
                  {busy === `delete-${p.id}` ? <Loader2 className="spin" /> : <Trash2 />}
                </button>
              </div>
            </article>
          ))}
        </div>
      </div>
      {note && <div className="inline-success">{note}</div>}
      {error && <div className="inline-error">{error}</div>}
    </section>
  );
}
