import { useCallback, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  FolderInput,
  Loader2,
  Package,
  Pin,
  Play,
  SquareMenu,
  Wrench,
} from 'lucide-react';
import { useI18n } from '../i18n';

/**
 * F-1 / F-2 / F-7：命令行集成面板。
 * - 用户 PATH 增删（REG_EXPAND_SZ）
 * - 目录绑定 / 解绑（cs run）
 * - 开始菜单快捷方式重建 / 清理
 * - 生成脱敏诊断包
 */
export function IntegrationPanel() {
  const { t } = useI18n();
  const [binDir, setBinDir] = useState('');
  const [dir, setDir] = useState('');
  const [accountName, setAccountName] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    invoke<string>('get_tool_bin_dir').then(setBinDir).catch(() => undefined);
  }, []);

  const run = useCallback(
    async (id: string, action: () => Promise<unknown>, success: string) => {
      setBusy(id);
      setError(null);
      try {
        await action();
        setMessage(success);
      } catch (e) {
        setError(String(e));
      } finally {
        setBusy(null);
      }
    },
    [],
  );

  return (
    <section className="profiles">
      <div className="section-title">
        <h2>{t('integ.title')}</h2>
      </div>

      {/* 用户 PATH */}
      <div className="panel">
        <div className="panel-title">
          <Wrench />
          <span>{t('integ.path.title')}</span>
        </div>
        <p className="telemetry-intro">{t('integ.path.intro')}</p>
        <code className="path-preview">{binDir || '…'}</code>
        <div className="quota-controls">
          <button
            className="primary"
            disabled={busy !== null || !binDir}
            onClick={() =>
              run(
                'path-add',
                () => invoke('add_to_user_path', { binDir }),
                t('integ.path.add'),
              )
            }
          >
            {busy === 'path-add' ? <Loader2 className="spin" /> : <Pin />}
            {t('integ.path.add')}
          </button>
          <button
            className="ghost"
            disabled={busy !== null || !binDir}
            onClick={() =>
              run(
                'path-remove',
                () => invoke('remove_from_user_path', { binDir }),
                t('integ.path.remove'),
              )
            }
          >
            {busy === 'path-remove' ? <Loader2 className="spin" /> : <Pin />}
            {t('integ.path.remove')}
          </button>
        </div>
      </div>

      {/* 目录绑定 */}
      <div className="panel">
        <div className="panel-title">
          <FolderInput />
          <span>{t('integ.bind.title')}</span>
        </div>
        <p className="telemetry-intro">{t('integ.bind.intro')}</p>
        <div className="runtime-bind">
          <input
            value={dir}
            onChange={(e) => setDir(e.target.value)}
            placeholder={t('integ.bind.dir')}
          />
          <input
            value={accountName}
            onChange={(e) => setAccountName(e.target.value)}
            placeholder={t('integ.bind.account')}
          />
        </div>
        <div className="quota-controls">
          <button
            className="primary"
            disabled={busy !== null || !dir || !accountName}
            onClick={() =>
              run(
                'bind',
                () =>
                  invoke('bind_directory', {
                    dir,
                    accountName,
                  }),
                t('integ.bind.bind'),
              )
            }
          >
            {busy === 'bind' ? <Loader2 className="spin" /> : <FolderInput />}
            {t('integ.bind.bind')}
          </button>
          <button
            className="ghost"
            disabled={busy !== null || !dir}
            onClick={() =>
              run(
                'unbind',
                () => invoke('unbind_directory', { dir }),
                t('integ.bind.unbind'),
              )
            }
          >
            {busy === 'unbind' ? <Loader2 className="spin" /> : <FolderInput />}
            {t('integ.bind.unbind')}
          </button>
        </div>
      </div>

      {/* 开始菜单 */}
      <div className="panel">
        <div className="panel-title">
          <SquareMenu />
          <span>{t('integ.menu.title')}</span>
        </div>
        <p className="telemetry-intro">{t('integ.menu.intro')}</p>
        <div className="quota-controls">
          <button
            className="primary"
            disabled={busy !== null}
            onClick={() =>
              run(
                'menu-rebuild',
                () => invoke('rebuild_start_menu_shortcuts'),
                t('integ.menu.rebuild'),
              )
            }
          >
            {busy === 'menu-rebuild' ? <Loader2 className="spin" /> : <SquareMenu />}
            {t('integ.menu.rebuild')}
          </button>
          <button
            className="ghost"
            disabled={busy !== null}
            onClick={() =>
              run(
                'menu-clear',
                () => invoke('clear_start_menu_shortcuts'),
                t('integ.menu.clear'),
              )
            }
          >
            {busy === 'menu-clear' ? <Loader2 className="spin" /> : <SquareMenu />}
            {t('integ.menu.clear')}
          </button>
        </div>
      </div>

      {/* 诊断包 */}
      <div className="panel">
        <div className="panel-title">
          <Package />
          <span>{t('integ.diag.title')}</span>
        </div>
        <p className="telemetry-intro">{t('integ.diag.intro')}</p>
        <div className="quota-controls">
          <button
            className="primary"
            disabled={busy !== null}
            onClick={() =>
              run(
                'diag',
                async () => {
                  const path = await invoke<string>('build_diagnostic_bundle', {
                    includeNetwork: false,
                  });
                  setMessage(path);
                },
                t('integ.diag.build'),
              )
            }
          >
            {busy === 'diag' ? <Loader2 className="spin" /> : <Play />}
            {t('integ.diag.build')}
          </button>
        </div>
      </div>

      {message && <div className="inline-success">{message}</div>}
      {error && <div className="inline-error">{error}</div>}
    </section>
  );
}
