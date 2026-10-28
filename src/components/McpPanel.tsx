import { useCallback, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Box, Loader2, Plus, Trash2, Wrench } from 'lucide-react';
import type { McpServer } from './types';

type Scope = 'global' | 'project';

/**
 * P2-3：MCP 服务器管理。
 * 管理全局 ~/.claude.json 的 mcpServers 与项目 .mcp.json；
 * stdio 以 npx/npm/pnpm/yarn 启动时后端自动 cmd /c 包装；
 * 密钥类 env 只显示键名，不展示值，也不写进日志。
 */
export function McpPanel() {
  const [scope, setScope] = useState<Scope>('global');
  const [projectDir, setProjectDir] = useState<string>('');
  const [servers, setServers] = useState<Record<string, McpServer>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // 新增表单。
  const [formType, setFormType] = useState<'stdio' | 'http' | 'sse'>('stdio');
  const [name, setName] = useState('');
  const [command, setCommand] = useState('');
  const [argsText, setArgsText] = useState('');
  const [envText, setEnvText] = useState('');
  const [url, setUrl] = useState('');

  const load = useCallback(async () => {
    try {
      const result = await invoke<Record<string, McpServer>>('list_mcp_servers', {
        scope,
        projectDir: scope === 'project' ? projectDir || null : null,
      });
      setServers(result);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, [scope, projectDir]);

  useEffect(() => {
    load();
  }, [load]);

  const resetForm = () => {
    setName('');
    setCommand('');
    setArgsText('');
    setEnvText('');
    setUrl('');
    setFormType('stdio');
  };

  const addServer = async () => {
    if (!name.trim()) {
      setError('请填写服务器名称');
      return;
    }
    let server: McpServer;
    if (formType === 'stdio') {
      if (!command.trim()) {
        setError('stdio 服务器必须填写 command');
        return;
      }
      const args = argsText
        .split('\n')
        .map((a) => a.trim())
        .filter(Boolean);
      const env: Record<string, string> = {};
      envText
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean)
        .forEach((line) => {
          const idx = line.indexOf('=');
          if (idx > 0) env[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
        });
      server = { type: 'stdio', command: command.trim(), args, env };
    } else {
      if (!url.trim()) {
        setError(`${formType} 服务器必须填写 url`);
        return;
      }
      server = { type: formType, url: url.trim() };
    }

    setBusy('add');
    try {
      await invoke('upsert_mcp_server', {
        scope,
        projectDir: scope === 'project' ? projectDir || null : null,
        name: name.trim(),
        server,
      });
      resetForm();
      await load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  };

  const removeServer = async (key: string) => {
    setBusy(key);
    try {
      await invoke('delete_mcp_server', {
        scope,
        projectDir: scope === 'project' ? projectDir || null : null,
        name: key,
      });
      await load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="profiles">
      <div className="section-title">
        <h2>MCP 服务器</h2>
        <span>{Object.keys(servers).length} 个</span>
      </div>
      <div className="panel">
        <div className="panel-title">
          <Box />
          <span>管理 mcpServers（全局 / 项目）</span>
        </div>

        <div className="mcp-scope">
          <button
            className={scope === 'global' ? 'primary' : 'ghost'}
            onClick={() => setScope('global')}
          >
            全局（~/.claude.json）
          </button>
          <button
            className={scope === 'project' ? 'primary' : 'ghost'}
            onClick={() => setScope('project')}
          >
            项目（.mcp.json）
          </button>
          {scope === 'project' && (
            <input
              placeholder="项目目录（留空=当前目录）"
              value={projectDir}
              onChange={(e) => setProjectDir(e.target.value)}
            />
          )}
        </div>

        <div className="mcp-list">
          {Object.entries(servers).length === 0 && <p className="muted">暂无 MCP 服务器。</p>}
          {Object.entries(servers).map(([key, srv]) => {
            const isStdio = (srv.type ?? 'stdio') === 'stdio';
            const target = isStdio
              ? `${srv.command ?? ''} ${(srv.args ?? []).join(' ')}`.trim()
              : srv.url ?? '';
            const envKeys = Object.keys(srv.env ?? {});
            return (
              <div className="mcp-row" key={key}>
                <div>
                  <strong>{key}</strong>
                  <span className="mcp-target">{target}</span>
                  {envKeys.length > 0 && (
                    <span className="mcp-env">env: {envKeys.join(', ')}</span>
                  )}
                </div>
                <button className="danger" onClick={() => removeServer(key)} disabled={busy === key}>
                  {busy === key ? <Loader2 className="spin" /> : <Trash2 />}
                </button>
              </div>
            );
          })}
        </div>

        <div className="mcp-form">
          <div className="mcp-form-head">
            <Wrench />
            <span>新增服务器</span>
            <select
              value={formType}
              onChange={(e) => setFormType(e.target.value as 'stdio' | 'http' | 'sse')}
            >
              <option value="stdio">stdio</option>
              <option value="http">http</option>
              <option value="sse">sse</option>
            </select>
          </div>
          <input placeholder="名称（唯一标识）" value={name} onChange={(e) => setName(e.target.value)} />
          {formType === 'stdio' ? (
            <>
              <input
                placeholder="command（如 npx；npx 系会自动 cmd /c 包装）"
                value={command}
                onChange={(e) => setCommand(e.target.value)}
              />
              <textarea
                placeholder="args：每行一个参数"
                value={argsText}
                onChange={(e) => setArgsText(e.target.value)}
                rows={2}
              />
              <textarea
                placeholder="env：每行 KEY=VALUE（密钥不进日志）"
                value={envText}
                onChange={(e) => setEnvText(e.target.value)}
                rows={2}
              />
            </>
          ) : (
            <input placeholder="url（http:// 或 https://）" value={url} onChange={(e) => setUrl(e.target.value)} />
          )}
          <button className="primary" onClick={addServer} disabled={busy === 'add'}>
            {busy === 'add' ? <Loader2 className="spin" /> : <Plus />}
            添加
          </button>
        </div>

        {error && <div className="inline-error">{error}</div>}
      </div>
    </section>
  );
}
