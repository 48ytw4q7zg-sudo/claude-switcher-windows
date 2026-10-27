import { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  Bug,
  Globe,
  Loader2,
  Lock,
  MonitorSmartphone,
  ShieldAlert,
  TerminalSquare,
} from 'lucide-react';
import type { CliInfo, SystemFingerprint } from './types';
import { humanBytes } from './types';

export function PrivacyTools() {
  // 安全浏览器
  const [safeUrl, setSafeUrl] = useState('https://');
  const [safeSession, setSafeSession] = useState<string | null>(null);
  // 代理诊断
  const [proxyUrl, setProxyUrl] = useState('http://127.0.0.1:7897');
  const [proxyResult, setProxyResult] = useState<Record<string, unknown> | null>(null);
  // 指纹体检
  const [fingerprint, setFingerprint] = useState<SystemFingerprint | null>(null);
  // CLI 体检
  const [cliInfo, setCliInfo] = useState<CliInfo | null>(null);

  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const openSafe = async () => {
    setBusy('safe-open');
    setError(null);
    try {
      const id = await invoke<string>('open_safe_cmd', { url: safeUrl.trim() });
      setSafeSession(id);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(null);
    }
  };

  const closeSafe = async () => {
    if (!safeSession) return;
    setBusy('safe-close');
    setError(null);
    try {
      await invoke('close_safe_cmd', { id: safeSession });
      setSafeSession(null);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(null);
    }
  };

  const diagnoseProxy = async () => {
    setBusy('proxy');
    setError(null);
    setProxyResult(null);
    try {
      const result = await invoke<Record<string, unknown>>('diagnose_proxy_cmd', {
        proxyUrl: proxyUrl.trim(),
      });
      setProxyResult(result);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(null);
    }
  };

  const loadFingerprint = async () => {
    setBusy('fingerprint');
    setError(null);
    try {
      const fp = await invoke<SystemFingerprint>('system_fingerprint_cmd');
      setFingerprint(fp);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(null);
    }
  };

  const loadCliInfo = async () => {
    setBusy('cli');
    setError(null);
    try {
      const info = await invoke<CliInfo>('cli_info_cmd');
      setCliInfo(info);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="profiles">
      <div className="section-title">
        <h2>隐私与诊断工具</h2>
        <span>本地隔离 · 不联动账号切换</span>
      </div>

      {error && (
        <div className="inline-error" style={{ marginBottom: 12 }}>
          <ShieldAlert /> {error}
        </div>
      )}

      <div className="profile-grid" style={{ gridTemplateColumns: 'repeat(2, minmax(0,1fr))' }}>
        {/* 安全浏览器 */}
        <div className="panel">
          <div className="panel-title">
            <Lock />
            <span>安全浏览器</span>
          </div>
          <p className="telemetry-intro">
            打开一个带指纹隔离 / 代理强制的临时浏览器窗口，关闭后会话与缓存全部销毁。
          </p>
          <input
            value={safeUrl}
            onChange={(e) => setSafeUrl(e.target.value)}
            placeholder="https://example.com"
            style={{ marginTop: 8 }}
          />
          <div className="profile-actions" style={{ marginTop: 10 }}>
            <button className="primary" onClick={openSafe} disabled={busy !== null}>
              {busy === 'safe-open' ? <Loader2 className="spin" /> : <Globe />}
              打开安全窗口
            </button>
            <button
              className="ghost"
              onClick={closeSafe}
              disabled={busy !== null || !safeSession}
            >
              {busy === 'safe-close' ? <Loader2 className="spin" /> : <Lock />}
              关闭并销毁
            </button>
          </div>
          {safeSession && (
            <p className="usage-note" style={{ marginTop: 8 }}>
              当前会话：{safeSession}
            </p>
          )}
        </div>

        {/* 代理诊断 */}
        <div className="panel">
          <div className="panel-title">
            <Bug />
            <span>代理诊断</span>
          </div>
          <p className="telemetry-intro">
            测试代理地址是否可达、是否需要认证（401/403 会标注）。
          </p>
          <input
            value={proxyUrl}
            onChange={(e) => setProxyUrl(e.target.value)}
            placeholder="http://127.0.0.1:7897"
            style={{ marginTop: 8 }}
          />
          <button
            className="primary wide"
            onClick={diagnoseProxy}
            disabled={busy !== null}
            style={{ marginTop: 10 }}
          >
            {busy === 'proxy' ? <Loader2 className="spin" /> : <Bug />}
            开始诊断
          </button>
          {proxyResult && (
            <pre className="diag-pre">{JSON.stringify(proxyResult, null, 2)}</pre>
          )}
        </div>

        {/* 指纹体检 */}
        <div className="panel">
          <div className="panel-title">
            <MonitorSmartphone />
            <span>系统指纹体检</span>
          </div>
          <p className="telemetry-intro">
            读取 OS / CPU / 内存 / GPU / 是否虚拟机，用于判断当前环境是否容易被关联。
          </p>
          <button className="ghost wide" onClick={loadFingerprint} disabled={busy !== null}>
            {busy === 'fingerprint' ? <Loader2 className="spin" /> : <MonitorSmartphone />}
            读取指纹
          </button>
          {fingerprint && (
            <div className="field-list" style={{ marginTop: 12 }}>
              <div className="field">
                <span>系统</span>
                <strong>
                  {fingerprint.os_name} {fingerprint.os_version} ({fingerprint.cpu_arch})
                </strong>
              </div>
              <div className="field">
                <span>主机名</span>
                <strong>{fingerprint.host_name}</strong>
              </div>
              <div className="field">
                <span>CPU</span>
                <strong style={{ fontSize: 12 }}>{fingerprint.cpu_brand}</strong>
              </div>
              <div className="field">
                <span>内存</span>
                <strong>{humanBytes(fingerprint.total_memory_bytes)}</strong>
              </div>
              <div className="field">
                <span>GPU</span>
                <strong style={{ fontSize: 12 }}>{fingerprint.gpu}</strong>
              </div>
              <div className="field">
                <span>虚拟机判定</span>
                <strong style={{ color: fingerprint.virtual_machine ? '#7a2722' : '#17463b' }}>
                  {fingerprint.virtual_machine ? '疑似虚拟机' : '物理机'}
                </strong>
              </div>
              {fingerprint.vm_reasons.length > 0 && (
                <div className="inline-warning" style={{ marginTop: 8 }}>
                  判定依据：{fingerprint.vm_reasons.join('、')}
                </div>
              )}
              {fingerprint.web_notice && (
                <p className="usage-note" style={{ marginTop: 8 }}>
                  {fingerprint.web_notice}
                </p>
              )}
            </div>
          )}
        </div>

        {/* CLI 体检 */}
        <div className="panel">
          <div className="panel-title">
            <TerminalSquare />
            <span>Claude Code CLI 体检</span>
          </div>
          <p className="telemetry-intro">
            扫描本机安装的 claude 可执行文件路径、版本与安装方式。
          </p>
          <button className="ghost wide" onClick={loadCliInfo} disabled={busy !== null}>
            {busy === 'cli' ? <Loader2 className="spin" /> : <TerminalSquare />}
            扫描 CLI
          </button>
          {cliInfo && (
            <div style={{ marginTop: 12 }}>
              <div className="link-mode-row">
                <span>是否找到 claude</span>
                <strong>{cliInfo.found ? '是' : '否'}</strong>
              </div>
              {cliInfo.config_dir && (
                <div className="link-mode-row">
                  <span>配置目录</span>
                  <strong style={{ fontSize: 12 }}>{cliInfo.config_dir}</strong>
                </div>
              )}
              {cliInfo.instances.map((inst, i) => (
                <div className="link-mode-row" key={i}>
                  <span>#{inst.order} · {inst.install_method}</span>
                  <strong style={{ fontSize: 11 }}>
                    {inst.version ? `v${inst.version} · ` : ''}
                    {inst.path}
                  </strong>
                </div>
              ))}
              {cliInfo.warnings.length > 0 && (
                <div className="inline-warning" style={{ marginTop: 8 }}>
                  {cliInfo.warnings.map((w, i) => (
                    <div key={i} style={{ fontSize: 12, fontWeight: 600 }}>
                      · {w}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
