import { useCallback, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  CheckCircle2,
  Loader2,
  Radar,
  ShieldCheck,
  ShieldX,
  Trash2,
} from 'lucide-react';
import type { GuardTick } from './types';

export function GuardPanel() {
  const [installed, setInstalled] = useState<boolean | null>(null);
  const [tick, setTick] = useState<GuardTick | null>(null);
  const [busy, setBusy] = useState<'install' | 'uninstall' | 'tick' | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refreshStatus = useCallback(async () => {
    try {
      const s = await invoke<{ installed: boolean }>('guard_status');
      setInstalled(s.installed);
    } catch (err) {
      setError(String(err));
    }
  }, []);

  useEffect(() => {
    refreshStatus();
  }, [refreshStatus]);

  const runTick = async () => {
    setBusy('tick');
    setError(null);
    try {
      const result = await invoke<GuardTick>('guard_run_tick');
      setTick(result);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(null);
    }
  };

  const install = async () => {
    setBusy('install');
    setError(null);
    try {
      await invoke('install_guard_cmd');
      await refreshStatus();
    } catch (err) {
      // 安装可能触发 UAC，失败把后端错误文本直接展示。
      setError(String(err));
    } finally {
      setBusy(null);
    }
  };

  const uninstall = async () => {
    setBusy('uninstall');
    setError(null);
    try {
      await invoke('uninstall_guard_cmd');
      setTick(null);
      await refreshStatus();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="panel">
      <div className="panel-title">
        <ShieldCheck />
        <span>保镖（后台巡检）</span>
      </div>

      <div className="clash-summary" style={{ gridTemplateColumns: 'repeat(2, minmax(0,1fr))' }}>
        <div>
          <span>安装状态</span>
          <strong>
            {installed === null ? '读取中' : installed ? '已安装' : '未安装'}
          </strong>
        </div>
        <div>
          <span>TUN 状态</span>
          <strong>{tick ? (tick.tun_up ? '正常' : '异常') : '未巡检'}</strong>
        </div>
        <div>
          <span>代理客户端</span>
          <strong>{tick ? (tick.client_up ? '在线' : '未运行') : '未巡检'}</strong>
        </div>
        <div>
          <span>保镖存活</span>
          <strong>{tick ? (tick.alive ? '存活' : '未存活') : '未巡检'}</strong>
        </div>
      </div>

      {tick && tick.tun_detail && (
        <p className="usage-note" style={{ marginTop: 8 }}>
          TUN：{tick.tun_detail}
        </p>
      )}
      {tick && tick.killed.length > 0 && (
        <div className="inline-warning" style={{ marginTop: 10 }}>
          本次巡检结束了 {tick.killed.length} 个越权进程：
          <div style={{ marginTop: 4, fontSize: 12, fontWeight: 600 }}>
            {tick.killed.join('、')}
          </div>
        </div>
      )}

      <div className="profile-actions" style={{ marginTop: 14 }}>
        {installed ? (
          <button className="danger" onClick={uninstall} disabled={!!busy} title="卸载保镖">
            {busy === 'uninstall' ? <Loader2 className="spin" /> : <Trash2 />}
            卸载
          </button>
        ) : (
          <button className="primary" onClick={install} disabled={!!busy}>
            {busy === 'install' ? <Loader2 className="spin" /> : <ShieldCheck />}
            安装保镖
          </button>
        )}
        <button className="ghost" onClick={runTick} disabled={!!busy || !installed}>
          {busy === 'tick' ? <Loader2 className="spin" /> : <Radar />}
          立即巡检
        </button>
      </div>

      {error && (
        <div className="inline-error" style={{ marginTop: 12 }}>
          {error}
        </div>
      )}

      {!error && installed === false && (
        <p className="usage-note" style={{ marginTop: 10 }}>
          <ShieldX /> 安装可能弹出 UAC 提权窗口；安装后后台会定时巡检 TUN 与代理客户端。
        </p>
      )}
      {!error && installed === true && (
        <p className="usage-note" style={{ marginTop: 10 }}>
          <CheckCircle2 /> 保镖已安装；点「立即巡检」手动跑一次检查。
        </p>
      )}
    </div>
  );
}
