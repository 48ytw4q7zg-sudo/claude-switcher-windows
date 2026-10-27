import { useCallback, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  CheckCircle2,
  Globe,
  Loader2,
  RefreshCw,
  Settings2,
} from 'lucide-react';
import type { RulesReport } from './types';

const MODE_LABELS: Record<string, string> = {
  rule: '规则模式 (rule)',
  global: '全局模式 (global)',
  direct: '直连模式 (direct)',
  unknown: '未知',
};

export function ClashModePanel() {
  const [mode, setMode] = useState<string | null>(null);
  const [rules, setRules] = useState<RulesReport | null>(null);
  const [webrtc, setWebrtc] = useState<string>('proxy');
  const [loadingMode, setLoadingMode] = useState(false);
  const [writingRules, setWritingRules] = useState(false);
  const [settingWebrtc, setSettingWebrtc] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadMode = useCallback(async () => {
    setLoadingMode(true);
    try {
      const m = await invoke<string>('get_clash_mode');
      setMode(m);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoadingMode(false);
    }
  }, []);

  useEffect(() => {
    loadMode();
  }, [loadMode]);

  const writeRules = async () => {
    setWritingRules(true);
    setError(null);
    try {
      const report = await invoke<RulesReport>('ensure_clash_rules');
      setRules(report);
      setMode(report.mode);
    } catch (err) {
      setError(String(err));
    } finally {
      setWritingRules(false);
    }
  };

  const changeWebrtc = async (policy: string) => {
    setWebrtc(policy);
    setSettingWebrtc(true);
    setError(null);
    try {
      await invoke('set_webrtc_policy', { policy });
    } catch (err) {
      setError(String(err));
    } finally {
      setSettingWebrtc(false);
    }
  };

  const busy = loadingMode || writingRules || settingWebrtc;

  return (
    <div className="panel">
      <div className="panel-title">
        <Globe />
        <span>Clash 模式 / 规则 / WebRTC</span>
      </div>

      <div className="clash-summary" style={{ gridTemplateColumns: 'repeat(2, minmax(0,1fr))' }}>
        <div>
          <span>当前模式</span>
          <strong>{mode ? MODE_LABELS[mode] ?? mode : '读取中'}</strong>
        </div>
        <div>
          <span>内核校验</span>
          <strong>
            {rules ? (rules.kernel_verified ? '通过' : '未通过') : '未写入'}
          </strong>
        </div>
      </div>

      <button className="ghost wide" onClick={loadMode} disabled={busy} style={{ marginTop: 10 }}>
        {loadingMode ? <Loader2 className="spin" /> : <RefreshCw />}
        刷新模式
      </button>

      <button className="primary wide" onClick={writeRules} disabled={busy} style={{ marginTop: 10 }}>
        {writingRules ? <Loader2 className="spin" /> : <Settings2 />}
        写入 / 校验 Clash 规则
      </button>

      {rules && (
        <div className="inline-warning" style={{ marginTop: 12 }}>
          <div>
            脚本变更：{rules.script_changed ? '是' : '否'}
            {rules.script_backup ? `（备份：${rules.script_backup}）` : ''}
          </div>
          <div>
            Merge 变更：{rules.merge_changed ? '是' : '否'}
            {rules.merge_backup ? `（备份：${rules.merge_backup}）` : ''}
          </div>
          <div>重启 Clash：{rules.restart_attempted ? '已尝试' : '未尝试'}</div>
          {rules.messages.length > 0 && (
            <div style={{ marginTop: 6, fontSize: 12, fontWeight: 600, whiteSpace: 'pre-line' }}>
              {rules.messages.join('\n')}
            </div>
          )}
        </div>
      )}

      <label style={{ marginTop: 16 }}>
        WebRTC 策略（防止 WebRTC 泄露真实 IP）
        <div className="telemetry-options" style={{ marginTop: 8 }}>
          <button
            className={webrtc === 'proxy' ? 'primary' : 'ghost'}
            onClick={() => changeWebrtc('proxy')}
            disabled={busy}
          >
            {webrtc === 'proxy' ? <CheckCircle2 /> : null}
            走代理（推荐）
          </button>
          <button
            className={webrtc === 'reject' ? 'primary' : 'ghost'}
            onClick={() => changeWebrtc('reject')}
            disabled={busy}
          >
            {webrtc === 'reject' ? <CheckCircle2 /> : null}
            完全拒绝
          </button>
        </div>
      </label>

      {error && (
        <div className="inline-error" style={{ marginTop: 12 }}>
          {error}
        </div>
      )}
    </div>
  );
}
