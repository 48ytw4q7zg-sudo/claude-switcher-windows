import { useCallback, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Globe, Loader2, MapPin, RefreshCw, Settings2 } from 'lucide-react';
import type { AppConfig, EgressInfo, RegionLockReport } from './types';

const CLIENT_OPTIONS = [
  { value: 'auto', label: '自动识别' },
  { value: 'clash-verge', label: 'Clash Verge' },
  { value: 'sing-box', label: 'sing-box' },
  { value: 'clashx', label: 'ClashX' },
  { value: 'surge', label: 'Surge' },
  { value: 'wireguard', label: 'WireGuard' },
  { value: 'flclash', label: 'FlClash' },
  { value: 'other', label: '其他' },
];

export function RegionPanel() {
  const [egress, setEgress] = useState<EgressInfo | null>(null);
  const [regionReport, setRegionReport] = useState<RegionLockReport | null>(null);
  const [clientMode, setClientMode] = useState<string>('auto');
  const [applyNow, setApplyNow] = useState(false);
  const [probing, setProbing] = useState(false);
  const [locking, setLocking] = useState(false);
  const [settingClient, setSettingClient] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const probe = useCallback(async () => {
    setProbing(true);
    setError(null);
    try {
      const info = await invoke<EgressInfo>('detect_egress');
      setEgress(info);
    } catch (err) {
      setError(String(err));
    } finally {
      setProbing(false);
    }
  }, []);

  // 回读已保存的代理客户端：不回读会让下拉框在重启后恒显示「自动识别」，
  // 用户一选别的就把旧选择覆盖掉。
  const loadConfig = useCallback(async () => {
    try {
      const cfg = await invoke<AppConfig>('get_appconfig');
      if (cfg.proxy_mode) setClientMode(cfg.proxy_mode);
    } catch {
      // 配置读取失败不阻塞面板，下拉保持默认态。
    }
  }, []);

  useEffect(() => {
    probe();
    loadConfig();
  }, [probe, loadConfig]);

  const lockRegion = async () => {
    setLocking(true);
    setError(null);
    try {
      const report = await invoke<RegionLockReport>('lock_region', { apply: applyNow });
      setRegionReport(report);
    } catch (err) {
      setError(String(err));
    } finally {
      setLocking(false);
    }
  };

  const changeClient = async (value: string) => {
    setClientMode(value);
    setSettingClient(true);
    setError(null);
    try {
      await invoke('set_client', { mode: value });
    } catch (err) {
      setError(String(err));
    } finally {
      setSettingClient(false);
    }
  };

  const busy = probing || locking || settingClient;

  return (
    <div className="panel">
      <div className="panel-title">
        <Globe />
        <span>地区与代理客户端</span>
      </div>

      <div className="clash-summary" style={{ gridTemplateColumns: 'repeat(2, minmax(0,1fr))' }}>
        <div>
          <span>出口 IP</span>
          <strong>{egress?.ip || '未探测'}</strong>
        </div>
        <div>
          <span>国家/地区</span>
          <strong>{egress?.country || '—'}</strong>
        </div>
        <div>
          <span>时区</span>
          <strong>{egress?.iana_tz || '—'}</strong>
        </div>
        <div>
          <span>运营商 / ASN</span>
          <strong style={{ fontSize: 13 }}>{egress?.org || '—'}</strong>
        </div>
      </div>

      {egress?.source && (
        <p className="usage-note">探测来源：{egress.source}</p>
      )}

      <button className="ghost wide" onClick={probe} disabled={busy} style={{ marginTop: 10 }}>
        {probing ? <Loader2 className="spin" /> : <RefreshCw />}
        探测出口
      </button>

      <label style={{ marginTop: 16 }}>
        代理客户端
        <select value={clientMode} onChange={(e) => changeClient(e.target.value)} disabled={busy}>
          {CLIENT_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      </label>

      <div className="link-mode-row" style={{ cursor: 'pointer', marginTop: 14 }}>
        <span>锁定地区时立即应用到系统时区/区域</span>
        <input
          type="checkbox"
          checked={applyNow}
          onChange={(e) => setApplyNow(e.target.checked)}
          style={{ width: 16, height: 16, flex: '0 0 auto' }}
        />
      </div>

      <button className="primary wide" onClick={lockRegion} disabled={busy} style={{ marginTop: 12 }}>
        {locking ? <Loader2 className="spin" /> : <MapPin />}
        {applyNow ? '锁定地区并立即应用' : '仅保存目标地区'}
      </button>

      {regionReport && (
        <div className="inline-warning" style={{ marginTop: 12 }}>
          <Settings2 /> {regionReport.message}
          <div style={{ marginTop: 6, fontSize: 12, fontWeight: 600 }}>
            目标：{regionReport.plan.country} · {regionReport.plan.iana_tz} · {regionReport.plan.locale}
            {regionReport.applied ? '（已应用到系统）' : '（仅保存，未应用）'}
          </div>
        </div>
      )}

      {error && (
        <div className="inline-error" style={{ marginTop: 12 }}>
          {error}
        </div>
      )}
    </div>
  );
}
