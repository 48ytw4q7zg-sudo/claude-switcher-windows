import { useCallback, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Bell, BellOff, Loader2, Repeat, TriangleAlert } from 'lucide-react';
import type { QuotaReminder } from './types';

/**
 * P2-1：额度阈值提醒。
 * 当前账号达阈值（默认 90%）时提醒，并给出「一键切换」到缓存里余量最多的账号。
 * 只做提醒，不做后台自动换号；默认关闭。
 */
export function QuotaReminderPanel() {
  const [reminder, setReminder] = useState<QuotaReminder | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setReminder(await invoke<QuotaReminder>('get_quota_reminder'));
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(load, 60_000);
    return () => clearInterval(timer);
  }, [load]);

  const setEnabled = async (enabled: boolean) => {
    setBusy('toggle');
    try {
      await invoke('set_quota_reminder', {
        enabled,
        threshold: reminder?.threshold ?? 90,
      });
      await load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  };

  const setThreshold = async (value: number) => {
    if (value < 1 || value > 100) return;
    setBusy('threshold');
    try {
      await invoke('set_quota_reminder', { enabled: true, threshold: value });
      await load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  };

  const switchNow = async (id: string) => {
    setBusy('switch');
    try {
      await invoke('switch_profile', { id });
      await load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  };

  const enabled = reminder?.enabled ?? false;
  const threshold = reminder?.threshold ?? 90;
  const percent = reminder?.current_percent;
  const recommended = reminder?.recommended;

  return (
    <section className="profiles">
      <div className="section-title">
        <h2>额度阈值提醒</h2>
        <span>{enabled ? `达 ${threshold}% 提醒` : '默认关闭'}</span>
      </div>
      <div className="panel">
        <div className="panel-title">
          {enabled ? <Bell /> : <BellOff />}
          <span>当前账号达阈值时提醒 + 一键切换</span>
        </div>
        <p className="telemetry-intro">
          只在你确认后切换，不会后台自动换号（其他账号用量会过时、后台刷新令牌风险高）。
        </p>

        <div className="quota-controls">
          <button
            className={enabled ? 'primary' : 'ghost'}
            onClick={() => setEnabled(!enabled)}
            disabled={busy === 'toggle'}
          >
            {busy === 'toggle' ? <Loader2 className="spin" /> : enabled ? <Bell /> : <BellOff />}
            {enabled ? '已开启' : '开启提醒'}
          </button>
          <label className="quota-threshold">
            阈值
            <input
              type="number"
              min={1}
              max={100}
              value={threshold}
              disabled={!enabled || busy === 'threshold'}
              onChange={(e) => setThreshold(Number(e.target.value))}
            />
            %
          </label>
        </div>

        {/* 达阈值：提醒 + 一键切换。 */}
        {enabled && percent != null && percent >= threshold && (
          <div className="quota-banner">
            <TriangleAlert />
            <div>
              <strong>当前账号 5 小时额度已用 {percent.toFixed(0)}%</strong>
              {recommended ? (
                <span>
                  缓存里「{recommended.name}」余量最多
                  {recommended.last_used_percent != null &&
                    `（约 ${recommended.last_used_percent.toFixed(0)}%）`}
                  {recommended.minutes_ago != null &&
                    `，数据为 ${recommended.minutes_ago} 分钟前`}
                  ，建议切换。
                </span>
              ) : (
                <span>暂无其他带用量缓存的账号可推荐，可手动切换。</span>
              )}
            </div>
            {recommended && (
              <button
                className="primary"
                onClick={() => switchNow(recommended.id)}
                disabled={busy === 'switch'}
              >
                {busy === 'switch' ? <Loader2 className="spin" /> : <Repeat />}
                一键切换
              </button>
            )}
          </div>
        )}

        {error && <div className="inline-error">{error}</div>}
      </div>
    </section>
  );
}
