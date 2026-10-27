import { useCallback, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  AlertTriangle,
  CheckCircle2,
  Loader2,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  Wrench,
  XCircle,
} from 'lucide-react';
import type { CheckItem, CheckStatus, FixReport } from './types';

function StatusDot({ status }: { status: CheckStatus }) {
  if (status === 'ok') {
    return (
      <span className="check-dot ok">
        <CheckCircle2 />
      </span>
    );
  }
  if (status === 'warn') {
    return (
      <span className="check-dot warn">
        <AlertTriangle />
      </span>
    );
  }
  return (
    <span className="check-dot fail">
      <XCircle />
    </span>
  );
}

export function SecurityPanel() {
  const [items, setItems] = useState<CheckItem[] | null>(null);
  const [fixReport, setFixReport] = useState<FixReport | null>(null);
  const [checking, setChecking] = useState(false);
  const [fixing, setFixing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runChecks = useCallback(async () => {
    setChecking(true);
    setError(null);
    try {
      const result = await invoke<CheckItem[]>('run_security_checks');
      setItems(result);
      // 重新检测后清掉上一次修复报告，避免新旧结果混在一起。
      setFixReport(null);
    } catch (err) {
      setError(String(err));
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    runChecks();
  }, [runChecks]);

  const runFix = async () => {
    setFixing(true);
    setError(null);
    try {
      const report = await invoke<FixReport>('run_security_fix');
      setFixReport(report);
      // 修复后用后端返回的复测结果刷新列表。
      if (Array.isArray(report.checks)) setItems(report.checks);
    } catch (err) {
      setError(String(err));
    } finally {
      setFixing(false);
    }
  };

  const summary = (() => {
    const list = items ?? [];
    const ok = list.filter((i) => i.status === 'ok').length;
    const warn = list.filter((i) => i.status === 'warn').length;
    const fail = list.filter((i) => i.status === 'fail').length;
    return { total: list.length, ok, warn, fail };
  })();

  const busy = checking || fixing;

  return (
    <section className="profiles">
      <div className="section-title">
        <h2>环境安检</h2>
        <span>
          {items ? `${summary.ok}/${summary.total} 通过` : '读取中'}
        </span>
      </div>

      <div className="panel">
        <div className="panel-title">
          <ShieldCheck />
          <span>本地环境安全检查</span>
        </div>

        <div className="security-toolbar">
          <div className="security-summary">
            <span className="pill ok">{summary.ok} 通过</span>
            <span className="pill muted" style={{ background: '#efdcc6', color: '#7a3a1a' }}>
              {summary.warn} 警告
            </span>
            <span className="pill muted" style={{ background: '#f1d7cf', color: '#6e221f' }}>
              {summary.fail} 失败
            </span>
          </div>
          <div className="security-actions">
            <button className="ghost" onClick={runChecks} disabled={busy}>
              {checking ? <Loader2 className="spin" /> : <RefreshCw />}
              重新检测
            </button>
            <button className="primary" onClick={runFix} disabled={busy || !items?.length}>
              {fixing ? <Loader2 className="spin" /> : <Wrench />}
              一键修复
            </button>
          </div>
        </div>

        {error && (
          <div className="inline-error" style={{ marginTop: 12 }}>
            <ShieldAlert /> {error}
          </div>
        )}

        {!items && !error && <div className="empty">正在检测环境…</div>}

        {items && items.length > 0 && (
          <div className="check-list">
            {items.map((item) => (
              <div className="check-row" key={item.id}>
                <StatusDot status={item.status} />
                <div className="check-row-body">
                  <strong>{item.name}</strong>
                  <span>{item.detail}</span>
                </div>
              </div>
            ))}
          </div>
        )}

        {fixReport && (
          <div className="fix-report">
            <div className="panel-title" style={{ marginTop: 18 }}>
              <Wrench />
              <span>修复步骤（复测：{fixReport.summary.ok}/{fixReport.summary.total} 通过）</span>
            </div>
            <div className="check-list">
              {fixReport.steps.map((step, idx) => (
                <div className="check-row" key={`${idx}-${step.name}`}>
                  <StatusDot status={step.status} />
                  <div className="check-row-body">
                    <strong>{step.name}</strong>
                    <span>{step.detail}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
