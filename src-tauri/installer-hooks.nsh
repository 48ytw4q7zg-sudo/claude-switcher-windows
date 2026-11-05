; Claude Switcher 卸载钩子（P0-E / P0-06 / QW-05）。
;
; 目的：卸载前必须先撤销本产品创建的防火墙规则、隔离与断网状态。
; 恢复失败时**阻止**卸载——否则会连同唯一能清理这些规则的执行器一起删掉。
;
; 恢复命令：ClaudeSwitcher.exe --exit-restore（不初始化 GUI，直接返回退出码）。
; 退出码 0 = 已完整恢复；非 0 = 有残留，必须让用户先处理。

!macro NSIS_HOOK_PREUNINSTALL
  ; **QW-05**：找不到恢复执行器**不能**默认放行。
  ; 「程序文件不在」不等于「防火墙规则不存在」——规则可能仍然生效，
  ; 而卸载会删掉唯一能清理它们的程序。
  IfFileExists "$INSTDIR\ClaudeSwitcher.exe" claude_switcher_have_restorer

    MessageBox MB_ICONSTOP|MB_OK \
      "卸载已中止：找不到恢复程序（$INSTDIR\ClaudeSwitcher.exe）。$\r$\n$\r$\n无法确认 Claude Switcher 创建的系统保护规则（防火墙隔离/断网）是否已经清理。$\r$\n请先重新安装/修复本程序，运行「解除隔离」与「恢复网络」后再卸载。"
    Abort

  claude_switcher_have_restorer:
  DetailPrint "正在恢复 Claude Switcher 创建的系统保护规则..."
  ExecWait '"$INSTDIR\ClaudeSwitcher.exe" --exit-restore' $0

  ${If} $0 != 0
    MessageBox MB_ICONSTOP|MB_OK \
      "卸载已中止：Claude Switcher 仍持有系统保护状态（防火墙隔离/断网），且自动恢复未成功（退出码 $0）。$\r$\n$\r$\n请先运行 ClaudeSwitcher.exe 的「解除隔离」与「恢复网络」，或在命令行执行：$\r$\n    ClaudeSwitcher.exe --egate-restore$\r$\n$\r$\n确认恢复后再重新卸载。"
    Abort
  ${EndIf}

  ; 恢复成功：撤销本产品的保镖计划任务，避免留下指向已卸载程序的引用。
  ExecWait 'schtasks /Delete /TN "ClaudeBodyguard" /F' $1
  DetailPrint "已清理保镖计划任务（退出码 $1）"
!macroend
