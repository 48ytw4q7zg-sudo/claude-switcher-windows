; Claude Switcher 卸载钩子（P0-E）。
;
; 目的：卸载前必须先撤销本产品创建的防火墙规则、隔离与断网状态。
; 若恢复失败，**阻止**卸载——否则会连同唯一能清理这些规则的执行器一起删掉。
;
; 恢复命令：ClaudeSwitcher.exe --exit-restore（不初始化 GUI，直接返回退出码）。
; 退出码 0 = 已完整恢复；非 0 = 有残留，必须让用户先处理。

!macro NSIS_HOOK_PREUNINSTALL
  ; 主程序可能仍在运行：先尝试静默恢复（单实例会把参数转交给运行中的实例）。
  IfFileExists "$INSTDIR\ClaudeSwitcher.exe" 0 claude_switcher_restore_skipped

  DetailPrint "正在恢复 Claude Switcher 创建的系统保护规则..."
  ExecWait '"$INSTDIR\ClaudeSwitcher.exe" --exit-restore' $0

  ${If} $0 != 0
    MessageBox MB_ICONSTOP|MB_OK \
      "卸载已中止：Claude Switcher 仍持有系统保护状态（防火墙隔离/断网），且自动恢复未成功。$\r$\n$\r$\n请先运行 ClaudeSwitcher.exe 的「解除隔离」与「恢复网络」，或在命令行执行：$\r$\n    ClaudeSwitcher.exe --egate-restore$\r$\n$\r$\n确认恢复后再重新卸载。"
    Abort
  ${EndIf}

  Goto claude_switcher_restore_done

  claude_switcher_restore_skipped:
    DetailPrint "未找到主程序，跳过自动恢复（无规则可清理）。"

  claude_switcher_restore_done:
!macroend
