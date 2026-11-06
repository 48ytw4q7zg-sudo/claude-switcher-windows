; Claude Switcher 卸载钩子（P0-E / P0-06 / QW-05 / P1-05）。
;
; 目的：卸载前必须先撤销本产品创建的防火墙规则、隔离与断网状态。
; 恢复失败时**阻止**卸载——否则会连同唯一能清理这些规则的执行器一起删掉。
;
; 恢复命令：ClaudeSwitcher.exe --exit-restore（不初始化 GUI，直接返回退出码）。
; 退出码 0 = 已完整恢复；非 0 = 有残留，必须让用户先处理。

!macro NSIS_HOOK_PREUNINSTALL
  ; **QW-05**：找不到恢复执行器**不能**默认放行。
  IfFileExists "$INSTDIR\ClaudeSwitcher.exe" claude_switcher_have_restorer

    MessageBox MB_ICONSTOP|MB_OK       "卸载已中止：找不到恢复程序（$INSTDIR\ClaudeSwitcher.exe）。$\r$\n$\r$\n无法确认 Claude Switcher 创建的系统保护规则（防火墙隔离/断网）是否已经清理。$\r$\n请先重新安装/修复本程序，运行「解除隔离」与「恢复网络」后再卸载。"
    Abort

  claude_switcher_have_restorer:
  DetailPrint "正在恢复 Claude Switcher 创建的系统保护规则..."
  ExecWait '"$INSTDIR\ClaudeSwitcher.exe" --exit-restore' $0

  ${If} $0 != 0
    MessageBox MB_ICONSTOP|MB_OK       "卸载已中止：Claude Switcher 仍持有系统保护状态（防火墙隔离/断网），且自动恢复未成功（退出码 $0）。$\r$\n$\r$\n请先运行 ClaudeSwitcher.exe 的「解除隔离」与「恢复网络」，或在命令行执行：$\r$\n    ClaudeSwitcher.exe --egate-restore$\r$\n$\r$\n确认恢复后再重新卸载。"
    Abort
  ${EndIf}

  ; **P1-05（v0.8.1）**：撤销保镖计划任务，并**严格回查**。
  ;
  ; 原实现只记录 schtasks 的退出码就继续卸载。权限不足 / 任务计划服务异常 /
  ; 任务受保护时 schtasks 返回非 0，却照样继续，留下一个指向已删除程序路径
  ; 的高权限任务。
  ;
  ; 更麻烦的是：纯 schtasks 的退出码分不清「任务不存在」与「服务异常」——
  ; 两者都返回非 0。所以这里改用程序自带的三态查询
  ; （--egate-guard-task-state：0=确认不存在 / 1=确认存在 / 2=无法确认），
  ; 只有「确认不存在」才放行。
  DetailPrint "正在清理保镖计划任务..."
  ExecWait 'schtasks /Delete /TN "ClaudeBodyguard" /F' $1
  DetailPrint "schtasks 退出码 $1，正在回查任务状态..."

  ExecWait '"$INSTDIR\ClaudeSwitcher.exe" --egate-guard-task-state' $2
  ${If} $2 = 0
    DetailPrint "保镖计划任务已确认不存在"
  ${Else}
    ${If} $2 = 1
      MessageBox MB_ICONSTOP|MB_OK         "卸载已中止：保镖计划任务「ClaudeBodyguard」删除后仍然存在（schtasks 退出码 $1）。$\r$\n$\r$\n该任务以最高权限运行并指向 $INSTDIR，留下它会指向一个已删除的程序。$\r$\n请以管理员身份打开命令提示符执行：$\r$\n    schtasks /Delete /TN ClaudeBodyguard /F$\r$\n然后再重新卸载。"
    ${Else}
      MessageBox MB_ICONSTOP|MB_OK         "卸载已中止：无法确认保镖计划任务「ClaudeBodyguard」是否已删除（查询返回 $2）。$\r$\n$\r$\n「无法确认」不能当成「已清理」——该任务以最高权限运行并指向 $INSTDIR。$\r$\n请确认任务计划程序服务正常后，以管理员身份执行：$\r$\n    schtasks /Query /TN ClaudeBodyguard$\r$\n如仍存在则执行 schtasks /Delete /TN ClaudeBodyguard /F，再重新卸载。"
    ${EndIf}
    Abort
  ${EndIf}
!macroend
