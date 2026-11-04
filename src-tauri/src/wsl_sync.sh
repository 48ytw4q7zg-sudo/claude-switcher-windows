# Canonical WSL material protocol. Payload is stdin only; records never contain payload or paths.
export LC_ALL=C
umask 077
case "$HOME" in /*) ;; *) printf '%s\n' 'WSL 家目录必须是非空的绝对路径' >&2; exit 1 ;; esac
cd -- "$HOME" || exit 1
root="$HOME/.claude-switcher-wsl-sync"
record="$root/record"
credential="$HOME/.claude/.credentials.json"
metadata="$HOME/.claude.json"

fail() {
    printf '%s\n' "$1" >&2
    if [ -e "$record" ]; then printf '恢复记录保留在：%s\n' "$record" >&2; fi
    # Normal failures consume the remaining request so the caller retains the useful stderr.
    cat >/dev/null 2>/dev/null || :
    exit 1
}
for tool in sha256sum head wc cmp cp mv rm mkdir chmod; do
    command -v "$tool" >/dev/null 2>&1 || fail "WSL 缺少必需工具：$tool"
done
regular_or_absent() {
    [ ! -L "$1" ] && { [ ! -e "$1" ] || [ -f "$1" ]; }
}
fingerprint() {
    regular_or_absent "$1" || return 1
    if [ ! -e "$1" ]; then printf absent; return; fi
    local sum
    sum=$(sha256sum <"$1") || return 1
    printf '%s' "${sum%% *}"
}
valid_hash() { [[ "$1" =~ ^[0-9a-f]{64}$ ]]; }
valid_old() { [ "$1" = absent ] || valid_hash "$1"; }
layout() {
    if [ -L "$HOME/.claude" ] || { [ -e "$HOME/.claude" ] && [ ! -d "$HOME/.claude" ]; }; then
        fail 'WSL .claude 目录不是受支持的普通目录，未修改材料'
    fi
    regular_or_absent "$credential" && regular_or_absent "$metadata" || fail 'WSL 材料目标为目录、链接或其他不支持类型，未修改材料'
    if [ -e "$root" ] || [ -L "$root" ]; then
        [ -d "$root" ] && [ ! -L "$root" ] || fail 'WSL 恢复目录类型不受支持'
        [ -f "$root/owner" ] && [ ! -L "$root/owner" ] || fail 'WSL 恢复目录没有有效归属标记，已保留现场'
        cmp -s -- "$root/owner" <(printf 'CSWSL-SYNC-OWNER-1\n') || fail 'WSL 恢复目录归属不明，已保留现场'
        local item
        for item in "$root"/* "$root"/.[!.]* "$root"/..?*; do
            [ -e "$item" ] || [ -L "$item" ] || continue
            case "$item" in "$root/owner"|"$record") ;; *) fail "发现未知恢复材料，已保留：$item" ;; esac
        done
        regular_or_absent "$record" || fail 'WSL 事务记录不是普通文件，已保留现场'
    fi
}
paths() {
    c_new="$credential.cswsltxn-$transaction.new"
    c_old="$credential.cswsltxn-$transaction.old"
    m_new="$metadata.cswsltxn-$transaction.new"
    m_old="$metadata.cswsltxn-$transaction.old"
}
validate_slots() {
    local item
    for item in "$credential".cswsltxn-* "$metadata".cswsltxn-*; do
        [ -e "$item" ] || [ -L "$item" ] || continue
        if [ ! -e "$record" ]; then fail "发现未登记的暂存材料，已保留：$item"; fi
        case "$item" in "$c_new"|"$c_old"|"$m_new"|"$m_old") ;; *) fail "发现其他事务的暂存材料，已保留：$item" ;; esac
        [ -f "$item" ] && [ ! -L "$item" ] || fail "暂存材料类型不受支持：$item"
        if [ "$mode" = metadata ] && { [ "$item" = "$c_new" ] || [ "$item" = "$c_old" ]; }; then
            fail "仅同步身份文件的事务含未知凭据暂存：$item"
        fi
    done
}
load_record() {
    local lines=()
    mapfile -t lines <"$record" || fail '无法读取 WSL 事务记录'
    [ "${#lines[@]}" -eq 9 ] || fail 'WSL 事务记录损坏，已保留现场'
    [ "${lines[0]}" = CSWSL-TXN-1 ] || fail 'WSL 事务记录版本或归属不明'
    [ "$(printf '%s\n' "${lines[@]}" | wc -c)" -eq "$(wc -c <"$record")" ] || fail 'WSL 事务记录含非法字节'
    transaction=${lines[1]}; phase=${lines[2]}; mode=${lines[3]}; owner_pid=${lines[4]}
    old_c=${lines[5]}; new_c=${lines[6]}; old_m=${lines[7]}; new_m=${lines[8]}
    [[ "$transaction" =~ ^[0-9a-f]{32}$ ]] || fail 'WSL 事务编号无效'
    case "$phase" in preparing|prepared|committed) ;; *) fail 'WSL 事务阶段无效' ;; esac
    case "$mode" in pair|metadata) ;; *) fail 'WSL 事务模式无效' ;; esac
    [[ "$owner_pid" =~ ^[1-9][0-9]{0,9}$ ]] && [ "$owner_pid" -le 2147483647 ] || fail 'WSL 事务进程标记无效'
    valid_old "$old_c" && valid_old "$old_m" && valid_hash "$new_m" || fail 'WSL 事务指纹无效'
    if [ "$mode" = pair ]; then valid_hash "$new_c" || fail 'WSL 凭据指纹无效'; else [ "$new_c" = keep ] || fail 'WSL 保留凭据标记无效'; fi
    if [ "$owner_pid" != "$$" ] && kill -0 "$owner_pid" 2>/dev/null; then
        fail '上次 WSL 同步进程仍可能运行，已拒绝并发恢复，请稍后重试'
    fi
    paths
    validate_slots
}
write_record() {
    local next="$root/record.next"
    [ ! -e "$next" ] && [ ! -L "$next" ] || fail "事务记录暂存已存在，已保留：$next"
    (set -C; printf '%s\n' CSWSL-TXN-1 "$transaction" "$phase" "$mode" "$$" "$old_c" "$new_c" "$old_m" "$new_m" >"$next") || fail '写入 WSL 恢复记录失败，原材料已保留'
    chmod 600 -- "$next" && mv -T -- "$next" "$record" || fail '提交 WSL 恢复记录失败，已保留现场'
}
check_staged() {
    local item=$1 expected=$2
    [ -e "$item" ] || return 0
    regular_or_absent "$item" || fail "恢复材料不是普通文件：$item"
    if [ "$phase" != preparing ]; then
        [ "$(fingerprint "$item")" = "$expected" ] || fail "恢复材料已被外部修改，已保留：$item"
    fi
}
cleanup() {
    check_staged "$m_new" "$new_m"
    check_staged "$m_old" "$old_m"
    if [ "$mode" = pair ]; then check_staged "$c_new" "$new_c"; check_staged "$c_old" "$old_c"; fi
    rm -f -- "$c_new" "$c_old" "$m_new" "$m_old" || fail '清理已核对的事务暂存失败，恢复记录已保留'
    rm -f -- "$record" || fail '清理 WSL 恢复记录失败，材料状态已保留'
}
current_state() {
    current_c=$(fingerprint "$credential") && current_m=$(fingerprint "$metadata") || fail '读取当前 WSL 材料指纹失败或目标类型已变化'
}
is_new_pair() {
    [ "$current_m" = "$new_m" ] || return 1
    if [ "$mode" = pair ]; then [ "$current_c" = "$new_c" ]; else [ "$current_c" = "$old_c" ]; fi
}
restore_slot() {
    local target=$1 backup=$2 previous=$3 replacement=$4 current
    current=$(fingerprint "$target") || fail "恢复目标类型已变化：$target"
    [ "$current" = "$previous" ] && return 0
    [ "$current" = "$replacement" ] || fail "恢复目标已被外部修改，拒绝覆盖：$target"
    if [ "$previous" = absent ]; then
        rm -f -- "$target" || fail "无法恢复原先不存在的目标：$target"
    else
        [ "$(fingerprint "$backup")" = "$previous" ] || fail "原材料备份缺失或已变化：$backup"
        mv -T -- "$backup" "$target" || fail "回滚失败，原材料备份保留在：$backup"
    fi
}
recover() {
    layout
    if [ ! -e "$record" ]; then validate_slots; return; fi
    load_record
    current_state
    if is_new_pair; then cleanup; return; fi
    if [ "$phase" = committed ]; then fail '已完成事务的目标被外部修改，已保留恢复材料'; fi
    if [ "$phase" = preparing ]; then
        [ "$current_c" = "$old_c" ] && [ "$current_m" = "$old_m" ] || fail '准备中的目标已被外部修改，未执行恢复'
        cleanup
        return
    fi
    if [ "$mode" = pair ]; then
        { [ "$current_c" = "$old_c" ] || [ "$current_c" = "$new_c" ]; } || fail '凭据已被外部修改，拒绝回滚'
    else
        [ "$current_c" = "$old_c" ] || fail '保留的凭据已被外部修改，拒绝回滚'
    fi
    { [ "$current_m" = "$old_m" ] || [ "$current_m" = "$new_m" ]; } || fail '身份文件已被外部修改，拒绝回滚'
    restore_slot "$metadata" "$m_old" "$old_m" "$new_m"
    if [ "$mode" = pair ]; then restore_slot "$credential" "$c_old" "$old_c" "$new_c"; fi
    current_state
    [ "$current_c" = "$old_c" ] && [ "$current_m" = "$old_m" ] || fail '恢复后的材料指纹不一致，已保留现场'
    cleanup
}
receive() {
    local target=$1 length=$2 expected=$3
    (set -C; : >"$target") || fail "无法创建材料暂存，原文件未修改：$target"
    head -c "$length" >"$target" || fail "接收材料失败，原文件未修改：$target"
    [ "$(wc -c <"$target")" -eq "$length" ] && [ "$(fingerprint "$target")" = "$expected" ] || fail "输入不完整或校验失败，原文件未修改；暂存保留在：$target"
    chmod 600 -- "$target" || fail "收敛暂存权限失败，原文件未修改：$target"
}
backup() {
    local target=$1 destination=$2 expected=$3
    [ "$expected" = absent ] && return 0
    (set -C; : >"$destination") || fail "备份路径已存在：$destination"
    cp -P -- "$target" "$destination" && chmod 600 -- "$destination" || fail "创建原材料备份失败：$destination"
    [ "$(fingerprint "$destination")" = "$expected" ] || fail "备份期间原材料已变化，未提交：$destination"
}

recover
case "${1:-${CS_WSL_OP:-}}" in
    recover) exit 0 ;;
    inspect)
        c_size=absent; m_size=absent
        [ ! -e "$credential" ] || c_size=$(wc -c <"$credential")
        [ ! -e "$metadata" ] || m_size=$(wc -c <"$metadata")
        printf 'CSWSL-READ-1\n%s\n%s\n' "$c_size" "$m_size"
        [ "$c_size" = absent ] || cat -- "$credential" || fail '读取 WSL 凭据失败'
        [ "$m_size" = absent ] || cat -- "$metadata" || fail '读取 WSL 身份文件失败'
        exit 0 ;;
    clear)
        regular_or_absent "$credential" && regular_or_absent "$metadata" || fail '清理目标类型已变化，未清理'
        rm -f -- "$credential" "$metadata" || fail '清理 WSL 材料失败，请检查剩余文件'
        exit 0 ;;
    apply) ;;
    *) fail 'WSL 材料操作无效' ;;
esac

header=()
for ((index=0; index<9; index++)); do
    IFS= read -r line || fail 'WSL 输入头不完整，原材料未修改'
    header+=("$line")
done
[ "${header[0]}" = CSWSL-FRAME-1 ] || fail 'WSL 输入协议版本无效'
transaction=${header[1]}; mode=${header[2]}; old_c=${header[3]}; old_m=${header[4]}
c_length=${header[5]}; new_c=${header[6]}; m_length=${header[7]}; new_m=${header[8]}
[[ "$transaction" =~ ^[0-9a-f]{32}$ ]] || fail 'WSL 输入事务编号无效'
case "$mode" in pair|metadata) ;; *) fail 'WSL 输入材料模式无效' ;; esac
valid_old "$old_c" && valid_old "$old_m" && valid_hash "$new_m" || fail 'WSL 输入材料指纹无效'
[[ "$c_length" =~ ^(0|[1-9][0-9]{0,9})$ ]] && [[ "$m_length" =~ ^[1-9][0-9]{0,9}$ ]] || fail 'WSL 输入材料字节长度无效'
if [ "$mode" = pair ]; then
    [ "$c_length" -gt 0 ] && valid_hash "$new_c" || fail 'WSL 输入凭据长度或指纹无效'
else
    [ "$c_length" = 0 ] && [ "$new_c" = keep ] || fail 'WSL 保留凭据的输入格式无效'
fi
paths
current_state
if ! is_new_pair && { [ "$current_c" != "$old_c" ] || [ "$current_m" != "$old_m" ]; }; then fail 'WSL 材料在观察后已变化，拒绝覆盖，请重新同步'; fi
if [ ! -e "$root" ]; then
    mkdir -- "$root" || fail '无法创建 WSL 恢复目录'
    printf 'CSWSL-SYNC-OWNER-1\n' >"$root/owner" || fail '无法创建 WSL 归属标记'
fi
if [ "$mode" = pair ] && [ ! -d "$HOME/.claude" ]; then mkdir -- "$HOME/.claude" || fail '无法创建 WSL 凭据目录'; fi
phase=preparing
write_record
if [ "$mode" = pair ]; then receive "$c_new" "$c_length" "$new_c"; fi
receive "$m_new" "$m_length" "$new_m"
[ "$(head -c 1 | wc -c)" -eq 0 ] || fail 'WSL 输入包含多余字节，原文件未修改'
current_state
if is_new_pair; then cleanup; printf 'WSL 材料已与本次请求一致\n'; exit 0; fi
[ "$current_c" = "$old_c" ] && [ "$current_m" = "$old_m" ] || fail 'WSL 材料在接收期间已变化，原文件未覆盖'
if [ "$mode" = pair ]; then backup "$credential" "$c_old" "$old_c"; fi
backup "$metadata" "$m_old" "$old_m"
phase=prepared
write_record
current_state
[ "$current_c" = "$old_c" ] && [ "$current_m" = "$old_m" ] || fail 'WSL 材料在提交前已变化，拒绝覆盖'
if [ "$mode" = pair ]; then
    mv -T -- "$c_new" "$credential" || { recover; fail '提交凭据失败，已恢复原材料'; }
fi
mv -T -- "$m_new" "$metadata" || { recover; fail '提交身份文件失败，已恢复原材料'; }
phase=committed
write_record
recover
printf 'WSL 材料事务已完成\n'
