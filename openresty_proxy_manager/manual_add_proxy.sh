#!/bin/bash

# ==============================================================================
# OpenResty 手动反向代理管理脚本
# 描述: 当机器人宕机时，此脚本可用于手动添加、删除或查询反向代理规则。
# 使用: sudo ./manual_add_proxy.sh
# ==============================================================================

# --- 可配置变量 ---
# 请根据您的服务器环境修改这些路径。
# 您可以通过在服务器上运行 `sudo openresty -t` 来找到主配置文件路径，
# 其他路径通常位于主配置文件所在目录的 `conf.d` 子目录中。
HTTP_CONFIG_PATH="/usr/local/openresty/nginx/conf/conf.d/astrabot_http.conf"
STREAM_CONFIG_PATH="/usr/local/openresty/nginx/conf/conf.d/astrabot_stream.stream_conf"
SSL_CERT_PATH="/etc/ssl/certs/" # SSL 证书所在的目录路径

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- 函数定义 ---

function error_exit {
    echo -e "${RED}错误: $1${NC}" >&2
    exit 1
}

function success_msg {
    echo -e "${GREEN}$1${NC}"
}

function info_msg {
    echo -e "${YELLOW}$1${NC}"
}

function command_exists {
    command -v "$1" >/dev/null 2>&1
}

function test_and_reload {
    info_msg "正在测试 OpenResty 配置 (openresty -t)..."
    TEST_OUTPUT=$(openresty -t 2>&1)

    if [[ $? -ne 0 ]]; then
        error_exit "新配置无效！\n${TEST_OUTPUT}\n请检查配置文件: $1"
    fi

    success_msg "配置测试成功。"
    info_msg "正在重载 OpenResty (openresty -s reload)..."
    RELOAD_OUTPUT=$(openresty -s reload 2>&1)

    if [[ $? -ne 0 ]]; then
        error_exit "重载 OpenResty 失败！\n${RELOAD_OUTPUT}\n请手动检查服务状态。"
    fi

    success_msg "OpenResty 重载成功！操作已生效。"
}

# --- 规则解析和显示 (公共函数) ---
function parse_and_display_rules {
    # 使用 awk 来解析 server blocks，这是一个比 sed 更健壮的方法
    RULES=$(awk '/server *{/{f=1; s=""} f{s=s $0 RS} /}/{f=0; if(s) print s "---"}' "$HTTP_CONFIG_PATH" "$STREAM_CONFIG_PATH" 2>/dev/null)

    if [ -z "$RULES" ]; then
        info_msg "在 ${HTTP_CONFIG_PATH} 或 ${STREAM_CONFIG_PATH} 中未找到任何代理规则。"
        return 1
    fi

    echo "发现以下规则:"
    echo "----------------------------------------"
    IFS='---'
    read -ra RULE_ARRAY <<< "$RULES"
    
    INDEX=1
    for rule in "${RULE_ARRAY[@]}"; do
        if [[ -n "$rule" ]]; then
            # 提取关键信息用于显示
            LISTEN_PORT=$(echo "$rule" | grep -oP 'listen\s+\K[0-9]+' | head -n 1)
            PROXY_PASS=$(echo "$rule" | grep -oP 'proxy_pass\s+\K[^;]+' | head -n 1)
            COMMENT=$(echo "$rule" | grep '#' | head -n 1)
            echo -e "${CYAN}${INDEX})${NC} ${COMMENT}"
            echo -e "    ${YELLOW}外网端口:${NC} ${LISTEN_PORT} -> ${YELLOW}内网目标:${NC} ${PROXY_PASS}"
            echo ""
            INDEX=$((INDEX+1))
        fi
    done
    echo "----------------------------------------"
    # 将解析出的规则数组返回给调用者
    # 使用全局变量，因为 bash 函数返回状态码
    # declare -g 会使其成为全局变量
    declare -g PARSED_RULES=("${RULE_ARRAY[@]}")
    return 0
}


# --- 添加规则功能 ---
function add_rule {
    info_msg "--- 添加新的代理规则 ---"
    
    read -p "请输入协议 (http, https, tcp): " PROTOCOL
    PROTOCOL=$(echo "$PROTOCOL" | tr '[:upper:]' '[:lower:]')
    if [[ "$PROTOCOL" != "http" && "$PROTOCOL" != "https" && "$PROTOCOL" != "tcp" ]]; then
        error_exit "无效的协议。请输入 http, https, 或 tcp。"
    fi

    read -p "请输入内网地址和端口 (例如: 192.168.1.10:8080): " LAN_ADDRESS
    if ! [[ "$LAN_ADDRESS" =~ ^[0-9a-zA-Z\.-]+:[0-9]+$ ]]; then
        error_exit "无效的内网地址格式。"
    fi

    read -p "请输入外网端口 (例如: 80): " WAN_PORT
    if ! [[ "$WAN_PORT" =~ ^[0-9]+$ ]]; then
        error_exit "无效的外网端口。"
    fi

    CERT_NAME=""
    if [ "$PROTOCOL" == "https" ]; then
        read -p "请输入 SSL 证书名称 (不带 .pem/.key 后缀): " CERT_NAME
        if [ -z "$CERT_NAME" ]; then
            error_exit "HTTPS 协议必须提供证书名称。"
        fi
        if [ ! -f "${SSL_CERT_PATH}${CERT_NAME}.pem" ] || [ ! -f "${SSL_CERT_PATH}${CERT_NAME}.key" ]; then
            error_exit "在 ${SSL_CERT_PATH} 目录下找不到证书文件 ${CERT_NAME}.pem 或 ${CERT_NAME}.key。"
        fi
    fi

    read -p "请输入此规则的用途备注 (例如: MyWebService): " REMARK

    CONFIG_BLOCK=""
    TARGET_FILE=""
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    COMMENT="# Manually added on ${TIMESTAMP} | Purpose: ${REMARK}"

    if [[ "$PROTOCOL" == "http" || "$PROTOCOL" == "https" ]]; then
        TARGET_FILE=$HTTP_CONFIG_PATH
        PROXY_PASS="http://${LAN_ADDRESS}"
        
        if [ "$PROTOCOL" == "https" ]; then
            CONFIG_BLOCK=$(cat <<EOF

${COMMENT}
server {
    listen ${WAN_PORT} ssl http2;
    server_name _;
    ssl_certificate ${SSL_CERT_PATH}${CERT_NAME}.pem;
    ssl_certificate_key ${SSL_CERT_PATH}${CERT_NAME}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    location / {
        proxy_pass ${PROXY_PASS};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
)
        else # HTTP
            CONFIG_BLOCK=$(cat <<EOF

${COMMENT}
server {
    listen ${WAN_PORT};
    server_name _;
    location / {
        proxy_pass ${PROXY_PASS};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
)
        fi
    elif [ "$PROTOCOL" == "tcp" ]; then
        TARGET_FILE=$STREAM_CONFIG_PATH
        CONFIG_BLOCK=$(cat <<EOF

${COMMENT} (TCP)
server {
    listen ${WAN_PORT};
    proxy_pass ${LAN_ADDRESS};
}

${COMMENT} (UDP)
server {
    listen ${WAN_PORT} udp;
    proxy_pass ${LAN_ADDRESS};
}
EOF
)
    fi

    info_msg "准备将以下配置追加到 ${TARGET_FILE}..."
    echo "----------------------------------------"
    echo -e "$CONFIG_BLOCK"
    echo "----------------------------------------"
    read -p "确认要继续吗? (y/n): " CONFIRM
    if [[ "$CONFIRM" != "y" ]]; then
        info_msg "操作已取消。"
        exit 0
    fi

    # 备份与写入
    BACKUP_FILE="${TARGET_FILE}.bak.$(date +%s)"
    info_msg "正在创建备份: ${BACKUP_FILE}"
    cp "${TARGET_FILE}" "${BACKUP_FILE}" || error_exit "创建备份失败。"
    echo "$CONFIG_BLOCK" >> "$TARGET_FILE"
    info_msg "配置已追加。"

    # 测试和重载
    test_and_reload "${TARGET_FILE}"
    rm -f "${BACKUP_FILE}"
    info_msg "临时备份文件已删除。"
}

# --- 删除规则功能 ---
function delete_rule {
    info_msg "--- 删除现有代理规则 ---"
    
    parse_and_display_rules
    # 检查 parse_and_display_rules 是否成功
    if [ $? -ne 0 ]; then
        exit 0
    fi
    
    RULE_ARRAY=("${PARSED_RULES[@]}")

    read -p "请输入要删除的规则编号 (输入 q 退出): " RULE_NUM
    if [[ "$RULE_NUM" == "q" || -z "$RULE_NUM" ]]; then
        info_msg "操作已取消。"
        exit 0
    fi

    if ! [[ "$RULE_NUM" =~ ^[0-9]+$ ]] || [ "$RULE_NUM" -lt 1 ] || [ "$RULE_NUM" -gt "${#RULE_ARRAY[@]}" ]; then
        error_exit "无效的编号。"
    fi

    SELECTED_RULE=${RULE_ARRAY[$((RULE_NUM-1))]}
    
    # 确定规则所在的文件
    TARGET_FILE=""
    if grep -qFz -- "$SELECTED_RULE" "$HTTP_CONFIG_PATH" 2>/dev/null; then
        TARGET_FILE="$HTTP_CONFIG_PATH"
    elif grep -qFz -- "$SELECTED_RULE" "$STREAM_CONFIG_PATH" 2>/dev/null; then
        TARGET_FILE="$STREAM_CONFIG_PATH"
    else
        error_exit "无法确定所选规则的源文件。可能文件已被手动更改。"
    fi

    info_msg "将从 ${TARGET_FILE} 中删除以下规则:"
    echo "----------------------------------------"
    echo -e "$SELECTED_RULE"
    echo "----------------------------------------"
    read -p "确认要删除吗? (y/n): " CONFIRM
    if [[ "$CONFIRM" != "y" ]]; then
        info_msg "操作已取消。"
        exit 0
    fi

    # 备份与删除
    BACKUP_FILE="${TARGET_FILE}.bak.$(date +%s)"
    info_msg "正在创建备份: ${BACKUP_FILE}"
    cp "${TARGET_FILE}" "${BACKUP_FILE}" || error_exit "创建备份失败。"
    
    # 使用 Perl 进行精确的多行文本删除
    perl -i -0pe "s/^\Q$SELECTED_RULE\E//smg" "$TARGET_FILE"

    if [ $? -eq 0 ]; then
        info_msg "规则已从文件中删除。"
    else
        error_exit "使用 perl 删除规则失败。正在从备份恢复..."
        mv "${BACKUP_FILE}" "${TARGET_FILE}"
    fi

    # 测试和重载
    test_and_reload "${TARGET_FILE}"
    rm -f "${BACKUP_FILE}"
    info_msg "临时备份文件已删除。"
}

# --- 查询规则功能 ---
function view_rules {
    info_msg "--- 查询现有代理规则 ---"
    parse_and_display_rules
    read -p "按任意键返回主菜单..." -n 1 -s
    echo ""
}


# --- 主逻辑 ---

# 检查 root 权限
if [[ $EUID -ne 0 ]]; then
   error_exit "此脚本需要 root 权限运行。请使用 'sudo ./manual_add_proxy.sh'。"
fi

# 检查 openresty 命令
if ! command_exists openresty; then
    error_exit "未找到 'openresty' 命令。请确保 OpenResty 已正确安装并已添加到系统的 PATH 中。"
fi

# 主菜单循环
while true; do
    clear
    info_msg "欢迎使用 OpenResty 手动代理管理工具。"
    echo "----------------------------------------"
    echo "请选择要执行的操作:"
    echo "  1) 添加新的代理规则"
    echo "  2) 删除现有的代理规则"
    echo "  3) 查询所有代理规则"
    echo "  q) 退出"
    echo "----------------------------------------"
    read -p "请输入选项 [1, 2, 3, q]: " CHOICE

    case $CHOICE in
        1)
            add_rule
            break
            ;;
        2)
            delete_rule
            break
            ;;
        3)
            view_rules
            ;;
        q)
            info_msg "已退出。"
            exit 0
            ;;
        *)
            error_exit "无效的选项。"
            ;;
    esac
done

exit 0
