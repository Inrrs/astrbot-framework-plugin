#!/bin/bash

# ==============================================================================
# OpenResty 手动代理管理工具
# ==============================================================================
# 描述:
# 当 AstrBot 框架不可用时，此脚本可作为应急手段，手动管理 OpenResty 反向代理规则。
# 它支持添加、查询和删除规则，并确保生成的配置与机器人兼容。
#
# 作者: Cline (为 AstrBot 生成)
# 版本: 2.0.0
# ==============================================================================
#
# !! 重要：同步说明 !!
# ------------------------------------------------------------------------------
# 此脚本修改的是 OpenResty 的配置文件，不会更新机器人的本地数据库 (data.json)。
# 在 AstrBot 恢复正常后，请按照以下步骤同步：
#
# 1. 在聊天窗口发送 `/反代 查看规则`。
# 2. 机器人会列出所有规则，并将您手动添加的规则标记为 "未知规则"。
# 3. 对于每一个未知规则，请使用机器人的 `/反代 添加` 命令将其重新添加一遍。
#    这样，机器人就会将该规则正式记录到自己的数据库中。
# 4. （可选）当所有手动规则都通过机器人重新添加后，再次运行 `/反代 查看规则`
#    确认没有不一致的地方。
# ==============================================================================

# --- 用户配置 ---
# 请根据您的服务器实际情况修改以下路径。
# 当机器人正常时，可通过 `/反代 查看配置` 指令查询到这些路径。

# HTTP/S 配置文件路径
HTTP_CONF_PATH="/etc/openresty/conf.d/astrabot_http.conf"

# TCP/UDP (Stream) 配置文件路径
STREAM_CONF_PATH="/etc/openresty/conf.d/astrabot_stream.stream_conf"

# SSL 证书存放目录
SSL_CERT_PATH="/etc/openresty/ssl/"

# 用于 HTTPS 规则的主域名，脚本将根据此域名寻找证书文件。
# 例如: a.com，脚本会寻找 a.com.pem 和 a.com.key
MAIN_DOMAIN="your.main.domain.com"

# --- 脚本核心逻辑 ---
# 非专业人士请勿修改以下内容。

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 显示用法
usage() {
    echo "OpenResty 手动代理管理工具"
    echo "------------------------------------------------------------------"
    echo "用法: $0 <命令> [参数...]"
    echo ""
    echo "命令:"
    echo "  add <http|https|tcp> <内网IP:端口> <外网端口> [用途备注]"
    echo "      - 添加一条新的代理规则。"
    echo "      - 示例: $0 add http 192.168.1.5:8000 8080 '我的Web服务'"
    echo ""
    echo "  list"
    echo "      - 查询并列出当前所有已配置的代理规则。"
    echo ""
    echo "  delete <外网端口>"
    echo "      - 根据外网端口删除一条或多条规则 (HTTP/S 和 TCP/UDP)。"
    echo "      - 示例: $0 delete 8080"
    echo "------------------------------------------------------------------"
    exit 1
}

# 添加规则
do_add() {
    # 参数校验
    if [ "$#" -lt 3 ]; then usage; fi
    PROTOCOL=$(echo "$2" | tr '[:upper:]' '[:lower:]')
    LAN_ADDRESS=$3
    WAN_PORT=$4
    REMARK=${5:-"手动添加"}

    if ! [[ "$WAN_PORT" =~ ^[0-9]+$ ]]; then echo -e "${RED}错误: 外网端口 '$WAN_PORT' 不是一个有效的数字。${NC}"; exit 1; fi
    if ! [[ "$LAN_ADDRESS" =~ ^[0-9a-zA-Z\.\-]+:[0-9]+$ ]]; then echo -e "${RED}错误: 内网地址 '$LAN_ADDRESS' 格式不正确，应为 'ip:port'。${NC}"; exit 1; fi

    # 生成配置片段
    CONFIG_SNIPPET=""
    TARGET_CONF=""
    COMMENT_HEADER="# 手动添加规则 | 协议: ${PROTOCOL} | 外网端口: ${WAN_PORT} | 内网地址: ${LAN_ADDRESS} | 用途: ${REMARK} | 添加日期: $(date '+%Y-%m-%d %H:%M:%S')"

    case "$PROTOCOL" in
        http)
            TARGET_CONF=$HTTP_CONF_PATH
            CONFIG_SNIPPET=$(cat <<EOF

${COMMENT_HEADER}
server {
    listen ${WAN_PORT};
    listen [::]:${WAN_PORT};
    server_name _;

    location / {
        proxy_pass http://${LAN_ADDRESS};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
)
            ;;
        https)
            TARGET_CONF=$HTTP_CONF_PATH
            CONFIG_SNIPPET=$(cat <<EOF

${COMMENT_HEADER}
server {
    listen ${WAN_PORT} ssl http2;
    listen [::]:${WAN_PORT} ssl http2;
    server_name ${MAIN_DOMAIN};

    ssl_certificate ${SSL_CERT_PATH}${MAIN_DOMAIN}.pem;
    ssl_certificate_key ${SSL_CERT_PATH}${MAIN_DOMAIN}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    location / {
        proxy_pass http://${LAN_ADDRESS};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
)
            ;;
        tcp)
            TARGET_CONF=$STREAM_CONF_PATH
            CONFIG_SNIPPET=$(cat <<EOF

${COMMENT_HEADER}
server {
    listen ${WAN_PORT};
    listen ${WAN_PORT} udp;
    proxy_pass ${LAN_ADDRESS};
}
EOF
)
            ;;
        *)
            echo -e "${RED}错误: 无效的协议 '$PROTOCOL'。支持 http, https, tcp。${NC}"; usage
            ;;
    esac

    echo "--- 操作确认 ---"
    echo -e "协议:      ${YELLOW}${PROTOCOL}${NC}"
    echo -e "目标文件:  ${YELLOW}${TARGET_CONF}${NC}"
    echo -e "代理规则:  ${YELLOW}${LAN_ADDRESS} -> ${WAN_PORT}${NC}"
    echo -e "用途:      ${YELLOW}${REMARK}${NC}"
    read -p "确定要添加此规则吗? (y/n): " confirm
    if [[ ! ($confirm == "y" || $confirm == "Y") ]]; then echo "操作已取消。"; exit 0; fi

    apply_config "$TARGET_CONF" "$CONFIG_SNIPPET" "append"
}

# 查询规则
do_list() {
    parse_config_file() {
        local file_path=$1
        if [ ! -f "$file_path" ]; then
            echo "文件不存在或为空。"
            return
        fi

        # 使用兼容性最强的 POSIX awk 状态机来解析
        awk '
        /^(# Rule ID:|# 手动添加规则)/ {
            header = $0;
            in_block = 1;
            lan = wan = rid = remark = "";
        }
        in_block && /listen/ {
            if (wan == "" && match($0, /[0-9]+/)) {
                wan = substr($0, RSTART, RLENGTH);
            }
        }
        in_block && /proxy_pass/ {
            lan = $2;
            sub(/;$/, "", lan);
            sub(/^http:\/\//, "", lan);
        }
        in_block && /^\}/ {
            if (header ~ /^# Rule ID:/) {
                rid_str = header;
                sub(/.*Rule ID: /, "", rid_str);
                sub(/ .*/, "", rid_str);
                rid = rid_str;
                printf "  [机器人] 代理: %-25s -> 外网端口: %-5s (ID: %s)\n", lan, wan, rid;
            } else if (header ~ /^# 手动添加规则/) {
                remark_str = header;
                sub(/.*用途: /, "", remark_str);
                sub(/ *\|.*/, "", remark_str);
                remark = remark_str;
                yellow = "\033[1;33m"; nc = "\033[0m";
                printf "  " yellow "[手动]" nc "   代理: %-25s -> 外网端口: %-5s (用途: %s)\n", lan, wan, remark;
            }
            in_block = 0;
        }
        ' "$file_path"
    }

    echo -e "${GREEN}--- HTTP/S 规则 (${HTTP_CONF_PATH}) ---${NC}"
    parse_config_file "$HTTP_CONF_PATH"

    echo -e "\n${GREEN}--- TCP/UDP 规则 (${STREAM_CONF_PATH}) ---${NC}"
    parse_config_file "$STREAM_CONF_PATH"
}

# 删除规则
do_delete() {
    if [ "$#" -ne 2 ]; then usage; fi
    WAN_PORT_TO_DELETE=$2
    if ! [[ "$WAN_PORT_TO_DELETE" =~ ^[0-9]+$ ]]; then echo -e "${RED}错误: 端口 '$WAN_PORT_TO_DELETE' 不是一个有效的数字。${NC}"; exit 1; fi

    echo "将在以下两个文件中查找并删除外网端口为 ${YELLOW}${WAN_PORT_TO_DELETE}${NC} 的规则:"
    echo "1. ${HTTP_CONF_PATH}"
    echo "2. ${STREAM_CONF_PATH}"
    read -p "确定要继续吗? (y/n): " confirm
    if [[ ! ($confirm == "y" || $confirm == "Y") ]]; then echo "操作已取消。"; exit 0; fi

    # 处理每个文件
    process_deletion "$HTTP_CONF_PATH" "$WAN_PORT_TO_DELETE"
    process_deletion "$STREAM_CONF_PATH" "$WAN_PORT_TO_DELETE"
    echo -e "${GREEN}删除操作完成。${NC}"
}

# 删除处理函数
process_deletion() {
    local target_conf=$1
    local port_to_delete=$2
    local found=0

    if [ ! -f "$target_conf" ]; then return; fi

    # 使用 awk 识别并排除包含指定端口的 server块
    TEMP_FILE=$(mktemp)
    awk -v port="$port_to_delete" '
    BEGIN { record=""; in_block=0; delete_block=0; }
    /server *{/ {
        in_block=1;
        record=$0"\n";
        next;
    }
    in_block && /listen *[0-9\[\]:]* *'"port"'[^0-9]/ {
        delete_block=1;
    }
    in_block {
        record=record $0 "\n";
    }
    /}/ {
        if (in_block) {
            if (!delete_block) {
                printf "%s", record;
            } else {
                # This block is being deleted, we can set a flag here if needed
            }
            in_block=0;
            delete_block=0;
            record="";
        } else {
            print;
        }
        next;
    }
    !in_block {
        print;
    }
    ' "$target_conf" > "$TEMP_FILE"

    # 检查文件内容是否有变化
    if cmp -s "$target_conf" "$TEMP_FILE"; then
        echo -e "在 ${YELLOW}${target_conf}${NC} 中未找到端口为 ${port_to_delete} 的规则，已跳过。"
        rm "$TEMP_FILE"
        return
    fi

    echo -e "在 ${YELLOW}${target_conf}${NC} 中找到并准备删除规则。"
    apply_config "$target_conf" "$(cat $TEMP_FILE)" "overwrite"
    rm "$TEMP_FILE"
}

# 应用配置并重载
apply_config() {
    local target_conf=$1
    local content=$2
    local mode=$3 # "append" or "overwrite"

    # 1. 备份
    echo "步骤 1/4: 备份配置文件到 ${target_conf}.bak..."
    sudo cp "$target_conf" "${target_conf}.bak"
    if [ $? -ne 0 ]; then echo -e "${RED}错误: 创建备份失败，操作中止。${NC}"; exit 1; fi

    # 2. 写入
    echo "步骤 2/4: 写入新配置..."
    if [ "$mode" == "append" ]; then
        echo "$content" | sudo tee -a "$target_conf" > /dev/null
    else
        echo "$content" | sudo tee "$target_conf" > /dev/null
    fi
    if [ $? -ne 0 ]; then
        echo -e "${RED}错误: 写入配置文件失败，正在从备份还原...${NC}"
        sudo mv "${target_conf}.bak" "$target_conf"
        exit 1
    fi

    # 3. 测试
    echo "步骤 3/4: 测试 OpenResty 配置..."
    if sudo openresty -t; then
        echo -e "${GREEN}配置测试成功。${NC}"
        # 4. 重载
        echo "步骤 4/4: 重载 OpenResty 服务..."
        if sudo openresty -s reload; then
            echo -e "${GREEN}✅ 操作成功！OpenResty 已重载。${NC}"
            sudo rm "${target_conf}.bak"
        else
            echo -e "${RED}❌ 错误: 重载 OpenResty 失败，正在从备份还原...${NC}"
            sudo mv "${target_conf}.bak" "$target_conf"
            exit 1
        fi
    else
        echo -e "${RED}❌ 错误: 配置测试失败，正在从备份还原...${NC}"
        sudo mv "${target_conf}.bak" "$target_conf"
        exit 1
    fi
}

# --- 主逻辑 ---
if [ "$#" -eq 0 ]; then
    usage
fi

COMMAND=$1
case "$COMMAND" in
    add)
        do_add "$@"
        ;;
    list)
        do_list
        ;;
    delete)
        do_delete "$@"
        ;;
    *)
        echo -e "${RED}未知命令: $COMMAND${NC}"
        usage
        ;;
esac

exit 0
