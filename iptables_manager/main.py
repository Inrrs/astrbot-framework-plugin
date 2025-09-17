import asyncio
import json
import re
import shlex
import time
from pathlib import Path

from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.api import logger
from astrbot.core.utils.session_waiter import session_waiter, SessionController

# --- 数据存储 ---
DATA_DIR = Path("data/iptables_manager_pro")
CONFIG_FILE = DATA_DIR / "config.json"
REQUESTS_FILE = DATA_DIR / "requests.json"
WHITELIST_FILE = DATA_DIR / "whitelist.json"

def setup_data_files():
    """确保所有数据目录和文件都存在"""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_FILE.exists():
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f)
    if not REQUESTS_FILE.exists():
        with open(REQUESTS_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f)
    if not WHITELIST_FILE.exists():
        with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
            json.dump({"ips": []}, f)

def load_data(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_data(file_path, data):
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

@register("iptables_manager_pro", "781899414", "通过SSH管理iptables，带审批、端口检测、IP白名单。", "2.8.0")
class IptablesManagerProPlugin(Star):
    def __init__(self, context: Context):
        super().__init__(context)
        self.config = {}
        self.requests = {}
        self.whitelist = {}
        self.lock = asyncio.Lock()
        asyncio.create_task(self.initialize())

    async def initialize(self):
        """异步初始化"""
        async with self.lock:
            setup_data_files()
            self.config = load_data(CONFIG_FILE)
            self.requests = load_data(REQUESTS_FILE)
            self.whitelist = load_data(WHITELIST_FILE)
            logger.info("Iptables Manager Pro 插件已加载。")

    # --- 核心辅助函数 ---

    async def _run_ssh_command(self, command: str):
        """使用 sshpass 执行 SSH 命令"""
        host = self.config.get("host")
        port = self.config.get("port", 22)
        username = self.config.get("username")
        password = self.config.get("password")
        if not all([host, username, password]):
            raise ValueError("SSH主机信息未配置。请使用 '/端口映射 设置主机' 命令进行配置。")

        # 使用 shlex.quote 来安全地处理密码中的特殊字符
        ssh_command = (
            f"sshpass -p {shlex.quote(password)} "
            f"ssh -p {port} -o StrictHostKeyChecking=no -o ConnectTimeout=10 "
            f"{shlex.quote(username)}@{shlex.quote(host)} \"sudo {command}\""
        )
        
        process = await asyncio.create_subprocess_shell(
            ssh_command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            err_msg = stderr.decode('utf-8').strip()
            if "No chain/target/match by that name" in err_msg:
                return err_msg
            raise IOError(f"SSH命令执行失败: {err_msg or stdout.decode('utf-8').strip()}")
        
        return stdout.decode('utf-8').strip() or stderr.decode('utf-8').strip() or "命令执行成功。"

    async def _is_port_in_use(self, port: int):
        try:
            rules = await self._run_ssh_command('iptables -t nat -L PREROUTING -n')
            return f"dpt:{port}" in rules
        except Exception as e:
            logger.error(f"检查端口状态失败: {e}")
            raise ValueError("无法检查端口状态，请联系管理员。")

    async def _is_ip_whitelisted(self, ip: str):
        return ip in self.whitelist.get("ips", [])

    async def _notify_user(self, user_context: dict, message: str):
        if not user_context or "unified_msg_origin" not in user_context:
            return
        try:
            await self.context.send_plain_message(user_context["unified_msg_origin"], message)
        except Exception as e:
            logger.error(f"通知用户失败: {e}")

    async def _execute_port_forward(self, action: str, params: str):
        parts = params.strip().split()
        if len(parts) != 2:
            return "参数格式错误。正确格式: [内网IP]:[内网端口] [外网端口]"
        
        lan, wan_port = parts
        try:
            lan_ip, lan_port = lan.split(":")
        except ValueError:
            return "内网地址格式错误，应为 IP:端口"

        operation_char = "A" if action == "添加" else "D"
        rollback_char = "D" if action == "添加" else "A"

        # 确保 IP 转发开启 (此操作无需回滚)
        if action == "添加":
            try:
                await self._run_ssh_command("sysctl -w net.ipv4.ip_forward=1")
            except Exception as e:
                return f"操作失败: 开启IP转发失败: {e}"

        # 生成所有命令
        all_commands = []
        for protocol in ['tcp', 'udp']:
            cmd_dnat = f"iptables -t nat -{operation_char} PREROUTING -p {protocol} --dport {wan_port} -j DNAT --to-destination {lan_ip}:{lan_port}"
            cmd_forward_in = f"iptables -{operation_char} FORWARD -d {lan_ip} -p {protocol} --dport {lan_port} -j ACCEPT"
            cmd_forward_out = f"iptables -{operation_char} FORWARD -s {lan_ip} -p {protocol} --sport {lan_port} -j ACCEPT"
            cmd_snat = f"iptables -t nat -{operation_char} POSTROUTING -p {protocol} -d {lan_ip} --dport {lan_port} -j MASQUERADE"
            all_commands.extend([cmd_dnat, cmd_snat, cmd_forward_in, cmd_forward_out])

        executed_commands = []
        try:
            for cmd in all_commands:
                await self._run_ssh_command(cmd)
                executed_commands.append(cmd)
        except Exception as e:
            # 回滚
            error_message = f"执行命令失败: {e}\n正在回滚已执行的操作..."
            for cmd_to_rollback in reversed(executed_commands):
                rollback_cmd = cmd_to_rollback.replace(f"-{operation_char}", f"-{rollback_char}", 1)
                try:
                    await self._run_ssh_command(rollback_cmd)
                except Exception as rollback_e:
                    error_message += f"\n回滚失败: {rollback_cmd}\n错误: {rollback_e}"
            return error_message

        # 成功
        success_action = "添加成功" if action == "添加" else "删除成功"
        return f"规则 {success_action}。"

    async def _get_deletable_rules(self):
        """获取可删除的规则列表，并附带元数据"""
        # 1. 获取远程规则
        raw_rules = await self._run_ssh_command("iptables -t nat -L PREROUTING -n")
        
        # 2. 创建已批准申请的查找表
        approved_map = {
            req['params'].split()[1]: req 
            for rid, req in self.requests.items() 
            if req.get("status") == "approved" and 'params' in req and len(req['params'].split()) > 1
        }

        # 3. 解析规则并创建对象列表
        deletable_rules = []
        rule_pattern = re.compile(r"(tcp|udp).+dpt:(\d+)\s+to:([\d\.]+):(\d+)")

        for line in raw_rules.splitlines():
            if "DNAT" not in line:
                continue
            
            match = rule_pattern.search(line)
            if match:
                protocol, wan_port, lan_ip, lan_port = match.groups()
                
                # 查找对应的本地请求ID
                request_id = None
                if wan_port in approved_map:
                    req_to_find = approved_map[wan_port]
                    for rid, req_item in self.requests.items():
                        if req_item == req_to_find:
                            request_id = rid
                            break

                rule_info = {
                    "protocol": protocol,
                    "wan_port": wan_port,
                    "lan_ip": lan_ip,
                    "lan_port": lan_port,
                    "params": f"{lan_ip}:{lan_port} {wan_port}",
                    "request_id": request_id
                }

                if request_id and wan_port in approved_map:
                    req = approved_map[wan_port]
                    rule_info["sender_name"] = req['request_event']['sender']['name']
                    rule_info["remark"] = req.get('remark', '无')
                    rule_info["source"] = "known"
                else:
                    rule_info["source"] = "unknown"
                
                deletable_rules.append(rule_info)
        
        return sorted(deletable_rules, key=lambda x: int(x['wan_port']))

    # --- 指令组 ---
    @filter.command_group("端口映射")
    def iptables_group(self):
        """通过SSH管理iptables，带审批、端口检测、IP白名单。"""
        pass

    # ===================================================================
    # --- 管理员指令 (需要ADMIN权限) ---
    # ===================================================================
    @filter.permission_type(filter.PermissionType.ADMIN)
    @iptables_group.command("设置主机")
    async def set_host(self, event: AstrMessageEvent, host_str: str, username: str, password: str):
        """设置转发主机信息，并自动检查和配置远程环境。用法: /端口映射 设置主机 <ip[:端口]> <用户名> <密码>"""
        
        # --- Step 0: Configure Host Info ---
        async with self.lock:
            if ":" in host_str:
                host, port_str = host_str.split(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    yield event.plain_result("端口号必须是数字。")
                    return
            else:
                host = host_str
                port = 22

            self.config["host"] = host
            self.config["port"] = port
            self.config["username"] = username
            self.config["password"] = password
            save_data(CONFIG_FILE, self.config)
        
        # --- Step 1: Run all checks and collect logs ---
        log_messages = [
            f"主机信息设置成功：\nIP: {host}\n端口: {port}\n用户名: {username}",
            "\n开始自动检查和配置远程主机环境..."
        ]

        try:
            # Check 1: iptables
            log_messages.append("1/3: 正在检查远程主机 iptables 是否可用...")
            try:
                await self._run_ssh_command("iptables -V")
                log_messages.append("✅ iptables 已安装。")
            except IOError:
                log_messages.append("⚠️ 未找到 iptables 命令，正在尝试自动安装... (这可能需要几分钟，请耐心等待)")
                try:
                    install_script = (
                        "if command -v apt-get > /dev/null; then "
                        "apt-get update && apt-get install -y iptables; "
                        "elif command -v yum > /dev/null; then "
                        "yum install -y iptables; "
                        "elif command -v dnf > /dev/null; then "
                        "dnf install -y iptables; "
                        "else "
                        "echo 'Unsupported package manager.' >&2; exit 1; "
                        "fi"
                    )
                    install_result = await self._run_ssh_command(install_script)
                    log_messages.append(f"✅ iptables 自动安装成功。\n{install_result}")
                except Exception as install_e:
                    log_messages.append(f"❌ iptables 自动安装失败: {install_e}\n请在远程主机上手动安装 iptables 相关工具包，然后重试。")
                    yield event.plain_result("\n".join(log_messages))
                    return

            # Check 2: IP Forwarding (Runtime)
            log_messages.append("\n2/3: 正在检查 IP 转发状态...")
            runtime_check = await self._run_ssh_command("sysctl net.ipv4.ip_forward")
            if "net.ipv4.ip_forward = 1" in runtime_check:
                log_messages.append("✅ IP 转发在当前运行时已开启。")
            else:
                log_messages.append("⚠️ IP 转发在当前运行时未开启，正在临时启用...")
                await self._run_ssh_command("sysctl -w net.ipv4.ip_forward=1")

            # Check 3: IP Forwarding (Permanent)
            log_messages.append("\n3/3: 正在检查 IP 转发是否已永久启用...")
            permanent_check_command = "grep -q '^\\s*net.ipv4.ip_forward\\s*=\\s*1' /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null"
            
            try:
                await self._run_ssh_command(f"bash -c '{permanent_check_command}'")
                log_messages.append("✅ IP 转发已永久启用。")
            except IOError:
                log_messages.append("⚠️ IP 转发未永久启用，正在尝试自动配置...")
                enable_command = (
                    "echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-astrbot-forward.conf && "
                    "sysctl -p /etc/sysctl.d/99-astrbot-forward.conf"
                )
                enable_result = await self._run_ssh_command(enable_command)
                log_messages.append(f"✅ 永久启用 IP 转发成功。\n{enable_result}")
            
            log_messages.append("\n远程主机环境检查和配置完成。")

        except Exception as e:
            log_messages.append(f"❌ 环境检查时发生未知错误: {e}")
        
        # --- Step 2: Send the final consolidated report ---
        yield event.plain_result("\n".join(log_messages))

    @filter.permission_type(filter.PermissionType.ADMIN)
    @iptables_group.command("查看主机")
    async def view_host(self, event: AstrMessageEvent):
        """查看当前配置的转发主机。用法: /端口映射 查看主机"""
        host = self.config.get("host", "未设置")
        port = self.config.get("port", "22 (默认)")
        username = self.config.get("username", "未设置")
        yield event.plain_result(f"当前配置的主机信息：\nIP: {host}\n端口: {port}\n用户名: {username}")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @iptables_group.command("设置审批")
    async def set_admin(self, event: AstrMessageEvent):
        """将您自己设置为转发申请的审批员。用法: /端口映射 设置审批"""
        async with self.lock:
            self.config["admin_notify_context"] = {"unified_msg_origin": event.unified_msg_origin}
            save_data(CONFIG_FILE, self.config)
        yield event.plain_result("设置成功，新的转发申请将通知到您。")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @iptables_group.command("白名单")
    async def whitelist_cmd(self, event: AstrMessageEvent, action: str, ips_str: str):
        """管理IP白名单。用法: /端口映射 白名单 <添加|删除> <ip1> <ip2> ..."""
        ips = ips_str.strip().split()
        if not ips:
            yield event.plain_result("IP地址不能为空。")
            return
        
        if action not in ["添加", "删除"]:
            yield event.plain_result("无效的操作，请输入 '添加' 或 '删除'。")
            return

        async with self.lock:
            ip_list = self.whitelist.get("ips", [])
            added, removed, existed, not_found = [], [], [], []

            if action == "添加":
                for ip in ips:
                    if ip not in ip_list:
                        ip_list.append(ip)
                        added.append(ip)
                    else:
                        existed.append(ip)
            else: # 删除
                for ip in ips:
                    if ip in ip_list:
                        ip_list.remove(ip)
                        removed.append(ip)
                    else:
                        not_found.append(ip)
            
            self.whitelist["ips"] = ip_list
            save_data(WHITELIST_FILE, self.whitelist)

        reply_msg = ""
        if added: reply_msg += f"成功添加IP: {', '.join(added)}\n"
        if removed: reply_msg += f"成功删除IP: {', '.join(removed)}\n"
        if existed: reply_msg += f"IP已存在: {', '.join(existed)}\n"
        if not_found: reply_msg += f"IP不存在: {', '.join(not_found)}\n"
        yield event.plain_result(reply_msg.strip() or "未执行任何操作。")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @iptables_group.command("查看白名单")
    async def view_whitelist(self, event: AstrMessageEvent):
        """查看IP白名单。用法: /端口映射 查看白名单"""
        ip_list = self.whitelist.get("ips", [])
        yield event.plain_result("内网IP白名单：\n" + "\n".join(ip_list) if ip_list else "白名单为空。")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @iptables_group.command("待审列表")
    async def view_pending(self, event: AstrMessageEvent):
        """查看待审批的转发申请。用法: /端口映射 待审列表"""
        pending_list = []
        for rid, req in self.requests.items():
            if req.get("status") == "pending":
                remark = req.get('remark', '未填写')
                pending_list.append(f"ID: {rid} | 申请人: {req['request_event']['sender']['name']} | 内容: {req['params']} | 用途: {remark}")
        
        yield event.plain_result("待处理的申请列表:\n" + "\n".join(pending_list) if pending_list else "当前没有待处理的申请。")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @iptables_group.command("同意")
    async def approve_request(self, event: AstrMessageEvent, request_id: str):
        """同意一个或全部转发申请。用法: /端口映射 同意 <id|all>"""
        if request_id.lower() == "all":
            async with self.lock:
                pending_requests = {rid: req for rid, req in self.requests.items() if req.get("status") == "pending"}
                if not pending_requests:
                    yield event.plain_result("没有待处理的申请。")
                    return

                approved_count = 0
                failed_count = 0
                results_log = []
                yield event.plain_result(f"开始批量批准 {len(pending_requests)} 个申请...")

                for rid, req in pending_requests.items():
                    try:
                        lan_ip = req['params'].split()[0].split(":")[0]
                        if not await self._is_ip_whitelisted(lan_ip):
                            req['status'] = "rejected_not_whitelisted"
                            results_log.append(f"ID {rid}: 失败 - IP {lan_ip} 不在白名单。")
                            await self._notify_user(req['request_event'], f"您的申请 {rid} 审批失败，原因：IP已不在白名单内。")
                            failed_count += 1
                            continue

                        wan_port = int(req['params'].split()[1])
                        if await self._is_port_in_use(wan_port):
                            req['status'] = "rejected_conflict"
                            results_log.append(f"ID {rid}: 失败 - 端口 {wan_port} 已被占用。")
                            await self._notify_user(req['request_event'], f"您的申请 {rid} 审批失败，原因：端口已被占用。")
                            failed_count += 1
                            continue

                        await self._execute_port_forward("添加", req['params'])
                        req['status'] = "approved"
                        results_log.append(f"ID {rid}: 成功批准。")
                        await self._notify_user(req['request_event'], f"您的端口转发申请 {rid} 已被管理员批准。")
                        approved_count += 1
                    except Exception as e:
                        results_log.append(f"ID {rid}: 处理时发生错误 - {e}")
                        failed_count += 1
                
                save_data(REQUESTS_FILE, self.requests)
            
            summary = (
                f"批量批准完成。\n"
                f"成功: {approved_count}\n"
                f"失败: {failed_count}\n\n"
                f"详细日志:\n" + "\n".join(results_log)
            )
            yield event.plain_result(summary)
            return

        async with self.lock:
            req = self.requests.get(request_id)
            if not req or req.get("status") != "pending":
                yield event.plain_result(f"未找到ID为 {request_id} 的待处理申请。")
                return

            try:
                lan_ip = req['params'].split()[0].split(":")[0]
                if not await self._is_ip_whitelisted(lan_ip):
                    req['status'] = "rejected_not_whitelisted"
                    save_data(REQUESTS_FILE, self.requests)
                    await self._notify_user(req['request_event'], f"您的申请 {request_id} 审批失败，原因：IP已不在白名单内。")
                    yield event.plain_result(f"审批失败：内网IP {lan_ip} 已不在白名单内。")
                    return

                wan_port = int(req['params'].split()[1])
                if await self._is_port_in_use(wan_port):
                    req['status'] = "rejected_conflict"
                    save_data(REQUESTS_FILE, self.requests)
                    await self._notify_user(req['request_event'], f"您的申请 {request_id} 审批失败，原因：端口已被占用。")
                    yield event.plain_result(f"审批失败：外网端口 {wan_port} 在此期间已被占用。")
                    return

                yield event.plain_result(f"正在处理申请 {request_id}...")
                result = await self._execute_port_forward("添加", req['params'])
                req['status'] = "approved"
                save_data(REQUESTS_FILE, self.requests)
                await self._notify_user(req['request_event'], f"您的端口转发申请 {request_id} 已被管理员批准。")
                yield event.plain_result(f"申请 {request_id} 已批准并执行。\n{result}")

            except Exception as e:
                yield event.plain_result(f"处理申请时发生错误: {e}")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @iptables_group.command("检查转发")
    async def check_forwarding(self, event: AstrMessageEvent):
        """(管理员) 检查远程主机IP转发是否开启。用法: /端口映射 检查转发"""
        try:
            yield event.plain_result("正在检查 IP 转发状态...")
            result = await self._run_ssh_command("sysctl net.ipv4.ip_forward")
            yield event.plain_result(f"检查结果:\n{result}")
        except Exception as e:
            yield event.plain_result(f"检查失败: {e}")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @iptables_group.command("查看规则")
    async def view_rules(self, event: AstrMessageEvent):
        """(管理员) 查看已解析的端口映射规则。用法: /端口映射 查看规则"""
        try:
            yield event.plain_result("正在远程查询并解析规则...")
            
            # 1. 获取远程规则
            raw_rules = await self._run_ssh_command("iptables -t nat -L PREROUTING -n")
            
            # 2. 创建已批准申请的查找表
            approved_map = {
                req['params'].split()[1]: req 
                for rid, req in self.requests.items() 
                if req.get("status") == "approved" and 'params' in req and len(req['params'].split()) > 1
            }

            # 3. 解析规则并格式化输出
            formatted_rules = []
            rule_pattern = re.compile(r"(tcp|udp).+dpt:(\d+)\s+to:([\d\.]+):(\d+)")

            for line in raw_rules.splitlines():
                if "DNAT" not in line:
                    continue
                
                match = rule_pattern.search(line)
                if match:
                    protocol, wan_port, lan_ip, lan_port = match.groups()
                    
                    if wan_port in approved_map:
                        req = approved_map[wan_port]
                        sender_name = req['request_event']['sender']['name']
                        remark = req.get('remark', '无')
                        rule_str = f"✅ [{protocol.upper()}] {sender_name}: {lan_ip}:{lan_port} -> {wan_port} (用途: {remark})"
                    else:
                        rule_str = f"❓ [{protocol.upper()}] 未知规则: {lan_ip}:{lan_port} -> {wan_port}"
                    
                    formatted_rules.append(rule_str)

            if not formatted_rules:
                yield event.plain_result("在远程主机上未找到有效的端口映射规则。")
                return

            final_message = "当前端口映射规则列表：\n" + "\n".join(sorted(formatted_rules))
            final_message += "\n\n💡提示: 可以发送 '/端口映射 删除 <端口1> <端口2>...' 来删除规则。"
            yield event.plain_result(final_message)

        except Exception as e:
            yield event.plain_result(f"查询规则失败: {e}")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @iptables_group.command("添加")
    async def add_rule(self, event: AstrMessageEvent, lan_address: str, wan_port: int):
        """(管理员) 直接添加端口转发规则。用法: /端口映射 添加 <内网IP:端口> <外网端口>"""
        try:
            lan_ip = lan_address.split(":")[0]
            if not await self._is_ip_whitelisted(lan_ip):
                yield event.plain_result(f"操作失败：内网IP {lan_ip} 不在白名单内。")
                return
            
            if await self._is_port_in_use(wan_port):
                yield event.plain_result(f"操作失败：外网端口 {wan_port} 已被占用。")
                return

            yield event.plain_result("正在远程主机上添加规则...")
            params = f"{lan_address} {wan_port}"
            result = await self._execute_port_forward("添加", params)

            # 如果成功，则记录这次操作
            if "添加成功" in result:
                async with self.lock:
                    # 使用时间戳确保ID唯一
                    request_id = f"admin_{wan_port}_{int(time.time())}"
                    admin_event = {
                        "unified_msg_origin": event.unified_msg_origin,
                        "sender": {"id": event.get_sender_id(), "name": "管理员"}
                    }
                    self.requests[request_id] = {
                        "params": params,
                        "remark": "管理员直接添加",
                        "request_event": admin_event,
                        "status": "approved"
                    }
                    save_data(REQUESTS_FILE, self.requests)
            
            yield event.plain_result(result)
        except Exception as e:
            yield event.plain_result(f"添加规则失败: {e}")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @iptables_group.command("删除")
    async def remove_rule_by_port(self, event: AstrMessageEvent, ports_str: str):
        """(管理员) 根据映射端口删除一个或多个规则。用法: /端口映射 删除 <端口1> <端口2> ..."""
        try:
            ports_to_delete = {p.strip() for p in ports_str.split()}
            if not all(p.isdigit() for p in ports_to_delete):
                raise ValueError()
        except ValueError:
            yield event.plain_result("端口号必须是数字。请检查您的输入。")
            return

        yield event.plain_result("正在获取最新规则列表并准备删除...")
        
        async with self.lock:
            rules = await self._get_deletable_rules()
            
            deleted_count = 0
            failed_count = 0
            results_log = []

            if not rules:
                yield event.plain_result("未找到任何规则，无法删除。")
                return

            # 去重，因为TCP和UDP会产生相同的params
            unique_rules_to_delete = {
                rule['params']: rule for rule in rules if rule['wan_port'] in ports_to_delete
            }.values()

            if not unique_rules_to_delete:
                yield event.plain_result("提供的端口号无效或不匹配任何现有规则。")
                return

            for rule in unique_rules_to_delete:
                rule_desc = f"端口 {rule['wan_port']} ({rule['lan_ip']}:{rule['lan_port']})"
                result = await self._execute_port_forward("删除", rule['params'])
                
                if "删除成功" in result:
                    if rule.get("request_id"):
                        request_id = rule["request_id"]
                        if request_id in self.requests:
                            self.requests[request_id]['status'] = 'deleted'
                    
                    results_log.append(f"✅ {rule_desc}: 删除成功。")
                    deleted_count += 1
                else:
                    results_log.append(f"❌ {rule_desc}: 删除失败 - {result}")
                    failed_count += 1
            
            if deleted_count > 0:
                save_data(REQUESTS_FILE, self.requests)

            summary = (
                f"批量删除完成。\n"
                f"成功: {deleted_count}\n"
                f"失败: {failed_count}\n\n"
                f"详细日志:\n" + "\n".join(results_log)
            )
            yield event.plain_result(summary)

    @filter.permission_type(filter.PermissionType.ADMIN)
    @iptables_group.command("拒绝")
    async def reject_request(self, event: AstrMessageEvent, request_id: str):
        """拒绝一个或全部转发申请。用法: /端口映射 拒绝 <id|all>"""
        if request_id.lower() == "all":
            async with self.lock:
                pending_requests = {rid: req for rid, req in self.requests.items() if req.get("status") == "pending"}
                if not pending_requests:
                    yield event.plain_result("没有待处理的申请。")
                    return
                
                rejected_count = 0
                yield event.plain_result(f"开始批量拒绝 {len(pending_requests)} 个申请...")

                for rid, req in pending_requests.items():
                    req['status'] = "rejected"
                    await self._notify_user(req['request_event'], f"抱歉，您的端口转发申请 {rid} 已被管理员拒绝。")
                    rejected_count += 1
                
                save_data(REQUESTS_FILE, self.requests)
            
            yield event.plain_result(f"批量拒绝完成，共拒绝 {rejected_count} 个申请。")
            return

        async with self.lock:
            req = self.requests.get(request_id)
            if not req or req.get("status") != "pending":
                yield event.plain_result(f"未找到ID为 {request_id} 的待处理申请。")
                return
            
            req['status'] = "rejected"
            save_data(REQUESTS_FILE, self.requests)
            await self._notify_user(req['request_event'], f"抱歉，您的端口转发申请 {request_id} 已被管理员拒绝。")
        yield event.plain_result(f"申请 {request_id} 已拒绝。")

    # ===================================================================
    # --- 用户指令 (所有用户可用) ---
    # ===================================================================
    @iptables_group.command("申请")
    async def apply_forward(self, event: AstrMessageEvent, lan_address: str, wan_port: int, remark: str):
        """申请端口转发。用法: /端口映射 申请 <内网IP:端口> <外网端口> <备注用途>"""
        try:
            lan_ip = lan_address.split(":")[0]
            if not await self._is_ip_whitelisted(lan_ip):
                yield event.plain_result(f"申请失败：内网IP {lan_ip} 不在白名单内。")
                return
            
            if await self._is_port_in_use(wan_port):
                yield event.plain_result(f"申请失败：外网端口 {wan_port} 已被占用。")
                return

            request_id = event.get_sender_id()
            async with self.lock:
                if self.requests.get(request_id) and self.requests[request_id].get("status") == "pending":
                    yield event.plain_result("申请失败：您已有一个待处理的申请，请勿重复提交。")
                    return

                simple_event = {
                    "unified_msg_origin": event.unified_msg_origin,
                    "sender": {"id": event.get_sender_id(), "name": event.get_sender_name()}
                }
                self.requests[request_id] = {
                    "params": f"{lan_address} {wan_port}",
                    "remark": remark,
                    "request_event": simple_event,
                    "status": "pending"
                }
                save_data(REQUESTS_FILE, self.requests)
            
            yield event.plain_result(f"您的申请已提交，ID为您的QQ号: {request_id}。请等待管理员审核。")
            
            admin_context = self.config.get("admin_notify_context")
            if admin_context:
                await self._notify_user(admin_context, 
                    f"收到新的端口转发申请:\nID: {request_id}\n"
                    f"申请人: {event.get_sender_name()}\n"
                    f"内容: {lan_address} -> {wan_port}\n"
                    f"用途: {remark}\n"
                    f"请使用 '/端口映射 同意 {request_id}' 或 '/端口映射 拒绝 {request_id}' 处理。")

        except Exception as e:
            yield event.plain_result(f"申请失败: {e}")
