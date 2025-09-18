import asyncio
import json
import re
import asyncssh
import time
from pathlib import Path
from urllib.parse import urlparse

from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.api import logger, AstrBotConfig
from astrbot.core.utils.session_waiter import session_waiter, SessionController

@register("openresty_proxy_manager","通过SSH管理OpenResty反向代理，带审批、域名白名单。", "1.0.0", "https://github.com/Inrrs/astrbot-framework-plugin")
class OpenRestyProxyManagerPlugin(Star):
    def __init__(self, context: Context, config: AstrBotConfig = None):
        super().__init__(context)
        if not isinstance(config, AstrBotConfig):
            logger.error("OpenResty Proxy Manager 插件配置未加载。功能将受限。请检查 _conf_schema.json 文件是否在插件根目录且格式正确，或检查插件压缩包结构。")
            self.config = AstrBotConfig({}, schema={})
        else:
            self.config = config

        # 使用独立文件进行数据持久化
        self.data_path = Path(__file__).parent / "data.json"
        self.requests = {}
        self.whitelist = {}
        self.forbidden_ports = {80, 443, 8080, 8443}  # 禁止反代的端口
        self.lock = asyncio.Lock()
        asyncio.create_task(self.initialize())

    async def _load_data(self):
        """从 data.json 加载数据"""
        if self.data_path.exists():
            with open(self.data_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}

    async def _save_data(self):
        """将数据保存到 data.json"""
        data_to_save = {
            "requests": self.requests,
            "whitelist": self.whitelist
        }
        with open(self.data_path, 'w', encoding='utf-8') as f:
            json.dump(data_to_save, f, ensure_ascii=False, indent=4)

    async def initialize(self):
        """异步初始化"""
        async with self.lock:
            # 从独立json文件加载数据
            data = await self._load_data()
            self.requests = data.get("requests", {})
            self.whitelist = data.get("whitelist", {})
            if "ips" not in self.whitelist:
                self.whitelist["ips"] = []
            logger.info("OpenResty Proxy Manager 插件已加载，并从 data.json 恢复了数据。")

    # --- 核心辅助函数 ---

    async def _run_ssh_command(self, command: str):
        """使用 asyncssh 执行远程 SSH 命令"""
        ssh_config = self.config.get("ssh_config", {})
        host = ssh_config.get("host")
        port = ssh_config.get("port")
        username = ssh_config.get("username")
        password = ssh_config.get("password")

        if not all([host, username, password]):
            raise ValueError("SSH主机信息未在插件配置中完全配置。")

        try:
            async with asyncssh.connect(
                host,
                port=port,
                username=username,
                password=password,
                known_hosts=None
            ) as conn:
                result = await conn.run(f"sudo {command}", check=True)
                return result.stdout.strip() if result.stdout else ""
        except asyncssh.Error as e:
            raise IOError(f"SSH连接或命令执行失败: {e}")
        except Exception as e:
            raise IOError(f"执行SSH命令时发生未知错误: {e}")

    async def _check_cert_exists(self, cert_name: str):
        """检查远程服务器上是否存在指定的SSL证书文件 (.pem 和 .key)"""
        openresty_config = self.config.get("openresty_config", {})
        ssl_path = openresty_config.get("ssl_cert_path")
        if not ssl_path:
            raise ValueError("SSL证书路径未配置。")
            
        cert_path = f"{ssl_path}{cert_name}.pem"
        key_path = f"{ssl_path}{cert_name}.key"
        
        command = f"[ -f {cert_path} ] && [ -f {key_path} ]"
        try:
            await self._run_ssh_command(command)
            return True
        except IOError:
            return False

    async def _get_occupying_request(self, port: int, exclude_req_id=None):
        """检查外网端口是否已被本地记录占用, 如果是，则返回该请求"""
        port_str = str(port)
        for req_id, req in self.requests.items():
            if exclude_req_id and req_id == exclude_req_id:
                continue
            if req.get("status") in ["pending", "approved"]:
                if req['params'].split()[1] == port_str:
                    return req
        return None

    async def _is_ip_whitelisted(self, ip: str):
        """检查目标地址的IP是否在白名单中"""
        return ip in self.whitelist.get("ips", [])

    async def _notify_user(self, user_context: dict, message: str):
        if not user_context or "unified_msg_origin" not in user_context:
            return
        try:
            await self.context.send_plain_message(user_context["unified_msg_origin"], message)
        except Exception as e:
            logger.error(f"通知用户失败: {e}")

    async def _update_openresty_config(self):
        """生成并更新远程OpenResty配置"""
        approved_requests = [(rid, req) for rid, req in self.requests.items() if req.get("status") == "approved"]
        openresty_config = self.config.get("openresty_config", {})

        http_rules, stream_rules = [], []
        for rid, req in approved_requests:
            protocol = req.get("protocol", "http")
            if protocol in ["http", "https"]:
                http_rules.append((rid, req))
            elif protocol in ["tcp", "udp"]:
                if not any(r[1]['params'] == req['params'] for r in stream_rules):
                    stream_rules.append((rid, req))
        
        main_domain = openresty_config.get("main_domain") or "_"
        ssl_cert_path = openresty_config.get("ssl_cert_path")
        
        http_config_lines = ["# Auto-generated by AstrBot. Do not edit manually."]
        if http_rules:
            for rid, req in http_rules:
                applicant_name = req.get('request_event', {}).get('sender', {}).get('name', 'N/A')
                remark = req.get('remark', 'N/A')
                protocol, (lan_address, wan_port) = req.get("protocol", "http"), req['params'].split()
                proxy_pass = f"http://{lan_address}"
                
                comment = f"# Rule ID: {rid} | Applicant: {applicant_name} | Purpose: {remark}"

                if protocol == "https":
                    cert_name = req.get("cert_name")
                    if not cert_name or not ssl_cert_path: continue
                    http_config_lines.append(f"""
{comment}
server {{
    listen {wan_port} ssl http2;
    server_name {main_domain};
    ssl_certificate {ssl_cert_path}{cert_name}.pem;
    ssl_certificate_key {ssl_cert_path}{cert_name}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    location / {{
        proxy_pass {proxy_pass};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}""")
                else:
                    http_config_lines.append(f"""
{comment}
server {{
    listen {wan_port};
    server_name {main_domain};
    location / {{
        proxy_pass {proxy_pass};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}""")
        
        await self._upload_and_reload(
            "\n".join(http_config_lines), 
            openresty_config.get("remote_http_config_path"),
            is_stream=False
        )

        stream_config_lines = ["# Auto-generated by AstrBot. Do not edit manually."]
        if stream_rules:
            for rid, req in stream_rules:
                applicant_name = req.get('request_event', {}).get('sender', {}).get('name', 'N/A')
                remark = req.get('remark', 'N/A')
                comment = f"# Rule ID: {rid} | Applicant: {applicant_name} | Purpose: {remark}"
                lan_address, wan_port = req['params'].split()
                stream_config_lines.extend([f"""
{comment}
server {{
    listen {wan_port};
    proxy_pass {lan_address};
}}""", f"""
{comment} (UDP)
server {{
    listen {wan_port} udp;
    proxy_pass {lan_address};
}}"""])

        await self._upload_and_reload(
            "\n".join(stream_config_lines), 
            openresty_config.get("remote_stream_config_path"),
            is_stream=True
        )

        return f"OpenResty配置已更新: {len(http_rules)}条HTTP/S规则, {len(stream_rules)}条TCP/UDP规则。"

    async def _upload_and_reload(self, config_content: str, remote_path: str, is_stream: bool):
        """安全地上传配置、测试，然后重载 OpenResty。"""
        if not remote_path:
            logger.error(f"远程配置文件路径未设置 ({'Stream' if is_stream else 'HTTP'})。跳过更新。")
            return

        logger.info(f"准备上传配置到: {remote_path}")
        logger.debug(f"配置内容:\n---\n{config_content}\n---")

        remote_path_obj = Path(remote_path)
        backup_path = remote_path_obj.with_suffix(remote_path_obj.suffix + ".bak")
        remote_dir = remote_path_obj.parent
        
        temp_path = f"/tmp/astrabot_conf_{int(time.time())}_{hash(config_content) & 0xffffff}"
        logger.info(f"使用临时文件: {temp_path}")

        ssh_details = self.config.get("ssh_config", {})
        if not ssh_details.get("host"):
            raise ValueError("SSH主机信息未配置。")

        async with asyncssh.connect(**ssh_details, known_hosts=None) as conn:
            try:
                logger.info(f"步骤 1/8: 上传配置到临时文件 {temp_path}...")
                async with conn.start_sftp_client() as sftp:
                    async with sftp.open(temp_path, 'w') as f:
                        await f.write(config_content)
                logger.info("上传成功。")

                logger.info(f"步骤 2/8: 确保远程目录存在: {remote_dir}")
                await conn.run(f"sudo mkdir -p {remote_dir}", check=True)
                
                logger.info(f"步骤 3/8: 备份现有配置 (如果存在) 从 {remote_path} 到 {backup_path}")
                await conn.run(f"sudo mv -f {remote_path} {backup_path}", check=False)
                
                logger.info(f"步骤 4/8: 将新配置从 {temp_path} 移动到 {remote_path}")
                await conn.run(f"sudo cp {temp_path} {remote_path}", check=True)

                logger.info("步骤 5/8: 验证远程文件内容...")
                cat_result = await conn.run(f"sudo cat {remote_path}", check=True)
                remote_content = cat_result.stdout.strip()
                local_content_stripped = config_content.strip()

                if remote_content.replace('\r\n', '\n') != local_content_stripped.replace('\r\n', '\n'):
                    logger.error("远程文件内容验证失败！")
                    await conn.run(f"sudo mv -f {backup_path} {remote_path}", check=False)
                    raise IOError("验证失败：远程文件内容与生成的内容不匹配。")
                logger.info("内容验证成功。")

                logger.info("步骤 6/8: 测试 OpenResty 配置 (sudo openresty -t)...")
                test_result = await conn.run("sudo openresty -t", check=False)
                full_test_output = f"STDOUT:\n{test_result.stdout}\nSTDERR:\n{test_result.stderr}"
                logger.debug(f"openresty -t 输出:\n{full_test_output}")

                if test_result.returncode != 0:
                    logger.error(f"新配置无效，返回码: {test_result.returncode}。正在回滚...")
                    await conn.run(f"sudo mv -f {backup_path} {remote_path}", check=False)
                    await conn.run(f"[ ! -f {backup_path} ] && sudo rm -f {remote_path}", check=False)
                    raise ValueError(f"新配置无效，操作已取消: {test_result.stderr}")
                logger.info("配置测试成功。")

                logger.info("步骤 7/8: 重载 OpenResty (sudo openresty -s reload)...")
                reload_result = await conn.run("sudo openresty -s reload", check=False)
                if reload_result.returncode != 0:
                    logger.error(f"重载 OpenResty 失败，返回码: {reload_result.returncode}。正在回滚...")
                    await conn.run(f"sudo mv -f {backup_path} {remote_path}", check=False)
                    logger.info("尝试再次重载以恢复旧配置...")
                    await conn.run("sudo openresty -s reload", check=False)
                    raise IOError(f"重载 OpenResty 失败: {reload_result.stderr}")
                logger.info("重载成功。")

                logger.info(f"步骤 8/8: 删除备份文件 {backup_path}...")
                await conn.run(f"sudo rm -f {backup_path}", check=False)
                logger.info("配置更新流程成功完成。")

            except Exception as e:
                logger.error(f"在配置更新过程中发生错误: {e}。正在尝试恢复备份...")
                await conn.run(f"sudo mv -f {backup_path} {remote_path}", check=False)
                logger.error("备份恢复尝试完成。")
                raise e
            finally:
                logger.info(f"清理临时文件 {temp_path}...")
                await conn.run(f"rm -f {temp_path}", check=False)

    # --- 指令组 ---
    @filter.command_group("反代")
    def proxy_group(self):
        """通过SSH管理OpenResty反向代理，带审批、IP白名单。"""
        pass

    # ===================================================================
    # --- 管理员指令 (需要ADMIN权限) ---
    # ===================================================================
    async def _run_ssh_command_full_output(self, command: str):
        """使用 asyncssh 执行远程 SSH 命令并返回 stdout 和 stderr。"""
        ssh_config = self.config.get("ssh_config", {})
        host = ssh_config.get("host")
        port = ssh_config.get("port")
        username = ssh_config.get("username")
        password = ssh_config.get("password")

        if not all([host, username, password]):
            raise ValueError("SSH主机信息未在插件配置中完全配置。")

        try:
            async with asyncssh.connect(
                host, port=port, username=username, password=password, known_hosts=None
            ) as conn:
                result = await conn.run(f"sudo {command}", check=False)
                return (result.stdout or "", result.stderr or "")
        except asyncssh.Error as e:
            raise IOError(f"SSH连接或命令执行失败: {e}")
        except Exception as e:
            raise IOError(f"执行SSH命令时发生未知错误: {e}")

    async def _run_ssh_command_and_get_code(self, command: str):
        """使用 asyncssh 执行远程 SSH 命令并返回退出码。"""
        ssh_config = self.config.get("ssh_config", {})
        host = ssh_config.get("host")
        port = ssh_config.get("port")
        username = ssh_config.get("username")
        password = ssh_config.get("password")

        if not all([host, username, password]):
            raise ValueError("SSH主机信息未在插件配置中完全配置。")

        try:
            async with asyncssh.connect(
                host, port=port, username=username, password=password, known_hosts=None
            ) as conn:
                result = await conn.run(f"sudo {command}", check=False)
                return result.returncode
        except (asyncssh.Error, IOError, Exception) as e:
            logger.warning(f"执行SSH命令 '{command}' 时出错: {e}")
            return -1 # 返回一个表示失败的特定代码

    async def _is_remote_port_in_use(self, port: int):
        """通过SSH检查远程主机上的端口是否被监听 (TCP或UDP)。"""
        # 使用 \b 来确保精确匹配端口号, 避免 80 匹配到 8080
        command = f"ss -lntu | grep -q ':{port}\\b'"
        returncode = await self._run_ssh_command_and_get_code(command)
        # returncode 0 表示 grep 找到匹配 (端口被占用)
        return returncode == 0

    @filter.permission_type(filter.PermissionType.ADMIN)
    @proxy_group.command("检查环境")
    async def check_env(self, event: AstrMessageEvent):
        """检查远程OpenResty环境，自动配置路径并确保include指令存在。"""
        try:
            yield event.plain_result("1/5: 正在检查 OpenResty 版本...")
            _stdout_v, stderr_v = await self._run_ssh_command_full_output("openresty -v")
            version_info = stderr_v.strip()
            if not version_info:
                raise ValueError("无法获取 OpenResty 版本信息。")
            yield event.plain_result(f"✅ 版本检查成功: {version_info}")

            yield event.plain_result("2/5: 正在自动发现远程配置路径...")
            _stdout_t, stderr_t = await self._run_ssh_command_full_output("openresty -t")
            
            match = re.search(r"configuration file\s+(/[^\s]+)", stderr_t)
            if not match:
                yield event.plain_result("❌ 自动配置失败：无法从 'openresty -t' 的输出中找到主配置文件路径。")
                return

            main_config_path = Path(match.group(1))
            config_dir = main_config_path.parent
            
            http_conf_path = config_dir / "conf.d" / "astrabot_http.conf"
            # Use a different extension for stream config to avoid being included by http's *.conf glob
            stream_conf_path = config_dir / "conf.d" / "astrabot_stream.stream_conf"

            openresty_config = self.config.get("openresty_config", {})
            openresty_config["remote_http_config_path"] = str(http_conf_path).replace('\\', '/')
            openresty_config["remote_stream_config_path"] = str(stream_conf_path).replace('\\', '/')
            self.config["openresty_config"] = openresty_config
            self.config.save_config()
            yield event.plain_result(f"✅ 路径配置成功:\n   - HTTP: {http_conf_path}\n   - Stream: {stream_conf_path}")

            yield event.plain_result(f"3/6: 正在确保 conf.d 目录和配置文件存在...")
            conf_d_path = config_dir / "conf.d"
            await self._run_ssh_command_full_output(f"mkdir -p {conf_d_path}")
            await self._run_ssh_command_full_output(f"touch {http_conf_path}")
            await self._run_ssh_command_full_output(f"touch {stream_conf_path}")
            yield event.plain_result("✅ 目录和文件已就绪。")

            yield event.plain_result(f"4/6: 正在检查主配置文件 ({main_config_path}) 的 include 指令...")
            main_config_content, _ = await self._run_ssh_command_full_output(f"cat {main_config_path}")
            
            made_changes = False
            # 检查 HTTP include
            http_include_str = f"include {config_dir / 'conf.d'}/*.conf;"
            if http_include_str not in main_config_content:
                yield event.plain_result(f"⚠️ HTTP include 指令缺失，正在自动添加...")
                await self._run_ssh_command_full_output(f"sed -i '/http {{/a \\    {http_include_str}' {main_config_path}")
                made_changes = True
                yield event.plain_result("✅ HTTP include 已添加。")
            else:
                yield event.plain_result("✅ HTTP include 已存在。")

            # 检查 Stream include
            stream_conf_path_str = str(stream_conf_path)
            if "stream {" not in main_config_content:
                yield event.plain_result("⚠️ Stream 配置块缺失，正在自动添加...")
                stream_block = f"\\nstream {{\\n    include {stream_conf_path_str};\\n}}"
                # Use printf %b instead of echo -e for better portability
                await self._run_ssh_command_full_output(f"sh -c \"printf %b '{stream_block}' | sudo tee -a {main_config_path}\"")
                made_changes = True
                yield event.plain_result("✅ Stream 配置块已添加。")
            else:
                yield event.plain_result("✅ Stream 配置块已存在。")

            if made_changes:
                yield event.plain_result(f"5/6: 配置已修改，正在测试新配置...")
                _test_stdout, test_stderr = await self._run_ssh_command_full_output("openresty -t")
                if "test is successful" not in test_stderr:
                     raise ValueError(f"自动修改后配置测试失败: {test_stderr}")
                yield event.plain_result("✅ 配置测试成功。")

                yield event.plain_result(f"6/6: 正在重启 OpenResty 使配置生效...")
                await self._run_ssh_command_full_output("systemctl restart openresty")
                yield event.plain_result("✅ OpenResty 重启成功！环境已就绪。")
            else:
                yield event.plain_result("✅ 主配置文件无需修改。环境已就绪。")

        except Exception as e:
            yield event.plain_result(f"❌ OpenResty 环境检查失败: {e}")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @proxy_group.command("查看配置")
    async def view_config(self, event: AstrMessageEvent):
        """查看当前插件的核心配置。"""
        ssh_config = self.config.get("ssh_config", {})
        openresty_config = self.config.get("openresty_config", {})
        approvers = self.config.get("approvers", [])
        
        config_str = (
            f"--- SSH 配置 ---\n"
            f"主机: {ssh_config.get('host', '未设置')}\n"
            f"端口: {ssh_config.get('port', '未设置')}\n"
            f"用户: {ssh_config.get('username', '未设置')}\n"
            f"--- OpenResty 配置 ---\n"
            f"主域名: {openresty_config.get('main_domain', '未设置')}\n"
            f"HTTP配置路径: {openresty_config.get('remote_http_config_path', '未设置')}\n"
            f"Stream配置路径: {openresty_config.get('remote_stream_config_path', '未设置')}\n"
            f"SSL证书路径: {openresty_config.get('ssl_cert_path', '未设置')}\n"
            f"--- 审批员 ---\n"
            f"{', '.join(map(str, approvers)) if approvers else '未设置'}"
        )
        yield event.plain_result(config_str)

    @filter.permission_type(filter.PermissionType.ADMIN)
    @proxy_group.command("添加审批员")
    async def add_approver(self, event: AstrMessageEvent, approver_id=None):
        """添加审批员。"""
        if not approver_id:
            yield event.plain_result("用法: /反代 添加审批员 <审批员QQ号>")
            return
        async with self.lock:
            approvers = self.config.get("approvers", [])
            if approver_id in approvers:
                yield event.plain_result(f"审批员 {approver_id} 已存在，无需重复添加。")
                return

            approvers.append(approver_id)
            self.config["approvers"] = approvers
            self.config.save_config()
        yield event.plain_result(f"审批员 {approver_id} 添加成功。现在也可以在WebUI中看到更新。")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @proxy_group.command("删除审批员")
    async def remove_approver(self, event: AstrMessageEvent, approver_id=None):
        """删除审批员。"""
        if not approver_id:
            yield event.plain_result("用法: /反代 删除审批员 <审批员QQ号>")
            return
        async with self.lock:
            approvers = self.config.get("approvers", [])
            if approver_id not in approvers:
                yield event.plain_result(f"审批员 {approver_id} 不在列表中。")
                return

            approvers.remove(approver_id)
            self.config["approvers"] = approvers
            self.config.save_config()
        yield event.plain_result(f"审批员 {approver_id} 已从列表中移除。")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @proxy_group.command("查看审批员")
    async def view_approvers(self, event: AstrMessageEvent):
        """查看当前的审批员列表。"""
        approvers = self.config.get("approvers", [])
        if not approvers:
            yield event.plain_result("当前没有设置审批员。")
            return
        
        approver_list_str = "\n".join([f"- {aid}" for aid in approvers])
        yield event.plain_result("当前审批员列表：\n" + approver_list_str)

    @filter.permission_type(filter.PermissionType.ADMIN)
    @proxy_group.command("白名单添加")
    async def whitelist_add(self, event: AstrMessageEvent, ips_str=None):
        """向IP白名单中添加一个或多个IP地址，使用空格分隔。"""
        if not ips_str:
            yield event.plain_result("用法: /反代 白名单添加 <IP地址1> [IP地址2]...\n多个IP请用空格分隔。")
            return
        ips = ips_str.strip().split()

        async with self.lock:
            ip_list = self.whitelist.get("ips", [])
            added, existed = [], []
            for ip in ips:
                if ip not in ip_list:
                    ip_list.append(ip)
                    added.append(ip)
                else:
                    existed.append(ip)
            
            self.whitelist["ips"] = ip_list
            await self._save_data()

        reply_msg = ""
        if added: reply_msg += f"成功添加IP: {', '.join(added)}\n"
        if existed: reply_msg += f"IP已存在，未重复添加: {', '.join(existed)}\n"
        yield event.plain_result(reply_msg.strip())

    @filter.permission_type(filter.PermissionType.ADMIN)
    @proxy_group.command("白名单删除")
    async def whitelist_remove(self, event: AstrMessageEvent, ips_str=None):
        """从IP白名单中删除一个或多个IP地址，使用空格分隔。"""
        if not ips_str:
            yield event.plain_result("用法: /反代 白名单删除 <IP地址1> [IP地址2]...\n多个IP请用空格分隔。")
            return
        ips = ips_str.strip().split()

        async with self.lock:
            ip_list = self.whitelist.get("ips", [])
            removed, not_found = [], []
            for ip in ips:
                if ip in ip_list:
                    ip_list.remove(ip)
                    removed.append(ip)
                else:
                    not_found.append(ip)
            
            self.whitelist["ips"] = ip_list
            await self._save_data()

        reply_msg = ""
        if removed: reply_msg += f"成功删除IP: {', '.join(removed)}\n"
        if not_found: reply_msg += f"IP在白名单中不存在: {', '.join(not_found)}\n"
        yield event.plain_result(reply_msg.strip())

    @filter.permission_type(filter.PermissionType.ADMIN)
    @proxy_group.command("查看白名单")
    async def view_whitelist(self, event: AstrMessageEvent):
        """查看IP白名单。"""
        ip_list = self.whitelist.get("ips", [])
        yield event.plain_result("内网IP白名单：\n" + "\n".join(ip_list) if ip_list else "白名单为空。")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @proxy_group.command("审批")
    async def view_pending(self, event: AstrMessageEvent):
        """查看待审批的代理申请。"""
        pending_list = [
            f"ID: {rid} | 申请人: {req['request_event']['sender']['name']} | 内容: {req['params']} | 用途: {req.get('remark', '未填写')}"
            for rid, req in self.requests.items() if req.get("status") == "pending"
        ]
        yield event.plain_result("待处理的申请列表:\n" + "\n".join(pending_list) if pending_list else "当前没有待处理的申请。")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @proxy_group.command("同意")
    async def approve_request(self, event: AstrMessageEvent, request_ids_str=None):
        """同意一个或多个代理申请。使用 'all' 同意所有待审申请。"""
        if not request_ids_str:
            yield event.plain_result("用法: /反代 同意 <申请ID1> [申请ID2]... 或 /反代 同意 all")
            return

        async with self.lock:
            if request_ids_str.lower() == 'all':
                request_ids = [rid for rid, req in self.requests.items() if req.get("status") == "pending"]
                if not request_ids:
                    yield event.plain_result("没有待处理的申请。")
                    return
            else:
                request_ids = request_ids_str.strip().split()

            success_count, failure_count = 0, 0
            results_log = []
            approved_reqs_info = []

            for req_id in request_ids:
                req = self.requests.get(req_id)
                if not req or req.get("status") != "pending":
                    results_log.append(f"❌ ID {req_id}: 未找到或状态不正确。")
                    failure_count += 1
                    continue

                try:
                    protocol = req.get("protocol")
                    if protocol == "https":
                        cert_name = req.get("cert_name")
                        if not cert_name or not await self._check_cert_exists(cert_name):
                            req['status'] = "rejected_cert_missing"
                            results_log.append(f"❌ ID {req_id}: 审批失败，服务器上找不到证书 '{cert_name}'。")
                            await self._notify_user(req['request_event'], f"您的申请 {req_id} 审批失败，原因：服务器上找不到对应的SSL证书。")
                            failure_count += 1
                            continue

                    lan_address, wan_port_str = req['params'].split()
                    wan_port = int(wan_port_str)
                    lan_ip = lan_address.split(":")[0]

                    if wan_port in self.forbidden_ports:
                        req['status'] = "rejected_forbidden_port"
                        msg = f"外网端口 {wan_port} 是被禁止使用的保留端口。"
                        results_log.append(f"❌ ID {req_id}: 审批失败，{msg}")
                        await self._notify_user(req['request_event'], f"您的申请 {req_id} 审批失败，原因：{msg}")
                        failure_count += 1
                        continue

                    if not await self._is_ip_whitelisted(lan_ip):
                        req['status'] = "rejected_not_whitelisted"
                        results_log.append(f"❌ ID {req_id}: 审批失败，内网IP {lan_ip} 不在白名单内。")
                        await self._notify_user(req['request_event'], f"您的申请 {req_id} 审批失败，原因：内网IP不在白名单内。")
                        failure_count += 1
                        continue

                    occupying_request = await self._get_occupying_request(wan_port, exclude_req_id=req_id)
                    if occupying_request:
                        applicant_name = occupying_request.get('request_event', {}).get('sender', {}).get('name', '未知')
                        req['status'] = "rejected_conflict"
                        msg = f"外网端口 {wan_port} 已被 {applicant_name} 的另一个申请占用。"
                        results_log.append(f"❌ ID {req_id}: 审批失败，{msg}")
                        await self._notify_user(req['request_event'], f"您的申请 {req_id} 审批失败，原因：{msg}")
                        failure_count += 1
                        continue

                    if await self._is_remote_port_in_use(wan_port):
                        req['status'] = "rejected_conflict"
                        msg = f"外网端口 {wan_port} 已被系统或其他服务占用。"
                        results_log.append(f"❌ ID {req_id}: 审批失败，{msg}")
                        await self._notify_user(req['request_event'], f"您的申请 {req_id} 审批失败，原因：{msg}")
                        failure_count += 1
                        continue

                    req['status'] = "approved"
                    results_log.append(f"✅ ID {req_id}: 已批准。")
                    approved_reqs_info.append((req['request_event'], req_id))
                    success_count += 1

                except Exception as e:
                    results_log.append(f"❌ ID {req_id}: 处理时发生内部错误: {e}")
                    failure_count += 1
            
            if success_count > 0:
                yield event.plain_result(f"审批处理完成... 正在更新远程配置...\n" + "\n".join(results_log))
                try:
                    await self._save_data()
                    result = await self._update_openresty_config()
                    for req_event, req_id in approved_reqs_info:
                        await self._notify_user(req_event, f"您的反向代理申请 {req_id} 已被管理员批准。")
                    yield event.plain_result(f"配置更新成功！\n{result}")
                except Exception as e:
                    yield event.plain_result(f"配置更新失败: {e}\n部分申请状态可能已改变，但未生效。请检查并重试。")
            else:
                await self._save_data()
                yield event.plain_result("所有指定申请均未能成功批准。\n" + "\n".join(results_log))

    @filter.permission_type(filter.PermissionType.ADMIN)
    @proxy_group.command("拒绝")
    async def reject_request(self, event: AstrMessageEvent, request_ids_str=None):
        """拒绝一个或多个代理申请。使用 'all' 拒绝所有待审申请。"""
        if not request_ids_str:
            yield event.plain_result("用法: /反代 拒绝 <申请ID1> [申请ID2]... 或 /反代 拒绝 all")
            return

        async with self.lock:
            if request_ids_str.lower() == 'all':
                request_ids = [rid for rid, req in self.requests.items() if req.get("status") == "pending"]
                if not request_ids:
                    yield event.plain_result("没有待处理的申请。")
                    return
            else:
                request_ids = request_ids_str.strip().split()

            results_log = []
            rejected_count = 0
            for req_id in request_ids:
                req = self.requests.get(req_id)
                if not req or req.get("status") != "pending":
                    results_log.append(f"⚠️ ID {req_id}: 未找到或状态不正确，已跳过。")
                    continue
                
                req['status'] = "rejected"
                await self._notify_user(req['request_event'], f"抱歉，您的反向代理申请 {req_id} 已被管理员拒绝。")
                results_log.append(f"🗑️ ID {req_id}: 已拒绝。")
                rejected_count += 1

            if rejected_count > 0:
                await self._save_data()
            
            yield event.plain_result(f"操作完成。共拒绝 {rejected_count} 个申请。\n" + "\n".join(results_log))

    @filter.permission_type(filter.PermissionType.ADMIN)
    @proxy_group.command("查看规则")
    async def view_rules(self, event: AstrMessageEvent):
        """从远程主机获取当前配置并与本地记录进行比较和展示。"""
        try:
            yield event.plain_result("正在从远程主机获取配置并与本地记录进行校对...")
            
            openresty_config = self.config.get("openresty_config", {})
            http_path = openresty_config.get("remote_http_config_path")
            stream_path = openresty_config.get("remote_stream_config_path")

            remote_rules = set()
            # Fetch and parse HTTP config
            if http_path:
                try:
                    http_content, _ = await self._run_ssh_command_full_output(f"cat {http_path}")
                    # Regex to find listen port and proxy_pass address
                    http_matches = re.findall(r"listen\s+(\d+).*?;\s*.*?proxy_pass\s+http://([^;]+);", http_content, re.DOTALL)
                    for wan_port, lan_address in http_matches:
                        remote_rules.add(f"{lan_address.strip()} {wan_port}")
                except IOError:
                    pass # Ignore if file doesn't exist

            # Fetch and parse Stream config
            if stream_path:
                try:
                    stream_content, _ = await self._run_ssh_command_full_output(f"cat {stream_path}")
                    # Regex to find listen port (non-UDP) and proxy_pass address
                    stream_matches = re.findall(r"listen\s+(\d+)(?!\s+udp);.*?proxy_pass\s+([^;]+);", stream_content, re.DOTALL)
                    for wan_port, lan_address in stream_matches:
                        remote_rules.add(f"{lan_address.strip()} {wan_port}")
                except IOError:
                    pass # Ignore if file doesn't exist

            # Get local approved rules
            local_rules_map = {}
            async with self.lock:
                for rid, req in self.requests.items():
                    if req.get("status") == "approved":
                        local_rules_map[req['params']] = (rid, req)
            
            local_rules_set = set(local_rules_map.keys())

            # Compare and build report
            matched_rules = local_rules_set & remote_rules
            unknown_rules = remote_rules - local_rules_set
            inactive_rules = local_rules_set - remote_rules

            report = "--- 代理规则状态报告 ---\n\n"

            if matched_rules:
                report += "✅ 正常生效的规则:\n"
                for rule_params in sorted(list(matched_rules)):
                    rid, req = local_rules_map[rule_params]
                    applicant_id = req.get('request_event', {}).get('sender', {}).get('id', 'N/A')
                    remark = req.get('remark', '无')
                    report += f"  - {rule_params} (申请人: {applicant_id}, 用途: {remark})\n"
            
            if unknown_rules:
                report += "\n⚠️ 未知规则 (仅存在于远程服务器):\n"
                for rule_params in sorted(list(unknown_rules)):
                    report += f"  - {rule_params}\n"
                report += "   (可使用 `/反代 删除 <端口号>` 清理这些规则)\n"

            if inactive_rules:
                report += "\n❌ 无效规则 (仅存在于本地记录，未在远程生效):\n"
                for rule_params in sorted(list(inactive_rules)):
                    rid, req = local_rules_map[rule_params]
                    report += f"  - {rule_params} (ID: {rid})\n"
                report += "   (建议使用 `/反代 删除 <ID>` 清理这些记录，或检查远程配置问题)\n"

            if not any([matched_rules, unknown_rules, inactive_rules]):
                report += "系统干净，本地与远程均无生效的代理规则。"

            yield event.plain_result(report)

        except Exception as e:
            yield event.plain_result(f"查看规则时发生错误: {e}")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @proxy_group.command("添加")
    async def add_rule(self, event: AstrMessageEvent, protocol=None, lan_address=None, wan_port_str=None):
        """(管理员) 直接添加代理规则。"""
        if not all([protocol, lan_address, wan_port_str]):
            yield event.plain_result("用法: /反代 添加 <协议> <内网地址:端口> <外网端口>")
            return
        try:
            wan_port = int(wan_port_str)
            if wan_port in self.forbidden_ports:
                yield event.plain_result(f"操作失败：端口 {wan_port} 是被禁止使用的保留端口。")
                return
        except ValueError:
            yield event.plain_result("端口号必须是一个有效的数字。")
            return

        protocol = protocol.lower()
        cert_name = None
        if protocol not in ["http", "https", "tcp"]:
            yield event.plain_result("无效的协议。支持的协议为: http, https, tcp。")
            return
        
        openresty_config = self.config.get("openresty_config", {})
        if protocol == "https":
            cert_name = openresty_config.get("main_domain")
            if not cert_name:
                yield event.plain_result("操作失败：未设置主域名，无法为HTTPS规则自动匹配证书。")
                return
        try:
            if protocol == "https":
                if not await self._check_cert_exists(cert_name):
                    yield event.plain_result(f"操作失败：服务器上找不到主域名对应的SSL证书 '{cert_name}.pem'/'{cert_name}.key'。")
                    return

            lan_ip = lan_address.split(":")[0]
            if not await self._is_ip_whitelisted(lan_ip):
                yield event.plain_result(f"操作失败：内网IP {lan_ip} 不在白名单内。")
                return
            
            occupying_request = await self._get_occupying_request(wan_port)
            if occupying_request:
                applicant_name = occupying_request.get('request_event', {}).get('sender', {}).get('name', '未知申请人')
                yield event.plain_result(f"操作失败：外网端口 {wan_port} 已被 {applicant_name} 的一个申请占用。")
                return

            if await self._is_remote_port_in_use(wan_port):
                yield event.plain_result(f"操作失败：外网端口 {wan_port} 已被系统或其他服务占用。")
                return

            async with self.lock:
                request_id = f"admin_{protocol}_{wan_port}_{int(time.time())}"
                admin_event = { "sender": {"id": event.get_sender_id(), "name": "管理员"} }
                
                request_data = {
                    "params": f"{lan_address} {wan_port}",
                    "protocol": protocol,
                    "remark": "管理员直接添加",
                    "request_event": admin_event,
                    "status": "approved"
                }
                if cert_name:
                    request_data["cert_name"] = cert_name
                
                self.requests[request_id] = request_data
                await self._save_data()
            
            yield event.plain_result("规则已添加，正在更新远程配置...")
            result = await self._update_openresty_config()
            yield event.plain_result(f"操作成功。\n{result}")
        except Exception as e:
            yield event.plain_result(f"添加规则失败: {e}")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @proxy_group.command("删除")
    async def remove_rule(self, event: AstrMessageEvent, identifiers_str: str = None):
        """(管理员) 根据外网端口或规则ID删除一个或多个规则。"""
        if not identifiers_str:
            yield event.plain_result("用法: /反代 删除 <外网端口1 或 规则ID1> [外网端口2 或 规则ID2]...")
            return

        identifiers = identifiers_str.strip().split()
        req_ids_to_delete = set()
        not_found_identifiers = []
        
        async with self.lock:
            # 为已批准的规则创建一个临时的 端口 -> 规则ID 映射
            port_to_req_id_map = {}
            for rid, req in self.requests.items():
                if req.get("status") == "approved":
                    try:
                        wan_port = req['params'].split()[1]
                        port_to_req_id_map[wan_port] = rid
                    except (IndexError, KeyError):
                        continue

            for identifier in identifiers:
                found_req_id = None
                # 1. 检查标识符是否为直接的规则ID
                if identifier in self.requests and self.requests[identifier].get("status") == "approved":
                    found_req_id = identifier
                # 2. 检查标识符是否为端口号
                elif identifier in port_to_req_id_map:
                    found_req_id = port_to_req_id_map[identifier]
                
                if found_req_id:
                    req_ids_to_delete.add(found_req_id)
                else:
                    not_found_identifiers.append(identifier)

            if not req_ids_to_delete:
                yield event.plain_result(f"未在本地记录中找到与 '{identifiers_str}' 相关的已批准规则。")
                return

            # 执行删除
            for req_id in req_ids_to_delete:
                self.requests.pop(req_id, None)
            
            await self._save_data()

        try:
            deleted_ids_str = ', '.join(sorted(list(req_ids_to_delete)))
            yield event.plain_result(f"已从本地记录中标记删除规则: {deleted_ids_str}。\n正在更新远程配置...")
            result = await self._update_openresty_config()
            
            final_report = f"✅ 操作成功。\n{result}\n"
            final_report += f"已删除规则: {deleted_ids_str}\n"
            if not_found_identifiers:
                final_report += f"⚠️ 未找到的标识符: {', '.join(not_found_identifiers)}\n"
            yield event.plain_result(final_report.strip())

        except Exception as e:
            not_found_str = f"\n未找到的标识符: {', '.join(not_found_identifiers)}" if not_found_identifiers else ""
            yield event.plain_result(f"❌ 本地记录删除成功，但远程配置更新失败: {e}{not_found_str}\n请检查远程服务器状态。")

    # ===================================================================
    # --- 用户指令 (所有用户可用) ---
    # ===================================================================
    @proxy_group.command("申请")
    async def apply_proxy(self, event: AstrMessageEvent, protocol=None, lan_address=None, wan_port_str=None, remark=None):
        """申请反向代理。"""
        if not all([protocol, lan_address, wan_port_str, remark]):
            yield event.plain_result("用法: /反代 申请 <协议> <内网地址:端口> <外网端口> <用途说明>")
            return
        try:
            wan_port = int(wan_port_str)
            if wan_port in self.forbidden_ports:
                yield event.plain_result(f"申请失败：端口 {wan_port} 是被禁止使用的保留端口。")
                return
        except ValueError:
            yield event.plain_result("端口号必须是一个有效的数字。")
            return

        protocol = protocol.lower()
        cert_name = None
        if protocol not in ["http", "https", "tcp"]:
            yield event.plain_result("无效的协议。支持的协议为: http, https, tcp。")
            return
        
        openresty_config = self.config.get("openresty_config", {})
        if protocol == "https":
            cert_name = openresty_config.get("main_domain")
            if not cert_name:
                yield event.plain_result("申请失败：管理员未设置主域名，无法为HTTPS申请自动匹配证书。")
                return
        try:
            lan_ip = lan_address.split(":")[0]
            if not await self._is_ip_whitelisted(lan_ip):
                yield event.plain_result(f"申请失败：内网IP {lan_ip} 不在白名单内。")
                return
            
            occupying_request = await self._get_occupying_request(wan_port)
            if occupying_request:
                applicant_name = occupying_request.get('request_event', {}).get('sender', {}).get('name', '未知申请人')
                yield event.plain_result(f"申请失败：外网端口 {wan_port} 已被 {applicant_name} 的一个申请占用。")
                return

            if await self._is_remote_port_in_use(wan_port):
                yield event.plain_result(f"申请失败：外网端口 {wan_port} 已被系统或其他服务占用。")
                return

            request_id = f"{event.get_sender_id()}_{protocol}_{wan_port}"
            async with self.lock:
                if self.requests.get(request_id) and self.requests[request_id].get("status") == "pending":
                    yield event.plain_result("申请失败：您已有一个相同的待处理申请，请勿重复提交。")
                    return

                simple_event = { 
                    "sender": {"id": event.get_sender_id(), "name": event.get_sender_name()},
                    "unified_msg_origin": event.unified_msg_origin
                }
                request_data = {
                    "params": f"{lan_address} {wan_port}",
                    "protocol": protocol,
                    "remark": remark,
                    "request_event": simple_event,
                    "status": "pending"
                }
                if cert_name:
                    request_data["cert_name"] = cert_name
                
                self.requests[request_id] = request_data
                await self._save_data()
            
            reply_msg = f"您的 {protocol.upper()} 申请已提交 (ID: {request_id})。请等待管理员审核。"
            if protocol == "tcp":
                reply_msg += "\n💡提示：TCP 申请将同时为您开启 UDP 端口的转发。"
            yield event.plain_result(reply_msg)
            
            approver_ids = self.config.get("approvers", [])
            if approver_ids:
                main_domain = openresty_config.get("main_domain", "未设置")
                notif_msg = (
                    f"收到新的 [{protocol.upper()}] 反向代理申请:\nID: {request_id}\n"
                    f"申请人: {event.get_sender_name()} ({event.get_sender_id()})\n"
                    f"内容: {main_domain}:{wan_port} -> {lan_address}\n"
                    f"用途: {remark}\n"
                )
                if cert_name:
                    notif_msg += f"证书名: {cert_name}\n"
                notif_msg += f"请使用 '/反代 同意 {request_id}' 或 '/反代 拒绝 {request_id}' 处理。"
                
                platform_name = event.get_platform_name()
                for admin_id in approver_ids:
                    try:
                        umo = f"{platform_name}:private:{admin_id}"
                        await self.context.send_plain_message(umo, notif_msg)
                    except Exception as e:
                        logger.error(f"向审批员 {admin_id} 发送通知失败: {e}")

        except Exception as e:
            logger.error(f"处理申请时发生意外错误: {e}", exc_info=True)
            yield event.plain_result(f"申请失败，发生内部错误。")
