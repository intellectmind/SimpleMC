import asyncio
import websockets
import json
import sys
import os
from aiohttp import web
import yaml
import struct
import subprocess
import platform
import threading
import queue
import time
import hashlib
import secrets
import re
from pathlib import Path
from typing import Dict, Set, Optional
import ipaddress

class SecurityManager:
    """安全管理器"""
    
    def __init__(self, config):
        self.config = config
        self.login_attempts: Dict[str, Dict] = {}
        self.rate_limits: Dict[str, Dict] = {}
        self.allowed_origins = config.get('security', {}).get('allowed_origins', ["http://localhost:8081", "http://127.0.0.1:8081"])
        self.rate_limit_requests = config.get('security', {}).get('rate_limit_requests', 100)
        self.rate_limit_window = config.get('security', {}).get('rate_limit_window', 60)
        
        # IP白名单配置
        self.ip_whitelist_enabled = config.get('security', {}).get('ip_whitelist_enabled', True)
        self.allowed_ips = config.get('security', {}).get('allowed_ips', [])
        self.allowed_networks = config.get('security', {}).get('allowed_networks', [])
        
        print(f"[安全] IP白名单功能: {'已启用' if self.ip_whitelist_enabled else '已禁用'}")
        if self.ip_whitelist_enabled:
            print(f"[安全] IP白名单: {self.allowed_ips}")
            print(f"[安全] 网络白名单: {self.allowed_networks}")
    
    def is_ip_allowed(self, ip: str) -> bool:
        """检查IP是否允许访问"""
        try:
            # 如果IP白名单功能已禁用，允许所有IP
            if not self.ip_whitelist_enabled:
                return True
            
            # 允许本地访问
            if ip in ['127.0.0.1', 'localhost', '::1']:
                return True
            
            # 检查IP白名单
            if ip in self.allowed_ips:
                return True
            
            # 检查网络白名单
            ip_obj = ipaddress.ip_address(ip)
            for network_str in self.allowed_networks:
                try:
                    network = ipaddress.ip_network(network_str, strict=False)
                    if ip_obj in network:
                        return True
                except ValueError:
                    continue
            
            # 默认允许私有网络（即使白名单启用，也允许私有网络）
            if ip.startswith('192.168.') or ip.startswith('10.') or (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31):
                return True
                
            # 如果白名单为空，默认允许所有IP（生产环境应该更严格）
            if not self.allowed_ips and not self.allowed_networks:
                print(f"[安全] 警告: IP白名单已启用但未配置任何规则，允许所有IP访问")
                return True
                
            print(f"[安全] 拒绝访问: IP {ip} 不在白名单中")
            return False
        except Exception as e:
            print(f"[安全] IP检查错误 {ip}: {e}")
            return False
    
    def check_rate_limit(self, identifier: str) -> bool:
        """检查频率限制"""
        now = time.time()
        if identifier not in self.rate_limits:
            self.rate_limits[identifier] = {'count': 1, 'window_start': now}
            return True
        
        record = self.rate_limits[identifier]
        
        # 检查是否在新窗口
        if now - record['window_start'] > self.rate_limit_window:
            record['count'] = 1
            record['window_start'] = now
            return True
        
        # 检查是否超过限制
        if record['count'] >= self.rate_limit_requests:
            return False
        
        record['count'] += 1
        return True
    
    def check_login_attempt(self, username: str, ip: str) -> bool:
        """检查登录尝试"""
        key = f"{username}_{ip}"
        now = time.time()
        
        if key not in self.login_attempts:
            self.login_attempts[key] = {'attempts': 1, 'lock_until': 0}
            return True
        
        record = self.login_attempts[key]
        
        # 检查是否在锁定期内
        if now < record['lock_until']:
            return False
        
        # 重置计数如果超过锁定时间
        lockout_time = self.config['web'].get('login_lockout_time', 300)
        if record['lock_until'] > 0 and now - record['lock_until'] > lockout_time:
            record['attempts'] = 1
            record['lock_until'] = 0
            return True
        
        record['attempts'] += 1
        
        # 如果超过最大尝试次数，锁定账户
        max_attempts = self.config['web'].get('max_login_attempts', 5)
        if record['attempts'] >= max_attempts:
            record['lock_until'] = now + lockout_time
            return False
        
        return True
    
    def get_remaining_lock_time(self, username: str, ip: str) -> int:
        """获取剩余锁定时间"""
        key = f"{username}_{ip}"
        if key in self.login_attempts:
            record = self.login_attempts[key]
            remaining = record['lock_until'] - time.time()
            return max(0, int(remaining))
        return 0

class SecureSessionManager:
    """安全的会话管理器"""
    
    def __init__(self, config):
        self.config = config
        self.sessions: Dict[str, Dict] = {}
        self.session_timeout = config['web'].get('session_timeout', 3600)
    
    def create_session(self, username: str, ip: str) -> str:
        """创建新会话"""
        session_id = secrets.token_urlsafe(32)
        self.sessions[session_id] = {
            'username': username,
            'ip': ip,
            'created_at': time.time(),
            'last_activity': time.time()
        }
        return session_id
    
    def validate_session(self, session_id: str, ip: str) -> bool:
        """验证会话"""
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        
        # 检查IP是否匹配
        if session['ip'] != ip:
            print(f"[安全] 会话IP不匹配: {session['ip']} != {ip}")
            return False
        
        # 检查会话是否过期
        if time.time() - session['last_activity'] > self.session_timeout:
            del self.sessions[session_id]
            return False
        
        # 更新最后活动时间
        session['last_activity'] = time.time()
        return True
    
    def revoke_session(self, session_id: str):
        """撤销会话"""
        if session_id in self.sessions:
            del self.sessions[session_id]
    
    def cleanup_expired_sessions(self):
        """清理过期会话"""
        current_time = time.time()
        expired_sessions = [
            session_id for session_id, session in self.sessions.items()
            if current_time - session['last_activity'] > self.session_timeout
        ]
        for session_id in expired_sessions:
            del self.sessions[session_id]

class InputValidator:
    """输入验证器"""
    
    @staticmethod
    def validate_username(username: str) -> bool:
        """验证用户名"""
        if not username or len(username) > 50:
            return False
        # 只允许字母、数字、下划线和连字符
        return bool(re.match(r'^[a-zA-Z0-9_-]+$', username))
    
    @staticmethod
    def validate_password(password: str) -> bool:
        """验证密码"""
        if not password or len(password) < 8 or len(password) > 100:
            return False
        return True
    
    @staticmethod
    def validate_command(command: str) -> bool:
        """验证命令"""
        if not command or len(command) > 1000:
            return False
        
        # 禁止的危险命令
        dangerous_commands = [
            'sudo', 'rm -rf', 'del /f', 'format', 'mkfs', 'dd if=',
            'shutdown', 'reboot', 'init', 'chmod 777', 'passwd'
        ]
        
        command_lower = command.lower()
        for dangerous in dangerous_commands:
            if dangerous in command_lower:
                return False
        
        return True
    
    @staticmethod
    def validate_filename(filename: str) -> bool:
        """验证文件名"""
        if not filename:
            return False
        
        # 防止路径遍历攻击
        if '..' in filename or filename.startswith('/') or ':' in filename:
            return False
        
        # 只允许安全的字符
        return bool(re.match(r'^[a-zA-Z0-9_.-]+$', filename))
    
    @staticmethod
    def sanitize_html(text: str) -> str:
        """清理HTML内容"""
        if not text:
            return ""
        
        # 基本的HTML转义
        replacements = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '&': '&amp;',
            '/': '&#x2F;',
            '`': '&#x60;',
            '=': '&#x3D;'
        }
        
        for char, replacement in replacements.items():
            text = text.replace(char, replacement)
        
        return text

class MinecraftProxy:
    def __init__(self, config):
        self.mc_host = config['minecraft']['host']
        self.mc_port = config['minecraft']['port']
        self.mc_token = config['minecraft']['token']
        self.proxy_port = config['proxy']['port']
        self.web_port = config['web']['port']
        self.web_username = config['web']['username']
        self.web_password = config['web']['password']
        
        # 安全组件
        self.security_manager = SecurityManager(config)
        self.session_manager = SecureSessionManager(config)
        self.validator = InputValidator()
        
        # RCON 配置
        self.rcon_enabled = config['rcon'].get('enabled', False)
        self.rcon_host = config['rcon'].get('host', 'localhost')
        self.rcon_port = config['rcon'].get('port', 25575)
        self.rcon_password = config['rcon'].get('password', '')
        
        # 服务器启动配置
        self.startup_script = config['server'].get('startup_script', '')
        self.working_directory = config['server'].get('working_directory', '.')
        
        # 安全限制工作目录
        self.working_directory = self._secure_working_directory(self.working_directory)
        
        self.connections = {}
        self.server_process = None
        self.server_output_queue = queue.Queue()
        self.server_output_listeners = set()
        
        # 定期清理任务
        self.cleanup_task = None
        
    def _secure_working_directory(self, path: str) -> str:
        """安全地设置工作目录"""
        try:
            safe_path = os.path.abspath(path)
            # 防止目录遍历
            if '..' in safe_path:
                raise ValueError("工作目录包含非法路径")
            return safe_path
        except Exception as e:
            print(f"[安全] 工作目录设置失败，使用当前目录: {e}")
            return os.path.abspath('.')

    async def handle_client(self, websocket, path):
        """处理来自浏览器的连接"""
        client_ip = websocket.remote_address[0] if websocket.remote_address else 'unknown'
        
        # 检查IP是否允许
        if not self.security_manager.is_ip_allowed(client_ip):
            print(f"[安全] 拒绝连接来自: {client_ip}")
            await websocket.close(1008, "IP not allowed")
            return
            
        # 检查频率限制
        if not self.security_manager.check_rate_limit(f"ws_{client_ip}"):
            print(f"[安全] 频率限制: {client_ip}")
            await websocket.close(1008, "Rate limit exceeded")
            return
        
        client_id = id(websocket)
        print(f"[代理] 新客户端连接: {client_id} from {client_ip}")
        
        # 检查是否是服务器输出监听连接
        if path == "/server_output":
            await self.handle_server_output_listener(websocket, client_id)
            return
            
        try:
            # 连接到 Minecraft 服务器，带上认证头
            mc_uri = f"ws://{self.mc_host}:{self.mc_port}"
            mc_ws = await websockets.connect(
                mc_uri,
                extra_headers={"Authorization": f"Bearer {self.mc_token}"},
                max_size=10 * 1024 * 1024  # 10MB限制
            )
            
            print(f"[代理] 已连接到 Minecraft 服务器: {mc_uri}")
            self.connections[client_id] = mc_ws
            
            # 创建两个任务：转发客户端消息 和 转发服务器消息
            client_to_server = asyncio.create_task(
                self.forward_client_to_server(websocket, mc_ws, client_id)
            )
            server_to_client = asyncio.create_task(
                self.forward_server_to_client(mc_ws, websocket, client_id)
            )
            
            # 等待任一任务完成（连接断开）
            done, pending = await asyncio.wait(
                [client_to_server, server_to_client],
                return_when=asyncio.FIRST_COMPLETED
            )
            
            # 取消剩余任务
            for task in pending:
                task.cancel()
                
        except Exception as e:
            print(f"[代理] 错误: {e}")
            safe_error = self.validator.sanitize_html(str(e))
            await websocket.send(json.dumps({
                "error": "代理连接失败",
                "message": safe_error
            }))
        finally:
            if client_id in self.connections:
                await self.connections[client_id].close()
                del self.connections[client_id]
            print(f"[代理] 客户端断开: {client_id}")

    async def handle_server_output_listener(self, websocket, client_id):
        """处理服务器输出监听连接"""
        client_ip = websocket.remote_address[0] if websocket.remote_address else 'unknown'
        
        # 检查IP是否允许
        if not self.security_manager.is_ip_allowed(client_ip):
            print(f"[安全] 拒绝服务器输出连接来自: {client_ip}")
            await websocket.close(1008, "IP not allowed")
            return
            
        print(f"[服务器输出] 新监听器连接: {client_id}")
        self.server_output_listeners.add(websocket)
        
        try:
            # 发送最近的一些日志
            await websocket.send(json.dumps({
                "type": "server_output",
                "data": "[系统] 已连接到服务器输出流"
            }))
            
            # 保持连接直到断开
            await websocket.wait_closed()
        except Exception as e:
            print(f"[服务器输出] 监听器错误: {e}")
        finally:
            if websocket in self.server_output_listeners:
                self.server_output_listeners.remove(websocket)
            print(f"[服务器输出] 监听器断开: {client_id}")
    
    async def forward_client_to_server(self, client_ws, server_ws, client_id):
        """转发客户端消息到 Minecraft 服务器"""
        try:
            async for message in client_ws:
                # 验证消息大小
                if len(message) > 10 * 1024 * 1024:  # 10MB限制
                    print(f"[安全] 消息过大: {client_id}")
                    continue
                    
                print(f"[代理] 客户端 -> 服务器: {message[:100]}...")
                await server_ws.send(message)
        except websockets.exceptions.ConnectionClosed:
            print(f"[代理] 客户端连接关闭: {client_id}")
    
    async def forward_server_to_client(self, server_ws, client_ws, client_id):
        """转发 Minecraft 服务器消息到客户端"""
        try:
            async for message in server_ws:
                # 验证消息大小
                if len(message) > 10 * 1024 * 1024:  # 10MB限制
                    print(f"[安全] 服务器消息过大: {client_id}")
                    continue
                    
                print(f"[代理] 服务器 -> 客户端: {message[:100]}...")
                await client_ws.send(message)
        except websockets.exceptions.ConnectionClosed:
            print(f"[代理] 服务器连接关闭: {client_id}")
    
    async def broadcast_server_output(self, message):
        """向所有监听器广播服务器输出"""
        if not self.server_output_listeners:
            return
            
        disconnected = set()
        safe_message = self.validator.sanitize_html(message)
        
        for listener in self.server_output_listeners:
            try:
                await listener.send(json.dumps({
                    "type": "server_output",
                    "data": safe_message
                }))
            except Exception as e:
                print(f"[服务器输出] 广播失败: {e}")
                disconnected.add(listener)
        
        # 移除断开的连接
        for listener in disconnected:
            self.server_output_listeners.remove(listener)
    
    def read_server_output(self):
        """读取服务器输出（在单独的线程中运行）"""
        if not self.server_process:
            return
            
        try:
            # 读取标准输出
            for line in iter(self.server_process.stdout.readline, ''):
                if line:
                    line = line.strip()
                    if line:
                        print(f"[服务器输出] {line}")
                        # 将输出放入队列，由主循环处理
                        self.server_output_queue.put(line)
                        
            # 读取标准错误
            for line in iter(self.server_process.stderr.readline, ''):
                if line:
                    line = line.strip()
                    if line:
                        print(f"[服务器错误] {line}")
                        self.server_output_queue.put(f"[错误] {line}")
        except Exception as e:
            print(f"[服务器输出] 读取错误: {e}")
    
    async def process_server_output(self):
        """处理服务器输出队列（在主事件循环中运行）"""
        while True:
            try:
                # 非阻塞地从队列中获取输出
                try:
                    output = self.server_output_queue.get_nowait()
                    await self.broadcast_server_output(output)
                except queue.Empty:
                    pass
                
                # 短暂休眠以避免占用过多CPU
                await asyncio.sleep(0.1)
            except Exception as e:
                print(f"[服务器输出] 处理错误: {e}")
                await asyncio.sleep(1)
    
    async def execute_rcon_command(self, command):
        """执行 RCON 命令"""
        if not self.rcon_enabled:
            return {"success": False, "message": "RCON 未启用"}
        
        # 验证命令
        if not self.validator.validate_command(command):
            return {"success": False, "message": "命令包含不安全内容"}
        
        try:
            # 创建TCP连接
            reader, writer = await asyncio.open_connection(
                self.rcon_host, self.rcon_port
            )
            
            # 生成请求ID
            import random
            request_id = random.randint(1, 1000)
            
            # 发送认证包
            auth_packet = self._build_rcon_packet(
                request_id, 
                3,  # 认证类型
                self.rcon_password
            )
            writer.write(auth_packet)
            await writer.drain()
            
            # 读取认证响应
            auth_response = await self._read_rcon_packet(reader)
            if not auth_response or auth_response['id'] != request_id:
                writer.close()
                await writer.wait_closed()
                return {"success": False, "message": "RCON 认证失败"}
            
            # 发送命令包
            command_packet = self._build_rcon_packet(
                request_id,
                2,  # 命令类型
                command
            )
            writer.write(command_packet)
            await writer.drain()
            
            # 读取命令响应
            response = await self._read_rcon_packet(reader)
            
            # 发送结束包（有些服务器需要）
            end_packet = self._build_rcon_packet(
                request_id,
                2,  # 命令类型
                ""  # 空命令表示结束
            )
            writer.write(end_packet)
            await writer.drain()
            
            writer.close()
            await writer.wait_closed()
            
            if response and response['id'] == request_id:
                return {
                    "success": True, 
                    "response": response['body'] or "命令执行成功（无输出）"
                }
            else:
                return {"success": False, "message": "RCON 命令执行失败"}
            
        except ConnectionRefusedError:
            return {"success": False, "message": "无法连接到RCON服务器，请检查RCON是否启用"}
        except Exception as e:
            safe_error = self.validator.sanitize_html(str(e))
            return {"success": False, "message": f"RCON 命令执行失败: {safe_error}"}
    
    def _build_rcon_packet(self, request_id, packet_type, body):
        """构建RCON数据包"""
        # 编码body
        body_encoded = body.encode('utf-8') + b'\x00'
        # 构建数据包
        packet = (
            struct.pack('<ii', request_id, packet_type) +
            body_encoded +
            b'\x00'
        )
        # 添加长度前缀
        length = struct.pack('<i', len(packet))
        return length + packet
    
    async def _read_rcon_packet(self, reader):
        """读取RCON响应数据包"""
        try:
            # 读取长度
            length_data = await reader.read(4)
            if len(length_data) < 4:
                return None
            
            length = struct.unpack('<i', length_data)[0]
            
            # 读取数据包内容
            packet_data = await reader.read(length)
            if len(packet_data) < length:
                return None
            
            # 解析数据包
            request_id = struct.unpack('<i', packet_data[0:4])[0]
            packet_type = struct.unpack('<i', packet_data[4:8])[0]
            
            # 提取body（跳过两个null字节）
            body = packet_data[8:-2].decode('utf-8', errors='ignore')
            
            return {
                'id': request_id,
                'type': packet_type,
                'body': body
            }
        except Exception as e:
            print(f"读取RCON数据包错误: {e}")
            return None
    
    async def start_server(self):
        """启动 Minecraft 服务器"""
        if not self.startup_script:
            return {"success": False, "message": "未配置启动脚本"}
        
        # 验证启动脚本文件名
        if not self.validator.validate_filename(self.startup_script):
            return {"success": False, "message": "启动脚本文件名不安全"}
        
        if self.server_process and self.server_process.poll() is None:
            return {"success": False, "message": "服务器已在运行中"}
        
        try:
            script_path = os.path.join(self.working_directory, self.startup_script)
            
            if not os.path.exists(script_path):
                return {"success": False, "message": f"启动脚本不存在: {script_path}"}
            
            # 根据操作系统选择启动方式
            if platform.system() == "Windows":
                if script_path.endswith('.bat') or script_path.endswith('.cmd'):
                    self.server_process = subprocess.Popen(
                        [script_path],
                        cwd=self.working_directory,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        stdin=subprocess.PIPE,
                        creationflags=subprocess.CREATE_NEW_CONSOLE,
                        bufsize=1,
                        universal_newlines=True
                    )
                else:
                    self.server_process = subprocess.Popen(
                        [script_path],
                        cwd=self.working_directory,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        stdin=subprocess.PIPE,
                        bufsize=1,
                        universal_newlines=True
                    )
            else:  # Linux/Mac
                if script_path.endswith('.sh'):
                    self.server_process = subprocess.Popen(
                        ['bash', script_path],
                        cwd=self.working_directory,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        stdin=subprocess.PIPE,
                        bufsize=1,
                        universal_newlines=True
                    )
                else:
                    self.server_process = subprocess.Popen(
                        [script_path],
                        cwd=self.working_directory,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        stdin=subprocess.PIPE,
                        bufsize=1,
                        universal_newlines=True
                    )
            
            # 启动输出读取线程
            output_thread = threading.Thread(target=self.read_server_output, daemon=True)
            output_thread.start()
            
            await self.broadcast_server_output("[系统] 服务器启动中...")
            
            return {"success": True, "message": "服务器启动命令已执行"}
            
        except Exception as e:
            safe_error = self.validator.sanitize_html(str(e))
            return {"success": False, "message": f"启动服务器失败: {safe_error}"}
    
    async def stop_server(self):
        """停止 Minecraft 服务器"""
        if not self.server_process or self.server_process.poll() is not None:
            return {"success": False, "message": "服务器未在运行"}
        
        try:
            await self.broadcast_server_output("[系统] 正在停止服务器...")
            
            # 发送停止命令
            if platform.system() == "Windows":
                self.server_process.terminate()
            else:
                self.server_process.terminate()
            
            # 等待进程结束
            try:
                self.server_process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.server_process.kill()
                self.server_process.wait()
            
            self.server_process = None
            await self.broadcast_server_output("[系统] 服务器已停止")
            
            # 停止后立即更新服务器状态
            await asyncio.sleep(1)  # 等待一下确保进程完全停止
            return {"success": True, "message": "服务器已停止"}
            
        except Exception as e:
            safe_error = self.validator.sanitize_html(str(e))
            return {"success": False, "message": f"停止服务器失败: {safe_error}"}
    
    async def get_server_status(self):
        """获取服务器状态"""
        if not self.server_process:
            return {"running": False, "message": "服务器未运行"}
        
        if self.server_process.poll() is None:
            return {"running": True, "message": "服务器运行中"}
        else:
            return {"running": False, "message": "服务器已停止"}
    
    async def serve_web(self):
        """提供 Web 界面"""
        app = web.Application()
        
        async def get_client_ip(request):
            """获取客户端IP"""
            forwarded_for = request.headers.get('X-Forwarded-For')
            if forwarded_for:
                return forwarded_for.split(',')[0].strip()
            return request.remote
        
        # 安全中间件
        @web.middleware
        async def security_middleware(request, handler):
            # 添加安全头
            response = await handler(request)
            
            # 内容安全策略
            csp_policy = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "connect-src 'self' ws: wss:; "
                "img-src 'self' data:; "
                "font-src 'self'; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "frame-ancestors 'none'; "
            )
            
            response.headers.update({
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
                'Content-Security-Policy': csp_policy,
                'Referrer-Policy': 'strict-origin-when-cross-origin',
                'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
            })
            
            return response
        
        app.middlewares.append(security_middleware)
        
        # 登录验证
        async def handle_login(request):
            try:
                client_ip = await get_client_ip(request)
                
                # 检查IP是否允许
                if not self.security_manager.is_ip_allowed(client_ip):
                    return web.json_response({
                        'success': False, 
                        'message': '您的IP地址不允许访问'
                    }, status=403)
                
                # 检查频率限制
                if not self.security_manager.check_rate_limit(f"login_{client_ip}"):
                    return web.json_response({
                        'success': False, 
                        'message': '请求过于频繁，请稍后重试'
                    }, status=429)
                
                data = await request.json()
                username = data.get('username', '')
                password = data.get('password', '')
                
                # 验证输入
                if not self.validator.validate_username(username):
                    return web.json_response({
                        'success': False, 
                        'message': '用户名格式无效'
                    })
                
                # 检查登录尝试
                if not self.security_manager.check_login_attempt(username, client_ip):
                    lock_time = self.security_manager.get_remaining_lock_time(username, client_ip)
                    return web.json_response({
                        'success': False, 
                        'message': f'登录尝试次数过多，请 {lock_time} 秒后再试'
                    })
                
                # 验证凭据
                if username == self.web_username and password == self.web_password:
                    session_id = self.session_manager.create_session(username, client_ip)
                    return web.json_response({
                        'success': True, 
                        'session': session_id,
                        'message': '登录成功'
                    })
                else:
                    return web.json_response({
                        'success': False, 
                        'message': '用户名或密码错误'
                    })
            except Exception as e:
                safe_error = self.validator.sanitize_html(str(e))
                return web.json_response({
                    'success': False, 
                    'message': f'登录请求解析失败: {safe_error}'
                })
        
        # RCON 命令执行
        async def handle_rcon_command(request):
            try:
                client_ip = await get_client_ip(request)
                
                # 检查频率限制
                if not self.security_manager.check_rate_limit(f"rcon_{client_ip}"):
                    return web.json_response({
                        'success': False, 
                        'message': '请求过于频繁'
                    }, status=429)
                
                # 检查认证
                session_id = request.headers.get('X-Session-ID') or request.query.get('session')
                if not session_id:
                    return web.json_response({
                        'success': False, 
                        'message': '未提供会话ID'
                    }, status=401)
                
                if not self.session_manager.validate_session(session_id, client_ip):
                    return web.json_response({
                        'success': False, 
                        'message': '会话已过期或无效'
                    }, status=401)
                
                data = await request.json()
                command = data.get('command', '')
                
                if not command:
                    return web.json_response({
                        'success': False, 
                        'message': '命令不能为空'
                    })
                
                print(f"[RCON] 执行命令: {command}")
                result = await self.execute_rcon_command(command)
                print(f"[RCON] 命令结果: {result}")
                return web.json_response(result)
                
            except Exception as e:
                safe_error = self.validator.sanitize_html(str(e))
                return web.json_response({
                    'success': False, 
                    'message': f'RCON命令执行错误: {safe_error}'
                })
        
        # 启动服务器
        async def handle_start_server(request):
            try:
                client_ip = await get_client_ip(request)
                
                # 检查认证
                session_id = request.headers.get('X-Session-ID') or request.query.get('session')
                if not session_id:
                    return web.json_response({
                        'success': False, 
                        'message': '未提供会话ID'
                    }, status=401)
                
                if not self.session_manager.validate_session(session_id, client_ip):
                    return web.json_response({
                        'success': False, 
                        'message': '会话已过期或无效'
                    }, status=401)
                
                result = await self.start_server()
                return web.json_response(result)
                
            except Exception as e:
                safe_error = self.validator.sanitize_html(str(e))
                return web.json_response({
                    'success': False, 
                    'message': f'启动服务器失败: {safe_error}'
                })
        
        # 停止服务器
        async def handle_stop_server(request):
            try:
                client_ip = await get_client_ip(request)
                
                # 检查认证
                session_id = request.headers.get('X-Session-ID') or request.query.get('session')
                if not session_id:
                    return web.json_response({
                        'success': False, 
                        'message': '未提供会话ID'
                    }, status=401)
                
                if not self.session_manager.validate_session(session_id, client_ip):
                    return web.json_response({
                        'success': False, 
                        'message': '会话已过期或无效'
                    }, status=401)
                
                result = await self.stop_server()
                return web.json_response(result)
                
            except Exception as e:
                safe_error = self.validator.sanitize_html(str(e))
                return web.json_response({
                    'success': False, 
                    'message': f'停止服务器失败: {safe_error}'
                })
        
        # 获取服务器状态
        async def handle_server_status(request):
            try:
                client_ip = await get_client_ip(request)
                
                # 检查认证
                session_id = request.headers.get('X-Session-ID') or request.query.get('session')
                if not session_id:
                    return web.json_response({
                        'success': False, 
                        'message': '未提供会话ID'
                    }, status=401)
                
                if not self.session_manager.validate_session(session_id, client_ip):
                    return web.json_response({
                        'success': False, 
                        'message': '会话已过期或无效'
                    }, status=401)
                
                result = await self.get_server_status()
                return web.json_response(result)
                
            except Exception as e:
                safe_error = self.validator.sanitize_html(str(e))
                return web.json_response({
                    'success': False, 
                    'message': f'获取服务器状态失败: {safe_error}'
                })
        
        # 提供 HTML 管理界面
        async def handle_index(request):
            # 对于根路径，直接返回HTML，不检查认证
            html_file = "minecraft_management.html"
            if os.path.exists(html_file):
                with open(html_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                return web.Response(text=content, content_type='text/html')
            else:
                return web.Response(
                    text="<h1>错误：找不到管理界面文件</h1>",
                    content_type='text/html'
                )
        
        # 检查认证的API接口
        async def handle_api_check(request):
            client_ip = await get_client_ip(request)
            session_id = request.headers.get('X-Session-ID') or request.query.get('session')
            if not session_id or not self.session_manager.validate_session(session_id, client_ip):
                return web.json_response({
                    'success': False, 
                    'message': '未授权访问'
                }, status=401)
            return web.json_response({'success': True, 'message': '认证有效'})
        
        # 登出接口
        async def handle_logout(request):
            client_ip = await get_client_ip(request)
            session_id = request.headers.get('X-Session-ID') or request.query.get('session')
            if session_id:
                self.session_manager.revoke_session(session_id)
            return web.json_response({'success': True, 'message': '已登出'})
        
        # 添加 CORS 支持
        async def add_cors_headers(request, response):
            origin = request.headers.get('Origin', '')
            if origin in self.security_manager.allowed_origins:
                response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PUT, DELETE'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Session-ID'
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        # 处理 OPTIONS 请求
        async def handle_options(request):
            origin = request.headers.get('Origin', '')
            allowed_origin = origin if origin in self.security_manager.allowed_origins else 'null'
            
            return web.Response(
                headers={
                    'Access-Control-Allow-Origin': allowed_origin,
                    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, PUT, DELETE',
                    'Access-Control-Allow-Headers': 'Content-Type, X-Session-ID',
                    'Access-Control-Allow-Credentials': 'true',
                    'Access-Control-Max-Age': '86400'
                }
            )
        
        # 注册路由
        app.router.add_post('/api/login', handle_login)
        app.router.add_post('/api/rcon', handle_rcon_command)
        app.router.add_post('/api/server/start', handle_start_server)
        app.router.add_post('/api/server/stop', handle_stop_server)
        app.router.add_get('/api/server/status', handle_server_status)
        app.router.add_get('/api/check', handle_api_check)
        app.router.add_post('/api/logout', handle_logout)
        app.router.add_get('/', handle_index)
        app.router.add_options('/api/{tail:.*}', handle_options)
        
        # 添加CORS中间件
        app.on_response_prepare.append(add_cors_headers)
        
        # 启动Web服务器
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', self.web_port)
        await site.start()
        print(f"[Web] 管理界面已启动: http://0.0.0.0:{self.web_port}")
    
    async def start_cleanup_task(self):
        """启动清理任务"""
        async def cleanup_loop():
            while True:
                try:
                    # 清理过期会话
                    self.session_manager.cleanup_expired_sessions()
                    
                    # 清理旧的频率限制记录
                    current_time = time.time()
                    expired_rate_limits = [
                        identifier for identifier, record in self.security_manager.rate_limits.items()
                        if current_time - record['window_start'] > self.security_manager.rate_limit_window * 2
                    ]
                    for identifier in expired_rate_limits:
                        del self.security_manager.rate_limits[identifier]
                    
                    # 清理旧的登录尝试记录
                    expired_login_attempts = [
                        key for key, record in self.security_manager.login_attempts.items()
                        if record['lock_until'] > 0 and current_time - record['lock_until'] > 3600
                    ]
                    for key in expired_login_attempts:
                        del self.security_manager.login_attempts[key]
                    
                    await asyncio.sleep(300)  # 5分钟清理一次
                except Exception as e:
                    print(f"[清理] 错误: {e}")
                    await asyncio.sleep(60)
        
        self.cleanup_task = asyncio.create_task(cleanup_loop())
    
    async def start(self):
        """启动代理服务器"""
        print(f"[代理] 启动 Minecraft 代理服务器...")
        print(f"[代理] ws端口: {self.proxy_port}")
        print(f"[代理] management-server: {self.mc_host}:{self.mc_port}")
        print(f"[代理] Web 管理端口: {self.web_port}")
        
        # 启动Web服务器
        await self.serve_web()
        
        # 启动清理任务
        await self.start_cleanup_task()
        
        # 启动服务器输出处理
        asyncio.create_task(self.process_server_output())
        
        # 启动WebSocket代理服务器
        ws_server = await websockets.serve(
            self.handle_client,
            "0.0.0.0",
            self.proxy_port,
            max_size=10 * 1024 * 1024  # 10MB限制
        )
        
        print(f"[代理] 服务器已启动，等待连接...")
        
        try:
            await ws_server.wait_closed()
        except KeyboardInterrupt:
            print(f"[代理] 收到中断信号，正在关闭...")
        finally:
            # 关闭所有连接
            for client_id, mc_ws in self.connections.items():
                await mc_ws.close()
            self.connections.clear()
            
            # 停止清理任务
            if self.cleanup_task:
                self.cleanup_task.cancel()
            
            # 停止服务器进程
            if self.server_process and self.server_process.poll() is None:
                await self.stop_server()

def load_config():
    """加载配置文件"""
    try:
        with open('config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        # 设置默认值
        config.setdefault('proxy', {}).setdefault('port', 8765)
        config.setdefault('web', {}).setdefault('port', 8081)
        config.setdefault('web', {}).setdefault('username', 'admin')
        config.setdefault('web', {}).setdefault('password', 'Admin123!')
        config.setdefault('web', {}).setdefault('session_timeout', 3600)
        config.setdefault('web', {}).setdefault('max_login_attempts', 5)
        config.setdefault('web', {}).setdefault('login_lockout_time', 300)
        
        config.setdefault('security', {}).setdefault('ip_whitelist_enabled', False)
        config.setdefault('security', {}).setdefault('allowed_origins', ["http://localhost:8081", "http://127.0.0.1:8081"])
        config.setdefault('security', {}).setdefault('rate_limit_requests', 100)
        config.setdefault('security', {}).setdefault('rate_limit_window', 60)
        config.setdefault('security', {}).setdefault('allowed_ips', [])
        config.setdefault('security', {}).setdefault('allowed_networks', [])
        
        config.setdefault('rcon', {}).setdefault('enabled', False)
        config.setdefault('rcon', {}).setdefault('host', 'localhost')
        config.setdefault('rcon', {}).setdefault('port', 25575)
        config.setdefault('rcon', {}).setdefault('password', '')
        
        config.setdefault('server', {}).setdefault('startup_script', '')
        config.setdefault('server', {}).setdefault('working_directory', '.')
        
        return config
    except Exception as e:
        print(f"[配置] 加载配置文件失败: {e}")
        sys.exit(1)

async def main():
    """主函数"""
    config = load_config()
    
    proxy = MinecraftProxy(config)
    
    try:
        await proxy.start()
    except KeyboardInterrupt:
        print(f"[主程序] 程序已停止")
    except Exception as e:
        print(f"[主程序] 错误: {e}")

if __name__ == "__main__":
    asyncio.run(main())