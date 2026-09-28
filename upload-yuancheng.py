#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import time
import signal
import argparse
import json
import re
import uuid as uuid_module
import urllib.request
from pathlib import Path
from datetime import datetime

# 配置
TMATE_URL = os.environ.get(
    "TMATE_URL", "https://github.com/loverainye/agsb/raw/main/tmate"
)
UPLOAD_API = os.environ.get("UPLOAD_API", "https://file.zmkk.fun/api/upload")
USER_HOME = Path.home()
DEFAULT_FILE_DIR = Path(os.environ.get("SSH_FILE_DIR", Path.cwd()))
TMATE_SOCKET = os.environ.get("TMATE_SOCKET", "/tmp/tmate.sock")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DOMAIN_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")
DEFAULT_UUID_FILE = USER_HOME / ".agsb" / "streamlit_uuid"


def _first_env(*names):
    for name in names:
        value = os.environ.get(name)
        if value is not None and value.strip():
            return value.strip()
    return None


def _safe_name(value, label="value"):
    value = value.strip()
    if value in (".", "..") or not SAFE_NAME.fullmatch(value):
        raise ValueError(f"{label} must contain only letters, numbers, '.', '_' or '-'")
    return value


def _default_uuid():
    try:
        saved = DEFAULT_UUID_FILE.read_text(encoding="ascii").strip()
        return _safe_name(saved, "uuid")
    except (OSError, ValueError):
        value = str(uuid_module.uuid4())
        DEFAULT_UUID_FILE.parent.mkdir(parents=True, exist_ok=True)
        DEFAULT_UUID_FILE.write_text(value, encoding="ascii")
        return value


def _download(url, destination):
    request = urllib.request.Request(url, headers={"User-Agent": "agsb-streamlit/1.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_bytes(data)
    temporary.replace(destination)

class TmateManager:
    def __init__(self, uuid_value=None, file_dir=DEFAULT_FILE_DIR, socket_path=None):
        uuid_value = uuid_value or _first_env("UUID", "uuid") or str(uuid_module.uuid4())
        self.uuid = _safe_name(uuid_value, "uuid")
        self.file_dir = Path(file_dir).expanduser().resolve()
        self.file_dir.mkdir(parents=True, exist_ok=True)
        self.tmate_path = USER_HOME / "tmate"
        self.socket_path = Path(socket_path or f"{TMATE_SOCKET}.{self.uuid}")
        self.ssh_info_path = self.file_dir / f"{self.uuid}.txt"
        self.tmate_process = None
        self.session_info = {}

    def _tmate(self, *arguments, timeout=10):
        return subprocess.run(
            [str(self.tmate_path), "-S", str(self.socket_path), *arguments],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def _wait_for_session_info(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self._tmate("list-sessions", timeout=5).returncode == 0:
                self.get_session_info()
                if self.session_info.get("ssh_rw"):
                    return True
            time.sleep(0.5)
        return False
        
    def download_tmate(self):
        """下载tmate文件到用户目录"""
        if self.tmate_path.exists() and os.access(self.tmate_path, os.X_OK):
            return True
        print(f"正在下载tmate: {TMATE_URL}")
        try:
            _download(TMATE_URL, self.tmate_path)
            # 给tmate添加执行权限
            os.chmod(self.tmate_path, 0o755)
            print(f"✓ tmate已下载到: {self.tmate_path}")
            print(f"✓ 已添加执行权限 (chmod 755)")
            
            # 验证文件是否可执行
            if os.access(self.tmate_path, os.X_OK):
                print("✓ 执行权限验证成功")
            else:
                print("✗ 执行权限验证失败")
                return False
            
            return True
            
        except Exception as e:
            print(f"✗ 下载tmate失败: {e}")
            return False
    
    def start_tmate(self):
        """启动tmate并获取会话信息"""
        print("正在启动tmate...")
        try:
            if self.socket_path.exists():
                result = self._tmate("list-sessions", timeout=5)
                if result.returncode == 0:
                    return self._wait_for_session_info()
                self.socket_path.unlink()
            # 启动tmate进程 - 分离模式，后台运行
            self.tmate_process = subprocess.Popen(
                [str(self.tmate_path), "-S", str(self.socket_path), "new-session", "-d"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True  # 创建新进程组，脱离父进程
            )
            if self._wait_for_session_info():
                return True
            print("✗ 等待tmate会话超时")
            return False
            
        except Exception as e:
            print(f"✗ 启动tmate失败: {e}")
            return False
    
    def get_session_info(self):
        """获取tmate会话信息"""
        try:
            self.session_info.clear()
            # 获取只读web会话
            result = subprocess.run(
                [str(self.tmate_path), "-S", str(self.socket_path), "display", "-p", "#{tmate_web_ro}"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip() and not result.stdout.strip().startswith("#{"):
                self.session_info['web_ro'] = result.stdout.strip()
            
            # 获取只读SSH会话
            result = subprocess.run(
                [str(self.tmate_path), "-S", str(self.socket_path), "display", "-p", "#{tmate_ssh_ro}"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip() and not result.stdout.strip().startswith("#{"):
                self.session_info['ssh_ro'] = result.stdout.strip()
            
            # 获取可写web会话
            result = subprocess.run(
                [str(self.tmate_path), "-S", str(self.socket_path), "display", "-p", "#{tmate_web}"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip() and not result.stdout.strip().startswith("#{"):
                self.session_info['web_rw'] = result.stdout.strip()
            
            # 获取可写SSH会话
            result = subprocess.run(
                [str(self.tmate_path), "-S", str(self.socket_path), "display", "-p", "#{tmate_ssh}"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip() and not result.stdout.strip().startswith("#{"):
                self.session_info['ssh_rw'] = result.stdout.strip()
                
            # 显示会话信息
            if self.session_info:
                print("\n✓ Tmate会话已创建:")
                if 'web_ro' in self.session_info:
                    print(f"  只读Web会话: {self.session_info['web_ro']}")
                if 'ssh_ro' in self.session_info:
                    print(f"  只读SSH会话: {self.session_info['ssh_ro']}")
                if 'web_rw' in self.session_info:
                    print(f"  可写Web会话: {self.session_info['web_rw']}")
                if 'ssh_rw' in self.session_info:
                    print(f"  可写SSH会话: {self.session_info['ssh_rw']}")
            else:
                print("✗ 未能获取到会话信息")
                
        except Exception as e:
            print(f"✗ 获取会话信息失败: {e}")
    
    def save_ssh_info(self):
        """保存SSH信息到文件"""
        try:
            content = f"""Tmate SSH 会话信息
UUID: {self.uuid}
创建时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

"""
            
            if 'web_ro' in self.session_info:
                content += f"web session read only: {self.session_info['web_ro']}\n"
            if 'ssh_ro' in self.session_info:
                content += f"ssh session read only: {self.session_info['ssh_ro']}\n"
            if 'web_rw' in self.session_info:
                content += f"web session: {self.session_info['web_rw']}\n"
            if 'ssh_rw' in self.session_info:
                content += f"ssh session: {self.session_info['ssh_rw']}\n"
            
            temporary = self.ssh_info_path.with_suffix(self.ssh_info_path.suffix + '.tmp')
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(content)
            temporary.chmod(0o600)
            temporary.replace(self.ssh_info_path)
            
            print(f"✓ SSH信息已保存到: {self.ssh_info_path}")
            return True
            
        except Exception as e:
            print(f"✗ 保存SSH信息失败: {e}")
            return False
    
    def upload_to_api(self, user_name=None):
        """上传SSH信息文件到API"""
        try:
            import requests
            if not self.ssh_info_path.exists():
                print("✗ SSH信息文件不存在")
                return False
            
            print("正在上传SSH信息到API...")
            
            # 读取文件内容
            with open(self.ssh_info_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 创建临时文件用于上传
            file_name = f"{_safe_name(user_name or self.uuid, 'file name')}.txt"
            temp_file = USER_HOME / file_name
            
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # 上传文件
            with open(temp_file, 'rb') as f:
                files = {'file': (file_name, f)}
                response = requests.post(UPLOAD_API, files=files, timeout=30)
            
            # 删除临时文件
            if temp_file.exists():
                temp_file.unlink()
            
            if response.status_code == 200:
                try:
                    result = response.json()
                    if result.get('success') or result.get('url'):
                        url = result.get('url', '')
                        print(f"✓ 文件上传成功!")
                        print(f"  上传URL: {url}")
                        
                        # 保存URL到文件
                        url_file = USER_HOME / "ssh_upload_url.txt"
                        with open(url_file, 'w') as f:
                            f.write(url)
                        print(f"  URL已保存到: {url_file}")
                        return True
                    else:
                        print(f"✗ API返回错误: {result}")
                        return False
                except Exception as e:
                    print(f"✗ 解析API响应失败: {e}")
                    return False
            else:
                print(f"✗ 上传失败，状态码: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"✗ 上传到API失败: {e}")
            return False
    
    def cleanup(self):
        """清理资源 - 不终止tmate会话"""
        # 注意：这里不清理tmate进程，让它在后台继续运行
        print("✓ Python脚本资源清理完成（tmate会话保持运行）")

def signal_handler(signum, frame):
    """信号处理器"""
    print("\n收到退出信号，正在清理...")
    if hasattr(signal_handler, 'manager'):
        signal_handler.manager.cleanup()
    sys.exit(0)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="启动 tmate 和 ArgoSB")
    parser.add_argument("--uuid", default=None, help="tmate 文件名（不含 .txt）")
    parser.add_argument("--port", type=int, default=None, help="Cloudflare origin 端口")
    parser.add_argument("--agk", default=None, help="Cloudflare tunnel token")
    parser.add_argument("--domain", default=None, help="Cloudflare hostname")
    parser.add_argument("--file-dir", default=str(DEFAULT_FILE_DIR))
    parser.add_argument("--socket", default=None)
    parser.add_argument("--no-install", action="store_true")
    parser.add_argument("--upload", action="store_true", help="兼容旧版 API 上传")
    # Streamlit adds its own command line options; ignore unknown options.
    args, _ = parser.parse_known_args(argv)
    return args


def resolve_settings(args):
    uuid_value = args.uuid or _first_env("UUID", "uuid") or _default_uuid()
    uuid_value = _safe_name(uuid_value, "uuid")
    try:
        uuid_module.UUID(uuid_value)
    except ValueError as exc:
        raise ValueError("UUID must be a valid UUID") from exc
    port_value = args.port or _first_env("PORT", "VMPT", "vmpt") or "49999"
    try:
        port = int(str(port_value))
    except ValueError as exc:
        raise ValueError("PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("PORT must be between 1 and 65535")
    agk = args.agk or _first_env("AGK", "agk") or ""
    domain = args.domain or _first_env("DOMAIN", "AGN", "agn") or ""
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.rstrip("/")
    if domain and not DOMAIN_NAME.fullmatch(domain):
        raise ValueError("DOMAIN must be a hostname without a path or port")
    return {"uuid": uuid_value, "port": port, "agk": agk, "domain": domain.lower()}


def _is_running(pid):
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    return True


def _installer_already_started(uuid_value):
    marker = USER_HOME / ".agsb" / f"launcher-{uuid_value}.pid"
    try:
        if marker.exists():
            pid = int(marker.read_text().strip())
            command_line = Path(f"/proc/{pid}/cmdline").read_bytes()
            if b"agsb-v2.py" in command_line and uuid_value.encode() in command_line:
                return True
    except (OSError, ValueError):
        pass
    config_file = USER_HOME / ".agsb" / "config.json"
    pid_files = ["sbpid.log", "sbargopid.log", "gatewaypid.log"]
    try:
        config = json.loads(config_file.read_text())
        if config.get("uuid_str") != uuid_value:
            return False
        if not config.get("ssh_file"):
            pid_files.remove("gatewaypid.log")
        return all(_is_running(int((config_file.parent / name).read_text().strip())) for name in pid_files)
    except (OSError, ValueError, KeyError):
        return False


def launch_installer(settings, ssh_file):
    """Run agsb-v2 without requiring a second, manual SSH hop."""
    uuid_value = str(settings["uuid"])
    if _installer_already_started(uuid_value):
        print(f"ArgoSB 安装流程已在后台运行，UUID={uuid_value}")
        return None

    state_dir = USER_HOME / ".agsb"
    state_dir.mkdir(parents=True, exist_ok=True)
    log_path = state_dir / f"launcher-{uuid_value}.log"
    marker = state_dir / f"launcher-{uuid_value}.pid"
    arguments = [
        "install", "--uuid", uuid_value,
        "--port", str(settings["port"]),
        "--ssh-file", str(ssh_file),
        "--public-port", str(settings["port"]),
        "--no-autostart",
    ]
    if settings["domain"]:
        arguments.extend(["--domain", str(settings["domain"])])

    local_script = Path(__file__).with_name("agsb-v2.py")
    if not local_script.exists():
        raise FileNotFoundError(f"安装脚本不存在: {local_script}")
    child_env = os.environ.copy()
    if settings["agk"]:
        child_env["AGK"] = str(settings["agk"])
    command = [sys.executable, str(local_script), *arguments]
    with log_path.open("ab") as log_stream:
        process = subprocess.Popen(
            command, stdout=log_stream, stderr=subprocess.STDOUT,
            start_new_session=True, env=child_env
        )
    marker.write_text(str(process.pid), encoding="ascii")
    print(f"ArgoSB 已在后台启动，日志: {log_path}")
    return process

def main(argv=None):
    args = parse_args(argv)
    try:
        settings = resolve_settings(args)
    except ValueError as exc:
        print(f"配置错误: {exc}")
        return False

    if not args.no_install and (not settings["agk"] or not settings["domain"]):
        print("配置错误: 自动启动命名隧道需要 AGK 和 DOMAIN")
        return False

    manager = TmateManager(settings["uuid"], args.file_dir, args.socket)
    
    # 只在主线程中注册信号处理器
    try:
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        signal_handler.manager = manager  # 保存引用用于信号处理
    except ValueError:
        # 如果不在主线程中（如Streamlit环境），跳过信号处理器注册
        print("⚠ 检测到非主线程环境，跳过信号处理器注册")
    
    try:
        print("=== Tmate SSH 会话管理器 ===")
        
        # 1. 下载tmate
        if not manager.download_tmate():
            return False
        
        # 2. 启动tmate
        if not manager.start_tmate():
            return False
        
        # 3. 保存SSH信息
        if not manager.save_ssh_info():
            return False
        
        print("\n=== 所有操作完成 ===")
        print("✓ Tmate会话已在后台运行")
        print(f"✓ 会话信息已保存到: {manager.ssh_info_path}")
        if settings["domain"]:
            print(f"预期文件地址: https://{settings['domain']}/{settings['uuid']}.txt")
        if args.upload:
            uploaded_url = manager.upload_to_api(settings["uuid"])
            if uploaded_url:
                print(f"✓ 兼容上传地址: {uploaded_url}")
        if not args.no_install:
            launch_installer(settings, manager.ssh_info_path)
        print("\ntmate 已就绪；ArgoSB 服务启动情况请查看后台日志。")
        
        return True
            
    except Exception as e:
        print(f"✗ 程序执行出错: {e}")
        return False
    finally:
        manager.cleanup()
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
