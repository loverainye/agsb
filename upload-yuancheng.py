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
import socket
import uuid as uuid_module
import urllib.request
from pathlib import Path

# 配置
TMATE_URL = os.environ.get(
    "TMATE_URL", "https://github.com/loverainye/agsb/raw/main/tmate"
)
USER_HOME = Path.home()
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
    def __init__(self, socket_path=None):
        self.tmate_path = USER_HOME / "tmate"
        self.socket_path = Path(socket_path or TMATE_SOCKET)
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

    def _wait_for_session_info(self, timeout=45):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                local_session = self._tmate("list-sessions", timeout=5)
                if local_session.returncode == 0 and self.get_session_info():
                    return True
            except (OSError, subprocess.TimeoutExpired):
                pass
            time.sleep(1)
        return False

    def failure_reason(self):
        """Return a fixed status category without exposing tmate session output."""
        ssh_dir = USER_HOME / ".ssh"
        missing_identity = not os.environ.get("SSH_AUTH_SOCK") and not any(
            (ssh_dir / name).is_file() for name in ("id_ed25519", "id_rsa")
        )
        try:
            local_session = self._tmate("list-sessions", timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            local_session = None
        if local_session is None or local_session.returncode != 0:
            if missing_identity:
                return "未检测到本地 SSH 身份密钥（id_ed25519 或 id_rsa）"
            if self.tmate_process is not None:
                exit_code = self.tmate_process.poll()
                if exit_code is not None:
                    return f"tmate 启动命令退出，退出码 {exit_code}；本地会话未建立"
            return "tmate 本地会话未建立"
        try:
            result = self._tmate("show-messages", timeout=5)
            messages = result.stdout.lower() if result.returncode == 0 else ""
        except (OSError, subprocess.TimeoutExpired):
            messages = ""
        if "ssh keys not found" in messages:
            return "tmate 未找到 SSH 身份密钥"
        if "protocol mismatch" in messages or "protocol version mismatch" in messages:
            return "tmate 与服务器协议不兼容，请检查二进制版本"
        if "cannot authenticate server" in messages:
            return "tmate 无法验证服务器身份，请检查服务器指纹配置"
        if any(value in messages for value in ("public key authentication error", "access denied", "authentication failed")):
            return "tmate 服务器拒绝 SSH 身份密钥"
        if "lookup failure" in messages or "failed to resolve hostname" in messages:
            return "tmate 服务器 DNS 解析失败"
        if any(value in messages for value in ("timeout connecting", "error connecting", "connection refused")):
            return "无法连接 tmate 服务器，请检查出站 TCP 网络连接"
        if missing_identity:
            return "未检测到本地 SSH 身份密钥（id_ed25519 或 id_rsa）"
        return self._probe_default_server()

    @staticmethod
    def _probe_default_server():
        """Check only the default tmate TCP endpoint; never log remote session data."""
        try:
            with socket.create_connection(("ssh.tmate.io", 22), timeout=4):
                return "默认服务器 ssh.tmate.io:22 的 TCP 连接可达，但 tmate 远端会话未就绪"
        except socket.gaierror:
            return "容器无法解析默认 tmate 服务器 ssh.tmate.io"
        except TimeoutError:
            return "容器连接默认 tmate 服务器 ssh.tmate.io:22 超时，出站 TCP 22 可能受限"
        except ConnectionRefusedError:
            return "默认 tmate 服务器 ssh.tmate.io:22 拒绝连接"
        except OSError:
            return "容器无法连接默认 tmate 服务器 ssh.tmate.io:22"
        
    def download_tmate(self):
        """下载tmate文件到用户目录"""
        if self.tmate_path.exists() and os.access(self.tmate_path, os.X_OK):
            print(f"tmate 已存在，跳过下载: {self.tmate_path}", flush=True)
            return True
        print(f"正在下载tmate: {TMATE_URL}", flush=True)
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
            print(f"✗ 下载tmate失败: {e}", flush=True)
            return False

    def ensure_ssh_identity(self):
        ssh_dir = USER_HOME / ".ssh"
        if any((ssh_dir / name).is_file() for name in ("id_ed25519", "id_rsa")):
            print("✓ 已检测到 SSH 身份密钥", flush=True)
            return True

        key_path = ssh_dir / "id_ed25519"
        try:
            ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            ssh_dir.chmod(0o700)
            print("未检测到 SSH 身份密钥，正在生成 Ed25519 密钥...", flush=True)
            result = subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_path)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
            if result.returncode != 0 or not key_path.is_file():
                print(f"✗ 生成 SSH 身份密钥失败，ssh-keygen 退出码: {result.returncode}", flush=True)
                return False
            key_path.chmod(0o600)
            print("✓ SSH 身份密钥已就绪", flush=True)
            return True
        except FileNotFoundError:
            print("✗ 系统缺少 ssh-keygen，请安装 openssh-client", flush=True)
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"✗ 生成 SSH 身份密钥失败: {type(exc).__name__}", flush=True)
        return False
    
    def start_tmate(self):
        """启动tmate并获取会话信息"""
        print("正在启动tmate...", flush=True)
        if not self.ensure_ssh_identity():
            return False
        try:
            if self.socket_path.exists():
                result = self._tmate("list-sessions", timeout=5)
                if result.returncode == 0:
                    if self._wait_for_session_info():
                        return True
                    print(f"✗ tmate 会话未就绪：{self.failure_reason()}", flush=True)
                    return False
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
            print(f"✗ tmate 会话未就绪：{self.failure_reason()}", flush=True)
            return False
            
        except Exception as e:
            print(f"✗ 启动tmate失败: {e}", flush=True)
            return False
    
    def get_session_info(self):
        """获取tmate会话信息"""
        self.session_info.clear()
        try:
            result = self._tmate("display", "-p", "#{tmate_ssh}", timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            return False
        address = result.stdout.strip()
        if result.returncode != 0 or not address or address.startswith("#{"):
            return False
        self.session_info["ssh_rw"] = address
        return True
    
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
    parser.add_argument("--uuid", default=None, help="sing-box 节点 UUID")
    parser.add_argument("--port", type=int, default=None, help="sing-box 本地端口")
    parser.add_argument("--agk", default=None, help="Cloudflare tunnel token")
    parser.add_argument("--domain", default=None, help="Cloudflare hostname")
    parser.add_argument("--socket", default=None)
    parser.add_argument("--no-install", action="store_true")
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


def _installer_already_started(settings):
    uuid_value = str(settings["uuid"])
    port = str(settings["port"])
    marker = USER_HOME / ".agsb" / f"launcher-{uuid_value}.pid"
    try:
        if marker.exists():
            pid = int(marker.read_text().strip())
            arguments = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            if (any(b"agsb-v2.py" in item for item in arguments)
                    and uuid_value.encode() in arguments
                    and b"--ssh-file" not in arguments
                    and b"--port" in arguments
                    and arguments[arguments.index(b"--port") + 1] == port.encode()):
                return True
    except (OSError, ValueError, IndexError):
        pass
    config_file = USER_HOME / ".agsb" / "config.json"
    try:
        config = json.loads(config_file.read_text())
        if (config.get("uuid_str") != uuid_value
                or config.get("ssh_file")
                or int(config.get("port_vm_ws", 0)) != int(port)
                or config.get("custom_domain_agn") != settings["domain"]):
            return False
        return all(
            _is_running(int((config_file.parent / name).read_text().strip()))
            for name in ("sbpid.log", "sbargopid.log")
        )
    except (OSError, ValueError, KeyError):
        return False


def launch_installer(settings):
    """Run agsb-v2 without requiring a second, manual SSH hop."""
    uuid_value = str(settings["uuid"])
    if _installer_already_started(settings):
        print(f"ArgoSB 安装流程已在后台运行，UUID={uuid_value}")
        return None

    state_dir = USER_HOME / ".agsb"
    state_dir.mkdir(parents=True, exist_ok=True)
    log_path = state_dir / f"launcher-{uuid_value}.log"
    marker = state_dir / f"launcher-{uuid_value}.pid"
    arguments = [
        "install", "--uuid", uuid_value,
        "--port", str(settings["port"]),
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
    print(f"ArgoSB 已在后台启动，日志: {log_path}", flush=True)
    return process

def main(argv=None):
    print("Streamlit 启动脚本已执行", flush=True)
    args = parse_args(argv)
    try:
        settings = resolve_settings(args)
    except ValueError as exc:
        print(f"配置错误: {exc}", flush=True)
        return False

    if not args.no_install and (not settings["agk"] or not settings["domain"]):
        print("配置错误: 自动启动命名隧道需要 AGK 和 DOMAIN", flush=True)
        return False

    manager = TmateManager(socket_path=args.socket)
    
    # 只在主线程中注册信号处理器
    try:
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        signal_handler.manager = manager  # 保存引用用于信号处理
    except ValueError:
        # 如果不在主线程中（如Streamlit环境），跳过信号处理器注册
        print("⚠ 检测到非主线程环境，跳过信号处理器注册", flush=True)
    
    try:
        print("=== Tmate SSH 会话管理器 ===", flush=True)
        
        # 1. 下载tmate
        if not manager.download_tmate():
            return False
        
        # sing-box/Cloudflare 与 tmate 的连接等待独立运行。
        installer_process = None
        if not args.no_install:
            installer_process = launch_installer(settings)

        # 2. 启动tmate
        if not manager.start_tmate():
            if installer_process is not None:
                status = installer_process.poll()
                print("ArgoSB 安装进程仍在运行" if status is None else f"ArgoSB 安装进程退出码: {status}", flush=True)
            return False
        
        print("\n=== 所有操作完成 ===")
        print("✓ Tmate会话已在后台运行")
        print(f"tmate SSH 连接: {manager.session_info['ssh_rw']}", flush=True)
        print("\ntmate 已就绪；ArgoSB 服务启动情况请查看后台日志。")
        
        return True
            
    except Exception as e:
        print(f"✗ 程序执行出错: {e}", flush=True)
        return False
    finally:
        manager.cleanup()
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
