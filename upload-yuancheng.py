#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import signal
import argparse
import json
import re
import uuid as uuid_module
from pathlib import Path
from upterm_manager import UptermManager

# 配置
USER_HOME = Path.home()
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


def signal_handler(signum, frame):
    """信号处理器"""
    print("\n收到退出信号，正在清理...")
    if hasattr(signal_handler, 'manager'):
        signal_handler.manager.cleanup()
    sys.exit(0)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="启动 Upterm 和 ArgoSB")
    parser.add_argument("--uuid", default=None, help="sing-box 节点 UUID")
    parser.add_argument("--port", type=int, default=None, help="sing-box 本地端口")
    parser.add_argument("--agk", default=None, help="Cloudflare tunnel token")
    parser.add_argument("--domain", default=None, help="Cloudflare hostname")
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

    manager = UptermManager(home=USER_HOME)
    
    # 只在主线程中注册信号处理器
    try:
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        signal_handler.manager = manager  # 保存引用用于信号处理
    except ValueError:
        # 如果不在主线程中（如Streamlit环境），跳过信号处理器注册
        print("⚠ 检测到非主线程环境，跳过信号处理器注册", flush=True)
    
    try:
        print("=== Upterm SSH 会话管理器 ===", flush=True)

        # sing-box/Cloudflare and Upterm start independently.
        installer_process = None
        if not args.no_install:
            installer_process = launch_installer(settings)

        if not manager.prepare() or not manager.start():
            if installer_process is not None:
                status = installer_process.poll()
                print("ArgoSB 安装进程仍在运行" if status is None else f"ArgoSB 安装进程退出码: {status}", flush=True)
            return False
        
        print("\n=== 所有操作完成 ===")
        print("✓ Upterm 会话已在后台运行")
        print("Upterm 连接命令已在上方日志输出；ArgoSB 服务启动情况请查看后台日志。", flush=True)
        
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
