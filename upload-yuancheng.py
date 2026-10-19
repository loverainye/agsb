#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import argparse
import json
import re
import uuid as uuid_module
from pathlib import Path
from tailscale_support import cloudflare_settings, redact, settings_from_env, start_log_relay
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


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="启动 Upterm、ArgoSB、Cloudflare Tunnel 和 Tailscale")
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
    if pid <= 0 or not Path(f"/proc/{pid}/exe").exists():
        return False
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    return True


def _installer_already_started(settings):
    uuid_value = str(settings["uuid"])
    port = str(settings["port"])
    marker = USER_HOME / ".agsb" / f"launcher-{uuid_value}.pid"
    tailscale = settings_from_env(uuid_value)
    cloudflare = cloudflare_settings(settings["agk"])
    signature_file = marker.with_suffix(".runtime.json")
    signature = {"tailscale": tailscale, "cloudflare": cloudflare, "domain": settings["domain"]}
    try:
        if marker.exists():
            pid = int(marker.read_text().strip())
            arguments = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            if (any(b"agsb-v2.py" in item for item in arguments)
                    and uuid_value.encode() in arguments
                    and b"--ssh-file" not in arguments
                    and b"--embedded-cloudflare" in arguments
                    and b"--port" in arguments
                    and arguments[arguments.index(b"--port") + 1] == port.encode()
                    and json.loads(signature_file.read_text()) == signature):
                return True
    except (OSError, ValueError, IndexError):
        pass
    config_file = USER_HOME / ".agsb" / "config.json"
    try:
        config = json.loads(config_file.read_text())
        if (config.get("uuid_str") != uuid_value
                or config.get("ssh_file")
                or int(config.get("port_vm_ws", 0)) != int(port)
                or config.get("custom_domain_agn") != settings["domain"]
                or config.get("cloudflare") != cloudflare
                or config.get("tailscale") != tailscale):
            return False
        if tailscale:
            ready = json.loads((config_file.parent / "tailscale-ready.json").read_text())
            if (ready.get("settings") != tailscale
                    or ready.get("port") != int(config.get("singbox_port", port))):
                return False
        return all(
            _is_running(int((config_file.parent / name).read_text().strip()))
            for name in (("sbpid.log", "tailscale-launcher.pid", "tailscaled.pid") if tailscale else ("sbpid.log",))
        )
    except (OSError, ValueError, KeyError):
        return False


def launch_installer(settings):
    """Run agsb-v2 without requiring a second, manual SSH hop."""
    uuid_value = str(settings["uuid"])
    state_dir = USER_HOME / ".agsb"
    log_path = state_dir / f"launcher-{uuid_value}.log"
    tailscale = settings_from_env(uuid_value)
    cloudflare = cloudflare_settings(settings["agk"])
    start_log_relay(state_dir, log_path, secrets=(settings["agk"],))
    print(f"Cloudflare: enabled in sing-box; DOMAIN={settings['domain']}, origin=http://localhost:{settings['port']}; diagnostics will appear in app logs", flush=True)
    if tailscale:
        print(f"Tailscale: official userspace daemon enabled; hostname={tailscale['hostname']}, ephemeral={tailscale['ephemeral']}; diagnostics will appear in app logs", flush=True)
        print("Tailscale: --advertise-connector enabled; configure the connector tag and Apps/domains in the admin console", flush=True)
        print("Tailscale: exit-node advertisement enabled; approve it in the admin console and select it on the client to use Internet egress", flush=True)
        print(f"Tailscale VMess: server=<node Tailscale IP> or {tailscale['hostname']}; port={settings['port']}; transport=ws; path=/{uuid_value[:8]}-vm; TLS=off", flush=True)
        print(f"Tailscale: the proxy client must join the tailnet and ACL/grants must allow TCP {settings['port']}", flush=True)
    if _installer_already_started(settings):
        print(f"ArgoSB 安装流程已在后台运行，UUID={uuid_value}")
        if tailscale:
            import pwd
            import shlex
            username = pwd.getpwuid(os.getuid()).pw_name
            print(f"Tailscale SSH connection: ssh {shlex.quote(username + '@' + tailscale['hostname'])}", flush=True)
            print("Tailscale: node must be online and SSH policy must allow this user", flush=True)
        return None

    state_dir.mkdir(parents=True, exist_ok=True)
    marker = state_dir / f"launcher-{uuid_value}.pid"
    arguments = [
        "install", "--uuid", uuid_value,
        "--port", str(settings["port"]),
        "--no-autostart",
        "--embedded-cloudflare",
    ]
    if settings["domain"]:
        arguments.extend(["--domain", str(settings["domain"])])

    local_script = Path(__file__).with_name("agsb-v2.py")
    if not local_script.exists():
        raise FileNotFoundError(f"安装脚本不存在: {local_script}")
    child_env = os.environ.copy()
    child_env["PYTHONUNBUFFERED"] = "1"
    child_env["AGK"] = str(settings["agk"])
    command = [sys.executable, str(local_script), *arguments]
    with log_path.open("ab") as log_stream:
        process = subprocess.Popen(
            command, stdout=log_stream, stderr=subprocess.STDOUT,
            start_new_session=True, env=child_env
        )
    marker.write_text(str(process.pid), encoding="ascii")
    marker.with_suffix(".runtime.json").write_text(json.dumps({
        "tailscale": tailscale, "cloudflare": cloudflare, "domain": settings["domain"],
    }), encoding="utf-8")
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

    installer_ok = True
    installer_process = None
    try:
        if args.no_install:
            print("已跳过 ArgoSB 自动启动；继续启动 Upterm", flush=True)
        elif not settings["agk"] or not settings["domain"]:
            print("配置错误: 自动启动命名隧道需要 AGK 和 DOMAIN；继续启动 Upterm", flush=True)
            installer_ok = False
        else:
            print("=== ArgoSB 服务启动 ===", flush=True)
            installer_process = launch_installer(settings)
    except Exception as exc:
        print(f"ArgoSB 启动失败: {redact(exc)}；继续启动 Upterm", flush=True)
        installer_ok = False

    manager = UptermManager(home=USER_HOME)
    upterm_ok = False
    try:
        print("=== Upterm SSH 会话管理器 ===", flush=True)
        upterm_ok = manager.prepare() and manager.start()
    except Exception as exc:
        print(f"Upterm 启动失败: {redact(exc)}", flush=True)
    finally:
        manager.cleanup()

    if installer_process is not None:
        status = installer_process.poll()
        if status not in (None, 0):
            print(f"ArgoSB 安装进程退出码: {status}", flush=True)
            installer_ok = False
    print("Upterm 连接命令及 ArgoSB/Tailscale 状态请查看应用日志。", flush=True)
    return installer_ok and upterm_ok

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
