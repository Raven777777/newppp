#!/usr/bin/env python3
"""newppp Docker 镜像打包启动脚本（无需本机安装 Docker）。

把静态 musl Linux 二进制 + 系统 CA 根证书封装成标准 `docker save` 格式
(v1.2) 镜像 tar，拷到任意有 Docker 的机器（服务器/NAS）直接 `docker load`。

流程：先跑 build_linux.bat 出二进制，再运行本脚本：

    py -3 build_docker.py

交互输入版本号与启动参数即可；也支持原命令行参数（--version/--args/...）。

CA 事项（重要）：镜像基于 scratch，没有系统 CA 根证书，客户端校验 HTTPS
证书（WT/wss/时钟源）会报 UnknownIssuer。本脚本自动把 Mozilla CA bundle
（curl.se 官方 cacert.pem）注入镜像 /etc/ssl/certs/ca-certificates.crt，
程序经 rustls-native-certs 自动读取，证书校验恢复正常。
"""

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
import re
import shlex
import tarfile
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BINARY = os.path.join(
    ROOT, "target", "x86_64-unknown-linux-musl", "release", "newppp"
)
CA_URL = "https://curl.se/ca/cacert.pem"
CA_PATH_IN_IMAGE = "etc/ssl/certs/ca-certificates.crt"
# 本地 CA bundle 缓存（避免每次打包都联网；删除该文件即可强制重新下载）
CA_CACHE = os.path.join(ROOT, ".cacert.pem")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_ca_bundle() -> bytes:
    """获取 Mozilla CA bundle：优先本地缓存，否则从 curl.se 下载并缓存。"""
    if os.path.isfile(CA_CACHE):
        with open(CA_CACHE, "rb") as f:
            data = f.read()
        if b"BEGIN CERTIFICATE" in data:
            print(f"CA 根证书: 使用本地缓存 {CA_CACHE} "
                  f"({data.count(b'BEGIN CERTIFICATE')} 个)")
            return data
    print(f"CA 根证书: 从 {CA_URL} 下载 ...")
    with urllib.request.urlopen(CA_URL, timeout=30) as resp:
        data = resp.read()
    if b"BEGIN CERTIFICATE" not in data:
        raise SystemExit("下载的 CA bundle 无效（无证书内容）")
    with open(CA_CACHE, "wb") as f:
        f.write(data)
    print(f"CA 根证书: {data.count(b'BEGIN CERTIFICATE')} 个，已缓存到 {CA_CACHE}")
    return data


def make_layer(binary_path: str, ca_bundle: bytes, mtime: int) -> bytes:
    with open(binary_path, "rb") as f:
        data = f.read()
    if not data:
        raise SystemExit(f"二进制文件为空或读取失败: {binary_path}")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        def add_dir(name: str, mode: int = 0o755) -> None:
            info = tarfile.TarInfo(name=name)
            info.type = tarfile.DIRTYPE
            info.mode = mode
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mtime = mtime
            tar.addfile(info)

        def add_file(name: str, content: bytes, mode: int) -> None:
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            info.mode = mode
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mtime = mtime
            tar.addfile(info, io.BytesIO(content))

        # scratch 镜像没有标准临时目录，--self-signed 开发模式要往 /tmp 写证书。
        add_dir("tmp/", mode=0o1777)
        # 系统 CA 根证书：rustls-native-certs (openssl-probe) 的标准探测路径。
        add_dir("etc/")
        add_dir("etc/ssl/")
        add_dir("etc/ssl/certs/")
        add_file(CA_PATH_IN_IMAGE, ca_bundle, mode=0o644)
        add_file("newppp", data, mode=0o755)
    return buf.getvalue()


def interactive_args() -> str:
    """交互输入 newppp 启动参数（与容器管理器里填的运行命令一致）。"""
    print()
    print("请输入 newppp 启动参数（必须以 -c 或 -s 开头，留空则不烧进镜像，")
    print("运行时在 docker run / 容器管理器里自行填写）。示例:")
    print("  -s --auth alice:secret123 --listen 0.0.0.0:443 "
          "--fallback-listen 0.0.0.0:443 --http-listen 0.0.0.0:80")
    print("  -c --auth alice:secret123 --server https://host "
          "--url wss://host/api/ppp --bind 0.0.0.0:1080")
    raw = input("启动参数: ").strip()
    if raw:
        extra = shlex.split(raw)
        if not extra or extra[0] not in ("-c", "-s"):
            raise SystemExit("启动参数必须以 -c 或 -s 开头")
    return raw


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--binary", default=DEFAULT_BINARY, help="静态二进制路径")
    parser.add_argument("--tag", default=None, help="镜像标签，默认使用 newppp:<版本号>")
    parser.add_argument(
        "-o", "--output", default=None, help="输出 tar 文件名，默认使用 newppp-<版本号>.tar"
    )
    parser.add_argument("--version", default=None, help="版本号(不传则交互输入)")
    parser.add_argument(
        "--args",
        default=None,
        help="把 newppp 启动参数烧进镜像 Cmd(NAS 管理器无需再填运行命令)，"
        "例如: --args \"-c --auth u:p --server https://host --bind 0.0.0.0:1080\""
        "(不传则交互输入)",
    )
    args = parser.parse_args()

    version = args.version or input("请输入版本号: ").strip()
    if not version:
        raise SystemExit("版本号不能为空")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", version):
        raise SystemExit("版本号只能包含字母、数字、点、下划线和连字符，长度最多 128 个字符")

    if args.args is None:
        args.args = interactive_args()

    created_at = datetime.now(timezone.utc).replace(microsecond=0)
    created = created_at.isoformat().replace("+00:00", "Z")
    mtime = int(created_at.timestamp())
    tag = args.tag or f"newppp:{version}"
    output = args.output or f"newppp-{version}.tar"

    cmd = ["/newppp"]
    exposed = {"80/tcp": {}, "443/tcp": {}, "443/udp": {}}
    if args.args:
        extra = shlex.split(args.args)
        if not extra or extra[0] not in ("-c", "-s"):
            raise SystemExit("--args 必须以 -c 或 -s 开头")
        cmd += extra
        exposed = {"1080/tcp": {}} if extra[0] == "-c" else exposed
        print(f"烧进镜像的启动参数: {' '.join(cmd)}")

    if not os.path.isfile(args.binary):
        raise SystemExit(f"找不到二进制文件: {args.binary}")

    ca_bundle = load_ca_bundle()
    layer = make_layer(args.binary, ca_bundle, mtime)
    layer_digest = sha256(layer)

    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {
            "Env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            ],
            "Labels": {
                "org.opencontainers.image.version": version,
                "org.opencontainers.image.created": created,
            },
            "Cmd": cmd,
            "WorkingDir": "/",
            "ExposedPorts": exposed,
        },
        "created": created,
        "rootfs": {"type": "layers", "diff_ids": [f"sha256:{layer_digest}"]},
        "history": [
            {"created": created, "created_by": f"newppp image package {version}"}
        ],
    }
    config_bytes = json.dumps(config, separators=(",", ":")).encode()
    config_digest = sha256(config_bytes)

    manifest = [
        {
            "Config": f"{config_digest}.json",
            "RepoTags": [tag],
            "Layers": [f"{layer_digest}/layer.tar"],
        }
    ]
    manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode()

    with tarfile.open(output, "w") as tar:
        def add(name: str, data: bytes, mode: int = 0o644) -> None:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = mode
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mtime = mtime
            tar.addfile(info, io.BytesIO(data))

        add("manifest.json", manifest_bytes)
        add(f"{config_digest}.json", config_bytes)
        add(f"{layer_digest}/layer.tar", layer)

    size = os.path.getsize(output)
    print()
    print("=" * 62)
    print(f"已生成: {output} ({size} bytes)")
    print(f"镜像标签: {tag}")
    print(f"版本号: {version}")
    print(f"创建时间 (UTC): {created}")
    print("=" * 62)
    print()
    print("【CA 证书事项】")
    print("  镜像基于 scratch，本身无系统 CA 根证书——已自动注入 Mozilla CA")
    print(f"  bundle 到 /{CA_PATH_IN_IMAGE}，程序自动读取，HTTPS 证书校验正常，")
    print("  不会再出现 UnknownIssuer。注意：")
    print("  * 根证书随镜像打包，若镜像长期不更新可能过期（Mozilla 每季度")
    print("    更新），届时重新打包即可；")
    print("  * 自签调试仍需 --self-signed（服务端）+ --skip-verify（客户端），")
    print("    与 CA 无关。")
    print()
    print("【docker 使用注意】")
    print("  1. 导入镜像:")
    print(f"       docker load -i {output}")
    print("  2. 若镜像 Cmd 已含启动参数（本脚本已烧入），NAS 容器管理器的")
    print("     「容器运行命令」必须留空保持默认——多数管理器会把整行命令")
    print("     当成单个参数导致 container startup failed；")
    print("  3. 客户端容器端口映射只加 本地端口 → 1080/TCP；443/udp、80 是")
    print("     服务端端口；")
    print("  4. 容器内必须绑 0.0.0.0（如 --bind 0.0.0.0:1080），写 127.0.0.1")
    print("     会导致映射失效；")
    print("  5. 服务端正式部署挂载证书:")
    print("       -v /etc/newppp/certs:/certs  改用 --cert/--key，去掉 --self-signed")
    print("  6. --args 里的密码会写进镜像配置（docker inspect 可见），镜像")
    print("     tar 请妥善保管。")
    print()
    print("服务端示例（Cmd 为空时）:")
    print(f"  docker run -d -p 80:80 -p 443:443/tcp -p 443:443/udp {tag} -s \\")
    print("    --auth alice:secret123 --listen 0.0.0.0:443 \\")
    print("    --fallback-listen 0.0.0.0:443 --http-listen 0.0.0.0:80 --self-signed")
    print()
    print("客户端示例（Cmd 为空时）:")
    print(f"  docker run -d -p 1080:1080 {tag} -c \\")
    print("    --server https://your.host:443 --auth alice:secret123")


if __name__ == "__main__":
    main()
