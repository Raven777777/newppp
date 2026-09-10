#!/usr/bin/env python3
"""把静态二进制打包成 Docker 镜像 tar（无需 Docker daemon）。

产物为标准 `docker save` 格式（v1.2），可在任意装有 Docker 的机器上：

    docker load -i newppp-<version>.tar
    docker run -p 443:443/tcp -p 443:443/udp newppp:<version> -s ...
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

ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BINARY = os.path.join(
    ROOT, "target", "x86_64-unknown-linux-musl", "release", "newppp"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_layer(binary_path: str, mtime: int) -> bytes:
    with open(binary_path, "rb") as f:
        data = f.read()
    if not data:
        raise SystemExit(f"二进制文件为空或读取失败: {binary_path}")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        # scratch 镜像没有标准临时目录，--self-signed 开发模式要往 /tmp 写证书。
        info = tarfile.TarInfo(name="tmp/")
        info.type = tarfile.DIRTYPE
        info.mode = 0o1777
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        info.mtime = mtime
        tar.addfile(info)
        info = tarfile.TarInfo(name="newppp")
        info.size = len(data)
        info.mode = 0o755
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        info.mtime = mtime
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default=DEFAULT_BINARY, help="静态二进制路径")
    parser.add_argument("--tag", default=None, help="镜像标签，默认使用 newppp:<版本号>")
    parser.add_argument("-o", "--output", default=None, help="输出 tar 文件名，默认使用 newppp-<版本号>.tar")
    parser.add_argument("--version", default=None, help="版本号(不传则交互输入)")
    parser.add_argument(
        "--args",
        default=None,
        help="把 newppp 启动参数烧进镜像 Cmd(NAS 管理器无需再填运行命令)，"
        "例如: --args \"-c --auth u:p --server https://host --bind 0.0.0.0:1080\"",
    )
    args = parser.parse_args()

    version = args.version or input("请输入版本号: ").strip()
    if not version:
        raise SystemExit("版本号不能为空")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", version):
        raise SystemExit("版本号只能包含字母、数字、点、下划线和连字符，长度最多 128 个字符")

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

    layer = make_layer(args.binary, mtime)
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

        def add_dir(name: str) -> None:
            info = tarfile.TarInfo(name=name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mtime = mtime
            tar.addfile(info)

        add("manifest.json", manifest_bytes)
        add(f"{config_digest}.json", config_bytes)
        add_dir(f"{layer_digest}/")
        add(f"{layer_digest}/layer.tar", layer)

    size = os.path.getsize(output)
    print(f"已生成: {output} ({size} bytes)")
    print(f"镜像标签: {tag}")
    print(f"版本号: {version}")
    print(f"创建时间 (UTC): {created}")
    print()
    print("使用方式:")
    print(f"  docker load -i {output}")
    print()
    print("服务端示例:")
    print(f"  docker run -d -p 80:80 -p 443:443/tcp -p 443:443/udp {tag} -s \\")
    print("    --auth alice:secret123 --listen 0.0.0.0:443 \\")
    print("    --fallback-listen 0.0.0.0:443 --http-listen 0.0.0.0:80 --self-signed")
    print("(正式部署: 挂载证书 -v /etc/newppp/certs:/certs,改用 --cert/--key 去掉 --self-signed)")
    print()
    print("客户端示例:")
    print(f"  docker run -d -p 1080:1080 {tag} -c \\")
    print("    --server https://your.host:443 --auth alice:secret123")


if __name__ == "__main__":
    main()
