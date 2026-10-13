#!/usr/bin/env python3
"""Generate `src/hostkey/cert_fixture.mbt` from real ssh-keygen certificates.

Every constant is emitted from a blob that OpenSSH itself produced and
`ssh-keygen -L` describes. Nothing is typed by hand -- including the timestamps,
so a regenerated fixture never leaves a stale hand-written date in a test.

The cert type constants come from the bytes, cross-checked against
`ssh-keygen -L`:

    ssh-keygen -s ca -h ...   ->  type field == 2, "-L" says "host certificate"
    ssh-keygen -s ca     ...  ->  type field == 1, "-L" says "user certificate"

so `SSH_CERT_TYPE_USER == 1` and `SSH_CERT_TYPE_HOST == 2`. Getting this pair
backwards would make the client accept a certificate minted for a *user*
(principal `alice`) as proof of a *host* identity.

The principal is `127.0.0.1` -- the name the gates actually connect to. A
certificate whose principal is anything else is refused for the right reason but
tests the wrong branch, and a test that only passes because it never reached the
check it was written for is worse than no test.

The good certificates get a ten-year window so a gate can be re-run weeks later
without the fixture silently expiring; the expired one is minted in the past on
purpose.
"""
import base64
import struct
import sys

USER_TYPE = 1
HOST_TYPE = 2

PRINCIPAL = "127.0.0.1"
LONG = "-3650d:+3650d"

FILES = [
    ("GOOD_CERT", "host-good-cert.pub"),
    ("OTHER_PRINCIPAL_CERT", "host-other-cert.pub"),
    ("EXPIRED_CERT", "host-exp-cert.pub"),
    ("ROGUE_CA_CERT", "host-rogue-cert.pub"),
    ("USER_CERT", "usercert-in-cert.pub"),
    ("NON_HOST_PRINCIPAL_CERT", "user-cert-cert.pub"),
]

PUB_FILES = [
    ("CA_PUB", "ca.pub"),
    ("ROGUE_CA_PUB", "rogue.pub"),
    ("HOST_PUB", "host.pub"),
]


class R:
    def __init__(self, b):
        self.b = b
        self.o = 0

    def st(self):
        (n,) = struct.unpack(">I", self.b[self.o:self.o + 4])
        self.o += 4
        v = self.b[self.o:self.o + n]
        self.o += n
        return v

    def u64(self):
        (v,) = struct.unpack(">Q", self.b[self.o:self.o + 8])
        self.o += 8
        return v

    def u32(self):
        (v,) = struct.unpack(">I", self.b[self.o:self.o + 4])
        self.o += 4
        return v


def fields(path):
    b = base64.b64decode(open(path).read().split()[1])
    r = R(b)
    name = r.st().decode()
    nonce = r.st()
    key = r.st()
    serial = r.u64()
    ctype = r.u32()
    key_id = r.st().decode()
    # The principals field is a string whose *contents* are a concatenation of
    # length-prefixed principal strings -- not a comma-separated ASCII list.
    principals_blob = r.st()
    principals = []
    pr = R(principals_blob)
    while pr.o < len(principals_blob):
        principals.append(pr.st().decode())
    va = r.u64()
    vb = r.u64()
    crit = r.st()
    ext = r.st()
    resv = r.st()
    sig_key = r.st()
    sig = r.st()
    # Signed data is everything up to (not including) the trailing
    # `string signature` field -- so it INCLUDES the type name AND the signature
    # key field. Verified against Node/OpenSSL with cert_signed_data_oracle.mjs:
    # of every contiguous slice tried, only blob[0 : len-4-len(sig)] verifies.
    signed_len = r.o - 4 - len(sig)
    assert r.o == len(b), f"{path}: {len(b) - r.o} trailing bytes"
    return {
        "blob": b, "name": name, "nonce": nonce, "key": key, "serial": serial,
        "type": ctype, "key_id": key_id, "principals": ",".join(principals),
        "valid_after": va, "valid_before": vb, "critical": crit,
        "extensions": ext, "reserved": resv, "sig_key": sig_key, "sig": sig,
        "signed_len": signed_len,
    }


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else ".loop53"
    out = []
    out.append("///| Loop #53 测试固定件 —— 由 `host/cert_gen_fixture.py` 生成，勿手改。")
    out.append("///")
    out.append("/// 来源：真实 `ssh-keygen -s <ca> [-h]` 签出的 ed25519 主机/用户证书，")
    out.append("/// 每一条都被 `ssh-keygen -L` 复核过。文件在 `.loop53/`。")
    out.append("///")
    out.append("/// **cert type 常量来自字节本身**（并与 `ssh-keygen -L` 交叉验证）：")
    out.append("///   -h 签出的证书，type 字段 == 2，`-L` 打印 `host certificate`")
    out.append("///   不带 -h 签出的证书，type 字段 == 1，`-L` 打印 `user certificate`")
    out.append("/// 所以 `USER == 1` / `HOST == 2`。写反的后果是把发给 alice 的")
    out.append("/// 用户证书当成主机身份证明。")
    out.append("")
    out.append("/// principal 一律是 `127.0.0.1`，即门禁真正连的名字。principal 写成别的")
    out.append("/// 也能得到一个正确的拒绝，但测到的是另一条分支——一个没走到它要测的那一步")
    out.append("/// 的测试比没有测试更糟。好证书的窗口拉到十年，门禁过几周再跑也不会自己过期。")
    out.append("")
    out.append("/// 常量 `SSH_CERT_TYPE_USER` / `SSH_CERT_TYPE_HOST` 不在这里重复定义：")
    out.append("/// 它们是生产代码（`cert.mbt`）的一部分，固定件只负责提供 blob。")
    out.append("")

    for const, fname in FILES:
        f = fields(f"{root}/{fname}")
        kind = "host" if f["type"] == HOST_TYPE else (
            "user" if f["type"] == USER_TYPE else "?")
        out.append(f"///| `{fname}`：type={f['type']} ({kind}) key id={f['key_id']!r} "
                   f"principals={f['principals']!r}")
        out.append(f"///| valid {f['valid_after']} .. {f['valid_before']}, "
                   f"signed_data = {f['signed_len']} bytes")
        out.append(f'pub const {const} : String = "{base64.b64encode(f["blob"]).decode()}"')
        out.append("")

    for const, fname in PUB_FILES:
        b = base64.b64decode(open(f"{root}/{fname}").read().split()[1])
        out.append(f"///| `{fname}`")
        out.append(f'pub const {const} : String = "{base64.b64encode(b).decode()}"')
        out.append("")

    # Everything below is emitted rather than written by hand, so regenerating the
    # certificates can never leave a stale number behind in a test.
    out.append("///| 每张证书的 signed_data 长度 = `len(blob) - 4 - len(signature)`，也就是")
    out.append("/// 证书 blob 去掉末尾那个 `string signature` 字段之后的全部内容——")
    out.append("/// **包含类型名，也包含 signature key 字段**。这不是照着源码抄的，是用")
    out.append("/// Node/OpenSSL 把所有连续切片都试了一遍、只有这一个过验签得来的")
    out.append("///（见 `host/cert_signed_data_oracle.mjs`）。")
    out.append("///")
    out.append("/// signed_data 切错不会报任何结构性错误，只会让验签失败；所以长度本身就是")
    out.append("/// 那个断言。")
    for const, fname in FILES:
        f = fields(f"{root}/{fname}")
        out.append(f"pub const {const}_SIGNED_LEN : Int = {f['signed_len']}")
    out.append("")
    out.append("///| 有效期边界，同样由脚本给出——测试里不手写任何时间戳。")
    for const, fname in FILES:
        f = fields(f"{root}/{fname}")
        out.append(f"pub const {const}_VALID_AFTER : UInt64 = {f['valid_after']}UL")
        out.append(f"pub const {const}_VALID_BEFORE : UInt64 = {f['valid_before']}UL")
    out.append("")

    return "\n".join(out)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        raise SystemExit(2)
    # Write the file ourselves instead of piping to stdout: PowerShell decodes
    # the pipe with the console code page (cp936) and mangles every CJK comment
    # on the way through. Encoding it here keeps the docs readable.
    out_path = sys.argv[3] if len(sys.argv) > 3 else "src/hostkey/cert_fixture.mbt"
    text = main()
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(f"wrote {out_path}: {len(text.encode('utf-8'))} bytes")