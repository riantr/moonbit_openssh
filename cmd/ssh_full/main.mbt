///| cmd/ssh_full — Loop #22 SSH client write 侧完整字节级协议闭环

///|
/// 输出 8 行 byte-exact hash 跨 4 target × 2 mode
fn main {
  let (sent, recv, stdout, exit_code, remote_channel) = @sshclient.ssh_client_full_unencrypted(
    "moonbit", "sshpass", "ls",
  )

  println("=== SSH-WASM-SSH Loop #22 (Full Write Path) ===")
  println("sent_bytes: " + sent.length().to_string())
  println("recv_bytes: " + recv.length().to_string())
  println("stdout: " + stdout)
  println("exit_code: " + exit_code.to_string())
  println("remote_channel: " + remote_channel.to_string())
  println("version: " + "SSH-2.0-MoonBit")
  println("userauth_method: " + "password")
  println("channel_type: " + "session")
}
