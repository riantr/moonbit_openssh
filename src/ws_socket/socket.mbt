///| WebSocket Socket (wasm-gc target)

///|
/// 简化方案:用 Int + 长度而非 FixedArray[Byte]
/// host shim 直接读 wasm 内存 offset 处 N 个字节 (与 Loop #17 fd_write 同款)

///|
/// Loop #20: 浏览器 demo HTML 用本包的 Socket::connect + send + read_n + close

///|
/// 真 WebSocket Socket
pub struct Socket {
  handle : Int32
  mut closed : Bool
}

///|
/// 写入 buffer (固定 wasm 内存 offset 0..4096)
/// host shim 直接读 mem[ptr..ptr+len]
let ws_buf : FixedArray[Byte] = FixedArray::make(4096, b'\x00')

///|
fn ws_buf_write(bytes : FixedArray[Byte]) -> Int32 {
  let len = if bytes.length() > 4096 { 4096 } else { bytes.length() }
  for i = 0; i < len; i = i + 1 {
    ws_buf[i] = bytes[i]
  }
  len
}

///|
/// ASCII string → FixedArray[Byte]
fn ascii_bytes(s : String) -> FixedArray[Byte] {
  let arr : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    arr[i] = s[i].to_byte()
  }
  arr
}

///|
/// 连接 WebSocket URL (wasm-gc target only)
pub fn Socket::connect(url : String) -> Socket {
  let url_len = ws_buf_write(ascii_bytes(url))
  let handle = ws_connect_extern(0, url_len)
  { handle, closed: false, }
}

///|
pub fn Socket::send(self : Socket, bytes : FixedArray[Byte]) -> Unit {
  if self.closed {
    abort("Socket::send: closed")
  }
  let len = ws_buf_write(bytes)
  ignore(ws_send_extern(self.handle, 0, len))
}

///|
pub fn Socket::read_n(self : Socket, n : Int32) -> FixedArray[Byte] {
  if self.closed {
    abort("Socket::read_n: closed")
  }
  let actual = ws_recv_into_extern(self.handle, 0, n)
  if actual < n {
    abort("Socket::read_n: short read, want \{n} got \{actual}")
  }
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = ws_buf[i]
  }
  out
}

///|
pub fn Socket::close(self : Socket) -> Unit {
  self.closed = true
  ignore(ws_close_extern(self.handle))
}

///|
/// host shim imports (wasm-gc target only)
extern "wasm" fn ws_connect_extern(url_ptr : Int32, url_len : Int32) -> Int32 = "moonbit_socket" "ws_connect"

///|
extern "wasm" fn ws_send_extern(
  handle : Int32,
  bytes_ptr : Int32,
  len : Int32,
) -> Int32 = "moonbit_socket" "ws_send"

///|
extern "wasm" fn ws_recv_into_extern(
  handle : Int32,
  out_ptr : Int32,
  n : Int32,
) -> Int32 = "moonbit_socket" "ws_recv_into"

///|
extern "wasm" fn ws_close_extern(handle : Int32) -> Int32 = "moonbit_socket" "ws_close"
