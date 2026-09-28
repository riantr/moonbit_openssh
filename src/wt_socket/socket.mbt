///| WebTransport Socket (wasm-gc target)
///|
/// Loop #21: MoonBit extern 接口 ready
/// 浏览器 host shim 实现 WebTransport API + bidirectional stream
/// Node.js 没有原生 HTTP/3,留 Loop #22+ 接 cloudflare/quiche
///|
/// 与 ws_socket 同模式:用 Int + 长度而非 FixedArray[Byte]
/// host shim 直接读 wasm 内存 offset 处 N 个字节

///|
/// 真 WebTransport Socket
pub struct WtSocket {
  handle : Int
  mut closed : Bool
}

///|
/// 写入 buffer (固定 wasm 内存 offset 0..4096)
let wt_buf : FixedArray[Byte] = FixedArray::make(4096, b'\x00')

fn wt_buf_write(bytes : FixedArray[Byte]) -> Int {
  let len = if bytes.length() > 4096 { 4096 } else { bytes.length() }
  for i = 0; i < len; i = i + 1 {
    wt_buf[i] = bytes[i]
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
/// 连接 WebTransport URL (wasm-gc target only)
pub fn WtSocket::connect(url : String) -> WtSocket {
  let url_len = wt_buf_write(ascii_bytes(url))
  let handle = wt_connect_extern(0, url_len)
  { handle, closed: false }
}

///|
pub fn WtSocket::send(self : WtSocket, bytes : FixedArray[Byte]) -> Unit {
  if self.closed {
    abort("WtSocket::send: closed")
  }
  let len = wt_buf_write(bytes)
  ignore(wt_send_extern(self.handle, 0, len))
}

///|
pub fn WtSocket::read_n(self : WtSocket, n : Int) -> FixedArray[Byte] {
  if self.closed {
    abort("WtSocket::read_n: closed")
  }
  let actual = wt_recv_into_extern(self.handle, 0, n)
  if actual < n {
    abort("WtSocket::read_n: short read, want \{n} got \{actual}")
  }
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = wt_buf[i]
  }
  out
}

///|
pub fn WtSocket::close(self : WtSocket) -> Unit {
  self.closed = true
  ignore(wt_close_extern(self.handle))
}

///|
/// host shim imports (浏览器 WebTransport API)
extern "wasm" fn wt_connect_extern(url_ptr : Int, url_len : Int) -> Int =
  "moonbit_wt" "wt_connect"

extern "wasm" fn wt_send_extern(handle : Int, bytes_ptr : Int, len : Int) -> Int =
  "moonbit_wt" "wt_send"

extern "wasm" fn wt_recv_into_extern(handle : Int, out_ptr : Int, n : Int) -> Int =
  "moonbit_wt" "wt_recv_into"

extern "wasm" fn wt_close_extern(handle : Int) -> Int =
  "moonbit_wt" "wt_close"