///| Known hosts store — host shim extern 接口 (wasm target)
///|
/// Loop #19 extern 接口 ready (wasm-only stub)
/// Loop #21 升级:浏览器 IndexedDB sync wrapper 真实持久化
/// 浏览器 host shim 用 Map<key, value> in-memory cache 同步返回
/// 异步写 IDB 持久化 (浏览器重启后数据仍在)
///|
/// 限制:MoonBit extern wasm 是同步,IDB 是异步。Loop #21 用 sync cache + async persist 解决。

///|
/// host shim imports (浏览器 + Node.js 都实现)
extern "wasm" fn khs_open(path_ptr : Int, path_len : Int) -> Int =
  "moonbit_khs" "open"

extern "wasm" fn khs_count(handle : Int) -> Int =
  "moonbit_khs" "count"

extern "wasm" fn khs_get(handle : Int, idx : Int, out_ptr : Int, out_cap : Int) -> Int =
  "moonbit_khs" "get"

extern "wasm" fn khs_put(handle : Int, idx : Int, val_ptr : Int, val_len : Int) -> Int =
  "moonbit_khs" "put"

extern "wasm" fn khs_close(handle : Int) -> Int =
  "moonbit_khs" "close"