path = r'E:\src\moon\openssh_moonbit\src\kexflow\flow.mbt'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Insert step 6.5 (host_key_check) between verify and derive_keys
# Find: _ => return Failed(SignatureInvalid) }
# followed by // :212-213 kex_derive_keys
old_block = """  match
    @hostkey.HostKey::verify(@hostkey.Ed25519Key(hostkey), h, rep.sig_blob) {
    @hostkey.Accepted => ()
    _ => return Failed(SignatureInvalid)
  }
  // :212-213 kex_derive_keys"""

new_block = """  match
    @hostkey.HostKey::verify(@hostkey.Ed25519Key(hostkey), h, rep.sig_blob) {
    @hostkey.Accepted => ()
    _ => return Failed(SignatureInvalid)
  }
  // ---- Loop #13 step 6.5: host_key_check ----
  // 入参 cfg.knownhosts_entries 可空（空数组 = 跳过检查）; bytesters_hostname 必须非空
  if cfg.knownhosts_entries.length() > 0 {
    let host_status = @knownhosts.check_host_key_strict(
      cfg.knownhosts_entries, cfg.hostname, rep.hostkey_blob, cfg.strict_kex,
    )
    match host_status {
      @knownhosts.Ok => ()
      @knownhosts.Mismatch => return Failed(HostKeyMismatch(cfg.hostname))
      @knownhosts.Unknown =>
        if cfg.strict_kex {
          return Failed(HostKeyUnknown(cfg.hostname))
        }
      @knownhosts.InvalidEntry => return Failed(ProtocolError)
    }
  }
  // :212-213 kex_derive_keys"""

assert old_block in content, 'old_block not found'
content = content.replace(old_block, new_block)

with open(path, 'w', encoding='utf-8', newline='') as f:
    f.write(content)
print('OK: step 6.5 host_key_check inserted')