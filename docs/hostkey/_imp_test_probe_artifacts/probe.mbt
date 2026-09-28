///|
test "cross_pkg_import_probe" {
  let blob : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  let r = @hostkey.HostKey::from_blob(blob)
  ignore(@kexc25519.parse_reply(blob))
  let ctx = @bpacket.SendCtx::make(@bpacket.Unencrypted, 0U, false, true)
  ignore(ctx.seqnr())
  ignore(r)
}
