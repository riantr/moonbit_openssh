///|
/// Loop #85: the stub half of making a private key file private.
///
/// There is no file system on the browser, so there is nothing to
/// protect: this reports failure, and the caller says so rather than
/// pretending the key is private.
///
/// The alternative -- reporting success -- would be a lie that only
/// shows up later, on a machine where the file does exist.  A tool that
/// says "the key is private" when it did nothing is worse than one that
/// says "this platform cannot make a key private".
pub fn protect(path : String) -> Int32 {
  // The path is not used: there is nothing here that could act on it.  It is
  // named and ignored rather than dropped from the signature, because the
  // signature is the package's contract and the native half has to honour
  // the same one.
  ignore(path)
  -1
}
