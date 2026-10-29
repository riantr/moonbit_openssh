/* Loop #84: the native entropy source.
 *
 * Windows' documented CSPRNG is BCryptGenRandom.  Passing a NULL algorithm
 * handle asks for the primary provider, which is the same generator the
 * system uses for its own keys -- the "system preferred" flag makes that
 * explicit rather than leaving it to the default.
 *
 * Two things this file deliberately does NOT do:
 *
 *   - It does not seed anything.  A seeded generator whose seed lives in the
 *     binary is not a CSPRNG, and a package whose whole job is to be one
 *     should not also be the place where that mistake hides.
 *
 *   - It does not fall back to a weaker source when BCryptGenRandom fails.
 *     The return value says what happened, and the caller decides; a silent
 *     fallback to, say, the tick count would turn a visible failure into an
 *     invisible key.
 */

#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

/* Fill `len` bytes of `buf` with random bytes.
 *
 * Returns 0 on success and -1 on failure.  A length of zero is a success
 * with nothing to do -- asking for no randomness is not an error, and the
 * caller is entitled to ask.
 */
int mb_rng_fill(unsigned char *buf, int len) {
    NTSTATUS st;

    if (buf == NULL || len < 0) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    st = BCryptGenRandom(NULL, buf, (ULONG)len,
                         BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return st == 0 ? 0 : -1;
}
