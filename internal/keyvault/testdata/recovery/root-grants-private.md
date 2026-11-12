# Private root sealing and numbered input fixtures

The private helper source adds no external input or custody API, signer,
archive target, C symbol or parent-returning plaintext operation. It is not
linked or qualified by the presence of these files. The final custody helper
must use one Go archive/runtime for its Namecoin and root operations.

The sealing primitive uses the existing recovery ECIES algorithm and layout:
P256 ECDH, SHA256(Z || counter1-big-endian || ephemeral-point65), AES128 with the
first16 derived bytes, GCM with the last16 as nonce, and point65 || ciphertext68
|| tag16. The plaintext is KVG1 || SHA256(domain ||00||complete canonical root
metadata) || normalized scalar32. Invalid metadata, public/pair binding, scalar
or parity refuses before random input. Production randomness is crypto/rand;
an invalid random P256 exponent hard-refuses without a retry. Private injection
exists only to ground primitive tests and is not an external random option or
software custody fallback.

Tests use published BIP340 scalar3/K plus deliberately public synthetic P256
recipient3/ephemeral4. Test-only code independently opens a real software-sealed
envelope to the exact KVG1/domain/scalar bytes. Wrong record, recipient, point,
ciphertext, tag, zero/order/odd scalar and even-but-wrong K have paired valid
controls. Shared standard crypto libraries remain a limit: existing published
and qualified recovery primitive anchors must remain in the validation lanes.
No expected private data is an owner's key or device representation.

The numbered grammar admits exactly1..24 consecutive canonical decimal
ordinals, dot, one ASCII space and a lowercase English BIP39 word, one per
LF/CRLF line, followed by exact END. It validates24-word checksum. It refuses
blank/aliased/skipped/duplicate/reordered ordinals, extra spaces/case/non-ASCII,
single-line phrases, wrong count/END/checksum, EOF and cancellation without
rereads. Production word data remains in owned byte buffers, never String,
diagnostics, files, argv, environment, clipboard or parent/IPC. Pure grammar
and line-I/O fixtures do not enable an alternate production input source.
Only the controlling-tty transport maps physical Return CR to LF, consuming one
optional following LF so CRLF ends exactly one line. CR CR exposes a blank line
and refuses; a CR inside a word cannot produce an accepted whole phrase. The
direct parser still refuses bare CR; no pipe/argv/reader option gains that mapper.

On Darwin, the private frontend opens only /dev/tty with O_NOCTTY, CLOEXEC and
NONBLOCK; it checks a character device, termios and the foreground process group.
It verifies hidden attributes, disables echo and input transformations, uses
bounded select waits and handles cancellation/signals/EOF. Cleanup flushes input
and uses immediate TIOCSETA rather than an output-draining ioctl, then verifies
the exact saved attributes. SIGKILL, host loss, OS restoration refusal, terminal
recording and runtime/opaque-crypto copies are outside any erasure guarantee.
Portable platforms refuse custody input rather than use stdin or a file.

The engine retains one original900-second deadline across read, preparation,
waiting and sealing. Duplicate phase calls invalidate the attempt. Both old
public pins and origin are rederived/checked before any random/seal call; only
public preparation is returned while the private scalar waits for the separately
qualified native-created wrap. Cancellation invalidates abandoned handles.
Known retained Nostr/Namecoin wrapping points cannot be reused for the root;
rejecting those points does not itself establish freshness or native policy.
Copies share private lifetime; all owned plaintext/shared/random/derived buffers
are cleared at logical exits. ecdh and AES/GCM opaque objects, compiler/runtime
copies and reflection/unsafe are not guaranteed physically erased.

The outer qualified vault must retain its same existing mutation guard across
all attended phases and sole create-only add. It must authenticate native code,
actual wrap/TouchID-only qualification and key correspondence. Public point/blob
shape and successful software encryption prove none of these. Native final
review/confirmation, one-operation helper lifecycle, archive/header docking,
actual tty/PTY and restoration qualification, custody regression and signed
release remain separate. These private tests create no stored/enrolled receipt,
fresh-all3/restore operation, or live grant/transaction signature.
