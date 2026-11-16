# Process/2 subprocess fixture

This Go program exercises the portable parent transport with public bytes only.
It reads one fd5 frame through EOF, writes the existing public signed-result
fixture to fd3, and emits the accepted status/ACK shape on fd4/stdout. Timeout
values 11, 12 and 13 select partial-status, unexpected-stderr and no-read
controls for tests. It does not call Keychain, Secure Enclave, a signing engine,
or any production helper identity check.

`result.json` must remain byte-identical to
`internal/namecoinwire/testdata/all-four-before-release/A-result.json`:

| Bytes | SHA-256 |
| ---: | --- |
| 2143 | `1dbf4017e1fc94b7b13527842e0b9f223b4fabe7988c2c31cf0a43c4685726a6` |
