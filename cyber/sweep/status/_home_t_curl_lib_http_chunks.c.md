# /home/t/curl/lib/http_chunks.c

## Scanner findings

Looking at the struct definition in the header:

```c
char hexbuffer[CHUNK_MAXNUM_LEN + 1]; /* +1 for null-terminator */
unsigned char hexindex;
```

The guard is `if(ch->hexindex >= CHUNK_MAXNUM_LEN)` — max `hexindex` after fill is `CHUNK_MAXNUM_LEN`, and the null write `ch->hexbuffer[ch->hexindex] = 0` is at `hexbuffer[CHUNK_MAXNUM_LEN]`, which is within the `[CHUNK_MAXNUM_LEN+1]` array. Correctly sized.

Tracing every other site:

- `add_chunk`: `blen` is clamped to `CURL_CHUNKED_MAXLEN` before the `< sizeof(tmp)` branch; read into `tmp[1024]` with `blen = sizeof(tmp)`; `hd[11]` holds hex of at most 65536 (5 chars) + `\r\n\0` = 8 bytes — no overflow.
- `CHUNK_POSTLF` reset: `Curl_httpchunk_reset` resets state to `CHUNK_HEX`; `buf` is then advanced and the while-loop continues correctly.
- `CHUNK_TRAILER` dynbuf: pointer is refreshed via `curlx_dyn_ptr` after every `curlx_dyn_addn`; dynbuf limit failures are checked and propagated.
- `Curl_httpchunk_add_reader`: on `Curl_creader_add` failure, frees the reader — standard libcurl ownership pattern, not a double-free.
- `hexindex` is `unsigned char`; `CHUNK_MAXNUM_LEN` ≤ 16; no wraparound possible.
- `curlx_str_hex` is bounded by `CURL_OFF_T_MAX`; no path to overflow `ch->datasize`.
- `cr_chunked_read` initialization of `result = CURLE_READ_ERROR` is never returned on the normal-exit path; the function returns `CURLE_OK` at the end.

No concretely traceable path from crafted input to an unsafe operation.

skip


## Test harnesses

SKIP — the scanner found no concretely traceable path from crafted input to an unsafe operation in `lib/http_chunks.c`. All candidate sites are correctly bounded:

- `hexbuffer` is `[CHUNK_MAXNUM_LEN+1]` and the null-write lands at index `CHUNK_MAXNUM_LEN` — within bounds.
- `add_chunk`'s `hd[11]` is large enough for the maximum hex representation of `CURL_CHUNKED_MAXLEN`.
- `CHUNK_TRAILER` dynbuf pointer is refreshed after every `curlx_dyn_addn`.
- `hexindex` is `unsigned char` and `CHUNK_MAXNUM_LEN ≤ 16` — no wraparound.
- `curlx_str_hex` is bounded by `CURL_OFF_T_MAX`.

Writing a harness here would only confirm correct behaviour, which is explicitly not the goal. No test files generated.

