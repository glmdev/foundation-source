LZ👌
===

A minimal, C++14 implementation of the
[LZO compression format](http://www.oberhumer.com/opensource/lzo/).

Objective
---------

The implementation provides compression behavior similar to the
`lzo1x_999_compress` function in `lzo2` (i.e. higher compression, lower speed).
The implementation is fixed to the default parameters of the original and
provides no facilities for various compression "levels" or an initialization
dictionary.

The decompressor is compatible with data compressed by other LZO1X
implementations.

Usage
-----

```c
#include <lzokay.h>
#include <string.h>
#include <stdlib.h>

int compress_and_decompress(const uint8_t* data, std::size_t length) {
  EResult error;

  /* This variable and 5th parameter of compress() is optional, but may
   * be reused across multiple compression runs; avoiding repeat
   * allocation/deallocation of the work memory used by the compressor.
   */
  struct DictBase_Data dict;

  size_t estimated_size = compress_worst_size(length);
  uint8_t * compressed = malloc(estimated_size);
  size_t compressed_size;
  error = lzokay_compress_dict(data, length, compressed, estimated_size,
                           &compressed_size, &dict);
  if (error < EResult_Success) {
    free(compressed);
    return 1;
  }

  uint8_t * decompressed = malloc(length);
  size_t decompressed_size;
  error = lzokay_decompress(compressed, compressed_size,
                             decompressed, length, &decompressed_size);
  free(compressed);
  if (error < EResult_Success) {
    free(decompressed);
    return 1;
  }

  if (memcmp(data, decompressed, decompressed_size) != 0) {
    free(decompressed);
    return 1;
  }
  free(decompressed);

  return 0;
}
```

License
-------

LZ👌 is available under the
[MIT License](https://github.com/jackoalan/lzokay/blob/master/LICENSE)
and has no external dependencies.
