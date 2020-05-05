#include "lzokay.h"
#include <string.h>
#include <stdlib.h>

int compress_and_decompress(const uint8_t* data, size_t length) {
  EResult error;

  /* This variable and 5th parameter of compress() is optional, but may
   * be reused across multiple compression runs; avoiding repeat
   * allocation/deallocation of the work memory used by the compressor.
   */
  struct DictBase_Data dict;

  size_t compressed_size = compress_worst_size(length);
  uint8_t * compressed = malloc(compressed_size);
  error = lzokay_compress_dict(data, length, compressed, compressed_size,
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

int main(int argc, char** argv) {
  const char* testdata = "Hello World!";
  int ret = compress_and_decompress((const uint8_t*)testdata, 12);
  return ret;
}
