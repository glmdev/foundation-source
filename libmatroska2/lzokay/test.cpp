#include "lzokay.hpp"
#include <cstring>

int compress_and_decompress(const uint8_t* data, size_t length) {
  EResult error;

  /* This variable and 5th parameter of compress() is optional, but may
   * be reused across multiple compression runs; avoiding repeat
   * allocation/deallocation of the work memory used by the compressor.
   */
  DictBase_Data dict;

  size_t compressed_size = compress_worst_size(length);
  std::unique_ptr<uint8_t[]> compressed(new uint8_t[compressed_size]);
  error = compress(data, length, compressed.get(), compressed_size,
                           &compressed_size, &dict);
  if (error < EResult_Success)
    return 1;

  std::unique_ptr<uint8_t[]> decompressed(new uint8_t[length]);
  size_t decompressed_size;
  error = decompress(compressed.get(), compressed_size,
                             decompressed.get(), length, &decompressed_size);
  if (error < EResult_Success)
    return 1;

  if (std::memcmp(data, decompressed.get(), decompressed_size) != 0)
    return 1;

  return 0;
}

int main(int argc, char** argv) {
  const char* testdata = "Hello World!";
  int ret = compress_and_decompress(reinterpret_cast<const uint8_t*>(testdata), 12);
  return ret;
}
