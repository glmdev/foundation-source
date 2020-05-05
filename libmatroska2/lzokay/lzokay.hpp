#pragma once
#include <cstddef>
#include <cstdint>
#include <memory>

extern "C" {

typedef enum {
  EResult_LookbehindOverrun = -4,
  EResult_OutputOverrun = -3,
  EResult_InputOverrun = -2,
  EResult_Error = -1,
  EResult_Success = 0,
  EResult_InputNotConsumed = 1,
} EResult;

static const uint32_t HashSize = 0x4000;
static const uint32_t DictBase_MaxDist = 0xbfff;
static const uint32_t DictBase_MaxMatchLen = 0x800;
static const uint32_t DictBase_BufSize = DictBase_MaxDist + DictBase_MaxMatchLen;

static size_t compress_worst_size(size_t s) {
  return s + s / 16 + 64 + 3;
}

EResult decompress(const uint8_t* src, size_t src_size,
                   uint8_t* dst, size_t dst_size,
                   size_t* out_size);

/* List encoding of previous 3-byte data matches */
struct Match3 {
  uint16_t head[HashSize]; /* key -> chain-head-pos */
  uint16_t chain_sz[HashSize]; /* key -> chain-size */
  uint16_t chain[DictBase_BufSize]; /* chain-pos -> next-chain-pos */
  uint16_t best_len[DictBase_BufSize]; /* chain-pos -> best-match-length */
};
/* Encoding of 2-byte data matches */
struct Match2 {
  uint16_t head[1 << 16]; /* 2-byte-data -> head-pos */
};

struct DictBase_Data {
  Match3 match3;
  Match2 match2;

  /* Circular buffer caching enough data to access the maximum lookback
    * distance of 48K + maximum match length of 2K. An additional 2K is
    * allocated so the start of the buffer may be replicated at the end,
    * therefore providing efficient circular access.
    */
  uint8_t buffer[DictBase_BufSize + DictBase_MaxMatchLen];
};
}; // "C"

namespace lzokay {

class DictBase {
public:
  DictBase_Data* _storage;
  DictBase() = default;
protected:
  friend EResult compress(const uint8_t* src, size_t src_size,
                          uint8_t* dst, size_t* dst_size, DictBase& dict);
};
template <template<typename> class _Alloc = std::allocator>
class Dict : public DictBase {
  _Alloc<DictBase_Data> _allocator;
public:
  Dict() { _storage = _allocator.allocate(1); }
  ~Dict() { _allocator.deallocate(_storage, 1); }
};

EResult compress(const uint8_t* src, size_t src_size,
                 uint8_t* dst, size_t dst_size,
                 size_t* out_size, DictBase& dict);
inline EResult compress(const uint8_t* src, size_t src_size,
                        uint8_t* dst, size_t dst_size,
                        size_t* out_size) {
  Dict<> dict;
  return compress(src, src_size, dst, dst_size, out_size, dict);
}

}
