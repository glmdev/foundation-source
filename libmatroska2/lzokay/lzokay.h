#ifndef LZOKAY_H_INCLUDED
#define LZOKAY_H_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <memory.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
#ifndef inline
#define inline __inline
#endif
#endif

typedef enum {
  EResult_LookbehindOverrun = -4,
  EResult_OutputOverrun = -3,
  EResult_InputOverrun = -2,
  EResult_Error = -1,
  EResult_Success = 0,
  EResult_InputNotConsumed = 1,
} lzokay_EResult;

#define HashSize             0x4000
#define DictBase_MaxDist     0xbfff
#define DictBase_MaxMatchLen  0x800
#define DictBase_BufSize (DictBase_MaxDist + DictBase_MaxMatchLen)

lzokay_EResult lzokay_decompress(const uint8_t* src, size_t src_size,
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

struct lzokay_Dict {
  struct Match3 match3;
  struct Match2 match2;

  /* Circular buffer caching enough data to access the maximum lookback
    * distance of 48K + maximum match length of 2K. An additional 2K is
    * allocated so the start of the buffer may be replicated at the end,
    * therefore providing efficient circular access.
    */
  uint8_t buffer[DictBase_BufSize + DictBase_MaxMatchLen];
};

lzokay_EResult lzokay_compress_dict(const uint8_t* src, size_t src_size,
                 uint8_t* dst, size_t dst_size,
                 size_t* out_size, struct lzokay_Dict* dict_storage);

static inline lzokay_EResult lzokay_compress(const uint8_t* src, size_t src_size,
                 uint8_t* dst, size_t dst_size, size_t* out_size)
{
  struct lzokay_Dict dict;
  return lzokay_compress_dict(src, src_size, dst, dst_size, out_size, &dict);
}

static inline size_t lzokay_compress_worst_size(size_t s) {
  return s + s / 16 + 64 + 3;
}

#ifdef __cplusplus
}
#endif

#endif // LZOKAY_H_INCLUDED
