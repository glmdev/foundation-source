#include <lzokay.h>
#include <minilzo.h>
#include <stdio.h>
#include <assert.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdlib.h>
#endif

typedef struct RandomTest RandomTest;
static int InitRandom(RandomTest *rnd);
static int FillRandom(RandomTest *, void *buf, unsigned len);
static void ReleaseRandom(RandomTest *);

#ifdef _WIN32
struct RandomTest
{
    BCRYPT_ALG_HANDLE algo_handle;
};

static int InitRandom(RandomTest *rnd)
{
    NTSTATUS ret = BCryptOpenAlgorithmProvider(&rnd->algo_handle, BCRYPT_RNG_ALGORITHM,
                                               MS_PRIMITIVE_PROVIDER, 0);
    return BCRYPT_SUCCESS(ret);
}

static int FillRandom(RandomTest *rnd, void *buf, unsigned len)
{
    NTSTATUS ret = BCryptGenRandom(rnd->algo_handle, buf, len, 0);
    return BCRYPT_SUCCESS(ret);
}

static void ReleaseRandom(RandomTest *rnd)
{
    BCryptCloseAlgorithmProvider(rnd->algo_handle, 0);
}
#else // !_WIN32
#error unsupported OS for testing
#endif

#define HEAP_ALLOC(var,size) \
    lzo_align_t __LZO_MMODEL var [ ((size) + (sizeof(lzo_align_t) - 1)) / sizeof(lzo_align_t) ]

static HEAP_ALLOC(wrkmem,LZO1X_1_MEM_COMPRESS);

int main(void)
{
    RandomTest init;
    uint16_t test_size;
    uint8_t TestInputBuffer[1 << 16];
    uint8_t TestDecompressedBuffer[1 << 16];
    uint8_t TestOutputBuffer[1 << 17];
    lzo_uint out_size;
    size_t decompressed_size;
    int res;
    lzokay_EResult ores;

    if (lzo_init() != LZO_E_OK)
    {
        fprintf(stderr, "Failed to init minilzo");
        return -1;
    }

    if (!InitRandom(&init)) {
        fprintf(stderr, "Failed to init the random generator");
        return -1;
    }

    test_size = 0;
    if (!FillRandom(&init, &test_size, sizeof(test_size))) {
        fprintf(stderr, "failed to generate the buffer size");
        goto error;
    }

    for (test_size = 1; test_size < 65000; test_size++ )
    {
        assert(test_size <= sizeof(TestInputBuffer));
        if (!FillRandom(&init, TestInputBuffer, test_size)) {
            fprintf(stderr, "failed to generate the random buffer");
            goto error;
        }

        // compress with minilzo
        out_size = sizeof(TestOutputBuffer);
        res = lzo1x_1_compress(TestInputBuffer, test_size, TestOutputBuffer, &out_size, wrkmem);
        if (res != LZO_E_OK)
        {
            fprintf(stderr, "compression failed %d", res);
            goto error;
        }

        decompressed_size = sizeof(TestDecompressedBuffer);
        ores = lzokay_decompress(TestOutputBuffer, out_size, TestDecompressedBuffer, decompressed_size, &decompressed_size);
        if (ores != EResult_Success)
        {
            fprintf(stderr, "decompression failed %d", res);
            goto error;
        }
        if (decompressed_size != test_size)
        {
            fprintf(stderr, "decompressed size (%zd) doesn't match original size (%d)!", decompressed_size, test_size);
            goto error;
        }
        if (memcmp(TestDecompressedBuffer, TestInputBuffer, test_size) != 0)
        {
            fprintf(stderr, "decompressed doesn't match original (size %d)!", test_size);
            goto error;
        }
    }

    fprintf(stdout, "SUCCESS");

error:
    ReleaseRandom(&init);
    return 0;
}
