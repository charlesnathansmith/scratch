#include <iostream>
#include <string>
#include "sha1.h"
#include "sha512.h"

const wchar_t pw[] = L"123456";

void print_buffer(uint8_t* buf, size_t size)
{
    for (size_t i = 0; i < size; i++)
        printf("%.2X ", buf[i] & 0xff);

    putchar('\n');
}

void unkhash1_helper(uint64_t* hash)
{
    // Equivalent to function at file offset 26FD20 in em039_64.dll
    // The first 5 constants are the same as those used in the parent function
    // I'll need to run possible input ranges through z3 or something to prove it, but I don't think this ever actually does anything
    static const uint64_t constants[6] = { 0x12631A5CF5D3ED, 0xF9DEA2F89CD658, 0x14DE, 0, 0x1000000000, 0x75252e };

    uint64_t buf[4];
    uint64_t cur = constants[0];

    // Similar to hash loop in parent but values are stored in an intermediate buffer
    for (size_t i = 0; i < 4; i++)
    {
        uint64_t tmp = (hash[i] - cur) >> 0x3f;
        buf[i] = hash[i] + (tmp << 0x38) - cur;
        cur = constants[i + 1] + tmp;
    }

    /*
    puts("\nhelper intermeds buffer");
    print_buffer((uint8_t*)buf, 32);
    */

    uint64_t tmp = (hash[4] - cur) >> 0x3f;

    hash[0] ^= (hash[0] ^ buf[0]) & (tmp - 1);
    hash[1] ^= (hash[1] ^ buf[1]) & (tmp - 1);
    hash[2] ^= (hash[2] ^ buf[2]) & (tmp - 1);
    hash[3] ^= (hash[3] ^ buf[3]) & (tmp - 1);

    uint64_t tmp2 = hash[4] + ((tmp << 0x20) - cur);
    hash[4] ^= (hash[4] ^ tmp2) & (tmp - 1);
}

void unkhash1(uint8_t* out, uint8_t* in)
{
    // Corresponds roughly to file offset 0x270318
    uint64_t hash[5];

    // Split the first 32 bytes of the input buffer into 5 48-bit numbers
    hash[0] = *((uint64_t*)&in[0]) & 0xffffffffffffff;
    hash[1] = *((uint64_t*)&in[7]) & 0xffffffffffffff;
    hash[2] = *((uint64_t*)&in[14]) & 0xffffffffffffff;
    hash[3] = *((uint64_t*)&in[21]) & 0xffffffffffffff;
    hash[4] = *((uint64_t*)&in[28]) & 0xffffffff;

    puts("\nBuffer split into 48-bit values");
    print_buffer((uint8_t*)hash, 40);

    // Very reduced version of file offset 26fdec, possible because of underutilization on their part

    // Only one byte of the input is used to as an entropy seed
    // And it gets shifted in such a way that only a nib of it gets used in calculations
    uint64_t entropy = ((in[31] & 0xff) * 0x0FFFFFFFFF) >> 0x28;

    // This next part was designed to be really complicated for a large entropy value,
    // with bits from the overflowing portion of each multiplication getting used in the next calculation
    // But since they always use such a small entropy value, the multiplications never overflow,
    // most of the calculations reduce to 0, and the whole thing simplifies dramatically
    uint64_t modifier[5];

    modifier[0] = (0x12631A5CF5D3ED * entropy) & 0x0FFFFFFFFFFFFFF;
    uint64_t tmp1 = 0xF9DEA2F79CD658 * entropy;
    modifier[1] = tmp1 & 0x0FFFFFFFFFFFFFF;
    modifier[2] = ((0x14DE * entropy) + (tmp1 >> 0x38)) & 0x0FFFFFFFFFFFFFF;
    modifier[3] = 0;
    modifier[4] = (entropy * 0x10000000) & 0xFFFFFFFFFF;

    /*
    puts("\nmodifiers");
    print_buffer((uint8_t*)modifier, 40);
    */

    // The calculated modifiers are used to hash the 48-bit numbers created from the input
    uint64_t cur = modifier[0];

    // Hash first 4 numbers
    for (size_t i = 0; i < 4; i++)
    {
        uint64_t tmp2 = (hash[i] - cur) >> 0x3f;
        hash[i] += (tmp2 << 0x38) - cur;
        cur = tmp2 + modifier[i + 1];
    }

    // The last one gets special attention but uses final cur value from the loop
    hash[4] += (((hash[4] - cur) >> 0x3f) << 0x28) - cur;

    /*
    puts("\nhashed before helpers");
    print_buffer((uint8_t*)hash, 40);
    */

    // Calls this sub-hash twice which is a variation on the one we just performed
    // I'm not sure it ever actually has an effect
    unkhash1_helper(hash);

    /*
    puts("\nhashed after first helper call");
    print_buffer((uint8_t*)hash, 40);
    */

    unkhash1_helper(hash);

    /*
    puts("\nhashed after second helper call");
    print_buffer((uint8_t*)hash, 40);
    */
    memcpy(out, hash, 40);
}

void unkhash2_sub1(uint8_t e1, uint8_t e2)
{
}

void unkhash2(uint64_t* in)
{
    uint8_t buf[64];
    size_t buf_pos = 0;

    // Expand input buffer into nibs
    for (size_t i = 0; i < 5; i++)
    {
        uint64_t tmp = in[i];
        size_t good_nibs = (i != 4) ? 14 : 8;

        for (size_t j = 0; j < good_nibs; j++)
        {
            buf[buf_pos++] = tmp & 0xf;
            tmp >>= 4;
        }
    }

    puts("\nunkhash2 expanded buffer");
    print_buffer(buf, 64);

    // Some sort of carried subtraction across the entire buffer
    uint8_t c = 0;

    for (size_t i = 0; i < 63; i++)
    {
        c += buf[i];
        buf[i + 1] += (int64_t) c / 16; // signed divide
        
        uint8_t c2 = c = c & 0xf;
        c >>= 3;
        buf[i] = c2 - (c << 4);
    }

    buf[63] += c;

    puts("\nunkhash2 manipulated buffer");
    print_buffer(buf, 64);


}

int main()
{
    static const uint8_t hard_bytes[] = "\xE4\x62\x2C\xDB\x5F\xA8\x45\x1E\xA9\xBE\x3D\xB6\xC3\x2F\x06\xA5"
                                        "\xDD\x51\xB1\x9E\x1D\x47\x4A\x12\x5C\xDC\x7B\xAB\xB4\x07\xCB\xC4";

    ///////////////
    // Setup
    ///////////////
    
    SHA1_CTX sha;

    // Final hash
    uint8_t hash[20], fin_hash[40];
    memset(hash, 0, 20);

    // Buffers repeatedly used during hashing loop
    uint8_t pw_digest[3][64];

    // SHA-1 digest of widechar-format password if necessary to shrink it,
    // otherwise use as is. Padded to 64 bytes with 00
    size_t pw_len = wcslen(pw);
    memset(pw_digest, 0, 64);

    if (pw_len > 32)
    {
            SHA1Init(&sha);
            SHA1Update(&sha, (uint8_t*)pw, pw_len * 2);
            SHA1Final(pw_digest[0], &sha);
    }
    else
    {
        memcpy(pw_digest, pw, pw_len * 2);
    }

    // XOR-encoded versions of password digest
    for (size_t i = 0; i < 64; i++)
    {
        char c = pw_digest[0][i] ^ 0x36;
        pw_digest[1][i] = c;
        pw_digest[2][i] = c ^ 0x6A;
    }

    puts("Password digest");
    print_buffer(pw_digest[0], 64);

    puts("\nPassword digest ^ 0x36");
    print_buffer(pw_digest[1], 64);

    puts("\nPassword digest ^ 0x36 ^ 0x6A");
    print_buffer(pw_digest[2], 64);

    // Intermediate digests
    uint8_t intermed[2][64];

    SHA1Init(&sha);
    SHA1Update(&sha, pw_digest[1], 64);
    SHA1Update(&sha, hard_bytes, 32);
    SHA1Update(&sha, (const uint8_t *) "\x00\x00\x00\x01", 4);

    for (size_t loop_count = 0; loop_count < 10000; loop_count++)
    {
        SHA1Final(intermed[0], &sha);

        SHA1Init(&sha);
        SHA1Update(&sha, pw_digest[2], 64);
        SHA1Update(&sha, intermed[0], 20);
        SHA1Final(intermed[1], &sha);

        // Update hash
        for (size_t i = 0; i < 20; i++)
            hash[i] ^= intermed[1][i];

        SHA1Init(&sha);
        SHA1Update(&sha, pw_digest[1], 64);
        SHA1Update(&sha, intermed[1], 20);
    }

    printf("\nhash0:\t");
    print_buffer(hash, 20);

    memcpy(fin_hash, hash, 20);
    memset(hash, 0, 20);

    SHA1Init(&sha);
    SHA1Update(&sha, pw_digest[1], 64);
    SHA1Update(&sha, hard_bytes, 32);
    SHA1Update(&sha, (const uint8_t*)"\x00\x00\x00\x02", 4);

    for (size_t loop_count = 0; loop_count < 10000; loop_count++)
    {
        SHA1Final(intermed[0], &sha);

        SHA1Init(&sha);
        SHA1Update(&sha, pw_digest[2], 64);
        SHA1Update(&sha, intermed[0], 20);
        SHA1Final(intermed[1], &sha);

        // Update hash
        for (size_t i = 0; i < 20; i++)
            hash[i] ^= intermed[1][i];

        SHA1Init(&sha);
        SHA1Update(&sha, pw_digest[1], 64);
        SHA1Update(&sha, intermed[1], 20);
    }

    printf("hash1:\t");
    print_buffer(hash, 20);
    memcpy(fin_hash + 20, hash, 32 - 20);

    printf("combined hash:\t");
    print_buffer(fin_hash, 32);

    // SHA-512 hashing
    uint8_t sha512_digest[64];
    SHA512Digest(sha512_digest, fin_hash, 32);

    puts("\nSHA512");
    print_buffer(sha512_digest, 64);
    
    // Two bytes are modified in preparation for the next stage
    sha512_digest[0] &= 0xf8;
    sha512_digest[0x1f] = (sha512_digest[0x1f] & 0x3f) | 0x40;

    puts("\nunkhash1 input");
    print_buffer(sha512_digest, 32);

    uint8_t unkhash1_buf[sizeof(uint64_t) * 5];
    unkhash1(unkhash1_buf, sha512_digest);

    puts("\nunkhash1 output");
    print_buffer(unkhash1_buf, 40);

    unkhash2((uint64_t*)unkhash1_buf);

    return 0;
}
