#pragma once

#include <zlib.h>
#include <tomcrypt.h>

#define CHUNK 16384

static size_t zlib_uncompressed_size(int uncomp_size) {
    int n16kBlocks = (uncomp_size + (CHUNK - 1)) / CHUNK; // round up any fraction of a block
    return (uncomp_size + 6 + (n16kBlocks * 5));
}

#include <cstring>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <bit>

//! Byte swap unsigned short
uint16_t swap_uint16(uint16_t val) {
    return (val << 8) | (val >> 8);
}

//! Byte swap unsigned int
uint32_t swap_uint32(uint32_t val) {
    val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
    return (val << 16) | (val >> 16);
}

uint64_t swap_uint64(uint64_t val) {
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL) | ((val >> 8) & 0x00FF00FF00FF00FFULL);
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL) | ((val >> 16) & 0x0000FFFF0000FFFFULL);
    return (val << 32) | (val >> 32);
}

static const uint8_t sWiiUFastFileKey[] = { 0xB3, 0xBD, 0x6B, 0x2C, 0x82, 0x42, 0x8D, 0x11, 0xB8, 0x88, 0x2D,
                                            0x4C, 0x6D, 0x18, 0xCC, 0x79, 0xE2, 0x70, 0x9F, 0x6B, 0xD4, 0x39,
                                            0x91, 0x35, 0xFD, 0xDE, 0x14, 0xE6, 0x8F, 0x3A, 0xBC, 0xCE };

class FastFile {

  public:
    enum Version : uint32_t {
        PC = 0x93,
        WiiU = 0x94,
    };

    enum Endian : uint8_t {
        Big = 0,
        Little = 1,
    };

    enum Magic : uint64_t {
        Signed = 0x5441666630313030,   // TAff0100
        Unsigned = 0x5441666675313030, // TAffu100
    };

  private:
    static const uint8_t* GetPlatformKey(Version ver) {
        if (ver == WiiU) {
            return sWiiUFastFileKey;
        } else {
            std::printf("No key for this platform.\n");
            std::exit(-1);
        }
    }

    static constexpr bool is_little_endian = std::endian::native == std::endian::little;
    static constexpr bool is_big_endian = std::endian::native == std::endian::big;

    std::ifstream in_stream;
    std::ofstream out_stream;

    Version source_ver = PC;
    Version target_ver = WiiU;

    bool in_swap;
    bool out_swap;

    uint8_t iv[8];
    uint32_t iv_counter[4];
    uint8_t* iv_table = nullptr;

  public:
    FastFile(std::string filepath, Version src_ver, Version tgt_ver, Endian source, Endian target)
        : source_ver(src_ver), target_ver(tgt_ver) {
        in_stream = std::ifstream(filepath, std::ios::binary);
        out_stream = std::ofstream(filepath + ".zone", std::ios::binary);

        if (source == Endian::Big && is_big_endian) {
            in_swap = false;
        } else {
            in_swap = true;
        }

        if (target == Endian::Big && is_big_endian) {
            out_swap = false;
        } else {
            out_swap = true;
        }

        iv_table = new uint8_t[0x4000];
    }

    uint8_t read8() {
        uint8_t c;
        in_stream.read(reinterpret_cast<char*>(&c), sizeof(c));
        return c;
    }

    uint16_t read16() {
        uint16_t c;
        in_stream.read(reinterpret_cast<char*>(&c), sizeof(c));
        if (in_swap) {
            c = swap_uint16(c);
        }
        return c;
    }

    uint32_t read32() {
        uint32_t c;
        in_stream.read(reinterpret_cast<char*>(&c), sizeof(c));
        if (in_swap) {
            c = swap_uint32(c);
        }
        return c;
    }

    uint64_t read64() {
        uint64_t c;
        in_stream.read(reinterpret_cast<char*>(&c), sizeof(c));
        if (in_swap) {
            c = swap_uint64(c);
        }
        return c;
    }

    void ValidateHeader() {

        uint64_t magic = read64();
        if (magic != Magic::Signed && magic != Magic::Unsigned) {
            std::printf("Header magic is invalid! (0x%016llX)", magic);
            std::exit(-1);
        }

        uint32_t version = read32();
        if (version != target_ver) {
            std::printf("FastFile version is invalid! (0x%08x, but expected 0x%08x)", version, target_ver);
            std::exit(-1);
        }
    }

    void Decrypt() {

        in_stream.seekg(0x18);

        /* IV Table setup */

        for (int i = 0; i < 4; i++) {
            iv_counter[i] = 1;
        }

        char buffer[32];
        in_stream.read(buffer, 32);
        FillIVTable(buffer);

        // Skip RSA signature, we can't guess the private key, just patch the rsa check.
        in_stream.seekg(0x138);

        int section_idx = 0;
        while (true) {

            size_t filesize = read32();
            if (filesize == 0) {
                std::printf("Next section has size %d, quiting.\n", filesize);
                break;
            }
            size_t uncompressed_filesize = filesize * 32;

            uint8_t* buffer = new uint8_t[filesize];
            uint8_t* decompress_buffer = new uint8_t[uncompressed_filesize];
            in_stream.read((char*)buffer, filesize);

            /* Decrypt data */
            salsa20_memory(GetPlatformKey(source_ver), 32, 20, GetIV(section_idx % 4), 8, 0, buffer, filesize, buffer);

            /* Decompress data */
            z_stream d_stream;
            memset(&d_stream, 0, sizeof(d_stream));
            d_stream.next_in = buffer;
            d_stream.avail_in = filesize;
            d_stream.next_out = decompress_buffer;
            d_stream.avail_out = uncompressed_filesize;

            inflateInit2_(&d_stream, -13, ZLIB_VERSION, sizeof(d_stream));
            inflate(&d_stream, Z_NO_FLUSH);
            inflateEnd(&d_stream);

            /* Update IV table */
            uint8_t hash[20];
            hash_state sha_st;
            sha1_init(&sha_st);
            sha1_process(&sha_st, (const uint8_t*)buffer, filesize);
            sha1_done(&sha_st, hash);
            UpdateIVTable(section_idx % 4, hash);

            out_stream.write((char*)decompress_buffer, d_stream.total_out);
            std::printf("Wrote section %d -> %d bytes (uncomp %d)\n", section_idx, filesize, d_stream.total_out);

            delete[] buffer;
            delete[] decompress_buffer;
            section_idx++;
        }
    }

  private:
    void FillIVTable(const char* ff_name) {
        size_t ff_name_len = std::strlen(ff_name);
        int addDiv = 0;
        for (int i = 0; i < 0x4000; i += ff_name_len * 4) {
            for (int x = 0; x < ff_name_len * 4; x += 4) {
                if ((i + addDiv) >= 0x4000 || i + x >= 0x4000)
                    return;

                if (x > 0)
                    addDiv = x / 4;
                else
                    addDiv = 0;

                for (int y = 0; y < 4; y++)
                    this->iv_table[i + x + y] = ff_name[addDiv];
            }
        }
    }

    uint8_t* GetIV(int idx) {
        int array_idx = (idx + 4 * (iv_counter[idx] - 1)) % 800 * 20;
        std::memcpy(iv, &iv_table[array_idx], 8);
        return iv;
    }

    void UpdateIVTable(int idx, uint8_t* sha1_hash) {
        for (int i = 0; i < 20; i += 5) {
            int value = (idx + 4 * iv_counter[idx]) % 800 * 5;
            for (int x = 0; x < 5; x++)
                iv_table[4 * value + x + i] ^= sha1_hash[i + x];
        }
        iv_counter[idx]++;
    }
};