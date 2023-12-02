/*
 *文件名：SHA256.h
 *
 *这个文件是用来计算指定文件和字符串的SHA-512值的
*/

#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>

const uint32_t kSHA256BlockSize = 64;
const uint32_t kSHA256HashSize = 32;
const uint32_t kSHA256RoundCount = 64;
const uint32_t kSHA256IV[] = {
	0x6a09e667u, 0xbb67ae85u,
	0x3c6ef372u, 0xa54ff53au,
	0x510e527fu, 0x9b05688cu,
	0x1f83d9abu, 0x5be0cd19u
};

// SHA-256 constants
const uint32_t k[] = {
	0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
	0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
	0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
	0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
	0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
	0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
	0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
	0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
	0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
	0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
	0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
	0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
	0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
	0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
	0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
	0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

// SHA-256 functions
inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
	return (x & y) ^ (~x & z);
}

inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
	return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t rotr(uint32_t x, uint32_t n) {
	return (x >> n) | (x << (32 - n));
}

inline uint32_t shr(uint32_t x, uint32_t n) {
	return x >> n;
}

inline uint32_t sigma0(uint32_t x) {
	return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint32_t sigma1(uint32_t x) {
	return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint32_t gamma0(uint32_t x) {
	return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3);
}

inline uint32_t gamma1(uint32_t x) {
	return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10);
}

void sha256_block(const uint8_t *block, uint32_t *state) {
	uint32_t w[64];
	for (uint32_t i = 0; i < 16; i++) {
		w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) |
		       (block[i * 4 + 2] << 8) | block[i * 4 + 3];
	}
	for (uint32_t i = 16; i < kSHA256RoundCount; i++) {
		w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
	}
	uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
	uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
	for (uint32_t i = 0; i < kSHA256RoundCount; i++) {
		uint32_t t1 = h + sigma1(e) + ch(e, f, g) + k[i] + w[i];
		uint32_t t2 = sigma0(a) + maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}

std::string calculate_file_sha256(const std::string &path, bool USE_NAME) {
	if (USE_NAME) {
		return path;
	}

	std::ifstream file(path, std::ios::binary);
	if (!file) {
		std::cerr << "failed to open file: " << path << '\n';
		return "";
	}
	uint32_t state[kSHA256HashSize / sizeof(uint32_t)];
	for (uint32_t i = 0; i < kSHA256HashSize / sizeof(uint32_t); i++) {
		state[i] = kSHA256IV[i];
	}
	const uint32_t bufSize = 64 * 1024;
	uint8_t buffer[bufSize];
	while (file) {
		file.read(reinterpret_cast<char *>(buffer), bufSize);
		sha256_block(buffer, state);
	}
	std::ostringstream result;
	result << std::hex << std::setfill('0');
	for (const uint32_t i : state) {
		result << std::setw(8) << i;
	}
	return result.str();
}