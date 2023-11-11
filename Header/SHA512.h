/*
 *文件名：SHA512.h
 *
 *这个文件是用来计算指定文件和字符串的SHA-512值的
*/

#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <conio.h>
#include <io.h>

std::string get_string_sha512(const std::string &data) {//获取字符串的sha512值
	const unsigned int SHA512_DIGEST_SIZE = 64;
	const unsigned int BLOCK_SIZE = 128;

	// Initialize hash values
	uint64_t h0 = 0x6a09e667f3bcc908;
	uint64_t h1 = 0xbb67ae8584caa73b;
	uint64_t h2 = 0x3c6ef372fe94f82b;
	uint64_t h3 = 0xa54ff53a5f1d36f1;
	uint64_t h4 = 0x510e527fade682d1;
	uint64_t h5 = 0x9b05688c2b3e6c1f;
	uint64_t h6 = 0x1f83d9abfb41bd6b;
	uint64_t h7 = 0x5be0cd19137e2179;

	// Constants defined for SHA-512
	const uint64_t k[] = {
		0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
		0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
		0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
		0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
		0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
		0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
		0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
		0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
		0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
		0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
		0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
		0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
		0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
		0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
		0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
		0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
		0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
		0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
		0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
		0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
	};

	// Preprocessing
	uint64_t bit_length = data.length() * 8;
	uint64_t padding_length = BLOCK_SIZE - ((bit_length + 128) % BLOCK_SIZE);
	if (padding_length < 128) {
		padding_length += BLOCK_SIZE;
	}

	uint8_t *message = new uint8_t[data.length() + padding_length];
	memcpy(message, data.c_str(), data.length());

	message[data.length()] = 0x80;
	for (unsigned int i = data.length() + 1; i < data.length() + padding_length - 16; i++) {
		message[i] = 0x00;
	}

	for (unsigned int i = 0; i < 8; i++) {
		message[data.length() + padding_length - 8 + i] = static_cast<uint8_t>((bit_length >> (56 - i * 8)) & 0xff);
	}

	// Message processing
	for (unsigned int i = 0; i < data.length() + padding_length; i += BLOCK_SIZE) {
		uint64_t w[80];
		for (unsigned int j = 0; j < 16; j++) {
			w[j] = static_cast<uint64_t>(message[i + j * 8]) << 56 |
			       static_cast<uint64_t>(message[i + j * 8 + 1]) << 48 |
			       static_cast<uint64_t>(message[i + j * 8 + 2]) << 40 |
			       static_cast<uint64_t>(message[i + j * 8 + 3]) << 32 |
			       static_cast<uint64_t>(message[i + j * 8 + 4]) << 24 |
			       static_cast<uint64_t>(message[i + j * 8 + 5]) << 16 |
			       static_cast<uint64_t>(message[i + j * 8 + 6]) << 8 |
			       static_cast<uint64_t>(message[i + j * 8 + 7]);
		}

		for (unsigned int j = 16; j < 80; j++) {
			uint64_t s0 = ((w[j - 15] >> 1) | (w[j - 15] << 63)) ^ ((w[j - 15] >> 8) | (w[j - 15] << 56)) ^ (w[j - 15] >> 7);
			uint64_t s1 = ((w[j - 2] >> 19) | (w[j - 2] << 45)) ^ ((w[j - 2] >> 61) | (w[j - 2] << 3)) ^ (w[j - 2] >> 6);
			w[j] = w[j - 16] + s0 + w[j - 7] + s1;
		}

		uint64_t a = h0;
		uint64_t b = h1;
		uint64_t c = h2;
		uint64_t d = h3;
		uint64_t e = h4;
		uint64_t f = h5;
		uint64_t g = h6;
		uint64_t h = h7;

		for (unsigned int j = 0; j < 80; j++) {
			uint64_t s0 = ((a >> 28) | (a << 36)) ^ ((a >> 34) | (a << 30)) ^ ((a >> 39) | (a << 25));
			uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
			uint64_t t2 = s0 + maj;
			uint64_t s1 = ((e >> 14) | (e << 50)) ^ ((e >> 18) | (e << 46)) ^ ((e >> 41) | (e << 23));
			uint64_t ch = (e & f) ^ (~e & g);
			uint64_t t1 = h + s1 + ch + k[j] + w[j];

			h = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		}

		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;
		h5 += f;
		h6 += g;
		h7 += h;
	}

	delete[] message;

	// Produce the final hash value
	std::stringstream ss;
	ss << std::hex << std::setw(16) << std::setfill('0') << h0;
	ss << std::hex << std::setw(16) << std::setfill('0') << h1;
	ss << std::hex << std::setw(16) << std::setfill('0') << h2;
	ss << std::hex << std::setw(16) << std::setfill('0') << h3;
	ss << std::hex << std::setw(16) << std::setfill('0') << h4;
	ss << std::hex << std::setw(16) << std::setfill('0') << h5;
	ss << std::hex << std::setw(16) << std::setfill('0') << h6;
	ss << std::hex << std::setw(16) << std::setfill('0') << h7;

	return ss.str();
}

std::string get_file_sha512(const std::string &file_path, bool USE_NAME) {//获取文件的sha512值
	if (USE_NAME) {
		return file_path;
	}

	std::ifstream file(file_path, std::ios::binary);

	if (!file) {
//		std::cerr << "Failed to open file: " << file_path << std::endl;
		return "";
	}

	std::stringstream buffer;
	buffer << file.rdbuf();
	std::string data = buffer.str();
	file.close();

	const unsigned int SHA512_DIGEST_SIZE = 64;
	const unsigned int BLOCK_SIZE = 128;

	// Initialize hash values
	uint64_t h0 = 0x6a09e667f3bcc908;
	uint64_t h1 = 0xbb67ae8584caa73b;
	uint64_t h2 = 0x3c6ef372fe94f82b;
	uint64_t h3 = 0xa54ff53a5f1d36f1;
	uint64_t h4 = 0x510e527fade682d1;
	uint64_t h5 = 0x9b05688c2b3e6c1f;
	uint64_t h6 = 0x1f83d9abfb41bd6b;
	uint64_t h7 = 0x5be0cd19137e2179;

	// Constants defined for SHA-512
	const uint64_t k[] = {
		0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
		0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
		0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
		0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
		0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
		0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
		0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
		0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
		0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
		0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
		0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
		0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
		0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
		0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
		0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
		0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
		0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
		0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
		0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
		0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
	};

	// Preprocessing
	uint64_t bit_length = data.length() * 8;
	uint64_t padding_length = BLOCK_SIZE - ((bit_length + 128) % BLOCK_SIZE);
	if (padding_length < 128) {
		padding_length += BLOCK_SIZE;
	}

	uint8_t *message = new uint8_t[data.length() + padding_length];
	memcpy(message, data.c_str(), data.length());

	message[data.length()] = 0x80;
	for (unsigned int i = data.length() + 1; i < data.length() + padding_length - 16; i++) {
		message[i] = 0x00;
	}

	for (unsigned int i = 0; i < 8; i++) {
		message[data.length() + padding_length - 8 + i] = static_cast<uint8_t>((bit_length >> (56 - i * 8)) & 0xff);
	}

	// Message processing
	for (unsigned int i = 0; i < data.length() + padding_length; i += BLOCK_SIZE) {
		uint64_t w[80];
		for (unsigned int j = 0; j < 16; j++) {
			w[j] = static_cast<uint64_t>(message[i + j * 8]) << 56 |
			       static_cast<uint64_t>(message[i + j * 8 + 1]) << 48 |
			       static_cast<uint64_t>(message[i + j * 8 + 2]) << 40 |
			       static_cast<uint64_t>(message[i + j * 8 + 3]) << 32 |
			       static_cast<uint64_t>(message[i + j * 8 + 4]) << 24 |
			       static_cast<uint64_t>(message[i + j * 8 + 5]) << 16 |
			       static_cast<uint64_t>(message[i + j * 8 + 6]) << 8 |
			       static_cast<uint64_t>(message[i + j * 8 + 7]);
		}

		for (unsigned int j = 16; j < 80; j++) {
			uint64_t s0 = ((w[j - 15] >> 1) | (w[j - 15] << 63)) ^ ((w[j - 15] >> 8) | (w[j - 15] << 56)) ^ (w[j - 15] >> 7);
			uint64_t s1 = ((w[j - 2] >> 19) | (w[j - 2] << 45)) ^ ((w[j - 2] >> 61) | (w[j - 2] << 3)) ^ (w[j - 2] >> 6);
			w[j] = w[j - 16] + s0 + w[j - 7] + s1;
		}

		uint64_t a = h0;
		uint64_t b = h1;
		uint64_t c = h2;
		uint64_t d = h3;
		uint64_t e = h4;
		uint64_t f = h5;
		uint64_t g = h6;
		uint64_t h = h7;

		for (unsigned int j = 0; j < 80; j++) {
			uint64_t s0 = ((a >> 28) | (a << 36)) ^ ((a >> 34) | (a << 30)) ^ ((a >> 39) | (a << 25));
			uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
			uint64_t t2 = s0 + maj;
			uint64_t s1 = ((e >> 14) | (e << 50)) ^ ((e >> 18) | (e << 46)) ^ ((e >> 41) | (e << 23));
			uint64_t ch = (e & f) ^ (~e & g);
			uint64_t t1 = h + s1 + ch + k[j] + w[j];

			h = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		}

		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;
		h5 += f;
		h6 += g;
		h7 += h;
	}

	delete[] message;

	// Produce the final hash value
	std::stringstream ss;
	ss << std::hex << std::setw(16) << std::setfill('0') << h0;
	ss << std::hex << std::setw(16) << std::setfill('0') << h1;
	ss << std::hex << std::setw(16) << std::setfill('0') << h2;
	ss << std::hex << std::setw(16) << std::setfill('0') << h3;
	ss << std::hex << std::setw(16) << std::setfill('0') << h4;
	ss << std::hex << std::setw(16) << std::setfill('0') << h5;
	ss << std::hex << std::setw(16) << std::setfill('0') << h6;
	ss << std::hex << std::setw(16) << std::setfill('0') << h7;

	return ss.str();
}