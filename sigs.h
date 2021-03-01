#pragma once
#include <cstddef>
#include <apiquery2.h>
#include <intrin.h>
#include <cmath>
#include <cstdint>
#include <vector>
#include <string>

// use whatever sigscan here, taken from https://www.unknowncheats.me/forum/general-programming-and-reversing/141599-findpattern-real-faster-urs-g3t-ov3r-1t.html
uint32_t dwFindPattern(const unsigned char* pat, const char* msk, unsigned char* pData = (unsigned char*)0x401000)
{
	const unsigned char* end = (const unsigned char*)(pData + 0xffffffff - strlen(msk));
	int num_masks = ceil((float)strlen(msk) / (float)16);
	int masks[32]; //32*16 = enough masks for 512 bytes
	memset(masks, 0, num_masks * sizeof(int));
	for (int i = 0; i < num_masks; ++i)
		for (int j = strnlen(msk + i * 16, 16) - 1; j >= 0; --j)
			if (msk[i * 16 + j] == 'x')
				masks[i] |= 1 << j;

	__m128i xmm1 = _mm_loadu_si128((const __m128i*) pat);
	__m128i xmm2, xmm3, mask;
	for (; pData != end; _mm_prefetch((const char*)(++pData + 64), _MM_HINT_NTA)) {
		if (pat[0] == pData[0]) {
			xmm2 = _mm_loadu_si128((const __m128i*) pData);
			mask = _mm_cmpeq_epi8(xmm1, xmm2);
			if ((_mm_movemask_epi8(mask) & masks[0]) == masks[0]) {
				for (int i = 1; i < num_masks; ++i) {
					xmm2 = _mm_loadu_si128((const __m128i*) (pData + i * 16));
					xmm3 = _mm_loadu_si128((const __m128i*) (pat + i * 16));
					mask = _mm_cmpeq_epi8(xmm2, xmm3);
					if ((_mm_movemask_epi8(mask) & masks[i]) == masks[i]) {
						if ((i + 1) == num_masks)
							return (DWORD)pData;
					}
					else goto cont;
				}
				return (DWORD)pData;
			}
		}cont:;
	}
	return NULL;
}

// get references to AuthenticatedSymmetricCipherBase::ProcessData
std::vector<uint32_t> get_vf_references() {
	std::vector<uint32_t> ret;

	const auto adr = dwFindPattern(reinterpret_cast<const unsigned char*>("\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x81\xEC\x00\x00\x00\x00\x53\x55\x56\x57\xA1\x00\x00\x00\x00\x33\xC4\x50\x8D\x84\x24\x00\x00\x00\x00\x64\xA3\x00\x00\x00\x00\x8B\xF1\x83\x7E\x34\x02"), "xxx????xx????xxx????xxxxx????xxxxxx????xx????xxxxxx");
	const auto le_num = _byteswap_ulong(adr);
	std::vector<uint8_t> le_arr(4);
	for (auto i = 0; i < 4; i++)
		le_arr[3 - i] = le_num >> i * 8;
	const std::string le_string(le_arr.begin(), le_arr.end());

	ret.push_back(dwFindPattern(reinterpret_cast<const unsigned char*>(le_string.c_str()), "xxxx"));
	ret.push_back(dwFindPattern(reinterpret_cast<const unsigned char*>(le_string.c_str()), "xxxx", reinterpret_cast<unsigned char*>(ret.back() + 0x4)));
	
	return ret;
}