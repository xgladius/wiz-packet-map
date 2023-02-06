#pragma once
#include <cstddef>
#include <apiquery2.h>
#include <intrin.h>
#include <cmath>
#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <iomanip>

inline uintptr_t pattern_scan(const char* module, const char* pattern, uintptr_t offset = 0) {

#define in_range(x, a, b) (x >= a && x <= b)
#define get_bits(x) (in_range((x & (~0x20)), 'A', 'F') ? ((x & (~0x20)) - 'A' + 0xA): (in_range(x, '0', '9') ? x - '0': 0))
#define get_byte(x) (get_bits(x[0]) << 4 | get_bits(x[1]))

	MODULEINFO mod;
	GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(module), &mod, sizeof(MODULEINFO));
	uintptr_t start = (uintptr_t)mod.lpBaseOfDll + offset;
	uintptr_t end = (uintptr_t)mod.lpBaseOfDll + (uintptr_t)mod.SizeOfImage;
	uintptr_t match = 0;
	const char* current = pattern;

	for (uintptr_t pCur = start; pCur < end; pCur++) {

		if (!*current)
			return match;

		if (*(PBYTE)current == ('\?') || *(BYTE*)pCur == get_byte(current)) {
			if (!match)
				match = pCur;

			if (!current[2])
				return match;

			if (*(PWORD)current == ('\?\?') || *(PBYTE)current != ('\?'))
				current += 3;
			else
				current += 2;
		}
		else {
			current = pattern;
			match = 0;
		}
	}
	return 0;
}

void add_veh_hook() {
	uintptr_t ProcessDataAddress = pattern_scan(NULL, "40 53 55 56 57 41 54 41 56 41 57 48 81 EC ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 ?? ?? ?? ?? 49 8B F1");
	orig_ProcessData = reinterpret_cast<og_ProcessData>(ProcessDataAddress);
	AddVectoredExceptionHandler(true, ExceptionHandler);
}