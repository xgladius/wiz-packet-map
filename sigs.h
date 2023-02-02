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

template< typename T > std::array< unsigned char, sizeof(T) >  to_bytes(const T& object)
{
	std::array< unsigned char, sizeof(T) > bytes;

	const unsigned char* begin = reinterpret_cast<const unsigned char*>(std::addressof(object));
	const unsigned char* end = begin + sizeof(T);
	std::copy(begin, end, std::begin(bytes));

	return bytes;
}

template< typename T >
T& from_bytes(const std::array< unsigned char, sizeof(T) >& bytes, T& object)
{
	// http://en.cppreference.com/w/cpp/types/is_trivially_copyable
	static_assert(std::is_trivially_copyable<T>::value, "not a TriviallyCopyable type");

	unsigned char* begin_object = reinterpret_cast<unsigned char*>(std::addressof(object));
	std::copy(std::begin(bytes), std::end(bytes), begin_object);

	return object;
}
// get references to AuthenticatedSymmetricCipherBase::ProcessData
std::vector<uint32_t> get_vf_references() {
	std::vector<uint32_t> ret;

	uintptr_t wizardgraphicalclient_base = reinterpret_cast<uintptr_t>(GetModuleHandleA(NULL));
	uintptr_t ProcessDataAddress = pattern_scan(NULL, "40 53 55 56 57 41 54 41 56 41 57 48 81 EC ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 ?? ?? ?? ?? 49 8B F1");
	const auto pd_bytes = to_bytes((ProcessDataAddress));
	std::stringstream ss;
	ss << std::hex << std::setfill('0');
	for (int i = 0; i < 8; i++)
	{
		ss << std::setw(2) << int(pd_bytes[i]) << ' ';
	}
	const char* pd_bytes_string = ss.str().c_str();
	uintptr_t ProcessDataRef1 = pattern_scan(NULL, pd_bytes_string);
	uintptr_t ProcessDataRef2 = pattern_scan(NULL, pd_bytes_string, (ProcessDataRef1 - wizardgraphicalclient_base) + 0x8);

	ret.push_back(ProcessDataRef1);
	ret.push_back(ProcessDataRef2);
	
	return ret;
}