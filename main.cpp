#include <winsock2.h>
#include <Windows.h>
#include "wiz_msgs.h"
#include "wiz_packet.h"
#include "minhook/MinHook.h"
#include <allocate.h>
#pragma comment(lib, "minhook/VC16/lib/Release/libMinHook.x86.lib")

// use whatever sigscan here, taken from https://www.unknowncheats.me/forum/general-programming-and-reversing/141599-findpattern-real-faster-urs-g3t-ov3r-1t.html
uint32_t dwFindPattern(const unsigned char* pat, const char* msk, unsigned char* pData = (unsigned char*)0x401000)
{
	const unsigned char* end = (const unsigned char* )(pData + 0xffffffff - strlen(msk));
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

int main()
{
	const auto protocols = get_protocols();
	for (auto& p : protocols)
	{
		printf("\n%s -- %s\n", p.protocol_type.c_str(), p.protocol_description.c_str());
		for (auto& m : p.messages)
		{
			printf("	%s - %s\n", m.msg_name.c_str(), m.msg_description.c_str());
			for (auto& a : m.params)
			{
				printf("		%s: %s\n", a.type.c_str(), a.name.c_str());
			}
		}
	}

	const auto adr = dwFindPattern(reinterpret_cast<const unsigned char*>("\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x81\xEC\x00\x00\x00\x00\x53\x55\x56\x57\xA1\x00\x00\x00\x00\x33\xC4\x50\x8D\x84\x24\x00\x00\x00\x00\x64\xA3\x00\x00\x00\x00\x8B\xF1\x83\x7E\x34\x02"), "xxx????xx????xxx????xxxxx????xxxxxx????xx????xxxxxx");
	
	MH_Initialize();
	MH_CreateHook(reinterpret_cast<LPVOID>(adr), &ProcessData_hook, reinterpret_cast<LPVOID*>(&orig_ProcessData)); // AuthenticatedSymmetricCipherBase::ProcessData
	MH_EnableHook(reinterpret_cast<LPVOID>(adr)); // ": message length exceeds maximum"

	const auto wsock32 = GetModuleHandle(L"wsock32.dll");
	if (wsock32) {
		const LPVOID recv_address = GetProcAddress(wsock32, "recv");
		MH_CreateHook(recv_address, &recv_hook, reinterpret_cast<LPVOID*>(&o_recv));
		MH_EnableHook(recv_address);
	}

	const auto w2sock32 = GetModuleHandle(L"Ws2_32.dll");
	if (w2sock32) {
		const LPVOID wsasend_address = GetProcAddress(w2sock32, "WSASend");
		MH_CreateHook(wsasend_address, &wsasend_hook, reinterpret_cast<LPVOID*>(&o_wsasend));
		MH_EnableHook(wsasend_address);
	}
}


BOOL WINAPI DllMain(HMODULE dll, DWORD reason, PVOID reserved) {
	DisableThreadLibraryCalls(static_cast<HMODULE>(dll));

	switch (reason)
	{
	case DLL_PROCESS_ATTACH: {
		AllocConsole();
		freopen("CONOUT$", "w", stdout);
		freopen("CONIN$", "r", stdin);
		CreateThread(nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(main), nullptr, NULL, nullptr);
		break;
	}
	case DLL_PROCESS_DETACH:
		break;
	default:
		break;
	}
	return TRUE;
}