#include <winsock2.h>
#include <Windows.h>
#include "wiz_msgs.h"
#include "wiz_packet.h"
#include "minhook/MinHook.h"
#pragma comment(lib, "minhook/VC16/lib/Release/libMinHook.x86.lib")

int main()
{
	const auto protocols = get_protocols();
	for (auto &p : protocols)
	{
		printf("\n%s -- %s\n", p.protocol_type.c_str(), p.protocol_description.c_str());
		for (auto &m : p.messages)
		{
			printf("	%s - %s\n", m.msg_name.c_str(), m.msg_description.c_str());
			for (auto &a : m.params)
			{
				printf("		%s: %s\n", a.type.c_str(), a.name.c_str());
			}
		}
	}
	
	MH_Initialize();
	MH_CreateHook(reinterpret_cast<LPVOID>(rebase(0x4396C0)), &ProcessData_hook, reinterpret_cast<LPVOID*>(&orig_ProcessData)); // AuthenticatedSymmetricCipherBase::ProcessData
	MH_EnableHook(reinterpret_cast<LPVOID>(rebase(0x4396C0))); // ": message length exceeds maximum"

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