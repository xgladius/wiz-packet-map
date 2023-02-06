#include <winsock2.h>
#include <Windows.h>
#include "wiz_msgs.h"
#include "wiz_packet.h"
#include "MinHook.h"
#include "sigs.h"

int main()
{
	const auto protocols = get_protocols();

	add_veh_hook();

	MH_Initialize();
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