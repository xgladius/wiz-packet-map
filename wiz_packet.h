#pragma once
#include <winsock2.h>
#include <windows.h>
#include <vector>
#include "wiz_msgs.h"	
#include <polyhook2/IHook.hpp>
#include <polyhook2/Detour/ADetour.hpp>
#include <emmintrin.h>

enum class packet_mode
{
	none,
	sent,
	sent_encrytped,
	recieved,
	recieved_encrypted
};

#pragma pack(push, 1)
struct wiz_packet {
	unsigned __int16 header; // 0xFOOD
	unsigned __int16 size; // size of packet including header
	byte is_control; // 0 == DML
	byte opcode;
	unsigned __int16 padding;
	byte service_id;
	byte message_type;
	__int16 length;
};
#pragma pack(pop)

class packet_helper {

public:
	packet_helper() {
		protocols_ = get_protocols();
	}

	protocol_info get_protocol_from_id(const uint8_t id)
	{
		for (auto p : protocols_) {
			if (id == p.service_id)
				return p;
		}
		return {};
	}
private:
	std::vector<protocol_info> protocols_;
};

template<class T>
T read(char*& buf, const bool inc = true)
{
	const T ret = *reinterpret_cast<T*>(buf);
	if (inc)
		buf += sizeof(T);
	return ret;
}

packet_helper helper;

void handle_packet(std::vector<char>& full, packet_mode mode) {
	auto* buf = full.data();
	const auto packet_ = read<wiz_packet>(buf, false);

	std::vector<uint8_t> newbuf;
	std::copy(full.begin(), full.end(), back_inserter(newbuf));

	if (packet_.is_control) {
		return;
	}

	const auto packet = read<wiz_packet>(buf);

	const auto svc = helper.get_protocol_from_id(packet.service_id);

	if (packet.message_type > 254 || !svc.service_id || packet.message_type > svc.messages.size())
	{
		printf("invalid message type, or svc id\n");
		return;
	}

	auto msg = svc.messages.at(packet.message_type);

	std::string mode_str;
	switch (mode)
	{
	case packet_mode::sent:
		mode_str = "Sent";
		break;
	case packet_mode::sent_encrytped:
		mode_str = "Sent Encrypted";
		break;
	case packet_mode::recieved:
		mode_str = "Recieved";
		break;
	case packet_mode::recieved_encrypted:
		mode_str = "Recieved Encrypted";
		break;
	}

	printf("[%s] %s [%x] %s (%s)\n", mode_str.c_str(), svc.protocol_type.c_str(), packet.message_type, msg.msg_name.c_str(), msg.msg_description.c_str());
	for (auto& msg_arg : msg.params) {
		if (msg_arg.type == "UBYT") {
			printf("	%s %s %x\n", msg_arg.type.c_str(), msg_arg.name.c_str(), read<uint8_t>(buf));
			continue;
		}
		else if (msg_arg.type == "BYT") {
			printf("	%s %s %x\n", msg_arg.type.c_str(), msg_arg.name.c_str(), read<int8_t>(buf));
			continue;
		}
		else if (msg_arg.type == "UINT") {
			printf("	%s %s %x\n", msg_arg.type.c_str(), msg_arg.name.c_str(), read<unsigned int>(buf));
			continue;
		}
		else if (msg_arg.type == "INT") {
			printf("	%s %s %x\n", msg_arg.type.c_str(), msg_arg.name.c_str(), read<int>(buf));
			continue;
		}
		else if (msg_arg.type == "STR") {
			const auto str_size = read<int16_t>(buf);
			if (str_size == 0 || str_size >= packet.size || str_size < 0)
				continue;

			std::vector<char> str(str_size);
			memcpy(str.data(), buf, str_size);
			str.push_back('\0');

			printf("	%s %s %s\n", msg_arg.type.c_str(), msg_arg.name.c_str(), str.data());
			buf += str_size;
			continue;
		}
		else if (msg_arg.type == "GID") {
			printf("	%s %s %lld\n", msg_arg.type.c_str(), msg_arg.name.c_str(), read<long long>(buf));
		}
		else if (msg_arg.type == "USHRT")
		{
			printf("	%s %s %x\n", msg_arg.type.c_str(), msg_arg.name.c_str(), read<unsigned short>(buf));
		}
		else if (msg_arg.type == "SHRT")
		{
			printf("	%s %s %x\n", msg_arg.type.c_str(), msg_arg.name.c_str(), read<short>(buf));
		}
		else if (msg_arg.type == "FLT")
		{
			printf("	%s %s %ff\n", msg_arg.type.c_str(), msg_arg.name.c_str(), read<float>(buf));
		}
		else
		{
			printf("Unfinished type: %s\n", msg_arg.type.c_str());
		}
	}
}

int(__stdcall* o_recv)(SOCKET, char*, int, int);
int __stdcall recv_hook(SOCKET s, char* buf, int len, int flags) {
	const auto is_encrypted = *reinterpret_cast<uint16_t*>(buf) != 0xF00D;
	
	if (is_encrypted)
		return o_recv(s, buf, len, flags);

	std::vector<char> t;
	for (auto i = 0; i < len; i++)
	{
		t.push_back(buf[i]);
	}

	handle_packet(t, packet_mode::recieved);
	return o_recv(s, buf, len, flags);
}

int(__stdcall* o_wsasend)(SOCKET s, LPWSABUF lp, DWORD dwc, LPDWORD lpnbs, DWORD dwflags, LPWSAOVERLAPPED lpo, LPWSAOVERLAPPED_COMPLETION_ROUTINE lcr);
int __stdcall wsasend_hook(SOCKET s, LPWSABUF lp, DWORD dwc, LPDWORD lpnbs, DWORD dwflags, LPWSAOVERLAPPED lpo, LPWSAOVERLAPPED_COMPLETION_ROUTINE lcr) {
	const auto is_encrypted = *reinterpret_cast<uint16_t*>(lp[0].buf) != 0xF00D;
	std::vector<char> full_packet;
	
	if (is_encrypted)
		return o_wsasend(s, lp, dwc, lpnbs, dwflags, lpo, lcr);

	for (DWORD i = 0; i < dwc; i++)
	{
		for (auto p = 0; p < lp[i].len; p++)
		{
			full_packet.push_back(lp[i].buf[p]);
		}
	}
	handle_packet(full_packet, packet_mode::sent);
	return o_wsasend(s, lp, dwc, lpnbs, dwflags, lpo, lcr);
}

typedef void(__thiscall* og_ProcessData)(uint32_t _this, uint8_t* outString, uint8_t* inString, int _length);
auto adr = reinterpret_cast<uint32_t>(GetModuleHandle(nullptr)) + 0x432960 - 0x400000;//dwFindPattern(reinterpret_cast<const unsigned char*>("\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x81\xEC\x00\x00\x00\x00\x53\x55\x56\x57\xA1\x00\x00\x00\x00\x33\xC4\x50\x8D\x84\x24\x00\x00\x00\x00\x64\xA3\x00\x00\x00\x00\x8B\xF1\x83\x7E\x34\x02"), "xxx????xx????xxx????xxxxx????xxxxxx????xx????xxxxxx");
auto replacement_adr = reinterpret_cast<uint32_t>(GetModuleHandle(nullptr)) + 0x2259240 - 0x400000;
auto orig_ProcessData = reinterpret_cast<og_ProcessData>(adr);

uint64_t ogrig_ProcessData = NULL;

std::pair<std::vector<char>, packet_mode> set_iv;
NOINLINE void __fastcall ogProcessData_hook(uint32_t _this, uint32_t* edx, uint8_t* outString, uint8_t* inString, int length)
{
	if (length == 8 && *reinterpret_cast<uint16_t*>(inString) == 0xf00d) // is header of packet (will always be sent)
	{
		for (auto i = 0; i < length; i++)
		{
			set_iv.first.push_back(inString[i]);
		}
		set_iv.second = packet_mode::sent_encrytped;
		orig_ProcessData(_this, outString, inString, length);
		return;
	}

	if (!set_iv.first.empty()) // we are in data section of packet
	{
		for (auto i = 0; i < length; i++)
		{
			set_iv.first.push_back(inString[i]);
		}
		handle_packet(set_iv.first, set_iv.second);
		set_iv.first.clear();
		set_iv.second = packet_mode::none;
		orig_ProcessData(_this, outString, inString, length);
		return;
	}

	set_iv.second = packet_mode::recieved_encrypted;

	orig_ProcessData(_this, outString, inString, length); // decrypt message from server

	for (auto i = 0; i < length; i++)
	{
		set_iv.first.push_back(outString[i]);
	}

	handle_packet(set_iv.first, set_iv.second);
	set_iv.first.clear();
	set_iv.second = packet_mode::none;
}