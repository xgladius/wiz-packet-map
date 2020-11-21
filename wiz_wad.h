#pragma once
#include <Windows.h>
#include <fstream>
#include <vector>
#include <ostream>
#include "zlib/zlib.h"

#pragma pack(push, 1)
struct wad_header {
	char KIWAD[5]; // "KIWAD"
	int version;
	int files;
	byte padding;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct wad_file {
	int offset;
	int size;
	int zsize;
	byte zip;
	int crc;
	int namesz;
};
#pragma pack(pop)

struct file_dat {
	std::string name;
	std::vector<byte> file;
};

inline void inflate_buf(const int zsize, byte* wad_in, const int size, byte* data) {
	z_stream infstream;
	infstream.zalloc = nullptr;
	infstream.zfree = nullptr;
	infstream.opaque = nullptr;
	infstream.avail_in = static_cast<uInt>(zsize);
	infstream.next_in = wad_in;
	infstream.avail_out = static_cast<uInt>(size);
	infstream.next_out = data;
	inflateInit(&infstream);
	inflate(&infstream, Z_NO_FLUSH);
	inflateEnd(&infstream);
}

inline void get_wad(const char* filter, const char* type, std::vector<file_dat>& file_map) {
	std::ifstream in("C:\\ProgramData\\KingsIsle Entertainment\\Wizard101\\Data\\GameData\\Root.wad", std::ios::in | std::ios::binary);
	in.seekg(0, std::ios::end);
	const auto file_size = in.tellg();
	in.seekg(0, std::ios::beg);
	std::vector<byte> fileData(file_size);
	in.read(reinterpret_cast<char*>(&fileData[0]), file_size);
	auto* wad_in = fileData.data();
	auto* wad_back = fileData.data();
	auto* header = reinterpret_cast<wad_header*>(wad_in);
	wad_in += sizeof(wad_header);
	for (auto i = 0; i < header->files; ++i) {
		auto* file = reinterpret_cast<wad_file*>(wad_in);
		wad_in += sizeof(wad_file);

		std::vector<char> fileName(file->namesz);
		memcpy(fileName.data(), wad_in, file->namesz);
		wad_in += fileName.size();

		if (strstr(fileName.data(), type) == nullptr)
			continue;
		if (strstr(fileName.data(), filter) == nullptr)
			continue;

		const auto tmp = wad_in;
		wad_in = &wad_back[0];
		wad_in += file->offset;

		if (*wad_in == 0) {
			continue;
		}
		std::vector<byte> output(file->size);
		if (file->zip == 0) {
			memcpy(output.data(), wad_in, file->size);
		}
		else {
			inflate_buf(file->zsize, wad_in, file->size, output.data());
		}
		file_map.push_back(file_dat{ std::string(fileName.data()), std::vector<byte>(output.begin(), output.end()) }); // string was needed to create a copy of fileName.data() , really annoying
		wad_in = tmp;
	}
}