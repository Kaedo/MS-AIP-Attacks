#include <Windows.h>
#include <iostream>
#include <memory>
#include <vector>
#include <algorithm>
#include <fstream>

constexpr auto CIPHER_SIZE = 0x80;

void fail(std::string&& msg) 
{
	std::cerr << msg;
	std::cin.get();
	exit(1);
}

const auto get_decryptfunc()
{
	constexpr auto func_dec_offset = 0x85249;

	const auto ipcsecproc = reinterpret_cast<char*>(LoadLibraryA("ipcsecproc.dll"));

	if (ipcsecproc == nullptr)
	{
		fail("Couldn't load ipcsecproc.dll, make sure it's loadeable!\n");
	}

	return reinterpret_cast<bool(__stdcall* const)(char * dec, const char * enc)>(ipcsecproc + func_dec_offset);
}

auto get_cipher(std::string&& filename)
{
	std::ifstream ifs{ filename, std::ios::binary | std::ios::ate };
	if (ifs.is_open())
	{
		const auto size = ifs.tellg(); ifs.seekg(0);
		if (size < CIPHER_SIZE)
		{
			fail("File ins't big enough for decryption!\n");
		}
		
		auto cipher = std::vector<char>(std::istreambuf_iterator<char>{ ifs }, {});
		std::reverse(cipher.begin(), cipher.end());
		return cipher;
	}
	else
	{
		fail("Couldn't open cipher file, make sure it's readable!\n");
	}
}

void write_plain(std::string&& filename, const std::vector<char>& plain)
{
	std::ofstream ofs(filename, std::ios::binary | std::ios::trunc);
	if (ofs.is_open()) {
		ofs.write(plain.data(), plain.size());
	}
	else
	{
		fail("Couldn't open plaintext file, make sure it's writeable!\n");
	}
}

int main(int argc, char *argv[])
{
	if (argc < 3)
	{
		std::cout << "usage: " << argv[0] << " cipherfile plainfile\n";
		std::cin.get();
		exit(1);
	}

	const auto func_dec = get_decryptfunc();
	const auto cipher = get_cipher(argv[1]);
	std::vector<char> plain(CIPHER_SIZE);

	if (func_dec(plain.data(), cipher.data()))
	{
		std::reverse(plain.begin(), plain.begin() + 0x30);
		write_plain(argv[2], plain);
	}

	return 0;
}