// Loader.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>

extern "C" ICvGameContext1* DllGetGameContext();

static const std::size_t DATA_BLOCK_SIZE = 71311360;
#pragma section(".data_block", read, write)
__declspec(allocate(".data_block"))
char blockBuffer[DATA_BLOCK_SIZE + 2]; //extra padding, just in case

using fn_t = decltype(&DllGetGameContext);

void fillBuffer()
{
	std::ifstream is("_10028000.mem", std::ios::binary);
	//is.seekg(0, std::ios::end);
	//std::size_t size = is.tellg();
	//is.seekg(0, std::ios::beg);
	is.read(blockBuffer, DATA_BLOCK_SIZE);
}

int _tmain(int argc, _TCHAR* argv[])
{
	fillBuffer();
	std::cout << &blockBuffer << std::endl;
	ICvGameContext1 *context;
	fn_t fn_ptr;

	BOOL freeResult, runtimeLinkSuccess = FALSE;
	HINSTANCE dllHandle = nullptr;

	dllHandle = LoadLibrary("CvGameCoreDLLFinal Release.dll");

	if (dllHandle)
	{
		fn_ptr = reinterpret_cast<fn_t>(GetProcAddress(dllHandle, "DllGetGameContext"));
	}

	std::cerr << "Holy S*#T we have a GameContext!" << std::endl;
	
	return 0;
}

