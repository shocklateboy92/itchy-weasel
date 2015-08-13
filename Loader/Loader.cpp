// Loader.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>

extern "C" ICvGameContext1* DllGetGameContext();

int _tmain(int argc, _TCHAR* argv[])
{
	ICvGameContext1 *context = DllGetGameContext();

	std::cerr << "Holy S*#T we have a GameContext!" << std::endl;
	
	return 0;
}

