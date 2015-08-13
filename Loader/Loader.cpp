// Loader.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <CvGameCoreDLLPCH.h>
#include <CvDllContext.h>

extern "C" ICvGameContext1* DllGetGameContext();

int _tmain(int argc, _TCHAR* argv[])
{
	ICvGameContext1 *context = DllGetGameContext();
	
	return 0;
}

