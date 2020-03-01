
#include <stdio.h>
#include <stdlib.h>
#include "BaseTool.h"
#include <iostream>

using namespace std;

#if 0
int main()
{
	printf("Hello world!.....\n");
	system("pause");
	return 0;
	
}
#endif
#if 0
int main()
{
	char buf[1024] = { 0 };

	printf("%d\n", BaseTool::isSuitable("hello2.exe"));
	BaseTool peReader("hello2.exe");
	DWORD base = peReader.getKernal32Base();
	

	IMAGE_DOS_HEADER h = peReader.get_IMAGE_DOS_HEADER();
	h.display();
	printf("peHeader: %X\n", peReader.e_lfnew);
	//peReader.change_AddressEntry(0x1294);
	_IMAGE_NT_HEADERS nth = peReader.get_IMAGE_NT_HEADER();
	nth.display();
	printf("address of entry point :%X \n", nth.OptionalHeader.AddressOfEntryPoint);
	printf("checksum :%X\n", nth.OptionalHeader.CheckSum);
	printf("Size of Image :%X \n", nth.OptionalHeader.SizeOfImage);
	printf("Size of COde : %X \n", nth.OptionalHeader.SizeOfCode);
	size_t sectionCnt = peReader.get_Number_OF_Section();
	IMAGE_SECTION_HEADER*  sectionheaders = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER)*sectionCnt);
	peReader.get_IMAGE_SECTION_HEADERS(sectionheaders, &sectionCnt);
	for (int i = 0; i < sectionCnt; i++)
	{
		sectionheaders[i].display();
	}
	peReader.uninfect();

	system("pause");

	return 0;
}
#endif