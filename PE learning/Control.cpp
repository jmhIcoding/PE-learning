#include <stdio.h>
#include <stdlib.h>
#include "BaseTool.h"
#include <iostream>


using namespace std;



int main()
{
	char * filename = "hello.exe";
	int flag = BaseTool::isSuitable(filename);

	if (flag==2)
	{
		printf("infecting.....\n");
		BaseTool pe(filename);
		pe.infect();
	}
	if (flag == 1)
	{
		printf("uninfecting....\n");
		BaseTool pe(filename);
		pe.uninfect();
	}
	system("pause");
	return 0;
}