#include<stdio.h> 
#include<windows.h>
#include<time.h>
#include<tchar.h>
#include<winnt.h>

int main() {
  
    LPVOID lpBase;                      //Pointer to the base memory of mapped file
    PIMAGE_DOS_HEADER dosHeader;        //Pointer to DOS Header
    PIMAGE_NT_HEADERS ntHeader;         //Pointer to NT Header
    IMAGE_FILE_HEADER fileHeader;           //Pointer to image file header of NT Header 
    IMAGE_OPTIONAL_HEADER32 opHeader;     //Optional Header of PE files present in NT Header structure
    PIMAGE_SECTION_HEADER pSecHeader;   //Section Header or Section Table Header
    

        //Open the Exe File 
        HANDLE h_File = CreateFile(L"HxDSetup.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (!h_File) { 
            printf("\nERROR : Could not open the file specified\n"); 
        }

        //Mapping Given EXE file to Memory
        HANDLE hMapObject = CreateFileMapping(h_File, NULL, PAGE_READONLY, 0, 0, NULL);
        lpBase = MapViewOfFile(hMapObject, FILE_MAP_READ, 0, 0, 0);

        long int filesize = GetFileSize(h_File, NULL);

        printf("File size is %lu\n", filesize);
        printf("Base Virtual Address %lu\n", lpBase);

        //DOS Header: First 64 bytes
        dosHeader = (PIMAGE_DOS_HEADER)lpBase; // 0x04000000

        //printf("%X", dosHeader->e_magic);

        if (dosHeader->e_magic == 0x5a4d) { // MZ //
            printf("[+] Windows Executable File\n");
        }
        else printf("File is not a Windows Compatible Executable\n");

        printf("\nxxxxxxxIMAGE DOS HEADERxxxxxxx\n");
        printf("Magic number - %X\n",dosHeader->e_magic);         // Magic number
        printf("Bytes on last page of file - %X\n", dosHeader->e_cblp);          // Bytes on last page of file
        printf("Pages in file - %X\n", dosHeader->e_cp);            // Pages in file
        printf("Relocations - %X\n", dosHeader->e_crlc);          // Relocations
        printf("Size of header in paragraphs - %X\n", dosHeader->e_cparhdr);       // Size of header in paragraphs
        printf("Minimum extra paragraphs needed - %X\n", dosHeader->e_minalloc);      // Minimum extra paragraphs needed
        printf("Maximum extra paragraphs needed - %X\n", dosHeader->e_maxalloc);      // Maximum extra paragraphs needed
        printf("Initial (relative) SS value - %X\n", dosHeader->e_ss);            // Initial (relative) SS value
        printf("Initial SP value - %X\n", dosHeader->e_sp);            // Initial SP value
        printf("Checksum - %X\n", dosHeader->e_csum);          // Checksum
        printf("Initial IP value - %X\n", dosHeader->e_ip);            // Initial IP value
        printf("Initial (relative) CS value - %X\n", dosHeader->e_cs);            // Initial (relative) CS value
        printf("File address of relocation table - %X\n", dosHeader->e_lfarlc);        // File address of relocation table
        printf("Overlay number - %X\n", dosHeader->e_ovno);          // Overlay number
        printf("Reserved words - %X\n", dosHeader->e_res[4]);        // Reserved words
        printf("OEM identifier (for e_oeminfo) - %X\n", dosHeader->e_oemid);         // OEM identifier (for e_oeminfo)
        printf("OEM information; e_oemid specific - %X\n", dosHeader->e_oeminfo);       // OEM information; e_oemid specific
        printf("Reserved words - %X\n", dosHeader->e_res2[10]);      // Reserved words
        printf("IMAGE NT HEADER offset(Relative Address) - %X\n", dosHeader->e_lfanew);        // File address of new exe header
        
        ntHeader = PIMAGE_NT_HEADERS((DWORD)lpBase + dosHeader->e_lfanew);
        
        printf("\nxxxxxxxIMAGE NT HEADERxxxxxxx\n");
        printf("nt Header base offset: %X\n", (ntHeader)); //
        printf("Signature: %X\n", ntHeader->Signature); // 0x4550 ~ PE

        printf("\n\t+++++++IMAGE FILE HEADER+++++++\n");
        printf("\n\tMachine Architecture -  %X\n", ntHeader->FileHeader.Machine);  // 0x014c ~ x86 architecture
        printf("\tNumberOfSections - %X\n", ntHeader->FileHeader.NumberOfSections);
        printf("\tTimeDateStamp - %X\n", ntHeader->FileHeader.TimeDateStamp);
        printf("\tPointerToSymbolTable - %X\n", ntHeader->FileHeader.PointerToSymbolTable);
        printf("\tNumberOfSymbols - %X\n", ntHeader->FileHeader.NumberOfSymbols);
        printf("\tSizeOfOptionalHeader - %X\n", ntHeader->FileHeader.SizeOfOptionalHeader);
        printf("\tCharacteristics - %X\n", ntHeader->FileHeader.Characteristics);

        printf("\n\t+++++++IMAGE OPTIONAL HEADER+++++++\n");
        printf("\n\tMagic Number - %X\n", ntHeader->OptionalHeader.Magic); // 0x10b - File is an executable image
        printf("\tThe major version number of the linker - %X\n", ntHeader->OptionalHeader.MajorLinkerVersion);
        printf("\tThe minor version number of the linker - %X\n", ntHeader->OptionalHeader.MinorLinkerVersion);
        printf("\tThe size of the code section - %X\n", ntHeader->OptionalHeader.SizeOfCode);
        printf("\tThe size of the initialized data section - %X\n", ntHeader->OptionalHeader.SizeOfInitializedData);
        printf("\tThe size of the uninitialized data section - %X\n", ntHeader->OptionalHeader.SizeOfUninitializedData);
        printf("\tPointer to Entry Point of EXE - %X\n", ntHeader->OptionalHeader.AddressOfEntryPoint);
        printf("\tpointer to the beginning of the code section - %X\n", ntHeader->OptionalHeader.BaseOfCode);
        printf("\tpointer to the beginning of the data section - %X\n", ntHeader->OptionalHeader.BaseOfData);
        printf("\tfirst byte of the image when it is loaded in memory - %X\n", ntHeader->OptionalHeader.ImageBase);
        printf("\tThe alignment of sections loaded in memory - %X\n", ntHeader->OptionalHeader.SectionAlignment);
        printf("\tThe alignment of the raw data of sections in the image file - %X\n", ntHeader->OptionalHeader.FileAlignment);
        printf("\tThe major version number of the required operating system - %X\n", ntHeader->OptionalHeader.MajorOperatingSystemVersion);
        printf("\tThe minor version number of the required operating system - %X\n", ntHeader->OptionalHeader.MinorOperatingSystemVersion);
        printf("\tMajor Image Version - %X\n", ntHeader->OptionalHeader.MajorImageVersion);
        printf("\tMinor Image Version - %X\n", ntHeader->OptionalHeader.MinorImageVersion);
        printf("\tMajor Subsystem Version - %X\n", ntHeader->OptionalHeader.MajorSubsystemVersion);
        printf("\tMinor Subsystem Version - %X\n", ntHeader->OptionalHeader.MinorSubsystemVersion);
        printf("\tWin32 Version Value - %X\n", ntHeader->OptionalHeader.Win32VersionValue);
        printf("\tThe size of the image - %X\n", ntHeader->OptionalHeader.SizeOfImage);
        printf("\tThe combined size of all the Headers - %X\n", ntHeader->OptionalHeader.SizeOfHeaders);
        printf("\tThe size of the image - %X\n", ntHeader->OptionalHeader.CheckSum);
        printf("\tThe subsystem required to run this image - %X\n", ntHeader->OptionalHeader.Subsystem);
        printf("\tThe DLL characteristics of the image - %X\n", ntHeader->OptionalHeader.DllCharacteristics);
        printf("\tThe number of bytes to reserve for the stack - %X\n", ntHeader->OptionalHeader.SizeOfStackReserve);
        printf("\tThe number of bytes to commit for the stack - %X\n", ntHeader->OptionalHeader.SizeOfStackCommit);
        printf("\tThe number of bytes to reserve for the local heap - %X\n", ntHeader->OptionalHeader.SizeOfHeapReserve);
        printf("\tThe number of bytes to commit for the local heap - %X\n", ntHeader->OptionalHeader.SizeOfHeapCommit);
        printf("\tLoader Flags - %X\n", ntHeader->OptionalHeader.LoaderFlags);
        printf("\tThe number of directory entries in the remainder of the optional header - %X\n", ntHeader->OptionalHeader.NumberOfRvaAndSizes);

        printf("\n\t\t+++++++IMAGE DATA DIRECTORY+++++++\n");
}