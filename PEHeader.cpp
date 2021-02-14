#include<stdio.h> 
#include<windows.h>
#include<time.h>
#include<tchar.h>
#include<winnt.h>

int main() {
  
    LPVOID lpBase;                      //Pointer to the base memory of mapped file
    PIMAGE_DOS_HEADER dosHeader;        //Pointer to DOS Header
    PIMAGE_NT_HEADERS ntHeader;         //Pointer to NT Header
    IMAGE_FILE_HEADER header;           //Pointer to image file header of NT Header 
    IMAGE_OPTIONAL_HEADER opHeader;     //Optional Header of PE files present in NT Header structure
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

        printf("xxxPORTABLE EXECUTABLE DOS HEADERxxx\n");
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
        
}