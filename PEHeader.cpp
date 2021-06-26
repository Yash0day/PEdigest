#include<stdio.h> 
#include<windows.h>
#include<winnt.h>
#include<winternl.h>
#include <iostream>
#include<string>


std::wstring file = L"C:/Users/Boyka/Desktop/Project1.exe";
std::wstring filetest = L"C:/Users/Boyka/Desktop/m.PNG"; 

int PEHeader_() {

    HANDLE h_File = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (!h_File) {
        printf("\nERROR : Could not open the file specified!!!\n");
    }

    //Mapping Given EXE file to Memory
    HANDLE hMapObject = CreateFileMapping(h_File, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID basepointer = (char*)MapViewOfFile(hMapObject, FILE_MAP_READ, 0, 0, 0);

    //PIMAGE_DOS_HEADER dos_header;        
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)basepointer;

   if (dos_header->e_magic != IMAGE_DOS_SIGNATURE){
        
        printf("[-]Not an Executable file!\n");
        printf("Terminated...\n");
        exit(3);
    }
    else {
        printf("[+] A Valid NT Executable file\n");
    }
    printf("[ . ]Image DOS header:\n");
    printf("\n\tMagic number - %X\n", dos_header->e_magic);
    printf("\tBytes on last page of file - %X\n", dos_header->e_cblp);
    printf("\tPages in file - %X\n", dos_header->e_cp);
    printf("\tRelocations - %X\n", dos_header->e_crlc);
    printf("\tSize of header in paragraphs - %X\n", dos_header->e_cparhdr);
    printf("\tMinimum extra paragraphs needed - %X\n", dos_header->e_minalloc);
    printf("\tMaximum extra paragraphs needed - %X\n", dos_header->e_maxalloc);
    printf("\tInitial (relative) SS value - %X\n", dos_header->e_ss);
    printf("\tInitial SP value - %X\n", dos_header->e_sp);
    printf("\tChecksum - %X\n", dos_header->e_csum);
    printf("\tInitial IP value - %X\n", dos_header->e_ip);
    printf("\tInitial (relative) CS value - %X\n", dos_header->e_cs);
    printf("\tFile address of relocation table - %X\n", dos_header->e_lfarlc);
    printf("\tOverlay number - %X\n", dos_header->e_ovno);
    printf("\tReserved words - %X\n", dos_header->e_res[4]);
    printf("\tOEM identifier (for e_oeminfo) - %X\n", dos_header->e_oemid);
    printf("\tOEM information; e_oemid specific - %X\n", dos_header->e_oeminfo);
    printf("\tReserved words - %X\n", dos_header->e_res2[10]);
    

    printf("\tDOS HEADER: IMAGE NT HEADER offset(Relative Address) - %X\n", dos_header->e_lfanew);  

    //PIMAGE_NT_HEADERS ntHeaders   
    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((DWORD)basepointer + dos_header->e_lfanew);

    printf("\n[ . ]Image NT headers:\n");
    printf("\tNT HEADER: Signature 'PE: 5045' : %x\n", nt_header->Signature);

    PIMAGE_FILE_HEADER file_header = (PIMAGE_FILE_HEADER)((DWORD)basepointer + dos_header->e_lfanew + sizeof(nt_header->Signature));
    
    if (file_header->Machine != IMAGE_FILE_MACHINE_I386) {
        printf("[-] The File is not compatible with the Processor!\n");
        exit(3);
    }
    else {
        printf("\t[+] File Compatible with Intel Processor\n");
    }

    printf("\n\t[ .. ]Image File headers:\n");
    printf("\tType of Target Machine: %x\n", file_header->Machine);
    printf("\tNumber of Sections: %x\n", file_header->NumberOfSections);
    printf("\tTime the file was created(Time Date Stamp): %x\n", file_header->TimeDateStamp);
    printf("\tOffset to the Symbol Table(Deprecated for Exe Images): %x\n", file_header->PointerToSymbolTable);
    printf("\tThe number of entries in the symbol table(Deprecated for Exe Images): %x\n", file_header->NumberOfSymbols);
    printf("\tThe size of the optional header: %x\n", file_header->SizeOfOptionalHeader);
    printf("\tCharacteristics: %x\n", file_header->Characteristics);

    PIMAGE_OPTIONAL_HEADER optional_header = (PIMAGE_OPTIONAL_HEADER)((DWORD)basepointer + dos_header->e_lfanew + sizeof(nt_header->Signature) + sizeof(nt_header->FileHeader));

    printf("\n\t[ .. ]Image OPTIONAL5 headers:\n");
    printf("\tState of Image(Magic number): %x\n", optional_header->Magic);
    printf("\tThe linker major version number: %x\n", optional_header->MajorLinkerVersion);
    printf("\tThe linker minor version number: %x\n", optional_header->MinorLinkerVersion);
    printf("\tThe size of the code (text) section: %x\n", optional_header->SizeOfCode);
    printf("\tThe size of the initialized data section: %x\n", optional_header->SizeOfInitializedData);
    printf("\tThe size of the uninitialized data section (BSS): %x\n", optional_header->SizeOfUninitializedData);
    printf("\tThe address of the entry point relative to the image base: %x\n", optional_header->AddressOfEntryPoint);
    printf("\tThe address that is relative to the image base of the beginning-of-code section: %x\n", optional_header->BaseOfCode);
    printf("\tThe address that is relative to the image base of the beginning-of-data section: %x\n", optional_header->BaseOfData);
    printf("\tThe preferred address of the first byte of image when loaded into memory(Image Base) %x\n", optional_header->ImageBase);
    printf("\tThe alignment (in bytes) of sections: %x\n", optional_header->SectionAlignment);
    printf("\tThe alignment factor (in bytes): %x\n", optional_header->FileAlignment);
    printf("\tThe major version number of the required operating system: %x\n", optional_header->MajorOperatingSystemVersion);
    printf("\tThe minor version number of the required operating system: %x\n", optional_header->MinorOperatingSystemVersion);
    printf("\tThe major version number of the image: %x\n", optional_header->MajorImageVersion);
    printf("\tThe minor version number of the image: %x\n", optional_header->MinorImageVersion);
    printf("\tThe major version number of the subsystem: %x\n", optional_header->MajorSubsystemVersion);
    printf("\tThe minor version number of the subsystem %x\n", optional_header->MinorSubsystemVersion);
    printf("\tReserved(== 0): %x\n", optional_header->Win32VersionValue);
    printf("\tThe size (in bytes) of the image(including all headers, as the image is loaded in memory): %x\n", optional_header->SizeOfImage);
    printf("\tThe combined size of an MS-DOS stub, PE header, and section headers: %x\n", optional_header->SizeOfHeaders);
    printf("\tThe image file checksum: %x\n", optional_header->CheckSum);
    printf("\tThe subsystem that is required to run this image: %x\n", optional_header->Subsystem);
    printf("\t[ ] DllCharacteristics: %x\n", optional_header->DllCharacteristics);
    printf("\tThe size of the stack to reserve: %x\n", optional_header->SizeOfStackReserve);
    printf("\tThe size of the stack to commit: %x\n", optional_header->SizeOfStackCommit);
    printf("\tThe size of the local heap space to reserve: %x\n", optional_header->SizeOfHeapReserve);
    printf("\tThe size of the local heap space to commit: %x\n", optional_header->SizeOfHeapCommit);
    printf("\tReserved(== 0): %x\n", optional_header->LoaderFlags);
    printf("\tThe number of data-directory entries: %x\n", optional_header->NumberOfRvaAndSizes);


    PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)((DWORD)basepointer + dos_header->e_lfanew + sizeof(nt_header->Signature) + sizeof(nt_header->FileHeader) + sizeof(nt_header->OptionalHeader));
    DWORD numberofsections = file_header->NumberOfSections;
    //printf("\tSection Header: Number of Sections %x\n", file_header->NumberOfSections);

    printf("\n\t[ ... ]DATA DIRECTORIES:\n");
    for (int j = 0; j < optional_header->NumberOfRvaAndSizes;j++) {
        printf("\t\tData Directory: Virtual Address: %x\t\n", optional_header->DataDirectory[j].VirtualAddress);
    }

    DWORD RVAimport_directory = nt_header->OptionalHeader.DataDirectory[1].VirtualAddress;
    //printf("RVAimport_directory %x", RVAimport_directory);

    PIMAGE_SECTION_HEADER import_section = {};
    printf("\t[ ... ] SECION HEADERS:\n");
    for (int i = 1; i <= numberofsections; i++, section_header++) {
        printf("\t\tSection Header: Section Name %s\n", section_header->Name);

        if (RVAimport_directory >= section_header->VirtualAddress && RVAimport_directory < section_header->VirtualAddress + section_header->Misc.VirtualSize) {

            import_section = section_header;
        }
        //section_header += (DWORD)sizeof(PIMAGE_SECTION_HEADER);
    }

    DWORD import_table_base_offset = (DWORD)basepointer + import_section->PointerToRawData;

    PIMAGE_IMPORT_DESCRIPTOR importImageDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(import_table_base_offset + (nt_header->OptionalHeader.DataDirectory[1].VirtualAddress - import_section->VirtualAddress));

    //DLL Imports
    for (;importImageDescriptor->Name != 0; importImageDescriptor++) {
        DWORD Imported_DLL = import_table_base_offset + (importImageDescriptor->Name - import_section->VirtualAddress);
        printf("\n[+]Imported DLLs: %s\n", Imported_DLL);

        DWORD thunk = importImageDescriptor->FirstThunk;
        PIMAGE_THUNK_DATA thunk_data = (PIMAGE_THUNK_DATA)(import_table_base_offset + (thunk - import_section->VirtualAddress));

        for (;thunk_data->u1.AddressOfData != 0; thunk_data++) {
            if (thunk_data->u1.AddressOfData > 0x80000000) {
                printf("\n\tOrdinal: %x", (WORD)thunk_data->u1.AddressOfData);
            }
            else {
                DWORD functionname = import_table_base_offset + (thunk_data->u1.AddressOfData - (import_section->VirtualAddress - 2));
                printf("\n\tFunction Name: %s", functionname);
            }
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
   
    PEHeader_();
    return 1;
}