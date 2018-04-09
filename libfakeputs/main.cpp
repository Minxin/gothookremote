#include <stdio.h>
#include <elf.h>
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>



void write_data_to_addr(void* fixaddress,uint32_t newfuncaddr){
    *(uint32_t*)fixaddress=newfuncaddr;
}
long get_module_base(pid_t pid, const char* module_name)  
{  
    FILE *fp;  
    long addr = 0;  
    char *pch;  
    char filename[32];  
    char line[1024];  
  
    if (pid < 0) {  
        /* self process */  
        snprintf(filename, sizeof(filename), "/proc/self/maps", pid);  
    } else {  
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);  
    }  
  
    fp = fopen(filename, "r");  
    if (fp != NULL) {  
        while (fgets(line, sizeof(line), fp)) {  
            if (strstr(line, module_name)) {  
                pch = strtok( line, "-" );  
                addr = strtoul( pch, NULL, 16 );  
  
                if (addr == 0x8000)  
                    addr = 0;  
  
                break;  
            }  
        }  
  
        fclose(fp) ;  
    }  
  
    return addr;  
}  

char * GetElf32StringTabBaseFromfile(FILE* fp){
    Elf32_Ehdr Elf32_ElfHeader;
    memset(&Elf32_ElfHeader,0,sizeof(Elf32_ElfHeader));

    Elf32_Shdr Elf32_SectionHeader;
    memset(&Elf32_SectionHeader,0,sizeof(Elf32_SectionHeader));

    int shstrtaboffset=0;
    char* pStringTab=NULL;

    fseek(fp,0,SEEK_SET);
    fread(&Elf32_ElfHeader,sizeof(Elf32_ElfHeader),1,fp);

    shstrtaboffset=Elf32_ElfHeader.e_shoff + Elf32_ElfHeader.e_shstrndx*Elf32_ElfHeader.e_shentsize;

    fseek(fp,shstrtaboffset,SEEK_SET);
    fread(&Elf32_SectionHeader,sizeof(Elf32_SectionHeader),1,fp);

    pStringTab=(char* )malloc(Elf32_SectionHeader.sh_size);
    if(pStringTab==NULL){
        printf("malloc fail\n");
        return NULL;
    }
    fseek(fp,Elf32_SectionHeader.sh_offset,SEEK_SET);
    fread(pStringTab,Elf32_SectionHeader.sh_size,1,fp);

    printf("pStringTab :%p\n",pStringTab);
    return pStringTab;

}

int GetGotStartAddrAndSize(FILE* fp,uint32_t* GotTabStartaddr,uint32_t* GotTabSize){
    const char szGotTabName[]=".got";

    Elf32_Ehdr Elf32_ElfHeader;
    memset(&Elf32_ElfHeader,0,sizeof(Elf32_ElfHeader));

    fseek(fp,0,SEEK_SET);
    fread(&Elf32_ElfHeader,sizeof(Elf32_ElfHeader),1,fp);

    Elf32_Shdr Elf32_SectionHeader;
    memset(&Elf32_SectionHeader,0,sizeof(Elf32_SectionHeader));
    
    
    char* pStringTabStartOff=NULL;
    pStringTabStartOff=GetElf32StringTabBaseFromfile(fp);

    fseek(fp,Elf32_ElfHeader.e_shoff,SEEK_SET);
    if(pStringTabStartOff==NULL){
        printf("get string table address fail\n");
        return -1;
    }

    for(int i =0; i<Elf32_ElfHeader.e_shnum;i++){
        fread(&Elf32_SectionHeader,Elf32_ElfHeader.e_shentsize,1,fp);

        if(Elf32_SectionHeader.sh_type == SHT_PROGBITS && strncmp(szGotTabName,pStringTabStartOff+Elf32_SectionHeader.sh_name,sizeof(szGotTabName))==0){
            *GotTabStartaddr=Elf32_SectionHeader.sh_addr;
            *GotTabSize=Elf32_SectionHeader.sh_size;
        }
    }
    free(pStringTabStartOff);
    printf("Get Got table address and size success\n");
    return 1;

}


int DoGotHook(const char* TargetDir,const char* TargetSoName,void* symbol,void* new_function,void** old_function){
    uint32_t uiGotTabStartaddr=0;
    uint32_t uiGotTabSize=0;

    if(TargetDir==NULL){
        printf("path can be NULL\n");
        return -1;
    }
    if(access(TargetDir,F_OK)==-1){
        printf("path is not existing\n");
        return -1;
    }
    char filepath[256]={0};
    snprintf(filepath,sizeof(filepath),"%s%s",TargetDir,TargetSoName);
    FILE* fp=fopen(filepath,"rb");
    if(fp==NULL){
        printf("can't open so file\n");
        return -1;
    }
    int nRet=GetGotStartAddrAndSize(fp,&uiGotTabStartaddr,&uiGotTabSize);

    if(nRet==-1){
        printf("can't get Got table address and size\n");
        return -1;
    }
    printf("Got size:%d\n",uiGotTabSize);
    uint32_t base=get_module_base(getpid(),TargetSoName);
    int bHaveFoundTargetAddr=0;
    for(int i=0;i<uiGotTabSize;i=i+4){
        if(*(uint32_t*)(base+uiGotTabStartaddr+i)==(uint32_t)symbol){
            if(mprotect((void *) ((base+uiGotTabStartaddr+i) / 0x1000 * 0x1000), 4096 * 1,PROT_READ | PROT_WRITE) != 0){
                puts("mem privilege change failed");
            }
            *old_function=symbol;
            printf("before hook, the addr :%x the value is: %x\n",(base+uiGotTabStartaddr+i),*(uint32_t*)(base+uiGotTabStartaddr+i));
            write_data_to_addr((void*)(base+uiGotTabStartaddr+i),(uint32_t)new_function);
            printf("after hook, the value :%x\n",*(uint32_t*)(base+uiGotTabStartaddr+i));
            bHaveFoundTargetAddr=1;
             if(mprotect((void *) ((base+uiGotTabStartaddr+i) / 0x1000 * 0x1000), 4096 * 1,PROT_READ) != 0){
                puts("mem privilege change failed");
            }
        
        }
    }
    if(bHaveFoundTargetAddr==1){
        printf("do gothook success\n");
    }
    else{
        printf("do gothook fail\n");
    }
    fclose(fp);
    return 0;

}



int myputs(const char* str){
    printf("FAKE:%s",str);
    int i=1;
    for(;*(str+i)!=0;i++){}
    return i+5;
}

int DoHook(){
    
    char* path="/data/local/tmp/";
    char* soname="tobehook";
    void* oldfunc;
    // char tfile[128]={0};
    // snprintf(tfile,sizeof(tfile),"%s%s",path,soname);
    DoGotHook(path,soname,(void*)&puts,(void*)&myputs,&oldfunc);
   
    puts("hook ok!");
    return 0;
}