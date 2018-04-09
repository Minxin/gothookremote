#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <dlfcn.h>  
#include <dirent.h> 
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/ptrace.h> 
#include <sys/user.h>   

#define CPSR_T_MASK  (1u << 5) 

const char *libc_path = "/system/lib/libc.so";  
const char *linker_path = "/system/bin/linker"; 
const char *library_path="/data/local/tmp/libfakeputs.so";
const char *function_name="_Z6DoHookv";

void* lDoHook=NULL;




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

int ptrace_getregs(pid_t pid, struct pt_regs * regs)  
{  
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {  
        perror("ptrace_getregs: Can not get register values");  
        return -1;  
    }  
  
    return 0;  
}  
  
  
int ptrace_setregs(pid_t pid, struct pt_regs * regs)  
{  
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {  
  
        perror("ptrace_setregs: Can not set register values");  
        return -1;  
    }  
  
    return 0;  
}  
  
  

int ptrace_continue(pid_t pid)  
{  
    if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {  
  
        perror("ptrace_cont");  
        return -1;  
    }  
  
    return 0;  
}  
  
  
int ptrace_attach(pid_t pid)  
{  
    if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {  
  
        perror("ptrace_attach");  
        return -1;  
    }  
  
    int status = 0;  
    waitpid(pid, &status , WUNTRACED);  
  
    return 0;  
}  


int ptrace_detach(pid_t pid)  
{  
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {  
        perror("ptrace_detach");  
        return -1;  
    }  
  
    return 0;  
}  

void * get_remote_func_addr(pid_t targetPid,const char* moduleName,void* local_func_addr){
    void* local_base=0;
    void* remote_base=0;

    local_base=(void*)get_module_base(-1,moduleName);
    remote_base=(void*)get_module_base(targetPid,moduleName);

    void* remote_func_addr=(void *)((uint32_t)local_func_addr + (uint32_t)remote_base - (uint32_t)local_base); 

    //printf("remote_func_addr:0x%x\n",remote_func_addr);

    return remote_func_addr;
}


int find_pid_of(const char *process_name)  
{  
    int id;  
    pid_t pid = -1;  
    DIR* dir;  
    FILE *fp;  
    char filename[32];  
    char cmdline[256];  
  
    struct dirent * entry;  
  
    if (process_name == NULL)  
        return -1;  
  
    dir = opendir("/proc");  
    if (dir == NULL)  
        return -1;  
  
    while((entry = readdir(dir)) != NULL) {  
        id = atoi(entry->d_name);  
        if (id != 0) {  
            sprintf(filename, "/proc/%d/cmdline", id);  
            fp = fopen(filename, "r");  
            if (fp) {  
                fgets(cmdline, sizeof(cmdline), fp);  
                fclose(fp);  
  
                if (strcmp(process_name, cmdline) == 0) {  
                    /* process found */  
                    pid = id;  
                    break;  
                }  
            }  
        }  
    }  
  
    closedir(dir);  
  
    return pid;  
}  



// 读取目标进程中内存数据  
int ptrace_readdata(pid_t pid,  uint8_t *src, uint8_t *buf, size_t size)  
{  
    uint32_t i, j, remain;  
    uint8_t *laddr;  
  
    union u {  
        long val;  
        char chars[sizeof(long)];  
    } d;  
  
    j = size / 4;  
    remain = size % 4;  
  
    laddr = buf;  
  
    for (i = 0; i < j; i ++) {  
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);  
        memcpy(laddr, d.chars, 4);  
        src += 4;  
        laddr += 4;  
    }  
  
    if (remain > 0) {  
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);  
        memcpy(laddr, d.chars, remain);  
    }  
  
    return 0;  
}  
  
  

int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size)  
{  
    uint32_t i, j, remain;  
    uint8_t *laddr;  
  
    union u {  
        long val;  
        char chars[sizeof(long)];  
    } d;  
  
    j = size / 4;  
    remain = size % 4;  
  
    laddr = data;  
  
    for (i = 0; i < j; i ++) {  
        //字节序
        memcpy(d.chars, laddr, 4);  
        ptrace(PTRACE_POKETEXT, pid, dest, d.val);  
  
        dest  += 4;  
        laddr += 4;  
    }  
    //printf("poke success\n");
    if (remain > 0) {  
        d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);  
        for (i = 0; i < remain; i ++) {  
            d.chars[i] = *laddr ++;  
        }  
  
        ptrace(PTRACE_POKETEXT, pid, dest, d.val);  
    }  

    //printf("writedata ok\n");
    return 0;  
} 

int ptrace_call(pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct pt_regs* regs)  
{  
    uint32_t i;  
  
    // 设置目标pid进程中被调用的函数的参数（arm的函数调用中前4个函数参数，通过r0-r3寄存器传递）  
    for (i = 0; i < num_params && i < 4; i ++) {          
        regs->uregs[i] = params[i];  
    }  
  
    //  
    // push remained params onto stack  
    // 设置目标pid进程中被调用的函数的超过4个参数的参数（arm的函数调用中超过4个参数之后的函数参数，通过栈进行传递）  
    if (i < num_params) {  
        regs->ARM_sp -= (num_params - i) * sizeof(long) ;  
        ptrace_writedata(pid, (uint8_t *)regs->ARM_sp, (uint8_t *)&params[i], (num_params - i) * sizeof(long));  
    }  
  
    // 设置将被调用的函数的调用地址（pc为指令指针寄存器，控制着进程的具体执行）  
    regs->ARM_pc = addr;  
  
    // 根据当前进程的运行模式，设置进程的状态寄存器cpsr的值  
    if (regs->ARM_pc & 1) {  
        /* thumb */  
        regs->ARM_pc &= (~1u);  
        regs->ARM_cpsr |= CPSR_T_MASK;  
    } else {  
        /* arm */  
        regs->ARM_cpsr &= ~CPSR_T_MASK;  
    }  
  
    // 设置函数调用完的返回地址为0，触发地址0异常，程序的控制权又从目标pid进程回到了当前进程中  
    regs->ARM_lr = 0;  
    
    printf("set regs ok\n");
    // 设置目标pid进程的寄存器的状态值--实现在目标pid进程中调用指定的目标函数  
    if (ptrace_setregs(pid, regs) == -1  
        // 让目标pid进程继续执行代码指令  
        || ptrace_continue(pid) == -1) {  
  
        printf("error\n");  
        return -1;  
    }  
  
    int stat = 0;  
  
    // 等待在目标pid进程中，调用指定的目标函数完成  
    waitpid(pid, &stat, WUNTRACED);  
  
    /*** 
     WUNTRACED告诉waitpid，如果子进程进入暂停状态，那么就立即返回。 
     如果是被ptrace的子进程，那么即使不提供WUNTRACED参数，也会在子进程进入暂停状态的时候立即返回。 
     对于使用PTRACE_CONT运行的子进程，它会在3种情况下进入暂停状态：①下一次系统调用；②子进程退出；③子进程的执行发生错误。 
     这里的0xb7f就表示子进程进入了暂停状态，且发送的错误信号为11(SIGSEGV)，它表示试图访问未分配给自己的内存, 或试图往没有写权限的内存地址写数据。 
     那么什么时候会发生这种错误呢？ 
     显然，当子进程执行完注入的函数后，由于我们在前面设置了regs->ARM_lr = 0，它就会返回到0地址处继续执行，这样就会产生SIGSEGV。 
     ***/  
    while (stat != 0xb7f) {  
        if (ptrace_continue(pid) == -1) {  
  
            printf("error\n");  
            return -1;  
        }  
  
        // 进程等待  
        waitpid(pid, &stat, WUNTRACED);  
    }  
  
    return 0;  
}  


 
long ptrace_retval(struct pt_regs * regs)  
{  
    return regs->ARM_r0;
}  
  
long ptrace_ip(struct pt_regs * regs)  
{  
    return regs->ARM_pc;
}

int ptrace_call_wrapper(pid_t target_pid, const char * func_name, void * func_addr, long * parameters, int param_num, struct pt_regs * regs)  
{  
    printf("[+] Calling %s in target process.\n", func_name);  
   
    if (ptrace_call(target_pid, (uint32_t)func_addr, parameters, param_num, regs) == -1)  
        return -1;  
    printf("ptrace_call_ok\n");
    if (ptrace_getregs(target_pid, regs) == -1)  
        return -1;  
    printf("[+] Target process returned from %s, return value=%x, pc=%x \n",  
            func_name, ptrace_retval(regs), ptrace_ip(regs));  
  
    return 0;  
} 



int DoInject(uint32_t TargetPid){
     int ret = -1;  
    void *mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr;  
    void *local_handle, *remote_handle, *dlhandle;  
    uint8_t *dlopen_param1_ptr, *dlsym_param2_ptr, *saved_r0_pc_ptr, *inject_param_ptr, *remote_code_ptr, *local_code_ptr;  
  
    // 用于保存目标pid进程的寄存器状态值  
    struct pt_regs regs, original_regs;  
  
    // 用于保存目标pid进程中的dopen函数调用地址以及参数的值、dlsym函数调用地址以及参数的值、以及诸如so的导出函数function_name以及参数值  
    extern uint32_t _dlopen_addr_s, _dlopen_param1_s, _dlopen_param2_s, _dlsym_addr_s, \  
        _dlsym_param2_s, _dlclose_addr_s, _inject_start_s, _inject_end_s, _inject_function_param_s, \  
        _saved_cpsr_s, _saved_r0_pc_s;  
  
    uint32_t code_length;  
    long params[10]={0};

    if (ptrace_attach(TargetPid) == -1)  
        return -1; 
    if (ptrace_getregs(TargetPid, &regs) == -1)  
        return -1; 

  //save regs
    memcpy(&original_regs, &regs, sizeof(regs));  

    uint32_t remote_mmap_addr=(uint32_t)get_remote_func_addr(TargetPid,libc_path,(void*)mmap);

    params[0] = 0;  // addr  
    params[1] = 0x4000; // size--在目标pid进程中申请的内存空间的大小  
    params[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot  
    params[3] =  MAP_ANONYMOUS | MAP_PRIVATE; // flags  
    params[4] = 0; //fd  
    params[5] = 0; //offset  

    if(ptrace_call_wrapper(TargetPid,"mmap",(void*)remote_mmap_addr,params,6,&regs)==-1){
        return -1;
    }
    
    long map_base=(long)ptrace_retval(&regs);

    dlopen_addr = (void*)get_remote_func_addr( TargetPid, linker_path, (void *)dlopen ); 

    dlsym_addr = (void*)get_remote_func_addr( TargetPid, linker_path, (void *)dlsym );  
  
    dlclose_addr = (void*)get_remote_func_addr( TargetPid, linker_path, (void *)dlclose );  
  
    dlerror_addr = (void*)get_remote_func_addr( TargetPid, linker_path, (void *)dlerror );  

    
    

    printf("[+] Get imports: dlopen: %x, dlsym: %x, dlclose: %x, dlerror: %x\n",  
            dlopen_addr, dlsym_addr, dlclose_addr, dlerror_addr);  
  
    printf("library path = %s\n", library_path);  
  
    ptrace_writedata(TargetPid, (uint8_t*)map_base, (uint8_t*)library_path, strlen(library_path) + 1);  
  
    // 设置调用dlopen函数的函数参数  
    params[0] = map_base;   // library_path将被加载到目标pid进程中的so文件路径  
    params[1] = RTLD_NOW| RTLD_GLOBAL;  
  
    if (ptrace_call_wrapper(TargetPid, "dlopen", dlopen_addr, params, 2, &regs) == -1)   
        return -1; 
  
    void * sohandle = (void*)ptrace_retval(&regs);  
  
    // 设置map_base中保存library_path指定的so文件的导出函数function_name字符串的内存偏移  
#define FUNCTION_NAME_ADDR_OFFSET       0x100  
    // 将library_path指定的so文件的导出函数function_name的函数名称字符串写入到目标pid进程中前面mmap申请的内存空间offset=0x100的位置  
    ptrace_writedata(TargetPid, (uint8_t* )(map_base + FUNCTION_NAME_ADDR_OFFSET), (uint8_t*)function_name, strlen(function_name) + 1);  
  
    // 设置dlsym函数调用的函数参数  
    params[0] = (long)sohandle;   // so基址模块句柄  
    params[1] = map_base + FUNCTION_NAME_ADDR_OFFSET;   // 将被获取的导出函数的调用地址  
  
    if (ptrace_call_wrapper(TargetPid, "dlsym", dlsym_addr, params, 2, &regs) == -1)  
        return -1; 
  
    // 获取调用dlsym函数后，返回的导出函数function_name的调用地址  
    void * hook_entry_addr = (void*)ptrace_retval(&regs);  

    //void* hook_entry_addr = (void*)get_remote_func_addr(TargetPid,library_path,(void*)lDoHook);
  
    // 打印获取到的导出函数function_name的调用地址  
    printf("hook_entry_addr = %p\n", hook_entry_addr);  
  
  /*
    // 设置map_base中保存调用导出函数function_name需要的函数参数的内存偏移  
#define FUNCTION_PARAM_ADDR_OFFSET      0x200  
    // 将调用hook_entry_addr函数需要的函数参数保存到前面在目标pid进程中mmap申请的内存空间offset=0x200的位置  
    ptrace_writedata(TargetPid, map_base + FUNCTION_PARAM_ADDR_OFFSET, params, strlen(param) + 1);  
  
    // 设置调用目标pid进程中hook_entry函数的函数参数  
    parameters[0] = map_base + FUNCTION_PARAM_ADDR_OFFSET;  
  */
    // 调用注入到目标pid进程中的so库的导出函数hook_entry实现我们自定义的代码，可以是Hook目标pid进程的函数  
    params[0] = 1;
    if (ptrace_call_wrapper(TargetPid, "_Z6DoHookv", hook_entry_addr, params, 1, &regs) == -1)  
        return -1; 

    // 等待用户的输入  
    printf("Press enter to dlclose and detach\n");  
    getchar();  
  
    // // 设置dlclose函数调用的函数参数  
    // params[0] = (long)sohandle;  
  
    // // 调用目标pid进程中的dlclose函数卸载上面加载的library_path指定的so文件（实现so注入的卸载）  
    // if (ptrace_call_wrapper(TargetPid, "dlclose", dlclose_addr,params, 1, &regs) == -1)  
    //     return -1;
  
  
    ptrace_setregs(TargetPid, &original_regs);  

    ptrace_detach(TargetPid);  

    ret = 0;  
   
    return ret;  
}

int main(){
    //void* localso= dlopen("/data/local/tmp/libfakeputs.so",RTLD_NOW);
    //lDoHook=dlsym(localso,"_Z6DoHookv");
    //printf("local DoHook addr:%x",lDoHook);
    pid_t targetPid=find_pid_of("./tobehook");
    printf("targetpid is :%d\n",targetPid);
    DoInject(targetPid);
    return 0;
}