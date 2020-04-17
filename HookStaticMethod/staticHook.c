//
//  staticHook.c
//  HookStaticMethod
//
//  Created by Qu,Ke on 2020/4/16.
//  Copyright © 2020 baidu. All rights reserved.
//

#include "staticHook.h"
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>

#include <objc/runtime.h>
#include <stdlib.h>

#include "dlfcn.h"
#include "string.h"

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

bool isMainExceteHead(struct mach_header *header) {
    Dl_info info;
    
    if (dladdr(header, &info) == 0) {
        return false;
    }
    
    if (strstr(info.dli_fname, "HookStaticMethod")) { // 最好动态使用自定义类地址查找fname比较
        return true;
    }
    
    return false;
}


void _searchStaticMethodForName(const struct mach_header *header,
                                 intptr_t slide,
                                 const char *mname) {
    
    // 遍历load commond 查找sym tab ，str tab 位置
    segment_command_t *cur_seg_cmd;
    segment_command_t *linkedit_segment = NULL;
    segment_command_t *pageZero_cmd = NULL;
    struct symtab_command * symtab_comand = NULL;
    
    uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
    for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (segment_command_t *)cur;
        if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
            if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
                linkedit_segment = cur_seg_cmd;
            } else if (strcmp(cur_seg_cmd->segname, SEG_PAGEZERO) == 0 ) {
                pageZero_cmd = cur_seg_cmd;
            }
            
            
        } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
            
            symtab_comand = (struct symtab_command*)cur_seg_cmd;
        }
    }
    
    if (!linkedit_segment ||
        !symtab_comand ||
        !pageZero_cmd) {
        printf("linkedit_segment or symtab_comand find ");
        return;
    }
    

    
    uintptr_t segBase = (uintptr_t)header; //
    
    uintptr_t baseAddr = pageZero_cmd->vmsize; // 基地址
    
    //    segBase = segment的vmaddr - linkedit_segment->fileoff
    //    segBase = baseAddr + slide
    //    uintptr_t vmbase = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
    //    if (vmbase == (uintptr_t)header) {
    //
    //    }
        
    nlist_t *symtab = (nlist_t *)(segBase + symtab_comand->symoff);
    char * strtab = (char *)(segBase + symtab_comand->stroff);
        
    
    char * curFile = NULL;
    
    for (uint i = 0; i < symtab_comand->nsyms; i++) {
        
        nlist_t sym = (nlist_t)symtab[i];
        uint32_t strtab_offset = sym.n_un.n_strx;
        
        char *symbol_name = strtab + strtab_offset;
        bool symbol_name_longer_than_1 = symbol_name[0] && symbol_name[1];
        
        
        if (sym.n_type == 0x64 && symbol_name_longer_than_1) {
            /*
             N_STAB (0xe0)—If any of these 3 bits are set, the symbol is a symbolic debugging table (stab) entry. In that case, the entire n_type field is interpreted as a stab value. See /usr/include/mach-o/stab.h for valid stab values.
             */
            if (curFile != NULL) {
                                    free(curFile);
                                    curFile = NULL;
            }
            curFile = malloc(strlen(symbol_name) + 1);
            strcpy(curFile, symbol_name);
//            printf("fileName %s\n\n",curFile);
            continue;
        }
        
        // https://developer.apple.com/documentation/kernel/nlist/1583961-n_type?language=objc
        // sym.n_type == N_SECT  . For the N_SECT symbol type, n_value is the address of the symbol. See the description of the n_type field for information on other possible values.
        // n_type char
        /*
         *  二进制空间    111        1               111      1
                        N_STAB     N_PEXT        N_TYPE    N_EXT
         
         
       
                                                
         */
        if (symbol_name_longer_than_1 &&
            strcmp(&symbol_name[1], mname) == 0) {
            
            if ((sym.n_type & N_STAB) == 0) { //
                /*
                   N_STAB (0xe0)—If any of these 3 bits are set, the symbol is a symbolic debugging table (stab) entry. In that case, the entire n_type field is interpreted as a stab value. See /usr/include/mach-o/stab.h for valid stab values.
                 */
                // 选择打开N_STAB的符号
                continue;
            }
            
            printf("函数n_type 0x%x \n",sym.n_type);

            printf("函数文件名称 %s \n",curFile);
            printf("基地址 0x%lx \n",baseAddr);
            printf("可执行文件地址 0x%lx \n",(uintptr_t)header);
            printf("符号表存储函数位置 0x%llx \n",sym.n_value);
            

            uintptr_t funAddress = sym.n_value - baseAddr +  (uintptr_t)header;
            void (*funtion1)(void) = (void( *)(void))funAddress;
            funtion1();
            
        }
    }
    
    if (curFile != NULL) {
        free(curFile);
    }
    
    
}

void searchStaticMethodForName(const char *mname) {
    
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++) {
        struct mach_header * mach_header = (struct mach_header *)_dyld_get_image_header(i);
        if (isMainExceteHead(mach_header)) { //仅查询可执行mach-o文件
            intptr_t vm_slider = _dyld_get_image_vmaddr_slide(i);
            _searchStaticMethodForName(mach_header, vm_slider, mname);
        }
    }
}

