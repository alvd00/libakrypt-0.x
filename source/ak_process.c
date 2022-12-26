/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2004 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_process.с                                                                              */
/* ----------------------------------------------------------------------------------------------- */
#include "libakrypt-base.h"
#include "libakrypt.h"
#include <sys/errno.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <string.h>
#include <stdlib.h>


/*! Функция получения массива диапазонов памяти в адресном пространстве процесса,
 * а также размера данного массива.

    @param pid Идентификатор процесса.
    @param out_length Указатель на переменную для длины массива.

    @return В случае успеха функция возвращает массив вида:
    (размер секции, начало адреса)                                                                 */
/* ----------------------------------------------------------------------------------------------- */


memory_span *get_process_memory_spans1(pid_t pid, size_t *out_length) {
    char filename[PATH_MAX];
    FILE *f;
    int i = 0;
    long long int *begin, *end;
    ak_int64 size;
    memory_span *array_process_data = NULL;

    sprintf(filename, "/proc/%ld/maps", (long) pid);
    f = fopen(filename, "r");
    array_process_data = malloc(4096);
    long long int total = 0;
    while (!feof(f)) {
        char buf[PATH_MAX + 700], perm[5];
        if (fgets(buf, sizeof(buf), f) == 0){
            break;
        }
        sscanf(buf, "%llx-%llx %s ", &begin, &end, perm);
        size = (ak_uint64)end - (ak_uint64)begin;

        array_process_data[i].begin_address = (long *) begin;
        array_process_data[i].size = size;
//        total+=size;
        i++;
    }
//     printf("size: %llu \n", total);

    *out_length = i;
    return array_process_data;
}






struct SectionInfo* get_process_memory_spans(int pid, size_t* infoSize)
{
    struct SectionInfo* result = malloc(sizeof(struct SectionInfo));
    if(result == NULL)
    {
        *infoSize = 0;
        return result;
    }
    char pathToProcMaps[255];
    *infoSize = 0;
    sprintf(pathToProcMaps, "/proc/%i/maps", pid);
    FILE* processMaps = fopen(pathToProcMaps, "r");
    unsigned long long sectionBegin, sectionEnd;
    size_t sectionSize;
    char rights[5];
    memset(rights, 0, 5);
    char line[1000];
    while(!feof(processMaps))
    {
        fgets(line, 1000, processMaps);
        sscanf(line, "%llx-%llx %4s", &sectionBegin, &sectionEnd, rights);
        sectionSize = sectionEnd - sectionBegin;
        if(rights[0] == 'r')
        {
            result = realloc(result, sizeof(struct SectionInfo) * ++(*infoSize));
            result[(*infoSize) - 1].sectionBegin = sectionBegin;
            result[(*infoSize) - 1].sizeInBits = sectionSize;
        }
    }
    fclose(processMaps);
    return result;
}












/* ----------------------------------------------------------------------------------------------- */
/*! Функция преобразовывает идентификатор процесса из char* в тип идентификатора процесса .

    @param pid Идентификатор процесса.

    @return В случае успеха функция возвращает преобразованный идентификатор процесса типа pid_t   */
/* ----------------------------------------------------------------------------------------------- */
pid_t parse_pid(const char *p) {
    while (!isdigit(*p) && *p)
        p++;
    return strtol(p, 0, 0);
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция преобразовывает идентификатор процесса в соответствующий тип и по нему вызывает функцию,
 * возвращающую массива диапазонов памяти в адресном пространстве пространстве процесса и его размер.

    @param pid Идентификатор процесса.
    @param out_length Указатель на переменную для длины массива.

    @return В случае успеха функция возвращает массив вида:
    (начало адреса, размер секции, конец адреса)                                                   */
/* ----------------------------------------------------------------------------------------------- */
struct SectionInfo * get_process_memory_spans_by_pid(pid_t process_id, size_t *out_length) {
//    pid_t pid = parse_pid(process_id);
    return get_process_memory_spans(process_id, out_length);
}

/* ----------------------------------------------------------------------------------------------- */
/*перевод 16-чной long long int в char * */
static const char *xllitoa(long long int x) {
    static char buff[40];
    char *p = buff + 40;
    int sign = 0;
    *(p--) = 0;
    if (x < 0) sign = 1;
    else x = -x;
    do {
        if (-(x % 16) == 0) { *(p--) = '0'; }
        if (-(x % 16) == 1) { *(p--) = '1'; }
        if (-(x % 16) == 2) { *(p--) = '2'; }
        if (-(x % 16) == 3) { *(p--) = '3'; }
        if (-(x % 16) == 4) { *(p--) = '4'; }
        if (-(x % 16) == 5) { *(p--) = '5'; }
        if (-(x % 16) == 6) { *(p--) = '6'; }
        if (-(x % 16) == 7) { *(p--) = '7'; }
        if (-(x % 16) == 8) { *(p--) = '8'; }
        if (-(x % 16) == 9) { *(p--) = '9'; }
        if (-(x % 16) == 10) { *(p--) = 'a'; }
        if (-(x % 16) == 11) { *(p--) = 'b'; }
        if (-(x % 16) == 12) { *(p--) = 'c'; }
        if (-(x % 16) == 13) { *(p--) = 'd'; }
        if (-(x % 16) == 14) { *(p--) = 'e'; }
        if (-(x % 16) == 15) { *(p--) = 'f'; }
        x /= 16;
    } while (x);
    if (sign) *(p--) = '-';
    return (const char *) (p + 1);
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                   ak_process.c  */
/* ----------------------------------------------------------------------------------------------- */
