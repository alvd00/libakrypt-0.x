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

struct section_info* get_process_memory_spans(int pid, size_t* infoSize)
{
    struct section_info* result = malloc(sizeof(struct section_info));
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
            result = realloc(result, sizeof(struct section_info) * ++(*infoSize));
            result[(*infoSize) - 1].section_begin = sectionBegin;
            result[(*infoSize) - 1].size_in_bits = sectionSize;
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

/* ----------------------------------------------------------------------------------------------- */
/*! Функция преобразовывает идентификатор процесса в соответствующий тип и по нему вызывает функцию,
 * возвращающую массива диапазонов памяти в адресном пространстве пространстве процесса и его размер.

    @param pid Идентификатор процесса.
    @param out_length Указатель на переменную для длины массива.

    @return В случае успеха функция возвращает массив вида:
    (начало адреса, размер секции, конец адреса)                                                   */
/* ----------------------------------------------------------------------------------------------- */
struct section_info * get_process_memory_spans_by_pid(pid_t process_id, size_t *out_length) {
    return get_process_memory_spans(process_id, out_length);
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                   ak_process.c  */
/* ----------------------------------------------------------------------------------------------- */
