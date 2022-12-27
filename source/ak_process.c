/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2004 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_process.с                                                                              */
/* ----------------------------------------------------------------------------------------------- */
#include "libakrypt.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


/*! Функция получения массива диапазонов памяти в адресном пространстве процесса,
 * а также размера данного массива.

    @param pid Идентификатор процесса.
    @param out_length Указатель на переменную для длины массива.

    @return В случае успеха функция возвращает массив вида:
    (размер секции, начало адреса)                                                                 */
/* ----------------------------------------------------------------------------------------------- */

struct section_info *get_process_memory_spans(int pid, size_t *infoSize) {
    struct section_info *result = malloc(sizeof(struct section_info));
    if (result == NULL) {
        *infoSize = 0;
        return result;
    }
    char path_to_proc_maps[255];
    *infoSize = 0;
    sprintf(path_to_proc_maps, "/proc/%i/maps", pid);
    FILE *process_maps = fopen(path_to_proc_maps, "r");
    elf_sections_data elf;
    unsigned long long sectionBegin, sectionEnd, a, b, c;
    long d = 0;
    a = 0;
    b = 0;
    c = 0;

    size_t sectionSize;
    char rights[5];
    char path[256];
    memset(rights, 0, 5);
    char line[1000];
    int k = 0;

    while (!feof(process_maps)) {
        fgets(line, 1000, process_maps);
        sscanf(line, "%llx-%llx %4s %llx %lld:%lld %ld %s\n", &sectionBegin, &sectionEnd, rights, &a, &b, &c, &d,
               &path);
        sectionSize = sectionEnd - sectionBegin;
        k++;
        if (rights[2] == 'x' && k == 2) {
            printf("'%s'\n", path);
            elf = get_executable_memory_spans((const char *) path);
            result = realloc(result, sizeof(struct section_info) * ++(*infoSize));
            printf("offf %x\n", elf.offset_text);
            result[(*infoSize) - 1].section_begin = sectionBegin + elf.offset_text - (sectionSize);
            result[(*infoSize) - 1].size_in_bits = elf.size_text;

        }
    }
    fclose(process_maps);
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
struct section_info *get_process_memory_spans_by_pid(pid_t process_id, size_t *out_length) {
    return get_process_memory_spans(process_id, out_length);
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                   ak_process.c  */
/* ----------------------------------------------------------------------------------------------- */
