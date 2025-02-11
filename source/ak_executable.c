/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2004 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_executable.с                                                                           */
/* ----------------------------------------------------------------------------------------------- */
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include "libakrypt-base.h"
#include "libakrypt.h"

/*! Функция получения массива диапазонов памяти в адресном пространстве исполняемого файла,
 * а также размера данного массива.

    @param filename Имя исполняемого файла.
    @param out_length Указатель на переменную для длины массива.

    @return В случае успеха функция возвращает массив вида:
    (размер секции, начало адреса)                                                                 */
/* ----------------------------------------------------------------------------------------------- */

elf_sections_data get_executable_memory_spans(const char *filename) {

    int fd;
    int filesize;
    void *data;
    char *str;
    Elf64_Ehdr *elf;
    Elf64_Shdr *shdr;
    Elf64_Rela *elfhead = NULL;
    elf_sections_data sections_data;

    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("open : ");
    }

    filesize = lseek(fd, 0, SEEK_END);

    data = mmap(NULL, filesize, PROT_READ, MAP_SHARED, fd, 0);

    elf = (Elf64_Ehdr *) (data);
    shdr = (Elf64_Shdr *) ((char *) data + elf->e_shoff);
    str = (char *) ((char *) data + shdr[elf->e_shstrndx].sh_offset);
    for (int i = 0; i < elf->e_shnum; i++) {
        if (strcmp(&str[shdr[i].sh_name], ".text") == 0) {

            sections_data.begin_address_text = shdr[i].sh_addr;
            sections_data.size_text = shdr[i].sh_size;
            sections_data.offset_text = shdr[i].sh_offset;

        }
    }

    close(fd);
    return sections_data;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                ak_executable.c  */
/* ----------------------------------------------------------------------------------------------- */


