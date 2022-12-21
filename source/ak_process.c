/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2004 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_file.с                                                                                 */
/* ----------------------------------------------------------------------------------------------- */
#include <libakrypt-base.h>
#include "libakrypt.h"


/*Функции, получающие данные о процессе по его id*/
process_data *print_maps(pid_t pid, size_t *length) {
    char fname[PATH_MAX];
    FILE *f;
    int i = 0;
    void *begin, *end;
    ak_int64 size;

    sprintf(fname, "/proc/%ld/maps", (long) pid);
    f = fopen(fname, "r");
    process_data *array_process_data = NULL;
    array_process_data = malloc(35);
    while (!feof(f)) {
        char buf[PATH_MAX + 100], perm[5], mapname[PATH_MAX];
        i++;
        if (fgets(buf, sizeof(buf), f) == 0)
            break;
        mapname[0] = '\0';
        sscanf(buf, "%llx-%llx %4s ", &begin, &end, perm);
        size = (ak_int64) end - (ak_int64) begin;

        array_process_data[i].begin_address = begin;
        array_process_data[i].end_address = end;
        array_process_data[i].size = size;//array_process_data[i].begin_address - array_process_data[i].begin_address;
    }
    *length = i;
    return array_process_data;
}

pid_t parse_pid(char *p) {
    while (!isdigit(*p) && *p)
        p++;
    return strtol(p, 0, 0);
}

process_data * aktool_icode_proc(char *process_id, size_t *length) {
    char *ppid;
    pid_t pid;
    ppid = process_id;
    pid = parse_pid(ppid);
    return print_maps(pid, length);
}



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
