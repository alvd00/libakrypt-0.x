/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_mac.c                                                                                  */
/*  - содержит реализацию алгоритмов итерационного сжатия                                          */
/* ----------------------------------------------------------------------------------------------- */
#include <libakrypt-internal.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <errno.h>

/* ----------------------------------------------------------------------------------------------- */
int ak_mac_create(ak_mac mctx, const size_t size, ak_pointer ictx,
                  ak_function_clean *clean, ak_function_update *update,
                  ak_function_finalize *finalize) {
    if (mctx == NULL)
        return ak_error_message(ak_error_null_pointer, __func__,
                                "using null pointer to mac context");
    if (!size)
        return ak_error_message(ak_error_zero_length, __func__,
                                "using zero length of input data block size");
    if (size > ak_mac_max_buffer_size)
        return ak_error_message(ak_error_wrong_length,
                                __func__, "using very huge length of input data block size");
    if (ictx == NULL)
        return ak_error_message(ak_error_null_pointer, __func__,
                                "using null pointer to internal context");
    memset(mctx->data, 0, sizeof(mctx->data));
    mctx->length = 0;
    mctx->bsize = size;
    mctx->ctx = ictx;
    mctx->clean = clean;
    mctx->update = update;
    mctx->finalize = finalize;

    return ak_error_ok;
}

/*for deleting header once_______*/
bool_t first_block_only = ak_true;

/* ----------------------------------------------------------------------------------------------- */
/*! @param mctx Указатель на контекст итерационного сжатия.
    @return В случае успеха возвращается \ref ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
int ak_mac_destroy(ak_mac mctx) {
    if (mctx == NULL)
        return ak_error_message(ak_error_null_pointer, __func__,
                                "using null pointer to mac context");
    memset(mctx->data, 0, sizeof(mctx->data));
    mctx->length = 0;
    mctx->bsize = 0;
    mctx->ctx = NULL;
    mctx->clean = NULL;
    mctx->update = NULL;
    mctx->finalize = NULL;

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param mctx Указатель на контекст итерационного сжатия.
    @return В случае успеха возвращается \ref ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
int ak_mac_clean(ak_mac mctx) {
    int error = ak_error_ok;
    if (mctx == NULL)
        return ak_error_message(ak_error_null_pointer, __func__,
                                "using a null pointer to internal mac context");
    if (mctx->clean == NULL)
        return ak_error_message(ak_error_undefined_function, __func__,
                                "using an undefined clean function");
    memset(mctx->data, 0, ak_mac_max_buffer_size);
    mctx->length = 0;
    if ((error = mctx->clean(mctx->ctx)) != ak_error_ok)
        ak_error_message(error, __func__, "incorrect cleaning of parent context");

    return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param mctx Указатель на контекст итерационного сжатия.
    @param in Сжимаемые данные
    @param size Размер сжимаемых данных в байтах. Данное значение может
    быть произвольным, в том числе равным нулю и/или не кратным длине блока обрабатываемых данных
    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
int ak_mac_update(ak_mac mctx, const ak_pointer in, const size_t size) {
    ak_uint8 *ptrin = (ak_uint8 *) in;
    size_t quot = 0, offset = 0, newsize = size;

    if (mctx == NULL)
        return ak_error_message(ak_error_null_pointer, __func__,
                                "using a null pointer to internal mac context");
    if (mctx->update == NULL)
        return ak_error_message(ak_error_undefined_function, __func__,
                                "using an undefined update function");
    /* в начале проверяем, есть ли данные во временном буфере */
    if (mctx->length != 0) {
        /* если новых данных мало, то добавляем во временный буффер и выходим */
        if ((mctx->length + newsize) < mctx->bsize) {
            memcpy(mctx->data + mctx->length, ptrin, newsize);
            mctx->length += newsize;
            return ak_error_ok;
        }
        /* дополняем буффер до длины, кратной bsize */
        offset = mctx->bsize - mctx->length;
        memcpy(mctx->data + mctx->length, ptrin, offset);

        /* обновляем значение контекста функции и очищаем временный буффер */
        mctx->update(mctx->ctx, mctx->data, mctx->bsize);
        memset(mctx->data, 0, mctx->bsize);
        mctx->length = 0;
        ptrin += offset;
        newsize -= offset;
    }

    /* теперь обрабатываем входные данные с пустым временным буффером */
    if (newsize != 0) {
        quot = newsize / mctx->bsize;
        offset = quot * mctx->bsize;
        /* обрабатываем часть, кратную величине bsize */
        if (quot > 0) mctx->update(mctx->ctx, ptrin, offset);
        /* хвост оставляем на следующий раз */
        if (offset < newsize) {
            mctx->length = newsize - offset;
            memcpy(mctx->data, ptrin + offset, mctx->length);
        }
    }

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Конечный результат применения сжимающего отображения помещается в область памяти,
    на которую указывает out. Если out равен NULL, то возвращается ошибка.

    \note Внутренняя структура, хранящая промежуточные данные, не очищается. Это позволяет повторно
    вызывать функцию finalize к текущему состоянию.

    @param mctx Указатель на контекст итерационного сжатия.
    @param in Указатель на входные данные для которых вычисляется хеш-код.
    @param size Размер входных данных в байтах.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти должен быть не менее значения поля hsize для класса-родителя и может
    быть определен с помощью вызова соответствующей функции, например, ak_hash_context_get_tag_size().
    @param out_size Размер области памяти (в октетах), в которую будет помещен результат.

    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
int ak_mac_finalize(ak_mac mctx,
                    const ak_pointer in, const size_t size, ak_pointer out, const size_t out_size) {
    if (mctx == NULL)
        return ak_error_message(ak_error_null_pointer, __func__,
                                "using a null pointer to internal mac context");
    if (mctx->finalize == NULL)
        return ak_error_message(ak_error_undefined_function, __func__,
                                "using an undefined finalize function");
    /* начинаем с того, что обрабатываем все переданные данные */
    if (ak_mac_update(mctx, in, size) != ak_error_ok)
        return ak_error_message(ak_error_get_value(), __func__, "incorrect updating input data");

    /* потом обрабатываем хвост, оставшийся во временном буффере, и выходим */
    return mctx->finalize(mctx->ctx, mctx->data, mctx->length, out, out_size);
}

/* ----------------------------------------------------------------------------------------------- */
/*! \note Внутренняя структура, хранящая промежуточные данные, не очищается. Это позволяет повторно
    примененять функцию finalize к текущему состоянию.

    @param mctx Указатель на контекст итерационного сжатия.
    @param in Указатель на входные данные для которых вычисляется хеш-код.
    @param size Размер входных данных в байтах.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти должен быть не менее значения поля hsize для класса-родителя и может
    быть определен с помощью вызова соответствующей функции, например, ak_hash_context_get_tag_size().
    @param out_size Размер области памяти (в октетах), в которую будет помещен результат.

    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
int ak_mac_ptr(ak_mac mctx,
               const ak_pointer in, const size_t size, ak_pointer out, const size_t out_size) {
    int error = ak_error_ok;
    if (mctx == NULL)
        return ak_error_message(ak_error_null_pointer, __func__,
                                "using null pointer to mac context");
    if ((error = ak_mac_clean(mctx)) != ak_error_ok)
        ak_error_message(error, __func__, "incorrect cleaning of mac context");

    if ((error = ak_mac_finalize(mctx, in, size, out, out_size)) != ak_error_ok)
        return ak_error_message(error, __func__, "incorrect updating mac context");

    return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет результат сжимающего отображения для заданного файла и помещает
    его в область памяти, на которую указывает out.

    @param mctx Указатель на контекст итерационного сжатия.
    @param filename имя сжимаемого файла
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти должен быть не менее значения поля hsize для класса-родителя и может
    быть определен с помощью вызова соответствующей функции, например, ak_hash_context_get_tag_size().
    @param out_size Размер области памяти (в октетах), в которую будет помещен результат.

    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
int ak_mac_file(ak_mac mctx, const char *filename, ak_pointer out, const size_t out_size) {
    size_t len = 0;
    struct file file;
    int error = ak_error_ok;
    size_t block_size = 4096; /* оптимальная длина блока для Windows пока не ясна */
    ak_uint8 *localbuffer = NULL; /* место для локального считывания информации */

    /* выполняем необходимые проверки */
    if (mctx == NULL)
        return ak_error_message(ak_error_null_pointer, __func__,
                                "use a null pointer to mac context");
    if (filename == NULL)
        return ak_error_message(ak_error_null_pointer, __func__,
                                "use a null pointer to filename");
    if ((error = ak_mac_clean(mctx)) != ak_error_ok)
        return ak_error_message(error, __func__, "incorrect cleaning a mac context");

    if ((error = ak_file_open_to_read(&file, filename)) != ak_error_ok)
        return ak_error_message_fmt(error, __func__, "incorrect access to file %s", filename);

    /* для файла нулевой длины результатом будет хеш от нулевого вектора */
    if (!file.size) {
        ak_file_close(&file);
        return ak_mac_finalize(mctx, "", 0, out, out_size);
    }

    /* готовим область для хранения данных */
    block_size = ak_max((size_t) file.blksize, mctx->bsize);
    /* здесь мы выделяем локальный буффер для считывания/обработки данных */
    if ((localbuffer = (ak_uint8 *) ak_aligned_malloc(block_size)) == NULL) {
        ak_file_close(&file);
        return ak_error_message(ak_error_out_of_memory, __func__,
                                "memory allocation error for local buffer");
    }
    /* теперь обрабатываем файл с данными */
    read_label:
    len = (size_t) ak_file_read(&file, localbuffer, block_size);
    if (len == block_size) {
        ak_mac_update(mctx, localbuffer, block_size); /* добавляем считанные данные */
        goto read_label;
    } else {
        size_t qcnt = len / mctx->bsize,
                tail = len - qcnt * mctx->bsize;
        if (qcnt) ak_mac_update(mctx, localbuffer, qcnt * mctx->bsize);
        error = ak_mac_finalize(mctx,
                                localbuffer + qcnt * mctx->bsize, tail, out, out_size);
    }
    /* очищаем за собой данные, содержащиеся в контексте */
    ak_mac_clean(mctx);
    /* закрываем данные */
    ak_file_close(&file);
    ak_aligned_free(localbuffer);
    return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет результат сжимающего отображения для заданного исполняемого файла и помещает
    его в область памяти, на которую указывает out.

    @param mctx Указатель на контекст итерационного сжатия.
    @param identity Структура с информацией о сжимаемом исполняемом файле.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти должен быть не менее значения поля hsize для класса-родителя и может
    быть определен с помощью вызова соответствующей функции, например, ak_hash_context_get_tag_size().
    @param out_size Размер области памяти (в октетах), в которую будет помещен результат.

    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
int ak_mac_executable_file(ak_mac mctx, ak_identity_info identity, ak_pointer out, const size_t out_size) {
    int error = ak_error_ok;
    size_t spans_array_length = 0;
    elf_sections_data executable_memory_spans = get_executable_memory_spans(identity.name);


//    printf("address %lx \n",  executable_memory_spans.begin_address_rodata);
//    printf("size %lld\n21", executable_memory_spans->size_rodata);

//    if (spans_array_length == 0) {
//        return ak_mac_finalize(mctx, "", 0, out, out_size);
//    }

    ak_uint8 *data_for_hashing = NULL;
    size_t total_size = 0;
//    for (int i = 0; i < spans_array_length; i++) {
//    total_size = executable_memory_spans.size_text;
//    printf("size %lld\n", executable_memory_spans.size_text);

//    }

    data_for_hashing = malloc(total_size);

    for (int i = 0; i < spans_array_length; i++) {
        // TODO update function like fpr processes
        ak_mac_update(mctx, data_for_hashing, executable_memory_spans.size_text);
    }

    error = ak_mac_finalize(mctx, data_for_hashing, total_size, out, out_size);

    ak_mac_clean(mctx);
    ak_aligned_free(data_for_hashing);
    return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет результат сжимающего отображения для заданного процесса и помещает
    его в область памяти, на которую указывает out.

    @param mctx Указатель на контекст итерационного сжатия.
    @param identity Сутруктура с информацией о сжимаемом роцессе.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти должен быть не менее значения поля hsize для класса-родителя и может
    быть определен с помощью вызова соответствующей функции, например, ak_hash_context_get_tag_size().
    @param out_size Размер области памяти (в октетах), в которую будет помещен результат.

    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */

pid_t parse_pid1(const char *p) {
    while (!isdigit(*p) && *p)
        p++;
    return strtol(p, 0, 0);
}

int ak_mac_process(ak_mac mctx, ak_identity_info identity, ak_pointer out, const size_t out_size) {
    int error = ak_error_ok;
    size_t spans_array_length = 0;
    pid_t name_pid = (int)parse_pid1(identity.name);


    if (ptrace(PTRACE_SEIZE, name_pid , NULL, NULL) == -1) {
        printf("%d \n",errno);
        return errno;
    }

    memory_span *process_memory_spans = get_process_memory_spans_by_pid(identity.name, &spans_array_length);

    if (spans_array_length == 0) {
        return ak_mac_finalize(mctx, "", 0, out, out_size);
    }

    long *data_for_hashing = NULL;
    size_t total_size = 0;
    for (int i = 0; i < spans_array_length; i++) {
        total_size += process_memory_spans[i].size;
    }

    //TODO проверить, что память выделилась
    for (int i = 0; i < spans_array_length - 1; i++) {
        // memcpy all spans to data for hashing (to spans_array_length)
        printf("%lld \n",process_memory_spans[i].size);
        //data_for_hashing=realloc(process_memory_spans[i].begin_address,process_memory_spans[i].size);
        data_for_hashing = malloc((size_t)process_memory_spans[i].size);
        for (int j = 0; j < process_memory_spans[i].size; j += sizeof(long)) {
            //TODO проверка на то, что ерно не содержит ошибок иначе возврат ерно
            data_for_hashing[j / sizeof(long)] = ptrace(PTRACE_PEEKTEXT, identity.name,
                                                        process_memory_spans[i].begin_address + j, NULL);
            if (errno!=0){
                ptrace(PTRACE_DETACH, identity.name, NULL, NULL);
                return errno;
            }

        }

        //TODO проверка возвращаемого значения
        ak_mac_update(mctx, (const ak_pointer) data_for_hashing, process_memory_spans[i].size);
        free(data_for_hashing);
    }
//call after all memcpy memmove
//    error = ak_mac_finalize(mctx, data_for_hashing, total_size, out, out_size);
    error = ak_mac_finalize(mctx, process_memory_spans[spans_array_length - 1].begin_address,
                            process_memory_spans[spans_array_length - 1].size, out, out_size);

    ak_mac_clean(mctx);
    //TODO проверка что не -1
    ptrace(PTRACE_DETACH, identity.name, NULL, NULL);
//    ak_aligned_free(data_for_hashing);*/
    return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция определяет тип файла или процесса, указанный в identity.type и вызывает
 *  функцию, вычисляемую результат сжимающего отображения для заданного типа.

    @param mctx Указатель на контекст итерационного сжатия.
    @param identity Структура с информацией о сжимаемом файле либо процессе.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти должен быть не менее значения поля hsize для класса-родителя и может
    быть определен с помощью вызова соответствующей функции, например, ak_hash_context_get_tag_size().
    @param out_size Размер области памяти (в октетах), в которую будет помещен результат.

    @return В случае успеха функция вызывает соответсвующую функцию, вычисляемую результат сжимающего
    отображения для файла или процесса(\ref ak_error_ok). В противном случае возвращается код ошибки.
                                                                                                   */
/* ----------------------------------------------------------------------------------------------- */

int ak_choose_processing_strategy(ak_mac mctx, ak_identity_info identity, ak_pointer out, const size_t out_size) {
    int error = ak_error_ok;
    switch (identity.type) {
        case linux_file:
            error = ak_mac_file(mctx, identity.name, out, out_size);
            break;
        case linux_executable_x32:
        case linux_executable_x64:
            error = ak_mac_executable_file(mctx, identity, out, out_size);
            break;
        case win_file:
            error = ak_mac_file(mctx, identity.name, out, out_size);
            break;
        case win_executable:
            error = ak_error_function_not_implemented;
            ak_error_message(error, __func__, "no implementation for windows");
            break;
        case linux_process:
            error = ak_mac_process(mctx, identity, out, out_size);
            break;
        case win_process:
            error = ak_error_function_not_implemented;
            ak_error_message(error, __func__, "no implementation for windows");
            break;
        default:
            error = ak_error_undefined_value;
            ak_error_message(error, __func__, "Processing type not defined or implemented.");
            break;
    }
    return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_mac.c  */
/* ----------------------------------------------------------------------------------------------- */
