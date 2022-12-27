/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2021 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Прикладной модуль, реализующий процедуры проверки целостности данных                           */
/*                                                                                                 */
/*  aktool_icode.c                                                                                 */
/* ----------------------------------------------------------------------------------------------- */
#include <aktool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef AK_HAVE_ERRNO_H

#include <errno.h>

#endif

/* ----------------------------------------------------------------------------------------------- */
int aktool_icode_help(void);

int aktool_icode_work(int argc, tchar *argv[]);

int aktool_icode_check(void);

tchar *aktool_strtok_r(tchar *, const tchar *, tchar **);

int aktool_file_or_process(char *type);

ak_identity_type aktool_get_identity_type(const char *filename, int type);



/* ----------------------------------------------------------------------------------------------- */
int aktool_icode(int argc, tchar *argv[]) {
    int next_option = 0, exit_status = EXIT_FAILURE;
    enum {
        do_nothing, do_hash, do_check
    } work = do_hash;

    const struct option long_options[] = {
            /* сначала уникальные */
            {"algorithm", 1, NULL, 'a'},
            {"pattern", 1, NULL, 'p'},
            {"output", 1, NULL, 'o'},
            {"recursive", 0, NULL, 'r'},
            {"reverse-order", 0, NULL, 254},
            {"seed", 1, NULL, 253},
            {"tag", 0, NULL, 250},
            {"mode", 1, NULL, 'm'},
            {"no-derive", 0, NULL, 160},
            {"check", 1, NULL, 'c'},
            {"dont-show-stat", 0, NULL, 161},
            {"ignore-errors", 0, NULL, 162},
            {"type", 1, NULL, 240},

            /* аналоги из aktool_key */
            {"key", 1, NULL, 203},
            {"inpass-hex", 1, NULL, 251},
            {"inpass", 1, NULL, 252},

            /* это стандартые для всех программ опции */
            aktool_common_functions_definition,
            {NULL, 0, NULL, 0},
    };

    /* устанавливаем значения по-умолчанию */
    ki.processing_type = 0;
    ki.method = ak_oid_find_by_name("streebog256");
    ki.mode = NULL;
    ki.outfp = NULL;
    ki.pattern =
#ifdef _WIN32
            "*.*";
#else
            "*";
#endif
    ki.tree = ak_false;
    ki.outfp = stdout;
    ki.seed = NULL;
    ki.key_derive = ak_true;
    ki.ignore_errors = ak_false;
    ki.dont_show_stat = ak_false;

    /* разбираем опции командной строки */
    do {
        next_option = getopt_long(argc, argv, "ha:p:ro:m:c:", long_options, NULL);
        switch (next_option) {
            aktool_common_functions_run(aktool_icode_help);

            case 'a': /* --algorithm устанавливаем имя криптографического алгоритма */
                if ((ki.method = ak_oid_find_by_ni(optarg)) == NULL) {
                    aktool_error(_("using unsupported name or identifier \"%s\""), optarg);
                    printf(_("try \"aktool s --oids\" for list of all available identifiers\n"));
                    return EXIT_FAILURE;
                }
                break;

            case 'm': /* --mode  устанавливаем режим использования криптографического алгоритма */
                if ((ki.mode = ak_oid_find_by_ni(optarg)) == NULL) {
                    aktool_error(_("using unsupported name or identifier \"%s\""), optarg);
                    printf(_("try \"aktool s --oids\" for list of all available identifiers\n"));
                    return EXIT_FAILURE;
                }
                if (ki.mode->engine != block_cipher) {
                    aktool_error(_("you must use the block cipher mode as an argument to the --mode option"));
                    printf(_("try \"aktool s --oid cipher\" for list of all available identifiers\n"));
                    return EXIT_FAILURE;
                }
                switch (ki.mode->mode) {
                    case mac: /* здесь перечисляются допустимые режимы выработки имитовставки */
                        break;
                    default:
                        aktool_error(_("argument of --mode option must be authentication mode (mac) for block cipher"));
                        return EXIT_FAILURE;
                }
                break;

            case 'o' : /* устанавливаем имя файла для вывода результатов */
#ifdef _WIN32
                GetFullPathName( optarg, FILENAME_MAX, ki.op_file, NULL );
#else
                realpath(optarg, ki.op_file);
#endif
                if ((ki.outfp = fopen(optarg, "w")) == NULL) {
                    aktool_error(_("checksum file \"%s\" cannot be created"), optarg);
                    return EXIT_FAILURE;
                }
                break;

            case 'c' : /* выполняем проверку контрольных сумм */
                work = do_check;
#ifdef _WIN32
                GetFullPathName( optarg, FILENAME_MAX, ki.os_file, NULL );
#else
                realpath(optarg, ki.os_file);
#endif
                break;

            case 'p' : /* устанавливаем дополнительную маску для поиска файлов */
                ki.pattern = optarg;
                break;

            case 'r' : /* устанавливаем флаг рекурсивного обхода каталогов */
                ki.tree = ak_true;
                break;


            case 254 : /* --reverse-order установить обратный порядок вывода байт */
                ki.reverse_order = ak_true;
                break;

            case 250 : /* --tag вывод в стиле BSD */
                ki.tag = ak_true;
                break;

            case 253: /* --seed */
                ki.seed = optarg;
                break;

            case 160: /* --no-derive */
                ki.key_derive = ak_false;
                break;

            case 161: /* --dont-show-stat */
                ki.dont_show_stat = ak_true;
                break;

            case 162: /* --ignore-errors */
                ki.ignore_errors = ak_true;
                break;

            case 240: /* --type */
                ki.processing_type = aktool_file_or_process(optarg);
                break;

            case 252: /* --inpass */
                memset(ki.inpass, 0, sizeof(ki.inpass));
                strncpy(ki.inpass, optarg, sizeof(ki.inpass) - 1);
                if ((ki.leninpass = strlen(ki.inpass)) == 0) {
                    aktool_error(_("the password cannot be zero length"));
                    return EXIT_FAILURE;
                }
                break;

            case 251: /* --inpass-hex */
                ki.leninpass = 0;
                memset(ki.inpass, 0, sizeof(ki.inpass));
                if (ak_hexstr_to_ptr(optarg, ki.inpass,
                                     sizeof(ki.inpass), ak_false) == ak_error_ok) {
                    ki.leninpass = ak_min((strlen(optarg) % 2) + (strlen(optarg) >> 1),
                                          sizeof(ki.inpass));
                }
                if (ki.leninpass == 0) {
                    aktool_error(_("the password cannot be zero length, "
                                   "maybe input error, see --inpass-hex %s%s%s"),
                                 ak_error_get_start_string(), optarg, ak_error_get_end_string());
                    return EXIT_FAILURE;
                }
                break;

            case 203: /* --key, --ca-key */
#ifdef _WIN32
                GetFullPathName( optarg, FILENAME_MAX, ki.key_file, NULL );
#else
                realpath(optarg, ki.key_file);
#endif
                break;

            default:  /* обрабатываем ошибочные параметры */
                if (next_option != -1) work = do_nothing;
                break;
        }

    } while (next_option != -1);
    if (work == do_nothing) return aktool_icode_help();

    /* начинаем работу с криптографическими примитивами */
    if (!aktool_create_libakrypt()) return EXIT_FAILURE;

    /* теперь вызов соответствующей функции */
    switch (work) {
        case do_hash:
            exit_status = aktool_icode_work(argc, argv);
            break;

        case do_check:
            exit_status = aktool_icode_check();
            break;

        default:
            exit_status = EXIT_FAILURE;
    }

    if (ki.outfp != NULL) fclose(ki.outfp);
    aktool_destroy_libakrypt();

    return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
/*                    Реализация общего алгоритма обработки входных файлов                         */
/* ----------------------------------------------------------------------------------------------- */
typedef int ( ak_function_icode_file )(ak_pointer, ak_identity_info, ak_pointer, const size_t);

typedef struct {
    ak_pointer handle;
    ak_oid oid;
    size_t tagsize;
    ak_function_icode_file *icode;
    int errcount;
    int total;
    int lines;
} handle_ptr_t;

/* ----------------------------------------------------------------------------------------------- */
static int aktool_icode_function(const char *filename, ak_pointer ptr) {
    handle_ptr_t *st = ptr;
    ak_uint8 buffer[256];
    ak_pointer kh = NULL;
    ak_identity_info identity = {filename, aktool_get_identity_type(filename, ki.processing_type)};
    int error = ak_error_ok;
    char flongname[FILENAME_MAX];

    /* проверяем размер доступной памяти для вычисления имитовставки */
    if (sizeof(buffer) < st->tagsize) {
        st->errcount++;
        return ak_error_wrong_length;
    }

    /* файл для вывода результатов не хешируем */
    if (ki.outfp != stdout) {
        memset(flongname, 0, sizeof(flongname));
#ifdef _WIN32
        GetFullPathName( filename, FILENAME_MAX, flongname, NULL );
#else
        realpath(filename, flongname);
#endif
        if (!strncmp(flongname, ki.op_file, FILENAME_MAX - 2)) return ak_error_ok;
        if (!strncmp(flongname, ki.audit_filename,
                     sizeof(ki.audit_filename) - 2))
            return ak_error_ok;
    }

    /* вырабатываем производный ключ (если пользователь не запретил) */
    if (!ki.key_derive || st->oid->engine == hash_function) {
        kh = st->handle;
    } else {
        if ((kh = ak_skey_new_derive_kdf256(st->oid, st->handle,
                                            (ak_uint8 *) filename, strlen(filename),
                                            ki.seed != NULL ? (ak_uint8 *) ki.seed : NULL,
                                            ki.seed != NULL ? strlen(ki.seed) : 0)) == NULL) {
            aktool_error(_("incorrect creation of derivative key for %s"), filename);
            st->errcount++;
            return ak_error_get_value();
        }
    }

    /* проверяем ресурс секретного ключа */
    if (st->oid->engine == block_cipher) {
        struct file fs;
        if ((error = ak_file_open_to_read(&fs, filename)) != ak_error_ok) {
            aktool_error(_("access error to %s [%s]"), filename, strerror(errno));
            st->errcount++;
            goto labex;
        }
        if (((ak_bckey) kh)->key.resource.value.counter < (ssize_t) (1 + fs.size / st->tagsize)) {
            st->errcount++;
            aktool_error(_("low key resource for %s (%lld bytes)"), filename, fs.size);
            error = ak_error_low_key_resource;
        }
        ak_file_close(&fs);
        if (error != ak_error_ok) goto labex;
    }

    /* хешируем */
    if ((error = st->icode(kh, /* производный ключ */
                           identity, buffer, st->tagsize)) != ak_error_ok) {
        aktool_error(_("incorrect integrity code calculation for %s"), filename);
        st->errcount++;
        return error;
    }

    /* теперь вывод результата */
    if (ki.tag) { /* вывод bsd */
        fprintf(ki.outfp, "%s (%s) = %s\n", st->oid->name[0], filename,
                ak_ptr_to_hexstr(buffer, st->tagsize, ki.reverse_order));
    } else { /* вывод линуксовый */
        fprintf(ki.outfp, "%s %s\n",
                ak_ptr_to_hexstr(buffer, st->tagsize, ki.reverse_order), filename);
    }

    labex:
    if (kh != st->handle) ak_oid_delete_object(st->oid, kh);
    return error;
}

/* ----------------------------------------------------------------------------------------------- */
static int aktool_create_handle(handle_ptr_t *st) {
    if (strlen(ki.key_file) != 0) {
        ak_libakrypt_set_password_read_function(aktool_load_user_password);
        if ((st->handle = ak_skey_load_from_file(ki.key_file)) == NULL) {
            if (!ki.quiet) aktool_error(_("wrong reading a secret key from %s file"), ki.key_file);
            return EXIT_FAILURE;
        }
        st->oid = ((ak_skey) st->handle)->oid;
        switch (st->oid->engine) {
            case hmac_function:
                st->icode = (ak_function_icode_file *) ak_hmac_file;
                st->tagsize = ak_hmac_get_tag_size(st->handle);
                break;

            case block_cipher:
                if (ki.mode == NULL) {
                    aktool_error(_("you need specify the argument of --mode option"));
                    if (st->handle != NULL) ak_oid_delete_object(ki.method, st->handle);
                    return EXIT_FAILURE;
                }
                switch (ki.mode->mode) {
                    case mac: /* здесь перечисляются допустимые режимы выработки имитовставки */
                        st->icode = (ak_function_icode_file *) ak_bckey_cmac_file;
                        break;

                    default:
                        aktool_error(_("you must use authentication mode for block cipher"));
                        return EXIT_FAILURE;
                }
                st->oid = ki.mode;
                st->tagsize = ((ak_bckey) st->handle)->bsize;
                break;

            default:
                ki.method = ((ak_skey) st->handle)->oid;
                aktool_error(_(
                                     "%s is not valid identifier for integrity checking algorithm (wrong engine: %s)"),
                             ki.method->name[0], ak_libakrypt_get_engine_name(ki.method->engine));
                if (st->handle != NULL) ak_oid_delete_object(ki.method, st->handle);
                return EXIT_FAILURE;
        }
    } else { /* ключ не определен, следовательно, создаем контекст алгоритма хеширования */
        if (ki.method->engine != hash_function) {
            aktool_error(_("the --algorithm option argument should be the name of the hash function"));
            return EXIT_FAILURE;
        }
        if ((st->handle = ak_oid_new_object(ki.method)) == NULL) {
            if (!ki.quiet)
                aktool_error(_("wrong creation context for %s algorithm"),
                             ki.method->name[0]);
            return EXIT_FAILURE;
        }
        st->icode = (ak_function_icode_file *) ak_hash_file;
        st->tagsize = ak_hash_get_tag_size(st->handle);
        st->oid = ((ak_hash) st->handle)->oid;
    }
    st->errcount = 0;

    return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
int aktool_icode_work(int argc, tchar *argv[]) {
    handle_ptr_t st = {
            .errcount = 0,
            .handle = NULL,
            .icode = NULL,
            .lines = 0,
            .oid = NULL,
            .tagsize = 0,
            .total = 0
    };
    int errcount = 0;

    /* проверяем, что файлы для контроля заданы */
    ++optind; /* пропускаем команду - i или icode */
    if (optind >= argc) {
        aktool_error(_(
                             "the name of file or directory is not specified as the argument of the program"));
        return EXIT_FAILURE;
    }

    /* создаем контекст хеширования (имитозащиты) и проверяем входные параметры  */
    if (aktool_create_handle(&st) != EXIT_SUCCESS) return EXIT_FAILURE;

    /* только сейчас начинаем основной цикл хеширования файлов и каталогов, указанных пользователем */
    while (optind < argc) {
        char *value = argv[optind++];
        switch (ak_file_or_directory(value)) {
            case DT_DIR:
                st.errcount = 0;
                if (ak_file_find(value, ki.pattern,
                                 aktool_icode_function, &st, ki.tree) != ak_error_ok)
                    errcount += st.errcount;
                break;

            case DT_REG:
                if (aktool_icode_function(value, &st) != ak_error_ok) errcount++;
                break;

            case 2664:
                if (aktool_icode_function(value, &st) != ak_error_ok) errcount++;
                break;
            default:
                aktool_error(_("%s is unsupported argument"), value);
                errcount++;
                break;
        }
    }

    /* освобождаем выделенную ранее память */
    if (st.handle != NULL) {
        if (st.icode == (ak_function_icode_file *) ak_hash_file)
            ak_oid_delete_object(((ak_hash) st.handle)->oid, st.handle);
        else ak_oid_delete_object(((ak_skey) st.handle)->oid, st.handle);
    }
    if (errcount) {
        if (!ki.quiet)
            aktool_error(_("aktool found %d error(s), "
                           "rerun aktool with \"--audit-file stderr\" option or see syslog messages"), errcount);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*                    Реализация алгоритма проверки файла с контрольными суммами                   */
/* ----------------------------------------------------------------------------------------------- */
static int aktool_icode_check_function(const tchar *string, ak_pointer ptr) {
    size_t len;
    ak_pointer kh = NULL;
    handle_ptr_t *st = ptr;
    ak_uint8 buffer[256], out2[256];
    tchar *substr = NULL, *filename = NULL, *icode = NULL;
    int error = ak_error_ok, reterror = ak_error_undefined_value;
    ak_identity_info identity = {filename, aktool_get_identity_type(filename, ki.processing_type)};

    st->lines++;

    /* получаем первый токен */
    if ((icode = aktool_strtok_r((tchar *) string, "(", &substr)) == NULL)
        return ak_error_undefined_value;

    if (strlen(substr) == 0) { /* строка не содержит скобки => вариант строки в формате Linux */
        /* получаем первый токен - это должно быть значение контрольной суммы */
        if ((icode = aktool_strtok_r((tchar *) string, " ", &substr)) == NULL) return reterror;
        if ((error = ak_hexstr_to_ptr(icode,
                                      out2, sizeof(out2), ki.reverse_order)) != ak_error_ok) {
            st->errcount++;
            return ak_error_message_fmt(error, __func__, "incorrect icode string %s\n", icode);
        }
        /* теперь второй токен - это имя файла */
        if ((filename = substr) == NULL) { /* не кооректно -> aktool_strtok_r( substr, " ", &substr ) */
            st->errcount++;
            return ak_error_message(ak_error_undefined_file, __func__,
                                    "the name of file cannot be determined");
        }
    } else { /* обнаружилась скобка => вариант строки в формате BSD */

        /* теперь надо проверить, что пролученное значение действительно является
           допустимым криптографическим алгоритмом */

        /* сперва уничтожаем пробелы в конце слова и получаем имя */
        if (strlen(icode) > 1024) return reterror;
        if ((len = strlen(icode) - 1) == 0) return reterror;
        while ((icode[len] == ' ') && (len)) icode[len--] = 0;

        /* теперь второй токен - это имя файла */
        if ((filename = aktool_strtok_r(substr, ")", &substr)) == NULL) return reterror;

        /* теперь, контрольная сумма */
        while ((*substr == ' ') || (*substr == '=')) substr++;
        if ((error = ak_hexstr_to_ptr(substr, out2, sizeof(out2), ki.reverse_order)) != ak_error_ok) {
            st->errcount++;
            return ak_error_message_fmt(error, __func__, "incorrect icode string %s\n", icode);
        }
    }

    /* приступаем к проверке*/
    st->total++;

    /* вырабатываем производный ключ (если пользователь не запретил) */
    if (!ki.key_derive || st->oid->engine == hash_function) {
        kh = st->handle;
    } else {
        if ((kh = ak_skey_new_derive_kdf256(st->oid, st->handle,
                                            (ak_uint8 *) filename, strlen(filename),
                                            ki.seed != NULL ? (ak_uint8 *) ki.seed : NULL,
                                            ki.seed != NULL ? strlen(ki.seed) : 0)) == NULL) {
            aktool_error(_("incorrect creation of derivative key for %s"), filename);
            st->errcount++;
            return ak_error_get_value();
        }
    }

    /* проверяем контрольную сумму */
    if ((error = st->icode(kh, identity, buffer, sizeof(buffer))) != ak_error_ok) {
        if (!ki.quiet) printf(_("%s Wrong\n"), filename);
        ak_error_message_fmt(error, __func__,
                             "incorrect evaluation integrity code for \"%s\" file", filename);
        st->errcount++;
        goto labex;
    }

    if (ak_ptr_is_equal_with_log(buffer, out2, st->tagsize) == ak_true) {
        if (!ki.quiet) printf("%s Ok\n", filename);
        goto labex;
    } else {
        if (!ki.quiet)
            printf(_("%s %sWrong%s\n"), filename,
                   ak_error_get_start_string(), ak_error_get_end_string());
        st->errcount++;
        if (ki.ignore_errors) error = ak_error_ok;
        else error = ak_error_not_equal_data;
    }

    labex:
    if (kh != st->handle) ak_oid_delete_object(st->oid, kh);

    return error;
}

/* ----------------------------------------------------------------------------------------------- */
int aktool_icode_check(void) {
    handle_ptr_t st = {
            .errcount = 0,
            .handle = NULL,
            .icode = NULL,
            .lines = 0,
            .oid = NULL,
            .tagsize = 0,
            .total = 0
    };
    int exit_status = EXIT_FAILURE;

    /* создаем контекст хеширования (имитозащиты) и проверяем входные параметры  */
    if (aktool_create_handle(&st) != EXIT_SUCCESS) return EXIT_FAILURE;

    /* теперь разбираем файл со строками и ведем статичтику происходящего */
    if (ak_file_read_by_lines(ki.os_file, aktool_icode_check_function, &st) == ak_error_ok) {
        if (!ki.quiet) {
            if (!ki.dont_show_stat) {
                printf(_("\n%s [%d lines, %d files, where: correct %d, wrong %d]\n"),
                       ki.os_file, st.lines, st.total, (st.total - st.errcount), st.errcount);

            }
        }
        if (!st.errcount) exit_status = EXIT_SUCCESS;
    }

    /* освобождаем выделенную ранее память */
    if (st.handle != NULL) {
        if (st.icode == (ak_function_icode_file *) ak_hash_file)
            ak_oid_delete_object(((ak_hash) st.handle)->oid, st.handle);
        else ak_oid_delete_object(((ak_skey) st.handle)->oid, st.handle);
    }

    return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
int aktool_icode_help(void) {
    printf(
            _("aktool icode [options] [files or directories]  - calculate or checking integrity codes for given files\n\n"
              "available options:\n"
              " -a, --algorithm         set the name or identifier of integrity function (used only for integrity checking)\n"
              "                         default algorithm is \"streebog256\" defined by RFC 6986\n"
              " -c, --check             check previously generated authentication or integrity codes\n"
              "     --dont-show-stat    don't show a statistical results after checking\n"
              "     --ignore-errors     don't break a check if file is missing or corrupted\n"
              "     --inpass            set the password for the secret key to be read directly in command line\n"
              "     --inpass-hex        read the password for the secret key as hexademal string\n"
              "     --key               specify the name of file with the secret key\n"
              " -m, --mode              set the block cipher mode [enabled values: cmac-{cipher}]\n"
              "     --no-derive         do not use derived keys for file authentication\n"
              " -o, --output            set the output file for generated authentication or integrity codes\n"
              " -p, --pattern           set the pattern which is used to find files\n"
              " -r, --recursive         recursive search of files\n"
              "     --reverse-order     output of authentication or integrity code in reverse byte order\n"
              "     --seed              set the initial value of key derivation functions (used only for file authentication)\n"
              "     --tag               create a BSD-style checksum format\n"
            ));
    aktool_print_common_options();

    printf(_("for usage examples try \"man aktool\"\n"));
    return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
tchar *aktool_strtok_r(tchar *str, const tchar *delim, tchar **nextp) {
    tchar *ret = NULL;

    if (str == NULL) { str = *nextp; }

    str += strspn(str, delim);
    if (*str == '\0') { return NULL; }

    ret = str;
    str += strcspn(str, delim);

    if (*str) { *str++ = '\0'; }

    *nextp = str;
    return ret;
}

/* ----------------------------------------------------------------------------------------------- */
int aktool_file_or_process(char *type) {
    return strcmp(type, "process") == 0 ? 1 : 0;
}

/* ----------------------------------------------------------------------------------------------- */
int is_elf_file(const char *filename) {
    unsigned char buf[5];
    int is_elf = 0;
    FILE *fin = fopen(filename, "r");
    fread(&buf, 5, 1, fin);
    if (buf[0] == 0x7F && buf[1] == 0x45 && buf[2] == 0x4c && buf[3] == 0x46) {
        if (buf[4] == 0x02) {
            is_elf = 2;
        } else {
            is_elf = 1;
        }
    } else {
        is_elf = 0;
    }
    fclose(fin);
    return is_elf;
}

/* ----------------------------------------------------------------------------------------------- */
ak_identity_type aktool_get_identity_type(const char *filename, int type) {
    ak_identity_type identity_type;
#ifdef _WIN32
    identity_type = win_file;
#else
    if (type) {
        identity_type = linux_process;
    } else {
        identity_type = is_elf_file(filename);
    }
#endif
    return identity_type;
}

/* ----------------------------------------------------------------------------------------------- */

/*                                                                                 aktool_icode.c  */
/* ----------------------------------------------------------------------------------------------- */
