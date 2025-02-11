/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2021 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл libakrypt-base.h (определение платформозависимых функций)                                 */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __LIBAKRYPT_BASE_H__
#define    __LIBAKRYPT_BASE_H__

/* ----------------------------------------------------------------------------------------------- */
#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef DLL_EXPORT
 #define building_dll
#endif
#ifdef _MSC_VER
 #define building_dll
#endif
/* ----------------------------------------------------------------------------------------------- */
/* Обрабатываем вариант сборки библиотеки для работы под Windows (Win32)                           */
#ifdef building_dll
 #define dll_export __declspec (dllexport)
#else
/* ----------------------------------------------------------------------------------------------- */
/* Для остальных операционных систем символ теряет свой смысл ;)                                   */
 #define dll_export
#endif

/* ----------------------------------------------------------------------------------------------- */
/* Устанавливаем множество доступных заголовочных файлов.
   Данное множество зависит от используемой операционной системы, компилятора и
   формируется при вызове программы cmake                                                          */
/* ----------------------------------------------------------------------------------------------- */
#define AK_HAVE_STDIO_H
#ifdef AK_HAVE_STDIO_H
 #include <stdio.h>
#else
 #error Library cannot be compiled without stdio.h header (required to determine vsnprintf() function)
#endif

#define AK_HAVE_STRING_H
#ifdef AK_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header (required to determine strlen() & memset() functions)
#endif

#define AK_HAVE_STDARG_H
#ifdef AK_HAVE_STDARG_H
 #include <stdarg.h>
#else
 #error Library cannot be compiled without string.h header (required to determine ak_snprintf() function)
#endif

#define AK_HAVE_CTYPE_H
#ifdef AK_HAVE_CTYPE_H
 #include <ctype.h>
#else
 #error Library cannot be compiled without ctype.h header (required to determine isspace() function)
#endif

#define AK_HAVE_STDLIB_H
#ifdef AK_HAVE_STDLIB_H
 #include <stdlib.h>
#else
 #error Library cannot be compiled without stdlib.h header (required to determine malloc() function)
#endif

/* #undef AK_HAVE_SYSENDIAN_H */
#ifdef AK_HAVE_SYSENDIAN_H
 #include <sys/endian.h>
#endif

#define AK_HAVE_BYTESWAP_H
#ifdef AK_HAVE_BYTESWAP_H
 #include <byteswap.h>
#endif

#define AK_HAVE_STDALIGN_H
#ifdef AK_HAVE_STDALIGN_H
 #include <stdalign.h>
#endif

#define AK_HAVE_TIME_H
#ifdef AK_HAVE_TIME_H
 #include <time.h>
#endif

#define AK_HAVE_SYSMMAN_H
#ifdef AK_HAVE_SYSMMAN_H
 #include <sys/mman.h>
#endif

#define AK_HAVE_ERRNO_H
#define AK_HAVE_SYSTYPES_H
#define AK_HAVE_STRINGS_H
#define AK_HAVE_ENDIAN_H
#define AK_HAVE_SYSTIME_H
#define AK_HAVE_SYSLOG_H
#define AK_HAVE_UNISTD_H
#define AK_HAVE_FCNTL_H
#define AK_HAVE_LIMITS_H
#define AK_HAVE_SYSSTAT_H
#define AK_HAVE_SYSSOCKET_H
#define AK_HAVE_SYSUN_H
#define AK_HAVE_SYSSELECT_H
#define AK_HAVE_TERMIOS_H
#define AK_HAVE_DIRENT_H
#define AK_HAVE_FNMATCH_H
#define AK_HAVE_LOCALE_H
#define AK_HAVE_SIGNAL_H
#define AK_HAVE_GETOPT_H
/* #undef AK_HAVE_LIBINTL_H */

/* ----------------------------------------------------------------------------------------------- */
/* #undef AK_HAVE_WINDOWS_H */
#ifdef AK_HAVE_WINDOWS_H
 #include <windows.h>
 #include <io.h>
 #include <process.h>
 #include <wincrypt.h>
 #include <tchar.h>
 #ifdef _MSC_VER
  #include <strsafe.h>
 #endif
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef _MSC_VER
 #pragma warning (disable : 4996)
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef _MSC_VER
 typedef __int32 ak_int32;
 typedef unsigned __int32 ak_uint32;
 typedef __int64 ak_int64;
 typedef unsigned __int64 ak_uint64;
 typedef __int64 ssize_t;
#endif
#ifdef __MINGW32__
 typedef __int32 ak_int32;
 typedef unsigned __int32 ak_uint32;
 typedef __int64 ak_int64;
 typedef unsigned __int64 ak_uint64;
#endif
#ifdef MSYS
 typedef int32_t ak_int32;
 typedef u_int32_t ak_uint32;
 typedef int64_t ak_int64;
 typedef u_int64_t ak_uint64;
 int snprintf(char *str, size_t size, const char *format, ... );
#endif
#if defined(__unix__) || defined(__APPLE__)
 typedef signed int ak_int32;
 typedef unsigned int ak_uint32;
 typedef signed long long int ak_int64;
 typedef unsigned long long int ak_uint64;
#endif

/* ----------------------------------------------------------------------------------------------- */
 typedef signed char ak_int8;
 typedef unsigned char ak_uint8;
#ifndef _WIN32
 typedef char tchar;
#else
 typedef TCHAR tchar;
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Объединение для обработки 128-ми битных значений. */
 typedef union {
    ak_uint8 b[16];
    ak_uint32 w[4];
    ak_uint64 q[2];
 } ak_uint128;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Определение булева типа, принимающего значения либо истина, либо ложь. */
 typedef enum {
  /*! \brief Ложь */
   ak_false,
  /*! \brief Истина */
   ak_true
} bool_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Указатель на произвольный объект библиотеки. */
 typedef void *ak_pointer;
/*! \brief Указатель на произвольный объект библиотеки. */
 typedef const void *ak_const_pointer;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Пользовательская функция аудита. */
 typedef int ( ak_function_log )( const char * );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Результат, говорящий об отсутствии ошибки. */
 #define ak_error_ok                            (0)
/*! \brief Ошибка выделения оперативной памяти. */
 #define ak_error_out_of_memory                (-1)
/*! \brief Ошибка, возникающая при доступе или передаче в качестве аргумента функции null указателя. */
 #define ak_error_null_pointer                 (-2)
/*! \brief Ошибка, возникащая при передаче аргументов функции или выделении памяти нулевой длины. */
 #define ak_error_zero_length                  (-3)
/*! \brief Ошибка, возникающая при обработке данных ошибочной длины. */
 #define ak_error_wrong_length                 (-4)
/*! \brief Использование неопределенного значения. */
 #define ak_error_undefined_value              (-5)
/*! \brief Использование неопределенного указателя на функцию (вызов null указателя). */
 #define ak_error_undefined_function           (-6)
/*! \brief Ошибка переполнения контролируемой переменной */
 #define ak_error_overflow                     (-7)
/*! \brief Ошибка недополнения контролируемой переменной */
 #define ak_error_underflow                    (-8)
/*! \brief Ошибка использования неинициализированной переменной */
 #define ak_error_not_ready                    (-9)
/*! \brief Ошибка дублирования/копирования данных */
 #define ak_error_duplicate                   (-10)
 /*! \brief Ошибка при сравнении двух переменных или массивов данных. */
 #define ak_error_not_equal_data              (-11)
/*! \brief Ошибка доступа за пределы массива. */
 #define ak_error_wrong_index                 (-12)

/*! \brief Неопределеное имя файла. */
 #define ak_error_undefined_file              (-14)
/*! \brief Ошибка создания файла. */
 #define ak_error_create_file                 (-15)
/*! \brief Ошибка доступа к файлу (устройству). */
 #define ak_error_access_file                 (-16)
/*! \brief Ошибка открытия файла (устройства). */
 #define ak_error_open_file                   (-17)
/*! \brief Ошибка закрытия файла (устройства). */
 #define ak_error_close_file                  (-18)
/*! \brief Ошибка чтения из файла (устройства). */
 #define ak_error_read_data                   (-19)
/*! \brief Ошибка чтения из файла (устройства) из-за превышения времени ожидания. */
 #define ak_error_read_data_timeout           (-20)
/*! \brief Ошибка записи в файл (устройство). */
 #define ak_error_write_data                  (-21)
 /*! \brief Ошибка удаления файла (удаление отменено) */
 #define ak_error_cancel_delete_file          (-22)
/*! \brief Ошибка записи в файл - файл существует */
 #define ak_error_file_exists                 (-23)
/*! \brief Ошибка использования несуществующего каталога */
 #define ak_error_not_directory               (-24)
/*! \brief Ошибка отображения файла в память */
 #define ak_error_mmap_file                   (-25)
/*! \brief Ошибка удаления файла из памяти */
 #define ak_error_unmap_file                  (-26)

/*! \brief Ошибка выполнения библиотеки на неверной архитектуре. */
 #define ak_error_wrong_endian                (-31)
/*! \brief Ошибка чтения из терминала. */
 #define ak_error_terminal                    (-32)

/*! \brief Ошибка функция не реализована. */
 #define ak_error_function_not_implemented     (-64)

/* ----------------------------------------------------------------------------------------------- */
 #define ak_null_string                  ("(null)")

/*! \brief Минимальный уровень аудита */
 #define ak_log_none                            (0)
/*! \brief Стандартный уровень аудита */
 #define ak_log_standard                        (1)
/*! \brief Максимальный уровень аудита */
 #define ak_log_maximum                         (2)

/* ----------------------------------------------------------------------------------------------- */
#define ak_max(x,y) ((x) > (y) ? (x) : (y))
#define ak_min(x,y) ((x) < (y) ? (x) : (y))

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup log Функции аудита и обработки ошибок
  @{ */
/*! \brief Функция возвращает уровень аудита библиотеки. */
 dll_export int ak_log_get_level( void );
/*! \brief Функция устанавливает уровень аудита библиотеки. */
 dll_export  int ak_log_set_level( int );
/*! \brief Прямой вывод сообщения аудита. */
 dll_export int ak_log_set_message( const char * );
/*! \brief Установка функции аудита. */
 dll_export int ak_log_set_function( ak_function_log * );
#ifdef AK_HAVE_SYSLOG_H
 /*! \brief Функция вывода сообщения об ошибке с помощью демона операционной системы. */
 dll_export int ak_function_log_syslog( const char * );
#endif
/*! \brief Функция вывода сообщения об ошибке в стандартный канал вывода ошибок. */
 dll_export int ak_function_log_stderr( const char * );
/*! \brief Вывод сообщений о возникшей в процессе выполнения ошибке. */
 dll_export int ak_error_message( const int, const char *, const char * );
/*! \brief Вывод сообщений о возникшей в процессе выполнения ошибке. */
 dll_export int ak_error_message_fmt( const int , const char *, const char *, ... );
/*! \brief Функция устанавливает значение переменной, хранящей ошибку выполнения программы. */
 dll_export int ak_error_set_value( const int );
/*! \brief Функция возвращает код последней ошибки выполнения программы. */
 dll_export int ak_error_get_value( void );

/*! \brief Функция запрещает/разрешает вывод цветных сообщений об ошибках. */
 dll_export int ak_error_set_color_output( bool_t );
/*! \brief Функция возвращает последовательность символов, начинающую выделение сообщения об ошибке. */
 dll_export const char *ak_error_get_start_string( void );
/*! \brief Функция возвращает последовательность символов, завершающую выделение сообщения об ошибке. */
 dll_export const char *ak_error_get_end_string( void );
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup list Функции для работы с двусвязными списками
  @{ */
 typedef struct list_node *ak_list_node;
/*! \brief Узел двусвязного списка. */
 struct list_node {
  /*! \brief указатель на хранимые данные. */
   ak_pointer data;
  /*! \brief указатель на предыдущий узел списка. */
   ak_list_node prev;
  /*! \brief указатель на следующий узел списка. */
   ak_list_node next;
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание нового узла двусвязного списка, содержащего символьную строку. */
 dll_export ak_list_node ak_list_node_new_string( const char * );
/*! \brief Удаление узла двусвязного списка */
 dll_export ak_pointer ak_list_node_delete( ak_list_node );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Двусвязный список. */
 typedef struct list {
   /*! \brief указатель на текущий узел списка */
    ak_list_node current;
   /*! \brief количество содержащихся узлов в списке (одного уровня) */
    size_t count;
 } *ak_list;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание двусвязного списка. */
 dll_export int ak_list_create( ak_list );
/*! \brief Создание двусвязного списка. */
 dll_export ak_list ak_list_new( void );
/*! \brief Перемещение к следующему узлу двусвязного списка. */
 dll_export bool_t ak_list_next( ak_list );
/*! \brief Перемещение к предыдущему узлу двусвязного списка. */
 dll_export bool_t ak_list_prev( ak_list );
/*! \brief Перемещение к последнему узлу двусвязного списка. */
 dll_export bool_t ak_list_last( ak_list );
/*! \brief Перемещение к первому узлу двусвязного списка. */
 dll_export bool_t ak_list_first( ak_list );
/*! \brief Изъятие текущего узла из двусвязного списка. */
 dll_export ak_list_node ak_list_exclude( ak_list );
/*! \brief Уничтожение текущего узла из двусвязного списка. */
 dll_export bool_t ak_list_remove( ak_list );
/*! \brief Уничтожение двусвязного списка. */
 dll_export int ak_list_destroy( ak_list );
/*! \brief Уничтожение двусвязного списка. */
 dll_export ak_pointer ak_list_delete( ak_list );
/*! \brief Добавление нового узла к двусвязному списку. */
 dll_export int ak_list_add_node( ak_list , ak_list_node );
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup ini Функции чтения ini-файлов
  @{ */
/*! \brief Прототип функции-обработчика, используемого при чтении ini-файлов. */
 typedef int (*ak_function_ini_handler)( void * , const char * , const char * , const char * );
/*! \brief Функция чтения ini-файла с заданным именем. */
 dll_export int ak_ini_parse( const char* , ak_function_ini_handler , void * );
/*! \brief Функция чтения ранее открытого ini-файла. */
 dll_export int ak_ini_parse_file( FILE* , ak_function_ini_handler , void * );
/*! \brief Функция чтения строки, содержащей корректные данные в формате ini-файла. */
 dll_export int ak_ini_parse_string( const char * , ak_function_ini_handler , void * );
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup file Платформонезависимые функции для работы с файлами
  @{ */
/*! \brief Определение функции для выполнения действий с заданным файлом */
 typedef int ( ak_function_find )( const tchar * , ak_pointer );
/*! \brief Определение функции, передаваемой в качестве аргумента в функцию построчного чтения файлов. */
 typedef int ( ak_file_read_function ) ( const char * , ak_pointer );
/*! \brief Определение функции, передаваемой в качестве аргумента в функции вывода информации. */
 typedef int ( ak_function_file_output ) ( const char * );

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_DIRENT_H
 #include <dirent.h>
#endif
#ifdef _MSC_VER
 #define	S_ISDIR(mode)  (((mode) & S_IFMT) == S_IFDIR)
 #define	S_ISREG(mode)  (((mode) & S_IFMT) == S_IFREG)
#endif
#ifndef DT_DIR
 #define DT_DIR (4)
#endif
#ifndef DT_REG
 #define DT_REG (8)
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Возможные режимы доступа к файлам и отображения файлов в память */
  typedef enum{
    readonly,    //!< доступ предоставляется только для чтения
    writeonly,   //!< доступ предоставляется только для записи
    readwrite,   //!< доступ предоставляется для чтения и записи
  } filestate_t;

/*! \brief Структура данных для хранения дескриптора и параметров файла. */
 typedef struct file {
#ifdef AK_HAVE_WINDOWS_H
 /*! \brief Дескриптор файла для операционной системы Windows. */
  HANDLE hFile;
#else
 /*! \brief Дескриптор файла. */
  int fd;
#endif
 /*! \brief Размер файла. */
  ak_int64 size;
 /*! \brief Размер блока для оптимального чтения с жесткого диска. */
  ak_int64 blksize;
 /*! \brief Указатель на память (после вызова mmap) */
  ak_pointer addr;
 /*! \brief Реальный размер отображенной памяти (после вызова mmap) */
  ak_int64 mmaped_size;
 } *ak_file;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция открывает заданный файл на чтение. */
 dll_export int ak_file_open_to_read( ak_file , const char * );
/*! \brief Функция создает файл с правами на запись. */
 dll_export int ak_file_create_to_write( ak_file , const char * );
/*! \brief Функция закрывает файл с заданным дескриптором. */
 dll_export int ak_file_close( ak_file );
/*! \brief Функция считывает заданное количество байт из файла. */
 dll_export ssize_t ak_file_read( ak_file , ak_pointer , size_t );
/*! \brief Функция записывает заданное количество байт в файл. */
 dll_export ssize_t ak_file_write( ak_file , ak_const_pointer , size_t );
/*! \brief Функция записывает в файл строку символов. */
 dll_export ssize_t ak_file_printf( ak_file , const char * , ... );
/*! \brief Отображение заданного файла в память. */
 dll_export ak_pointer ak_file_mmap( ak_file , void * , size_t , int , int , size_t );
/*! \brief Закрытие файла, отбраженног в память. */
 dll_export int ak_file_unmap( ak_file );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Проверка, является ли заданное имя обычным файлом или каталогом. */
 dll_export int ak_file_or_directory( const tchar * );
/*! \brief Обход каталога с учетом заданной маски */
 dll_export int ak_file_find( const tchar *, const tchar *, ak_function_find *, ak_pointer , bool_t );
/*! \brief Функция построчного чтения заданного файла */
 dll_export int ak_file_read_by_lines( const tchar *, ak_file_read_function * , ak_pointer );
/** @} */

/* ----------------------------------------------------------------------------------------------- */
#ifndef __STDC_VERSION__
  #define inline
  int snprintf(char *str, size_t size, const char *format, ... );
#endif
#ifdef _MSC_VER
 #define __func__  __FUNCTION__
 #define strtoll _strtoi64
#endif

#ifndef _WIN32
 #ifndef O_BINARY
   #define O_BINARY  ( 0x0 )
 #endif
#else
 #include <stdlib.h>
 #ifndef _MSC_VER
   unsigned __int64 __cdecl _byteswap_uint64(unsigned __int64 _Int64);

   #define _byteswap_ulong( x )  ((((x)&0xFF)<<24) \
                                 |(((x)>>24)&0xFF) \
                                 |(((x)&0x0000FF00)<<8)    \
                                 |(((x)&0x00FF0000)>>8)    )
 #endif
 #define bswap_32 _byteswap_ulong
 #define bswap_64 _byteswap_uint64
#endif
#ifdef AK_HAVE_SYSENDIAN_H
 #define bswap_64 bswap64
 #define bswap_32 bswap32
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifndef __VERSION__
 #define __VERSION__ LIBAKRYPT_COMPILER_VERSION
#endif

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup func Вспомогательные функции
  @{ */
/*! \brief Конвертация строки шестнадцатеричных символов в массив данных. */
 dll_export int ak_hexstr_to_ptr( const char *, ak_pointer , const size_t , const bool_t );
/*! \brief Функция высчитывает максимальную длину в байтах последовательности шестнадцатеричных символов. */
 dll_export ssize_t ak_hexstr_size( const char * );
/*! \brief Создание строки символов, содержащей человекочитаемое шестнадцатеричное значение
   заданной области памяти. */
 dll_export const char *ak_ptr_to_hexstr( ak_const_pointer , const size_t , const bool_t );
/*! \brief Создание строки символов, содержащей человекочитаемое шестнадцатеричное значение
   заданной области памяти. */
 dll_export char *ak_ptr_to_hexstr_alloc( ak_const_pointer , const size_t , const bool_t );
/*! \brief Сравнение двух областей памяти. */
 dll_export bool_t ak_ptr_is_equal( ak_const_pointer, ak_const_pointer , const size_t );
/*! \brief Сравнение двух областей памяти. */
 dll_export bool_t ak_ptr_is_equal_with_log( ak_const_pointer , ak_const_pointer , const size_t );
/*! \brief Вычисление 4-х байтной контрольной суммы Флетчера. */
 dll_export int ak_ptr_fletcher32( ak_const_pointer , const size_t , ak_uint32 * );
/*! \brief Вычисление 4-х байтной контрольной суммы Флетчера. */
 dll_export int ak_ptr_fletcher32_xor( ak_const_pointer , const size_t , ak_uint32 * );
/*! \brief Функция чтения заданного файла в буффер. */
 dll_export ak_uint8 *ak_ptr_load_from_file( ak_pointer , size_t * , const char * );
/*! \brief Функция чтения заданного файла в кодировке base64 в буффер. */
 dll_export ak_uint8 *ak_ptr_load_from_base64_file( ak_pointer , size_t * , const char * );
/*! \brief Выделение выравненной памяти. */
 dll_export ak_pointer ak_aligned_malloc( size_t );
/*! \brief Освобождение выравненной памяти. */
 dll_export void ak_aligned_free( ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция кодирует три байта информации в формат base64.  */
 dll_export void ak_base64_encodeblock( ak_uint8 *, ak_uint8 *, int );
/*! \brief Обобщенная реализация функции snprintf для различных компиляторов. */
 dll_export int ak_snprintf( char *str, size_t size, const char *format, ... );
/*! \brief Форматированный вывод (аналогичный printf) через пользовательскую функцию. */
 dll_export int ak_printf( ak_function_log *function, const char *format, ... );
/*! \brief Чтение строки из консоли. */
 dll_export int ak_string_read( const char * , char * , size_t * );
/*! \brief Чтение пароля из консоли. */
 dll_export ssize_t ak_password_read( char * , const size_t );
/** @} */

#ifdef __cplusplus
} /* конец extern "C" */
#endif
#endif

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                libakrypt-base.h */
/* ----------------------------------------------------------------------------------------------- */

