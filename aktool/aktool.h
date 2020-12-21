/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл aktool.h                                                                                  */
/*  - содержит объявления служебных функций консольного клиента                                    */
/* ----------------------------------------------------------------------------------------------- */
 #ifndef AKTOOL_H
 #define AKTOOL_H

/* ----------------------------------------------------------------------------------------------- */
 #include <getopt.h>
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_LOCALE_H
 #include <locale.h>
#endif
#ifdef AK_HAVE_LIBINTL_H
 #include <libintl.h>
 #define _( string ) gettext( string )
#else
 #define _( string ) ( string )
#endif
#ifdef AK_HAVE_TIME_H
 #include <time.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 #define aktool_password_max_length (256)

/* ----------------------------------------------------------------------------------------------- */
 extern int aktool_log_level;
 extern bool_t aktool_openssl_compability;
 extern char audit_filename[1024];

/* ----------------------------------------------------------------------------------------------- */
/* вывод очень короткой справки о программе */
 int aktool_litehelp( void );
/* вывод версии */
 int aktool_version( void );
/* вывод длинной справки о программе */
 int aktool_help( void );
/* вывод информации об ощих опциях */
 int aktool_print_common_options();
/* проверка корректности заданной пользователем команды */
 bool_t aktool_check_command( const char *, tchar * );
/* вывод сообщений в заданный пользователем файл, а также в стандартный демон вывода сообщений */
 int aktool_audit_function( const char * );
/* определение функции вывода сообщений о ходе выполнения программы */
 void aktool_set_audit( tchar * );
/* вывод в консоль строки с сообщением об ошибке */
 void aktool_error( const char *format, ... );
/* общий для всех подпрограмм запуск процедуры инициализации билиотеки */
 bool_t aktool_create_libakrypt( void );
/* общий для всех подпрограмм запуск процедуры остановки билиотеки */
 int aktool_destroy_libakrypt( void );

/* ----------------------------------------------------------------------------------------------- */
/* реализации пользовательских команд */
 int aktool_show( int argc, tchar *argv[] );
 int aktool_test( int argc, tchar *argv[] );
 int aktool_asn1( int argc, tchar *argv[] );
 int aktool_key( int argc, tchar *argv[] );
 int aktool_icode( int argc, tchar *argv[] );

 #endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       aktool.h  */
/* ----------------------------------------------------------------------------------------------- */
