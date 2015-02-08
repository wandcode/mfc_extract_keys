/*
 * mfc_extract_keys.c
 *
 * extract keys from raw mifare classic dump files and convert them to either
 * mfocGUI or Proxmark key format.
 *
 * Copyright (C) 2013-2015  Wilbert Duijvenvoorde
 *
 * Authors:
 * Wilbert Duijvenvoorde
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Changelog:
 * 0.1: Initial release
 * 0.2: Major code cleanup and added support for proxmark dumpkeys.bin
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define VERSION "0.2"

#define UID_SIZE        8
#define KEY_SIZE        6
#define KEYS_1K        16
#define KEYS_4K        40
#define FILE_SIZE_1K 1024
#define FILE_SIZE_4K 4096

/* https://github.com/Proxmark/proxmark3 */
uint64_t bytes_to_num(uint8_t *src, size_t len)
{
   uint64_t num = 0;
   while (len--)
   {
      num = (num << 8) | (*src);
      src++;
   }

   return num;
}

void print_version()
{
   printf("%s\n", VERSION);
}

void print_usage(char *argv)
{
   printf("Usage: %s [-hmpv] <input_file>\n", argv);
   printf("\n");
   printf("  h     print this help and exit\n");
   printf("  m     convert a raw dump to the mfocGUI key format\n");
   printf("  p     convert a raw dump to the proxmark key format\n");
   printf("  v     print the version and exit\n");
   printf("\n");
   printf("Example: %s -m mycard.mfd\n", argv);
}

void print_seperator()
{
   printf("+---+----------------+----------------+\n");
}

void print_header(uint8_t *uid, uint8_t type)
{
   print_seperator();
   printf("| %dK|            %08lx             |\n", type, bytes_to_num(uid, 4));
   print_seperator();
   printf("|sec|key A           |key B           |\n");
   print_seperator();
}

uint8_t write_keys(uint8_t *keys, char *filename, size_t size)
{
   FILE *file;
   if (!(file = fopen(filename, "wb"))) {
      fprintf(stderr, "Can not open file '%s' for writing\n", filename);
      return 1;
   }

   if (!fwrite(keys, sizeof(keys[0]), size, file)) {
      fprintf(stderr, "Can not write the file '%s'\n", filename);
      return 1;
   }

   fclose(file);
   printf("Wrote keys to: %s\n", filename);
   return 0;
}

int main(int argc, char *argv[])
{
   FILE *file;
   long filelength;

   int ch;
   uint8_t options = 0;
   char *input_file = NULL;
   while ((ch = getopt (argc, argv, "hmpv")) != -1) {
      switch (ch)
      {
         case 'm': /* mfocGUI */
            options |= 0x02;
            break;
         case 'p': /* Proxmark*/
            options |= 0x08;
            break;
         case 'v': /* Show version */
            print_version();
            return 1;
         case 'h': /* Show help */
            print_usage(argv[0]);
            return 1;
         default:
            return 1;
      }
   }

   input_file = argv[optind];

   if (!options || !input_file) {
      print_usage(argv[0]);
      return 1;
   }

   if ((file = fopen(input_file, "rb"))) {
      fseek(file, 0, SEEK_END);
      filelength = ftell(file);

      if (filelength == FILE_SIZE_1K)
         options |= 0x61; /* 0x01 (repres. 1K) + 0x60 (96 bytes) */
      else if (filelength == FILE_SIZE_4K)
         options |= 0xF4; /* 0x04 (repres. 4K) + 0xF0 (240 bytes) */

      if (options & 0x05) {
         uint8_t *uid, *a_keys, *b_keys;

         if (((uid = (uint8_t *)malloc(UID_SIZE)) == NULL)
               || ((a_keys = (uint8_t *)malloc(options & 0xF0)) == NULL)
               || ((b_keys = (uint8_t *)malloc(options & 0xF0)) == NULL)) {
            fprintf(stderr, "Can not allocate enough memory!\n");
            return 1;
         }

         uint8_t *aptr = a_keys;
         uint8_t *bptr = b_keys;

         /* Set the offset to the beginning of the file and read the UID */
         fseek(file, 0x00, SEEK_SET);
         fread(uid, 1, UID_SIZE, file);

         /* Print a header with the UID (layout based on proxmark tools) */
         print_header(uid, options & 0x05);

         /* Set the offset to the first key location (0x30) */
         fseek(file, 0x30, SEEK_SET);

         uint8_t i, offset = 0;
         for (i = 0; i < ((options & 0x05) == 0x01 ? KEYS_1K : KEYS_4K); i++) {
             /* Apply offset to the current location and read the A key */
             fseek(file, offset, SEEK_CUR);
             fread(aptr, 1, KEY_SIZE, file);

             /* Skip 4 bytes (access bytes) and read the B key */
             fseek(file, 0x04, SEEK_CUR);
             fread(bptr, 1, KEY_SIZE, file);

             /* Print the extracted keys while we are at it */
             printf("|%03d|  %012lx  |  %012lx  |\n", i,
                              bytes_to_num(aptr, KEY_SIZE),
                              bytes_to_num(bptr, KEY_SIZE));

             /* Update the offsets to the next key positions */
             aptr += KEY_SIZE;
             bptr += KEY_SIZE;

             /* Adjust offset according to the mifare classic layout */
             if (i < 31)
                offset = 0x30;
             else
                offset = 0xF0;
         }

         /* Print another separator and a return, finally close the file */
         print_seperator();
         printf("\n");
         fclose(file);

         char filename[15];

         if ((options & 0x0A) == 0x02) { /* mfocGUI output files */
            sprintf(filename, "a%08lx.dump", bytes_to_num(uid, 4));

            if (write_keys(a_keys, filename, options & 0xF0))
               return 1;

            sprintf(filename, "b%08lx.dump", bytes_to_num(uid, 4));

            if (write_keys(b_keys, filename, options & 0xF0))
               return 1;
         } else { /* Proxmark output file */
            uint8_t *output;
            sprintf(filename, "%08lx.bin", bytes_to_num(uid, 4));

            if ((output = (uint8_t *)malloc((options & 0xF0) * 2)) != NULL) {
                 memmove(output, a_keys, options & 0xF0);
                 memmove(output + (options & 0xF0), b_keys, options & 0xF0);
            } else {
               fprintf(stderr, "Can not allocate enough memory!\n");
               return 1;
            }

            if (write_keys(output, filename, (options & 0xF0) * 2))
               return 1;
         }
      } else {
         fclose(file);
         fprintf(stderr, "File '%s' is not the correct size!\n", input_file);
         return 1;
      }
   } else {
      fprintf(stderr, "Can not open file '%s'\n", input_file);
      return 1;
   }

   return 0;
}
