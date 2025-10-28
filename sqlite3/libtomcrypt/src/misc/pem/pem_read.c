/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file pem_read.c
  Read and interpret a PEM file, Steffen Jaeckel
*/

#ifdef LTC_PEM

extern const struct str pem_proc_type_encrypted;
#ifdef LTC_SSH
extern const struct str pem_ssh_comment;
#endif
extern const struct str pem_dek_info_start;
extern const struct blockcipher_info pem_dek_infos[];
extern const unsigned long pem_dek_infos_num;

#ifndef LTC_NO_FILE
int pem_get_char_from_file(struct get_char *g)
{
   return getc(g->data.f);
}
#endif /* LTC_NO_FILE */

int pem_get_char_from_buf(struct get_char *g)
{
   int ret;
   if (g->data.buf.work == g->data.buf.end) {
      return -1;
   }
   ret = *g->data.buf.work;
   g->data.buf.work++;
   return ret;
}

static void s_unget_line(char *buf, unsigned long buflen, struct get_char *g)
{
   if (buflen > sizeof(g->unget_buf_))
      return;
   g->unget_buf.p = g->unget_buf_;
   COPY_STR(g->unget_buf, buf, buflen);
}

static void s_tts(char *buf, unsigned long *buflen)
{
   while(1) {
      unsigned long blen = *buflen;
      if (blen < 2)
         return;
      blen--;
      switch (buf[blen]) {
         case ' ':
         case '\t':
            buf[blen] = '\0';
            *buflen = blen;
            break;
         default:
            return;
      }
   }
}

static char* s_get_line_i(char *buf, unsigned long *buflen, struct get_char *g, int search_for_start)
{
   unsigned long blen = 0, wr = 0;
   int c_;
   if (g->unget_buf.p) {
      if (*buflen < g->unget_buf.len) {
         return NULL;
      }
      XMEMCPY(buf, g->unget_buf.p, g->unget_buf.len);
      *buflen = g->unget_buf.len;
      RESET_STR(g->unget_buf);
      return buf;
   }
   if (g->prev_get == -1) {
      return NULL;
   }
   while(blen < *buflen || search_for_start) {
      wr = blen < *buflen ? blen : *buflen - 1;
      c_ = g->prev_get;
      g->prev_get = g->get(g);
      if (g->prev_get == '\n') {
         buf[wr] = '\0';
         if (c_ == '\r') {
            buf[--wr] = '\0';
         }
         s_tts(buf, &wr);
         *buflen = wr;
         return buf;
      }
      if (g->prev_get == -1 || g->prev_get == '\0') {
         buf[wr] = '\0';
         s_tts(buf, &wr);
         *buflen = wr;
         return buf;
      }
      buf[wr] = g->prev_get;
      blen++;
   }
   return NULL;
}

LTC_INLINE static char* s_get_first_line(char *buf, unsigned long *buflen, struct get_char *g)
{
   return s_get_line_i(buf, buflen, g, 1);
}

LTC_INLINE static char* s_get_line(char *buf, unsigned long *buflen, struct get_char *g)
{
   return s_get_line_i(buf, buflen, g, 0);
}

static LTC_INLINE int s_fits_buf(void *dest, unsigned long to_write, void *end)
{
   unsigned char *d = dest;
   unsigned char *e = end;
   unsigned char *w = d + to_write;
   if (w < d || w > e)
      return 0;
   return 1;
}

static int s_pem_decode_headers(struct pem_headers *hdr, struct get_char *g)
{
   char buf[LTC_PEM_DECODE_BUFSZ], *alg_start;
   unsigned long slen, tmplen, n;
   int has_more_headers = hdr->id->has_more_headers == no ? 0 : 3;

   /* Make sure the PEM has the appropriate extension headers if required.
    *
    * ```
    * Proc-Type: 4,ENCRYPTED[\r]\n
    * DEK-Info: <algorithm>,<IV>[\r]\n
    * [\r]\n
    * ```
    */
   while (has_more_headers) {
      slen = sizeof(buf);
      if (!s_get_line(buf, &slen, g) || (has_more_headers > 1 && slen == 0)) {
         return CRYPT_INVALID_PACKET;
      }
      switch (has_more_headers) {
         case 3:
            if (XMEMCMP(buf, pem_proc_type_encrypted.p, pem_proc_type_encrypted.len)) {
#ifdef LTC_SSH
               if (XMEMCMP(buf, pem_ssh_comment.p, pem_ssh_comment.len))
#endif
                  s_unget_line(buf, slen, g);
               if (hdr->id->has_more_headers == maybe)
                  return CRYPT_OK;
               else
                  return CRYPT_INVALID_PACKET;
            }
            hdr->encrypted = 1;
            break;
         case 2:
            hdr->info.algo = NULL;
            if (XMEMCMP(buf, pem_dek_info_start.p, pem_dek_info_start.len))
               return CRYPT_INVALID_PACKET;
            alg_start = &buf[pem_dek_info_start.len];
            for (n = 0; n < pem_dek_infos_num; ++n) {
               unsigned long namelen = XSTRLEN(pem_dek_infos[n].name);
               if (slen >= namelen + pem_dek_info_start.len && !XMEMCMP(alg_start, pem_dek_infos[n].name, namelen)) {
                  char *iv = alg_start + namelen;
                  hdr->info = pem_dek_infos[n];
                  tmplen = XSTRLEN(iv);
                  if (tmplen > sizeof(hdr->info.iv))
                     return CRYPT_INVALID_KEYSIZE;
                  XMEMCPY(hdr->info.iv, iv, tmplen);
                  break;
               }
            }
            if (hdr->info.algo == NULL) {
               return CRYPT_INVALID_CIPHER;
            }
            break;
         case 1:
            /* Make sure that there's an empty line in between */
            if (buf[0] != '\0')
               return CRYPT_INVALID_PACKET;
            break;
         default:
            return CRYPT_INVALID_CIPHER;
      }
      has_more_headers--;
   }
   return CRYPT_OK;
}

int pem_read(void *asn1_cert, unsigned long *asn1_len, struct pem_headers *hdr, struct get_char *g)
{
   char buf[LTC_PEM_DECODE_BUFSZ];
   char *wpem = asn1_cert;
   char *end = wpem + *asn1_len;
   const char pem_start[] = "----";
   unsigned long slen, linelen;
   int err, hdr_ok = 0;
   int would_overflow = 0;
   unsigned char empty_lines = 0;

   g->prev_get = 0;
   do {
      linelen = sizeof(buf);
      if (s_get_first_line(buf, &linelen, g) == NULL) {
         if (g->prev_get == -1)
            return CRYPT_NOP;
         else
            return CRYPT_INVALID_PACKET;
      }
      if (linelen < sizeof(pem_start) - 1)
         continue;
   } while(XMEMCMP(buf, pem_start, sizeof(pem_start) - 1) != 0);
   if (hdr->id->start.len != linelen || XMEMCMP(buf, hdr->id->start.p, hdr->id->start.len)) {
      s_unget_line(buf, linelen, g);
      return CRYPT_UNKNOWN_PEM;
   }

   hdr->encrypted = hdr->id->flags & pf_encrypted;
   if ((err = s_pem_decode_headers(hdr, g)) != CRYPT_OK)
      return err;

   /* Read the base64 encoded part of the PEM */
   slen = sizeof(buf);
   while (s_get_line(buf, &slen, g)) {
      if (slen == hdr->id->end.len && !XMEMCMP(buf, hdr->id->end.p, slen)) {
         hdr_ok = 1;
         break;
      }
      if (!slen) {
         if (empty_lines)
            break;
         empty_lines++;
      }
      if (!would_overflow && s_fits_buf(wpem, slen, end)) {
         XMEMCPY(wpem, buf, slen);
      } else {
         would_overflow = 1;
      }
      wpem += slen;
      slen = sizeof(buf);
   }
   if (!hdr_ok)
      return CRYPT_INVALID_PACKET;

   if (would_overflow || !s_fits_buf(wpem, 1, end)) {
      /* NUL termination */
      wpem++;
      /* prevent a wrap-around */
      if (wpem < (char*)asn1_cert)
         return CRYPT_OVERFLOW;
      *asn1_len = wpem - (char*)asn1_cert;
      return CRYPT_BUFFER_OVERFLOW;
   }

   *asn1_len = wpem - (char*)asn1_cert;
   *wpem++ = '\0';

   if ((err = base64_strict_decode(asn1_cert, *asn1_len, asn1_cert, asn1_len)) != CRYPT_OK) {
      return err;
   }
   return CRYPT_OK;
}

#endif /* LTC_PEM */
