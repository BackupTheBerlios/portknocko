/*-
 * Copyright (c) 2001, 2002 Allan Saddi <allan@saddi.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

%module sha256c
%{
#include "sha256.h"

unsigned char *
MySHA256Final (SHA256Context *sc)
{
  SHA256Context scBackup;
  unsigned char *hash = PyMem_Malloc (SHA256_HASH_SIZE);
  if (hash) {
    memcpy (&scBackup, sc, sizeof (scBackup));
    SHA256Final (&scBackup, hash);
    memset (&scBackup, 0, sizeof (scBackup));
  }
  return hash;  
}

void
SHA256Copy (SHA256Context *src, SHA256Context *dst)
{
  memcpy (dst, src, sizeof (*dst));
}

void
SHA256Sanitize (SHA256Context *sc)
{
  memset (sc, 0, sizeof (*sc));
}
%}

%typemap(python,in) char *data {
  if (PyString_Check ($input)) {
    int len;
    PyString_AsStringAndSize ($input, &$1, &len);
  }
  else {
    PyErr_BadArgument ();
    return NULL;
  }
}

%typemap(python,out) unsigned char * {
  if ($1) {
    $result = PyString_FromStringAndSize ($1, SHA256_HASH_SIZE);
    PyMem_Free ($1);
  }
  else
    return PyErr_NoMemory ();
}

struct _SHA256Context {
  _SHA256Context();
  ~_SHA256Context();
};

void SHA256Init (struct _SHA256Context *sc);
void SHA256Update (struct _SHA256Context *sc, char *data, unsigned long len);
unsigned char *MySHA256Final (struct _SHA256Context *sc);
void SHA256Copy (struct _SHA256Context *src, struct _SHA256Context *dst);
void SHA256Sanitize (struct _SHA256Context *sc);
