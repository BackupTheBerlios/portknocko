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

%module sha384c
%{
#include "sha384.h"

unsigned char *
MySHA384Final (SHA384Context *sc)
{
  SHA384Context scBackup;
  unsigned char *hash = PyMem_Malloc (SHA384_HASH_SIZE);
  if (hash) {
    memcpy (&scBackup, sc, sizeof (scBackup));
    SHA384Final (&scBackup, hash);
    memset (&scBackup, 0, sizeof (scBackup));
  }
  return hash;  
}

void
SHA384Copy (SHA384Context *src, SHA384Context *dst)
{
  memcpy (dst, src, sizeof (*dst));
}

void
SHA384Sanitize (SHA384Context *sc)
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
    $result = PyString_FromStringAndSize ($1, SHA384_HASH_SIZE);
    PyMem_Free ($1);
  }
  else
    return PyErr_NoMemory ();
}

struct _SHA384Context {
  _SHA384Context();
  ~_SHA384Context();
};

void SHA384Init (struct _SHA384Context *sc);
void SHA384Update (struct _SHA384Context *sc, char *data, unsigned long len);
unsigned char *MySHA384Final (struct _SHA384Context *sc);
void SHA384Copy (struct _SHA384Context *src, struct _SHA384Context *dst);
void SHA384Sanitize (struct _SHA384Context *sc);
