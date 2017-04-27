#include <openssl/sha.h>
#include <openssl/md5.h>
#include "ruby.h"
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <mm_malloc.h>

struct search_condition {
  unsigned char (*hash)(const unsigned char *d, size_t n, unsigned char *md);
  size_t md_len;
  unsigned char * restrict mask;
  unsigned char *target;
  unsigned char *result;
  size_t chars_len;
  unsigned char *chars;
  size_t search_length;
  size_t length;
};

unsigned char * safe_malloc(size_t length) {
  unsigned char *data = _mm_malloc(length + 15, 16);
  if(data == 0) {
    rb_raise(rb_eNoMemError, "Failed to allocate memory");
  }
  return data;
}

void search(unsigned char *data, size_t pos, unsigned char * restrict md, struct search_condition *cond) {
  if(cond->result != NULL) return; // Found Already
  if(pos == cond->search_length) {
	  int64_t *mdc = __builtin_assume_aligned(md, 16);
	  int64_t *mask = __builtin_assume_aligned(cond->mask, 16);
    // ハッシュ関数
    (cond->hash)(data, cond->length, md);

    for(size_t i = 0; i < cond->md_len / 8; i++) {
      mdc[i] &= mask[i];
    }

    if(memcmp(md, cond->target, cond->md_len) == 0) {
      #pragma omp critical
      {
        if(cond->result == NULL) {
          cond->result = malloc(cond->length);
          if(cond->result == 0) {
            rb_raise(rb_eNoMemError, "Failed to allocate memory");
          }
          memcpy(cond->result, data, cond->length);
        }
      }
    }
  } else {
    for(size_t i = 0; i < cond->chars_len; i++) {
      data[pos] = cond->chars[i];
      search(data, pos + 1, md, cond);
    }
  }
}

void search_parallel(unsigned char *data, size_t pos, unsigned char * restrict md, struct search_condition *cond) {
#pragma omp parallel for
  for(size_t i = 0; i < cond->chars_len; i++) {
    unsigned char *data2 = safe_malloc(cond->length);
    unsigned char *md2 = safe_malloc(cond->md_len);
    memcpy(data2, data, cond->length);
    data2[pos] = cond->chars[i];
    search(data2, pos + 1, md2, cond);
    _mm_free(data2);
    _mm_free(md2);
  }
}


static VALUE search_general(VALUE self, VALUE prefix, VALUE suffix, VALUE length, VALUE target, VALUE mask, VALUE chars, VALUE paralell, struct search_condition *cond) {
  Check_Type(prefix, T_STRING);
  Check_Type(suffix, T_STRING);
  FIXNUM_P(length);
  Check_Type(target, T_STRING);
  Check_Type(mask, T_STRING);
  Check_Type(chars, T_STRING);
  if((size_t)RSTRING_LEN(mask) != cond->md_len)
    rb_raise(rb_eArgError, "Invalid Mask length");
  if((size_t)RSTRING_LEN(target) != cond->md_len)
    rb_raise(rb_eArgError, "Invalid Target length");
  cond->mask = safe_malloc(cond->md_len); 
  memcpy(cond->mask, (unsigned char*)RSTRING_PTR(mask), cond->md_len);
  cond->target = (unsigned char*)RSTRING_PTR(target);
  cond->result = NULL;
  cond->chars = (unsigned char*)RSTRING_PTR(chars);
  cond->chars_len = RSTRING_LEN(chars);
  cond->search_length = FIX2INT(length) + RSTRING_LEN(prefix);
  cond->length = cond->search_length + RSTRING_LEN(suffix);
#ifdef _OPENMP
  if(RTEST(paralell) && length > 0) { // openmp
    unsigned char *data = safe_malloc(cond->length);
    unsigned char *md = safe_malloc(cond->md_len);
    memcpy(data, RSTRING_PTR(prefix), RSTRING_LEN(prefix));
    memcpy(data + cond->search_length, RSTRING_PTR(suffix), RSTRING_LEN(suffix));
    search_parallel(data, RSTRING_LEN(prefix), md, cond);
    _mm_free(data);
    _mm_free(md);
  } else {
#endif
    unsigned char *data = safe_malloc(cond->length);
    unsigned char *md = safe_malloc(cond->md_len);
    memcpy(data, RSTRING_PTR(prefix), RSTRING_LEN(prefix));
    memcpy(data + cond->search_length, RSTRING_PTR(suffix), RSTRING_LEN(suffix));
    search(data, RSTRING_LEN(prefix), md, cond);
    _mm_free(data);
    _mm_free(md);
#ifdef _OPENMP
  }
#endif
  _mm_free(cond->mask);
  if(cond->result) {
    return rb_str_new((char*)cond->result, cond->length);
  } else {
    return Qnil;
  }
}

static VALUE search_md5(VALUE self, VALUE prefix, VALUE suffix, VALUE length, VALUE target, VALUE mask, VALUE chars, VALUE paralell) {
  struct search_condition cond;
  cond.hash = MD5;
  cond.md_len = 128 / 8;
  return search_general(self, prefix, suffix, length, target, mask, chars, paralell, &cond);
}

static VALUE search_sha1(VALUE self, VALUE prefix, VALUE suffix, VALUE length, VALUE target, VALUE mask, VALUE chars, VALUE paralell) {
  struct search_condition cond;
  cond.hash = SHA1;
  cond.md_len = 160 / 8;
  return search_general(self, prefix, suffix, length, target, mask, chars, paralell, &cond);
}

static VALUE search_sha224(VALUE self, VALUE prefix, VALUE suffix, VALUE length, VALUE target, VALUE mask, VALUE chars, VALUE paralell) {
  struct search_condition cond;
  cond.hash = SHA224;
  cond.md_len = 224 / 8;
  return search_general(self, prefix, suffix, length, target, mask, chars, paralell, &cond);
}

static VALUE search_sha256(VALUE self, VALUE prefix, VALUE suffix, VALUE length, VALUE target, VALUE mask, VALUE chars, VALUE paralell) {
  struct search_condition cond;
  cond.hash = SHA256;
  cond.md_len = 256 / 8;
  return search_general(self, prefix, suffix, length, target, mask, chars, paralell, &cond);
}

static VALUE search_sha384(VALUE self, VALUE prefix, VALUE suffix, VALUE length, VALUE target, VALUE mask, VALUE chars, VALUE paralell) {
  struct search_condition cond;
  cond.hash = SHA384;
  cond.md_len = 384 / 8;
  return search_general(self, prefix, suffix, length, target, mask, chars, paralell, &cond);
}

static VALUE search_sha512(VALUE self, VALUE prefix, VALUE suffix, VALUE length, VALUE target, VALUE mask, VALUE chars, VALUE paralell) {
  struct search_condition cond;
  cond.hash = SHA512;
  cond.md_len = 512 / 8;
  return search_general(self, prefix, suffix, length, target, mask, chars, paralell, &cond);
}
void Init_ext()
{
  VALUE module = rb_define_module("EasyPow");
  rb_define_module_function(module, "search_md5_ext", search_md5, 7);
  rb_define_module_function(module, "search_sha1_ext", search_sha1, 7);
  rb_define_module_function(module, "search_sha224_ext", search_sha224, 7);
  rb_define_module_function(module, "search_sha256_ext", search_sha256, 7);
  rb_define_module_function(module, "search_sha384_ext", search_sha384, 7);
  rb_define_module_function(module, "search_sha512_ext", search_sha512, 7);
}
