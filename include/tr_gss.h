#ifndef __TR_GSS_H__
#define __TR_GSS_H__

#include <talloc.h>
#include <trust_router/tr_name.h>

#define TR_MAX_GSS_NAMES 5

typedef struct tr_gss_names {
  TR_NAME *names[TR_MAX_GSS_NAMES];
} TR_GSS_NAMES;

typedef struct tr_gss_names_iter {
  TR_GSS_NAMES *gn;
  int ii; /* which entry did we last output? */
} TR_GSS_NAMES_ITER;

TR_GSS_NAMES *tr_gss_names_new(TALLOC_CTX *mem_ctx);
void tr_gss_names_free(TR_GSS_NAMES *gn);
int tr_gss_names_add(TR_GSS_NAMES *gn, TR_NAME *new);
int tr_gss_names_matches(TR_GSS_NAMES *gn, TR_NAME *name);

TR_GSS_NAMES_ITER *tr_gss_names_iter_new(TALLOC_CTX *mem_ctx);
TR_NAME *tr_gss_names_iter_first(TR_GSS_NAMES_ITER *iter, TR_GSS_NAMES *gn);
TR_NAME *tr_gss_names_iter_next(TR_GSS_NAMES_ITER *iter);
void tr_gss_names_iter_free(TR_GSS_NAMES_ITER *iter);

#endif /* __TR_GSS_H__ */
