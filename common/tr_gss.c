#include <talloc.h>

#include <tr_gss.h>

static int tr_gss_names_destructor(void *obj)
{
  TR_GSS_NAMES *gss_names=talloc_get_type_abort(obj, TR_GSS_NAMES);
  int ii=0;

  for (ii=0; ii<TR_MAX_GSS_NAMES; ii++) {
    if (gss_names->names[ii]!=NULL)
      tr_free_name(gss_names->names[ii]);
  }
  return 0;
}
TR_GSS_NAMES *tr_gss_names_new(TALLOC_CTX *mem_ctx)
{
  TR_GSS_NAMES *gn=talloc(mem_ctx, TR_GSS_NAMES);
  int ii=0;

  if (gn!=NULL) {
    for (ii=0; ii<TR_MAX_GSS_NAMES; ii++)
      gn->names[ii]=NULL;
    talloc_set_destructor((void *)gn, tr_gss_names_destructor);
  }
  return gn;
}

void tr_gss_names_free(TR_GSS_NAMES *gn)
{
  talloc_free(gn);
}

/* returns 0 on success */
int tr_gss_names_add(TR_GSS_NAMES *gn, TR_NAME *new)
{
  int ii=0;

  for (ii=0; ii<TR_MAX_GSS_NAMES; ii++) {
    if (gn->names[ii]==NULL)
      break;
  }
  if (ii!=TR_MAX_GSS_NAMES) {
    gn->names[ii]=new;
    return 0;
  } else
    return -1;
}

int tr_gss_names_matches(TR_GSS_NAMES *gn, TR_NAME *name)
{
  int ii=0;

  for (ii=0; ii<TR_MAX_GSS_NAMES; ii++) {
    if ((gn->names[ii]!=NULL) &&
        (0==tr_name_cmp(gn->names[ii], name)))
      return 1;
  }
  return 0;
}

/* iterators */
TR_GSS_NAMES_ITER *tr_gss_names_iter_new(TALLOC_CTX *mem_ctx)
{
  TR_GSS_NAMES_ITER *iter=talloc(mem_ctx, TR_GSS_NAMES_ITER);
  if (iter!=NULL) {
    iter->gn=NULL;
    iter->ii=0;
  }
  return iter;
}

TR_NAME *tr_gss_names_iter_first(TR_GSS_NAMES_ITER *iter, TR_GSS_NAMES *gn)
{
  iter->gn=gn;
  iter->ii=-1;
  return tr_gss_names_iter_next(iter);
}

TR_NAME *tr_gss_names_iter_next(TR_GSS_NAMES_ITER *iter)
{
  for (iter->ii++;
       (iter->ii < TR_MAX_GSS_NAMES) && (iter->gn->names[iter->ii]==NULL);
       iter->ii++) { }

  if (iter->ii<TR_MAX_GSS_NAMES)
    return iter->gn->names[iter->ii];
  
  return NULL;
}

void tr_gss_names_iter_free(TR_GSS_NAMES_ITER *iter)
{
  talloc_free(iter);
}
