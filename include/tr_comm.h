/*
 * Copyright (c) 2012, 2015, JANET(UK)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of JANET(UK) nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef TR_COMM_H
#define TR_COMM_H

#include <stdio.h>
#include <talloc.h>
#include <time.h>

#include <tr_idp.h>
#include <tr_rp.h>
#include <tr_apc.h>

typedef struct tr_comm_table TR_COMM_TABLE;

typedef enum tr_comm_type {
  TR_COMM_UNKNOWN,
  TR_COMM_APC,
  TR_COMM_COI
} TR_COMM_TYPE;

typedef struct tr_comm {
  struct tr_comm *next;
  TR_NAME *id;
  TR_COMM_TYPE type;
  TR_APC *apcs;
  TR_NAME *owner_realm; /* what realm owns this community? */
  TR_NAME *owner_contact; /* contact email */
  time_t expiration_interval; /*Minutes to key expiration; only valid for an APC*/
  unsigned int refcount; /* how many TR_COMM_MEMBs refer to this community? */
} TR_COMM;

/* community membership - link realms to their communities */
typedef struct tr_comm_memb {
  struct tr_comm_memb *next;
  struct tr_comm_memb *origin_next; /* for multiple copies from different origins */
  TR_IDP_REALM *idp; /* only set one of idp and rp, other null */
  TR_RP_REALM *rp; /* only set one of idp and rp, other null */
  TR_COMM *comm;
  TR_NAME *origin;
  json_t *provenance; /* array of names of systems traversed */
  unsigned int interval;
  struct timespec *expiry;
  unsigned int times_expired; /* how many times has this expired? */
  int triggered; /* do we need to send this with triggered updates? */
} TR_COMM_MEMB;

/* table of communities/memberships */
struct tr_comm_table {
  TR_COMM *comms; /* all communities */
  TR_IDP_REALM *idp_realms; /* all idp realms */
  TR_RP_REALM *rp_realms; /* all rp realms */
  TR_COMM_MEMB *memberships; /* head of the linked list of membership records */
}; 

typedef enum tr_realm_role {
  TR_ROLE_UNKNOWN=0,
  TR_ROLE_IDP,
  TR_ROLE_RP
} TR_REALM_ROLE;

typedef struct tr_realm {
  TR_REALM_ROLE role;
  TR_RP_REALM *rp;
  TR_IDP_REALM *idp;
} TR_REALM;

/* nb, not all iterator routines use all members */
typedef struct tr_comm_iter {
  TR_COMM *cur_comm;
  TR_COMM_MEMB *cur_memb;
  TR_COMM_MEMB *cur_orig_head; /* for iterating along orig_next list */
  TR_NAME *match; /* realm or comm to match */
  TR_REALM *realm; /* handle so caller does not have to manage memory, private */
} TR_COMM_ITER;


TR_COMM_TABLE *tr_comm_table_new(TALLOC_CTX *mem_ctx);
void tr_comm_table_free(TR_COMM_TABLE *ctab);

TR_COMM_TABLE *tr_comm_table_new(TALLOC_CTX *mem_ctx);
void tr_comm_table_free(TR_COMM_TABLE *ctab);
void tr_comm_table_sweep(TR_COMM_TABLE *ctab);
void tr_comm_table_add_comm(TR_COMM_TABLE *ctab, TR_COMM *new);
void tr_comm_table_remove_comm(TR_COMM_TABLE *ctab, TR_COMM *comm);
TR_RP_REALM *tr_comm_table_find_rp_realm(TR_COMM_TABLE *ctab, TR_NAME *realm_id);
void tr_comm_table_add_rp_realm(TR_COMM_TABLE *ctab, TR_RP_REALM *new);
void tr_comm_table_remove_rp_realm(TR_COMM_TABLE *ctab, TR_RP_REALM *realm);
TR_IDP_REALM *tr_comm_table_find_idp_realm(TR_COMM_TABLE *ctab, TR_NAME *realm_id);
void tr_comm_table_add_idp_realm(TR_COMM_TABLE *ctab, TR_IDP_REALM *new);
void tr_comm_table_remove_idp_realm(TR_COMM_TABLE *ctab, TR_IDP_REALM *realm);
void tr_comm_table_add_memb(TR_COMM_TABLE *ctab, TR_COMM_MEMB *new);
void tr_comm_table_remove_memb(TR_COMM_TABLE *ctab, TR_COMM_MEMB *memb);
TR_COMM_MEMB *tr_comm_table_find_memb_origin(TR_COMM_TABLE *ctab, TR_NAME *realm, TR_NAME *comm, TR_NAME *origin);
TR_COMM_MEMB *tr_comm_table_find_memb(TR_COMM_TABLE *ctab, TR_NAME *realm, TR_NAME *comm);
TR_COMM_MEMB *tr_comm_table_find_rp_memb_origin(TR_COMM_TABLE *ctab, TR_NAME *rp_realm, TR_NAME *comm, TR_NAME *origin);
TR_COMM_MEMB *tr_comm_table_find_rp_memb(TR_COMM_TABLE *ctab, TR_NAME *rp_realm, TR_NAME *comm);
TR_COMM_MEMB *tr_comm_table_find_idp_memb_origin(TR_COMM_TABLE *ctab, TR_NAME *idp_realm, TR_NAME *comm, TR_NAME *origin);
TR_COMM_MEMB *tr_comm_table_find_idp_memb(TR_COMM_TABLE *ctab, TR_NAME *idp_realm, TR_NAME *comm);
TR_COMM *tr_comm_table_find_comm(TR_COMM_TABLE *ctab, TR_NAME *comm_id);
size_t tr_comm_table_size(TR_COMM_TABLE *ctab);
char *tr_comm_table_to_str(TALLOC_CTX *mem_ctx, TR_COMM_TABLE *ctab);
void tr_comm_table_print(FILE *f, TR_COMM_TABLE *ctab);

TR_COMM_MEMB *tr_comm_memb_new(TALLOC_CTX *mem_ctx);
void tr_comm_memb_free(TR_COMM_MEMB *memb);
int tr_comm_memb_cmp(TR_COMM_MEMB *m1, TR_COMM_MEMB *m2);
TR_REALM_ROLE tr_comm_memb_get_role(TR_COMM_MEMB *memb);
void tr_comm_memb_set_rp_realm(TR_COMM_MEMB *memb, TR_RP_REALM *realm);
TR_RP_REALM *tr_comm_memb_get_rp_realm(TR_COMM_MEMB *memb);
void tr_comm_memb_set_idp_realm(TR_COMM_MEMB *memb, TR_IDP_REALM *realm);
TR_IDP_REALM *tr_comm_memb_get_idp_realm(TR_COMM_MEMB *memb);
TR_NAME *tr_comm_memb_get_realm_id(TR_COMM_MEMB *memb);
void tr_comm_memb_set_comm(TR_COMM_MEMB *memb, TR_COMM *comm);
TR_COMM *tr_comm_memb_get_comm(TR_COMM_MEMB *memb);
TR_NAME *tr_comm_memb_get_origin(TR_COMM_MEMB *memb);
TR_NAME *tr_comm_memb_dup_origin(TR_COMM_MEMB *memb);
json_t *tr_comm_memb_get_provenance(TR_COMM_MEMB *memb);
void tr_comm_memb_set_provenance(TR_COMM_MEMB *memb, json_t *prov);
void tr_comm_memb_add_to_provenance(TR_COMM_MEMB *memb, TR_NAME *hop);
size_t tr_comm_memb_provenance_len(TR_COMM_MEMB *memb);
void tr_comm_memb_set_interval(TR_COMM_MEMB *memb, unsigned int interval);
unsigned int tr_comm_memb_get_interval(TR_COMM_MEMB *memb);
void tr_comm_memb_set_expiry(TR_COMM_MEMB *memb, struct timespec *time);
struct timespec *tr_comm_memb_get_expiry(TR_COMM_MEMB *memb);
int tr_comm_memb_is_expired(TR_COMM_MEMB *memb, struct timespec *curtime);
void tr_comm_memb_set_triggered(TR_COMM_MEMB *memb, int trig);
int tr_comm_memb_is_triggered(TR_COMM_MEMB *memb);
void tr_comm_memb_reset_times_expired(TR_COMM_MEMB *memb);
void tr_comm_memb_expire(TR_COMM_MEMB *memb);
unsigned int tr_comm_memb_get_times_expired(TR_COMM_MEMB *memb);

TR_COMM *tr_comm_new(TALLOC_CTX *mem_ctx);
void tr_comm_free(TR_COMM *comm);
void tr_comm_set_id(TR_COMM *comm, TR_NAME *id);
TR_NAME *tr_comm_get_id(TR_COMM *comm);
TR_NAME *tr_comm_dup_id(TR_COMM *comm);
void tr_comm_set_apcs(TR_COMM *comm, TR_APC *apc);
TR_APC *tr_comm_get_apcs(TR_COMM *comm);
void tr_comm_set_type(TR_COMM *comm, TR_COMM_TYPE type);
TR_COMM_TYPE tr_comm_get_type(TR_COMM *comm);
void tr_comm_set_owner_realm(TR_COMM *comm, TR_NAME *realm);
TR_NAME *tr_comm_get_owner_realm(TR_COMM *comm);
TR_NAME *tr_comm_dup_owner_realm(TR_COMM *comm);
void tr_comm_set_owner_contact(TR_COMM *comm, TR_NAME *contact);
TR_NAME *tr_comm_get_owner_contact(TR_COMM *comm);
TR_NAME *tr_comm_dup_owner_contact(TR_COMM *comm);
void tr_comm_add_idp_realm(TR_COMM_TABLE *ctab, TR_COMM *comm, TR_IDP_REALM *realm, unsigned int interval, json_t *provenance, struct timespec *expiry);
void tr_comm_add_rp_realm(TR_COMM_TABLE *ctab, TR_COMM *comm, TR_RP_REALM *realm, unsigned int interval, json_t *provenance, struct timespec *expiry);
TR_RP_REALM *tr_comm_find_rp(TR_COMM_TABLE *ctab, TR_COMM *comm, TR_NAME *rp_realm);
TR_IDP_REALM *tr_comm_find_idp(TR_COMM_TABLE *ctab, TR_COMM *comm, TR_NAME *idp_realm);
const char *tr_comm_type_to_str(TR_COMM_TYPE type);
TR_COMM_TYPE tr_comm_type_from_str(const char *s);
void tr_comm_incref(TR_COMM *comm);
void tr_comm_decref(TR_COMM *comm);
unsigned int tr_comm_get_refcount(TR_COMM *comm);

/* for iterating over communities within a realm or realms within a community */
TR_COMM_ITER *tr_comm_iter_new(TALLOC_CTX *mem_ctx);
void tr_comm_iter_free(TR_COMM_ITER *iter);

/* iterate over all communities in a table */
TR_COMM *tr_comm_table_iter_first(TR_COMM_ITER *iter, TR_COMM_TABLE *ctab);
TR_COMM *tr_comm_table_iter_next(TR_COMM_ITER *);

/* these iterate over communities for a realm */
TR_COMM *tr_comm_iter_first(TR_COMM_ITER *iter, TR_COMM_TABLE *ctab, TR_NAME *realm);
TR_COMM *tr_comm_iter_next(TR_COMM_ITER *iter);
TR_COMM *tr_comm_iter_first_rp(TR_COMM_ITER *iter, TR_COMM_TABLE *ctab, TR_NAME *realm);
TR_COMM *tr_comm_iter_next_rp(TR_COMM_ITER *iter);
TR_COMM *tr_comm_iter_first_idp(TR_COMM_ITER *iter, TR_COMM_TABLE *ctab, TR_NAME *realm);
TR_COMM *tr_comm_iter_next_idp(TR_COMM_ITER *iter);

/* iterate over realms for a community */
TR_REALM *tr_realm_iter_first(TR_COMM_ITER *iter, TR_COMM_TABLE *ctab, TR_NAME *comm);
TR_REALM *tr_realm_iter_next(TR_COMM_ITER *iter);
TR_RP_REALM *tr_rp_realm_iter_first(TR_COMM_ITER *iter, TR_COMM_TABLE *ctab, TR_NAME *comm);
TR_RP_REALM *tr_rp_realm_iter_next(TR_COMM_ITER *iter);
TR_IDP_REALM *tr_idp_realm_iter_first(TR_COMM_ITER *iter, TR_COMM_TABLE *ctab, TR_NAME *comm);
TR_IDP_REALM *tr_idp_realm_iter_next(TR_COMM_ITER *iter);

/* iterate over members with different origins */
TR_COMM_MEMB *tr_comm_memb_iter_first(TR_COMM_ITER *iter, TR_COMM_MEMB *memb);
TR_COMM_MEMB *tr_comm_memb_iter_next(TR_COMM_ITER *iter);

/* iterate over all members */
TR_COMM_MEMB *tr_comm_memb_iter_all_first(TR_COMM_ITER *iter, TR_COMM_TABLE *ctab);
TR_COMM_MEMB *tr_comm_memb_iter_all_next(TR_COMM_ITER *iter);

/* general realm stuff, should probably move */
TR_NAME *tr_realm_get_id(TR_REALM *realm);
TR_NAME *tr_realm_dup_id(TR_REALM *realm);

const char *tr_realm_role_to_str(TR_REALM_ROLE role);
TR_REALM_ROLE tr_realm_role_from_str(const char *s);

/* tr_comm_encoders.c */
json_t *tr_comm_table_to_json(TR_COMM_TABLE *ctable);

#endif
