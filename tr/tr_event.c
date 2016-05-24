#include <event2/event.h>

#include <tr.h>
#include <tid_internal.h>
#include <tr_debug.h>
#include <tr_event.h>

/* Allocate and set up the event base, return a pointer
 * to the new event_base or NULL on failure.
 * Does not currently enable thread-safe mode. */
struct event_base *tr_event_loop_init(void)
{
  struct event_base *base=NULL;

  base=event_base_new();
  return base;
}

/* run the loop, does not normally return */
int tr_event_loop_run(struct event_base *base)
{
  return event_base_dispatch(base);
}
