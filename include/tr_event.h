#ifndef TR_EVENT_H
#define TR_EVENT_H

#include <event2/event.h>

/* struct for hanging on to a socket listener event */
struct tr_socket_event {
  int sock_fd; /* the fd for the socket */
  struct event *ev; /* its event */
};

/* prototypes */
struct event_base *tr_event_loop_init(void);
int tr_event_loop_run(struct event_base *base);

#endif /* TR_EVENT_H */
