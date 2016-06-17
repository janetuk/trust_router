#ifndef TRP_H
#define TRP_H

#include <talloc.h>

#define TRP_PORT 12310
#define TRP_METRIC_INFINITY 0xFFFF
#define TRP_METRIC_INVALID 0xFFFFFFFF
#define TRP_INTERVAL_INVALID 0

typedef enum trp_rc {
  TRP_SUCCESS=0,
  TRP_ERROR, /* generic error */
  TRP_NOPARSE, /* parse error */
  TRP_NOMEM, /* allocation error */
  TRP_BADTYPE, /* typing error */
  TRP_UNSUPPORTED, /* unsupported feature */
} TRP_RC;


typedef struct trp_update TRP_UPD;
typedef struct trp_req TRP_REQ;

#endif /* TRP_H */
