#ifndef CPP_COMPAT_H
#define CPP_COMPAT_H

#ifndef __packed
#define __packed __attribute__((__packed__))
#endif /* __packed */

#ifndef __aligned
#define __aligned(n)
#endif

#endif //CPP_COMPAT_H
