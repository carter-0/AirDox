/* tiny_e164.h – public-domain, no dep */
#ifndef TINY_E164_H
#define TINY_E164_H

#include <ctype.h>
#include <string.h>

typedef struct {
    char e164[17];      /* '\0'-terminated, max 15 digits + ‘+’ */
    char cc[4];         /* country code slice (1-3 digits)     */
    char national[17];  /* remainder of number                 */
} phone_e164_t;

/* returns 0 on success, -1 on parse/length error */
static int phone_parse_e164(const char *in, phone_e164_t *out)
{
    char buf[17]; size_t len = 0;

    /* strip non-digits, remember leading ‘+’ */
    for (; *in; ++in) {
        if (*in == '+' && len == 0) { buf[len++] = '+'; }
        else if (isdigit((unsigned char)*in)) {
            if (len >= 16) return -1;       /* >15 digits */
            buf[len++] = *in;
        }
    }
    buf[len] = '\0';
    if (len < 4 || buf[0] != '+') return -1; /* need +CC… */

    /* split CC (1-3 digits after ‘+’) */
    size_t cc_len = (buf[2] && buf[3] && buf[4]) ? 3 :
                    (buf[2] && buf[3])           ? 2 : 1;
    strncpy(out->cc,     buf + 1, cc_len); out->cc[cc_len] = '\0';
    strcpy (out->national, buf + 1 + cc_len);
    strcpy (out->e164, buf);
    return 0;
}

#endif /* TINY_E164_H */
