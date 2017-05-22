/* Copyright 2017 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>

#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_file_io.h>
#include <apr_tables.h>

#include "md_util.h"

/**************************************************************************************************/
/* small things */

apr_status_t md_util_fopen(FILE **pf, const char *fn, const char *mode)
{
    *pf = fopen(fn, mode);
    if (*pf == NULL) {
        return errno;
    }

    return APR_SUCCESS;
}


apr_status_t md_util_fcreatex(apr_file_t **pf, const char *fn, apr_pool_t *p)
{
    return apr_file_open(pf, fn, (APR_FOPEN_WRITE|APR_FOPEN_CREATE|APR_FOPEN_EXCL),
                         MD_FPROT_F_UONLY, p);
}

const char *md_util_schemify(apr_pool_t *p, const char *s, const char *def_scheme)
{
    const char *cp = s;
    while (*cp) {
        if (*cp == ':') {
            /* could be an url scheme, leave unchanged */
            return s;
        }
        else if (!apr_isalnum(*cp)) {
            break;
        }
        ++cp;
    }
    return apr_psprintf(p, "%s:%s", def_scheme, s);
}

/* base64 url encoding ****************************************************************************/

static const int BASE64URL_UINT6[] = {
/*   0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f        */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  0 */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  1 */ 
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, /*  2 */
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, /*  3 */ 
    -1, 0,  1,  2,  3,  4,  5,  6,   7,  8,  9, 10, 11, 12, 13, 14, /*  4 */
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63, /*  5 */
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /*  6 */
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, /*  7 */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  8 */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  9 */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  a */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  b */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  c */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  d */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  e */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1  /*  f */
};
static const char BASE64URL_CHARS[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', /*  0 -  9 */
    'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', /* 10 - 19 */
    'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', /* 20 - 29 */
    'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', /* 30 - 39 */
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', /* 40 - 49 */
    'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', /* 50 - 59 */
    '8', '9', '-', '_', ' ', ' ', ' ', ' ', ' ', ' ', /* 60 - 69 */
};

apr_size_t md_util_base64url_decode(const char **decoded, const char *encoded, 
                                    apr_pool_t *pool)
{
    const unsigned char *e = (const unsigned char *)encoded;
    const unsigned char *p = e;
    unsigned char *d;
    int n;
    apr_size_t len, mlen, remain, i;
    
    while (*p && BASE64URL_UINT6[ *p ] != -1) {
        ++p;
    }
    len = p - e;
    mlen = (len/4)*4;
    *decoded = apr_pcalloc(pool, len+1);
    
    i = 0;
    d = (unsigned char*)*decoded;
    for (; i < mlen; i += 4) {
        n = ((BASE64URL_UINT6[ e[i+0] ] << 18) +
             (BASE64URL_UINT6[ e[i+1] ] << 12) +
             (BASE64URL_UINT6[ e[i+2] ] << 6) +
             (BASE64URL_UINT6[ e[i+3] ]));
        *d++ = n >> 16;
        *d++ = n >> 8 & 0xffu;
        *d++ = n & 0xffu;
    }
    remain = len - mlen;
    switch (remain) {
        case 2:
            n = ((BASE64URL_UINT6[ e[mlen+0] ] << 18) +
                 (BASE64URL_UINT6[ e[mlen+1] ] << 12));
            *d++ = n >> 16;
            break;
        case 3:
            n = ((BASE64URL_UINT6[ e[mlen+0] ] << 18) +
                 (BASE64URL_UINT6[ e[mlen+1] ] << 12) +
                 (BASE64URL_UINT6[ e[mlen+2] ] << 6));
            *d++ = n >> 16;
            *d++ = n >> 8 & 0xffu;
            break;
        default: /* do nothing */
            break;
    }
    return mlen/4*3 + remain;
}

const char *md_util_base64url_encode(const char *data, 
                                     apr_size_t len, apr_pool_t *pool)
{
    apr_size_t slen = ((len+2)/3)*4 + 1; /* 0 terminated */
    apr_size_t i;
    const unsigned char *udata = (const unsigned char*)data;
    char *enc, *p = apr_pcalloc(pool, slen);
    
    enc = p;
    for (i = 0; i < len-2; i+= 3) {
        *p++ = BASE64URL_CHARS[ (udata[i] >> 2) & 0x3fu ];
        *p++ = BASE64URL_CHARS[ ((udata[i] << 4) + (udata[i+1] >> 4)) & 0x3fu ];
        *p++ = BASE64URL_CHARS[ ((udata[i+1] << 2) + (udata[i+2] >> 6)) & 0x3fu ];
        *p++ = BASE64URL_CHARS[ udata[i+2] & 0x3fu ];
    }
    
    if (i < len) {
        *p++ = BASE64URL_CHARS[ (udata[i] >> 2) & 0x3fu ];
        if (i == (len - 1)) {
            *p++ = BASE64URL_CHARS[ (udata[i] << 4) & 0x3fu ];
        }
        else {
            *p++ = BASE64URL_CHARS[ ((udata[i] << 4) + (udata[i+1] >> 4)) & 0x3fu ];
            *p++ = BASE64URL_CHARS[ (udata[i+1] << 2) & 0x3fu ];
        }
    }
    *p++ = '\0';
    return enc;
}

/*******************************************************************************
 * link header handling 
 ******************************************************************************/

typedef struct {
    const char *s;
    apr_size_t slen;
    int i;
    int link_start;
    apr_size_t link_len;
    int pn_start;
    apr_size_t pn_len;
    int pv_start;
    apr_size_t pv_len;
} link_ctx;

static int attr_char(char c) 
{
    switch (c) {
        case '!':
        case '#':
        case '$':
        case '&':
        case '+':
        case '-':
        case '.':
        case '^':
        case '_':
        case '`':
        case '|':
        case '~':
            return 1;
        default:
            return apr_isalnum(c);
    }
}

static int ptoken_char(char c) 
{
    switch (c) {
        case '!':
        case '#':
        case '$':
        case '&':
        case '\'':
        case '(':
        case ')':
        case '*':
        case '+':
        case '-':
        case '.':
        case '/':
        case ':':
        case '<':
        case '=':
        case '>':
        case '?':
        case '@':
        case '[':
        case ']':
        case '^':
        case '_':
        case '`':
        case '{':
        case '|':
        case '}':
        case '~':
            return 1;
        default:
            return apr_isalnum(c);
    }
}

static int skip_ws(link_ctx *ctx)
{
    char c;
    while (ctx->i < ctx->slen 
           && (((c = ctx->s[ctx->i]) == ' ') || (c == '\t'))) {
        ++ctx->i;
    }
    return (ctx->i < ctx->slen);
}

static int skip_nonws(link_ctx *ctx)
{
    char c;
    while (ctx->i < ctx->slen 
           && (((c = ctx->s[ctx->i]) != ' ') && (c != '\t'))) {
        ++ctx->i;
    }
    return (ctx->i < ctx->slen);
}

static int find_chr(link_ctx *ctx, char c, int *pidx)
{
    int j;
    for (j = ctx->i; j < ctx->slen; ++j) {
        if (ctx->s[j] == c) {
            *pidx = j;
            return 1;
        }
    } 
    return 0;
}

static int read_chr(link_ctx *ctx, char c)
{
    if (ctx->i < ctx->slen && ctx->s[ctx->i] == c) {
        ++ctx->i;
        return 1;
    }
    return 0;
}

static int skip_qstring(link_ctx *ctx)
{
    if (skip_ws(ctx) && read_chr(ctx, '\"')) {
        int end;
        if (find_chr(ctx, '\"', &end)) {
            ctx->i = end + 1;
            return 1;
        }
    }
    return 0;
}

static int skip_ptoken(link_ctx *ctx)
{
    if (skip_ws(ctx)) {
        int i;
        for (i = ctx->i; i < ctx->slen && ptoken_char(ctx->s[i]); ++i) {
            /* nop */
        }
        if (i > ctx->i) {
            ctx->i = i;
            return 1;
        }
    }
    return 0;
}


static int read_link(link_ctx *ctx)
{
    ctx->link_start = ctx->link_len = 0;
    if (skip_ws(ctx) && read_chr(ctx, '<')) {
        int end;
        if (find_chr(ctx, '>', &end)) {
            ctx->link_start = ctx->i;
            ctx->link_len = end - ctx->link_start;
            ctx->i = end + 1;
            return 1;
        }
    }
    return 0;
}

static int skip_pname(link_ctx *ctx)
{
    if (skip_ws(ctx)) {
        int i;
        for (i = ctx->i; i < ctx->slen && attr_char(ctx->s[i]); ++i) {
            /* nop */
        }
        if (i > ctx->i) {
            ctx->i = i;
            return 1;
        }
    }
    return 0;
}

static int skip_pvalue(link_ctx *ctx)
{
    if (skip_ws(ctx) && read_chr(ctx, '=')) {
        ctx->pv_start = ctx->i;
        if (skip_qstring(ctx) || skip_ptoken(ctx)) {
            ctx->pv_len = ctx->i - ctx->pv_start;
            return 1;
        }
    }
    return 0;
}

static int skip_param(link_ctx *ctx)
{
    if (skip_ws(ctx) && read_chr(ctx, ';')) {
        ctx->pn_start = ctx->i;
        ctx->pn_len = 0;
        if (skip_pname(ctx)) {
            ctx->pn_len = ctx->i - ctx->pn_start;
            ctx->pv_len = 0;
            skip_pvalue(ctx); /* value is optional */
            return 1;
        }
    }
    return 0;
}

static int pv_contains(link_ctx *ctx, const char *s)
{
    int pvstart = ctx->pv_start;
    apr_size_t pvlen = ctx->pv_len;
    
    if (ctx->s[pvstart] == '\"' && pvlen > 1) {
        ++pvstart;
        pvlen -= 2;
    }
    if (pvlen > 0) {
        apr_size_t slen = strlen(s);
        link_ctx pvctx;
        int i;
        
        memset(&pvctx, 0, sizeof(pvctx));
        pvctx.s = ctx->s + pvstart;
        pvctx.slen = pvlen;

        for (i = 0; i < pvctx.slen; i = pvctx.i) {
            skip_nonws(&pvctx);
            if ((pvctx.i - i) == slen && !strncmp(s, pvctx.s + i, slen)) {
                return 1;
            }
            skip_ws(&pvctx);
        }
    }
    return 0;
}

/* RFC 5988 <https://tools.ietf.org/html/rfc5988#section-6.2.1>
  Link           = "Link" ":" #link-value
  link-value     = "<" URI-Reference ">" *( ";" link-param )
  link-param     = ( ( "rel" "=" relation-types )
                 | ( "anchor" "=" <"> URI-Reference <"> )
                 | ( "rev" "=" relation-types )
                 | ( "hreflang" "=" Language-Tag )
                 | ( "media" "=" ( MediaDesc | ( <"> MediaDesc <"> ) ) )
                 | ( "title" "=" quoted-string )
                 | ( "title*" "=" ext-value )
                 | ( "type" "=" ( media-type | quoted-mt ) )
                 | ( link-extension ) )
  link-extension = ( parmname [ "=" ( ptoken | quoted-string ) ] )
                 | ( ext-name-star "=" ext-value )
  ext-name-star  = parmname "*" ; reserved for RFC2231-profiled
                                ; extensions.  Whitespace NOT
                                ; allowed in between.
  ptoken         = 1*ptokenchar
  ptokenchar     = "!" | "#" | "$" | "%" | "&" | "'" | "("
                 | ")" | "*" | "+" | "-" | "." | "/" | DIGIT
                 | ":" | "<" | "=" | ">" | "?" | "@" | ALPHA
                 | "[" | "]" | "^" | "_" | "`" | "{" | "|"
                 | "}" | "~"
  media-type     = type-name "/" subtype-name
  quoted-mt      = <"> media-type <">
  relation-types = relation-type
                 | <"> relation-type *( 1*SP relation-type ) <">
  relation-type  = reg-rel-type | ext-rel-type
  reg-rel-type   = LOALPHA *( LOALPHA | DIGIT | "." | "-" )
  ext-rel-type   = URI
  
  and from <https://tools.ietf.org/html/rfc5987>
  parmname      = 1*attr-char
  attr-char     = ALPHA / DIGIT
                   / "!" / "#" / "$" / "&" / "+" / "-" / "."
                   / "^" / "_" / "`" / "|" / "~"
 */

typedef struct {
    apr_pool_t *pool;
    const char *relation;
    const char *url;
} find_ctx;

static int find_url(void *baton, const char *key, const char *value)
{
    find_ctx *outer = baton;
    
    if (!apr_strnatcasecmp("link", key)) {
        link_ctx ctx;
        
        memset(&ctx, 0, sizeof(ctx));
        ctx.s = value;
        ctx.slen = (int)strlen(value);
        
        while (read_link(&ctx)) {
            while (skip_param(&ctx)) {
                if (ctx.pn_len == 3 && !strncmp("rel", ctx.s + ctx.pn_start, 3)
                    && pv_contains(&ctx, outer->relation)) {
                    /* this is the link relation we are looking for */
                    outer->url = apr_pstrndup(outer->pool, ctx.s + ctx.link_start, ctx.link_len);
                    return 0;
                }
            }
        }
    }
    return 1;
}

const char *md_link_find_relation(const apr_table_t *headers, 
                                  apr_pool_t *pool, const char *relation)
{
    find_ctx ctx;
    
    memset(&ctx, 0, sizeof(ctx));
    ctx.pool = pool;
    ctx.relation = relation;
    
    apr_table_do(find_url, &ctx, headers, NULL);
    
    return ctx.url;
}

