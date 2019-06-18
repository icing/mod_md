/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>

#include "test_common.h"
#include "md_json.h"

/*
 * XXX To inspect pieces of the md_json_t struct, we need to include the jansson
 * definition of json_t and duplicate the md_json_t definition.
 */

/* jansson thinks everyone compiles with the platform's cc in its fullest capabilities
 * when undefining their INLINEs, we get static, unused functions, arg 
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wunreachable-code"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"

#include <jansson_config.h>
#undef   JSON_INLINE
#define JSON_INLINE 
#include <jansson.h>

/* duplicated from src/md_json.c */
struct md_json_t {
    apr_pool_t *p;
    json_t *j;
};

/*
 * Helpers
 */

/* A free function that does nothing. See md_json_setup(). */
static void noop_free(void *unused)
{
    (void) unused;
}

/*
 * Test Fixture -- runs once per test
 */

static apr_pool_t *g_pool;

static void md_json_setup(void)
{
    if (apr_pool_create(&g_pool, NULL) != APR_SUCCESS) {
        exit(1);
    }

    /*
     * Disable the free function in Jansson so that we can safely inspect
     * objects after their refcounts have fallen to zero. Otherwise we're
     * relying on undefined behavior.
     */
    json_set_alloc_funcs(malloc, noop_free);
}

static void md_json_teardown(void)
{
    apr_pool_destroy(g_pool);
}

/*
 * Tests
 */

START_TEST(json_create_makes_object_with_refcount_one)
{
    md_json_t *json = md_json_create(g_pool);

    ck_assert(json);
    ck_assert_int_eq(json->j->type, JSON_OBJECT);
    ck_assert_int_eq(json->j->refcount, 1);
}
END_TEST

START_TEST(json_destroy_releases_object)
{
    md_json_t *json = md_json_create(g_pool);
    json_t *internal = json->j;

    md_json_destroy(json);

    ck_assert_int_eq(internal->refcount, 0);
    ck_assert_ptr_eq(json->j, NULL);
}
END_TEST

START_TEST(clearing_md_json_t_pool_releases_internal_object)
{
    md_json_t *json = md_json_create(g_pool);
    json_t *internal = json->j;

    apr_pool_clear(g_pool);

    ck_assert_int_eq(internal->refcount, 0);
}
END_TEST

START_TEST(booleans)
{
    md_json_t *json = md_json_create(g_pool);
    
    ck_assert_int_eq( md_json_setb(1, json, NULL), 0 );
    ck_assert_int_eq( json->j->refcount,  -1 ); /* jansson constant */
    ck_assert_int_eq( md_json_getb(json, NULL), 1 );

    ck_assert_int_eq( md_json_setb( 0, json, NULL), 0 );
    ck_assert_int_eq( json->j->refcount,  -1 ); /* jansson constant */
    ck_assert_int_eq( md_json_getb(json, NULL), 0 );

    ck_assert_int_eq( md_json_setb(42, json, NULL), 0 );
    ck_assert_int_eq( json->j->refcount,  -1 ); /* jansson constant */
    ck_assert_int_eq( md_json_getb(json, NULL), 1 );

    /* Non-existent boolean defaults to false */
    ck_assert_int_eq( md_json_getb(json, "key", NULL), 0 );
}
END_TEST

START_TEST(longs)
{
    md_json_t *json = md_json_create(g_pool);
    
    ck_assert_int_eq( md_json_setl(1, json, NULL), 0 );
    ck_assert_int_eq( json->j->refcount,  1 );
    ck_assert_int_eq( md_json_getl(json, NULL), 1 );

    ck_assert_int_eq( md_json_setl(42, json, NULL), 0 );
    ck_assert_int_eq( json->j->refcount,  1 );
    ck_assert_int_eq( md_json_getl(json, NULL), 42 );

    /* Getting long as double casts to double */
    ck_assert_double_eq_tol( md_json_getn(json, NULL), 42.0, 0.001 );

    /* Non-existent long defaults to zero */
    ck_assert_int_eq( md_json_getl(json, "key", NULL), 0 );
}
END_TEST

START_TEST(doubles)
{
    md_json_t *json = md_json_create(g_pool);
    
    ck_assert_int_eq( md_json_setn(1, json, NULL), 0 );
    ck_assert_int_eq( json->j->refcount,  1 );
    ck_assert_double_eq_tol( md_json_getn(json, NULL), 1.0, 0.001 );

    ck_assert_int_eq( md_json_setn(3.14152, json, NULL), 0 );
    ck_assert_int_eq( json->j->refcount,  1 );
    ck_assert_double_eq_tol( md_json_getn(json, NULL), 3.14152, 0.001 );

    /* Getting double as long defaults to zero */
    ck_assert_double_eq_tol( md_json_getl(json, NULL), 0.0, 0.001);

    /* Non-existent double defaults to zero */
    ck_assert_double_eq_tol( md_json_getn(json, "key", NULL), 0.0, 0.001 );
}
END_TEST

START_TEST(strings)
{
    md_json_t *json = md_json_create(g_pool);
    
    ck_assert_int_eq( md_json_sets("test-value", json, NULL), 0 );
    ck_assert_int_eq( json->j->refcount,  1 );
    ck_assert_str_eq( md_json_gets(json, NULL), "test-value");

    ck_assert_int_eq( md_json_sets("test-value-1", json, NULL), 0 );
    ck_assert_int_eq( json->j->refcount,  1 );
    ck_assert_str_eq( md_json_gets(json, NULL), "test-value-1");

    /* Non-existent string defaults to NULL */
    ck_assert_ptr_eq( md_json_gets(json, "key", NULL), NULL );
}
END_TEST

START_TEST(string_arrays)
{
    md_json_t *ja, *json = md_json_create(g_pool);
    json_t *inta;
    apr_array_header_t *a, *b;
    
    a = apr_array_make(g_pool, 1, sizeof(char*));
    b = apr_array_make(g_pool, 1, sizeof(char*));
    
    ck_assert_int_eq( md_json_setsa(a, json, "array", NULL), 0);
    ja = md_json_getj(json, "array", NULL);
    inta = ja->j;
    
    ck_assert_int_eq(inta->refcount, 2);
    
    APR_ARRAY_PUSH(a, const char*) = "test-value-0";
    ck_assert_int_eq( md_json_setsa(a, json, "array", NULL), 0);

    ck_assert_int_eq(inta->refcount, 2);
    
    ck_assert_int_eq( md_json_getsa(b, json, "array", NULL), 0);
    ck_assert_int_eq(b->nelts, 1);
    ck_assert_str_eq(APR_ARRAY_IDX(b, 0, const char*), "test-value-0");
}
END_TEST

static apr_status_t str_to_json(void *value, md_json_t *json, apr_pool_t *p, void *baton)
{
    return md_json_sets((const char*)value, json, NULL);
}

START_TEST(json_arrays)
{
    md_json_t *ja, *json = md_json_create(g_pool);
    apr_array_header_t *a, *b;
    const char *s;
    json_t *internal;
    
    a = apr_array_make(g_pool, 1, sizeof(char*));
    b = apr_array_make(g_pool, 1, sizeof(char*));
    
    ck_assert_int_eq( md_json_seta(a, NULL, NULL, json, "array", NULL), 0 );
    ja = md_json_getj(json, "array", NULL);
    ck_assert_int_eq(ja->j->refcount, 2);
    
    APR_ARRAY_PUSH(a, const char*) = "test-value-0";
    ck_assert_int_eq( md_json_seta(a, str_to_json, NULL, json, "array", NULL), 0 );
    ja = md_json_getj(json, "array", NULL);
    ck_assert_int_eq(ja->j->refcount, 3);
    ja = md_json_getj(json, "array", NULL);
    ck_assert_int_eq(ja->j->refcount, 4);
    
    s = md_json_writep(json, g_pool, MD_JSON_FMT_COMPACT);
    ck_assert_str_eq(s, "{\"array\":[\"test-value-0\"]}");

    md_json_getsa(b, json, "array", NULL);
    ck_assert_int_eq(b->nelts, 1);
    s = APR_ARRAY_IDX(b, 0, const char*);
    ck_assert_str_eq(s, "test-value-0");

    ja = md_json_getj(json, "array", NULL);
    ck_assert_int_eq(ja->j->refcount, 5);

    internal = ja->j;
    apr_pool_clear(g_pool);
    ck_assert_int_eq(internal->refcount, 0);
}
END_TEST

START_TEST(objects)
{
    md_json_t *json = md_json_create(g_pool);
    md_json_t *jc, *jb = md_json_create(g_pool);
    const char *s;
    
    ck_assert_int_eq( md_json_setb(1, json, "boolean", NULL), 0 );
    ck_assert_int_eq( md_json_getb(json, "boolean", NULL), 1 );

    ck_assert_int_eq( md_json_setl(1, json, "long", NULL), 0 );
    ck_assert_int_eq( md_json_getl(json, "long", NULL), 1 );
    
    ck_assert_int_eq( md_json_setn(1, json, "double", NULL), 0 );
    ck_assert_double_eq_tol( md_json_getn(json, "double", NULL), 1.0, 0.001 );

    ck_assert_int_eq( md_json_sets("text", json, "string", NULL), 0 );
    ck_assert_str_eq( md_json_gets(json, "string", NULL), "text");
 
    md_json_sets("test2", jb, "string2", NULL);
    ck_assert_int_eq( md_json_setj(jb, json, "object", NULL), 0 );
    jc = md_json_getj(json, "object", NULL);
    ck_assert_ptr_nonnull( jc );

    s = md_json_writep(json, g_pool, MD_JSON_FMT_COMPACT);
    ck_assert_str_eq(s, "{\"boolean\":true,\"long\":1,\"double\":1.0,"
                     "\"string\":\"text\",\"object\":{\"string2\":\"test2\"}}");
    
    ck_assert_int_eq( md_json_clr(json, "object", NULL), 0 );
    s = md_json_writep(json, g_pool, MD_JSON_FMT_COMPACT);
    ck_assert_str_eq(s, "{\"boolean\":true,\"long\":1,\"double\":1.0,"
                     "\"string\":\"text\",\"object\":{}}");

    ck_assert_int_eq( md_json_del(json, "object", NULL), 0 );
    s = md_json_writep(json, g_pool, MD_JSON_FMT_COMPACT);
    ck_assert_str_eq(s, "{\"boolean\":true,\"long\":1,\"double\":1.0,"
                     "\"string\":\"text\"}");
}
END_TEST

START_TEST(copies)
{
    md_json_t *json = md_json_create(g_pool);
    md_json_t *jc, *jb = md_json_create(g_pool), *dest = md_json_create(g_pool);
    
    md_json_setb(1, json, "boolean", NULL);
    md_json_copy_to(dest, json, "boolean", NULL); 
    ck_assert_int_eq( md_json_getb(dest, "boolean", NULL), 1 );
    
    md_json_setl(1, json, "long", NULL);
    md_json_copy_to(dest, json, "long", NULL);
    ck_assert_int_eq( md_json_getl(dest, "long", NULL), 1 );
    
    md_json_setn(1, json, "double", NULL);
    md_json_copy_to(dest, json, "double", NULL); 
    ck_assert_double_eq_tol( md_json_getn(dest, "double", NULL), 1.0, 0.001 );

    md_json_sets("text", json, "string", NULL);
    md_json_copy_to(dest, json, "string", NULL); 
    ck_assert_str_eq( md_json_gets(dest, "string", NULL), "text");
 
    md_json_sets("test2", jb, "string2", NULL);
    ck_assert_int_eq( md_json_setj(jb, json, "object", NULL), 0 );
    md_json_copy_to(dest, json, "object", NULL);
    jc = md_json_getj(dest, "object", NULL);
    ck_assert_ptr_nonnull( jc );
}
END_TEST

START_TEST(json_writep_returns_NULL_for_corrupted_json_struct)
{
    md_json_t *json = md_json_create(g_pool);
    md_json_t *val1 = md_json_create(g_pool);

    /* { "val1": 20, "val2": 40 } */
    md_json_setl(20,   val1, NULL);
    md_json_setj(val1, json, "val1", NULL);
    md_json_setl(40,   json, "val2", NULL);

    /* Intentionally corrupt val1. */
    val1->j->type = (json_type) -2;

    ck_assert_ptr_eq( md_json_writep(json, g_pool, 0), NULL );
}
END_TEST

TCase *md_json_test_case(void)
{
    TCase *testcase = tcase_create("md_json");

    tcase_add_checked_fixture(testcase, md_json_setup, md_json_teardown);

    tcase_add_test(testcase, json_create_makes_object_with_refcount_one);
    tcase_add_test(testcase, json_destroy_releases_object);
    tcase_add_test(testcase, clearing_md_json_t_pool_releases_internal_object);
    
    tcase_add_test(testcase, booleans);
    tcase_add_test(testcase, longs);
    tcase_add_test(testcase, doubles);
    tcase_add_test(testcase, strings);
    tcase_add_test(testcase, string_arrays);
    tcase_add_test(testcase, json_arrays);
    tcase_add_test(testcase, objects);
    tcase_add_test(testcase, copies);

    tcase_add_test(testcase, json_writep_returns_NULL_for_corrupted_json_struct);

    return testcase;
}
