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

TCase *md_json_test_case(void)
{
    TCase *testcase = tcase_create("md_json");

    tcase_add_checked_fixture(testcase, md_json_setup, md_json_teardown);

    tcase_add_test(testcase, json_create_makes_object_with_refcount_one);
    tcase_add_test(testcase, json_destroy_releases_object);
    tcase_add_test(testcase, clearing_md_json_t_pool_releases_internal_object);

    return testcase;
}
