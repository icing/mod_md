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
 * Test Fixture -- runs once per test
 */

static apr_pool_t *g_pool;

static void md_json_setup(void)
{
    if (apr_pool_create(&g_pool, NULL) != APR_SUCCESS) {
        exit(1);
    }
}

static void md_json_teardown(void)
{
    apr_pool_destroy(g_pool);
}

/*
 * Tests
 */

START_TEST(first_test)
{
    md_json_t *j = md_json_create(g_pool);
    ck_assert(j);
}
END_TEST

TCase *md_json_test_case(void)
{
    TCase *testcase = tcase_create("md_json");

    tcase_add_checked_fixture(testcase, md_json_setup, md_json_teardown);

    tcase_add_test(testcase, first_test);

    return testcase;
}
