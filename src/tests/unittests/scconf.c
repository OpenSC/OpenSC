/*
 * scconf.c: Unit tests for the scconf configuration parser
 *
 * Copyright (C) 2026 MENG Guanlin <guanlinmeng@connect.hku.hk>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "scconf/scconf.h"
#include "torture.h"
#include <cmocka.h>
#include <stdint.h>

/*
 * A comment written between a key and the '{' or '=' that follows it used to
 * consume the pending key without resetting the parser state, so the block or
 * value added next was created with item->key == NULL. The lookup and write
 * functions then passed that NULL pointer to strcasecmp() or strlen().
 *
 * See https://github.com/OpenSC/OpenSC/issues/3930
 */
#define CONFIG_COMMENT_THEN_BLOCK "a #\n{"
#define CONFIG_COMMENT_THEN_VALUE "a #\n= b;"

static scconf_context *
parse_config(const char *config)
{
	scconf_context *ctx = scconf_new(NULL);

	assert_non_null(ctx);
	/* A malformed input is not reported as a parse error, the tree is
	 * handed to the caller instead, so the lookups below must cope. */
	assert_int_equal(scconf_parse_string(ctx, config), 1);
	return ctx;
}

/* Every BLOCK and VALUE item carries a key, only comments have none. */
static void
assert_item_keys(const scconf_block *block)
{
	const scconf_item *item;

	for (item = block->items; item; item = item->next) {
		if (item->type != SCCONF_ITEM_TYPE_COMMENT)
			assert_non_null(item->key);
		if (item->type == SCCONF_ITEM_TYPE_BLOCK && item->value.block)
			assert_item_keys(item->value.block);
	}
}

static void
torture_comment_keeps_pending_key(void **state)
{
	scconf_context *ctx = parse_config(CONFIG_COMMENT_THEN_BLOCK);
	const scconf_item *comment = ctx->root->items;
	const scconf_item *block;

	(void)state;

	assert_non_null(comment);
	assert_int_equal(comment->type, SCCONF_ITEM_TYPE_COMMENT);
	assert_null(comment->key);

	block = comment->next;
	assert_non_null(block);
	assert_int_equal(block->type, SCCONF_ITEM_TYPE_BLOCK);
	assert_string_equal(block->key, "a");

	scconf_free(ctx);
}

static void
torture_comment_then_block_find_block(void **state)
{
	scconf_context *ctx = parse_config(CONFIG_COMMENT_THEN_BLOCK);

	(void)state;

	assert_item_keys(ctx->root);
	/* used to dereference the NULL key of the block, scconf.c:79 */
	assert_null(scconf_find_block(ctx, NULL, "bar"));

	scconf_free(ctx);
}

static void
torture_comment_then_block_find_blocks(void **state)
{
	scconf_context *ctx = parse_config(CONFIG_COMMENT_THEN_BLOCK);
	scconf_block **blocks = scconf_find_blocks(ctx, NULL, "bar", NULL);

	(void)state;

	assert_non_null(blocks);
	assert_null(blocks[0]);
	free(blocks);

	scconf_free(ctx);
}

static void
torture_comment_then_value_find_list(void **state)
{
	scconf_context *ctx = parse_config(CONFIG_COMMENT_THEN_VALUE);

	(void)state;

	assert_item_keys(ctx->root);
	/* used to dereference the NULL key of the value, scconf.c:139 */
	assert_null(scconf_find_list(ctx->root, "bar"));

	scconf_free(ctx);
}

static void
torture_comment_then_block_write(void **state)
{
	const char *path = "scconf-test.conf";
	scconf_context *ctx;

	(void)state;

	ctx = parse_config(CONFIG_COMMENT_THEN_BLOCK);
	/* used to call strlen() on the NULL key of the block, write.c:145 */
	assert_int_equal(scconf_write(ctx, path), 0);
	scconf_free(ctx);

	assert_int_equal(remove(path), 0);
}

static void
torture_valid_config(void **state)
{
	scconf_context *ctx = parse_config("app default {\n\tdebug = 1;\n}\n");
	const scconf_block *app = scconf_find_block(ctx, NULL, "app");
	const scconf_list *value;

	(void)state;

	assert_non_null(app);
	value = scconf_find_list(app, "debug");
	assert_non_null(value);
	assert_string_equal(value->data, "1");

	scconf_free(ctx);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
			cmocka_unit_test(torture_comment_keeps_pending_key),
			cmocka_unit_test(torture_comment_then_block_find_block),
			cmocka_unit_test(torture_comment_then_block_find_blocks),
			cmocka_unit_test(torture_comment_then_value_find_list),
			cmocka_unit_test(torture_comment_then_block_write),
			cmocka_unit_test(torture_valid_config),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
