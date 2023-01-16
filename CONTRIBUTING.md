# Formatting style

The OpenSC formatting rules are described in `.clang-format` in the root
directory. It is based on [LLVM](https://llvm.org/docs/CodingStandards.html)
style with couple of modifications:

 * Tabs
   * Tabs are used instead of spaces
   * Tab is 4 spaces wide
 * Spaces are used for indentation continuation
 * The maximum line width is 110 characters
    * if you go over few characters, its ok
    * it does not make sense to wrap line at 60 characters though
 * Opening braces follow the condition/expression except for the function definition (see example below)
 * `case` keywords are not indented from the `switch` level (see example below)
 * Line continuation is indented with 2 tabs (see example below)
 * Includes are sorted alphabetically
 * There are no trailing whitespaces. There is no trailing newline on the end of the file
 * There is exactly one space around any operator. Example:
   `out->counter[ii] = (md_data->Nh >> 8 * (hh_size - 1 - ii)) & 0xFF;`
 * Explicit type cast should be attached to the variable without whitespace. Example:
   `r = pgp_gen_key(card, (sc_cardctl_openpgp_keygen_info_t *)ptr);`
 * There should be no spaces inside the braces for function arguments, conditions, cycles ... Example:
   `if (!body || rbuf[0] != 0x7C) {`
 * There should be spaces after keyword such as `if`, `while` and before opening brace. Example:
   `do { ... } while (0);`

Examples:

```
/* The arrays are indented with two tabs */
static const char list[] = {
		"the first item",           /* comments are aligned with spaces */
		"second item",              /* here too */
		"last with trailing comma", /* and the last comment */
};

static void
function_name(int arg)
{
	int var = 0;
	int rc = 0;

	if (arg) {
		var = do_something();
	}
	if (rc = call_some_function(arg) ||
			rc = call_some_other_long_funct(arg) ||
			rc = (int)call_one_more_func(arg)) {
		return rc;
	}

	rc = call_some_func_with_many_arguments("Some long string which will not fit on one line",
			var, var);
	if (rc == 0) {
		// do something
	} else if (rc <= 0) {
		// do other thing
	} else {
		// do something else
	}
	return var;

	switch (e) {
	case '1':
		// command
		break;
	// ...
	}
}
```

To check your changes if they follow the formatting style (before submitting
a PR), you can use `clang-format` tool or `git-clang-format`, which can check
only the parts of the code you changed in your branch

```
$ git-clang-format --diff --commit upstream/master
```

If you have an editor that supports the [EditorCofig](https://editorconfig.org/)
it should help you to keep this formatting. If your editor does not support this
natively, there is likely to be a plugin.

# Testing locally

To learn how to run the tests from Github actions locally in containers, see
[`containers`](containers/README.md).

# Spelling

One of the GitHub actions checks spelling using
[codespell](https://github.com/codespell-project/codespell).
If you need to ignore some words, such as variable names or
words in languages other than English, add them to file
`codespell_ignore_words.txt`.

Note that [codespell](https://github.com/codespell-project/codespell#usage)
expects words to be lower case:
> **Important note:** The list passed to -I is case-sensitive
> based on how it is listed in the codespell dictionaries.

After installing
[codespell](https://github.com/codespell-project/codespell#installation),
you can run it from the command line as:
```sh
codespell -I .github/codespell_ignore_words.txt
```

# Release process

The release process is described in [OpenSC wiki](https://github.com/OpenSC/OpenSC/wiki/OpenSC-Release-Howto)

TODO tarball signing: https://github.com/OpenSC/OpenSC/issues/1129
