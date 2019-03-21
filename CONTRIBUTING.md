# Formatting style

The OpenSC formatting rules are described in `.clang-format` in the root
directory. It is based on [LLVM](https://llvm.org/docs/CodingStandards.html)
style with couple of modifications:

 * Tabs
   * Tabs are used instead of spaces
   * Tab is 8 spaces wide
 * The maximum line width is 110 characters
 * Opening braces follow the condition/expression except for the functions

Examples:

```
void
function_name(int arg)
{
	int var = 0;
	int rc = 0;

	if (arg) {
		var = do_something();
	}
	if (rc = call_some_function(arg) ||
			rc = call_some_other_long_funct(arg) ||
			rc = call_one_more_func(arg)) {
		/* Note the two Tabs on the line above ! */
		return rc;
	}
	return var;
}
```

To check your changes if they follow the formatting style (before submitting
a PR), you can use `clang-format` tool or `git-clang-format`, which can check
only the parts of the code you changed in your branch

```
$ git-clang-format --diff --commit upstream/master
```

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
