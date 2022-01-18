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
