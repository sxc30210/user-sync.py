# Release Notes for User Sync Tool Version 3.0a1

These notes apply to v2.2.1 of 2017-10-06.

## New Features

## Bug Fixes

## Compatibility with Prior Versions

## Known Issues

Because the release on Windows is built with a pre-compiled version of pyldap, we have to specify a specific version to be used in each release.  This not always be the latest version.

On the Win64 platform, there are very long pathnames embedded in the released build artifact `user-sync.pex`, which will cause problems unless you are on Windows 10 and are either running Python 3.6 or have enabled long pathnames system-wide (as described in this [Microsoft Dev Center article](https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx)).  To work around this issue on older platforms, set the `PEX_ROOT` environment variable (as described [in the docs here](https://adobe-apiplatform.github.io/user-sync.py/en/user-manual/setup_and_installation.html)) to be a very short path (e.g., `set PEX_ROOT=C:\pex`).

On Win64, this release was built with and is only guaranteed to work with Python Win64 2.7.13. We have had reports that it will not work with Python Win64 2.7.14, recently released. Earlier Win64 versions of Python have been observed to work (in particular, 2.7.9 and 2.7.12).
