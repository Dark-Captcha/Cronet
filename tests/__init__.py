"""The test suite, a package so that its helpers can be imported by name.

`echoed` and `socks5_server` are shared by several modules; making this a
package is what lets them say `from . import echoed` rather than depending on
where pytest happened to put the test directory on `sys.path`.
"""
