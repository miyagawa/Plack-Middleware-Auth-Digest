use inc::Module::Install;
name 'Plack-Middleware-Auth-Digest';
all_from 'lib/Plack/Middleware/Auth/Digest.pm';

# requires '';

tests 't/*.t t/*/*.t t/*/*/*.t t/*/*/*/*.t t/*/*/*/*/*.t';
author_tests 'xt';

build_requires 'Test::More';
use_test_base;
auto_include;
WriteAll;
