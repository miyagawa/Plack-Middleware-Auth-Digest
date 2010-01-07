use inc::Module::Install;
name 'Plack-Middleware-Auth-Digest';
all_from 'lib/Plack/Middleware/Auth/Digest.pm';

requires 'Plack';
requires 'Text::CSV';
requires 'Digest::MD5';
requires 'String::Random';

tests 't/*.t t/*/*.t t/*/*/*.t t/*/*/*/*.t t/*/*/*/*/*.t';
author_tests 'xt';

build_requires 'Test::More', 0.88;
use_test_base;
auto_include;
WriteAll;
