use inc::Module::Install;
name 'Plack-Middleware-Auth-Digest';
all_from 'lib/Plack/Middleware/Auth/Digest.pm';
readme_from "lib/Plack/Middleware/Auth/Digest.pm";

requires 'Plack';
requires 'Digest::MD5';
requires 'Digest::HMAC_SHA1';
requires 'HTTP::Headers';

tests 't/*.t t/*/*.t t/*/*/*.t t/*/*/*/*.t t/*/*/*/*/*.t';
author_tests 'xt';
auto_set_repository;
build_requires 'Test::More', 0.88;
auto_include;
WriteAll;

