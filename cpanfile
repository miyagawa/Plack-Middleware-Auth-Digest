requires 'Digest::HMAC_SHA1';
requires 'Digest::MD5';
requires 'Plack';
requires 'perl', '5.008001';

on build => sub {
    requires 'ExtUtils::MakeMaker', '6.42';
    requires 'Test::More', '0.88';
};
