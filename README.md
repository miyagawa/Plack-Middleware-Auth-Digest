# NAME

Plack::Middleware::Auth::Digest - Digest authentication

# SYNOPSIS

    enable "Auth::Digest", realm => "Secured", secret => "blahblahblah",
        authenticator => sub {
            my ($username, $env) = @_;
            return $password; # for $username
        };

    # Or return MD5 hash of "$username:$realm:$password"
    enable "Auth::Digest", realm => "Secured", secret => "blahblahblah",
        password_hashed => 1,
        authenticator => sub { return $password_hashed };

# DESCRIPTION

Plack::Middleware::Auth::Digest is a Plack middleware component that
enables Digest authentication. Your `authenticator` callback is called using
two parameters: a username as a string and the PSGI `$env` hash. Your callback
should return a password, either as a raw password or a hashed password.

# CONFIGURATIONS

- authenticator

    A callback that takes a username and PSGI `$env` hash and returns a password
    for the user, either in a plaintext password or a MD5 hash of
    "username:realm:password" (quotes not included) when
    `password_hashed` option is enabled.

- password\_hashed

    A boolean (0 or 1) to indicate whether `authenticator` callback
    returns passwords in a plaintext or hashed. Defaults to 0 (plaintext).

- realm

    A string to represent the realm. Defaults to _restricted area_.

- secret

    Server secret text string that is used to sign nonce. Required.

- nonce\_ttl

    Time-to-live seconds to prevent replay attacks. Defaults to 60.

# LIMITATIONS

This middleware expects that the application has a full access to the
headers sent by clients in PSGI environment. That is normally the case
with standalone Perl PSGI web servers such as [Starman](https://metacpan.org/pod/Starman) or
[HTTP::Server::Simple::PSGI](https://metacpan.org/pod/HTTP::Server::Simple::PSGI).

However, in a web server configuration where you can't achieve this
(i.e. using your application via Apache's mod\_cgi), this middleware
does not work since your application can't know the value of
`Authorization:` header.

If you use Apache as a web server and CGI to run your PSGI
application, you can either a) compile Apache with
`-DSECURITY_HOLE_PASS_AUTHORIZATION` option, or b) use mod\_rewrite to
pass the Authorization header to the application with the rewrite rule
like following.

    RewriteEngine on
    RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization},L]

# AUTHOR

Yuji Shimada <xaicron@cpan.org>

Tatsuhiko Miyagawa

# COPYRIGHT

Yuji Shimada, Tatsuhiko Miyagawa 2010-

# SEE ALSO

[Plack::Middleware::Auth::Basic](https://metacpan.org/pod/Plack::Middleware::Auth::Basic)

# LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.
