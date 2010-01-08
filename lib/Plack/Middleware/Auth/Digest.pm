package Plack::Middleware::Auth::Digest;

use strict;
use warnings;
use parent qw/Plack::Middleware/;
use Plack::Util::Accessor qw/realm authenticator password_hashed/;
use HTTP::Headers::Util;
use Digest::MD5;
use String::Random qw/random_string/;

our $VERSION = '0.01';

sub hash {
    Digest::MD5::md5_hex(join ":", @_);
}

sub prepare_app {
    my $self = shift;

    my $auth = $self->authenticator or die 'authenticator is not set';
    if (ref $auth ne 'CODE') {
        die 'authenticator should be a code reference or an object that responds to authenticate()';
    }
}

sub call {
    my ($self, $env) = @_;

    my $auth = $env->{HTTP_AUTHORIZATION} or return $self->unauthorized;

    if ($auth =~ /^Digest (.*)/) {
        my $auth = $self->parse_challenge($1) || {};
        $auth->{method} = $env->{REQUEST_METHOD};

        ## TODO check if nonce is stale
        ## TODO check if uri matches
        ## TODO check qop

        my $password = $self->authenticator->($auth->{username});
        if (   defined $password
            && $self->digest($password, $auth) eq $auth->{response}) {
            $env->{REMOTE_USER} = $auth->{username};
            return $self->app->($env);
        }
    }

    return $self->unauthorized;
}

sub parse_challenge {
    my($self, $header) = @_;

    $header =~ tr/,/;/; # from LWP::UserAgent
    my($challenge) = HTTP::Headers::Util::split_header_words($header);

    return { @$challenge };
}

sub digest {
    my($self, $password, $auth) = @_;

    my $hashed = $self->password_hashed
        ? $password : hash($auth->{username}, $auth->{realm}, $password);

    return hash($hashed, @{$auth}{qw(nonce nc cnonce qop)}, hash("$auth->{method}:$auth->{uri}"));
}

sub unauthorized {
    my $self = shift;
    my $body      = '401 Authorization required';
    my $realm     = $self->realm || "restricted area";
    my $nonce     = random_string 's' x 52;
    my $algorithm = 'MD5';
    my $qop       = 'auth';

    return [
        401,
        [
            'Content-Type'     => 'text/plain',
            'Content-Length'   => length $body,
            'WWW-Authenticate' => qq|Digest realm="$realm", nonce="$nonce", algorithm=$algorithm, qop="$qop"|,
        ],
        [ $body ],
    ];
}

1;
__END__

=head1 NAME

Plack::Middleware::Auth::Digest - Digest authentication

=head1 SYNOPSIS

  enable "Auth::Digest", realm => "Secured", authenticator => sub {
      my $username = shift;
      return $password; # for $username
  };

  # Or return MD5 hash of "$username:$realm:$password"
  enable "Auth::Digest", realm => "Secured", password_hashed => 1,
      authenticator => sub { return $password_hashed };

=head1 DESCRIPTION

Plack::Middleware::Auth::Digest is a Plack middleware component that
enables Digest authentication. Your C<authenticator> callback is given
an username as a string and should return a password, either as a raw
password or a hashed password.

=head1 AUTHOR

Yuji Shimada E<lt>xaicron@cpan.orgE<gt>

Tatsuhiko Miyagawa

=head1 SEE ALSO

L<Plack::Middleware::Auth::Basic>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
