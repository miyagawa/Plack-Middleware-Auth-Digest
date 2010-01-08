package Plack::Middleware::Auth::Digest;
use 5.008001;
use strict;
use warnings;
use parent qw/Plack::Middleware/;
use Plack::Util::Accessor qw/realm authenticator password_hashed secret nonce_ttl/;

use HTTP::Headers::Util ();
use MIME::Base64 ();
use Digest::MD5 ();
use Digest::HMAC_SHA1 ();

our $VERSION = '0.01';

sub hash {
    Digest::MD5::md5_hex(join ":", @_);
}

sub prepare_app {
    my $self = shift;

    if ($self->authenticator && ref $self->authenticator ne 'CODE') {
        die 'authenticator should be a code reference';
    }

    unless ($self->secret) {
        die "Auth::Digest secret key is not set.";
    }
}

sub call {
    my ($self, $env) = @_;

    my $auth = $env->{HTTP_AUTHORIZATION} or return $self->unauthorized;

    if ($auth =~ /^Digest (.*)/) {
        my $auth = $self->parse_challenge($1) || {};
        $auth->{method} = $env->{REQUEST_METHOD};

        if ($auth->{uri} ne $env->{REQUEST_URI}) {
            return [ 400, ['Content-Type', 'text/plain'], [ "Bad Request" ] ];
        }

        my $password = $self->authenticator->($auth->{username});
        if (   defined $password
            && $self->valid_nonce($auth)
            && $self->digest($password, $auth) eq $auth->{response}) {

            if ($self->stale_nonce($auth)) {
                return $self->unauthorized(stale => "true");
            }

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
    my %params = @_;

    my $body      = '401 Authorization required';
    my $realm     = $self->realm || "restricted area";
    my $nonce     = $self->generate_nonce(time);
    my $algorithm = 'MD5';
    my $qop       = 'auth';

    my $challenge  = qq|Digest realm="$realm", nonce="$nonce", algorithm=$algorithm, qop=$qop|;
       $challenge .= qq(, stale=true) if $params{stale};

    return [
        401,
        [
            'Content-Type'     => 'text/plain',
            'Content-Length'   => length $body,
            'WWW-Authenticate' => $challenge,
        ],
        [ $body ],
    ];
}

sub valid_nonce {
    my($self, $auth) = @_;

    my($time, $digest) = split / /, MIME::Base64::decode_base64($auth->{nonce});
    $auth->{_nonce_time} = $time; # cache for stale check

    return $time && $digest && $digest eq $self->hmac($time);
}

sub stale_nonce {
    my($self, $auth) = @_;

    $auth->{_nonce_time} < time - ($self->nonce_ttl || 60);
}

sub generate_nonce {
    my($self, $time) = @_;

    my $nonce = MIME::Base64::encode_base64(join " ", $time, $self->hmac($time));
    chomp $nonce;

    return $nonce;
}

sub hmac {
    my($self, $time) = @_;
    Digest::HMAC_SHA1::hmac_sha1_hex($time, $self->secret);
}

1;
__END__

=head1 NAME

Plack::Middleware::Auth::Digest - Digest authentication

=head1 SYNOPSIS

  enable "Auth::Digest", realm => "Secured", secret => "blahblahblah",
      authenticator => sub {
          my $username = shift;
          return $password; # for $username
      };

  # Or return MD5 hash of "$username:$realm:$password"
  enable "Auth::Digest", realm => "Secured", secret => "blahblahblah",
      password_hashed => 1,
      authenticator => sub { return $password_hashed };

=head1 DESCRIPTION

Plack::Middleware::Auth::Digest is a Plack middleware component that
enables Digest authentication. Your C<authenticator> callback is given
an username as a string and should return a password, either as a raw
password or a hashed password.

=head1 CONFIGURATIONS

=over 4

=item authenticator

A callback that takes an username and returns a password for the user,
either in a plaintext password or a MD5 hash of
"username:realm:password" (quotes not included) when
C<password_hashed> option is enabled.

=item password_hashed

A boolean (0 or 1) to indicate whether C<authenticator> callback
returns passwords in a plaintext or hashed. Defaults to 0 (plaintext).

=item realm

A string to represent the realm. Defaults to I<restricted area>.

=item secret

Server secret text string that is used to sign nonce. Required.

=item nonce_ttl

Time-to-live seconds to prevent replay attacks. Defaults to 60.

=back

=head1 AUTHOR

Yuji Shimada E<lt>xaicron@cpan.orgE<gt>

Tatsuhiko Miyagawa

=head1 SEE ALSO

L<Plack::Middleware::Auth::Basic>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
