package Plack::Middleware::Auth::Digest;

use strict;
use warnings;
use parent qw/Plack::Middleware/;
use Plack::Util::Accessor qw/realm authenticator/;
use Scalar::Util ();
use Text::CSV ();
use Digest::MD5 qw/md5_hex/;
use String::Random qw/random_string/;
use Try::Tiny qw/try/;

our $VERSION = '0.01';

my $csv = Text::CSV->new({allow_loose_quotes => 1});

sub prepare_app {
    my $self = shift;
    
    my $auth = $self->authenticator or die 'authenticator is not set';
    if (Scalar::Util::blessed($auth) && $auth->can('authenticate')) {
        $self->authenticator(sub { my @args = @_; try { $auth->authenticate(@args) } });
    }
    elsif (ref $auth ne 'CODE') {
        die 'authenticator should be a code reference or an object that responds to authenticate()';
    }
}

sub call {
    my ($self, $env) = @_;
    
    my $auth = $env->{HTTP_AUTHORIZATION} or return $self->unauthorized;
    
    if ($auth =~ /^Digest (.*)/) {
        my $param = _parse_header($1);
        $param->{method} = $env->{REQUEST_METHOD};
        
        if ($self->authenticator->($param)) {
            $env->{REMOTE_USER} = $param->{username};
            return $self->app->($env);
        }
    }
    
    return $self->unauthorized;
}

sub _parse_header {
    my $str = shift;
    
    $csv->parse($str) or die $csv->error_diag;
    my %param = map {
        my $field = $_;
        $field =~ s/^\s*|\s*$//g;
        my ($key, $value) = $field =~ m/^(.*?)="?(.*?)"?$/;
        $key => $value;
    } $csv->fields;
    
    return \%param;
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

Plack::Middleware::Auth::Digest -

=head1 SYNOPSIS

  use Plack::Middleware::Auth::Digest;

=head1 DESCRIPTION

Plack::Middleware::Auth::Digest is

=head1 METHOD

=over

=item

=back

=head1 AUTHOR

Yuji Shimada E<lt>xaicron@cpan.orgE<gt>

=head1 SEE ALSO

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
