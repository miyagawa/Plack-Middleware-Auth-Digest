package t::CallBack;

use strict;
use warnings;
use Carp qw/croak/;
use Digest::MD5 qw/md5_hex/;

sub new {
    my $class = shift;
    my %args = @_;
    my $realm = $args{realm} || croak 'Usage: t::CallBack->new(realm => $realm)';
    
    bless +{user => +{}, realm => $realm }, $class;
}

sub user  { $_[0]->{user}  }
sub realm { $_[0]->{realm} }

sub add_user {
    my $self = shift;
    my %args = @_;
    @args{qw/username password/} || croak 'Usage: $cb->add_user(username => $user, password => $pass)';
    
    $self->user->{$args{username}} = md5_hex "$args{username}:" . $self->realm . ":$args{password}";
}

sub callback {
    my $self = shift;
    
    return sub {
        my $param = shift;
        
        my $A1 = $self->user->{$param->{username}} || return;
        my $A2 = md5_hex sprintf '%s:%s', $param->{method}, $param->{uri};
        my $response = md5_hex sprintf '%s:%s:%s:%s:%s:%s',
            $A1, $param->{nonce}, $param->{nc}, $param->{cnonce}, $param->{qop}, $A2;
        
        return $param->{response} eq $response;
    };
}

1;
