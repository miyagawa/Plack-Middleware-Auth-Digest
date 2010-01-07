package t::Client;

use strict;
use warnings;

use Text::CSV;
use HTTP::Request::Common;
use Exporter qw/import/;
use Carp;
use String::Random qw/random_string/;
use Digest::MD5 qw/md5_hex/;
#use Data::Dumper;

our @EXPORT = qw/make_auth_digest_response/;

my $csv = Text::CSV->new({allow_loose_quotes => 1});

sub make_auth_digest_response {
    my $args = shift;
    
    @$args{qw/response uri username password/} ||
        croak 'Usage: make_auth_digest_response({response => $res, uri => $uri, username => $username, password => $password})';
    
    my $header = $args->{response}->header('WWW-Authenticate');
    if ($header =~ /^Digest (.*)/) {
        my $param = _parse_header($1);
        
#        warn Dumper $param;
        
        my $nc = '00000001';
        my $cnonce = random_string 's' x 16;
        
        my $A1 = _make_a1($args->{username}, $param->{realm}, $args->{password});
        my $A2 = _make_a2($args->{uri});
        my $response = _make_response($A1, $param->{nonce}, $nc, $cnonce, $param->{qop}, $A2);
        
#        warn $response;
        
        return GET $args->{uri}, 'Authorization' => sprintf(
            'Digest username="%s", realm="%s", nonce="%s", uri="%s", algorithm=MD5, response="%s", qop=auth, nc=%s, cnonce="%s"',
            $args->{username}, $param->{realm}, $param->{nonce}, $args->{uri}, $response, $nc, $cnonce
        );
    }
    
    die "oops!";
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

sub _make_a1 {
    my $user = shift;
    my $realm = shift;
    my $pass = shift;
    
    return md5_hex "$user:$realm:$pass";
}

sub _make_a2 {
    my $uri = shift;
    
    return md5_hex "GET:$uri";
}

sub _make_response {
    my $A1 = shift;
    my $nonce = shift;
    my $nc = shift;
    my $cnonce = shift;
    my $qop = shift;
    my $A2 = shift;
    
    return md5_hex sprintf '%s:%s:%s:%s:%s:%s', $A1, $nonce, $nc, $cnonce, $qop, $A2;
}

1;
