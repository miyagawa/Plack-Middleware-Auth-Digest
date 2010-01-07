use Test::More;
use Plack::Test;
use Plack::Builder;
use HTTP::Request::Common;
use t::Client;
use t::CallBack;

my $username = 'admin';
my $password = 's3cr3t';

my $cb = t::CallBack->new(realm => 'restricted area');
$cb->add_user(username => $username, password => $password);

my $app = sub { return [ 200, [ 'Content-Type' => 'text/plain' ], [ "Hello $_[0]->{REMOTE_USER}" ] ] };
$app = builder {
    enable 'Auth::Digest', authenticator => $cb->callback;
    $app;
};

test_psgi app => $app, client => sub {
    my $cb = shift;
    
    my $res = $cb->(GET 'http://localhost');
    is $res->code, 401;
    
    my $req = make_auth_digest_response +{
        response => $res,
        uri      => 'http://localhost',
        username => $username,
        password => $password,
    };
    
    $res = $cb->($req);
    is $res->code, 200;
    is $res->content, "Hello admin"
};

done_testing;
