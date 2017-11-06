#!perl

use 5.010;
use strict;
use warnings;
use FindBin '$Bin';
use Test::More 0.98;

BEGIN { plan skip_all => "OS unsupported" if $^O eq 'MSWin32' }

use Unix::Passwd::File qw(get_max_gid);

subtest "default" => sub {
    my $res = get_max_gid(etc_dir=>"$Bin/data/debian");
    is($res->[2], 65535);
};

DONE_TESTING:
done_testing();
