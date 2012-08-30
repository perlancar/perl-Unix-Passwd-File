#!perl

use 5.010;
use strict;
use warnings;
use FindBin '$Bin';

use Unix::Passwd::File qw(list_users);
use Test::More 0.96;

subtest "default" => sub {
    my $res = list_users(etc_dir=>"$Bin/data/simple");
    is_deeply($res->[2], [qw/root bin daemon u1 u2/]);
};

subtest "detail=1" => sub {
    my $res = list_users(etc_dir=>"$Bin/data/simple", detail=>1);
    is_deeply($res->[2][0], {
        gecos => "root",
        gid => 0,
        home => "/root",
        pass => "x",
        shell => "/bin/bash",
        uid => 0,
        user => "root",
    });
};

subtest "detail=1, with_field_names=>0" => sub {
    my $res = list_users(etc_dir=>"$Bin/data/simple",
                         detail=>1, with_field_names=>0);
    is_deeply($res->[2][0], [qw(root x 0 0 root /root /bin/bash)]);
};

DONE_TESTING:
done_testing();
