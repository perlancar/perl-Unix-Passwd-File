#!perl

use 5.010;
use strict;
use warnings;
use FindBin '$Bin';

use Unix::Passwd::File qw(get_user);
use Test::More 0.96;

subtest "etc_dir unknown -> error" => sub {
    my $res = get_user(etc_dir=>"$Bin/data/foo", user=>"bin");
    is($res->[0], 500, "status");
};

subtest "by uid, found" => sub {
    my $res = get_user(etc_dir=>"$Bin/data/simple", uid=>2);
    is($res->[0], 200, "status");
    is($res->[2]{user}, "daemon", "res");
};

subtest "by uid, not found" => sub {
    my $res = get_user(etc_dir=>"$Bin/data/simple", uid=>99);
    is($res->[0], 404, "status");
};

subtest "by user, found" => sub {
    my $res = get_user(etc_dir=>"$Bin/data/simple", user=>"bin");
    is($res->[0], 200, "status");
    is($res->[2]{uid}, 1, "res");
};

subtest "by user, not found" => sub {
    my $res = get_user(etc_dir=>"$Bin/data/simple", user=>"foo");
    is($res->[0], 404, "status");
};

subtest "mention user AND uid -> error" => sub {
    my $res = get_user(etc_dir=>"$Bin/data/simple", user=>"bin", uid=>1);
    is($res->[0], 400, "status");
};

DONE_TESTING:
done_testing();
