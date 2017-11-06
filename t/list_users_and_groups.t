#!perl

use 5.010;
use strict;
use warnings;
use FindBin '$Bin';
use Test::More 0.98;

BEGIN { plan skip_all => "OS unsupported" if $^O eq 'MSWin32' }

use File::chdir;
use File::Copy::Recursive qw(rcopy);
use File::Temp qw(tempdir);
use Unix::Passwd::File qw(list_users_and_groups);

my $tmpdir = tempdir(CLEANUP=>1);
$CWD = $tmpdir;
note "tmpdir=$tmpdir";

rcopy("$Bin/data/simple", "$tmpdir/simple");
unlink "$tmpdir/simple/shadow";

subtest "shadow unreadable -> ok" => sub {
    my $res = list_users_and_groups(etc_dir=>"$tmpdir/simple");
    is_deeply($res->[2], [
        [qw/root bin daemon u1 u2/],
        [qw/root bin daemon nobody u1 u2/],
    ]);
};

subtest "default" => sub {
    my $res = list_users_and_groups(etc_dir=>"$Bin/data/simple");
    is_deeply($res->[2], [
        [qw/root bin daemon u1 u2/],
        [qw/root bin daemon nobody u1 u2/],
    ]);
};

subtest "detail=1" => sub {
    my $res = list_users_and_groups(etc_dir=>"$Bin/data/simple", detail=>1);
    is_deeply($res->[2][0][0], {
        gecos => "root",
        gid => 0,
        home => "/root",
        pass => "x",
        shell => "/bin/bash",
        uid => 0,
        user => "root",

        encpass => "*",
        expire_date => "",
        last_pwchange => 14607,
        max_pass_age => 99999,
        min_pass_age => 0,
        pass_inactive_period => "",
        pass_warn_period => 7,
        reserved => "",
    }) or diag explain $res->[2][0][0];
    is_deeply($res->[2][1][0], {
        admins => "",
        gid => 0,
        group => "root",
        members => "",
        pass => "x",

        encpass => "",
    }) or diag explain $res->[2][1][0];
};

subtest "detail=1, with_field_names=>0" => sub {
    my $res = list_users_and_groups(etc_dir=>"$Bin/data/simple",
                                    detail=>1, with_field_names=>0);
    is_deeply($res->[2][0][0], [qw(root x 0 0 root /root /bin/bash)]);
    is_deeply($res->[2][1][0], ["root", "x", 0, ""]);
};

DONE_TESTING:
done_testing();
if (Test::More->builder->is_passing) {
    note "all tests successful, deleting tmp dir";
    $CWD = "/";
} else {
    diag "there are failing tests, not deleting tmp dir $tmpdir";
}
