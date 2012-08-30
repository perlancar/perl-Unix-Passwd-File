use 5.010;
use strict;
use warnings;
use FindBin '$Bin';

use File::chdir;
use File::Temp qw(tempdir);
use Unix::Passwd::File;
use Test::More 0.96;

my $tmpdir = tempdir(CLEANUP=>1);
$CWD = $tmpdir;
note "tmpdir=$tmpdir";

subtest "list_users" => sub {
    my $res = list_users(etc_dir=>"$Bin/data/simple");
    is_deeply($res->[2], [qw/root bin daemon u1 u2/], "res");
};

DONE_TESTING:
done_testing();
if (Test::More->builder->is_passing) {
    note "all tests successful, deleting tmp dir";
    $CWD = "/";
} else {
    diag "there are failing tests, not deleting tmp dir $tmpdir";
}

1;
