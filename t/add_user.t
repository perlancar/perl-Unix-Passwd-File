#!perl

use 5.010;
use strict;
use warnings;
use FindBin '$Bin';

use File::chdir;
use File::Copy::Recursive qw(rcopy);
use File::Path qw(remove_tree);
use File::Temp qw(tempdir);
use Unix::Passwd::File qw(add_user get_user);
use Test::More 0.96;

my $tmpdir = tempdir(CLEANUP=>1);
$CWD = $tmpdir;
note "tmpdir=$tmpdir";

subtest "missing required fields" => sub {
    remove_tree "$tmpdir/simple"; rcopy("$Bin/data/simple", "$tmpdir/simple");
    my $res = add_user(etc_dir=>"$tmpdir/simple");
    is($res->[0], 400, "status") or diag explain $res;
};
subtest "invalid field: user" => sub {
    remove_tree "$tmpdir/simple"; rcopy("$Bin/data/simple", "$tmpdir/simple");
    my $res = add_user(etc_dir=>"$tmpdir/simple",
                       user=>"foo ");
    is($res->[0], 400, "status") or diag explain $res;
};
for my $f (qw/home gecos shell encpass pass_inactive_period expire_date/) {
    subtest "invalid field: $f" => sub {
        remove_tree "$tmpdir/simple";
        rcopy("$Bin/data/simple", "$tmpdir/simple");
        my $res = add_user(etc_dir=>"$tmpdir/simple",
                           user=>"foo", $f=>"\n");
        is($res->[0], 400, "status") or diag explain $res;
    };
}

subtest "user already exists -> fail" => sub {
    remove_tree "$tmpdir/simple"; rcopy("$Bin/data/simple", "$tmpdir/simple");
    my $res = add_user(etc_dir=>"$tmpdir/simple",
                       user=>"u1", home=>"/home/foo", shell=>"/bin/bash",
                   );
    is($res->[0], 412, "status");
};

subtest "success" => sub {
    remove_tree "$tmpdir/simple"; rcopy("$Bin/data/simple", "$tmpdir/simple");
    my $res = add_user(etc_dir=>"$tmpdir/simple",
                       user=>"foo", home=>"/home/foo", shell=>"/bin/bash",
                   );
    is($res->[0], 200, "status");
    is_deeply($res->[2], {uid=>1002, gid=>1002}, "res") or diag explain $res;

    $res = get_user(etc_dir=>"$tmpdir/simple", user=>"foo");
    is($res->[2]{encpass}, '*', "encpass");
};

subtest "set pass" => sub {
    remove_tree "$tmpdir/simple"; rcopy("$Bin/data/simple", "$tmpdir/simple");
    my $res = add_user(etc_dir=>"$tmpdir/simple",
                       user=>"foo", pass=>"123",
                   );
    is($res->[0], 200, "status");
    is_deeply($res->[2], {uid=>1002, gid=>1002}, "res") or diag explain $res;

    $res = get_user(etc_dir=>"$tmpdir/simple", user=>"foo");
    is($res->[2]{pass}, 'x', "pass");
    like($res->[2]{encpass}, qr/^\$6\$/, "encpass");
};

subtest "uid" => sub {
    remove_tree "$tmpdir/simple"; rcopy("$Bin/data/simple", "$tmpdir/simple");
    my $res = add_user(etc_dir=>"$tmpdir/simple",
                       user=>"foo", home=>"/home/foo", shell=>"/bin/bash",
                       uid=>2000,
                   );
    is($res->[0], 200, "status");
    is_deeply($res->[2], {uid=>2000, gid=>1002}, "res");
};
subtest "uid (unavailable)" => sub {
    remove_tree "$tmpdir/simple"; rcopy("$Bin/data/simple", "$tmpdir/simple");
    my $res = add_user(etc_dir=>"$tmpdir/simple",
                       user=>"foo", home=>"/home/foo", shell=>"/bin/bash",
                       uid=>1000,
                   );
    is($res->[0], 412, "status");
};

subtest "pick min_uid, max_uid" => sub {
    remove_tree "$tmpdir/simple"; rcopy("$Bin/data/simple", "$tmpdir/simple");
    my $res = add_user(etc_dir=>"$tmpdir/simple",
                       user=>"foo", home=>"/home/foo", shell=>"/bin/bash",
                       min_uid=>2000, max_uid=>2000,
                   );
    is($res->[0], 200, "status");
    is_deeply($res->[2], {uid=>2000, gid=>1002}, "res");
};
subtest "pick min_uid, max_uid (unavailable)" => sub {
    remove_tree "$tmpdir/simple"; rcopy("$Bin/data/simple", "$tmpdir/simple");
    my $res = add_user(etc_dir=>"$tmpdir/simple",
                       user=>"foo", home=>"/home/foo", shell=>"/bin/bash",
                       min_uid=>1000, max_uid=>1001,
                   );
    is($res->[0], 412, "status");
};

# XXX: test gid
# XXX: test can't find new uid
# XXX: test min_gid, max_gid
# XXX: test can't find new gid

DONE_TESTING:
done_testing();
if (Test::More->builder->is_passing) {
    note "all tests successful, deleting tmp dir";
    $CWD = "/";
} else {
    diag "there are failing tests, not deleting tmp dir $tmpdir";
}

1;
