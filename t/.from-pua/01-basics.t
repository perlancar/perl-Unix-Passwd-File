#!perl

use 5.010;
use strict;
use warnings;

use FindBin '$Bin';
use lib $Bin, "$Bin/t";

use Test::More 0.96;
require "testlib.pl";

use vars qw($pu);

setup();

my @res;

# get/list

@res = $pu->users();
is(scalar(@res), 5, "users(): return");
is($res[0], "root", "users(): return[0]");

@res = $pu->user("u3");
ok(!@res, "user(UNKNOWN): return");
ok($Passwd::Unix::Alt::errstr, "user(UNKNOWN): errstr is set");

@res = $pu->user("u1");
is(scalar(@res), 6, "user(u1): return");
is($res[1], 1000, "user(u1): return[1]");
ok(!$Passwd::Unix::Alt::errstr, "user(u1): errstr is not set");

@res = $pu->groups();
is(scalar(@res), 6, "groups(): return");
is($res[1], "bin", "groups(): return[1]");

@res = $pu->group("u3");
ok(!defined($res[0]), "group(UNKNOWN): return");
ok($Passwd::Unix::Alt::errstr, "group(UNKNOWN): errstr is set");

@res = $pu->group("u2");
is(scalar(@res), 2, "group(u2): return");
is($res[0], 1001, "group(u2): return[0]");
is_deeply($res[1], ["u2"], "group(u2): return[1]");
ok(!$Passwd::Unix::Alt::errstr, "group(u2): errstr is not set");

# add

@res = $pu->user("u3", $pu->encpass("u1"), 1010, 1010,
                 "", "/home/u3", "/bin/bash");
is($res[0], 1, "add user u3: returns") or diag explain \@res;
ok(!$Passwd::Unix::Alt::errstr, "add user u3: errstr is not set");
@res = $pu->user("u3");
ok(@res, "add user u3: user u3 now exists");
@res = $pu->group("u3");
ok(!defined($res[0]), "add user u3: group u3 still doesn't exist");

@res = $pu->group("u3", 1010, ["u3"]);
ok(!@res, "add group u3: returns") or diag explain \@res;
ok(!$Passwd::Unix::Alt::errstr, "add group u3: errstr is not set");
@res = $pu->group("u3");
ok(@res, "add group u3: group u3 now exists");

# update

@res = $pu->user("u3", "x", 1010, 1010,
                 "gecos 2", "/home2/u3", "/bin/bash2");
is($res[0], 1, "update user u3: returns") or diag explain \@res;
ok(!$Passwd::Unix::Alt::errstr, "update user u3: errstr is not set");
@res = $pu->user("u3");
is($res[3], "gecos 2", "update user u3: gecos updated");
is($res[4], "/home2/u3", "update user u3: homedir updated");
is($res[5], "/bin/bash2", "update user u3: shell updated");

@res = $pu->group("u3", 1010, ["u1", "u2", "u3"]);
ok(!@res, "update group u3: returns") or diag explain \@res;
ok(!$Passwd::Unix::Alt::errstr, "update group u3: errstr is not set");
@res = $pu->group("u3");
is_deeply($res[1], ["u1", "u2", "u3"], "update group u3: members updated");

# delete

@res = $pu->del("u3");
ok(!$Passwd::Unix::Alt::errstr, "delete user u3: errstr is not set");
@res = $pu->user("u3");
ok(!@res, "delete user u3: user u3 now doesn't exist");
@res = $pu->group("u3");
ok($res[0], "delete user u3: group u3 still exists");

@res = $pu->del_group("u3");
ok(!$Passwd::Unix::Alt::errstr, "delete group u3: errstr is not set");
@res = $pu->group("u3");
ok(!defined($res[0]), "delete group u3: group u3 now doesn't exist");

# TODO: delete unknown user/group = ok
# TODO: permission problem with some/all files
# TODO: some/all files don't exist
# TODO: problem creating backup
# TODO: set backup=0
# TODO: passwd/shadow different
# TODO: group/gshadow different
# TODO: the rest of the methods
# TODO: access as functions

DONE_TESTING:
teardown();
