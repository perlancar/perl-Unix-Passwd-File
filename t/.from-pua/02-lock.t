#!perl

use 5.010;
use strict;
use warnings;

use FindBin '$Bin';
use lib $Bin, "$Bin/t";

use Test::More 0.96;
require "testlib.pl";

use vars qw($pu);

setup({lock=>1});

my @res;

# XXX more testing, currently only casually testing users() and adding. should
# actually check if locking works.

@res = $pu->users();
is(scalar(@res), 5, "users(): return");
is($res[0], "root", "users(): return[0]");

@res = $pu->user("u3", $pu->encpass("u1"), 1010, 1010,
                 "", "/home/u3", "/bin/bash");
is($res[0], 1, "add user u3: returns") or diag explain \@res;
{
    no warnings;
    ok(!$Passwd::Unix::Alt::errstr, "add user u3: errstr is not set");
}
@res = $pu->user("u3");
ok(@res, "add user u3: user u3 now exists");

DONE_TESTING:
teardown();
