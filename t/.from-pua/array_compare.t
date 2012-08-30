#!perl

use 5.010;
use strict;
use warnings;

use Passwd::Unix::Alt;
use Test::More 0.96 tests => 4;

is(Passwd::Unix::Alt::array_compare("a", [1,2,3], "b", [1,2,3]), "", "same");
is(Passwd::Unix::Alt::array_compare("a", [1,2,3], "b", [1,2]), "only in a: 3", "some a only");
is(Passwd::Unix::Alt::array_compare("a", [1,2,3], "b", [1,2,3,4,5]), "only in b: 4, 5", "some b only");
is(Passwd::Unix::Alt::array_compare("a", [1,2,3], "b", [1,2,4]), "only in a: 3; only in b: 4", "some a only, some b only");


