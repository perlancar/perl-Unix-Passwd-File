use Test::More tests => 8;
use File::Copy;
use File::Path;

# prepare to leave provided files by tar untouched
mkdir 't/tmp';
foreach my $f (qw(passwd-debian group-debian shadow-debian shadow-debian)) {
    copy( "t/$f", "t/tmp/$f") or die "Copy $f failed: $!" ;
}

# COPIED from manual page 2012-03-22
#
# gid( USERNAME [,GID] )
# Read or modify a user's GID. Returns the result of operation (TRUE or FALSE)
# if GID was specified otherwhise returns the GID.
#
# DERIVED TESTS:
#
# (1) get:
# my $gid = $pua->gid($login);
#
# (2) set:
# 0|1 = $pua->gid($login, $number);

use_ok('Passwd::Unix::Alt');
my $pua = Passwd::Unix::Alt->new(
    passwd  => 't/tmp/passwd-debian',
    shadow  => 't/tmp/shadow-debian',
    group   => 't/tmp/group-debian',
    gshadow => 't/tmp/gshadow-debian',
);

# (1)
my $gid1 = $pua->gid('root');
ok( $gid1 == 0, 'gid: Can read gid root' );

my $gid2 = $pua->gid('nobody');
ok( $gid2 == 65534, 'gid: Can read gid nobody' );

my $gid3 = $pua->gid('nobody');
ok( $gid3 == 65534, 'gid: Second read of gid nobody' );

# (2)
# return value should be true

my $true1 = $pua->gid( 'nobody', 10000 );
ok( $true1, 'gid: Return value of set gid nobody is true' );

my $gid4 = $pua->gid('nobody');
ok( $gid4 == 10000, 'gid: Can set/read gid nobody' );

my $true2 = $pua->gid( 'nobody', 65534 );
ok( $true2, 'gid: Second return value of set gid is true' );

my $gid5 = $pua->gid('nobody');
ok( $gid5 == 65534, 'gid: Second read gid nobody' );

rmtree 't/tmp';

