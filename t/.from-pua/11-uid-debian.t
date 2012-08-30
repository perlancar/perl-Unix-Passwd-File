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
# uid( USERNAME [,UID] )
# Read or modify a user's UID. Returns the result of operation (TRUE or FALSE)
# if UID was specified otherwhise returns the UID.
#
# DERIVED TESTS:
#
# (1) get:
# my $uid = $pua->uid($login);
#
# (2) set:
# 0|1 = $pua->uid($login, $number);

use_ok('Passwd::Unix::Alt');
my $pua = Passwd::Unix::Alt->new(
    passwd  => 't/tmp/passwd-debian',
    shadow  => 't/tmp/shadow-debian',
    group   => 't/tmp/group-debian',
    gshadow => 't/tmp/gshadow-debian',
);

# (1)
my $uid1 = $pua->uid('root');
ok( $uid1 == 0, 'uid: Can read uid root' );

my $uid2 = $pua->uid('nobody');
ok( $uid2 == 65534, 'uid: Can read uid nobody' );

my $uid3 = $pua->uid('nobody');
ok( $uid3 == 65534, 'uid: Second read of uid nobody' );

# (2)
# return value should be true

my $true1 = $pua->uid( 'nobody', 10000 );
ok( $true1, 'uid: Return value of set uid nobody is true' );

my $uid4 = $pua->uid('nobody');
ok( $uid4 == 10000, 'uid: Can set/read uid nobody' );

my $true2 = $pua->uid( 'nobody', 65534 );
ok( $true2, 'uid: Second return value of set uid is true' );

my $uid5 = $pua->uid('nobody');
ok( $uid5 == 65534, 'uid: Second read uid nobody' );

# cleanup
rmtree 't/tmp';

