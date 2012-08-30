use Test::More tests => 2;
use File::Copy;
use File::Path;

# prepare to leave provided files by tar untouched
mkdir 't/tmp';
foreach my $f (qw(passwd-debian group-debian shadow-debian shadow-debian)) {
    copy( "t/$f", "t/tmp/$f" ) or die "Copy $f failed: $!";
}

# maxuid( ) This method returns the maximum UID in use by all users.

use_ok('Passwd::Unix::Alt');
my $pua = Passwd::Unix::Alt->new(
    passwd  => 't/tmp/passwd-debian',
    shadow  => 't/tmp/shadow-debian',
    group   => 't/tmp/group-debian',
    gshadow => 't/tmp/gshadow-debian',
);

my $maxuid = $pua->maxuid;
ok( $maxuid == 65534, 'maxuid: max uid is 65534' );

# cleanup
rmtree 't/tmp';

