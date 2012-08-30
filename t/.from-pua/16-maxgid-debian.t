use Test::More tests => 2;
use File::Copy;
use File::Path;

# prepare to leave provided files by tar untouched
mkdir 't/tmp';
foreach my $f (qw(passwd-debian group-debian shadow-debian shadow-debian)) {
    copy( "t/$f", "t/tmp/$f" ) or die "Copy $f failed: $!";
}

# maxgid( ) This method returns the maximum UID in use by all users.

use_ok('Passwd::Unix::Alt');
my $pua = Passwd::Unix::Alt->new(
    passwd  => 't/tmp/passwd-debian',
    shadow  => 't/tmp/shadow-debian',
    group   => 't/tmp/group-debian',
    gshadow => 't/tmp/gshadow-debian',
);

my $maxgid = $pua->maxgid;
is( $maxgid, 65535, 'maxgid: max gid is 65535' );

# cleanup
rmtree 't/tmp';

