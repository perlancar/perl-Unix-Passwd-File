use Test::More tests => 5;
use File::Copy;
use File::Path;

use_ok('Passwd::Unix::Alt');

# prepare to leave provided files by tar untouched
mkdir 't/tmp';
foreach my $f (qw(passwd-debian group-debian shadow-debian shadow-debian)) {
    copy( "t/$f", "t/tmp/$f" ) or die "Copy $f failed: $!";
}

my $pua = Passwd::Unix::Alt->new(
    passwd => 't/tmp/passwd-debian',
    shadow => 't/tmp/shadow-debian'
);
ok( $pua,     '->new returns true' );
ok( ref $pua, '->new returns a reference' );
isa_ok( $pua, 'HASH', '->new returns a hash reference' );
isa_ok( $pua, 'Passwd::Unix::Alt',
    '->new returns a Passwd::Unix::Alt object' );

# cleanup
rmtree 't/tmp';
