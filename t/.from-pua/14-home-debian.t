use Test::More tests => 6;
use File::Copy;
use File::Path;

# prepare to leave provided files by tar untouched
mkdir 't/tmp';
foreach my $f (qw(passwd-debian group-debian shadow-debian shadow-debian)) {
    copy( "t/$f", "t/tmp/$f" ) or die "Copy $f failed: $!";
}

# home( USERNAME [,HOMEDIR] ) Read or modify a user's home directory. Returns
# the result of operation (1 or "undef") if HOMEDIR was specified otherwhise
# returns the HOMEDIR
use_ok('Passwd::Unix::Alt');
my $pua = Passwd::Unix::Alt->new(
    passwd  => 't/tmp/passwd-debian',
    shadow  => 't/tmp/shadow-debian',
    group   => 't/tmp/group-debian',
    gshadow => 't/tmp/gshadow-debian',
);

my $home1 = $pua->home('root');
ok( $home1 eq '/root', 'home: Can read root home' );

my $true1 = $pua->home( 'root', $home1 );
ok( $true1, 'home: set home root return value true' );

my $home2 = $pua->home('bilbo');
ok( $home2 eq '/home/bilbo', 'home: Can read bilbo home' );

my $true2 = $pua->home( 'bilbo', '/home/bilbo2' );
ok( $true2, 'home: Can set bilbo home to /home/bilbo2' );

my $home3 = $pua->home('bilbo');
ok( $home3 eq '/home/bilbo2', 'home: Can read modified bilbo home' );

# cleanup
rmtree 't/tmp';

