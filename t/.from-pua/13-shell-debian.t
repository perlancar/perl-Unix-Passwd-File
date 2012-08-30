use Test::More tests => 3;
use File::Copy;
use File::Path;

# prepare to leave provided files by tar untouched
mkdir 't/tmp';
foreach my $f (qw(passwd-debian group-debian shadow-debian shadow-debian)) {
    copy( "t/$f", "t/tmp/$f" ) or die "Copy $f failed: $!";
}

#
# shell( USERNAME [,SHELL] )

# Read or modify a user's shell. Returns the result of operation (TRUE or
# FALSE) if SHELL was specified otherwhise returns the SHELL.

use_ok('Passwd::Unix::Alt');
my $pua = Passwd::Unix::Alt->new(
    passwd  => 't/tmp/passwd-debian',
    shadow  => 't/tmp/shadow-debian',
    group   => 't/tmp/group-debian',
    gshadow => 't/tmp/gshadow-debian',
);

my $shell = $pua->shell('root');
ok( $shell eq '/bin/zsh', 'shell: Can read root shell' );

# TODO: should return true value
# See description of man page:
#   shell( USERNAME [,SHELL] ) Read or modify a user's shell. Returns the result
#   of operation (TRUE or FALSE) if SHELL was specified otherwhise returns the
#   SHELL.
my $true = $pua->shell('root',$shell);
#diag("true [$true]");
ok($true, 'shell: Has root shell');

# cleanup
rmtree 't/tmp';


