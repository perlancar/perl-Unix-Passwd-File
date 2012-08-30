package Unix::Passwd::File;

use 5.010;
use strict;
use warnings;

# VERSION

use File::Flock;

our @ISA       = qw(Exporter);
our @EXPORT_OK = qw(
                       get_user list_users delete_user modify_user add_user
                       get_group list_groups delete_group modify_group add_group
               );

our %SPEC;

my %passwd_fields = (
    user => {
        index   => 0,
        schema  => ['str*' => {match => qr/\A[A-Za-z0-9._-]+\z/}],
        summary => 'User (login) name',
    },
    pass => {
        index   => 1,
        schema  => ['str*' => {match=>qr/\A[^\n:]*\z/}],
        summary => 'Password, generally should be "x" which means password is '.
            'encrypted in shadow',
    },
    uid => {
        index   => 2,
        schema  => 'int*',
        summary => 'Numeric user ID',
    },
    gid => {
        index   => 3,
        schema  => 'int*',
        summary => 'Numeric primary group ID for this user',
    },
    gecos => {
        index   => 4,
        schema  => ['str*' => {match=>qr/\A[^\n:]*\z/}],
        summary => 'Usually, it contains the full username',
    },
    home => {
        index   => 5,
        schema  => ['str*' => {match=>qr/\A[^\n:]*\z/}],
        summary => 'User\'s home directory',
    },
    shell => {
        index   => 6,
        schema  => ['str*' => {match=>qr/\A[^\n:]*\z/}],
        summary => 'User\'s home directory',
    },
);
my @passwd_field_names;
for (keys %passwd_fields) {$passwd_field_names[$passwd_fields{$_}{index}]=$_}

my %shadow_fields = (
    user => $passwd_fields{user},
    encpass => {
        index   => 1,
        schema  => ['str*' => {match=>qr/\A[^\n:]*\z/}],
        summary => 'Encrypted password',
    },
    last_pwchange => {
        index   => 2,
        schema  => 'int',
        summary => 'The date of the last password change, '.
            'expressed as the number of days since Jan 1, 1970.',
    },
    min_pass_age => {
        index   => 3,
        schema  => 'int',
        summary => 'The number of days the user will have to wait before she '.
            'will be allowed to change her password again',
    },
    max_pass_age => {
        index   => 4,
        schema  => 'int',
        summary => 'The number of days after which the user will have to '.
            'change her password',
    },
    pass_warn_period => {
        index   => 5,
        schema  => 'int',
        summary => 'The number of days before a password is going to expire '.
            '(see max_pass_age) during which the user should be warned',
    },
    pass_inactive_period => {
        index   => 6,
        schema  => 'int',
        summary => 'The number of days after a password has expired (see '.
            'max_pass_age) during which the password should still be accepted '.
                '(and user should update her password during the next login)',
    },
    expire_date => {
        index   => 7,
        schema  => 'int',
        summary => 'The date of expiration of the account, expressed as the '.
            'number of days since Jan 1, 1970',
    },
    reserved => {
        index   => 8,
        schema  => ['str*' => {match=>qr/\A[^\n:]*\z/}],
        summary => 'This field is reserved for future use',
    }
);
my @shadow_field_names;
for (keys %shadow_fields) {$shadow_field_names[$shadow_fields{$_}{index}]=$_}

my %group_fields = (
    group => {
        index   => 0,
        schema  => ['str*' => {match=>qr/\A[^\n:]*\z/}],
        summary => 'Group name',
    },
    pass => {
        index   => 1,
        schema  => ['str*' => {match=>qr/\A[^\n:]*\z/}],
        summary => 'Password, generally should be "x" which means password is '.
            'encrypted in gshadow',
    },
    gid => {
        index   => 2,
        schema  => 'int',
        summary => 'Numeric group ID',
    },
    members => {
        index   => 3,
        schema  => ['str*' => {match=>qr/\A[^\n:]*\z/}],
        summary => 'List of usernames that are members of this group, '.
            'separated by commas',
    },
);
my @group_field_names;
for (keys %group_fields) {$group_field_names[$group_fields{$_}{index}]=$_}

my %gshadow_fields = (
    group => $group_fields{group},
    encpass => {
        index => 1,
        schema  => ['str*' => {match=>qr/\A[^\n:]*\z/}],
        summary => 'Encrypted password',
    },
    admins => {
        index => 2,
        schema  => ['str*' => {match=>qr/\A[^\n:]*\z/}],
        summary => 'It must be a comma-separated list of user names, or empty',
    },
    members => {
        index => 3,
        schema  => ['str*' => {match=>qr/\A[^\n:]*\z/}],
        summary => 'List of usernames that are members of this group, '.
            'separated by commas; usually empty since this is already in group',
    },
);
my @gshadow_field_names;
for (keys %gshadow_fields) {$gshadow_field_names[$gshadow_fields{$_}{index}]=$_}

# _read_shadow  = 0/1/2 (2 means optional, don't exit if fail)
# _read_passwd  = 0/1
# _read_gshadow = 0/1/2 (2 means optional, don't exit if fail)
# _read_group   = 0/1
# _lock         = 0/1 (whether to lock)
sub _routine {
    my %args = @_;

    my $etc     = $args{etc_dir} // "/etc";
    my $detail  = $args{detail};
    my $wfn     = $args{with_field_names} // 1;
    my $locked;
    my $fh;
    my %stash;

    my $e = eval {

        if ($args{_lock}) {
            my $l;
            for (1..3) {
                $l = lock("$etc/passwd.lock", undef, 'nonblocking');
                last if $l;
                sleep 1;
            }
            return [412, "Can't lock $etc/passwd.lock"] unless $l;
            $locked++;
        }

        # read files

        my @shadow;
        my @shadowh;
        if ($args{_read_shadow} // 1) {
            if ($detail) {
                open $fh, "<", "$etc/shadow"
                    or return [500, "Can't open $etc/shadow: $!"];
                while (<$fh>) {
                    chomp;
                    next unless /\S/; # skip empty line
                    my @r = split /:/, $_, scalar(keys %shadow_fields);
                    push @shadow, \@r;
                    if ($wfn) {
                        my %r;
                        @r{@shadow_field_names} = @r;
                        push @shadowh, \%r;
                    }
                }
            }
        }

        my @passwd;
        my @passwdh;
        if ($args{_read_passwd} // 1) {
            open $fh, "<", "$etc/passwd"
                or return [500, "Can't open $etc/passwd: $!"];
            while (<$fh>) {
                chomp;
                next unless /\S/; # skip empty line
                my @r = split /:/, $_, scalar(keys %passwd_fields);
                push @passwd, \@r;
                if ($wfn) {
                    my %r;
                    @r{@passwd_field_names} = @r;
                    push @passwdh, \%r;
                }
            }
        }

        my @gshadow;
        my @gshadowh;
        if ($args{_read_gshadow} // 1) {
            open $fh, "<", "$etc/gshadow"
                or return [500, "Can't open $etc/gshadow: $!"];
            while (<$fh>) {
                chomp;
                next unless /\S/; # skip empty line
                my @r = split /:/, $_, scalar(keys %gshadow_fields);
                push @gshadow, \@r;
                if ($wfn) {
                    my %r;
                    @r{@gshadow_field_names} = @r;
                    push @gshadowh, \%r;
                }
            }
        }

        my @group;
        my @grouph;
        if ($args{_read_group} // 1) {
            open $fh, "<", "$etc/group"
                or return [500, "Can't open $etc/group: $!"];
            while (<$fh>) {
                chomp;
                next unless /\S/; # skip empty line
                my @r = split /:/, $_, scalar(keys %group_fields);
                push @group, \@r;
                if ($wfn) {
                    my %r;
                    @r{@group_field_names} = @r;
                    push @grouph, \%r;
                }
            }
        }

        $stash{shadow}   = \@shadow;
        $stash{shadowh}  = \@shadowh;
        $stash{passwd}   = \@passwd;
        $stash{passwdh}  = \@passwdh;
        $stash{group}    = \@group;
        $stash{grouph}   = \@grouph;
        $stash{gshadow}  = \@gshadow;
        $stash{gshadowh} = \@gshadowh;

        if ($args{_after_read}) {
            my $res = $args{_after_read}->(\%stash);
            return $res if $res->[0] != 200;
            return if $stash{exit};
        }
    }; # eval

    if ($locked) {
        unlock("$etc/passwd.lock");
    }

    $stash{res}   = $e if $e;
    $stash{res} //= [500, "BUG: res not set"];

    $stash{res};
}

$SPEC{list_users} = {
    v => 1.1,
    summary => 'List Unix users in passwd file',
    args => {
        detail => {
            summary => 'If true, return all fields instead of just usernames',
            schema => ['bool' => {default => 0}],
        },
        with_field_names => {
            summary => 'If false, don\'t return hash for each entry',
            description => <<'_',

By default, when `detail=>1`, a hashref is returned for each entry containing
field names and its values, e.g. `{user=>"neil", pass=>"x", uid=>500, ...}`.
With `with_field_names=>0`, an arrayref is returned instead: `["neil", "x", 500,
...]`.

_
        },
    },
};
sub list_users {
    my %args = @_;
    my $detail = $args{detail};
    my $wfn    = $args{with_field_names} // ($detail ? 1:0);

    _routine(
        @_,
        _read_shadow     => $detail ? 2:0,
        _read_gshadow    => $detail ? 2:0,
        with_field_names => $wfn,
        _after_read      => sub {
            my $stash = shift;

            my @rows;
            my $passwd  = $stash->{passwd};
            my $passwdh = $stash->{passwdh};

            for (my $i=0; $i < @$passwd; $i++) {
                if (!$detail) {
                    push @rows, $passwd->[$i][0];
                } elsif ($wfn) {
                    push @rows, $passwdh->[$i];
                } else {
                    push @rows, $passwd->[$i];
                }
            }

            $stash->{res} = [200, "OK", \@rows];

            $stash->{exit}++;
            [200, "OK"];
        },
    );
}

1;
# ABSTRACT: Manipulate /etc/{passwd,shadow,group,gshadow} entries

=head1 SYNOPSIS

 use Unix::Passwd::Files;

 # by default uses files in /etc (/etc/passwd, /etc/shadow, et al)
 my $res = list_users(); # [200, "OK", ["root", ...]]

 # change location of files, return details
 $res = list_users(etc_dir=>"/some/path");
     # [200, "OK", [{user=>"root", uid=>0, ...}, ...]]

 # getting user/group
 $res = get_group(user=>"buzz"); # [200, "OK", {user=>"buzz", uid=>501, ...}]
 $res = get_user(user=>"neil");  # [404, "Not found"]

 # adding user/group, by default adding user will also add a group with the same
 # name, unless using add_group=>0
 $res = add_user (user =>"steven", ...); # [200, "OK", {uid=>540, gid=>541}]
 $res = add_group(group=>"steven", ...); # [412, "Group already exists"]

 # modify user/group
 $res = modify_user(user=>"steven", home=>"/newhome/steven"); # [200, "OK"]
 $res = modify_group(group=>"neil"); # [404, "Not found"]

 # deleting user will also delete user's group, except using delete_group=>0
 $res = delete_user(user=>"neil");


=head1 DESCRIPTION

This module can be used to read and manipulate entries in Unix system password
files (/etc/passwd, /etc/group, /etc/group, /etc/gshadow; but can also be told
to search in custom location, for testing purposes).

=head1 SEE ALSO

Old modules on CPAN which do not support shadow files are pretty useless to me
(e.g. L<Unix::ConfigFile>). Shadow passwords have been around since 1988 (and in
Linux since 1992), FFS!

L<Passwd::Unix>. I created a fork of Passwd::Unix v0.52 called
L<Passwd::Unix::Alt> in 2011 to fix some of the deficiencies/quirks in
Passwd::Unix, including: lack of tests, insistence of running as root (despite
allowing custom passwd files), use of not-so-ubiquitous bzip2, etc. Then in 2012
I decided to create Unix::Passwd::File. Here are how Unix::Passwd::File differs
compared to Passwd::Unix (and Passwd::Unix::Alt):

=over 4

=item * tests in distribution

=item * no need to run as root

=item * no need to be able to read the shadow file for some operations

For example, C<list_users()> will simply not return the C<encpass> field if the
shadow file is unreadable. Of course, access to shadow file is required when
getting or setting password.

=item * strictly procedural (non-OO) interface

I consider this a feature :-)

=item * detailed error message for each operation

=item * removal of global error variable

=item * working locking

Locking is done by locking C<passwd.lock> file.

=back

L<Setup::Unix::User> and L<Setup::Unix::Group>, which use this module.

L<Rinci>
