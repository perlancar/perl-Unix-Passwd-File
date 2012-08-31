package Unix::Passwd::File;

use 5.010;
use strict;
use warnings;
use Log::Any '$log';

# VERSION

use File::Flock;
use List::Util qw(max first);
use List::MoreUtils qw(firstidx);

our @ISA       = qw(Exporter);
our @EXPORT_OK = qw(
                       get_user list_users delete_user modify_user add_user
                       get_max_uid
                       set_user_password
                       get_group list_groups delete_group modify_group add_group
                       get_max_gid
                       add_user_to_group
                       delete_user_from_group
               );

our %SPEC;

my %common_args = (
    etc_dir => {
        summary => 'Specify location of passwd files',
        schema  => ['str*' => {default=>'/etc'}],
    },
);
my %write_args = (
    backup => {
        summary => 'Whether to backup when modifying files',
        description => <<'_',

Backup is written with `.bak` extension in the same directory. Unmodified file
will not be backed up. Previous backup will be overwritten.

_
        schema  => ['bool' => {default=>0}],
    },
);

my $re_user   = qr/\A[A-Za-z0-9._-]+\z/;
my $re_group  = $re_user;
my $re_field  = qr/\A[^\n:]*\z/;
my $re_posint = qr/\A[1-9][0-9]*\z/;

my %passwd_fields = (
    user => {
        index   => 0,
        schema  => ['str*' => {match => $re_user}],
        summary => 'User (login) name',
    },
    pass => {
        index   => 1,
        schema  => ['str*' => {match => $re_field}],
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
        schema  => ['str*' => {match => $re_field}],
        summary => 'Usually, it contains the full username',
    },
    home => {
        index   => 5,
        schema  => ['str*' => {match => $re_field}],
        summary => 'User\'s home directory',
    },
    shell => {
        index   => 6,
        schema  => ['str*' => {match=>qr/\A[^\n:]*\z/}],
        summary => 'User\'s home directory',
    },
);
my @passwd_field_names;
for (keys %passwd_fields) {
    $passwd_field_names[$passwd_fields{$_}{index}] = $_;
    delete $passwd_fields{$_}{index};
}

my %shadow_fields = (
    user => {
        index   => 0,
        schema  => ['str*' => {match => $re_user}],
        summary => 'User (login) name',
    },
    encpass => {
        index   => 1,
        schema  => ['str*' => {match => $re_field}],
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
        schema  => ['str*' => {match => $re_field}],
        summary => 'This field is reserved for future use',
    }
);
my @shadow_field_names;
for (keys %shadow_fields) {
    $shadow_field_names[$shadow_fields{$_}{index}] = $_;
    delete $shadow_fields{$_}{index};
}

my %group_fields = (
    group => {
        index   => 0,
        schema  => ['str*' => {match => $re_group}],
        summary => 'Group name',
    },
    pass => {
        index   => 1,
        schema  => ['str*' => {match => $re_field}],
        summary => 'Password, generally should be "x" which means password is '.
            'encrypted in gshadow',
    },
    gid => {
        index   => 2,
        schema  => 'int*',
        summary => 'Numeric group ID',
    },
    members => {
        index   => 3,
        schema  => ['str*' => {match => $re_field}],
        summary => 'List of usernames that are members of this group, '.
            'separated by commas',
    },
);
my @group_field_names;
for (keys %group_fields) {
    $group_field_names[$group_fields{$_}{index}] = $_;
    delete $group_fields{$_}{index};
}

my %gshadow_fields = (
    group => {
        index   => 0,
        schema  => ['str*' => {match => $re_group}],
        summary => 'Group name',
    },
    encpass => {
        index => 1,
        schema  => ['str*' => {match=> $re_field}],
        summary => 'Encrypted password',
    },
    admins => {
        index => 2,
        schema  => ['str*' => {match => $re_field}],
        summary => 'It must be a comma-separated list of user names, or empty',
    },
    members => {
        index => 3,
        schema  => ['str*' => {match => $re_field}],
        summary => 'List of usernames that are members of this group, '.
            'separated by commas; You should use the same list of users as in '.
                '/etc/group.',
    },
);
my @gshadow_field_names;
for (keys %gshadow_fields) {
    $gshadow_field_names[$gshadow_fields{$_}{index}] = $_;
    delete $gshadow_fields{$_}{index};
}

sub _backup {
    my ($fh, $path) = @_;
    seek $fh, 0, 0 or return [500, "Can't seek: $!"];
    open my($bak), ">", "$path.bak" or return [500, "Can't open $path.bak: $!"];
    while (<$fh>) { print $bak $_ }
    close $bak or return [500, "Can't write $path.bak: $!"];
    # XXX set ctime & mtime of backup file?
    [200];
}

# all public functions in this module uses the _routine, which contains the
# basic flow, to avoid duplication of code. _routine accept these special
# arguments for flow control:
#
# - _read_shadow   = 0*/1/2 (2 means optional, don't exit if fail)
# - _read_passwd   = 0*/1
# - _read_gshadow  = 0*/1/2 (2 means optional, don't exit if fail)
# - _read_group    = 0*/1
# - _lock          = 0*/1 (whether to lock)
# - _after_read    = code (executed after reading all passwd/group files)
# - _after_read_passwd_entry = code (executed after reading a line in passwd)
# - _after_read_group_entry = code (executed after reading a line in group)
# - _write_shadow  = 0*/1
# - _write_passwd  = 0*/1
# - _write_gshadow = 0*/1
# - _write_group   = 0*/1
#
# all the hooks are fed $stash, sort of like a bag or object containing all
# data. should return enveloped response. _routine will return with response if
# response is non success. _routine will also return immediately if $stash{exit}
# is set.
#
# to write, we open once but with mode +< instead of <. we read first then we
# seek back to beginning and write from in-memory data. if
# $stash{write_passwd} and so on is set to false, routine cancel the write
# (can be used e.g. when there is no change so no need to write).
#
# final result is in $stash{res} or non-success result returned by hook.
sub _routine {
    my %args = @_;

    my $etc     = $args{etc_dir} // "/etc";
    my $detail  = $args{detail};
    my $wfn     = $args{with_field_names} // 1;
    my $locked;
    my ($fhp, $fhs, $fhg, $fhgs);
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
        my %shadow;
        my @shadowh;
        $stash{shadow}   = \@shadow;
        $stash{shadowh}  = \@shadowh;
        if ($args{_read_shadow} || $args{_write_shadow}) {
            unless (open $fhs, ($args{_write_shadow} ? "+":"")."<",
                    "$etc/shadow") {
                if ($args{_read_shadow} == 2 && !$args{_write_shadow}) {
                    goto L1;
                } else {
                    return [500, "Can't open $etc/shadow: $!"];
                }
            }
            while (<$fhs>) {
                chomp;
                next unless /\S/; # skip empty line
                my @r = split /:/, $_, scalar(keys %shadow_fields);
                push @shadow, \@r;
                $shadow{$r[0]} = \@r;
                if ($wfn) {
                    my %r;
                    @r{@shadow_field_names} = @r;
                    push @shadowh, \%r;
                }
            }
        }

      L1:
        my @passwd;
        my @passwdh;
        $stash{passwd}   = \@passwd;
        $stash{passwdh}  = \@passwdh;
        if ($args{_read_passwd} || $args{_write_passwd}) {
            open $fhp, ($args{_write_passwd} ? "+":"")."<", "$etc/passwd"
                or return [500, "Can't open $etc/passwd: $!"];
            while (<$fhp>) {
                chomp;
                next unless /\S/; # skip empty line
                my @r = split /:/, $_, scalar(keys %passwd_fields);
                push @passwd, \@r;
                if ($wfn) {
                    my %r;
                    @r{@shadow_field_names} = @{ $shadow{$r[0]} }
                        if $shadow{$r[0]};
                    @r{@passwd_field_names} = @r;
                    push @passwdh, \%r;
                }
                if ($args{_after_read_passwd_entry}) {
                    my $res = $args{_after_read_passwd_entry}->(\%stash);
                    return $res if $res->[0] != 200;
                    return if $stash{exit};
                }
            }
        }

        my @gshadow;
        my %gshadow;
        my @gshadowh;
        $stash{gshadow}  = \@gshadow;
        $stash{gshadowh} = \@gshadowh;
        if ($args{_read_gshadow} || $args{_write_gshadow}) {
            unless (open $fhgs, ($args{_write_gshadow} ? "+":"")."<",
                    "$etc/gshadow") {
                if ($args{_read_gshadow} == 2 && !$args{_write_gshadow}) {
                    goto L2;
                } else {
                    return [500, "Can't open $etc/gshadow: $!"];
                }
            }
            while (<$fhgs>) {
                chomp;
                next unless /\S/; # skip empty line
                my @r = split /:/, $_, scalar(keys %gshadow_fields);
                push @gshadow, \@r;
                $gshadow{$r[0]} = \@r;
                if ($wfn) {
                    my %r;
                    @r{@gshadow_field_names} = @r;
                    push @gshadowh, \%r;
                }
            }
        }

      L2:
        my @group;
        my @grouph;
        $stash{group}    = \@group;
        $stash{grouph}   = \@grouph;
        if ($args{_read_group} || $args{_write_group}) {
            open $fhg, ($args{_write_group} ? "+":"")."<",
                "$etc/group"
                    or return [500, "Can't open $etc/group: $!"];
            while (<$fhg>) {
                chomp;
                next unless /\S/; # skip empty line
                my @r = split /:/, $_, scalar(keys %group_fields);
                push @group, \@r;
                if ($wfn) {
                    my %r;
                    @r{@gshadow_field_names} = @{ $gshadow{$r[0]} }
                        if $gshadow{$r[0]};
                    @r{@group_field_names}   = @r;
                    push @grouph, \%r;
                }
                if ($args{_after_read_group_entry}) {
                    my $res = $args{_after_read_group_entry}->(\%stash);
                    return $res if $res->[0] != 200;
                    return if $stash{exit};
                }
            }
        }

        if ($args{_after_read}) {
            my $res = $args{_after_read}->(\%stash);
            return $res if $res->[0] != 200;
            return if $stash{exit};
        }

        # write files

        if ($args{_write_shadow} && ($stash{write_shadow}//1)) {
            if ($args{backup}) {
                my $res = _backup($fhs, "$etc/shadow");
                return $res if $res->[0] != 200;
            }
            seek $fhs, 0, 0 or return [500, "Can't seek in $etc/shadow: $!"];
            for (@shadow) {
                print $fhs join(":", map {$_//""} @$_), "\n";
            }
            truncate $fhs, tell($fhs);
            close $fhs or return [500, "Can't close $etc/shadow: $!"];
            chmod 0640, "$etc/shadow"; # check error?
        }

        if ($args{_write_passwd} && ($stash{write_passwd}//1)) {
            if ($args{backup}) {
                my $res = _backup($fhp, "$etc/passwd");
                return $res if $res->[0] != 200;
            }
            seek $fhp, 0, 0 or return [500, "Can't seek in $etc/passwd: $!"];
            for (@passwd) {
                print $fhp join(":", map {$_//""} @$_), "\n";
            }
            truncate $fhp, tell($fhp);
            close $fhp or return [500, "Can't close $etc/passwd: $!"];
            chmod 0644, "$etc/passwd"; # check error?
        }

        if ($args{_write_gshadow} && ($stash{write_gshadow}//1)) {
            if ($args{backup}) {
                my $res = _backup($fhgs, "$etc/gshadow");
                return $res if $res->[0] != 200;
            }
            seek $fhgs, 0, 0 or return [500, "Can't seek in $etc/gshadow: $!"];
            for (@gshadow) {
                print $fhgs join(":", map {$_//""} @$_), "\n";
            }
            truncate $fhgs, tell($fhgs);
            close $fhgs or return [500, "Can't close $etc/gshadow: $!"];
            chmod 0640, "$etc/gshadow"; # check error?
        }

        if ($args{_write_group} && ($stash{write_group}//1)) {
            if ($args{backup}) {
                my $res = _backup($fhg, "$etc/group");
                return $res if $res->[0] != 200;
            }
            seek $fhg, 0, 0 or return [500, "Can't seek in $etc/group: $!"];
            for (@group) {
                print $fhg join(":", map {$_//""} @$_), "\n";
            }
            truncate $fhg, tell($fhg);
            close $fhg or return [500, "Can't close $etc/group: $!"];
            chmod 0644, "$etc/group"; # check error?
        }

        [200, "OK"];
    }; # eval
    $e = [500, "Died: $@"] if $@;

    if ($locked) {
        unlock("$etc/passwd.lock");
    }

    $stash{res} //= $e if $e && $e->[0] != 200;
    $stash{res} //= $e if $e && $e->[0] != 200;
    $stash{res} //= [500, "BUG: res not set"];

    $stash{res};
}

$SPEC{list_users} = {
    v => 1.1,
    summary => 'List Unix users in passwd file',
    args => {
        %common_args,
        detail => {
            summary => 'If true, return all fields instead of just usernames',
            schema => ['bool' => {default => 0}],
        },
        with_field_names => {
            summary => 'If false, don\'t return hash for each entry',
            schema => [bool => {default=>1}],
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
        %args,
        _read_passwd     => 1,
        _read_shadow     => $detail ? 2:0,
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
            [200];
        },
    );
}

$SPEC{get_user} = {
    v => 1.1,
    summary => 'Get user details by username or uid',
    description => <<'_',

Either `user` OR `uid` must be specified.

The function is not dissimilar to Unix's `getpwnam()` or `getpwuid()`.

_
    args => {
        %common_args,
        user => {
            schema => 'str*',
        },
        uid => {
            schema => 'int*',
        },
        with_field_names => {
            summary => 'If false, don\'t return hash',
            schema => [bool => {default=>1}],
            description => <<'_',

By default, a hashref is returned containing field names and its values, e.g.
`{user=>"neil", pass=>"x", uid=>500, ...}`. With `with_field_names=>0`, an
arrayref is returned instead: `["neil", "x", 500, ...]`.

_
        },
    },
};
sub get_user {
    my %args = @_;
    my $wfn  = $args{with_field_names} // 1;
    my $user = $args{user};
    my $uid  = $args{uid};
    return [400, "Please specify user OR uid"]
        unless defined($user) xor defined($uid);

    _routine(
        %args,
        _read_passwd     => 1,
        _read_shadow     => 2,
        with_field_names => $wfn,
        detail           => 1,
        _after_read_passwd_entry => sub {
            my $stash = shift;

            my @rows;
            my $passwd  = $stash->{passwd};
            my $passwdh = $stash->{passwdh};

            if (defined($user) && $passwd->[-1][0] eq $user ||
                    defined($uid) && $passwd->[-1][2] == $uid) {
                $stash->{res} = [200,"OK", $wfn ? $passwdh->[-1]:$passwd->[-1]];
                $stash->{exit}++;
            }
            [200];
        },
        _after_read => sub {
            my $stash = shift;
            [404, "Not found"];
        },
    );
}

$SPEC{list_groups} = {
    v => 1.1,
    summary => 'List Unix groups in group file',
    args => {
        %common_args,
        detail => {
            summary => 'If true, return all fields instead of just group names',
            schema => ['bool' => {default => 0}],
        },
        with_field_names => {
            summary => 'If false, don\'t return hash for each entry',
            schema => [bool => {default=>1}],
            description => <<'_',

By default, when `detail=>1`, a hashref is returned for each entry containing
field names and its values, e.g. `{group=>"neil", pass=>"x", gid=>500, ...}`.
With `with_field_names=>0`, an arrayref is returned instead: `["neil", "x", 500,
...]`.

_
        },
    },
};
sub list_groups {
    my %args = @_;
    my $detail = $args{detail};
    my $wfn    = $args{with_field_names} // ($detail ? 1:0);

    _routine(
        %args,
        _read_group      => 1,
        _read_gshadow    => $detail ? 2:0,
        with_field_names => $wfn,
        _after_read      => sub {
            my $stash = shift;

            my @rows;
            my $group    = $stash->{group};
            my $grouph   = $stash->{grouph};

            for (my $i=0; $i < @$group; $i++) {
                if (!$detail) {
                    push @rows, $group->[$i][0];
                } elsif ($wfn) {
                    push @rows, $grouph->[$i];
                } else {
                    push @rows, $group->[$i];
                }
            }

            $stash->{res} = [200, "OK", \@rows];

            $stash->{exit}++;
            [200];
        },
    );
}

$SPEC{get_group} = {
    v => 1.1,
    summary => 'Get group details by group name or gid',
    description => <<'_',

Either `group` OR `gid` must be specified.

The function is not dissimilar to Unix's `getgrnam()` or `getgrgid()`.

_
    args => {
        %common_args,
        group => {
            schema => 'str*',
        },
        gid => {
            schema => 'int*',
        },
        with_field_names => {
            summary => 'If false, don\'t return hash',
            schema => [bool => {default=>1}],
            description => <<'_',

By default, a hashref is returned containing field names and its values, e.g.
`{group=>"neil", pass=>"x", gid=>500, ...}`. With `with_field_names=>0`, an
arrayref is returned instead: `["neil", "x", 500, ...]`.

_
        },
    },
};
sub get_group {
    my %args  = @_;
    my $wfn   = $args{with_field_names} // 1;
    my $gn    = $args{group};
    my $gid   = $args{gid};
    return [400, "Please specify group OR gid"]
        unless defined($gn) xor defined($gid);

    _routine(
        %args,
        _read_group      => 1,
        _read_gshadow    => 2,
        with_field_names => $wfn,
        detail           => 1,
        _after_read_group_entry => sub {
            my $stash = shift;

            my @rows;
            my $group  = $stash->{group};
            my $grouph = $stash->{grouph};

            if (defined($gn) && $group->[-1][0] eq $gn ||
                    defined($gid) && $group->[-1][2] == $gid) {
                $stash->{res} = [200,"OK", $wfn ? $grouph->[-1]:$group->[-1]];
                $stash->{exit}++;
            }
            [200];
        },
        _after_read => sub {
            my $stash = shift;
            [404, "Not found"];
        },
    );
}

$SPEC{get_max_uid} = {
    v => 1.1,
    summary => 'Get maximum UID used',
    args => {
        %common_args,
    },
};
sub get_max_uid {
    my %args  = @_;
    _routine(
        %args,
        _read_passwd     => 1,
        detail           => 0,
        with_field_names => 0,
        _after_read      => sub {
            my $stash = shift;
            my $passwd = $stash->{passwd};
            $stash->{res} = [200, "OK", max(
                map {$_->[2]} @$passwd
            )];
            $stash->{exit}++;
            [200];
        },
    );
}

$SPEC{get_max_gid} = {
    v => 1.1,
    summary => 'Get maximum GID used',
    args => {
        %common_args,
    },
};
sub get_max_gid {
    require List::Util;

    my %args  = @_;
    _routine(
        %args,
        _read_group      => 1,
        detail           => 0,
        with_field_names => 0,
        _after_read      => sub {
            my $stash = shift;
            my $group = $stash->{group};
            $stash->{res} = [200, "OK", List::Util::max(
                map {$_->[2]} @$group
            )];
            $stash->{exit}++;
            [200];
        },
    );
}

sub _enc_pass {
    require UUID::Random;
    require Digest::MD5;

    my $pass = shift;
    my $salt = substr(Digest::MD5::md5_base64(UUID::Random::generate()), 0, 8);
    crypt($pass, '$6$'.$salt.'$');
}

sub _add_group_or_user {
    my ($which, %args) = @_;

    # TMP,schema
    my ($user, $gn);
    if ($which eq 'user') {
        $user = $args{user} or return [400, "Please specify user"];
        $user =~ $re_user or return [400, "Invalid user, please use $re_user"];
        $gn = $user;
    }
    $gn //= $args{group};
    $gn or return [400, "Please specify group"];
    $gn =~ $re_group or return [400, "Invalid group, please use $re_group"];

    my $gid     = $args{gid};
    my $min_gid = $args{min_gid} // 1000;
    my $max_gid = $args{max_gid} // 65535;
    my $members;
    if ($which eq 'group') {
        $members = $args{members};
        if ($members && ref($members) eq 'ARRAY') {
            $members = join(",",@$members);
        }
        $members //= "";
        $members =~ $re_field
            or return [400, "Invalid members, please use $re_field"];
    } else {
        $members = "$user";
    }

    my ($uid, $min_uid, $max_uid);
    my ($pass, $gecos, $home, $shell);
    my ($encpass, $last_pwchange, $min_pass_age, $max_pass_age,
        $pass_warn_period, $pass_inactive_period, $expire_date);
    if ($which eq 'user') {
        $uid = $args{uid};
        $min_uid = $args{min_uid} // 1000;
        $max_uid = $args{max_uid} // 65535;

        $pass = $args{pass} // "";
        if ($pass !~ $re_field) { return [400, "Invalid pass"] }

        $gecos = $args{gecos} // "";
        if ($gecos !~ $re_field) { return [400, "Invalid gecos"] }

        $home = $args{home} // "";
        if ($home !~ $re_field) { return [400, "Invalid home"] }

        $shell = $args{shell} // "";
        if ($shell !~ $re_field) { return [400, "Invalid shell"] }

        $encpass = $args{encpass} // ($pass eq '' ? '*' : _enc_pass($pass));
        if ($encpass !~ $re_field) { return [400, "Invalid encpass"] }

        $last_pwchange = int($args{last_pwchange} // time()/86400);
        $min_pass_age  = int($args{min_pass_age} // 0);
        $max_pass_age  = int($args{max_pass_age} // 99999);
        $pass_warn_period = int($args{max_pass_age} // 7);
        $pass_inactive_period = $args{pass_inactive_period} // "";
        if ($pass_inactive_period !~ $re_field) {
            return [400, "Invalid pass_inactive_period"] }
        $expire_date = $args{expire_date} // "";
        if ($expire_date !~ $re_field) { return [400, "Invalid expire_date"] }
    }

    _routine(
        %args,
        _lock            => 1,
        _write_group     => 1,
        _write_gshadow   => 1,
        _write_passwd    => $which eq 'user',
        _write_shadow    => $which eq 'user',
        _after_read      => sub {
            my $stash = shift;

            my $group   = $stash->{group};
            my $gshadow = $stash->{gshadow};
            return [412, "Group $gn already exists"]
                if first { $_->[0] eq $gn } @$group;
            my @gids = map { $_->[2] } @$group;
            if (defined $gid) {
                return [412, "GID $gid already exists"] if $gid ~~ @gids;
            } else {
                for ($min_gid .. $max_gid) {
                    do { $gid = $_; last } unless $_ ~~ @gids;
                }
                return [412, "Can't find available GID"] unless defined($gid);
            }
            my $r = {gid=>$gid};
            push @$group  , [$gn, "x", $gid, $members];
            push @$gshadow, [$gn, "*", "", $members];

            if ($which eq 'user') {
                my $passwd  = $stash->{passwd};
                my $shadow  = $stash->{shadow};
                return [412, "User $gn already exists"]
                    if first { $_->[0] eq $user } @$passwd;
                my @uids = map { $_->[2] } @$passwd;
                if (defined $uid) {
                    return [412, "UID $gid already exists"] if $uid ~~ @uids;
                } else {
                    for ($min_uid .. $max_uid) {
                        do { $uid = $_; last } unless $_ ~~ @uids;
                    }
                    return [412, "Can't find available UID"]
                        unless defined($uid);
                }
                $r->{uid} = $uid;
                push @$passwd, [$user, "x", $uid, $gid, $gecos, $home, $shell];
                push @$shadow, [$user, $encpass, $last_pwchange, $min_pass_age,
                                $max_pass_age, $pass_warn_period,
                                $pass_inactive_period, $expire_date, ""];
            }

            $stash->{res} = [200, "OK", $r];
            [200];
        },
    );
}

$SPEC{add_group} = {
    v => 1.1,
    summary => 'Add a new group',
    args => {
        %common_args,
        %write_args,
        group => {
            req => 1,
        },
        gid => {
            summary => 'Pick a specific new GID',
            req => 0,
        },
        min_gid => {
            summary => 'Pick a range for new GID',
            req => 0,
        },
        max_gid => {
            summary => 'Pick a range for new GID',
            req => 0,
        },
        members => {
            summary => 'Fill initial members',
            req => 0,
        },
    },
};
sub add_group {
    _add_group_or_user('group', @_);
}

$SPEC{add_user} = {
    v => 1.1,
    summary => 'Add a new user',
    args => {
        %common_args,
        %write_args,
        group => {
            req => 1,
        },
        gid => {
            summary => 'Pick a specific new GID',
            req => 0,
        },
        min_gid => {
            summary => 'Pick a range for new GID',
            req => 0,
        },
        max_gid => {
            summary => 'Pick a range for new GID',
            req => 0,
        },
        uid => {
            summary => 'Pick a specific new UID',
            req => 0,
        },
        min_uid => {
            summary => 'Pick a range for new UID',
            req => 0,
        },
        max_uid => {
            summary => 'Pick a range for new UID',
            req => 0,
        },
        map( {($_=>$passwd_fields{$_})} qw/pass gecos home shell/),
        map( {($_=>$shadow_fields{$_})}
                 qw/encpass last_pwchange min_pass_age max_pass_age
                   pass_warn_period pass_inactive_period expire_date/),
    },
};
sub add_user {
    _add_group_or_user('user', @_);
}

sub _modify_group_or_user {
    my ($which, %args) = @_;

    # TMP,schema
    my ($user, $gn);
    if ($which eq 'user') {
        $user = $args{user} or return [400, "Please specify user"];
    } else {
        $gn = $args{group} or return [400, "Please specify group"];
    }

    if ($which eq 'user') {
        if (defined($args{uid}) && $args{uid} !~ $re_posint) {
            return [400, "Invalid uid"] }
        if (defined($args{gid}) && $args{gid} !~ $re_posint) {
            return [400, "Invalid gid"] }
        if (defined($args{gecos}) && $args{gecos} !~ $re_field) {
            return [400, "Invalid gecos"] }
        if (defined($args{home}) && $args{home} !~ $re_field) {
            return [400, "Invalid home"] }
        if (defined($args{shell}) && $args{shell} !~ $re_field) {
            return [400, "Invalid shell"] }
        if (defined $args{pass}) {
            $args{encpass} = $args{pass} eq '' ? '*' : _enc_pass($args{pass});
            $args{pass} = "x";
        }
        if (defined($args{encpass}) && $args{encpass} !~ $re_field) {
            return [400, "Invalid encpass"] }
        if (defined($args{last_pwchange}) && $args{last_pwchange} !~ $re_posint) {
            return [400, "Invalid last_pwchange"] }
        if (defined($args{min_pass_age}) && $args{min_pass_age} !~ $re_posint) {
            return [400, "Invalid min_pass_age"] }
        if (defined($args{max_pass_age}) && $args{max_pass_age} !~ $re_posint) {
            return [400, "Invalid max_pass_age"] }
        if (defined($args{pass_warn_period}) && $args{pass_warn_period} !~ $re_posint) {
            return [400, "Invalid pass_warn_period"] }
        if (defined($args{pass_inactive_period}) &&
                $args{pass_inactive_period} !~ $re_posint) {
            return [400, "Invalid pass_inactive_period"] }
        if (defined($args{expire_date}) && $args{expire_date} !~ $re_posint) {
            return [400, "Invalid expire_date"] }
    }

    my ($gid, $members);
    if ($which eq 'group') {
        if (defined($args{gid}) && $args{gid} !~ $re_posint) {
            return [400, "Invalid gid"] }
        if (defined $args{pass}) {
            $args{encpass} = $args{pass} eq '' ? '*' : _enc_pass($args{pass});
            $args{pass} = "x";
        }
        if (defined($args{encpass}) && $args{encpass} !~ $re_field) {
            return [400, "Invalid encpass"] }
        if (defined $args{members}) {
            if (ref($args{members}) eq 'ARRAY') { $args{members} = join(",",@{$args{members}}) }
            $args{members} =~ $re_field or return [400, "Invalid members"];
        }
        if (defined $args{admins}) {
            if (ref($args{admins}) eq 'ARRAY') { $args{admins} = join(",",@{$args{admins}}) }
            $args{admins} =~ $re_field or return [400, "Invalid admins"];
        }
    }

    _routine(
        %args,
        _lock            => 1,
        _write_group     => $which eq 'group',
        _write_gshadow   => $which eq 'group',
        _write_passwd    => $which eq 'user',
        _write_shadow    => $which eq 'user',
        _after_read      => sub {
            my $stash = shift;

            my ($found, $changed);
            if ($which eq 'user') {
                my $passwd = $stash->{passwd};
                for my $l (@$passwd) {
                    next unless $l->[0] eq $user;
                    $found++;
                    for my $f (qw/pass uid gid gecos home shell/) {
                        if (defined $args{$f}) {
                            my $idx = firstidx {$_ eq $f} @passwd_field_names;
                            $l->[$idx] = $args{$f};
                            $changed++;
                        }
                    }
                    last;
                }
                return [404, "Not found"] unless $found;
                $stash->{write_passwd} = 0 unless $changed;

                $changed = 0;
                my $shadow = $stash->{shadow};
                for my $l (@$shadow) {
                    next unless $l->[0] eq $user;
                    for my $f (qw/encpass last_pwchange min_pass_age max_pass_age
                                  pass_warn_period pass_inactive_period expire_date/) {
                        if (defined $args{$f}) {
                            my $idx = firstidx {$_ eq $f} @shadow_field_names;
                            $l->[$idx] = $args{$f};
                            $changed++;
                        }
                    }
                    last;
                }
                $stash->{write_shadow} = 0 unless $changed;
            } else {
                my $group = $stash->{group};
                for my $l (@$group) {
                    next unless $l->[0] eq $gn;
                    $found++;
                    for my $f (qw/pass gid members/) {
                        if (defined $args{$f}) {
                            my $idx = firstidx {$_ eq $f} @group_field_names;
                            $l->[$idx] = $args{$f};
                            $changed++;
                        }
                    }
                    last;
                }
                return [404, "Not found"] unless $found;
                $stash->{write_group} = 0 unless $changed;

                $changed = 0;
                my $gshadow = $stash->{gshadow};
                for my $l (@$gshadow) {
                    next unless $l->[0] eq $gn;
                    for my $f (qw/encpass admins members/) {
                        if (defined $args{$f}) {
                            my $idx = firstidx {$_ eq $f} @gshadow_field_names;
                            $l->[$idx] = $args{$f};
                            $changed++;
                        }
                    }
                    last;
                }
                $stash->{write_gshadow} = 0 unless $changed;
            }
            $stash->{res} = [200, "OK"];
            [200];
        },
    );
}

$SPEC{modify_group} = {
    v => 1.1,
    summary => 'Modify an existing group',
    description => <<'_',

Specify arguments to modify corresponding fields. Unspecified fields will not be
modified.

_
    args => {
        %common_args,
        %write_args,
        map( {($_=>$group_fields{$_})} qw/group pass gid members/),
        map( {($_=>$gshadow_fields{$_})}
                 qw/encpass admins/),
    },
};
sub modify_group {
    _modify_group_or_user('group', @_);
}

$SPEC{modify_user} = {
    v => 1.1,
    summary => 'Modify an existing user',
    description => <<'_',

Specify arguments to modify corresponding fields. Unspecified fields will not be
modified.

_
    args => {
        %common_args,
        %write_args,
        map( {($_=>$passwd_fields{$_})} qw/user pass uid gid gecos home shell/),
        map( {($_=>$shadow_fields{$_})}
                 qw/encpass last_pwchange min_pass_age max_pass_age
                   pass_warn_period pass_inactive_period expire_date/),
    },
};
sub modify_user {
    _modify_group_or_user('user', @_);
}

sub _delete_group_or_user {
    my ($which, %args) = @_;

    # TMP,schema
    my ($user, $gn);
    if ($which eq 'user') {
        $user = $args{user} or return [400, "Please specify user"];
        $gn = $user;
    }
    $gn //= $args{group};
    $gn or return [400, "Please specify group"];

    _routine(
        %args,
        _lock            => 1,
        _write_group     => 1,
        _write_gshadow   => 1,
        _write_passwd    => $which eq 'user',
        _write_shadow    => $which eq 'user',
        _after_read      => sub {
            my $stash = shift;
            my ($i, $changed);

            my $group = $stash->{group};
            $changed = 0; $i = 0;
            while ($i < @$group) {
                if ($which eq 'user') {
                    # also delete all mention of the user in any group
                    my @mm = split /,/, $group->[$i][3];
                    if ($user ~~ @mm) {
                        $changed++;
                        $group->[$i][3] = join(",", grep {$_ ne $user} @mm);
                    }
                }
                if ($group->[$i][0] eq $gn) {
                    $changed++;
                    splice @$group, $i, 1; $i--;
                }
                $i++;
            }
            $stash->{write_group} = 0 unless $changed;

            my $gshadow = $stash->{gshadow};
            $changed = 0; $i = 0;
            while ($i < @$gshadow) {
                if ($which eq 'user') {
                    # also delete all mention of the user in any group
                    my @mm = split /,/, $gshadow->[$i][3];
                    if ($user ~~ @mm) {
                        $changed++;
                        $gshadow->[$i][3] = join(",", grep {$_ ne $user} @mm);
                    }
                }
                if ($gshadow->[$i][0] eq $gn) {
                    $changed++;
                    splice @$gshadow, $i, 1; $i--;
                    last;
                }
                $i++;
            }
            $stash->{write_gshadow} = 0 unless $changed;

            if ($which eq 'user') {
                my $passwd = $stash->{passwd};
                $changed = 0; $i = 0;
                while ($i < @$passwd) {
                    if ($passwd->[$i][0] eq $user) {
                        $changed++;
                        splice @$passwd, $i, 1; $i--;
                        last;
                    }
                    $i++;
                }
                $stash->{write_passwd} = 0 unless $changed;

                my $shadow = $stash->{shadow};
                $changed = 0; $i = 0;
                while ($i < @$shadow) {
                    if ($shadow->[$i][0] eq $user) {
                        $changed++;
                        splice @$shadow, $i, 1; $i--;
                        last;
                    }
                    $i++;
                }
                $stash->{write_shadow} = 0 unless $changed;
            }

            $stash->{res} = [200, "OK"];
            [200];
        },
    );
}

$SPEC{delete_group} = {
    v => 1.1,
    summary => 'Delete a group',
    args => {
        %common_args,
        %write_args,
        group => {
            req => 1,
        },
    },
};
sub delete_group {
    _delete_group_or_user('group', @_);
}

$SPEC{delete_user} = {
    v => 1.1,
    summary => 'Delete a user',
    args => {
        %common_args,
        %write_args,
        user => {
            req => 1,
        },
    },
};
sub delete_user {
    _delete_group_or_user('user', @_);
}

1;
# ABSTRACT: Manipulate /etc/{passwd,shadow,group,gshadow} entries

=head1 SYNOPSIS

 use Unix::Passwd::Files;

 # by default uses files in /etc (/etc/passwd, /etc/shadow, et al)
 my $res = list_users(); # [200, "OK", ["root", ...]]

 # change location of files, return details
 $res = list_users(etc_dir=>"/some/path", detail=>1);
     # [200, "OK", [{user=>"root", uid=>0, ...}, ...]]

 # also return detail, but return array entries instead of hash
 $res = list_users(detail=>1, with_field_names=>0);
     # [200, "OK", [["root", "x", 0, ...], ...]]

 # getting user/group
 $res = get_group(user=>"buzz"); # [200, "OK", {user=>"buzz", uid=>501, ...}]
 $res = get_user(user=>"neil");  # [404, "Not found"]

 # adding user/group, by default adding user will also add a group with the same
 # name
 $res = add_user (user =>"steven", ...); # [200, "OK", {uid=>540, gid=>541}]
 $res = add_group(group=>"steven", ...); # [412, "Group already exists"]

 # modify user/group
 $res = modify_user(user=>"steven", home=>"/newhome/steven"); # [200, "OK"]
 $res = modify_group(group=>"neil"); # [404, "Not found"]

 # deleting user will also delete user's group
 $res = delete_user(user=>"neil");

 # change user password
 $res = set_user_password(user=>"steven", pass=>"foobar");

 # add/delete user to/from group
 $res = add_user_to_group(user=>"steven", group=>"wheel");
 $res = delete_user_from_group(user=>"steven", group=>"wheel");

 # others
 $res = get_max_uid();
 $res = get_max_gid();


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
