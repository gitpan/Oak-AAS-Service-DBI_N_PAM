package Oak::AAS::Service::DBI_N_PAM;

use base qw(Oak::AAS::Service);
use Oak::IO::DBI;
use Error qw(:try);
use Authen::PAM qw(:constants);
use strict;

=head1 NAME

Oak::AAS::Service::DBI_N_PAM - Class that defines the logic of how to use the DBI_N_PAM service.

=head1 HIERARCHY

L<Oak::Object|Oak::Object>

L<Oak::AAS::Service|Oak::AAS::Service>

L<Oak::AAS::Service|Oak::AAS::Service::DBI_N_PAM>

=head1 DESCRIPTION

This is the base class for all the AAS services. This class describes the functionality of any
service.

=head1 METHODS

=over

=item constructor($params)

Must create the object and store the params it needs to work. Must throw an error if something
goes wrong. The params must be a single string.

=back

=cut

sub constructor {
	my $self = shift;
	my $params=shift;
	my @kvs=split(m/;/, $params);
	foreach my $kv (@kvs) {
		my ($k,$v)=split(/=/,$kv);
		$self->{params}{$k}=$v;
	}
	$self->{params}{session_timeout}=3600;
	my $datasource="dbi:".$self->{params}{dbdriver}.":dbname=".$self->{params}{database}.";host=".$self->{params}{hostname};

	$self->{dbi}=new Oak::IO::DBI(
			RESTORE => {
				name=>"DBI_N_PAM_IO_DBI",
				datasource=>$datasource,
				username=>$self->{params}{username},
				password=>$self->{params}{dbpassword}
			}
		);
	# Authen::PAM is evil, it need the user! :(
}

=over

=item start_session(user,password)

Must start the session and return a unique id or false.

=back

=cut

sub start_session {
	my $self = shift;
	my $user = shift;
	my $password = shift;

	$self->_init_pam($user,$password);
	my $ret=$self->{pam}->pam_authenticate(0);
	return undef if($ret != &PAM_SUCCESS());

	my $sth=$self->{dbi}->do_sql("DELETE FROM aas_session WHERE login=".$self->{dbi}->quote($user));
	
	my $id=time.$$.int(rand(4096));

	my $ip=$self->{dbi}->quote(($ENV{HTTP_X_FORWARDED_FOR}||$ENV{REMOTE_ADDR}));
	$sth=$self->{dbi}->do_sql("INSERT INTO aas_session (login,id,last_access,ip) VALUES (".$self->{dbi}->quote($user).",".$self->{dbi}->quote($id).",".time.",$ip)");
	return undef if !$sth->rows;

	return $id;
}

=over

=item validate_session(user,sessionid)

Check if this is a valid session, return a boolean value (1=>success).

=back

=cut

sub validate_session {
	my $self = shift;
	my $user=shift;
	my $sid=shift;
	my $ip=$self->{dbi}->quote(($ENV{HTTP_X_FORWARDED_FOR}||$ENV{REMOTE_ADDR}));
	my $sql="SELECT * FROM aas_session WHERE id=".$self->{dbi}->quote($sid);
	$sql.=" AND login=".$self->{dbi}->quote($user);
	$sql.=" AND ip=".$self->{dbi}->quote($ip);

	if($self->{params}{session_timeout}) {
		$sql.=" AND last_access>".(time-$self->{params}{session_timeout});
	}
	my $sth=$self->{dbi}->do_sql($sql);

	if($sth->rows) {
		$sql="UPDATE aas_session SET last_access=".time." WHERE id=".$self->{dbi}->quote($sid);
		$self->{dbi}->do_sql($sql);
		return 1;
	}
	return 0;
}

=over

=item end_session(user,sessionid)

End this session

=back

=cut

sub end_session {
	my $self = shift;
	my $user=shift;
	my $sid=shift;

	$self->{dbi}->do_sql("DELETE FROM aas_session WHERE login=".$self->{dbi}->quote($user));
}

=over

=item is_allowed(user,uri)

Return a true value if this user have access to this uri false if not.

=back

=cut

sub is_allowed {
	my $self = shift;
	my $user=shift;
	my $uri=shift;

	my $sql="SELECT * FROM aas_user_perms  WHERE login=".$self->{dbi}->quote($user);
	$sql.=" AND uri LIKE ".$self->{dbi}->quote($uri.'%');
	my $sth=$self->{dbi}->do_sql($sql);
	return $sth->rows;
}

=over

=item is_allowed_group(group,uri)

Return a true value if this group have access to this uri false if not.

=back

=cut

sub is_allowed_group {
	my $self = shift;
	my $group=shift;
	my $uri=shift;
	my $sql="SELECT * FROM aas_group_perms WHERE group=".$self->{dbi}->quote($group);
	$sql.=" AND uri LIKE ".$self->{dbi}->quote($uri.'%');
	my $sth=$self->{dbi}->do_sql($sql);
	return $sth->rows;
}


=over

=item grant(user,uri)

Grant user the access to uri.

=back

=cut

sub grant {
	my $self = shift;
	my $user=$self->{dbi}->quote(shift);
	my $uri=$self->{dbi}->quote(shift);

	my $sql="INSERT INTO aas_user_perms (login,uri) VALUES ($user,$uri)";
	my $sth=$self->{dbi}->do_sql($sql);
	return $sth->rows;
}

=over

=item grant_group(group,uri)

Grant group the access to uri.

=back

=cut

sub grant_group {
	my $self = shift;
	my $group=$self->{dbi}->quote(shift);
	my $uri=$self->{dbi}->quote(shift);
	my $sql="INSERT INTO aas_group_perms (group,uri) VALUES ($group,$uri)";
	my $sth=$self->{dbi}->do_sql($sql);
	return $sth->rows;
}


=over

=item deny(user,uri)

Make the uri denied to the user

=back

=cut

sub deny {
	my $self = shift;
	my $user=$self->{dbi}->quote(shift);
	my $uri=$self->{dbi}->quote(shift);
	my $sql="DELETE FROM aas_user_perms WHERE login=$user AND uri=$uri";
	if($self->{dbi}->do_sql($sql)) {
		return 1;
	}
	return 0;
}

=over

=item deny_group(group,uri)

Make the uri denied to the group

=back

=cut

sub deny_group {
	my $self = shift;
	my $group=$self->{dbi}->quote(shift);
	my $uri=$self->{dbi}->quote(shift);
	my $sql="DELETE FROM aas_group_perms WHERE group=$group AND uri=$uri";
	if($self->{dbi}->do_sql($sql)) {
		return 1;
	}
	return 0;
}

=over

=item list_uri

return an array with the available uri

=back

=cut

sub list_uri {
	my $self = shift;
	die "Abstract method not implemented in ".ref $self;
}

sub _init_pam {
	my $self=shift;
	my $user=shift;
	my $pass=shift;
	$self->{pam}=new Authen::PAM($self->{params}{pam_service},$user,\&_pam_conv);
	$Oak::AAS::Service::DBI_N_PAM::user=$user;
	$Oak::AAS::Service::DBI_N_PAM::password=$pass;
}

sub _end_pam {
	my $self=shift;
	undef $self->{pam};
	delete $self->{pam};
}

sub _pam_conv {
	my @res;
	while ( @_ ) {
		my $code = shift;
		my $msg = shift;
		my $ans = "";

		$ans = $Oak::AAS::Service::DBI_N_PAM::user if ($code == PAM_PROMPT_ECHO_ON() );
		$ans = $Oak::AAS::Service::DBI_N_PAM::password if ($code == PAM_PROMPT_ECHO_OFF() );

		push @res, (PAM_SUCCESS(),$ans);
	}
	push @res, PAM_SUCCESS();
	return @res;
}

1;

__END__

=head1 COPYRIGHT

Copyright (c) 2003
Oktiva <http://www.oktiva.com.br>
All rights reserved.
This program is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.


=for nobody

CREATE TABLE aas_session (
	id varchar(255) NOT NULL DEFAULT "" PRIMARY KEY,
	login varchar(127) NOT NULL DEFAULT "" UNIQUE,
	last_access int UNSIGNED NOT NULL DEFAULT 0,
	ip varchar(255) NOT NULL DEFAULT ""
);

CREATE TABLE aas_user_perms (
	login varchar(127) NOT NULL DEFAULT "",
	uri varchar(255) NOT NULL DEFAULT "",
	PRIMARY KEY (login),
	UNIQUE KEY login_uri (login,uri)
);

CREATE TABLE aas_group_perms (
	login varchar(127) NOT NULL DEFAULT "",
	uri varchar(255) NOT NULL DEFAULT "",
	PRIMARY KEY (login),
	UNIQUE KEY login_uri (login,uri)
);


=cut
