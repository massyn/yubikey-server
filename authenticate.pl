#!/usr/bin/perl

use strict;
use DBI;
use CGI;
use Auth::Yubikey_Decrypter;
do "db.pl";

my $cgi = new CGI;

# == read the command line OTP if it was passed

my $otp = $cgi->param('otp');

print $cgi->header();

if($otp eq '')
{
	# if the OTP was blank, send a form to ask for it
	print $cgi->start_form();
	print $cgi->p('Enter the YubiKey token here');
	print $cgi->password_field('otp','',64,64);
	print $cgi->end_form();
}
else
{
	# confirm that it is infact modhex that we received
	$otp =~ s/[^cbdefghijklnrtuv]//g;	# we expect modhex, so remove anything else
	if(length($otp) != 44)
	{
		print "ERR_OTP_BADFORMAT";
		exit(0);
	}

	my $publicid = substr($otp,0,12);

	my ($host,$db,$user,$pass) = &dbconnect();
	my $dbh = DBI->connect("DBI:mysql:database=$db;host=$host",$user,$pass,{RaiseError => 0});
	my $sth = $dbh->prepare('select privateid,aeskey,session,counter,timestamp from tbl_yubikeys where publicid = ?');
	if($sth->execute($publicid))
	{
		my ($privateid,$aeskey,$session,$counter,$timestamp) = $sth->fetchrow_array();
		$sth->finish();

		&debug("From the database...");
		&debug("Private ID",$privateid);
		&debug("AES Key",$aeskey);
		&debug("Session",$session);
		&debug("Counter",$counter);
		&debug("Timestamp",$timestamp);

		# If we don't have it in the database, then it doesn't exist, and we fail
		if($privateid eq '' || $aeskey eq '')
		{
			print "ERR_UNKNOWN_TOKEN";
			exit(0);
		}

		# Now decrypt the contents using the AES key we have on file

        	my ($publicID,$secretid_hex,$counter_dec,$timestamp_dec,$session_use_dec,$random_dec,$crc_dec,$crc_ok) =
                	Auth::Yubikey_Decrypter::yubikey_decrypt($otp,$aeskey);

		&debug("From the decrypter");
        	&debug("publicID",$publicID);
        	&debug("Secret id",$secretid_hex);
        	&debug("Counter",$counter_dec);
        	&debug("Timestamp",$timestamp_dec);
        	&debug("Session",$session_use_dec);
        	&debug("Random",$random_dec);
        	&debug("crc",$crc_dec);
        	&debug("crc ok?",$crc_ok);

		if($privateid eq $secretid_hex && $crc_ok == 1)
		{
			if(($counter_dec > $counter) || ($counter_dec == $counter && $session_use_dec > $session && $timestamp_dec > $timestamp))
			{
				# update our session, counter and timestamp values, so this OTP can not be replayed
				if($dbh->do('update tbl_yubikeys set counter = ?, session = ?, timestamp = ? where publicid = ?',undef,$counter_dec,$session_use_dec,$timestamp_dec,$publicid))
				{
					print "OK\n";
				}
				else
				{
					print "ERR_UNKNOWN";
				}
			}
			else
			{
				print "ERR_REPLAYED_OTP\n";
			}
	}
	else
	{
		print "ERR_NOT_OK\n";
	}

				
	}
	else
	{
		print "ERR_UNKNOWN";
	}

	$dbh->disconnect();
}


sub debug
{
	my ($p,$v) = @_;
# Turn this on if you want to see how the decryption works... Don't leave it on.. that will be bad in a real world scenario
#	print "<p><font color=#FF0000>$p</font> : $v</p>\n";
}
