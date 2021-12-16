# replaceSSLcert.pl
# Borrowed from https://itsjustbytes.wordpress.com/2020/04/22/hp-ilo-4-certificate-upgrade-from-1024-bit-to-2048-bit/
# Author Unknown
#!/usr/bin/perl
 
use POSIX;
use Pod::Usage;
use Getopt::Long;
use Net::Domain qw(hostname hostfqdn hostdomain domainname);
use Socket;
use strict;
 
my %Options;
$Options{'title'} = "Local HP iLO SSL Cert Checker/Updater v1.3";
$Options{'CMDhponcfg'}="/sbin/hponcfg";
$Options{'CMDopenssl'}="/usr/bin/openssl";
$Options{'CMDgrep'}="/bin/grep";
$Options{'MinCertBit'}=2048;
$Options{'CurCertBit'}=0;
my $PID=$$;
my $WORKINGDIR="/tmp/${PID}_ilocert";
my $myCAkey="$WORKINGDIR/myCA.key";
my $myCApem="$WORKINGDIR/myCA.pem";
my $CRTpem="$WORKINGDIR/CRT.pem";
my $CSR_IN="$WORKINGDIR/csr.xml";
my $CSR_CHECK="$WORKINGDIR/csr.out";
my $ILOCERTCFG="$WORKINGDIR/ilocert.cfg";
my $ILOINFOFILE="$WORKINGDIR/hponcfg-a.txt";
my @ILOINFOLINES=();
my $ILOIP="";
my $ILODNSNAME="";
my $ILONAMEFROMDNS="";
my $ILODOMAINNAME="";
my $LOCALDOMAIN="";
my $ENVIRONMENT="OK";
my $CSR = <<'END_CSR';
<RIBCL VERSION="2.0">
<LOGIN USER_LOGIN = "USERID" PASSWORD = "PASSW0RD">
<RIB_INFO MODE="write">
<!-- Default -->
<!-- <CERTIFICATE_SIGNING_REQUEST/> -->
<!-- Custom CSR -->
<CERTIFICATE_SIGNING_REQUEST>
<!-- Change the following to match your needs -->
<CSR_STATE VALUE ="STATE"/>
<CSR_COUNTRY VALUE ="COUNTRY"/>
<CSR_LOCALITY VALUE ="LOCAL"/>
<CSR_ORGANIZATION VALUE ="COMPANY"/>
<CSR_ORGANIZATIONAL_UNIT VALUE ="ORG"/>
<CSR_COMMON_NAME VALUE ="VarFQDN"/>
</CERTIFICATE_SIGNING_REQUEST>
</RIB_INFO>
</LOGIN>
</RIBCL>
END_CSR
 
my $CERTCFGHEAD = <<'ENDHEAD';
<RIBCL VERSION="2.0">
<LOGIN USER_LOGIN = "USERID" PASSWORD = "PASSW0RD">
<RIB_INFO MODE = "write">
<IMPORT_CERTIFICATE>
ENDHEAD
 
my $CERTCFGTAIL = <<'ENDTAIL';
</IMPORT_CERTIFICATE>
<!-- The iLO will be reset after the certificate has been imported. -->
<MOD_GLOBAL_SETTINGS>
<ENFORCE_AES VALUE="Y"/>
<IPMI_DCMI_OVER_LAN_ENABLED VALUE="N"/>
</MOD_GLOBAL_SETTINGS>
<RESET_RIB/>
</RIB_INFO>
</LOGIN>
</RIBCL>
ENDTAIL
 
main_sub();
 
sub create_workingdir {
        if(-d $WORKINGDIR){
                print "Working Dir ($WORKINGDIR) already exists, something went terribly wrong\n" if $Options{'debug'};
                exit(1);
        }
        else
        {
                print "Creating working directory ($WORKINGDIR)\n" if $Options{'debug'};
                mkdir "$WORKINGDIR";
        }
}
 
sub remove_workingdir {
        if($Options{'noclean'})
        {
                print "No Clean Up Specified\n";
                print "Please inspect and clean up (if needed):\n";
                print "\t$WORKINGDIR\n";
        }
        if(-d $WORKINGDIR){
                print "Working Dir ($WORKINGDIR) exists, cleaning up and removing\n" if $Options{'debug'};
                unlink($CSR_IN) if !$Options{'noclean'};
                unlink($CSR_CHECK) if !$Options{'noclean'};
                unlink($CRTpem) if !$Options{'noclean'};
                unlink($ILOCERTCFG) if !$Options{'noclean'};
                unlink($ILOINFOFILE) if !$Options{'noclean'};
                unlink($myCAkey) if !$Options{'noclean'};
                unlink($myCApem) if !$Options{'noclean'};
                unlink("$WORKINGDIR/myCA.srl") if !$Options{'noclean'};
                rmdir "$WORKINGDIR" if !$Options{'noclean'};
        }
        else
        {
                print "Working directory ($WORKINGDIR) doesn't exist, something went terribly wrong\n" if $Options{'debug'};
                exit(1);
        }
}
 
sub check_args {
        my %options;
        my @arr;
        my $packaddr;
        my $addr;
        my $key;
        my $shortname;
        my $login;
        # Unfortunately, this appears to be the easiest way of getting the hostname
        # without resorting to forking another process
        $login = (getpwuid $>);
        die "must run as root" if $login ne 'root';
        @arr=POSIX::uname();
        $Options{'hostname'}=$arr[1];
 
        GetOptions(
                'help|h|?'          => \$options{'help'},
                'verbose|v'         => \$options{'verbose'},
#                'local'             => \$options{'local'},
#                'remote'            => \$options{'remote'},
#                'host=s'            => \$options{'ilohostname'},
                'check|c'           => \$options{'check'},
                'update|u'          => \$options{'update'},
                'debug|d'           => \$options{'debug'},
                'noclean'           => \$options{'noclean'},
                'minbits=s'         => \$options{'minbits'},
        );
 
        if($options{'help'})
        {
                usage();
                exit(0);
        }
 
        if(!$options{'check'} && !$options{'update'})
        {
                print "You must specify either check or update\n";
                usage();
                exit(1);
        }
 
        $Options{'noclean'}     = $options{'noclean'} if $options{'noclean'};
        $Options{'check'}       = $options{'check'}   if $options{'check'};
        $Options{'update'}      = $options{'update'}  if $options{'update'};
        $Options{'debug'}       = $options{'debug'}   if $options{'debug'};
        if($options{'minbits'} && int($options{'minbits'}) < $Options{'MinCertBit'})
        {
                print "What the heck are you smoking? $options{'minbits'} is less than the current minimum of $Options{'MinCertBit'}\n";
                exit(1);
        }
        $Options{'MinCertBit'} = int($options{'minbits'}) if $options{'minbits'};
 
        if($options{'update'})
        {
                $Options{'update'}=1;
                $Options{'check'}=1;
        }
}
 
sub get_host_ip {
        my $host=shift;
        my @arr;
        my ($addr,$packaddr);
 
        # Here we go, ugly way of getting the address
        @arr=gethostbyname($host);
        $packaddr=$arr[4];
        $addr=sprintf("%d.",unpack("C",substr($packaddr,0,1)));
        $addr=sprintf("%s%d.",$addr,unpack("C",substr($packaddr,1,1)));
        $addr=sprintf("%s%d.",$addr,unpack("C",substr($packaddr,2,1)));
        $addr=sprintf("%s%d",$addr,unpack("C",substr($packaddr,3,1)));
 
        return($addr);
}
 
sub usage {
        my $key;
 
        print "$Options{'title'}\n";
        print "\n";
        print "Usage: $0 [options]\n\n";
        print "Arguments:\n";
        print "\t--check             Check the iLO certificate\n";
        print "\t--update            Update the iLO certificate\n";
        print "\t--debug             Increase verbosity\n";
        print "\t--noclean           Do not clean up afterwards\n";
        print "\t--minbits length    Set Min Cert Bit Length\n";
        print "\n";
}
 
sub get_iloinfo {
 
        my $iloip;
        my $ilofqdnip;
        my $fqdn;
        my $iloinfocmd="$Options{'CMDhponcfg'} -a -w $ILOINFOFILE 2>&1 > /dev/null";
        my $x;
        my $tmpline;
        my $tmpaddr;
        my $tmpname;
 
        print "Pre Check/Update Info Gathering\n";
        print "\tGathering info from iLO: \n\t$iloinfocmd\n" if $Options{'debug'};
        print "\tGathering info from the local iLO\n" if ! $Options{'debug'};
 
        system($iloinfocmd);
 
        open(TEMP,$ILOINFOFILE);
        @ILOINFOLINES=<TEMP>;
        close(TEMP);
 
        for($x=0;$x<=$#ILOINFOLINES;$x++)
        {
#               print $ILOINFOLINES[$x];
                if($ILOINFOLINES[$x]=~/<IP_ADDRESS VALUE/)
                {
                        print "index is $x\n" if $Options{'debug'};
                        $tmpline=$ILOINFOLINES[$x];
                        chop $tmpline;
                        $tmpline=~s/^.*="//g;
                        $tmpline=~s/".*//g;
                        print "\t\tILO IP: $tmpline\n";
                        $ILOIP=$tmpline;
                }
                elsif($ILOINFOLINES[$x]=~/<DNS_NAME VALUE/)
                {
                        print "index is $x\n" if $Options{'debug'};
                        $tmpline=$ILOINFOLINES[$x];
                        chop $tmpline;
                        $tmpline=~s/^.*="//g;
                        $tmpline=~s/".*//g;
                        print "\t\tILO DNS NAME: $tmpline\n";
                        $ILODNSNAME=$tmpline;
                }
                elsif($ILOINFOLINES[$x]=~/<DOMAIN_NAME VALUE/)
                {
                        print "index is $x\n" if $Options{'debug'};
                        $tmpline=$ILOINFOLINES[$x];
                        chop $tmpline;
                        $tmpline=~s/^.*="//g;
                        $tmpline=~s/".*//g;
                        print "\t\tILO DOMAIN NAME: $tmpline\n";
                        $ILODOMAINNAME=$tmpline;
                }
        }
        # Get our local domainname
        $LOCALDOMAIN=hostdomain();
        print "local domain $LOCALDOMAIN\n" if $Options{'debug'};
 
        if($LOCALDOMAIN ne $ILODOMAINNAME)
        {
                print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";
                print "WARNING: ILO DNS Domain name does not match local domain\n";
                print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";
                $Options{'ilodomainmismatch'}=1;
        }
        $iloip=get_host_ip($Options{'fqdn'});
 
        $tmpaddr = inet_aton($ILOIP); # or whatever address
        $tmpname  = gethostbyaddr($tmpaddr, AF_INET);
 
        print "ilo name by addr: $tmpname\n" if $Options{'debug'};
        $tmpline=$tmpname;
        $tmpline=~s/\.$LOCALDOMAIN//g;
        if($ILODNSNAME eq $tmpline)
        {
                print "\tILO DNS Name matches ILO IP DNS Lookup ($tmpline)\n";
                $ILONAMEFROMDNS=$tmpname;
        }
        else
        {
                print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";
                print "WARNING: ILO IP ($ILOIP) resolves to\n\t\t$tmpname\n\twhich does not match configured ILO DNS Name\n\t\t$ILODNSNAME\n";
                print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";
                $ILONAMEFROMDNS=$tmpname;
                $Options{'ilonamemismatch'}=1;
        }
 
        $tmpline=$tmpname;
}
 
sub check_cert {
        my $cmd="echo | $Options{'CMDopenssl'} s_client -showcerts -connect $ILOIP:443 2> /dev/null | $Options{'CMDgrep'} 'Server public key'";
        my $line;
        print "Checking certificate for $ILODNSNAME\n";
        open(TEMP,"$cmd|");
                $line=<TEMP>;
                chop $line;
        close(TEMP);
 
        $line=~s/^Server public key is //g;
        $line=~s/ bit.*//g;
 
        $Options{'CurCertBit'}=int($line);
 
        if($Options{'CurCertBit'} < $Options{'MinCertBit'})
        {
                print "CERTIFICATE UPDATE NEEDED\n";
                print "$ILODNSNAME($ILOIP) certificate is only $Options{'CurCertBit'} bits long\n";
                print "Which is less than the minimum length of $Options{'MinCertBit'} bits.\n";
        }
        elsif($Options{'CurCertBit'} >= $Options{'MinCertBit'})
        {
                print "$ILODNSNAME($ILOIP) certificate is $Options{'CurCertBit'} bits long\n";
                print "Which meets the minimum length of $Options{'MinCertBit'} bits. No update needed\n";
        }
}
 
sub update_cert {
        my ($csr)=@_;
        my $gen_cmd="$Options{'CMDhponcfg'} -f $CSR_IN";
        my $gen_checkcmd="$Options{'CMDhponcfg'} -f $CSR_IN -l $CSR_CHECK 2>&1 >/dev/null";
        my $gen_crtpem="$Options{'CMDopenssl'} x509 -req -in $CSR_CHECK -CA $myCApem -CAkey $myCAkey -CAcreateserial -out $CRTpem -days 3650 -sha256";
        my $install_cert_cmd="$Options{'CMDhponcfg'} -f $ILOCERTCFG";
        my $complete=0;
        my $sleep_amt=5;
        my @lines;
        my $answer="";
 
        if($Options{'ilonamemismatch'})
        {
                print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";
                print "WARNING: ILO IP ($ILOIP) resolves to\n\t\t$ILONAMEFROMDNS\n\twhich does not match configured ILO DNS Name\n\t\t$ILODNSNAME\n";
                print "THIS NEEDS TO BE FIXED IN DNS or ON THE LOCAL ILO\n";
                print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";
        }
        if($Options{'ilodomainmismatch'})
        {
                print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";
                print "WARNING: ILO DNS Domain:\n\t$ILODOMAINNAME\n";
                print "         DOES NOT MATCH LOCAL DOMAIN:\n\t$LOCALDOMAIN\n";
                print "THIS NEEDS TO BE FIXED ON THE LOCAL ILO\n";
                print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";
        }
 
        print "About to update the local iLO certificate with:\n";
        print "\tFQDN: $ILONAMEFROMDNS\n\n";
        print "ARE YOU SURE YOU WANT TO CONTINUE?\n";
        print "PLEASE ANSWER 'YES' or 'NO': ";
        $answer=<STDIN>;
        chop($answer);
 
        if($answer ne "YES")
        {
                print "Answer does not match 'YES', exiting...\n";
                return(1);
        }
 
        print "sub update_cert\n" if $Options{'debug'};
        print "$csr\n" if $Options{'debug'};
        open(TEMP,">$CSR_IN");
        print TEMP $csr;
        close(TEMP);
 
 
        print "Issuing initial CSR generation request:\n";
        print "\t$gen_cmd\n";
        system($gen_cmd);
 
        while(!$complete)
        {
                print "Sleeping $sleep_amt seconds\n";
                sleep($sleep_amt);
                print "Issuing CSR check command: $gen_checkcmd\n";
                system($gen_checkcmd);
                if(-f $CSR_CHECK)
                {
                        print "Reading $CSR_CHECK\n";
                        open(TEMP,"$Options{'CMDgrep'} 'BEGIN CERTIFICATE REQUEST' $CSR_CHECK|");
                        @lines=<TEMP>;
                        close(TEMP);
                        if(grep(/BEGIN CERTIFICATE REQUEST/,@lines))
                        {
                                print "looks like it completed\n";
                                $complete=1;
                        }
                        else
                        {
                                print "Not ready yet\n";
                        }
                }
                else
                {
                        print "file $CSR_CHECK doesnt exist yet\n";
                }
        }
 
        print "Generating CRT.pem:\n";
        print "\t$gen_crtpem\n";
        system($gen_crtpem);
        open(TEMP,">$ILOCERTCFG");
                print TEMP $CERTCFGHEAD;
        close(TEMP);
        system("cat $CRTpem >> $ILOCERTCFG");
        open(TEMP,">>$ILOCERTCFG");
                print TEMP $CERTCFGTAIL;
        close(TEMP);
 
        print "Issuing certificate import command:\n";
        print "\t$install_cert_cmd\n";
        system($install_cert_cmd);
}
 
sub setup_ca{
        my $genrsa_cmd="$Options{'CMDopenssl'} genrsa -out $myCAkey 2048 2>/dev/null";
        my $genreq_cmd="$Options{'CMDopenssl'} req -x509 -new -nodes -key $myCAkey -sha256 -days 3650 -out $myCApem -subj \"/C=COUNTRY/ST=STATE/L=LOCAL/O=COMPANY/OU=ORG/CN=COUNTRY ORG\" 2>/dev/null";
        print "Issuing openssl genrsa command\n\t$genrsa_cmd\n" if $Options{'debug'};
        print "Issuing openssl genrsa command\n" if !$Options{'debug'};
        system($genrsa_cmd);
        print "Issuing openssl req command:\n\t$genreq_cmd\n" if $Options{'debug'};
        print "Issuing openssl req command\n" if !$Options{'debug'};
        system($genreq_cmd);
}
 
sub check_environment {
 
        if(! -x $Options{'CMDhponcfg'})
        {
                print "ERROR: $Options{'CMDhponcfg'} is missing or not executable\n";
                print "Is the package installed?\n";
                $ENVIRONMENT="BAD";
        }
 
        if(! -x $Options{'CMDopenssl'})
        {
                print "ERROR: $Options{'CMDopenssl'} is missing or not executable\n";
                print "Is the package installed?\n";
                $ENVIRONMENT="BAD";
        }
 
        if(! -x $Options{'CMDopenssl'})
        {
                print "ERROR: $Options{'CMDopenssl'} is missing or not executable\n";
                print "Is the package installed?\n";
                $ENVIRONMENT="BAD";
        }
 
        if($ENVIRONMENT eq "BAD")
        {
                print "ERROR: Dependency checks failed, please fix and try again\n";
                exit(1);
        }
}
 
sub main_sub {
        my $csr;
 
        check_args();
        check_environment();
        create_workingdir();
        get_iloinfo();
        print "CSR:\n$csr\n" if $Options{'debug'};
        if($Options{'check'})
        {
                check_cert();
        }
 
        if($Options{'update'})
        {
                setup_ca();
                $csr=$CSR;
                $csr=~s/VarFQDN/$ILONAMEFROMDNS/;
                update_cert($csr);
                check_cert();
        }
        remove_workingdir();
}
