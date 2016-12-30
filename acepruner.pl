#!/usr/bin/env perl

use warnings;
use strict;
use Getopt::Std;
use Expect;
use DBI;

my $overall_start_time = time();
my $verbose;

package acepruner;

sub init {
    my $hash_reference = $_[0]
      or die "FATAL: printHashReference called without parameter.\n";
    $hash_reference->{'hostname'}        = '10.135.2.33';
    $hash_reference->{'deviceloginname'} = 'acepruner';
    $hash_reference->{'devicepassword'}  = 'prunemefirst';
    $hash_reference->{'enablepassword'}  = 'prunemefirst';
    $hash_reference->{'sshpath'}         = '/usr/bin/ssh';
    $hash_reference->{'enablecmd'}       = 'enable';
    $hash_reference->{'commandtorun'}    = 'show access-list';
    $hash_reference->{'commandtoexit'}   = 'exit';
    $hash_reference->{'dbname'}          = 'acepruner';
    $hash_reference->{'username'}        = 'root';
    $hash_reference->{'password'}        = 'root';
    $hash_reference->{'socketfile'} = '/opt/local/var/run/mysql5/mysqld.sock';
    $hash_reference->{'dbh'}        = DBI->connect(
'DBI:mysql:acepruner;mysql_socket=/opt/local/var/run/mysql5/mysqld.sock',
        'root', 'root'
    ) or die "Could not connect to database: $DBI::errstr";
    $hash_reference->{'timediff'} = '1 MINUTE';
    $hash_reference->{'configpath'} =
      '/Users/dan/scripts/acepruner/bin/booth-fw-config.txt';
    return $hash_reference;
}

sub gracefulExit {
    print "gracefulExit called\n";
    my $hash_reference = $_[0]
      or die "FATAL: gracefulExit called without parameter.\n";
    print "Closing database handle.\n";
    $hash_reference->{'dbh'}->disconnect();
    return $hash_reference;
}

sub printVerbose {
    print "printVerbose called\n";
    my $debugString = $_[0]
      or die "FATAL: printDebug() called without string.\n";
    if ($verbose) {
        print "$debugString\n";
    }
}

sub printHashReference {
    my $hash_reference = $_[0]
      or die "FATAL: printHashReference called without parameter.\n";
    while ( my ( $key, $value ) = each(%$hash_reference) ) {

        #print "key $key\n";
        print "key: $key=$value\n";
    }
    return $hash_reference;
}

sub getConfigurationViaSSH {
    print "getConfigurationViaSSH called\n";
    my $hash_reference = $_[0]
      or die "FATAL: getConfiguration called without parameter.\n";
    print "Verbosity flag: " . $hash_reference->{'verbose'} . "\n";
    my $session = new Expect();
    $session->debug(0);
    $session->log_stdout(0);
    $hash_reference->{'command'} =
        $hash_reference->{'sshpath'} . " "
      . $hash_reference->{'deviceloginname'} . '@@'
      . $hash_reference->{'hostname'};
    $session->spawn( $hash_reference->{'command'} );
    my $prompt;
    $hash_reference->{'match'} = $session->expect(
        3,
        [
            '(yes/no)' => sub {
                $session->send("yes\n");
                Expect::exp_continue;
              }
        ],
        [
            'password:' => sub {
                $session->send( $hash_reference->{'devicepassword'} . "\n" );
                Expect::exp_continue;
              }
        ],
        [
            '>' => sub {
                $session->send( $hash_reference->{'enablecmd'} . "\n" );
                Expect::exp_continue;
              }
        ],
        [
            'Password:' => sub {
                $session->send( $hash_reference->{'enablepassword'} . "\n" );
                Expect::exp_continue;
              }
        ],
        [
            '-re',
            '^.*?# ' => sub {
                $prompt = $session->exp_match();

                #strip the carriage returns off the front.
                $prompt =~ s/^\s*//g;
                print "prompt: $prompt\n";
                my $match_value = $session->exp_match();
                $session->send( $hash_reference->{'commandtorun'} . "\n" );
              }
        ]
    );
    $hash_reference->{'match'} = $session->expect(
        3,
        [
            "$prompt" => sub {

                #print $session->exp_before();
                my $output = $session->exp_before();

                #print "$output";
                $hash_reference->{'output'} = $output;
                $session->send( $hash_reference->{'commandtoexit'} . "\n" );
              }
        ]
    );
    $session->soft_close();

    #print "match: $hash_reference->{'match'}\n";
    return $hash_reference;
}

sub getConfigurationFromFile {
    print "getConfigurationFromFile called\n";
    my $hash_reference = $_[0]
      or die "FATAL: getConfigurationFromFile called without parameter.\n";
    print "Verbosity flag: " . $hash_reference->{'verbose'} . "\n";
    my @lines;
    my $individualLine;
    if ( -e $hash_reference->{'filename'} ) {
        print "file exists, using it\n";
        print "opening configuraiton from file\n";
        open( MYINPUTFILE, "<" . $hash_reference->{'filename'} );
        @lines = <MYINPUTFILE>;
    }
    else {
        die "File does not exist.\n";
    }
    $hash_reference->{'output'} = \@lines;
    return $hash_reference;
}

sub parseConfiguration {
    print "parseConfiguration called\n";
    my $hash_reference = $_[0]
      or die "FATAL: parseConfiguration called without parameter.\n";
    print "Verbosity flag: " . $hash_reference->{'verbose'} . "\n";
    my $length = length( $hash_reference->{'output'} );
    print "length: $length\n";
    my @lines = split( "\n", $hash_reference->{'output'} );
    foreach my $line (@lines) {
        my @line = split($line);
        print $line . "\n";
    }
    print $hash_reference->{'output'};
}

sub parseACLSimple {
    print "parseACLSimple called.\n";
    my $hash_reference = $_[0]
      or die "FATAL: parseConfiguration called without parameter.\n";
    print "Verbosity flag: " . $hash_reference->{'verbose'} . "\n";
    printHashReference($hash_reference);
    my @lines = @{ $hash_reference->{'output'} };
    my $acelist;
    foreach my $line (@lines) {

        #print "$line";
        chomp($line);

        if ( $line =~ /(access-list.*) \(hitcnt=(\d+)\) (\S+)/ ) {

            #if ($line =~ /(.*) \(hitcnt=(\d+)\) (\S+)/) {
            print "Found an expanded out ACL\n";
            print
"Populating ace_list with record: hit_count=\"$2\" acl_id=\"$3\" raw_ace=\"$1\"\n";
            $acelist->{$3}{'hitcount'} = $2;
            $acelist->{$3}{'raw_ace'}  = $1;

            #print "line: $1\n";
        }
    }
    for my $key ( keys %{$acelist} ) {

        #print "key: $key hit count: " . $acelist->{$key}{'hitcount'} . "\n";
    }
    $hash_reference->{'acelist'} = $acelist;
    return $hash_reference;
}

sub updateSimpleACLTimestampsAndValues {
    print "updateSimpleACLTimetamps called.\n";
    my $hash_reference = $_[0]
      or die "FATAL: parseConfiguration called without parameter.\n";
    print "Verbosity flag: " . $hash_reference->{'verbose'} . "\n";
    my $acelist       = $hash_reference->{'acelist'};
    my $updatecounter = 0;
    my $insertcounter = 0;
    for my $key ( keys %{$acelist} ) {
        print "key: $key\n";
        my $value   = $acelist->{$key}{'hitcount'};
        my $raw_ace = $acelist->{$key}{'raw_ace'};
        print "raw ace: $raw_ace\n";
        print "hitcount: $value\n";
        print "iterating against ACL key: $key value: " . $value . "\n";

        $hash_reference->{'query'} =
          $hash_reference->{'dbh'}
          ->prepare("SELECT * FROM simple_tracker WHERE acl_id=\'$key\'");
        $hash_reference->{'query'}->execute()
          or die "Could not execute query" . $hash_reference->{'query'}->errstr;

        if ( $hash_reference->{'query'}->rows == 1 ) {
            my @recordset = $hash_reference->{'query'}->fetchrow_array();
            $hash_reference->{'query'}->finish();

            #print "recordset: @@recordset\n";
            #print "value of hits from database: $recordset[1]\n";
            print
"found single entry in database, checking hitcount value to see if it increased. database: $recordset[1] input: $value\n";
            if ( $value > $recordset[1] ) {
                print
"Value of hit count increased, updating MySQL database from $recordset[1] to $value (also triggering timestamp update)\n";
                $hash_reference->{'query'} =
                  $hash_reference->{'dbh'}->prepare(
"UPDATE simple_tracker SET hitcount = \'$value\' WHERE acl_id=\'$key\'"
                  );
                $hash_reference->{'query'}->execute()
                  or die "Could not execute query"
                  . $hash_reference->{'query'}->errstr;
                $updatecounter++;
            }
            else {
                print
"did not update database record because hit count did not change.  database: $recordset[1] input: $value\n";
            }
        }
        elsif ( $hash_reference->{'query'}->rows > 1 ) {
            die "more than one record found, this should never happen.\n";
        }
        elsif ( $hash_reference->{'query'}->rows == 0 ) {
            print "ace key " . $key
              . " not found, inserting record into database.\n";
            $hash_reference->{'query'} = $hash_reference->{'dbh'}->prepare(
"INSERT INTO simple_tracker (acl_id, hitcount, raw_ace) VALUES (\'$key\',\'$value\',\'$raw_ace\')"
                  or die "Could not prepare query."
            );
            $hash_reference->{'query'}->execute()
              or die "Could not execute query"
              . $hash_reference->{'query'}->errstr;
            $insertcounter++;

            #undef $hash_reference->{'query'};
        }
        else {
            die "this should never happen\n";
        }
    }

    print "Updated the timestamps on $updatecounter records\n";
    print "Inserted $insertcounter new records\n";
    undef $insertcounter;
    undef $updatecounter;
    return $hash_reference;
}

sub cleanupOldEntriesSimple {

    #For the entire data pulled from the ACL,

    print "cleanupOldEntriesSimple Called\n";
    my $hash_reference = $_[0]
      or die "FATAL: parseConfiguration called without parameter.\n";
    my $acelist = $hash_reference->{'acelist'};
    $hash_reference->{'query'} =
      $hash_reference->{'dbh'}->prepare("SELECT * FROM simple_tracker");
    $hash_reference->{'query'}->execute()
      or die "Could not execute query" . $hash_reference->{'query'}->errstr;
    my @result;
    my $match;
    my $key;
    my $value;
    my $db_prune_count = 0;
    my $start          = time();

    while ( @result = $hash_reference->{'query'}->fetchrow_array() ) {
        $value = $result[0];
        $key   = $result[0];
        $match = 0;

        #print "value from prune: $value\n";
        #print "key: $key\n";

        my $start2 = time();
        for my $acekey ( keys %{$acelist} ) {

#print "iterating through this loop, searching input key: $acekey against database result: $key\n";
            if ( $acekey eq $key ) {
                $match = "1";

                #print "Found a match for: $key\n";
                last;
            }
            else {

                #print "Did not find a match for key: $key\n";
            }
        }
        my $end2 = time();

#printDebug("Search for key $key took ". ($end2 - $start2). " seconds", $hash_reference->{'verbose'});
        if ( $match == 1 ) {

         #print "Found a match from input, leaving the record in the datbase\n";
        }
        else {
            print
"Did not find a match from the running-configuration, pruning the record from the database\n";
            $hash_reference->{'query2'} =
              $hash_reference->{'dbh'}
              ->prepare("DELETE FROM simple_tracker WHERE acl_id=\'$key\'");
            $hash_reference->{'query2'}->execute()
              or die "Could not execute query"
              . $hash_reference->{'query'}->errstr;
            $db_prune_count++;
            print "Record removed from database\n";
        }
    }
    my $end = time();
    print "Pruned: $db_prune_count records from the database.\n";
    print "Subroutine took: ", ( $end - $start ), " seconds\n";
    return $hash_reference;
}

sub toggleVerbose {
    my $hash_reference = $_[0]
      or die "Toggle verbose called without environment.\n";
    print "Verbosity flag: " . $hash_reference->{'verbose'} . "\n";

    #printDebug("toggleVerbose called\n", $hash_reference->{'verbose'});
    if ( $hash_reference->{'verbose'} == "0" ) {
        print "Verbose mode enabled.\n";
        $hash_reference->{'verbose'} = "1";
    }
    elsif ( $hash_reference->{'verbose'} == "1" ) {
        print "Verbose mode disabled.\n";
        $hash_reference->{'verbose'} = "0";
    }
    return $hash_reference;
}

sub detectOldRecords {
    my $hash_reference = $_[0]
      or die "Detect old records called without environment.\n";

    #printDebug("detectOldRecords called", $hash_reference->{'verbose'});
    $hash_reference->{'query'} =
      $hash_reference->{'dbh'}->prepare(
"SELECT * FROM simple_tracker WHERE timestamp < (CURRENT_TIMESTAMP() - INTERVAL 1 MINUTE)"
      );
    $hash_reference->{'query'}->execute()
      or die "Could not execute query" . $hash_reference->{'query'}->errstr;
    my $results = $hash_reference->{'query'}->rows;
    if ( $hash_reference->{'query'}->rows > 1 ) {
        print
"returned some rows that are older than SQL time interval:  \'$hash_reference->{'timediff'}\'\n";
    }
    else {
        print "did not return any rows\n";
    }

    my @result;

    while ( @result = $hash_reference->{'query'}->fetchrow_array() ) {
        print
"acl_id=$result[0] hitcount=$result[1] timestamp=$result[2] raw_ace=\"$result[3]\"\n";
    }
    print "Total records reccpmended for deletion: $results\n";
    return $hash_reference;
}

sub printUsage {
    my $hash_reference = $_[0]
      or die "Detect old records called without environment.\n";

    #printDebug("printUsage called\n" , $hash_reference->{'verbose'});
    print "Usage: \n";
    print "acepruner  -s|c [-k] -f|n [<value> [-t <value>]\n";
}

sub buildFirewallTree {
    my $hash_reference = $_[0]
      or die "build Firewall Tree called without environment.\n";
    print "Verbosity flag: " . $hash_reference->{'verbose'} . "\n";

    #printDebug("buildFirewallTree called.",$hash_reference->{'verbose'});
    my @lines;
    my $individualLine;
    my $firewall;

    if ( -e $hash_reference->{'filename'} ) {
        print "file exists, using it\n";
        print "opening configuraiton from file\n";
        open( MYINPUTFILE, "<" . $hash_reference->{'configpath'} );
        @lines = <MYINPUTFILE>;
    }
    else {
        die "file does not exist\n";
    }

    foreach $individualLine (@lines) {

        #print $individualLine;

        if ( $individualLine =~ /object-group network (\S+)/ ) {
            print "found a network-object group=$1\n";
            print "individualLine: $individualLine\n";
            print "setting parent to $1\n";

        }
        elsif ( $individualLine =~
/ network-object (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}) (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})/
          )
        {
            print
              "found a network-object member networkaddress=$1 subnetmask=$2\n";

            print "individualLine: $individualLine\n";
        }
        elsif ( $individualLine =~ / description (.*)/ ) {
            print "found a description=$1\n";
        }

        elsif ( $individualLine =~ /object-group service (\S+) (\S+)/ ) {
            print "found a service-object group=$1 type=$2\n";

        }
    }

    iy $hash_reference = $_[0]
      or die "Detect old records called without environment.\n";
    return $hash_reference;
}

my %commandLineOptions;
Getopt::Std::getopts( 'kcsf:v', \%commandLineOptions );

if ( $commandLineOptions{'h'} ) {
    print "Flags:\n";
    print "s - parse and update (no firewall tree)\n";
    print "v - enable verbose\n";
    print "Options:\n";
    print "f <path> - load the file from disk\n";
    print "n <node> - ssh into a device\n";
    exit 0;
}

my $hash_reference;

$hash_reference->{'version'} = "hi";

if ( $commandLineOptions{'v'} ) {
    print "Verbose flag found.\n";
    $verbose = 1;
}

$hash_reference = init($hash_reference);

if ( $commandLineOptions{'f'} ) {
    $hash_reference->{'filename'} = $commandLineOptions{'f'};
    $hash_reference = acepruner::getConfigurationFromFile($hash_reference);
}
elsif ( $commandLineOptions{'n'} ) {
    print "File flag not found, downloading configuration via SSH";
    $hash_reference->{'filename'} = $commandLineOptions{'f'};
    $hash_reference = acepruner::getConfigurationViaSSH($hash_reference);
}
else {
    die "Pass either 'n' or 'f' flags. \n";
}

if ( $commandLineOptions{'s'} ) {
    print "Script executed with simple flag set, calling simple.\n";
    $hash_reference = acepruner::parseACLSimple($hash_reference);
    $hash_reference =
      acepruner::updateSimpleACLTimestampsAndValues($hash_reference);
    $hash_reference = acepruner::detectOldRecords($hash_reference);
}
elsif ( $commandLineOptions{'c'} ) {
    print "Performing complex parse of firewall configuration.\n";
    $hash_reference = acepruner::buildFirewallTree($hash_reference);

}
else {
    die
      "Please pass either s or c option to script (run script with -h for ).\n";
}

if ( $commandLineOptions{'t'} ) {
    print "Script called with alternate time threshold.\n";
    $hash_reference->{'timediff'} = $commandLineOptions{'t'};
}

if ( $commandLineOptions{'k'} ) {
    print
"Found command line option k, cleaning up anything not in the database that was found from the device output\n";
    $hash_reference = acepruner::cleanupOldEntriesSimple($hash_reference);
}
else {
    print "Did not find command line option k\n";
}
$hash_reference = acepruner::gracefulExit($hash_reference);

if ( $commandLineOptions{'v'} ) {
    print "Printing hash reference because verbose was enabled.\n";

    $hash_reference = acepruner::printHashReference($hash_reference);
}

my $overall_end_time = time();
print "Subroutine took: ", ( $overall_end_time - $overall_start_time ),
  " seconds\n";
