#!/usr/bin/perl -w
###############################################################################
# Name        :  webhook.pl
# Version     :  v0.1.1
# Date        :  September 2017
# Description :  It sends a POST data to an endpoint (webhook)
# Author      :  Javier Santillan  [jusafing@gmail.com]
###############################################################################
use strict;
use LWP::UserAgent;
use Log::Log4perl qw(:easy);
use File::ReadBackwards;

###############################################################################
# Global Variables
my $endpoint  = "URL"; 
my $authfile  = "/var/log/auth.log";
my $logfile   = "/var/log/sshmon.log";
my $server    = "HOSTNAME";
my $readbuffer= 20; # Readlines buffer i.. read last n lines per iteration
my $maxpost   = 10;
my %readlogs  ;

###############################################################################
# Modules configuration
# Initialize Logger
Log::Log4perl->easy_init( { level    => $INFO,
                            file     => ">>$logfile",
                            layout   => '%d %F{1}-%L-%M: [%p] %m%n' },
                          { level    => $INFO,
                            file     => "STDOUT",
                            layout   => '%d %F{1}-%L-%M: [%p] %m%n' },
                        );
my $logger = Log::Log4perl->get_logger();


###############################################################################
# Send POST request
# http://xmodulo.com/how-to-send-http-get-or-post-request-in-perl.html
sub send_post {
    my ($line, $flag_send, $endpoint, $data) = @_;

    if ( exists $readlogs{$line} ) {
        $logger->debug("LOG LINE Already reported");
        return;
    }
    return if ( $flag_send == 0);

    $readlogs{$line}++;
    my $ua       = LWP::UserAgent->new;
    my $req      = HTTP::Request->new(POST => $endpoint);
    $req->header('content-type' => 'application/json');
    my $post_data = $data;
    $req->content($post_data);
    my $resp = $ua->request($req);
    $logger->info("Sending POST data: ($data)");
    if ($resp->is_success) {
        my $message = $resp->decoded_content();
        $logger->info("Received reply: ($message)");
    }
    else {
        my $res_code = $resp->code();
        my $res_msg  = $resp->message();
        $logger->error("HTTP POST error code: ($res_code)");
        $logger->error("HTTP POST error message: ($res_msg)");
    }
}


###############################################################################
# Send POST request
sub sshmon {
    my $file     = shift;
    my $buffer   = shift;
    my $line_cnt ;
    my $line     ;
    my $fh       ;
    $logger->debug(" >>>>>>>>>>>>>>>>>> Reading file $file");
    if ($fh = File::ReadBackwards->new($file)) {
        while ( defined($line = $fh->readline) ) {
            my $flag_send = 0;
            my $data      = "";
            $line_cnt ++;
            chomp($line);
            if ($line =~ m/accepted/i) {
                my $prefix = "### ALERT: SSH ACCEPTED on $server\n";
                $data = "{\"text\": \"$prefix`$line`\"}";
                $logger->debug("Accepted connection detected: Sending ($data)");
                $flag_send ++;
            }
            elsif ($line =~ m/failed/i) {
                my $prefix = "##### WARNING: SSH TRY FAILED on $server\n";
                $data = "{\"text\": \"$prefix`$line`\"}";
                $logger->debug("Failed connection detected: Sending ($data)");
                $flag_send ++;
            }
            # 1) Generic filter. It just look for "session opene" lines
            #elsif ($line =~ m/[session opened/i) {
            # 2) More complex regex. Skip CRON lines (too noisy notifications)
            #https://stackoverflow.com/questions/23403494/perl-matching-string-not-containing-pattern
            elsif ($line =~ m/^(?:(?!CRON).)*session opened/) {
                my $prefix = "### ALERT: SSH SESSION Opened $server\n";
                $data = "{\"text\": \"$prefix`$line`\"}";
                $logger->debug("Session opened detected: Sending ($data)");
                $flag_send ++;
            }
            elsif ($line =~ m/Successful su/i) {
                my $prefix = "### ALERT: ROOT session Opened $server\n";
                $data = "{\"text\": \"$prefix`$line`\"}";
                $logger->debug("ROOT session opened: Sending ($data)");
                $flag_send ++;
            }
            send_post($line, $flag_send, $endpoint, $data);
            last if ($line_cnt > $buffer);
        }
    }
    else {
        $logger->error("Unable to read auth file $file");
    }
}

###############################################################################
while(1) {
    sshmon($authfile, $readbuffer);
    sleep 3
}
