package Net::RBLClient;
use strict;
use IO::Socket;
use Time::HiRes qw( time );
use Net::DNS::Packet;

use vars qw( $VERSION $ip_pat );
$ip_pat = qr(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3});
$VERSION = '0.1';

sub new {
    my($class, %args) = @_;
    my $self = {
        lists       => [ lists() ],
        max_time    => 8,
        timeout     => 1,
        max_hits    => 1000,
        max_replies => 1000,
        udp_maxlen  => 4000,
        server      => 'resolv.conf',
    };
    bless $self, $class;
    foreach my $key(keys %args) {
        defined($self->{ $key })
            or die "Invalid key: $key";
        $self->{ $key } = $args{ $key }; 
    }
    if($self->{ server } eq 'resolv.conf') {
        open F, '/etc/resolv.conf'
            or die "Can't open resolv.conf: $!";
        local $/;
        my $resolv = <F>;
        if($resolv =~ /^nameserver\s+($ip_pat)/) {
            $self->{ server } = $1;
        }
        else {
            die "No nameserver found in resolv.conf: specify on in constructor";
        }
    }
    $self;
}

sub lookup {
    my($self, $target_ip) = @_;
    $target_ip =~ /^$ip_pat$/
        or die "Invalid ip: '$target_ip' - must be dotted quad";
    my $start_time = time;
    my $qip = join '.', reverse(split /\./, $target_ip);
    my $deadline = time + $self->{ max_time };

    my $sock = IO::Socket::INET->new(
        Proto     => 'udp',
        PeerPort  => 53,
        PeerAddr  => $self->{ server },
    ) or die "Failed to create UDP client";

    foreach my $list(@{ $self->{ lists } }) {
        my $msg = mk_packet($qip, $list);
        $sock->send($msg) || die "send: $!";
    }
    my $dur = time - $start_time;

    # Keep recv'ing packets until one of the exit conditions is met:

    my $needed = @{ $self->{ lists } }; # how many packets needed back
    my $hits;
    my $replies;

    while($needed && time < $deadline) {
        my $msg = '';
        eval {
            $SIG{ALRM} = sub { die "alarm time out" };
            alarm $self->{ timeout };
            $sock->recv($msg, $self->{ udp_maxlen })  || die "recv: $!";
            alarm 0;
            1; # eval was OK
        };
        if($msg) {
            my ($domain, $res) = decode_packet($msg);
            $replies ++;
            $hits ++ if $res;
            $self->{ results }{ $domain } = $res if $res;
            $needed --;
            return 1 if $hits >= $self->{ max_hits };
            return 1 if $replies >= $self->{ max_replies };
        }
    }
    1;
}

sub listed_by {
    my $self = shift;
    sort keys %{ $self->{ results } };
}

sub listed_hash {
    my $self = shift;
    %{ $self->{ results } };
}

# End methods - begin internal functions

sub mk_packet {
    # pass me a REVERSED dotted quad ip (qip) and a blocklist domain
    my($qip, $list) = @_;
    my $packet = Net::DNS::Packet->new("$qip.$list", 'A', 'IN');
    $packet->data;
}

sub decode_packet {
    # takes a raw DNS response packet
    # returns domain, response
    my $data = shift;
    my $packet = Net::DNS::Packet->new(\$data);
    my @answer = $packet->answer;
    
    foreach my $answer(@answer) {
        my $domain = $answer->name;
        $domain =~ s/^\d+\.\d+\.\d+\.\d+\.//;
        my $res = '?';
        if($answer->type eq 'A') {
            $res = inet_ntoa($answer->rdata);
        }
        elsif($answer->type eq 'CNAME') {
            $res = cleanup($answer->rdata);
        }
        return($domain, $res);
    }
    
    # OK, there were no answers -
    # need to determine which domain
    # sent the packet.

    my @question = $packet->question;
    foreach my $question(@question) {
        my $domain = $question->qname;
        $domain =~ s/^\d+\.\d+\.\d+\.\d+\.//;
        return($domain, undef);
    }
}

sub cleanup {
    # remove control chars and stuff
    $_[ 0 ] =~ tr/a-zA-Z0-9./ /cs;
    $_[ 0 ];
}

sub lists {
    qw(
        blackhole.compu.net
        blackholes.2mbit.com
        blackholes.brainerd.net
        blackholes.five-ten-sg.com
        blackholes.intersil.net
        blackholes.wirehub.net
        block.blars.org
        blocktest.relays.osirusoft.com
        bl.reynolds.net.au
        bl.spamcop.net
        dev.null.dk
        dews.qmail.org
        dialups.relays.osirusoft.com
        dnsbl.njabl.org
        dynablock.wirehub.net
        flowgoaway.com
        formmail.relays.monkeys.com
        http.opm.blitzed.org
        inputs.relays.osirusoft.com
        korea.services.net
        orbs.dorkslayers.com
        pm0-no-more.compu.net
        proxies.monkeys.com
        proxies.relays.monkeys.com
        proxy.relays.osirusoft.com
        relays.dorkslayers.com
        relays.ordb.org
        relays.osirusoft.com
        relays.visi.com
        socks.opm.blitzed.org
        socks.relays.osirusoft.com
        spamguard.leadmon.net
        spamhaus.relays.osirusoft.com
        spammers.v6net.org
        spamsites.relays.osirusoft.com
        spamsources.fabel.dk
        spews.relays.osirusoft.com
        work.drbl.croco.net
        xbl.selwerd.cx
        ztl.dorkslayers.com
    );
}
1;

__END__

=head1 NAME

Net::RBLClient - Queries multiple Realtime Blackhole Lists in parallel

=head1 SYNOPSIS

    use Net::RBLClient;
    my $rbl = Net::RBLClient->new;
    $rbl->lookup('211.101.236.160');
    my @listed_by = $rbl->listed_by;

=head1 DESCRIPTION

This module is used to discover what RBL's are listing a particular IP
address.  It parallelizes requests for fast response.

An RBL, or Realtime Blackhole List, is a list of IP addresses meeting some
criteria such as involvement in Unsolicited Bulk Email.  Each RBL has
its own criteria for addition and removal of addresses.  If you want to
block email or other traffic to/from your network based on one or more
RBL's, you should carefully study the behavior of those RBL's before and
during such blocking.

=head1 CONSTRUCTOR

=over 4

=item new( [ARGS] )

Takes an optional hash of arguments:

=over 4

=item lists

An arraref of (sub)domains representing RBLs.  In other words, each element
in the array is a string similar to 'relays.somerbl.org'.  Use this if
you want to query a specific list of RBL's - if this argument is omitted,
a large list of RBL's is queried.

=item max_time

The maximum time in seconds that the lookup function should take.  In fact,
the function can take up to C<max_time + timeout> seconds.  Max_time need
not be integer.  Of course, if the lookup returns due to max_time, some
DNS replies will be missed.

Default: 8 seconds.

=item timeout

The maximum time in seconds spent awaiting each DNS reply packet.  The
only reason to change this is if C<max_time> is decreased to a small value.

Default: 1 second.

=item max_hits

A hit is an affirmative response, stating that the IP address is on a certain
list.  If C<max_hits> hits are received, C<lookup()> returns immediately.
This lets the calling program save time.

Default: 1000 (effectively out of the picture).

=item max_replies

A reply from an RBL could be affirmative or negative.  Either way, it counts
towards C<max_replies>.  C<Lookup()> returns when C<max_replies> replies
have been received.

=item udp_maxlen

The maximum number of bytes read from a DNS reply packet.  There's probably
no reason to change this.

Default: 4000

=item server

The local nameserver to use for all queries.  Should be either a resolvable
hostname or a dotted quad IP address.

By default, the first nameserver in /etc/resolv.conf will be used.

=back

=head1 METHODS

=item lookup( IPADDR )

Lookup one IP address on all RBL's previously defined.  The IP address
must be expressed in dotted quad notation, like '1.2.3.4'.  C<Lookup()>
returns 1.

=item listed_by()

Return an array of RBL's which block the specified IP.  The RBL's are
indicated via the (sub)domain used for DNS query.  The calling program
must first call C<lookup()>.

=item listed_hash()

Return a hash whose keys are the RBL's which block the specified IP,
represented as in C<listed_by()>.  If the RBL returned an A record,
the value for that key will be the IP address in the A record -
typically 127.0.0.1 - 127.0.0.4.  If the RBL returned a CNAME, the
value will be the hostname, typically used for a comment on why the
IP address is listed.

=back

=head1 AUTHOR

Asher Blum E<lt>F<asher@wildspark.com>E<gt>

=head1 COPYRIGHT

Copyright (C) 2002 Asher Blum.  All rights reserved.
This code is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut

1;
