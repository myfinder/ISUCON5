use Text::LTSV;
use Data::Dumper;

my $ltsv = Text::LTSV->new;
my %cnt;

while(my $line = <STDIN>) {
    my $row = $ltsv->parse_line($line);
    $cnt{$row->{uri}} //= 0;
    $cnt{$row->{uri}}+=$row->{request_time};
}

for my $uri (keys %cnt) {
    print $uri . "\t" . $cnt{$uri} . "\n";
}
