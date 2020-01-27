#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

use Net::SNMP;
use Pod::Text::Termcap;

use constant OK         => 0;
use constant WARNING    => 1;
use constant CRITICAL   => 2;
use constant UNKNOWN    => 3;
use constant DEPENDENT  => 4;

my $pkg_nagios_available = 0;
my $pkg_monitoring_available = 0;
my @g_long_message;
my @sensors_enabled = ();
my @sensors_available = ('fan', 'power', 'system', 'temperature');

BEGIN {
    eval {
        require Monitoring::Plugin;
        require Monitoring::Plugin::Functions;
        $pkg_monitoring_available = 1;
    };
    if (!$pkg_monitoring_available) {
        eval {
            require Nagios::Plugin;
            require Nagios::Plugin::Functions;
            *Monitoring::Plugin:: = *Nagios::Plugin::;
            $pkg_nagios_available = 1;
        };
    }
    if (!$pkg_monitoring_available && !$pkg_nagios_available) {
        print("UNKNOWN - Unable to find module Monitoring::Plugin or Nagios::Plugin\n");
        exit UNKNOWN;
    }
}

my %session_opts;
my $parser = Pod::Text::Termcap->new (sentence => 0, width => 78);
my $extra_doc = <<'END_MESSAGE';

END_MESSAGE

my $extra_doc_output;
$parser->output_string(\$extra_doc_output);
$parser->parse_string_document($extra_doc);

my $mp = Monitoring::Plugin->new(
    shortname => "check_mikrotik",
    usage => "",
    extra => $extra_doc_output
);

$mp->add_arg(
    spec    => 'snmp-version=s',
    help    => 'SNMP Version: 1, 2, 3 (Default: 2)',
    default => '2'
);

$mp->add_arg(
    spec    => 'community|C=s',
    help    => 'Community string (Default: public)',
    default => 'public'
);

$mp->add_arg(
    spec    => 'seclevel|L=s',
    help    => 'One of "noAuthNoPriv", "authNoPriv" or "authPriv"',
    default => 'noAuthNoPriv',
);

$mp->add_arg(
    spec => 'secname|U=s',
    help => 'Username for SNMPv3',
);

$mp->add_arg(
    spec => 'context|c=s',
    help => 'SNMPv3 context name (default is empty string)',
);

$mp->add_arg(
    spec => 'authpass|A=s',
    help => 'Authentication Password for SNMPv3',
);

$mp->add_arg(
    spec    => 'authproto|a=s',
    help    => 'SNMPv3 authentication protocol must be MD5 or SHA1 (Default: MD5)',
    default => 'MD5',
);

$mp->add_arg(
    spec => 'privpass|X=s',
    help => 'SNMPv3 Privacy password',
);

$mp->add_arg(
    spec    => 'privproto|P=s',
    help    => 'SNMPv3 privacy protocol (DES or AES; default: DES)',
    default => 'DES',
);

$mp->add_arg(
    spec => 'hostname|H=s',
    help => '',
    required => 1
);

$mp->add_arg(
    spec    => 'sensor=s@',
    help    => sprintf('Enabled sensors: all, %s (Default: all)', join(', ', @sensors_available)),
    default => []
);

$mp->add_arg(
    spec => 'temperature-warn=s',
    help => 'Warning temperature for all temperature sensors',
);

$mp->add_arg(
    spec => 'temperature-crit=s',
    help => 'Critical temperature for all temperautre sensors',
);

$mp->add_arg(
    spec    => 'temperature-thresholds=s@',
    help    => 'Temperature thresholds. Format: <name>;<warn>;<crit>',
    default => []
);


$mp->getopts;

parse_args();

#Open SNMP Session
my ($session, $error) = Net::SNMP->session(%session_opts);

if (!defined($session)) {
    wrap_exit(UNKNOWN, $error)
}

check();

my ($code, $message) = $mp->check_messages();
wrap_exit($code, $message . "\n" . join("\n", @g_long_message));

sub parse_args
{
    my $snmp_version = $mp->opts->get('snmp-version');
    my $seclevel = $mp->opts->seclevel;
    my $secname = $mp->opts->secname;
    my $authproto = $mp->opts->authproto;
    my $authpass = $mp->opts->authpass;
    my $privpass = $mp->opts->privpass;
    my $privproto = $mp->opts->privproto;

    %session_opts = (
        -hostname   => $mp->opts->hostname,
        -version    => $mp->opts->get('snmp-version'),
    );

    $session_opts{'-community'} = $mp->opts->community if (defined $mp->opts->community && $snmp_version =~ /[12]/);

    if ($snmp_version =~ /3/ ) {
        if (!defined $seclevel) {
            wrap_exit(UNKNOWN, 'Security level is not defined');
        }
        unless ( grep /^$seclevel$/, qw(noAuthNoPriv authNoPriv authPriv) ) {
            wrap_exit(UNKNOWN, 'Security level must be one of "noAuthNoPriv", "authNoPriv" or "authPriv"');
        }

        if (!defined $secname) {
            wrap_exit(UNKNOWN, 'Security name is not defined');
        }
        $session_opts{'-username'} = $secname;

        if ( $seclevel eq 'authNoPriv' || $seclevel eq 'authPriv' ) {
            unless ( grep /^$authproto$/, qw(MD5 SHA1) ) {
                wrap_exit(UNKNOWN, 'Authentication protocol must be one of "MD5" or "SHA1"');
            }
            $session_opts{'-authprotocol'} = $authproto;

            if (!defined $authpass) {
                wrap_exit(UNKNOWN, 'Authentication password/key is not defined');
            }

            if ($authpass =~ /^0x/ ) {
                $session_opts{'-authkey'} = $authpass ;
            } else {
                $session_opts{'-authpassword'} = $authpass ;
            }
        }
        if ($seclevel eq 'authPriv') {
            if (! defined $privpass) {
			    wrap_exit(UNKNOWN, 'Privacy passphrase/key is not defined');
			}
            if ($privpass =~ /^0x/ ) {
                $session_opts{'-privkey'} = $privpass;
            }else{
                $session_opts{'-privpassword'} = $privpass;
            }
            $session_opts{'-privprotocol'} = $privproto;
        }
    }

    if(@{$mp->opts->sensor} == 0 || grep(/^all$/, @{$mp->opts->sensor})) {
        @sensors_enabled = @sensors_available;
    } else {
        foreach my $name (@{$mp->opts->sensor}) {
            if(!grep(/$name/, @sensors_available)) {
                wrap_exit(UNKNOWN, sprintf('Unknown sensor type: %s', $name));
            }
        }
        @sensors_enabled = @{$mp->opts->sensor};
    }
}


sub check
{
    if (grep(/^fan$/, @sensors_enabled)) {
        check_fan();
    }
    if (grep(/^power$/, @sensors_enabled)) {
        check_power();
    }
    if (grep(/^system$/, @sensors_enabled)) {
        check_system();
    }
    if (grep(/^temperature$/, @sensors_enabled)) {
        check_temperature();
    }
}



sub check_fan
{
    my $mtxrHlActiveFan = '.1.3.6.1.4.1.14988.1.1.3.9.0';
    my $mtxrHlFanSpeed1 = '.1.3.6.1.4.1.14988.1.1.3.17.0';
    my $mtxrHlFanSpeed2 = '.1.3.6.1.4.1.14988.1.1.3.18.0';

    my $result = $session->get_request(
        -varbindlist => [
            $mtxrHlActiveFan,
            $mtxrHlFanSpeed1,
            $mtxrHlFanSpeed2
        ]
    );
    if(!defined $result) {
        wrap_exit(UNKNOWN, 'Unable to get information');
    }
    my $active_fan = $result->{$mtxrHlActiveFan};
    $mp->add_message(OK, 'Active Fan: ' . $active_fan);
    
    my $fan_speed1 = $result->{$mtxrHlFanSpeed1};
    if ($fan_speed1 ne 'noSuchObject') {
        $mp->add_message(OK, 'Fan1: ' . $fan_speed1);
        $mp->add_perfdata(
            label     => 'fan1_speed',
            value     => $fan_speed1,
            uom       => ''
        );
    }
    my $fan_speed2 = $result->{$mtxrHlFanSpeed2};
    if ($fan_speed2 ne 'noSuchObject') {
        $mp->add_message(OK, 'Fan2: ' . $fan_speed2);
        $mp->add_perfdata(
            label     => 'fan2_speed',
            value     => $fan_speed2,
            uom       => ''
        );
    }

}

sub check_power
{
    my $mtxrHlPower = '.1.3.6.1.4.1.14988.1.1.3.12.0';
    my $mtxrHlCurrent = '.1.3.6.1.4.1.14988.1.1.3.13.0';
    my $mtxrHlVoltage = '.1.3.6.1.4.1.14988.1.1.3.8.0';

    my $result = $session->get_request(
        -varbindlist => [
            $mtxrHlVoltage,
            $mtxrHlPower,
            $mtxrHlCurrent
        ]
    );
    if(!defined $result) {
        wrap_exit(UNKNOWN, 'Unable to get information');
    }
    my $voltage = $result->{$mtxrHlVoltage};
    if ($voltage ne 'noSuchObject') {
        $voltage /= 10;
        $mp->add_perfdata(
            label     => 'voltage',
            value     => $voltage,
            uom       => ''
        );
        $mp->add_message(OK, 'Voltage: ' . $voltage . 'V');
    }

    my $power_consumption = $result->{$mtxrHlPower};
    if ($power_consumption ne 'noSuchObject') {
        $power_consumption /= 10;
        $mp->add_perfdata(
            label     => 'power-consumption',
            value     => $power_consumption,
            uom       => ''
        );
        $mp->add_message(OK, 'Power consumption: ' . $power_consumption . 'W');
    }
    
    my $current = $result->{$mtxrHlCurrent};
    if ($current ne 'noSuchObject') {
        $mp->add_perfdata(
            label     => 'current',
            value     => $current,
            uom       => ''
        );
        $mp->add_message(OK, 'Current: ' . $current . 'mA');
    }
}

sub check_system
{
    my $mtxrFirmwareVersion = '.1.3.6.1.4.1.14988.1.1.7.4.0';
    my $mtxrFirmwareUpgradeVersion = '.1.3.6.1.4.1.14988.1.1.7.7.0';
    my $mtxrBoardName = '.1.3.6.1.4.1.14988.1.1.7.8.0';

    my $result = $session->get_request(
        -varbindlist => [
            $mtxrFirmwareVersion,
            $mtxrFirmwareUpgradeVersion,
            $mtxrBoardName
        ]
    );
    if(!defined $result) {
        wrap_exit(UNKNOWN, 'Unable to get information');
    }
    my $firmware_version = $result->{$mtxrFirmwareVersion};
    if ($firmware_version ne 'noSuchObject') {
      $mp->add_message(OK, 'Current Firmware: ' . $firmware_version);
    }
    $firmware_version = $result->{$mtxrFirmwareUpgradeVersion};
    if ($firmware_version ne 'noSuchObject') {
      $mp->add_message(OK, 'Upgrade Firmware: ' . $firmware_version);
    }
    my $board_name = $result->{$mtxrBoardName};
    if ($board_name ne 'noSuchObject') {
      $mp->add_message(OK, 'Board: ' . $board_name);
    }
}


sub check_temperature
{
    my $mtxrHlSensorTemperature = '.1.3.6.1.4.1.14988.1.1.3.5.0';
    my $mtxrHlCpuTemperature = '.1.3.6.1.4.1.14988.1.1.3.6.0';
    my $mtxrHlBoardTemperature = '.1.3.6.1.4.1.14988.1.1.3.7.0';
    my $mtxrHlTemperature = '.1.3.6.1.4.1.14988.1.1.3.10.0';
    my $mtxrHlProcessorTemperature = '.1.3.6.1.4.1.14988.1.1.3.11.0';

    my $status = UNKNOWN;
    my %thresholds;

    my $result = $session->get_request(
        -varbindlist => [
            $mtxrHlSensorTemperature,
            $mtxrHlCpuTemperature,
            $mtxrHlBoardTemperature,
            $mtxrHlTemperature,
            $mtxrHlProcessorTemperature,
        ]
    );
    if(!defined $result) {
        wrap_exit(UNKNOWN, 'Unable to get information');
    }
    my $sensor_temperature = $result->{$mtxrHlSensorTemperature};
    if ($sensor_temperature ne 'noSuchObject') {
        $sensor_temperature /= 10.0;
        %thresholds = get_temperature_threshold('sensor');
        $status = $mp->check_threshold(
            check    => $sensor_temperature,
            %thresholds,
        );
        $mp->add_message(
            $status,
            sprintf('Sensor: %.1f°C', $sensor_temperature)
        );
        $mp->add_perfdata(
            label     => 'sensor_temperature',
            value     => $sensor_temperature,
            %thresholds,
        );
    }
    my $cpu_temperature = $result->{$mtxrHlCpuTemperature};
    if ($cpu_temperature ne 'noSuchObject') {
        $cpu_temperature /= 10.0;
        %thresholds = get_temperature_threshold('cpu');
        $status = $mp->check_threshold(
            check    => $cpu_temperature,
            %thresholds,
        );
        $mp->add_message(
            $status,
            sprintf('CPU: %.1f°C', $cpu_temperature)
        );
        $mp->add_perfdata(
            label     => 'cpu_temperature',
            value     => $cpu_temperature,
            %thresholds,
        );
    }
    my $board_temperature = $result->{$mtxrHlBoardTemperature};
    if ($board_temperature ne 'noSuchObject') {
        $board_temperature /= 10.0;
        %thresholds = get_temperature_threshold('board');
        $status = $mp->check_threshold(
            check    => $board_temperature,
            %thresholds,
        );
        $mp->add_message(
            $status,
            sprintf('Board: %.1f°C', $board_temperature)
        );
        $mp->add_perfdata(
            label     => 'board_temperature',
            value     => $board_temperature,
            %thresholds,
        );
    }
    my $env_temperature = $result->{$mtxrHlTemperature};
    if ($env_temperature ne 'noSuchObject') {
        $env_temperature /= 10.0;
        %thresholds = get_temperature_threshold('env');
        $status = $mp->check_threshold(
            check    => $env_temperature,
            %thresholds,
        );
        $mp->add_message(
            $status,
            sprintf('Temperature: %.1f°C', $env_temperature)
        );
        $mp->add_perfdata(
            label     => 'env_temperature',
            value     => $env_temperature,
            %thresholds,
        );
    }
    my $processor_temperature = $result->{$mtxrHlProcessorTemperature};
    if ($processor_temperature ne 'noSuchObject') {
        $processor_temperature /= 10.0;
        %thresholds = get_temperature_threshold('processor');
        $status = $mp->check_threshold(
            check    => $processor_temperature,
            %thresholds,
        );
        $mp->add_message(
            $status,
            sprintf('Processor: %.1f°C', $processor_temperature)
        );
        $mp->add_perfdata(
            label     => 'processor_temperature',
            value     => $processor_temperature,
            %thresholds,
        );


    }
}


sub get_temperature_threshold
{
    my $name = shift;
    my %thresholds = (
        critical => $mp->opts->get('temperature-crit'),
        warning  => $mp->opts->get('temperature-warn'),
    );

    foreach my $threshold (@{$mp->opts->get('temperature-thresholds')}) {
        if($threshold =~ /^(\S+?)(;(\S*?)(;(\S*))?)?$/) {
            if($1 eq $name) {
                if(defined $3) {
                    $thresholds{warning} = $3;
                }
                if(defined $5) {
                    $thresholds{critical} = $5;
                }
            }
        }
    }

    return %thresholds;
}

sub wrap_add_message
{
    my ($check_status, $message, $loop_value) = @_;
    if (defined $loop_value) {
        push @g_long_message, '  * ' . $message;
    }
    if (!defined $loop_value || $check_status != OK) {
        $mp->add_message($check_status, $message);
    }
}

sub wrap_exit
{
    if($pkg_monitoring_available == 1) {
        $mp->plugin_exit( @_ );
    } else {
        $mp->nagios_exit( @_ );
    }
}
