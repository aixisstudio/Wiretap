# Wiretap — Puppet module skeleton (community maintained, help wanted)
# EN: Same three primitives as the Ansible role — deploy the backend
#     tree, render /etc/wiretap/wiretap.toml, manage wiretap.service.
#     Extend with Hiera keys (wiretap::syslog_addr, wiretap::peers…) as
#     your fleet needs; PRs welcome.
# FR: Mêmes trois primitives que le rôle Ansible — déployer le backend,
#     rendre /etc/wiretap/wiretap.toml, gérer wiretap.service. Étendre avec
#     des clés Hiera selon la flotte ; PR bienvenues.
class wiretap (
  String  $install_dir   = '/opt/wiretap',
  String  $config_dir    = '/etc/wiretap',
  String  $user          = 'wiretap',
  Boolean $manage_service = true,
) {
  user { $user:
    ensure     => present,
    system     => true,
    managehome => false,
    shell      => '/usr/sbin/nologin',
  }

  file { [$install_dir, "${install_dir}/backend", $config_dir,
          '/var/lib/wiretap']:
    ensure => directory,
  }

  # EN: Push the checked-out backend/ tree (or swap for a release tarball
  #     via the `source` param of your file resource / an archive module).
  # FR: Pousser l'arbre backend/ (ou un tarball de release via `source`).
  file { "${install_dir}/backend":
    ensure  => directory,
    source  => 'puppet:///modules/wiretap/backend',
    recurse => true,
    owner   => 'root',
    group   => $user,
    mode    => '0644',
  }

  file { "${config_dir}/wiretap.toml":
    ensure  => file,
    content => template('wiretap/wiretap.toml.erb'),
    owner   => 'root',
    group   => $user,
    mode    => '0640',
    notify  => Service['wiretap'],
  }

  file { '/etc/systemd/system/wiretap.service':
    ensure => file,
    source => 'puppet:///modules/wiretap/wiretap.service',
    mode   => '0644',
    notify => Exec['systemd-reload'],
  }

  exec { 'systemd-reload':
    command     => '/bin/systemctl daemon-reload',
    refreshonly => true,
  }

  if $manage_service {
    service { 'wiretap':
      ensure    => running,
      enable    => true,
      subscribe => [File['/etc/systemd/system/wiretap.service'],
                    File["${config_dir}/wiretap.toml"]],
    }
  }
}
