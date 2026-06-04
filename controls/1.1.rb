# encoding: UTF-8

control 'C-1.1' do
  title 'Ensure packages are obtained from authorized repositories'
  desc  "
    Standard Linux distributions, although possessing the requisite packages, often do not have PostgreSQL pre-installed. The installation process includes installing the binaries and the means to generate a data cluster. Package installation should include both the server and client packages. Contribution modules are optional depending upon one's architectural requirements (they are recommended though).

    When obtaining and installing software packages (typically via `dnf` or `apt`), it's imperative that packages are sourced only from valid and authorized repositories. For PostgreSQL, the canonical repositories are the official PostgreSQL YUM repository (yum.postgresql.org) and the official PostgreSQL APT repository (apt.postgresql.org). Your chosen PostgreSQL vendor may offer its own software repositories as well.

    Being open-source, PostgreSQL packages are widely available across the internet through package aggregators and providers. However, using invalid or unauthorized sources for packages can lead to implementing untested, defective, or malicious software. 

    Many organizations choose to implement a local software repository within their organization. Care must be taken to ensure that only valid and authorized packages are downloaded and installed into such local repositories.

    From a security perspective, it's imperative to verify the PostgreSQL binary packages are sourced from a valid software repository. For a complete listing of all PostgreSQL binaries available via configured repositories inspect the output from `dnf provides '*libpq.so'` or `apt-file search /usr/pgsql-18/lib/libpq.so.5`.
  "
  desc  'rationale', "
    Standard Linux distributions, although possessing the requisite packages, often do not have PostgreSQL pre-installed. The installation process includes installing the binaries and the means to generate a data cluster. Package installation should include both the server and client packages. Contribution modules are optional depending upon one's architectural requirements (they are recommended though).

    When obtaining and installing software packages (typically via `dnf` or `apt`), it's imperative that packages are sourced only from valid and authorized repositories. For PostgreSQL, the canonical repositories are the official PostgreSQL YUM repository (yum.postgresql.org) and the official PostgreSQL APT repository (apt.postgresql.org). Your chosen PostgreSQL vendor may offer its own software repositories as well.

    Being open-source, PostgreSQL packages are widely available across the internet through package aggregators and providers. However, using invalid or unauthorized sources for packages can lead to implementing untested, defective, or malicious software. 

    Many organizations choose to implement a local software repository within their organization. Care must be taken to ensure that only valid and authorized packages are downloaded and installed into such local repositories.

    From a security perspective, it's imperative to verify the PostgreSQL binary packages are sourced from a valid software repository. For a complete listing of all PostgreSQL binaries available via configured repositories inspect the output from `dnf provides '*libpq.so'` or `apt-file search /usr/pgsql-18/lib/libpq.so.5`.
  "
  desc  'check', "
    Identify and inspect configured repositories to ensure they are all valid and authorized sources of packages. The following is an example of a simple RHEL 9 install illustrating the use of the `dnf repolist all` command.
    ```
    # whoami
    root
    # dnf repolist all | grep -E 'enabled$'
    rhel-9-for-x86_64-appstream-rpms                   Red Hat Enterprise enabled
    rhel-9-for-x86_64-baseos-rpms                      Red Hat Enterprise enabled
    #
    ```
    Ensure the list of configured repositories only includes organization-approved repositories. If any unapproved repositories are listed, this is a fail.

    To inspect what versions of PostgreSQL packages are currently installed, we can query using the `rpm` commands. As illustrated below, no PostgreSQL packages are installed:
    ```
    # whoami
    root
    # rpm -qa | grep postgres
    #
    ```
    If packages were returned in the above, we can determine from which repo they came by combining `dnf` and `rpm`:
    ```
    # whoami
    root
    # dnf info $(rpm -qa|grep postgres) | grep -E '^Name|^Version|^From'
    Name        : postgresql18
    Version     : 18.0
    From repo   : pgdg18
    Name        : postgresql18-contrib
    Version     : 18.0
    From repo   : pgdg18
    Name        : postgresql18-libs
    Version     : 18.0
    From repo   : pgdg18
    Name        : postgresql18-server
    Version     : 18.0
    From repo   : pgdg18
    ```
    If the expected binary packages are not installed, are not the expected versions, or did not come from an appropriate repo, this is a fail.
  "
  desc  'fix', "
    Alter the configured repositories so they only include valid and authorized sources of packages.

    As an example of adding an authorized repository, we will install the PGDG repository RPM from '[yum.postgresql.org](https://yum.postgresql.org)':
    ```
    # whoami
    root
    # dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm
    Last metadata expiration check: 0:01:35 ago on Mon 03 Oct 2022 01:19:37 PM EDT.
    [snip]
    Installed:
      pgdg-redhat-repo-42.0-64.noarch

    Complete!
    # whoami
    root
    # dnf repolist all | egrep 'enabled$'
    pgdg-common                                        PostgreSQL common  enabled
    pgdg14                                             PostgreSQL 14 for  enabled
    pgdg15                                             PostgreSQL 15 for  enabled
    pgdg16                                             PostgreSQL 16 for  enabled
    pgdg17                                             PostgreSQL 17 for  enabled
    rhel-9-for-x86_64-appstream-rpms                   Red Hat Enterprise enabled
    rhel-9-for-x86_64-baseos-rpms                      Red Hat Enterprise enabled
    ```

    If the version of PostgreSQL installed is not 18.x or they did not come from a valid repository, the packages may be uninstalled using this command:
    ```
    # whoami
    root
    # dnf remove $(rpm -qa|grep postgres)
    ```
    To install the PGDG RPMs for PostgreSQL 18.x, run:
    ```
    # whoami
    root
    # dnf install -y postgresql18-{server,contrib} Installed: postgresql18-18.3-1PGDG.rhel9.x86_64        postgresql18-contrib-18.3-1PGDG.rhel9.x86_64
      postgresql18-libs-18.3-1PGDG.rhel9.x86_64   postgresql18-server-18.3-1PGDG.rhel9.x86_64
    Complete!
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['CM-8 a 1']
  tag cci:                   ['CCI-000389']
  tag cis_number:            '1.1'
  tag cis_rid:               '1.1'
  tag cis_benchmark:         'CIS PostgreSQL Benchmark (v14–v18)'
  tag postgresql_versions:    ['14', '15', '16', '17', '18']
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag inherited_from:           'aws-shared-responsibility'
  tag attestation_references:   ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  tag cis_rule_id:           'SV-0101r1_rule'
  tag cis_version:           '1.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_version   = ['14', '15', '16', '17', '18'].include?(input('postgresql_version').to_s)
  applicable           = applicable_partition && applicable_version

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')}, postgresql_version=#{input('postgresql_version')})") do
    applicable
  end

  uri = input('inherited_evidence_uri', value: '')
  uri = attestation_uri(:leveraged, 'aws-soc2-type2', ext: 'json') if uri.to_s.empty?
  max_age_days = input('leveraged_evidence_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'AWS shared-responsibility evidence (no leveraged source configured)' do
      skip 'inherited-from-aws: set leveraged_evidence_base / inherited_evidence_uri to the pulled AWS evidence manifest (SOC 2 / FedRAMP / ISO), or `saf attest apply`.'
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "AWS shared-responsibility leveraged evidence (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "evidence unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current within #{max_age_days}d") { expect(doc.current?).to eq(true) }
    end
  end
end