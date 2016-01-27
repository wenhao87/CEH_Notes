# Notes on Certified Ethical Hacker

## `0x01` Getting Started with Ethical Hacking

### Security Solutions

#### Technologies

* virtual private network (**VPN**), cryptographic protocol
* intrusion detection systems (**IDSs**), intrusion detection systems (**IPSs**), <u>honeypot</u>
* access control lists (**ACLs**), biometrics, smart-cards, ...

#### Administrative Countermeasures

* policies, procedures, rules, ...

#### Physical Measures

* cable locks, device locks, alarm systems, ...

### Early Days Hacking

* 1970s, mainframes on college campuses and corporate environments
* 1980s, PCs
* 1990s, Internet
* 2000~, smartphones, tablets, bluetooth, ...

### Current Developments

#### Malicious Attacks

* Denial-of-Service (**DoS**) attacks, manipulation of stock prices
* identify theft, credit and theft, theft of service
* vandalism, piracy

#### Contributions to the increase in hacking and cybercrime

* amount of information being passed
* overall dependency on the Internet and digital devices
* openness of modern devices (smartphones) and technologies (bluetooth)
* number of Internet-connected devices (tablets, gadgets).

### Famous Hacks

* 1988, Robert T. Morris, first Internet **worm**
* 1999, David L. Smith, **Melissa virus**
* 2001, Jan de Wit, **Anna Kournikova virus**
* 2011, hacking group **Lulzsec**, **Anonymous**

### Generic Examples of Cybercrime

* stealing passwords and usernames / gaining access by using vulnerabilities
* **networking intrusions**: logging into a <u>guest account</u>
* **social engineering**: exploiting by going after <u>human element</u>
* fraud, software piracy, embezzlement, data-diddling
* **malicious code**: viruses, worms, spy-wares, adware, root-kits, other mal-wares
* posting / transmitting illegal material
* unauthorized destruction / alteration
* denial-of-service (**DoS**) / distributed denial-of-service (**DDoS**)

### Evaluation of Hacking

> **Attack Vector** is a path or means by which an attacker gains access to an information system to <u>perform malicious activities</u>.

* **Means**: the ability to carry out
* **Motive**: the reason to be pursuing
* **Opprotunity**: the opening / weakness needed

> Always try to think of **different ways** the situation or technology can be used. Keep **an observant eye** open for weaknesses or vulnerabilities that can be exploited. Train the mind to think **outside the norm**.

### Ethical Hacker

* **Script Kiddies**: limited or no training
* **White-Hat Hackers**: ethical hackers / <u>pen testers</u>
* **Gray-Hat Hackers**: straddle the line between good and bad
* **Black-Hat Hackers**: operate on the opposite of the law
* **Suicide Hackers**: <u>not</u> stealthy
* **Hacktivist**: push / promote a political agenda

> Ethical hackers are **employed** and work **under contract** to carry out their attack **with permission**, without revealing the weaknesses to others. They engage in **penetration testing** / **pen testing** once authorized, by means of investigating, uncovering, attacking, reporting on the strengths and vulnerabilities.

### Penetration Testing

#### Terms in Pen Testing

* **Hack Value**: <u>above-average</u> level of attraction
* **Target of Evaluation** (**TOE**): system / resource being evaluated
* **Attack**: act of targeting and engaging a TOE
* **Exploit**: breach the security
* **Zero Day**: unknown or not addressed threat or vulnerability
* **Security**: state of well-being
* **Threat**: <u>potential</u> violation of security
* **Vulnerability**: <u>weakness</u> in a system
* **Daisy Chaining**: several hacking attacks in sequence

> Security and Convenience often **confict**: the more secure a system becomes, the less convenient it tends to be.

#### Types of Pen Testing

* **Black Box**: little or no knowledge of the target
* **Gray Box**: limited knowledge
* **White Box**: full knowledge

> **IT audit** is used to evaluate and confirm the controls work as advertised, which **covers**: security protocols, software development, administrative policies, and IT governance.

#### Forms of Pen Testing

* **insider attack**: mimic actions by <u>internal</u> parties
* **outsider attack**: mimic actions by <u>outside</u> parties
* **stolen equipment attack**: extract information from equipment
* **social engineering attack**: exploit trust inherent in human nature

### Elements of Information Security

* **<u>C</u>onfidentiality**: by <u>permissions</u> and <u>encryption</u>
* **<u>I</u>ntegrity**: true and correct to its original purposes
* **<u>A</u>vailability**: available to who need to use it

> **Anti-CIA Triad**: disclosure, alteration, disruption

* **Authenticity**
    * quality being genuine or not corrupted from the original
    * biometrics, smart-cards, <u>digital certificates</u>
* **Non-repudiation**
    * cannot deny the authenticity of their <u>signature</u>

### Vulnerability Research

#### Classification of Vulnerability Research

* **severity level**: high, medium or low
* **exploit range**: local or remote

> Vulnerability research **passively** uncovers security issues (system design faults and weaknesses), whereas ethical hacking **actively** looks for the vulnerabilities.

### Hacking Methodologies

* **Footprinting**: gain information via <u>passive methods</u> with <u>minimum</u> interaction
    * WHOIS queries, Google searches
    * job board searches, discussion groups
* **Scanning**: target attack much more precisely
    * ping sweeps, port scans, observations of facilities
    * `nmap`
* **Enumeration**: extract more detailed information to determine its usefulness
    * a list of usernames, groups, applications
    * banner settings, auditing information, ...
* **System Hacking**
    * start choosing user account to attack
    * start crafting an attack based on service information
* **Escalation of Privilege**
    * obtain privileges to administrator or system-level access
* **Covering Tracks**: remove evidence and purge log files
    * **trojans**: destroy the evidence or replace system binaries
    * **rootkits**: automated tools to to hide the presence
    * **steganography**: hide data in images and sound files
    * **tunneling**: carry one transmission protocol over another
* **Planting Backdoors**
    * special accounts, Trojan horses, ...

### Types of Attacks

#### OS Attacks

* **buffer overflow** vulnerabilities
* **bugs** in the OS, **unpatched** OS
* exploit specific <u>network protocol implementations</u>
* attack built-in <u>authentication systems</u>
* break <u>file system</u> security
* crack passwords and encryption mechanisms

> **OS vulnerabilities** are searched and exploited to gain access to a network system.

#### Application-level Attacks

* **buffer overflow** attacks
* Active content, **Cross-site scripting**
* Denial-of-service and SYN attacks
* **SQL injection** attacks, malicious bots, **Phishing**
* **Session hijacking**: when <u>cookieless authentication</u> is enabled
* Man-in-the-middle attacks
* Parameter / form **tampering**, Directory traversal attacks

> Poor or nonexistent **error checking** in applications leads to vulnerabilities.

#### Misconfiguration Attacks

> Misconfigured system (e.g. change in <u>file permission</u>) is no longer secure and may result in <u>illegal access or owning</u> of the system.

#### Shrink wrap code Attacks

> **Default** configuration and settings of the off-the-shelf libraries and code are exploited.

### Security Policies

#### Classification of Security Policies

* **User Policy**: define what kind of <u>user</u> and limitation
    * Password Management Policy
* **IT Policy**: keep the <u>network</u> secure and stable
    * server configuration, patch updates
    * backup policies, modification policies, firewall policies
* **General Policies**: define the responsibility for general <u>business</u> purposes
    * high-level program policy, business continuity plans
    * crisis management, disaster recovery
* **Partner Policy**: defined among a group of <u>partners</u>
* **Issue-specific Policies**: recognize specific areas of concern
    * physical / personnel / communications security policy

#### Types of Security Policies

* **Promiscuous Policy**: <u>no restriction</u> on Internet access
* **Permissive Policy**: only <u>known</u> dangerous services and attacks are blocked
* **Prudent Policy**: with all <u>services blocked</u> and <u>maximum security</u>
* **Paranoid Policy**: <u>strict restriction</u> on system / network usage

#### Examples of Security Polices

* **Acceptable-Use Policy**: acceptable use of system resources
* **User-Account Policy**: authority, rights and responsibilities of user accounts
* **Remote-Access Policy**: remote access users, medium, and security controls
* **Information-Protection Policy**: sensitivity levels of information
* **Firewall-Management Policy**: access, management, and monitoring of firewalls
* **Special-Access Policy**: special access to system resources
* **Network-Connection Policy**: new resources on the network
* **Email Security Policy**: usage of corporate email
* **Password Policy**: strong password protection
