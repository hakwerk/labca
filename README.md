# LabCA

[![Go Report Card](https://goreportcard.com/badge/github.com/hakwerk/labca)](https://goreportcard.com/report/github.com/hakwerk/labca)

**A private Certificate Authority for internal (lab) use, based on the open source ACME Automated Certificate Management Environment implementation from Let's Encrypt (tm).**

![08-dashboard](https://user-images.githubusercontent.com/44847421/48658726-ebd4c400-ea46-11e8-8cb1-43584dbc3719.jpg)

## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)
- [Standalone version for step-ca](#standalone-version-for-step-ca)
- [Contributing](#contributing)
- [License](#license)

## Background

More and more websites and applications are served over HTTPS, where all traffic between your browser and the web server is encrypted. With standard HTTP the (form) data is unencrypted and open to eavesdroppers and hackers listening to communications between the user and the website. Therefore the Chrome browser now even warns about unsafe plain HTTP sites to nudge users towards HTTPS.

To a lesser extent this also applies to internal applications and sites that are not exposed publicly. Just because the users may have a higher level of trust versus users of a public facing website doesn't mean sensitive content shouldn't be protected as much as possible. Lots of hacking and theft occur from within a company's own walls, virtual or real. Also, no user should get used to ignoring any browser warnings (e.g. about self-signed certificates), even for internal sites.

> no user should get used to ignoring any browser warnings

For the public internet, [Let's Encrypt&trade;](https://letsencrypt.org/) has made a big impact by providing free HTTPS certificates in an easy and automated way. There are many clients available to interact with their so called ACME (Automated Certificate Management Environment). They also have a staging environment that allows you to get things right before issuing trusted certificates and reduce the chance of your running up against rate limits.

One technical requirement however is to have a publicly reachable location where your client application and their server can exchange information. For intranet / company internal applications or for testing clients within your organization this may not always be feasible.

Luckily they have made the core of their application, called "Boulder", available as [open source](https://github.com/letsencrypt/boulder/). It is possible to install Boulder on your own server and use it internally to hand out certificates. As long as all client machines / laptops in your organization trust your root CA certificate, all certificates it signed are trusted automatically and users see a green lock icon in their browsers.

Also if you are developing your own client application or integrating one into your own application, a local test ACME can be very handy. There is a lot of information on the internet about setting up your own PKI (Public Key Infrastructure) but those are usually not automated.

Getting Boulder up and running has quite a learning curve though and that is where **LabCA** comes in. It is a self-contained installation with a nice web GUI built on top of Boulder so you can quickly start using it. All regular management tasks can be done from the web interface. It is best installed in a Virtual Machine and uses Debian Linux as a base.

## Install

NOTE: LabCA depends on the boulder engine which cannot run on a Raspberry Pi.

NOTE2: The hostname of your LabCA machine must be in local DNS for the boulder engine to be able to give out a certificate for it.

**NEW**: It is now possible to run LabCA on an existing docker server, see [README_dockeronly](README_dockeronly.md)

LabCA is best run on its own server / virtual machine to prevent any issues caused by conflicting applications. On a freshly installed Linux machine (currently tested with Debian 12/bookworm, Debian 11/bullseye, and Ubuntu 22.04) run this command as root user (or as a regular user that already is in the sudo group):

```sh
curl -sSL https://raw.githubusercontent.com/hakwerk/labca/master/install | bash
```

Alternatively, clone this git repository and run the install script locally.
Or a combination: run the above curl command, but abort (ctrl-c) the script after the `[✓] Clone https://github.com/hakwerk/labca/ to /home/labca/labca` line (it will be waiting for the FQDN input) so that this repository is cloned in its final location, and then inspect, tweak and/or run the script `/home/labca/labca/install`.

The first-time install will take a while, depending on the power of your server and your internet speed. On my machine it takes about 12 minutes. It will install the latest versions of some packages, download the relevant programs and configure everything. If all goes well it should look like this:

<img src="https://user-images.githubusercontent.com/44847421/48658718-dc557b00-ea46-11e8-8596-00709fad9197.jpg" width="300">

### Setup

After the base install you must go through the setup in your browser. To give an idea of the setup process, see these screenshots:

<img src="https://user-images.githubusercontent.com/44847421/48658719-df506b80-ea46-11e8-9c51-08157a9a8b49.jpg" width="300"> <img src="https://user-images.githubusercontent.com/44847421/48658720-e0819880-ea46-11e8-9fda-8498ca28177d.jpg" width="300"> <img src="https://user-images.githubusercontent.com/44847421/48658721-e24b5c00-ea46-11e8-99ff-f30e0ba3ffe0.jpg" width="300"> <img src="https://user-images.githubusercontent.com/44847421/48658722-e4151f80-ea46-11e8-8b8b-6a0e57620d8c.jpg" width="300"> <img src="https://user-images.githubusercontent.com/44847421/48658723-e6777980-ea46-11e8-99ac-da046807973f.jpg" width="300"> <img src="https://user-images.githubusercontent.com/44847421/48658725-e9726a00-ea46-11e8-814f-4b25e5fc17aa.jpg" width="300">

Once the setup is completed, please make a backup of your Root and Issuer certificates! They can be exported from the "Certificates" tab of the Manage page. On the "Backup" tab you can also create a backup of the relevant data on the server. The backup files should be synchronized to an external location, but that is out of scope of this document.

### Update

When updates are available, this will be indicated on the Dashboard page (System Overview section). They can be installed from the Manage page where you can also manually check for available updates (but this is done regularly automatically).

Updates can also be done from the Linux shell, on the server run this command as root to update the installation:

```sh
~labca/labca/install
```

## Usage

Once LabCA has been setup you should go through the admin pages and e.g. configure the email details for outgoing notifications. Now your instance is ready to provide HTTPS certificates for your internal applications.

### Admin

The admin section is only accessible to the user account created at the start of the setup. The [dashboard](https://user-images.githubusercontent.com/44847421/48658726-ebd4c400-ea46-11e8-8cb1-43584dbc3719.jpg) gives an overview of the current status of your LabCA instance. Via the menu you can navigate to the details of your ACME objects such as the certificates, to several system logfiles and to the various management tasks such as backup/restore, email settings and changing your password.

These screenshots give a preview of the admin section:

<img src="https://user-images.githubusercontent.com/44847421/107797072-cf757e00-6d5a-11eb-8998-4ca00534d36d.png" width="300"> <img src="https://user-images.githubusercontent.com/44847421/107797106-d8fee600-6d5a-11eb-958d-512ddf9ef7ed.png" width="300"> <img src="https://user-images.githubusercontent.com/44847421/107797122-dc926d00-6d5a-11eb-8027-4e3854ce749c.png" width="300"> <img src="https://user-images.githubusercontent.com/44847421/48658728-f0997800-ea46-11e8-8d37-9244086b09d4.jpg" width="300"> <img src="https://user-images.githubusercontent.com/44847421/48658729-f2633b80-ea46-11e8-8fcb-78c273cf914f.jpg" width="300"> <img src="https://user-images.githubusercontent.com/44847421/48658730-f4c59580-ea46-11e8-9d26-8ec6da00c3ad.jpg" width="300">

### ACME Client

To request and automatically renew certificates for your applications, you need one of the many standard ACME clients that are out there. Just make sure to configure the server hostname to be your LabCA instance.

Some of the commonly used clients are:

* [certbot](https://github.com/certbot/certbot)
* [acme-tiny](https://github.com/diafygi/acme-tiny)
* [dehydrated](https://github.com/lukas2511/dehydrated)
* ...

Make sure to configure the client to use the server URL "https://YOUR_LABCA_FQDN/directory".

### Public Pages

The end users in your organization / lab can visit the public pages of you LabCA instance to get some basic information, and to download the root certificate that needs to be installed on each device that should trust the certificates generated by the LabCA instance. To give you and idea of what that looks like:

<img src="https://user-images.githubusercontent.com/44847421/48658731-f727ef80-ea46-11e8-985c-1ea64f340220.jpg" width="300"> <img src="https://user-images.githubusercontent.com/44847421/48658733-fa22e000-ea46-11e8-9fb1-901fddc9ee12.jpg" width="300">

## Troubleshooting

After installing sometimes the application is not starting up properly and it can be quite hard to figure out why.
First, make sure that all six containers are running:
```
root@testpki:/home/labca/boulder# docker compose ps -a
NAME                IMAGE                                           COMMAND                  SERVICE             CREATED             STATUS              PORTS
labca-bconsul-1     hashicorp/consul:1.14.2                         "docker-entrypoint.s…"   bconsul             2 hours ago         Up About an hour    8300-8302/tcp, 8500/tcp, 8301-8302/udp, 8600/tcp, 8600/udp
labca-bmysql-1      mariadb:10.5                                    "docker-entrypoint.s…"   bmysql              2 hours ago         Up About an hour    3306/tcp
labca-boulder-1     letsencrypt/boulder-tools:go1.20.5_2023-06-20   "labca/entrypoint.sh"    boulder             2 hours ago         Up About an hour    4001-4003/tcp
labca-control-1     letsencrypt/boulder-tools:go1.20.5_2023-06-20   "./control.sh"           control             2 hours ago         Up 2 hours          3030/tcp
labca-gui-1         letsencrypt/boulder-tools:go1.20.5_2023-06-20   "./setup.sh"             gui                 2 hours ago         Up 2 hours          3000/tcp
labca-nginx-1       nginx:1.25.1                                    "/docker-entrypoint.…"   nginx               2 hours ago         Up 2 hours          0.0.0.0:80->80/tcp, :::80->80/tcp, 0.0.0.0:443->443/tcp, :::443->443/tcp
```

Some log files to check in case of issues are:
* /home/labca/nginx_data/ssl/acme_tiny.log
* cd /home/labca/boulder; docker compose exec control cat /logs/commander.log (if it exists)
* cd /home/labca/boulder; docker compose logs control
* cd /home/labca/boulder; docker compose logs boulder
* cd /home/labca/boulder; docker compose logs labca
* possibly cd /home/labca/boulder; docker compose logs nginx

### Common error messages

If you get "**No valid IP addresses found for <hostname>**" in /home/labca/nginx_data/ssl/acme_tiny.log, solve it by entering the hostname in your local DNS. Same for "**Could not resolve host: <hostname>**" in one of those docker compose logs.

When issuing a certificate, LabCA/boulder checks for CAA (Certification Authority Authorization) records in DNS, which specify what CAs are allowed to issue certificates for the domain. If you get an error like "**SERVFAIL looking up CAA for internal**" or "**CAA record for ca01.foo.internal prevents issuance**", you can try to add something like this to your DNS domain:
```
foo.internal. CAA 0 issue "foo.internal"
```
The value in the issue field should be the domain of your LabCA instance, not the hostname. This value can be found in the issuerDomain property in the /home/labca/boulder_labca/config/va.json file.
See also the [Let's Encrypt&trade; page on CAA](https://letsencrypt.org/docs/caa/).

If all seems to be working at first, but you hit the **rate limit** after successfully issueing two certificates, make sure that in your list of whitelisted/lockdown domains (in the Manage section on the Config tab) you include all the subdomains that you want to use. So if you want to issue for `abc.dev.lan` and `def.dev.lan`, as well as `xyz.home.lan`, then you should include both `dev.lan` and `home.lan`. Only using `lan` in this example will trigger that rate limit.

When importing an existing CA certificate as the LabCA Root, you may get the error "**The organizationName field is different between CA certificate (MyOrg) and the request (MyOrg)**" when generating the issuing certificate. Although the printed names look identical, this means that on the binary level the imported CA certificate is using PRINTABLESTRING for the organization name where LabCA is using openssl which uses UTF8STRING. You can verify this with the commands `openssl asn1parse -in data/root-ca.pem` and `openssl asn1parse -in data/issuer/ca-int.csr`. You should probably generate the issuer certificate yourself using the existing CA, and then also upload that.

### NOTE

Although LabCA tries to be as robust as possible, use it at your own risk. If you depend on it, make sure that you know what you are doing!

## Standalone version for step-ca

See [README_standalone](README_standalone.md) [![status-experimental](https://img.shields.io/badge/status-experimental-orange.svg)](README_standalone.md)

## Contributing

Feel free to dive in! [Open an issue](https://github.com/hakwerk/labca/issues/new) or submit PRs.

## License

"Commons Clause" License Condition v1.0

The Software is provided to you by the Licensor under the License, as defined below, subject to the following condition.

Without limiting other conditions in the License, the grant of rights under the License will not include, and the License does not grant to you, the right to Sell the Software.

For purposes of the foregoing, "Sell" means practicing any or all of the rights granted to you under the License to provide to third parties, for a fee or other consideration (including without limitation fees for hosting or consulting/ support services related to the Software), a product or service whose value derives, entirely or substantially, from the functionality of the Software. Any license notice or attribution required by the License must also include this Commons Cause License Condition notice.

Software: LabCA

License: [Mozilla Public License 2.0](https://opensource.org/licenses/MPL-2.0)

Licensor: [hakwerk](https://github.com/hakwerk)
