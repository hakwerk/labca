# LabCA

[![Go Report Card](https://goreportcard.com/badge/github.com/hakwerk/labca)](https://goreportcard.com/report/github.com/hakwerk/labca)

**A private Certificate Authority for internal (lab) use, based on the open source ACME Automated Certificate Management Environment implementation from Let's Encrypt (tm).**

![08-dashboard](https://user-images.githubusercontent.com/44847421/48658726-ebd4c400-ea46-11e8-8cb1-43584dbc3719.jpg)

## Table of Contents

- [Background](#background)
- [Startup](#startup)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)
- [Standalone version for step-ca](#standalone-version-for-step-ca)
- [Legacy Mode](#legacy-mode)
- [Contributing](#contributing)
- [License](#license)

## Background

More and more websites and applications are served over HTTPS, where all traffic between your browser and the web server is encrypted. With standard HTTP the (form) data is unencrypted and open to eavesdroppers and hackers listening to communications between the user and the website. Therefore the Chrome browser now even warns about unsafe plain HTTP sites to nudge users towards HTTPS.

To a lesser extent this also applies to internal applications and sites that are not exposed publicly. Just because the users may have a higher level of trust versus users of a public facing website doesn't mean sensitive content shouldn't be protected as much as possible. Lots of hacking and theft occur from within a company's own walls, virtual or real. Also, no user should get used to ignoring any browser warnings (e.g. about self-signed certificates), even for internal sites.

> no user should get used to ignoring any browser warnings

For the public internet, [Let's Encrypt&trade;](https://letsencrypt.org/) has made a big impact by providing free HTTPS certificates in an easy and automated way. There are many clients available to interact with their so called ACME (Automated Certificate Management Environment). They also have a staging environment that allows you to get things right before issuing trusted certificates and reduce the chance of your running up against rate limits.

One technical requirement however is to have a publicly reachable location where your client application and their server can exchange information (for the HTTP-01 challenge type at least, alternatively there is also the DNS-01 method). For intranet / company internal applications or for testing clients within your organization this may not always be feasible.

Luckily they have made the core of their application, called "Boulder", available as [open source](https://github.com/letsencrypt/boulder/). It is possible to install Boulder on your own server and use it internally to hand out certificates. As long as all client machines / laptops in your organization trust your root CA certificate, all certificates it signed are trusted automatically and users see a green lock icon in their browsers.

Also if you are developing your own client application or integrating one into your own application, a local test ACME can be very handy. There is a lot of information on the internet about setting up your own PKI (Public Key Infrastructure) but those are usually not automated.

Getting Boulder up and running has quite a learning curve though and that is where **LabCA** comes in. It is a self-contained installation with a nice web GUI built on top of Boulder so you can quickly start using it. All regular management tasks can be done from the web interface.

## Startup

NOTE: LabCA depends on the boulder engine which cannot run on a Raspberry Pi.

NOTE2: The hostname of your LabCA machine must be in a local DNS for the boulder engine to be able to give out a certificate for it.

Make sure to have docker with the compose plugin installed on the machine where you want to run LabCA, e.g. on Ubuntu/Debian machines do:
```
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
```

For the initial setup you need to export an environment variable LABCA_FQDN with the FQDN (Fully Qualified Domain Name, the name you would use in the browser for accessing the web pages). It is not possible to run LabCA on an IP address only, there must be a DNS mapping present.

```
git clone https://github.com/hakwerk/labca.git
cd labca/build
export LABCA_FQDN=labca.example.com
docker compose up -d
```
To tail the logs, especially if there are any issues:
```
docker compose logs -f
```

All data is stored in docker volumes, you'll want to include those in your regular backups.

In case you get an error like this after running `docker compose up`:
```
Error response from daemon: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: exec: "labca/entrypoint.sh": stat labca/entrypoint.sh: no such file or directory: unknown
```
then you forgot to export the LABCA_FQDN environment variable.

### Setup

After the base install you must go through the setup in your browser. To give an idea of the setup process, see these screenshots:

<img src="https://user-images.githubusercontent.com/44847421/48658719-df506b80-ea46-11e8-9c51-08157a9a8b49.jpg" width="300"> <img src="https://user-images.githubusercontent.com/44847421/48658720-e0819880-ea46-11e8-9fda-8498ca28177d.jpg" width="300"> <img src="https://user-images.githubusercontent.com/44847421/48658721-e24b5c00-ea46-11e8-99ff-f30e0ba3ffe0.jpg" width="300"> <img src="https://user-images.githubusercontent.com/44847421/48658722-e4151f80-ea46-11e8-8b8b-6a0e57620d8c.jpg" width="300"> <img src="https://user-images.githubusercontent.com/44847421/48658723-e6777980-ea46-11e8-99ac-da046807973f.jpg" width="300"> <img src="https://user-images.githubusercontent.com/44847421/48658725-e9726a00-ea46-11e8-814f-4b25e5fc17aa.jpg" width="300">

Once the setup is completed, please make a backup of your Root and Issuer certificates! They can be exported from the "Certificates" tab of the Manage page. On the "Backup" tab you can also create a backup of the relevant data on the server. The backup files should be synchronized to an external location, but that is out of scope of this document.

### Update

By default, the `latest` LabCA docker image version tags are used when you start it. In case there is a newer version of images available, you can update to the new `:latest` versions by doing something like:
```
docker compose pull
docker compose up -d --remove-orphans
docker image prune
```
Or you can use something like [watchtower](https://containrrr.dev/watchtower/) to automatically keep the images updated, or [Diun](https://crazymax.dev/diun/) to inform you about new images.

If you prefer to use specific versions of the images and only update when you explicitly want to, you can set the `LABCA_IMAGE_VERSION` environment variable to an explicit version number. The easiest way to do this is by using a `.env` file in the same location as the `docker-compose.yml` file, e.g. by using something like this:
```
echo "LABCA_IMAGE_VERSION=v25.03" > labca.env
```

## Usage

Once LabCA has been setup, your instance is ready to provide HTTPS certificates for your internal applications.

### Admin

The admin section is only accessible to the user account created at the start of the setup. The [dashboard](https://user-images.githubusercontent.com/44847421/48658726-ebd4c400-ea46-11e8-8cb1-43584dbc3719.jpg) gives an overview of the current status of your LabCA instance. Via the menu you can navigate to the details of your ACME objects such as the certificates, to several system logfiles and to the various management tasks such as backup/restore and changing your password.

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
root@testpki:/home/labca/labca# docker compose ps -a
NAME                IMAGE                               COMMAND                  SERVICE     CREATED        STATUS        PORTS
labca-bconsul-1     hashicorp/consul:1.15.4             "docker-entrypoint.s…"   bconsul     19 hours ago   Up 14 hours   8300-8302/tcp, 8500/tcp, 8301-8302/udp, 8600/tcp, 8600/udp
labca-bmysql-1      mariadb:10.5                        "docker-entrypoint.s…"   bmysql      15 hours ago   Up 14 hours   3306/tcp
labca-boulder-1     hakwerk/labca-boulder:latest        "labca/entrypoint.sh"    boulder     15 hours ago   Up 14 hours   0.0.0.0:4001-4003->4001-4003/tcp, [::]:4001-4003->4001-4003/tcp
labca-bpkimetal-1   ghcr.io/pkimetal/pkimetal:v1.19.0   "/app/pkimetal"          bpkimetal   15 hours ago   Up 14 hours
labca-bredis-1      redis:6.2.7                         "docker-entrypoint.s…"   bredis      15 hours ago   Up 14 hours   6379/tcp
labca-control-1     hakwerk/labca-control:latest        "./control.sh"           control     15 hours ago   Up 14 hours   3030/tcp
labca-gui-1         hakwerk/labca-gui:latest            "bin/labca-gui"          gui         15 hours ago   Up 14 hours   3000/tcp
labca-nginx-1       nginx:latest                        "/docker-entrypoint.…"   nginx       15 hours ago   Up 14 hours   0.0.0.0:80->80/tcp, [::]:80->80/tcp, 0.0.0.0:443->443/tcp, [::]:443->443/tcp
```

Some log files to check in case of issues are (all commands should be run from the directory where the `docker-compose.yml` is located):
* docker compose exec control cat /etc/nginx/ssl/certbot.log
* docker compose exec control cat /opt/logs/commander.log (if it exists)
* docker compose logs control
* docker compose logs boulder
* docker compose logs labca
* (possibly) docker compose logs nginx

### Common error messages

If you get "**No valid IP addresses found for <hostname>**" in certbot.log, solve it by entering the hostname in your local DNS. Same for "**Could not resolve host: <hostname>**" in one of those docker compose logs.

When issuing a certificate, LabCA/boulder checks for CAA (Certification Authority Authorization) records in DNS, which specify what CAs are allowed to issue certificates for the domain. If you get an error like "**SERVFAIL looking up CAA for internal**" or "**CAA record for ca01.foo.internal prevents issuance**", you can try to add something like this to your DNS domain:
```
foo.internal. CAA 0 issue "foo.internal"
```
The value in the issue field should be the domain of your LabCA instance, not the hostname. This value can be found in the issuerDomain property in the va.json file:
```
docker compose exec boulder grep "issuerDomain" /opt/boulder/labca/config/va.json
```
See also the [Let's Encrypt&trade; page on CAA](https://letsencrypt.org/docs/caa/).

If all seems to be working at first, but you hit the **rate limit** after successfully issueing two certificates, make sure that in your list of whitelisted/lockdown domains (in the Manage section on the Config tab) you include all the subdomains that you want to use. So if you want to issue for `abc.dev.lan` and `def.dev.lan`, as well as `xyz.home.lan`, then you should include both `dev.lan` and `home.lan`. Only using `lan` in this example will trigger that rate limit.

When importing an existing CA certificate as the LabCA Root, you may get the error "**The organizationName field is different between CA certificate (MyOrg) and the request (MyOrg)**" when generating the issuing certificate. Although the printed names look identical, this means that on the binary level the imported CA certificate is using PRINTABLESTRING for the organization name where LabCA is using openssl which uses UTF8STRING. You can verify this with the commands `openssl asn1parse -in data/root-ca.pem` and `openssl asn1parse -in data/issuer/ca-int.csr`. You should probably generate the issuer certificate yourself using the existing CA, and then also upload that.

If you get a **failed to load chain.: failed to load certificate "labca/certs/webpki/issuer-01-cert.pem"** in your boulder logs, and **Root key file not present on the system: cannot upgrade automatically!** in the gui logs: in the past it was possible to store the LabCA root private key offline, and only upload it in the GUI for operations that required it. As of version v25.02 this is no longer possible: the root CA key must be present on the system. If you try to upgrade an existing LabCA install that does not have the root CA key online, the upgrade will fail! The solution is to either do a new LabCA install and import the certificates including their keys, or stick with an older version. Changes to the system make it too hard to support having the root CA key offline going forward.

### NOTE

Although LabCA tries to be as robust as possible, use it at your own risk. If you depend on it, make sure that you know what you are doing!

## Standalone version for step-ca

See [README_standalone](README_standalone.md) [![status-experimental](https://img.shields.io/badge/status-experimental-orange.svg)](README_standalone.md)

## Legacy Mode

See [README_legacy](https://github.com/hakwerk/labca/blob/master/README.md) on the `master` branch for the old `install` script installation method.

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
