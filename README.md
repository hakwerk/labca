# LabCA
A private Certificate Authority for internal (lab) use, based on the open source ACME Automated Certificate Management Environment implementation from Let's Encrypt (tm).

## About
More and more websites and applications are served over HTTPS, where all traffic between your browser and the web server is encrypted. With standard HTTP the (form) data is unencrypted and open to eavesdroppers and hackers listening to communications between the user and the website. Therefore the Chrome browser now even warns about unsafe plain HTTP sites to nudge users towards HTTPS.

To a lesser extent this also applies to internal applications and sites that are not exposed publicly. Just because the users may have a higher level of trust versus users of a public facing website doesn't mean sensitive content shouldn't be protected as much as possible. Lots of hacking and theft occur from within a company's own walls, virtual or real. Also, no user should get used to ignoring any browser warnings (e.g. about self-signed certificates), even for internal sites.

For the public internet, [Let's Encrypt&trade;](https://letsencrypt.org/) has made a big impact by providing free HTTPS certificates in an easy and automated way. There are many clients available to interact with their so called ACME (Automated Certificate Management Environment). They also have a staging environment that allows you to get things right before issuing trusted certificates and reduce the chance of your running up against rate limits.

One technical requirement however is to have a publicly reachable location where your client application and their server can exchange information. For intranet / company internal applications or for testing clients within your organization this may not always be feasible.

Luckily they have made the core of their application, called "Boulder", available as [open source](https://github.com/letsencrypt/boulder/). It is possible to install Boulder on your own server and use it internally to hand out certificates. As long as all client machines / laptops in your organization trust your root CA certificate, all certificates it signed are trusted automatically and users see a green lock icon in their browsers.

Also if you are developing your own client application or integrating one into your own application, a local test ACME can be very handy. There is a lot of information on the internet about setting up your own PKI (Public Key Infrastructure) but those are usually not automated.

Getting Boulder up and running has quite a learning curve though and that is where **LabCA** comes in. It is a self-contained installation with a nice web GUI built on top of Boulder so you can quickly start using it. All regular management tasks can be done from the web interface. It is best installed in a Virtual Machine and uses Debian Linux as a base.

### NOTE
Although LabCA tries to be as robust as possible, use it at your own risk. If you depend on it, make sure that you know what you are doing!

# License
"Commons Clause" License Condition v1.0

The Software is provided to you by the Licensor under the License, as defined below, subject to the following condition.

Without limiting other conditions in the License, the grant of rights under the License will not include, and the License does not grant to you, the right to Sell the Software.

For purposes of the foregoing, "Sell" means practicing any or all of the rights granted to you under the License to provide to third parties, for a fee or other consideration (including without limitation fees for hosting or consulting/ support services related to the Software), a product or service whose value derives, entirely or substantially, from the functionality of the Software. Any license notice or attribution required by the License must also include this Commons Cause License Condition notice.

Software: LabCA

License: [Mozilla Public License 2.0](https://opensource.org/licenses/MPL-2.0)

Licensor: [hakwerk](https://github.com/hakwerk)
