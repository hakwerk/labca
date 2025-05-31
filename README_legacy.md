# LabCA Legacy Mode

The `install` script method to run LabCA on a dedicated (virtual) machine is no longer updated, but it is still available on the `master` branch.
During installation this method takes a lot of time and CPU cycles as a lot of compiling is done on startup of the containers.

## Install

LabCA is best run on its own server / virtual machine to prevent any issues caused by conflicting applications. On a freshly installed Linux machine (tested with Debian and Ubuntu) run this command as root user (or as a regular user that already is in the sudo group):

```sh
curl -sSL https://raw.githubusercontent.com/hakwerk/labca/master/install | bash
```

Alternatively, clone this git repository, checkout the master branch and run the install script locally.
Or a combination: run the above curl command, but abort (ctrl-c) the script after the `[✓] Clone https://github.com/hakwerk/labca/ to /home/labca/labca` line (it will be waiting for the FQDN input) so that this repository is cloned in its final location, and then inspect, tweak and/or run the script `/home/labca/labca/install`.

The first-time install will take a while, depending on the power of your server and your internet speed. On my machine it takes about 12 minutes. It will install the latest versions of some packages, download the relevant programs and configure everything. If all goes well it should look like this:

<img src="https://user-images.githubusercontent.com/44847421/48658718-dc557b00-ea46-11e8-8596-00709fad9197.jpg" width="300">

Now you can point your browser to the LabCA GUI and setup your instance.

## Migration

If you have an existing VM installation that you would like to convert to the docker-only setup, first export the data from your existing instance: in the left menu in the Admin web gui click "Manage" then on the "Backup" tab click "Backup Now"; wait for the page to reload and then click on the newest file name and download it.

Now install the docker-only setup as described in the main [README](README.md). On the very first "Create admin account" GUI setup page, click the link "restore from a backup file".
