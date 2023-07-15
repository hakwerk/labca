# LabCA Docker Only

It is now also possible, instead of dedicating a complete (virtual) machine to LabCA, to run LabCA using docker compose on a non-dedicated machine.

## Startup

The `docker-compose.yml` file is located in the `build` subdirectory for now. You need to export an environment variable LABCA_FQDN with the FQDN (Fully Qualified Domain Name, the name you would use in the browser for accessing the web pages). It it not possible to run LabCA on an IP address only, there must be a DNS mapping present.
```
git clone https://github.com/hakwerk/labca.git
cd labca/build
export LABCA_FQDN=labca.example.com
docker compose up -d
```
And to tail the logs, especially if there are any issues:
```
docker compose logs -f
```

In case you get an error like the after running `docker compose up`:
```
Error response from daemon: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: exec: "labca/entrypoint.sh": stat labca/entrypoint.sh: no such file or directory: unknown
```
then you forgot to export the LABCA_FQDN environment variable.

Installing LabCA in this way saves a lot of time and CPU cycles as in the old method a lot of compiling was done on startup of the containers.
In this version all data is stored in docker volumes and no longer in mapped directories on the host system.

## Migration

If you have an existing VM installation that you would like to convert to the docker-only setup, first export the data from your existing instance: in the left menu in the Admin web gui click "Manage" then on the "Backup" tab click "Backup Now"; wait for the page to reload and then click on the newest file name and download it.

Now install the docker-only setup as described above. On the very first "Create admin account" GUI setup page, click the link "restore from a backup file".
