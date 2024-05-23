# CVE List V5 Monitor
This repo hosts an automated job that pulls the latest hourly CVE delta from [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) and parses it to look for new or updated CVEs impacting vendors and products listed in the root-level config `config.yaml`.

Anything found of interest is added to an RSS feed hosted in the repo. (??)
