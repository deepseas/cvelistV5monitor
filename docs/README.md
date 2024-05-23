# CVE List V5 Monitor
This repo hosts an automated job that pulls the latest hourly CVE delta from [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) and parses it to create and update an RSS feeds organized by vendor and product.

The `feeds/` directory contains all RSS feed files sorted by vendor and product. All names are encoded in URL escaped format. Use the `raw` view of an RSS file to obtain a URL you can use directly in your RSS reader. The URL should be of the format: `https://raw.githubusercontent.com/deepseas/cvelistV5monitor/main/feeds/{vendor}/{product}.rss`. In addition to RSS feeds for every vendor/product combination, there is also a `all.rss` feed that contains all CVEs for a specific vendor.

Feed items will contain a description of the CVE and will link to the official cve.mitre.org record.