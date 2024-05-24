# CVE List V5 Monitor
This repo hosts an automated job that pulls the latest hourly CVE delta from [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) and parses it to create and update an RSS feeds organized by vendor and product.

The `feeds/` directory contains all RSS feed files sorted by vendor and product. All names are encoded in URL escaped format. Use the `raw` view of an RSS file to obtain a URL you can use directly in your RSS reader. The URL will be of the format: 

```https://raw.githubusercontent.com/deepseas/cvelistV5monitor/main/feeds/{vendor}/{product}.rss``` 

In addition to RSS feeds for every vendor/product combination, there is also a `all.rss` feed that contains all CVEs for a specific vendor.

Feed items will contain a description of the CVE and will link to the official cve.mitre.org record.

## Manifest of Vendors and Products
There is a `manifest.json` file in the `feeds/` directory which contains a summary list of all vendors and products found in the CVEs. This can be useful in identifying the specific spellings and names used in the feeds.

All vendor and product names are modified from the content of the raw CVE json for the sake of clarity. Specifically, names are made all lower case and leading and trailing whitespace is removed. Some names can be very long and will exceed the maximum length for a file name. These names will be altered in the directory structure to insert a path seperator every 255 characters. For example, the string
```
abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnop
qrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdef
ghijklmnopqrstuvwxyz
```

will be transformed to

```
abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnop
qrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdef
ghijklmnopqrstu/vwxyz
               ^     
```

Product names that are too long will have their name split with path separators and used to create the directories which will contain the `.rss` file. The name of the actual file will `root.rss`. For example, the product name

```
abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnop
qrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdef
ghijklmnopqrstuvwxyz
```

will be transformed to

```
abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnop
qrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdef
ghijklmnopqrstu/vwxyz/root.rss
```
