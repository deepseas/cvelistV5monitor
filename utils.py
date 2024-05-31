import datetime
import dateutil.parser
from feedgen.feed import FeedGenerator
import feedparser
import json
import os
from pathlib import Path
from textwrap import wrap
import urllib.parse


def create_feed(vendor, product="all") -> FeedGenerator:
    clean_vendor = vendor.lower().strip()
    safe_vendor = urllib.parse.quote(clean_vendor, safe="")
    clean_product = product.lower().strip()
    safe_product = urllib.parse.quote(clean_product, safe="")
    # create feed
    fg = FeedGenerator()
    if os.path.isfile(f"feeds/{safe_vendor}/{safe_product}.rss"):
        fd = feedparser.parse(f"feeds/{safe_vendor}/{safe_product}.rss")
        fg.title(fd.feed.title)
        fg.link(href=fd.feed.link)
        fg.description(fd.feed.description)
        fg.ttl(fd.feed.ttl)
        for entry in fd.entries:
            pub_date = dateutil.parser.parse(entry.published)
            if datetime.datetime.now(datetime.UTC) - pub_date > datetime.timedelta(
                days=180
            ):
                continue
            fe = fg.add_entry()
            fe.id(entry.id)
            fe.title(entry.title)
            fe.link(href=entry.link)
            fe.description(entry.description)
            fe.published(entry.published)
            fe.updated(entry.updated)
    else:
        fg.title(f"CVE Feed for {vendor} -- {product}")
        fg.link(
            href=f"https://raw.githubusercontent.com/deepseas/cvelistV5monitor/main/feeds/{safe_vendor}/{safe_product}.rss"
        )
        fg.description(
            f"The latest CVEs for {vendor} -- {product if product else 'all products'}"
        )
        fg.ttl(60)

    return fg


def generate_feeds(cve_files):
    feeds = {}
    for cve_file in cve_files:
        with open(cve_file, "r") as f:
            cve = json.load(f)
        if cve["cveMetadata"]["state"] != "PUBLISHED":
            continue

        for affected in cve["containers"]["cna"]["affected"]:
            vendor = affected.get("vendor")
            product = affected.get("product")
            if vendor is None or product is None:
                continue
            # create feed for vendor
            clean_vendor = vendor.lower().strip()
            clean_product = product.lower().strip()
            if clean_vendor not in feeds:
                feeds[clean_vendor] = {"all": create_feed(vendor)}
            if clean_product not in feeds[clean_vendor]:
                feeds[clean_vendor][clean_product] = create_feed(vendor, product)
            fg_all = feeds[clean_vendor]["all"]
            fg_product: FeedGenerator = feeds[clean_vendor][clean_product]
            # id
            cve_id = cve["cveMetadata"]["cveId"]
            entry_id = f"{cve_id}|{cve["cveMetadata"]["dateUpdated"]}"
            # first check if entry exists
            skip_affected = False
            for existing_entry in fg_all.entry():
                if entry_id == existing_entry.id():
                    skip_affected = True
                    break
            if skip_affected:
                continue
            # add entry
            fe_all = fg_all.add_entry()
            fe_product = fg_product.add_entry()
            # title, link, description, updated, published
            entry_title = f"{entry_id} -- {vendor} -- {product}\n"
            entry_link = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
            cve_descriptions = cve["containers"]["cna"].get("descriptions")
            entry_description = "\n".join([desc["value"] for desc in cve_descriptions])
            cve_updated = cve["cveMetadata"]["dateUpdated"]
            cve_published = cve["cveMetadata"].get("datePublished", cve_updated)
            entry_updated = dateutil.parser.parse(cve_updated)
            if entry_updated.tzinfo is None:
                entry_updated = entry_updated.replace(tzinfo=datetime.timezone.utc)
            entry_published = dateutil.parser.parse(cve_published)
            if entry_published.tzinfo is None:
                entry_published = entry_published.replace(tzinfo=datetime.timezone.utc)
            fe_all.id(entry_id)
            fe_all.title(entry_title)
            fe_all.link(href=entry_link)
            fe_all.description(entry_description)
            fe_all.published(entry_published)
            fe_all.updated(entry_updated)
            fe_product.id(entry_id)
            fe_product.title(entry_title)
            fe_product.link(href=entry_link)
            fe_product.description(entry_description)
            fe_product.published(entry_published)
            fe_product.updated(entry_updated)
    for clean_vendor, vendor_feeds in feeds.items():
        for clean_product, feed in vendor_feeds.items():
            safe_vendor = urllib.parse.quote(clean_vendor, safe="")
            safe_product = urllib.parse.quote(clean_product, safe="")
            if len(safe_vendor) > 255:
                vendors = ["v__"+v for v in wrap(safe_vendor, 252)]
                file_safe_vendor = "/".join(vendors)
            else:
                file_safe_vendor = safe_vendor
            if len(safe_product+".rss") > 255:
                products = ["p__"+p for p in wrap(safe_product, 252)]
                file_safe_product_dir = "/".join(products)
                file_safe_product_name = "root.rss"
            else:
                file_safe_product_dir = ""
                file_safe_product_name = safe_product+".rss"
            os.makedirs(os.path.join("feeds", file_safe_vendor, file_safe_product_dir), exist_ok=True)
            rss_filename = os.path.join("feeds", file_safe_vendor, file_safe_product_dir, file_safe_product_name)
            feed.rss_file(rss_filename)


def update_manifest():
    # read through all rss files and build manifest
    manifest = {}
    for f in Path("feeds/").rglob("*.rss"):
        p = f.relative_to("feeds")
        # there are 4 possible cases when it comes to path naming
        # 1. short vendor name, short product name
        # 	path.parts == 2
        # 2. short vendor name, long product name
        # 	p__ prefix will be in some parts
        # 3. long vendor name, short product name
        # 	v__ prefix will be in some parts
        # 4. long vendor name, long product name
        # 	v__ or p__ prefix will be in all parts
        # collect the parts of the vendor and product names into lists
        vendor_parts = []
        product_parts = []
        if len(p.parts) == 2:
            # case 1. is if and only if
            vendor_parts = urllib.parse.unquote(p.parts[0])
            product_parts = urllib.parse.unquote(p.parts[1])
        else:
            # cases 2. - 4.
            # parts are in order and all vendor parts will precede product parts
            for i, part in enumerate(p.parts):
                # vendor part, will happen only for cases 3. and 4.
                if part.startswith("v__"):
                    vendor_parts.append(urllib.parse.unquote(part[3:]))
                # product part, will happen only for cases 2. and 4.
                elif part.startswith("p__"):
                    product_parts.append(urllib.parse.unquote(part[3:]))
                # this is a non-split name, will happen only for cases 2. and 3.
                else:
                    # we now need to identify whether this is case 2. or 3.
                    # case 2. implies the vendor part list will only ever have 0 or 1 elements
                    # since vendor parts precede product parts, if it has 0, then this part is the whole vendor name
                    if len(vendor_parts) == 0:
                        vendor_parts.append(urllib.parse.unquote(part))
                    # otherwise, this is the whole product name and case 3.
                    else:
                        product_parts.append(urllib.parse.unquote(part))
        # convert the lists to strings and add to manifest
        vendor = "".join(vendor_parts)
        product = "".join(product_parts)
        # strip extension
        product = product[:-4]
        if vendor not in manifest:
            manifest[vendor] = []
        if product not in manifest[vendor]:
            manifest[vendor].append(product)
            manifest[vendor].sort()
    # write manifest to file
    with open("feeds/manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)
