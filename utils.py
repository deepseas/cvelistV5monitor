import datetime
import dateutil.parser
from feedgen.feed import FeedGenerator
import feedparser
import json
import os
from pathlib import Path
import urllib.parse


def create_feed(orig_vendor, orig_product="all") -> FeedGenerator:
    vendor = normalize_name(orig_vendor)
    product = normalize_name(orig_product)
    # a check for None is not necessary since we only pass input from generate_feeds which has already checked for None
    # create feed
    fg = FeedGenerator()
    rss_filename = f"feeds/{vendor}/{product}.rss"
    if os.path.isfile(rss_filename):
        print(f"Loading existing feed {rss_filename}")
        fd = feedparser.parse(rss_filename)
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
        fg.title(f"CVE Feed for {orig_vendor} -- {orig_product}")
        fg.link(
            href=f"https://raw.githubusercontent.com/deepseas/cvelistV5monitor/main/feeds/{vendor}/{product}.rss"
        )
        fg.description(
            f"The latest CVEs for {orig_vendor} -- {orig_product if product != "all" else 'all products'}"
        )
        fg.ttl(60)

    return fg


def generate_feeds(cve_files):
    # {
    #   vendor1: {
    #     all: {
    #       feed: FeedGenerator,
    #       additions: int
    #     },
    #     product1: {
    #       feed: FeedGenerator,
    #       additions: int
    #     }
    #   }
    # }
    feeds = {}
    # l = len(cve_files)
    for i, cve_file in enumerate(cve_files):
        # print(f"{i+1}/{l}", cve_file)
        with open(cve_file, "r") as f:
            cve = json.load(f)
        if cve["cveMetadata"]["state"] != "PUBLISHED":
            continue

        for affected in cve["containers"]["cna"]["affected"]:
            orig_vendor = affected.get("vendor")
            orig_product = affected.get("product")
            vendor = normalize_name(orig_vendor)
            product = normalize_name(orig_product)
            if vendor is None or product is None:
                continue
            # create feed for vendor
            if vendor not in feeds:
                feeds[vendor] = {"all": {"feed": create_feed(orig_vendor), "additions": 0}}
            if product not in feeds[vendor]:
                feeds[vendor][product] = {"feed": create_feed(orig_vendor, orig_product), "additions": 0}
            fg_all: FeedGenerator = feeds[vendor]["all"]["feed"]
            fg_product: FeedGenerator = feeds[vendor][product]["feed"]
            # id
            cve_id = cve["cveMetadata"]["cveId"]
            updated_date = cve["cveMetadata"].get("dateUpdated")
            published_date = cve["cveMetadata"].get("datePublished")
            entry_date = updated_date if updated_date else published_date
            entry_id = f"{cve_id}|{entry_date}"
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
            feeds[vendor]["all"]["additions"] += 1
            fe_product = fg_product.add_entry()
            feeds[vendor][product]["additions"] += 1
            # title, link, description, updated, published
            entry_title = f"{entry_id} -- {vendor} -- {product}\n"
            entry_link = f"https://www.cve.org/CVERecord?id={cve_id}"
            cve_descriptions = cve["containers"]["cna"].get("descriptions")
            raw_entry_description = "\n".join([desc["value"] for desc in cve_descriptions])
            entry_description = ''.join(c for c in raw_entry_description if valid_xml_char_ordinal(c))
            entry_updated = None
            entry_published = None
            cve_updated = cve["cveMetadata"].get("dateUpdated")
            cve_published = cve["cveMetadata"].get("datePublished", cve_updated)
            if cve_updated:
                entry_updated = dateutil.parser.parse(cve_updated)
                if entry_updated.tzinfo is None:
                    entry_updated = entry_updated.replace(tzinfo=datetime.timezone.utc)
            if cve_published:
                entry_published = dateutil.parser.parse(cve_published)
                if entry_published.tzinfo is None:
                    entry_published = entry_published.replace(tzinfo=datetime.timezone.utc)
            fe_all.id(entry_id)
            fe_all.title(entry_title)
            fe_all.link(href=entry_link)
            fe_all.description(entry_description)
            if entry_published:
                fe_all.published(entry_published)
            if entry_updated:
                fe_all.updated(entry_updated)
            fe_product.id(entry_id)
            fe_product.title(entry_title)
            fe_product.link(href=entry_link)
            fe_product.description(entry_description)
            if entry_published:
                fe_product.published(entry_published)
            if entry_updated:
                fe_product.updated(entry_updated)
    for vendor, products in feeds.items():
        # str, {all: {feed: FeedGenerator, additions: int}, product1: {feed: FeedGenerator, additions: int}}
        for product, feed_info in products.items():
            # str, {feed: FeedGenerator, additions: int}
            feed = feed_info["feed"]
            additions = feed_info["additions"]
            if additions == 0:
                continue
            os.makedirs(os.path.join("feeds", vendor), exist_ok=True)
            rss_filename = f"feeds/{vendor}/{product}.rss"
            try:
                feed.rss_file(rss_filename, pretty=True)
            except Exception as e:
                print(f"Error writing feed to {rss_filename}: {e}")
                continue


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
            for part in p.parts:
                # skip root.rss part
                if part == "root.rss":
                    continue
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
                        vendor_parts.append(part)
                    # otherwise, this is the whole product name and case 3.
                    else:
                        product_parts.append(part)
        # convert the lists to strings and add to manifest
        vendor = "".join(vendor_parts)
        vendor = urllib.parse.unquote(vendor)
        product = "".join(product_parts)
        product = product[:-4]
        product = urllib.parse.unquote(product)
        if vendor not in manifest:
            manifest[vendor] = []
        if product not in manifest[vendor] and product != "all":
            manifest[vendor].append(product)
            manifest[vendor].sort()
    # write manifest to file
    with open("feeds/manifest.json", "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)


def normalize_name(name):
    if name is None or name == "n/a":
        return None
    clean_name = urllib.parse.quote(name.lower().strip(), safe="")[:250]
    if clean_name:
        return clean_name
    else:
        return None


def valid_xml_char_ordinal(c):
    codepoint = ord(c)
    return (
            0x20 <= codepoint <= 0xD7FF or
            codepoint in (0x9, 0xA, 0xD) or
            0xE000 <= codepoint <= 0xFFFD or
            0x10000 <= codepoint <= 0x10FFFF
    )
