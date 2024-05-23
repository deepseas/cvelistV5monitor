import datetime
import dateutil.parser
from feedgen.feed import FeedGenerator
import feedparser
import json
import os
import re
import requests
import urllib.parse
import zipfile


def create_feed(year, vendor, product="all"):
    # create feed
    fg = FeedGenerator()
    if os.path.isfile(f"feeds/{year}/{vendor}/{product}.rss"):
        fd = feedparser.parse(f"feeds/{year}/{vendor}/{product}.rss")
        fg.title(fd.feed.title)
        fg.link(href=fd.feed.link)
        fg.description(fd.feed.description)
        fg.ttl(fd.feed.ttl)
        for entry in fd.entries:
            fe = fg.add_entry()
            fe.id(entry.id)
            fe.title(entry.title)
            fe.link(href=entry.link)
            fe.description(entry.description)
            fe.published(entry.published)
            fe.updated(entry.updated)
    else:
        fg.title(f"CVE Feed for {vendor} -- {product}")
        fg.link(href=f"https://raw.githubusercontent.com/deepseas/cvelistV5monitor/main/feeds/{year}/{vendor}/{product}.rss")
        fg.description(f"The latest CVEs for {vendor} -- {product if product else 'all products'}")
        fg.ttl(60)

    return fg


def main():
    # get latest release from github
    latest_release_response = requests.get(
        "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
    )
    latest_release = latest_release_response.json()
    body = latest_release.get("body")

    # regex parse number of changes
    p = re.compile(r"(?P<change_count>\d+) changes \(\d+ new \| \d+ updated\)")
    m = p.search(body)
    if m is None:
        print("No match")
        return
    change_count = int(m.group("change_count"))
    if change_count == 0:
        print("No changes")
        return

    # get latest release and extract
    delta_asset = {}
    for asset in latest_release["assets"]:
        if "delta" in asset["name"]:
            delta_asset = asset
            break

    download = requests.get(
        delta_asset["url"],
        headers={
            "Accept": "application/octet-stream",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        stream=True,
    )
    with open(delta_asset.get("name"), "wb") as f:
        f.write(download.content)
    with zipfile.ZipFile(delta_asset.get("name"), "r") as zip_ref:
        zip_ref.extractall()

    # generate feeds
    feeds = {}
    for cve_file in os.listdir("deltaCves"):
        with open(f"deltaCves/{cve_file}", "r") as f:
            cve = json.load(f)
        if cve["cveMetadata"]["state"] != "PUBLISHED":
            continue
        cve_year = cve_file[4:8]
        if cve_year not in feeds:
            feeds[cve_year] = {}
        for affected in cve["containers"]["cna"]["affected"]:
            if affected.get("vendor") is None:
                continue
            # create feed for vendor
            vendor = affected.get("vendor")
            safe_vendor = urllib.parse.quote(vendor, safe="")
            product = affected.get("product")
            safe_product = urllib.parse.quote(product, safe="")
            if vendor not in feeds[cve_year]:
                feeds[cve_year][vendor] = {
                    "all": create_feed(cve_year, safe_vendor)
                }
            if product not in feeds[cve_year][vendor]:
                feeds[cve_year][vendor][product] = create_feed(cve_year, safe_vendor, safe_product)
            fg_all = feeds[cve_year][vendor]["all"]
            fg_product = feeds[cve_year][vendor][product]
            fe_all = fg_all.add_entry()
            fe_product = fg_product.add_entry()
            # id, title, link, description, published, updated
            cve_id = cve["cveMetadata"]["cveId"]
            entry_id = f"{cve["cveMetadata"]["cveId"]}|{cve["cveMetadata"]["dateUpdated"]}"
            cve_descriptions = cve["containers"]["cna"].get("descriptions")
            entry_title = f"{entry_id} -- {vendor} -- {product}\n"
            entry_link = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
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
    for year, year_feeds in feeds.items():
        for vendor, vendor_feeds in year_feeds.items():
            for product, feed in vendor_feeds.items():
                safe_vendor = urllib.parse.quote(vendor, safe="")
                safe_product = urllib.parse.quote(product, safe="")
                os.makedirs(f"feeds/{year}/{safe_vendor}", exist_ok=True)
                feed.rss_file(f"feeds/{year}/{safe_vendor}/{safe_product}.rss")


if __name__ == "__main__":
    main()
