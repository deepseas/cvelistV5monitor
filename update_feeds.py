import datetime
import dateutil.parser
from feedgen.feed import FeedGenerator
import feedparser
import os
from pathlib import Path
import re
import requests
import urllib.parse
import zipfile

from feeds import generate_feeds
from update_manifest import update_manifest


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
    with open("data/" + delta_asset.get("name"), "wb") as f:
        f.write(download.content)
    with zipfile.ZipFile("data/" + delta_asset.get("name"), "r") as zip_ref:
        zip_ref.extractall(path="data/")

    # generate feeds
    cve_files = list(Path("data/deltaCves/").rglob("*.json"))
    generate_feeds(cve_files)
    update_manifest()


if __name__ == "__main__":
    main()
