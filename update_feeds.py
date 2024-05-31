from pathlib import Path
import re
import requests
import zipfile

from utils import generate_feeds, update_manifest


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
