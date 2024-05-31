import datetime
from pathlib import Path
import requests
import zipfile

from utils import generate_feeds, update_manifest


def main():
    # get latest all at midnight release
    latest_release_response = requests.get(
        "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
    )
    latest_release = latest_release_response.json()
    all_asset = {}
    for asset in latest_release["assets"]:
        if "all_CVEs_at_midnight" in asset["name"]:
            all_asset = asset
            break
    download = requests.get(
        all_asset["url"],
        headers={
            "Accept": "application/octet-stream",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        stream=True,
    )
    with open(f"data/{all_asset.get("name")}", "wb") as f:
        f.write(download.content)
    # extract the cves.zip sub-archive
    with zipfile.ZipFile(f"data/{all_asset.get("name")}", "r") as zip_ref:
        zip_ref.extractall(path="data/")
    # extract the cves for this year
    with zipfile.ZipFile("data/cves.zip", "r") as zip_ref:
        all_members = zip_ref.namelist()
        this_year = datetime.datetime.now().year
        this_years_members = [
            m for m in all_members if m.startswith(f"cves/{this_year}/")
        ]
        zip_ref.extractall(path="data/", members=this_years_members)

    # generate feeds
    cve_files = list(Path("data/cves/").rglob("*.json"))
    generate_feeds(cve_files)
    update_manifest()


if __name__ == "__main__":
    main()
