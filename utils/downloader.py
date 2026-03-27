import os
import requests # type: ignore
import tarfile
import zipfile
import tempfile
import shutil
from pathlib import Path

class PackageDownloader:
    def __init__(self, base_temp_dir=None):
        self.base_temp_dir = base_temp_dir or tempfile.gettempdir()

    def download_npm(self, package_name):
        """Fetch package from npm registry."""
        url = f"https://registry.npmjs.org/{package_name}"
        response = requests.get(url)
        if response.status_code != 200:
            raise Exception(f"Npm package {package_name} not found.")
        
        data = response.json()
        latest_version = data.get('dist-tags', {}).get('latest')
        if not latest_version:
            raise Exception(f"Could not find latest version for npm package {package_name}.")
        
        tarball_url = data['versions'][latest_version]['dist']['tarball']
        return self._download_and_extract(tarball_url, "npm", package_name)

    def download_pypi(self, package_name):
        """Fetch package from PyPI registry."""
        url = f"https://pypi.org/pypi/{package_name}/json"
        response = requests.get(url)
        if response.status_code != 200:
            raise Exception(f"PyPI package {package_name} not found.")
        
        data = response.json()
        urls = data.get('urls', [])
        sdist_url = None
        for u in urls:
            if u['packagetype'] == 'sdist':
                sdist_url = u['url']
                break
        
        if not sdist_url:
            raise Exception(f"Could not find source distribution for PyPI package {package_name}.")
        
        return self._download_and_extract(sdist_url, "pypi", package_name)

    def _download_and_extract(self, url, registry, package_name):
        """Download archive and extract it."""
        dest_dir = Path(self.base_temp_dir) / f"{registry}_{package_name}"
        if dest_dir.exists():
            shutil.rmtree(dest_dir)
        dest_dir.mkdir(parents=True)

        archive_path = dest_dir / "archive"
        response = requests.get(url, stream=True)
        with open(archive_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        # Extract
        if url.endswith('.tar.gz') or url.endswith('.tgz'):
            with tarfile.open(archive_path, "r:gz") as tar:
                tar.extractall(path=dest_dir)
        elif url.endswith('.zip'):
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(dest_dir)
        else:
            # Try tar anyway if extension is unknown but it's a tarball
            try:
                with tarfile.open(archive_path, "r") as tar:
                    tar.extractall(path=dest_dir)
            except:
                raise Exception("Unsupported archive format.")

        # Cleanup archive
        os.remove(archive_path)
        return dest_dir

    def get_source_files(self, directory):
        """Find relevant .js and .py files in the extracted directory."""
        files = []
        for root, _, filenames in os.walk(directory):
            for filename in filenames:
                if filename.endswith(('.py', '.js', 'package.json', 'setup.py')):
                    files.append(Path(root) / filename)
        return files
