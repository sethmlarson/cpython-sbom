import datetime
import hashlib
import os
import re
import sys
import tarfile
from dataclasses import dataclass

import spdx_tools.common.spdx_licensing as spdx_license
import spdx_tools.spdx.model as spdx
import spdx_tools.spdx.writer.json.json_writer as spdx_json
import urllib3

CPYTHON_VERSION = "3.11.5"
CPYTHON_TARBALL_FILENAME = f"Python-{CPYTHON_VERSION}.tgz"

NOASSERTION = "NOASSERTION"


@dataclass
class Package:
    name: str
    version: str
    license: str
    license_evidence: str
    primary_package_purpose: spdx.PackagePurpose
    files_include: list[str]
    files_exclude: list[str] | None = None
    files_include_hashes: list[str] = None
    download_url: str | None = None
    download_hash_sha256: str | None = None
    cpes: list[str] = None
    purl: str | None = None
    supplier: spdx.Actor | None = None

    @property
    def spdx_id(self) -> str:
        return spdx_id_escape(f"SPDXRef-PACKAGE-{self.name}-{self.version}")

    def is_contained_file(self, filepath: str) -> bool:
        """
        Determines if a relative filepath is contained within the
        package based on files_include and files_exclude patterns.
        """

        def is_match(pattern: str) -> bool:
            nonlocal filepath
            return (pattern.endswith("/") and filepath.startswith(pattern)) or (
                not pattern.endswith("/") and filepath == pattern
            )

        return any(
            is_match(file_include) for file_include in self.files_include
        ) and not any(
            is_match(file_exclude) for file_exclude in self.files_exclude or ()
        )


PACKAGES = [
    Package(
        name="CPython",
        version=CPYTHON_VERSION,
        license="Python-2.0",
        license_evidence="LICENSE",
        primary_package_purpose=spdx.PackagePurpose.APPLICATION,
        download_url=f"https://www.python.org/ftp/python/{CPYTHON_VERSION}/{CPYTHON_TARBALL_FILENAME}",
        download_hash_sha256="64424e96e2457abbac899b90f9530985b51eef2905951febd935f0e73414caeb",
        cpes=[f"cpe:2.3:a:python:python:{CPYTHON_VERSION}:*:*:*:*:*:*:*"],
        files_include=[],
        supplier=spdx.Actor(spdx.ActorType.ORGANIZATION, name="Python Software Foundation"),
    ),
    Package(
        name="mpdecimal",
        version="2.5.1",
        license="BSD-2-Clause",
        license_evidence=NOASSERTION,
        primary_package_purpose=spdx.PackagePurpose.SOURCE,
        download_url="https://www.bytereef.org/software/mpdecimal/releases/mpdecimal-2.5.1.tar.gz",
        download_hash_sha256="9f9cd4c041f99b5c49ffb7b59d9f12d95b683d88585608aa56a6307667b2b21f",
        cpes=["cpe:2.3:a:bytereef:mpdecimal:2.5.1:*:*:*:*:*:*:*"],
        files_include=["Modules/_decimal/libmpdec/"],
        files_include_hashes=[
            "f86d26a0ada3a757f599453a8f86b46ee29073b85dd228783632aacc00ab9e50"
        ],
        supplier=spdx.Actor(spdx.ActorType.ORGANIZATION, name="bytereef.org"),
    ),
    Package(
        name="tiny_sha3",
        version="dcbb3192047c2a721f5f851db591871d428036a9",
        license="MIT",
        license_evidence="Modules/_sha3/LICENSE",
        primary_package_purpose=spdx.PackagePurpose.SOURCE,
        download_url="https://github.com/mjosaarinen/tiny_sha3/archive/dcbb3192047c2a721f5f851db591871d428036a9.zip",
        download_hash_sha256="9b43effc6c8e234af84fd2367f831a697248191c8fa35c4441bb222924d2836a",
        cpes=["cpe:2.3:a:mjosaarinen:tiny_sha3:dcbb3192047c2a721f5f851db591871d428036a9:*:*:*:*:*:*:*"],
        files_include=["Modules/_sha3/"],
        files_exclude=[
            "Modules/_sha3/clinic/",
            "Modules/_sha3/sha3module.c",
        ],
        files_include_hashes=[
            "9dae1929a47e74039273a530580c8fea2404922f9b34de42eb4dd2f69397b34b"
        ],
        supplier=spdx.Actor(spdx.ActorType.PERSON, name="Markku-Juhani O. Saarinen", email="mjos@iki.fi"),
    ),
    Package(
        name="expat",
        version="2.5.0",
        license="MIT",
        license_evidence="Modules/expat/COPYING",
        primary_package_purpose=spdx.PackagePurpose.SOURCE,
        download_url="https://github.com/libexpat/libexpat/releases/download/R_2_5_0/expat-2.5.0.tar.gz",
        download_hash_sha256="6b902ab103843592be5e99504f846ec109c1abb692e85347587f237a4ffa1033",
        cpes=["cpe:2.3:a:libexpat_project:libexpat:2.5.0:*:*:*:*:*:*:*"],
        files_include=["Modules/expat/"],
        files_include_hashes=[
            "1ce1444111271cc11d71b72c376a17447cf3d3b7dd61a0a01456d2e06faf22e9"
        ],
        supplier=spdx.Actor(spdx.ActorType.ORGANIZATION, name="Expat development team"),
    ),
    Package(
        name="macholib",
        version="1.0",
        download_url="https://svn.red-bean.com/bob/macholib/tags/macholib-1.0/",
        license="MIT OR PSF-2.0",
        license_evidence=NOASSERTION,
        primary_package_purpose=spdx.PackagePurpose.SOURCE,
        purl="pkg:pypi/macholib@1.0",
        files_include=["Lib/ctypes/macholib/"],
        files_exclude=["Lib/ctypes/macholib/README.ctypes"],
        files_include_hashes=[
            "59aa1f3194df7ebe23b0a821cb502b112032fc2e91470a04585d04c2ee63b3b5"
        ],
        supplier=spdx.Actor(spdx.ActorType.PERSON, name="Ronald Oussoren", email="ronaldoussoren@mac.com"),
    ),
    Package(
        name="libffi",
        version="1.20",
        download_url="https://github.com/libffi/libffi",
        license="MIT",
        license_evidence=NOASSERTION,
        primary_package_purpose=spdx.PackagePurpose.SOURCE,
        cpes=["cpe:2.3:a:libffi_project:libffi:1.20:*:*:*:*:*:*:*"],
        files_include=["Modules/_ctypes/libffi_osx/"],
        files_include_hashes=[
            "2720798b5a98d9b5c8a4d88144670b8c63f3ae92ef26491661350720094f5833"
        ],
        supplier=spdx.Actor(spdx.ActorType.PERSON, name="Ronald Oussoren", email="ronaldoussoren@mac.com"),
    ),
    Package(
        name="pip",
        version="23.2.1",
        download_url="https://files.pythonhosted.org/packages/50/c2/e06851e8cc28dcad7c155f4753da8833ac06a5c704c109313b8d5a62968a/pip-23.2.1-py3-none-any.whl",
        download_hash_sha256="7ccf472345f20d35bdc9d1841ff5f313260c2c33fe417f48c30ac46cccabf5be",
        license="MIT",
        license_evidence=NOASSERTION,
        primary_package_purpose=spdx.PackagePurpose.SOURCE,
        purl="pkg:pypi/pip@23.2.1",
        files_include=["Lib/ensurepip/_bundled/pip-23.2.1-py3-none-any.whl"],
        files_include_hashes=[
            "e3d26a8c958c7b53a243a24913fded4d4e7000dcf58a628d1d9c35111713c1a1"
        ],
        supplier=spdx.Actor(spdx.ActorType.ORGANIZATION, name="Python Packaging Authority")
    ),
    Package(
        name="setuptools",
        version="65.5.0",
        download_url="https://files.pythonhosted.org/packages/bb/26/7945080113158354380a12ce26873dd6c1ebd88d47f5bc24e2c5bb38c16a/setuptools-68.2.2-py3-none-any.whl",
        download_hash_sha256="b454a35605876da60632df1a60f736524eb73cc47bbc9f3f1ef1b644de74fd2a",
        license="MIT",
        license_evidence=NOASSERTION,
        primary_package_purpose=spdx.PackagePurpose.SOURCE,
        purl="pkg:pypi/setuptools@65.5.0",
        files_include=["Lib/ensurepip/_bundled/setuptools-65.5.0-py3-none-any.whl"],
        files_include_hashes=[
            "fe039e3aa4ac3550aa63c80b2ee9af608bb6b53abed32fc5ec3bca1b859694c0"
        ],
        supplier=spdx.Actor(spdx.ActorType.ORGANIZATION, name="Python Packaging Authority")
    ),
    Package(
        name="libb2",
        version="0.98.1",
        download_url="https://github.com/BLAKE2/libb2/releases/download/v0.98.1/libb2-0.98.1.tar.gz",
        download_hash_sha256="53626fddce753c454a3fea581cbbc7fe9bbcf0bc70416d48fdbbf5d87ef6c72e",
        license="CC0-1.0",
        license_evidence=NOASSERTION,
        primary_package_purpose=spdx.PackagePurpose.SOURCE,
        cpes=["cpe:2.3:a:blake2:libb2:0.98.1:*:*:*:*:*:*:*"],
        files_include=["Modules/_blake2/impl/"],
        files_include_hashes=[
            "8e7205846d00022f568480d9ed6ddc5d3de47cc5a658ca04747a3eb8003fa498"
        ],
        supplier=spdx.Actor(spdx.ActorType.ORGANIZATION, name="BLAKE2 — fast secure hashing")
    ),
]
PACKAGES[1:] = sorted(PACKAGES[1:], key=lambda pkg: pkg.name)

# Used for tracking all file checksums of 'included' files for non-CPython
# packages. These checksums eventually get used to detect when a package
# has been upgraded by core developers.
PACKAGES_TO_FILE_CHECKSUMS = {}

# Assert that the 'root' package is indeed CPython.
CPYTHON_PACKAGE = PACKAGES[0]
assert CPYTHON_PACKAGE.name == "CPython"


def package_to_verification_code(package: Package) -> str:
    # https://spdx.github.io/spdx-spec/v2.3/package-information/#791-description
    # for SPDX PackageVerificationCode algorithm
    pkg_file_checksums = PACKAGES_TO_FILE_CHECKSUMS.get(package.spdx_id, [])
    file_sha1s = [checksums.get("sha1") for checksums in pkg_file_checksums]
    file_sha1s.sort()
    sha1_combined = ''.join(file_sha1s)
    return hashlib.sha1(sha1_combined.encode()).hexdigest()  # nosec


def package_to_spdx_package(package: Package) -> spdx.Package:
    external_references = []
    if package.cpes:
        for cpe in package.cpes:
            assert cpe.startswith("cpe:2.3")
            external_references.append(
                spdx.ExternalPackageRef(
                    spdx.ExternalPackageRefCategory.SECURITY, "cpe23Type", cpe
                )
            )

    if package.purl:
        external_references.append(
            spdx.ExternalPackageRef(
                spdx.ExternalPackageRefCategory.PACKAGE_MANAGER, "purl", package.purl
            )
        )

    checksums = []
    if package.download_hash_sha256 is not None:
        checksums.append(
            spdx.Checksum(spdx.ChecksumAlgorithm.SHA256, package.download_hash_sha256)
        )

    verification_code = package_to_verification_code(package)
    spdx_verification_code = spdx.PackageVerificationCode(verification_code, package.files_exclude)

    return spdx.Package(
        spdx_id=package.spdx_id,
        name=package.name,
        version=package.version,
        download_location=package.download_url,
        checksums=checksums,
        verification_code=spdx_verification_code,
        license_concluded=spdx_license.spdx_licensing.parse(package.license),
        external_references=external_references,
        primary_package_purpose=package.primary_package_purpose,
        supplier=package.supplier
    )


def spdx_id_escape(spdx_id: str) -> str:
    return re.sub(r"[^a-zA-Z0-9.-]", "-", spdx_id)


def main() -> int:
    # Download the tarball if it's not already downloaded.
    if not os.path.exists(CPYTHON_TARBALL_FILENAME):
        resp = urllib3.request(
            "GET", CPYTHON_PACKAGE.download_url, preload_content=False
        )
        if resp.status != 200:
            print("Couldn't retrieve CPython tarball")
            return 1

        hashobj = hashlib.sha256()
        with open(CPYTHON_TARBALL_FILENAME, "wb") as f:
            f.truncate()
            while chunk := resp.read(16384):
                hashobj.update(chunk)
                f.write(chunk)

        assert (
            hashobj.hexdigest() == CPYTHON_PACKAGE.download_hash_sha256
        ), f"Hash should be {hashobj.hexdigest()}"

    # Extract the tarball
    tarball = tarfile.open(CPYTHON_TARBALL_FILENAME)
    tarball.extractall(".")
    cpython_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), f"Python-{CPYTHON_VERSION}"
    )

    # Create the top-level SBOM object
    sbom = spdx.Document(
        creation_info=spdx.CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name=CPYTHON_TARBALL_FILENAME,
            created=datetime.datetime.now(tz=datetime.timezone.utc),
            document_namespace=f"https://www.python.org/ftp/python/{CPYTHON_VERSION}/{CPYTHON_TARBALL_FILENAME}.spdx.json",
            creators=[spdx.Actor(spdx.ActorType.TOOL, name="cpython-sbom-0.1.0")],
        )
    )

    # Create the 'root' package for CPython
    # using the 'DESCRIBES' relationship type.
    root_package = package_to_spdx_package(CPYTHON_PACKAGE)
    root_package.file_name = CPYTHON_TARBALL_FILENAME
    sbom.packages.append(root_package)
    sbom.relationships.append(
        spdx.Relationship(
            sbom.creation_info.spdx_id,
            spdx.RelationshipType.DESCRIBES,
            root_package.spdx_id,
        )
    )

    # Now for all the files!
    for root, dirs, filenames in os.walk(cpython_dir):
        # We sort for deterministic SBOM builds.
        dirs.sort()
        for filename in sorted(filenames):
            abs_filepath = os.path.join(root, filename)
            rel_filepath = os.path.relpath(abs_filepath, cpython_dir)

            # Find the package SPDXID that matches for the file based
            # on 'files_include' and 'files_exclude' pattern matches.
            file_package_spdx_id = None
            for package in PACKAGES[1:]:
                if package.is_contained_file(rel_filepath):
                    file_package_spdx_id = package.spdx_id
                    break

            if file_package_spdx_id is None:
                file_package_spdx_id = CPYTHON_PACKAGE.spdx_id

            # We calculate SHA256 separately because we're going to add
            # it to the 'package' checksum list for later use.
            sha256_checksum = hashlib.file_digest(
                open(abs_filepath, "rb"), "sha256"
            ).hexdigest()

            sha1_checksum = hashlib.file_digest(
                open(abs_filepath, "rb"), "sha1"
            ).hexdigest()

            # We don't need to track CPython file checksums since
            # the version information is known before downloading the tarball.
            if file_package_spdx_id != CPYTHON_PACKAGE.spdx_id:
                PACKAGES_TO_FILE_CHECKSUMS.setdefault(file_package_spdx_id, []).append({
                        "sha256": sha256_checksum,
                        "sha1": sha1_checksum
                    }
                )

            # Add the SPDX file to the package.
            spdx_file = spdx.File(
                name=rel_filepath,
                spdx_id=spdx_id_escape(f"SPDXRef-FILE-{rel_filepath}"),
                checksums=[
                    spdx.Checksum(
                        spdx.ChecksumAlgorithm.SHA1,
                        sha1_checksum,
                    ),
                    spdx.Checksum(
                        spdx.ChecksumAlgorithm.SHA256,
                        sha256_checksum,
                    ),
                ],
            )
            sbom.files.append(spdx_file)
            sbom.relationships.append(
                spdx.Relationship(
                    file_package_spdx_id,
                    spdx.RelationshipType.CONTAINS,
                    spdx_file.spdx_id,
                )
            )

    # Add all the other packages
    for package in PACKAGES[1:]:
        spdx_package = package_to_spdx_package(package)
        sbom.packages.append(spdx_package)
        sbom.relationships.append(
            spdx.Relationship(
                root_package.spdx_id,
                spdx.RelationshipType.CONTAINS,
                spdx_package.spdx_id,
            )
        )

    # After we have processed all files, now we go back through our packages and double-check
    # that no files have changed since the last time we recorded the 'Package' entry,
    # otherwise we may need to update the version information for the package.
    package_file_hash_differences = []
    for package in PACKAGES[1:]:
        hashobj = hashlib.sha256()
        file_checksums_sorted = sorted(PACKAGES_TO_FILE_CHECKSUMS[package.spdx_id], key=lambda x: x["sha256"])
        for file_hash in file_checksums_sorted:
            hashobj.update(file_hash["sha256"].encode())
        package_file_hash = hashobj.hexdigest()
        if package_file_hash not in (package.files_include_hashes or ()):
            package_file_hash_differences.append((package, package_file_hash))

    if package_file_hash_differences:
        print("There are differences in the file contents of the following packages:")
        for package, package_file_hash in package_file_hash_differences:
            print(
                f"* {package.name} v{package.version} should be {package_file_hash!r}"
            )
        return 1

    # Write out the SBOM as JSON.
    with open(f"sboms/{CPYTHON_TARBALL_FILENAME}.spdx.json", "w") as f:
        f.truncate()
        spdx_json.write_document_to_stream(sbom, f)
    return 0


if __name__ == "__main__":
    sys.exit(main())
