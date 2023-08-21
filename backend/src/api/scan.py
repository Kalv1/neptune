"""scan endpoints"""
import json
import time
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from models import (
    ImageScanRequest,
    Package,
    PackageVersion,
    SBOMJson,
    Tag,
    Vulnerability,
    get_db,
)
from sqlalchemy.orm import Session
from utils import (
    Logger,
    cleanup_images,
    create_statistics,
    grype_report,
    human_readable_size,
    human_readable_time,
    scan_mutex,
    skopeo_pull,
    syft_report,
)

logger = Logger("api")
api_router = APIRouter(prefix='/api')

@api_router.post("/scan", tags=['scanner'])
def scan_image(scan_request: ImageScanRequest, session: Session = Depends(get_db)):
    """add a new image to neptune, or rescan an already inventoried sha."""
    if scan_request.image:
        image = scan_request.image
        logger.info("Processing %s", image)
        t0 = time.time()
        image_uuid = str(uuid4())
        logger.info("pulling image..")
        pull_ok, message = skopeo_pull(image, image_uuid)
        if not pull_ok:
            raise HTTPException(status_code=400, detail=message)
        logger.info("grabbing SBOM")
        syft_report_path, sbom_json = syft_report(image_uuid)
        if not syft_report_path:
            raise HTTPException(status_code=400, detail=sbom_json)
        sbom = [{"name": a['name'],
                "version":a["version"],
                "type":a["type"]}
                for a in sbom_json["artifacts"]]
        logger.info("fetched %s packages", len(sbom))

    elif scan_request.sha:
        spec_image = session.query(Tag).filter(
            Tag.sha == scan_request.sha).first()
        logger.info(f"rescanning {spec_image.image}:{spec_image.tag} ({spec_image.sha})")
        scan_uuid = uuid4()
        syft_report_path = f'/tmp/{scan_uuid}_syftreport.json'
        with open(syft_report_path, 'w+') as f:
            json.dump(spec_image.sbom.sbom, f)


    logger.info("checking vulns")
    grype_ok, vuln_json = grype_report(syft_report_path)
    if not grype_ok:
        raise HTTPException(status_code=400, detail=vuln_json)
    vulns = [{"id": v["vulnerability"]["id"],
              "severity":v["vulnerability"]["severity"],
              "description":v["vulnerability"].get("description", ""),
              "artifact_name":v["artifact"]["name"],
              "artifact_type":v["artifact"]["type"],
              "artifact_version":v["artifact"]["version"]}
             for v in vuln_json["matches"]]
    logger.info("found %s vulns", len(vulns))

    if scan_request.image:
        image_details = vuln_json["source"]["target"]
        image_sha = image_details["imageID"]
        image_size = image_details["imageSize"]
        image_distro = sbom_json["distro"].get(
            "name", "distroless")+":"+sbom_json["distro"].get("versionID", "unknown")
        try:
            image_name, image_tag = image.split(":")
        except ValueError:
            image_name, image_tag = image, "latest"

    cleanup_images()

    # mutex here to avoid race conditions when adding records concurrently
    with scan_mutex:
        if scan_request.image:
            sha_already_scanned = session.query(
                Tag).filter(Tag.sha == image_sha).one_or_none()
            if sha_already_scanned:
                logger.warning(
                    "This image (%s) was already inventoried. deleting the record.", image_sha)
                session.delete(sha_already_scanned)
            # create tag
            s_sbom = SBOMJson(sbom=sbom_json)
            s_image = Tag(tag=image_tag,
                        image=image_name,
                        distro=image_distro,
                        sha=image_sha,
                        size=image_size,
                        sbom=s_sbom,
                        packages=[])

            # packages
            for p in sbom:
                # check for base package
                package = session.query(Package).filter(Package.name == p["name"]).filter(
                    Package.type == p["type"]).one_or_none()

                if not package:
                    package = Package(name=p["name"], type=p["type"])
                    session.add(package)
                # check for version
                if p["version"] not in [p.version for p in package.versions]:
                    version = PackageVersion(version=p["version"])
                    package.versions.append(version)

                else:
                    version = [
                        v for v in package.versions if v.version == p["version"]][0]
                s_image.packages.append(version)

        # vulns
        new_vulns = []
        for v in vulns:
            is_referenced = session.query(Vulnerability).filter(
                Vulnerability.name == v["id"]).one_or_none()
            
            # If it's already referenced, we should update our record in case the severity was disclosed or other information
            # was updated on the CVE DB side
            if not is_referenced:
                logger.info(f"new vuln {v['id']} !")
                # find the linked package
                _, version = session.query(Package, PackageVersion).filter(Package.id == PackageVersion.package_id).filter(
                    Package.name == v["artifact_name"]).filter(Package.type == v["artifact_type"]).filter(PackageVersion.version == v["artifact_version"]).one_or_none()
                if version:
                    v = Vulnerability(name=v["id"], severity=v["severity"])
                    version.vulnerabilities.append(v)
                    version.refresh_outdated_status()
                    session.add(version)
        if scan_request.sha:
            return {'new_vulns': new_vulns}
        session.add(s_image)
        logger.info("commiting to DB")

    # now that we have updated the inventory, tell the client the stats of the image (size,packages, and vulns)
    # return 400 code if the image has active vulnerabilities and the client wants a 400 http error as a signal
    t1 = time.time() - t0
    active_vulns = []
    for package in s_image.packages:
        for v in package.vulnerabilities:
            if v.active:
                active_vulns.append(v.name)
    response = {"image": image_name,
                "tag": image_tag,
                "sha": image_sha,
                "size": human_readable_size(image_size),
                "scan_time": human_readable_time(int(t1)),
                "packages": len(s_image.packages),
                "vulnerabilities": active_vulns}
    create_statistics(session=session)
    return JSONResponse(response, status_code=400 if active_vulns and scan_request.return_error else 200)
