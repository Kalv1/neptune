"""ressources management endpoints (tags, vulns, packages)"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from enum import Enum
from models import (
    HistoricalStatistics,
    Package,
    PackagePut,
    RegistryConfig,
    RegistryConfigRequest,
    Tag,
    Vulnerability,
    VulnPut,
    get_db,
)
from sqlalchemy.orm import Session
from utils import (
    Logger,
    create_statistics,
    database_housekeeping,
    paginate_query,
    pagination,
    skopeo_login,
)

logger = Logger("api")

api_router = APIRouter(prefix='/api')

@api_router.post("/registries", tags=['registries'])
def post_config(new_config: RegistryConfigRequest, session: Session = Depends(get_db)):
    """add a new registry login for skopeo
    it will try to log in with the provided credentials. 200 if it succeeded, 400 otherwise"""
    auth_ok, message = skopeo_login(new_config.registry, new_config.user, new_config.password)
    if auth_ok:
        registry_conf = session.query(RegistryConfig).get(new_config.registry)
        if registry_conf:
            registry_conf.url = new_config.registry
            registry_conf.user = new_config.user
            registry_conf.password = new_config.password
        else:
            registry_conf = RegistryConfig(
                url=new_config.registry, user=new_config.user, password=new_config.password)
        session.add(registry_conf)
        return {"message": message}
    raise HTTPException(status_code=400, detail=message)


@api_router.delete("/registries", tags=['registries'])
def delete_config(registry_url:str, session: Session = Depends(get_db)):
    """get the current registries configs"""
    if registry_config := session.query(RegistryConfig).get(registry_url):
        session.delete(registry_config)
        return JSONResponse(content={}, status_code=204)
    raise HTTPException(404,"config does not exists")


@api_router.get("/registries", tags=['registries'])
def get_config(pg=Depends(pagination),session: Session = Depends(get_db)):
    """get the current registries configs"""
    return paginate_query(session.query(RegistryConfig),pg)


@api_router.get("/historical-stats", tags=['stats'])
def statistics(session: Session = Depends(get_db), last: bool = False):
    """statistics about the inventory
    if last is True, only returns the last element
    """
    if last:
        last_stat_json = session.query(HistoricalStatistics).order_by(HistoricalStatistics.timestamp.asc()).first().serialize()
        last_stat_json.pop("timestamp")
        last_stat_json["severities"] = {k: session.query(Vulnerability).filter(Vulnerability.severity == k).count(
        ) for k in ["Low", "Medium", "High", "Critical"]} # "Negligible", "Unknown"
        return last_stat_json
    stats = session.query(HistoricalStatistics).order_by(HistoricalStatistics.timestamp.asc()).all()
    return [s.serialize() for s in stats]


@api_router.get("/tags", tags=['images'])
def get_all_tags(pg=Depends(pagination), session: Session = Depends(get_db), name_filter: str = None, tag_filter: str = None,distro_filter: str = None):
    """list of tags"""
    filters = []
    if tag_filter:
        filters.append(Tag.tag.ilike(f"%{tag_filter}%"))
    if name_filter:
        filters.append(Tag.image.ilike(f"%{name_filter}%"))
    if distro_filter:
        filters.append(Tag.distro.ilike(f"%{distro_filter}%"))
    query = session.query(Tag).order_by(Tag.date_added.desc()).filter(*filters)
    return paginate_query(query, pg)


@api_router.get("/tags/featured", tags=['images'])
def get_featured_tags(session: Session = Depends(get_db)):
    """returns a curated list of 5 tags:
       ["active_vulnerabilities", "vulnerabilities", "outdated_packages", "packages","most_recent"]
    """
    response = {"most_vulnerabilities": {}, "most_packages": {},
                "most_outdated_packages": {}, "most_active_vulnerabilities": {},"most_recent":{}}
    all_tags = session.query(Tag).all()
    most_recent_tag = session.query(Tag).order_by(Tag.date_added.desc()).first()
    most_recent_tag_serialized = most_recent_tag.serialize()
    for t in all_tags:
        tag = t.serialize()
        for feature in ["active_vulnerabilities", "vulnerabilities", "outdated_packages", "packages"]:
            if tag[feature] > response["most_"+feature].get(feature, -1):
                response["most_"+feature] = tag
    response["most_recent"] = most_recent_tag_serialized
    return response


@api_router.get("/tags/{sha}", tags=['images'])
def get_tag(sha: str, session: Session = Depends(get_db)):
    """specific image:tag"""
    if spec_image := session.query(Tag).filter(Tag.sha == sha).first():
        return spec_image.serialize(full=True)
    raise HTTPException(404,"tag does not exist")

@api_router.delete("/tags/{sha}", tags=['images'])
def delete_tag(sha: str, session: Session = Depends(get_db)):
    if tag := session.query(Tag).filter(Tag.sha == sha).first(): 
        session.delete(tag)
        database_housekeeping()
        create_statistics()
        return {}
    raise HTTPException(404,"tag does not exist")


class Status(str, Enum):
    LOW = 'Low'
    MEDIUM = 'Medium'
    HIGH = 'High'
    CRITICAL = 'Critical'

@api_router.get("/vulnerabilities", tags=['vulnerabilities'])
def all_vulnerabilities(pg=Depends(pagination),session: Session = Depends(get_db), name_filter: str = None, severity_filter: Status = None, notes_filter: str = None, active_filter: bool = None):
    """vulnerabilities interface"""
    filters = []
    if name_filter:
        filters.append(Vulnerability.name.ilike(f"%{name_filter}%"))
    if severity_filter:
        filters.append(Vulnerability.severity.ilike(f"%{severity_filter.value}%"))
    if notes_filter:
        filters.append(Vulnerability.notes.ilike(f"%{notes_filter}%"))
    if active_filter is not None:
        filters.append(Vulnerability.active.is_(active_filter))

    query = session.query(Vulnerability).filter(*filters)
    return paginate_query(query, pg, full_serialize=True)


@api_router.get("/vulnerabilities/{cve_id}", tags=['vulnerabilities'])
def vulnerabilities(cve_id: int, session: Session = Depends(get_db)):
    """vulnerabilities interface"""
    if vuln:=session.query(Vulnerability).filter(Vulnerability.id == cve_id).first():
        return vuln.serialize(True)
    raise HTTPException(404,"vulnerability does not exist")


@api_router.put("/vulnerabilities/{cve_id}", tags=['vulnerabilities'])
def set_vuln_notes(cve_id: int, vuln_def: VulnPut, session: Session = Depends(get_db)):
    """set notes and toggle active boolean for a vuln
    """
    if vuln := session.query(Vulnerability).filter(Vulnerability.id == cve_id).first():
        if vuln_def.notes is not None:
            vuln.notes = vuln_def.notes
        if vuln_def.active is not None:
            vuln.active = vuln_def.active
        session.add(vuln)
        return {}
    raise HTTPException(404,"vulnerability does not exist")


@api_router.get("/packages", tags=['packages'])
def packages(pg=Depends(pagination), session: Session = Depends(get_db), name_filter: str = None, type_filter: str = None, with_outdated_versions: bool = None,with_vulnerable_versions: bool = None):
    """returns all packages that match the filters"""
    filters = []
    if name_filter:
        filters.append(Package.name.ilike(f"%{name_filter}%"))
    if type_filter:
        filters.append(Package.type.ilike(f"%{type_filter}%"))
    if with_outdated_versions is not None:
        filters.append(Package.has_outdated_packages == with_outdated_versions)
    if with_vulnerable_versions is not None:
        filters.append(Package.has_vulnerable_versions == with_vulnerable_versions)
    query = session.query(Package).filter(*filters)
    return paginate_query(query, pg)


@api_router.put("/packages/{package_id}", tags=['packages'])
def set_packages_notes(package_id: int, package_def: PackagePut, session: Session = Depends(get_db)):
    """set minimum required version for a package
    """
    package = session.query(Package).filter(Package.id == package_id).first()
    if not package:
        raise HTTPException(status_code=404, detail="id does not exists")
    if package_def.notes is not None:
        package.notes = package_def.notes
    if package_def.minimum_version:
        package.minimum_version = package_def.minimum_version

        # check for each version if they are now outdated
        for version in package.versions:
            version.outdated = version.is_outdated()
    session.add(package)
    return {}


@api_router.get("/packages/{package_id}", tags=['packages'])
def get_specific_package_versions(package_id: int, session: Session = Depends(get_db)):
    """set minimum required version for a package
    """
    if package:= session.query(Package).filter(Package.id == package_id).first():
        return package.serialize()
    raise HTTPException(404,"package does not exists")
