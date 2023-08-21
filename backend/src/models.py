"""models for the inventory
"""
import re
from datetime import datetime

from pydantic import BaseModel
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    create_engine,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import relationship, sessionmaker

engine = create_engine("sqlite:///data/neptune.db?check_same_thread=false")
SessionLocal = sessionmaker(autoflush=True, bind=engine)

Base = declarative_base()

# transition table because tags and packages versions have a many 2 many relation
_packages = Table('packages_association', Base.metadata,
                  Column('image_id', Integer,
                         ForeignKey('tags.sha')),
                  Column('package_id', Integer,
                         ForeignKey('packageversions.id'))
                  )

# Schema models for pydantic
class Pagination(BaseModel):
    page: int = 1
    per_page:int=20

class ImageScanRequest(BaseModel):
    image: str|None=None
    sha: str|None=None
    return_error:bool|None=None
    
class RegistryConfigRequest(BaseModel):
    registry: str
    user: str
    password: str


class VulnPut(BaseModel):
    notes: str|None=None
    active: bool|None=None


class PackagePut(BaseModel):
    notes: str|None=None
    minimum_version: str|None=None



class HistoricalStatistics(Base):
    """timestamp'd statistics for visualizing trends
    """
    __tablename__ = "historicalstatistics"
    timestamp = Column(DateTime, default=datetime.now, primary_key=True)

    tags_total_count = Column(Integer)
    vulnerable_tags_count = Column(Integer)
    outdated_tags_count = Column(Integer)
    packages_total_count = Column(Integer)
    outdated_packages_count = Column(Integer)
    vulnerable_packages_count = Column(Integer)

    vulnerabilities_total_count = Column(Integer)
    active_vulnerabilities_count = Column(Integer)

    low_vulnerabilities_count = Column(Integer)
    medium_vulnerabilities_count = Column(Integer)
    high_vulnerabilities_count = Column(Integer)
    critical_vulnerabilities_count = Column(Integer)

    def serialize(self):
        return {col.name: getattr(self, col.name) for col in self.__table__.columns}


class RegistryConfig(Base):
    """the configuration for the docker registry to pull from
    """
    __tablename__ = "registryconfig"
    url = Column(String(128), primary_key=True)
    user = Column(String(128))
    password = Column(String(128))

    def serialize(self,full=False):
        return {
            'registry': self.url,
            'user': self.user,
            'password': '*' * len(self.password)
        }


class SBOMJson(Base):
    __tablename__ = "sboms"
    id = Column(Integer, primary_key=True)
    sbom = Column(JSON)
    tag_sha = Column(Integer, ForeignKey('tags.sha'))
    tag = relationship("Tag", back_populates="sbom")


class Tag(Base):
    """A Tag is a specific version of an Image, eg alpine:3.12.

    There might be multiple tags with the same name, like latest, but the sha will be different
    """
    __tablename__ = "tags"
    sha = Column(String(64), primary_key=True)
    image = Column(String(128))
    tag = Column(String(128))
    distro = Column(String(64))
    size = Column(Integer)
    date_added = Column(DateTime, default=datetime.now)
    sbom = relationship("SBOMJson", uselist=False, back_populates="tag")

    # list of packages of that tag
    packages = relationship(
        "PackageVersion", secondary=_packages, back_populates="tags")

    def outdated_packages(self):
        return [p for p in self.packages if p.outdated]

    def has_outdated_packages(self):
        return any([p.outdated for p in self.packages])

    def has_vulnerabilities(self):
        return any(len(p.vulnerabilities) > 0 for p in self.packages)

    def number_of_vulns(self,only_active=False):
        full_vuln_ids = set()
        return sum([len(p.vulnerabilities) for p in self.packages])
        for p in self.packages:
            if only_active:
                full_vuln_ids.update(v.id for v in p.vulnerabilities if v.active)
            else:
                full_vuln_ids.update(v.id for v in p.vulnerabilities)
        return len(full_vuln_ids)
      
    def vulnerabilities(self, only_active=False):
        full_vuln_ids = set()
        full_vulns = []
        for p in self.packages:
            full_vulns += [v for v in p.vulnerabilities]
            if only_active:
                full_vuln_ids.update(
                    [v for v in p.vulnerabilities if v.active])
            else:
                full_vuln_ids.update([v.id for v in p.vulnerabilities])

        full_vulns_filter = list(
            {v.id: v.serialize() for v in full_vulns if v.id in full_vuln_ids}.values())
        return full_vulns_filter

    def serialize(self, full=False):
        spec = {
            "tag": self.tag,
            "sha": self.sha,
            "distro": self.distro,
            "size": self.size,
            "date_added": self.date_added,
            "image": self.image
        }
        if full:  # return the id of each related objects
            packages = self.packages
            vulns = self.vulnerabilities()
            spec.update({"packages": [p.serialize() for p in packages if not p.outdated],
                         "outdated_packages": [p.serialize() for p in packages if p.outdated],
                         "vulnerabilities": [v for v in vulns if not v['active']],
                         "active_vulnerabilities": [v for v in vulns if v['active']]})
        else:  # only return the len of the corresponding objects
            spec.update({"packages": len(self.packages),
                         "outdated_packages": len(self.outdated_packages()),
                         "vulnerabilities": self.number_of_vulns(),
                         'active_vulnerabilities': self.number_of_vulns(True)})
        return spec


class Package(Base):
    """A Package is a python package on which a Tag is dependent. It has a given version.
    """
    __tablename__ = "packages"
    id = Column(Integer, primary_key=True)
    name = Column(String(64))
    type = Column(String(64))
    minimum_version = Column(String(16), default="0.0.0")
    notes = Column(String(256), default="")
    date_added = Column(DateTime, default=datetime.now)

    # list of versions of this package
    versions = relationship("PackageVersion")

    @hybrid_property
    def has_outdated_packages(self):
        return any([p.outdated for p in self.versions])

    @has_outdated_packages.expression
    def has_outdated_packages(cls):
        return cls.versions.any(outdated=True)

    @hybrid_property
    def has_vulnerable_versions(self):
        return any([len(p.vulnerabilities) for p in self.versions])

    @has_vulnerable_versions.expression
    def has_vulnerable_versions(cls):
        return cls.versions.any(has_vulnerabilities=True)


    def serialize(self,full=False):
        return {
            'id': self.id,
            'name': self.name,
            'type': self.type,
            'minimum_version': self.minimum_version,
            'configured': self.minimum_version != '0.0.0',
            'notes': self.notes,
            "date_added": self.date_added,
            'versions': [v.serialize() for v in self.versions]
        }


class PackageVersion(Base):
    __tablename__ = "packageversions"
    id = Column(Integer, primary_key=True)
    version = Column(String(16))
    outdated = Column(Boolean, default=False)

    # to which package does we belong to
    package_id = Column(Integer, ForeignKey('packages.id'))
    package = relationship("Package", back_populates="versions")

    # list of vulns this specific package version has
    vulnerabilities = relationship("Vulnerability")

    # list of tags that have this package version
    tags = relationship("Tag", secondary=_packages, back_populates="packages")

    def refresh_outdated_status(self):
        self.outdated = self.is_outdated()

    @hybrid_property
    def has_vulnerabilities(self):
        return len(self.vulnerabilities) > 0

    @has_vulnerabilities.expression
    def has_vulnerabilities(cls):
        return cls.vulnerabilities.any()


    def is_outdated(self) -> bool:
        """is this specific version < the package minimum version

        the comparison is based on numbers only, grouped by separators being everything __not__ a number.

        Args:
            version_one (str): first version
            version_two (str): second
        """
        version_one_ints = [int(x) for x in re.findall(
            "[0-9]+", self.package.minimum_version)]
        version_two_ints = [int(x) for x in re.findall("[0-9]+", self.version)]

        # r-pad the shortest with 0s
        max_len = max(len(version_one_ints), len(version_two_ints))
        for length in [version_one_ints, version_two_ints]:
            if len(length) < max_len:
                length += [0] * (max_len - len(length))

        first_superior = next(
            (i for i in range(max_len) if version_one_ints[i] > version_two_ints[i]), None)
        first_inferior = next(
            (i for i in range(max_len) if version_one_ints[i] < version_two_ints[i]), None)
        return (first_superior if isinstance(first_superior, int) else max_len) <= (first_inferior if isinstance(first_inferior, int) else max_len)

    def serialize(self, full=False):
        spec = {
            "id": self.id,
            "package": self.package.name,
            "version": self.version,
            "outdated": self.outdated,
        }
        if not full:
            spec["vulnerabilities"] = [
                {"id": v.id, "name": v.name} for v in self.vulnerabilities]
            spec["tags"] = [
                {"sha": t.sha, "name": t.image + ":"+t.tag} for t in self.tags]
        else:
            spec["vulnerabilities"] = [v.serialize()
                                       for v in self.vulnerabilities]
            spec["tags"] = [t.serialize() for t in self.tags]

        return spec


class Vulnerability(Base):
    """A Vulnerability is a potential attribute of a Tag.
    """
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True)
    name = Column(String(64))
    severity = Column(String(64))
    notes = Column(String(1024), default="")
    date_added = Column(DateTime, default=datetime.now)
    active = Column(Boolean, default=True)

    package_id = Column(Integer, ForeignKey('packageversions.id'))
    package = relationship("PackageVersion", back_populates="vulnerabilities")

    def serialize(self, full=False):
        spec = {
            "id": self.id,
            "name": self.name,
            "severity": self.severity,
            "notes": self.notes,
            "active": self.active,
            "affected_package": self.package.id,
        }
        if full:
            spec["affected_images"] = [
                {"sha": t.sha, "name": t.image + ":"+t.tag} for t in self.package.tags]
            spec["affected_package"] = {
                "name": self.package.package.name, "version": self.package.version, "id": self.package.id}
        return spec


def create_db():
    Base.metadata.create_all(engine)


def create_session():
    """creates a sqlalchemy session for tasks and other backend stuff
    """
    db = SessionLocal()
    return db


def get_db():
    """wrapper for creating sessions for requests
    """
    db = SessionLocal()
    try:
        yield db
    except:
        db.rollback()
    finally:
        db.commit()
        db.close()
