"""
SQLite persistence for eUICC state.

Stores eUICC instances, profiles, eIM associations, and notifications
so state survives server restarts.

Uses SQLAlchemy with async SQLite via aiosqlite.
"""

import json
import structlog
from sqlalchemy import (
    Column, String, Integer, Boolean, LargeBinary, Text, ForeignKey,
    create_engine, event,
)
from sqlalchemy.orm import declarative_base, relationship, Session, sessionmaker

logger = structlog.get_logger()
Base = declarative_base()

_engine = None
_SessionLocal = None


# =====================================================================
# ORM Models
# =====================================================================


class DbEuicc(Base):
    __tablename__ = "euiccs"

    eid = Column(String(32), primary_key=True)
    svn = Column(String(10), default="3.1.0")
    profile_version = Column(String(10), default="2.3.1")
    firmware_version = Column(String(10), default="1.0.0")
    platform_label = Column(String(100), default="ConnectX-eUICC-Simulator")
    ipa_mode = Column(Integer, default=0)
    iot_version = Column(String(10), default="1.2.0")
    total_nvm = Column(Integer, default=524288)
    free_nvm = Column(Integer, default=491520)
    default_smdp_address = Column(String(255), default="")
    root_ds_address = Column(String(255), default="")
    max_profiles = Column(Integer, default=8)
    notification_seq = Column(Integer, default=0)

    profiles = relationship("DbProfile", back_populates="euicc", cascade="all, delete-orphan")
    eim_associations = relationship("DbEimAssociation", back_populates="euicc", cascade="all, delete-orphan")


class DbProfile(Base):
    __tablename__ = "profiles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    euicc_eid = Column(String(32), ForeignKey("euiccs.eid"), nullable=False)
    iccid = Column(LargeBinary(10), nullable=False)
    isdp_aid = Column(LargeBinary(16), nullable=False)
    state = Column(String(10), default="disabled")
    profile_name = Column(String(100), default="")
    service_provider_name = Column(String(100), default="")
    profile_nickname = Column(String(100), default="")
    profile_class = Column(String(20), default="operational")
    notification_address = Column(String(255), default="")
    policy_rules = Column(LargeBinary, default=b"")
    profile_data = Column(LargeBinary, default=b"")

    euicc = relationship("DbEuicc", back_populates="profiles")


class DbEimAssociation(Base):
    __tablename__ = "eim_associations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    euicc_eid = Column(String(32), ForeignKey("euiccs.eid"), nullable=False)
    eim_id = Column(String(100), nullable=False)
    eim_fqdn = Column(String(255), default="")
    counter_value = Column(Integer, default=0)
    association_token = Column(Integer, default=0)
    supported_protocol = Column(Integer, default=0)

    euicc = relationship("DbEuicc", back_populates="eim_associations")


# =====================================================================
# Init / Lifecycle
# =====================================================================


async def init_db(database_url: str):
    """Initialize the database and create tables."""
    global _engine, _SessionLocal

    # SQLite with synchronous engine (good enough for simulator)
    db_path = database_url.replace("sqlite:///", "")
    _engine = create_engine(f"sqlite:///{db_path}", echo=False)

    # Enable WAL mode for better concurrent reads
    @event.listens_for(_engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(_engine)
    _SessionLocal = sessionmaker(bind=_engine)

    logger.info("database_initialized", url=database_url)


def get_session() -> Session:
    return _SessionLocal()


# =====================================================================
# Load from DB -> In-Memory
# =====================================================================


async def load_persisted_euiccs(manager):
    """Load all persisted eUICCs into the in-memory manager."""
    from .euicc import (
        EuiccState, ProfileSlot, ProfileState, ProfileClass, EimAssociation,
    )

    if _SessionLocal is None:
        return

    session = get_session()
    try:
        db_euiccs = session.query(DbEuicc).all()
        for db_e in db_euiccs:
            euicc = EuiccState(
                eid=db_e.eid,
                svn=_parse_version(db_e.svn),
                profile_version=_parse_version(db_e.profile_version),
                firmware_version=_parse_version(db_e.firmware_version),
                platform_label=db_e.platform_label,
                ipa_mode=db_e.ipa_mode,
                iot_version=_parse_version(db_e.iot_version),
                total_nvm=db_e.total_nvm,
                free_nvm=db_e.free_nvm,
                default_smdp_address=db_e.default_smdp_address,
                root_ds_address=db_e.root_ds_address,
                max_profiles=db_e.max_profiles,
            )
            euicc._notification_seq = db_e.notification_seq

            for db_p in db_e.profiles:
                profile = ProfileSlot(
                    iccid=db_p.iccid,
                    isdp_aid=db_p.isdp_aid,
                    state=ProfileState(db_p.state),
                    profile_name=db_p.profile_name,
                    service_provider_name=db_p.service_provider_name,
                    profile_nickname=db_p.profile_nickname,
                    profile_class=ProfileClass(db_p.profile_class),
                    notification_address=db_p.notification_address,
                    policy_rules=db_p.policy_rules or b"",
                    profile_data=db_p.profile_data or b"",
                )
                euicc.profiles.append(profile)

            for db_a in db_e.eim_associations:
                assoc = EimAssociation(
                    eim_id=db_a.eim_id,
                    eim_fqdn=db_a.eim_fqdn,
                    counter_value=db_a.counter_value,
                    association_token=db_a.association_token,
                    supported_protocol=db_a.supported_protocol,
                )
                euicc.eim_associations.append(assoc)

            # Initialize PKI for this eUICC
            manager.create_euicc_from_state(euicc)

        logger.info("euiccs_loaded_from_db", count=len(db_euiccs))
    finally:
        session.close()


# =====================================================================
# Persist In-Memory -> DB
# =====================================================================


async def persist_euiccs(manager):
    """Persist all in-memory eUICC state to database."""
    if _SessionLocal is None:
        return

    session = get_session()
    try:
        for eid, instance in manager.instances.items():
            euicc = instance.euicc

            # Upsert eUICC
            db_e = session.query(DbEuicc).filter_by(eid=eid).first()
            if db_e is None:
                db_e = DbEuicc(eid=eid)
                session.add(db_e)

            db_e.svn = _format_version(euicc.svn)
            db_e.profile_version = _format_version(euicc.profile_version)
            db_e.firmware_version = _format_version(euicc.firmware_version)
            db_e.platform_label = euicc.platform_label
            db_e.ipa_mode = euicc.ipa_mode
            db_e.iot_version = _format_version(euicc.iot_version)
            db_e.total_nvm = euicc.total_nvm
            db_e.free_nvm = euicc.free_nvm
            db_e.default_smdp_address = euicc.default_smdp_address
            db_e.root_ds_address = euicc.root_ds_address
            db_e.max_profiles = euicc.max_profiles
            db_e.notification_seq = euicc._notification_seq

            # Replace profiles
            session.query(DbProfile).filter_by(euicc_eid=eid).delete()
            for p in euicc.profiles:
                db_p = DbProfile(
                    euicc_eid=eid,
                    iccid=p.iccid,
                    isdp_aid=p.isdp_aid,
                    state=p.state.value,
                    profile_name=p.profile_name,
                    service_provider_name=p.service_provider_name,
                    profile_nickname=p.profile_nickname,
                    profile_class=p.profile_class.value,
                    notification_address=p.notification_address,
                    policy_rules=p.policy_rules,
                    profile_data=p.profile_data,
                )
                session.add(db_p)

            # Replace eIM associations
            session.query(DbEimAssociation).filter_by(euicc_eid=eid).delete()
            for a in euicc.eim_associations:
                db_a = DbEimAssociation(
                    euicc_eid=eid,
                    eim_id=a.eim_id,
                    eim_fqdn=a.eim_fqdn,
                    counter_value=a.counter_value,
                    association_token=a.association_token,
                    supported_protocol=a.supported_protocol,
                )
                session.add(db_a)

        session.commit()
        logger.info("euiccs_persisted", count=len(manager.instances))
    except Exception as e:
        session.rollback()
        logger.error("persist_failed", error=str(e))
    finally:
        session.close()


# =====================================================================
# Helpers
# =====================================================================


def _parse_version(s: str) -> tuple[int, int, int]:
    parts = s.split(".")
    return (int(parts[0]), int(parts[1]), int(parts[2]))


def _format_version(v: tuple[int, int, int]) -> str:
    return f"{v[0]}.{v[1]}.{v[2]}"
