import os
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config, pool
from alembic import context

# Ajoute le répertoire backend/ au sys.path pour que `from db.tables import metadata` fonctionne
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db.tables import metadata  # noqa: E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# La MetaData SQLAlchemy Core contenant toutes les tables (db/tables.py)
target_metadata = metadata


def _get_url() -> str:
    """
    Lit DATABASE_URL depuis l'env ou alembic.ini (dans cet ordre de priorité).
    L'env a la priorité pour permettre :
      export DATABASE_URL=... && alembic upgrade head
    """
    return os.getenv("DATABASE_URL") or config.get_main_option("sqlalchemy.url", "")


def run_migrations_offline() -> None:
    url = _get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    cfg = config.get_section(config.config_ini_section, {})
    cfg["sqlalchemy.url"] = _get_url()

    connectable = engine_from_config(
        cfg,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
