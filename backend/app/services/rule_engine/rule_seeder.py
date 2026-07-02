"""Seeds the DB rules table from YAML rule definitions on startup."""

import logging

from sqlalchemy.orm import Session

from app.models.rule import Rule
from app.services.rule_engine.rule_loader import RuleLoader

logger = logging.getLogger(__name__)


def seed_rules(db_session: Session) -> int:
    existing = db_session.query(Rule).count()
    if existing > 0:
        logger.info("RULE_SEEDER: %d rules already in DB, skipping seed", existing)
        return 0

    loader = RuleLoader()
    definitions = loader.load_all()
    if not definitions:
        logger.warning("RULE_SEEDER: no rule definitions found, skipping seed")
        return 0

    count = 0
    for definition in definitions:
        rule = Rule(
            rule_id=definition.rule_id,
            name=definition.name,
            category=definition.category,
            severity=definition.severity,
            description=definition.description,
            remediation=definition.remediation,
            references=definition.references,
        )
        db_session.add(rule)
        count += 1

    db_session.commit()
    logger.info("RULE_SEEDER: seeded %d rules into DB", count)
    return count
