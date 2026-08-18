"""
Zepy - AI Vulnerability Detection Framework
Rule Manager: Rule registration, search, filtering, and export.
"""

from typing import List, Dict, Optional, Any
from zepy.core.models import Severity, VulnerabilityCategory
from zepy.rules.definitions import RuleDefinition, RULES_DATABASE


class RuleManager:
    def __init__(self):
        self._rules: Dict[str, RuleDefinition] = dict(RULES_DATABASE)

    def get_all_rules(self) -> List[RuleDefinition]:
        """Returns all registered vulnerability rules."""
        return list(self._rules.values())

    def get_rule_by_id(self, rule_id: str) -> Optional[RuleDefinition]:
        """Fetch a specific rule by its identifier."""
        return self._rules.get(rule_id)

    def filter_rules(
        self,
        severity: Optional[Severity] = None,
        category: Optional[VulnerabilityCategory] = None,
        tag: Optional[str] = None,
        keyword: Optional[str] = None,
    ) -> List[RuleDefinition]:
        """Filter rules based on severity, category, tags, or search query."""
        results = []
        for rule in self._rules.values():
            if severity and rule.severity != severity:
                continue
            if category and rule.category != category:
                continue
            if tag and tag.lower() not in [t.lower() for t in rule.tags]:
                continue
            if keyword:
                kw = keyword.lower()
                matches = (
                    kw in rule.id.lower()
                    or kw in rule.title.lower()
                    or kw in rule.description.lower()
                    or kw in rule.cwe_id.lower()
                    or kw in rule.owasp_id.lower()
                )
                if not matches:
                    continue
            results.append(rule)
        return results

    def register_custom_rule(self, rule: RuleDefinition) -> None:
        """Register a user-defined custom vulnerability rule."""
        self._rules[rule.id] = rule

    @property
    def total_count(self) -> int:
        return len(self._rules)
