from pathlib import Path

import pytest
import yaml
from muistamo_contracts.v1.agentinstance import AgentInstance
from muistamo_contracts.v1.agenttemplate import AgentTemplate
from muistamo_contracts.v1.knowledgepack import KnowledgePack

EXAMPLES = Path(__file__).parent.parent / "examples"
MODELS = {model.__name__: model for model in (AgentTemplate, AgentInstance, KnowledgePack)}


@pytest.mark.parametrize("path", sorted(EXAMPLES.glob("*.yaml")), ids=lambda p: p.name)
def test_example_validates_against_generated_model(path: Path) -> None:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))

    MODELS[document["kind"]].model_validate(document)


def test_unknown_field_is_rejected() -> None:
    document = yaml.safe_load((EXAMPLES / "knowledgepack.yaml").read_text(encoding="utf-8"))
    document["spec"]["unexpected"] = True

    with pytest.raises(ValueError, match="unexpected"):
        KnowledgePack.model_validate(document)
