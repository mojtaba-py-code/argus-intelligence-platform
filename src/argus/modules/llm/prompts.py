"""Versioned prompts: ``prompts/<name>/v<N>.yaml``, validated at start-up, rendered safely.

Rules the registry enforces when it loads (a bad prompt stops the process, not a request):

* the file name, ``name`` and ``version`` agree; names and versions are unique;
* ``output_schema`` (optional) is ``module:Class`` inside ``argus`` and resolves to a Pydantic model;
* the **system** template is static - no variables - so nothing a user or a web page supplies can
  ever reach the system prompt (and the prefix stays cacheable);
* the user template only references declared ``input_schema`` variables.

Rendering uses a Jinja2 ``SandboxedEnvironment`` with ``StrictUndefined``; values are type-checked
against ``input_schema`` and string values are Unicode-sanitised. Each rendered prompt carries the
SHA-256 of its text, which the gateway records with every call. Which version is *active* per
environment is data (``prompt_deployments``), so a rollback is an audited update, not a deploy.
"""

from __future__ import annotations

import hashlib
import importlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal, cast

import yaml
from jinja2 import StrictUndefined, TemplateSyntaxError, meta
from jinja2.sandbox import SandboxedEnvironment
from pydantic import BaseModel, ConfigDict, Field

from argus.core.resources import packaged_dir
from argus.modules.llm.types import RenderedPrompt
from argus.security.text import sanitize_text

_FILE: Final = re.compile(r"v([1-9][0-9]{0,3})\.yaml")
_NAME: Final = re.compile(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+")
VariableType = Literal["str", "int", "float", "bool", "list[str]"]
_PYTHON_TYPES: Final[dict[str, tuple[type, ...]]] = {
    "str": (str,),
    "int": (int,),
    "float": (int, float),
    "bool": (bool,),
    "list[str]": (list,),
}


class PromptError(ValueError):
    pass


class PromptFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=_NAME.pattern)
    version: int = Field(ge=1, le=9999)
    task: str = Field(pattern=_NAME.pattern)
    purpose: str = Field(min_length=10, max_length=500)
    input_schema: dict[str, VariableType] = Field(default_factory=dict)
    output_schema: str | None = None
    untrusted_inputs: list[str] = Field(default_factory=list)
    """Documentation of the untrusted parts the caller attaches (never template variables)."""
    system: str = Field(min_length=20)
    user: str = Field(min_length=1)


@dataclass(frozen=True)
class PromptTemplate:
    spec: PromptFile
    output_model: type[BaseModel] | None
    path: Path


def _import_schema(reference: str) -> type[BaseModel]:
    module_name, _, attribute = reference.partition(":")
    if not module_name.startswith("argus.") or not attribute.isidentifier():
        msg = f"output_schema {reference!r} must be 'argus.<module>:<Class>'"
        raise PromptError(msg)
    model = getattr(importlib.import_module(module_name), attribute, None)
    if not (isinstance(model, type) and issubclass(model, BaseModel)):
        msg = f"output_schema {reference!r} is not a Pydantic model"
        raise PromptError(msg)
    return model


class PromptRegistry:
    def __init__(self, templates: dict[tuple[str, int], PromptTemplate]) -> None:
        self._templates = templates
        self._env = SandboxedEnvironment(
            undefined=StrictUndefined, autoescape=False, keep_trailing_newline=False
        )

    # ------------------------------------------------------------------- loading
    @classmethod
    def load(cls, root: Path | None = None) -> PromptRegistry:
        root = root or packaged_dir("prompts")
        env = SandboxedEnvironment(undefined=StrictUndefined, autoescape=False)
        templates: dict[tuple[str, int], PromptTemplate] = {}
        for path in sorted(root.glob("*/v*.yaml")):
            match = _FILE.fullmatch(path.name)
            if match is None:
                msg = f"{path}: prompt files are named v<N>.yaml"
                raise PromptError(msg)
            try:
                spec = PromptFile.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
            except (yaml.YAMLError, ValueError) as exc:
                msg = f"{path}: invalid prompt file: {exc}"
                raise PromptError(msg) from exc
            if spec.name != path.parent.name or spec.version != int(match.group(1)):
                msg = f"{path}: name/version do not match the file location"
                raise PromptError(msg)
            try:
                system_vars = meta.find_undeclared_variables(env.parse(spec.system))
                user_vars = meta.find_undeclared_variables(env.parse(spec.user))
            except TemplateSyntaxError as exc:
                msg = f"{path}: template syntax error: {exc}"
                raise PromptError(msg) from exc
            if system_vars:
                msg = f"{path}: the system prompt must be static (found {sorted(system_vars)})"
                raise PromptError(msg)
            unknown = user_vars - set(spec.input_schema)
            if unknown:
                msg = f"{path}: undeclared template variables {sorted(unknown)}"
                raise PromptError(msg)
            overlap = set(spec.untrusted_inputs) & (set(spec.input_schema) | user_vars)
            if overlap:
                msg = f"{path}: untrusted inputs cannot be template variables: {sorted(overlap)}"
                raise PromptError(msg)
            output_model = _import_schema(spec.output_schema) if spec.output_schema else None
            key = (spec.name, spec.version)
            if key in templates:
                msg = f"{path}: duplicate prompt {spec.name} v{spec.version}"
                raise PromptError(msg)
            templates[key] = PromptTemplate(spec, output_model, path)
        return cls(templates)

    # ------------------------------------------------------------------- queries
    def names(self) -> list[str]:
        return sorted({name for name, _ in self._templates})

    def versions(self, name: str) -> list[int]:
        return sorted(version for prompt, version in self._templates if prompt == name)

    def latest(self, name: str) -> int:
        versions = self.versions(name)
        if not versions:
            msg = f"unknown prompt {name!r}"
            raise PromptError(msg)
        return versions[-1]

    def template(self, name: str, version: int) -> PromptTemplate:
        template = self._templates.get((name, version))
        if template is None:
            msg = f"unknown prompt {name} v{version}"
            raise PromptError(msg)
        return template

    # ----------------------------------------------------------------- rendering
    def render(
        self, name: str, variables: dict[str, Any], *, version: int | None = None
    ) -> RenderedPrompt:
        template = self.template(name, version or self.latest(name))
        spec = template.spec
        values: dict[str, Any] = {}
        for variable, kind in spec.input_schema.items():
            if variable not in variables:
                msg = f"prompt {name} v{spec.version}: missing variable {variable!r}"
                raise PromptError(msg)
            raw: Any = variables[variable]
            if not isinstance(raw, _PYTHON_TYPES[kind]) or (
                kind != "bool" and isinstance(raw, bool)
            ):
                msg = f"prompt {name}: variable {variable!r} must be {kind}"
                raise PromptError(msg)
            if kind == "str":
                values[variable] = sanitize_text(cast("str", raw)).text
            elif kind == "list[str]":
                items = cast("list[Any]", raw)
                if not all(isinstance(item, str) for item in items):
                    msg = f"prompt {name}: variable {variable!r} must be a list of strings"
                    raise PromptError(msg)
                values[variable] = [sanitize_text(item).text for item in items]
            else:
                values[variable] = raw
        extra = set(variables) - set(spec.input_schema)
        if extra:
            msg = f"prompt {name}: unexpected variables {sorted(extra)}"
            raise PromptError(msg)
        system = self._env.from_string(spec.system).render().strip()
        user = self._env.from_string(spec.user).render(**values).strip()
        digest = hashlib.sha256(f"{system}\n\x1e\n{user}".encode()).hexdigest()
        return RenderedPrompt(
            name=spec.name,
            version=spec.version,
            sha256=digest,
            task=spec.task,
            system=system,
            user=user,
            output_schema=template.output_model,
            variables=values,
        )
