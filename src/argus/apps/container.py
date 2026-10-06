"""Composition root: builds every long-lived dependency for one process, explicitly.

No module-level singletons, no service locator inside business code - services receive what they
need through their constructors, and tests swap pieces (clock, mailer, hasher, limiter, Redis,
research stages) by passing them to :func:`build_container`.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final, Literal

from redis.asyncio import Redis

from argus.core.circuit_breaker import BreakerRegistry
from argus.core.clock import Clock, SystemClock
from argus.core.config import EgressSettings, LLMSettings, Settings
from argus.core.logging import get_logger
from argus.infrastructure.db import Database
from argus.infrastructure.email import Mailer, create_mailer
from argus.infrastructure.idempotency import Idempotency
from argus.infrastructure.malware import MalwareScanner, create_scanner
from argus.infrastructure.observability.metrics import Metrics
from argus.infrastructure.observability.tracing import instrument_database
from argus.infrastructure.queue import JobQueue, TaskRegistry
from argus.infrastructure.redis import RedisKeys, create_redis
from argus.infrastructure.storage import ObjectStore, create_object_store
from argus.modules.agents.catalogue import TOOLS
from argus.modules.agents.killswitch import KillSwitchService
from argus.modules.agents.runtime import AgentRuntime
from argus.modules.audit.service import AuditService
from argus.modules.documents.service import DocumentDependencies, DocumentService
from argus.modules.documents.tasks import document_tasks
from argus.modules.identity.service import AuthDependencies, AuthService
from argus.modules.identity.session_cache import SessionCache
from argus.modules.knowledge.answer import AnswerDependencies, AnswerService, extractive_answer
from argus.modules.knowledge.indexing import KnowledgeIndexer
from argus.modules.knowledge.retrieval import Reranker, Retriever, VoyageReranker
from argus.modules.knowledge.service import KnowledgeService
from argus.modules.llm.deployments import PromptService
from argus.modules.llm.embeddings import Embedder, create_embedder
from argus.modules.llm.gateway import GatewayDependencies, LLMGateway
from argus.modules.llm.ledger import Ledger
from argus.modules.llm.prompts import PromptRegistry
from argus.modules.llm.providers import LocalProvider, Provider
from argus.modules.llm.routing import RoutingTable, default_routing, load_routing
from argus.modules.llm.voyage import VoyageClient, hardened_client
from argus.modules.monitoring.assess import MONITOR_ASSESSOR, local_assessor
from argus.modules.monitoring.service import MonitorDependencies, MonitorService
from argus.modules.monitoring.tasks import monitoring_tasks
from argus.modules.notifications.service import NotificationDependencies, NotificationService
from argus.modules.platform.dashboard import DashboardService
from argus.modules.platform.exports import ExportDependencies, ExportService
from argus.modules.platform.lifecycle import OrganizationLifecycle
from argus.modules.platform.retention import Retention
from argus.modules.platform.tasks import platform_tasks
from argus.modules.research.analysis import ANALYST, local_analyst
from argus.modules.research.contradictions import CONTRADICTION_JUDGE, local_contradiction_judge
from argus.modules.research.pipeline import ResearchPipeline, Stage
from argus.modules.research.planning import PLANNER, local_plan
from argus.modules.research.reporting import CRITIC, REPORTER, local_critic, local_report
from argus.modules.research.results import ResultsService
from argus.modules.research.service import ResearchDependencies, ResearchService
from argus.modules.research.stages import research_stages
from argus.modules.research.tasks import research_tasks
from argus.modules.research.verification import VERIFIER, local_verifier
from argus.modules.security_center.integrity import AuditIntegrity, IntegrityDependencies
from argus.modules.security_center.service import SecurityCenterService, SecurityDependencies
from argus.modules.sources.reputation import default_reputation_model
from argus.modules.sources.robots import Politeness, RobotsCache
from argus.modules.sources.search import SearchProvider, create_search_provider
from argus.modules.sources.service import SourceDependencies, SourceService
from argus.modules.sources.tasks import source_tasks
from argus.modules.tenancy.api_keys import ApiKeyDependencies, ApiKeyService
from argus.modules.tenancy.authorization import Authorizer
from argus.modules.tenancy.projects import ProjectService
from argus.modules.tenancy.service import OrganizationService, TenancyDependencies
from argus.security.fetcher import FetchPolicy, SafeFetcher
from argus.security.keys import KeyMaterial, load_key_material
from argus.security.parsing import ParseLimits, SandboxedParser
from argus.security.passwords import PasswordHasher
from argus.security.ratelimit import MemoryRateLimiter, RateLimiter, RedisRateLimiter
from argus.security.sealed import SealedStore
from argus.security.tokens import TokenService

ProcessRole = Literal["api", "worker", "scheduler", "cli"]
AGENTS: Final = (
    PLANNER,
    ANALYST,
    VERIFIER,
    CONTRADICTION_JUDGE,
    REPORTER,
    CRITIC,
    MONITOR_ASSESSOR,
)
PROVIDER_NAMES: Final = frozenset({"anthropic", "openai", "local"})
StageFactory = Callable[["Container"], Sequence[Stage]]
log = get_logger(__name__)


@dataclass
class Container:
    settings: Settings
    role: ProcessRole
    clock: Clock
    metrics: Metrics
    database: Database
    redis: Redis | None
    redis_keys: RedisKeys
    keys: KeyMaterial
    mailer: Mailer
    limiter: RateLimiter
    hasher: PasswordHasher
    tokens: TokenService
    audit: AuditService
    sessions: SessionCache
    auth: AuthService
    authorizer: Authorizer
    organizations: OrganizationService
    projects: ProjectService
    api_keys: ApiKeyService
    queue: JobQueue
    idempotency: Idempotency
    research: ResearchService
    fetcher: SafeFetcher
    search: SearchProvider
    sources: SourceService
    storage: ObjectStore
    scanner: MalwareScanner
    parser: SandboxedParser
    documents: DocumentService
    embedder: Embedder
    indexer: KnowledgeIndexer
    knowledge: KnowledgeService
    gateway: LLMGateway
    prompts: PromptService
    answers: AnswerService
    kill_switches: KillSwitchService
    agents: AgentRuntime
    results: ResultsService
    notifications: NotificationService
    monitors: MonitorService
    integrity: AuditIntegrity
    security: SecurityCenterService
    exports: ExportService
    dashboard: DashboardService
    retention: Retention
    lifecycle: OrganizationLifecycle
    llm_providers: Mapping[str, Provider] = field(default_factory=dict)
    tasks: TaskRegistry = field(default_factory=TaskRegistry)
    research_pipeline: ResearchPipeline | None = None
    _closed: bool = field(default=False, repr=False)

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self.fetcher.aclose()
        await self.search.aclose()
        await self.storage.aclose()
        await self.embedder.aclose()
        for provider in self.llm_providers.values():
            await provider.aclose()
        reranker_client = getattr(self.knowledge.retriever, "reranker_client", None)
        if reranker_client is not None:
            await reranker_client.aclose()
        if self.redis is not None:
            await self.redis.aclose()
        await self.database.dispose()


def build_container(
    settings: Settings,
    *,
    role: ProcessRole,
    clock: Clock | None = None,
    database: Database | None = None,
    redis: Redis | None = None,
    mailer: Mailer | None = None,
    hasher: PasswordHasher | None = None,
    limiter: RateLimiter | None = None,
    stages: StageFactory | None = None,
    fetcher: SafeFetcher | None = None,
    search: SearchProvider | None = None,
    storage: ObjectStore | None = None,
    scanner: MalwareScanner | None = None,
    parser: SandboxedParser | None = None,
    embedder: Embedder | None = None,
    llm_providers: Mapping[str, Provider] | None = None,
    routing: RoutingTable | None = None,
) -> Container:
    if (
        settings.security.allow_plaintext_internal_traffic
        and settings.environment.is_production_like
    ):
        log.warning(
            "config.plaintext_internal_traffic_accepted",
            detail="database/redis traffic is not encrypted by configuration choice",
        )
    clock = clock or SystemClock()
    metrics = Metrics()
    database = database or Database(settings.database, application_name=f"argus-{role}")
    instrument_database(database.engine, metrics)
    metrics.db_pool.watch(
        database.engine.pool,
        capacity=settings.database.pool_size + settings.database.max_overflow,
    )
    redis_client = redis if redis is not None else create_redis(settings.redis)
    redis_keys = RedisKeys(settings.redis.key_prefix, settings.environment)
    keys = load_key_material(settings)
    mailer = mailer or create_mailer(settings.email)
    hasher = hasher or PasswordHasher()
    if limiter is None:
        limiter = (
            RedisRateLimiter(redis_client, redis_keys, metrics=metrics)
            if redis_client is not None
            else MemoryRateLimiter(metrics=metrics)
        )
    tokens = TokenService(
        keys.jwt,
        issuer=settings.auth.issuer,
        audience=settings.auth.audience,
        ttl_s=settings.auth.access_token_ttl_s,
        clock=clock,
    )
    audit = AuditService(hmac_key=keys.audit_hmac_key, clock=clock, database=database)
    sessions = SessionCache(redis_client, redis_keys)
    queue = JobQueue(database)
    idempotency = Idempotency()
    egress = settings.egress
    fetcher = fetcher or SafeFetcher(fetch_policy(egress), metrics=metrics)
    docs = settings.documents
    parser = parser or SandboxedParser(
        ParseLimits(
            max_input_bytes=max(settings.http.max_upload_bytes, egress.max_response_bytes),
            max_pdf_pages=docs.max_pdf_pages,
            max_archive_entries=docs.max_archive_entries,
            max_uncompressed_bytes=docs.max_uncompressed_bytes,
            max_compression_ratio=docs.max_compression_ratio,
            max_json_depth=docs.max_json_depth,
            max_csv_field_bytes=docs.max_csv_field_bytes,
            max_csv_rows=docs.max_csv_rows,
            max_text_chars=docs.max_text_chars,
        ),
        timeout_s=docs.parse_timeout_s,
        memory_mb=docs.parse_memory_mb,
    )
    storage = storage or create_object_store(settings.storage)
    scanner = scanner or create_scanner(docs)
    embedder = embedder or create_embedder(settings.embeddings, user_agent=egress.user_agent)
    indexer = KnowledgeIndexer(
        database=database,
        embedder=embedder,
        settings=settings.retrieval,
        clock=clock,
        metrics=metrics,
    )
    reranker: Reranker | None = None
    reranker_client: VoyageClient | None = None
    if settings.retrieval.rerank == "voyage" and settings.embeddings.voyage_api_key is not None:
        reranker_client = VoyageClient(
            settings.embeddings.voyage_api_key.get_secret_value(),
            client=hardened_client(timeout_s=30.0, user_agent=egress.user_agent),
        )
        reranker = VoyageReranker(reranker_client)
    retriever = Retriever(
        database=database,
        embedder=embedder,
        settings=settings.retrieval,
        metrics=metrics,
        keyring=keys.encryption,
        redis=redis_client,
        keys=redis_keys,
        reranker=reranker,
    )
    retriever.reranker_client = reranker_client
    documents = DocumentService(
        DocumentDependencies(
            database=database,
            blobs=SealedStore(storage, keys.encryption),
            scanner=scanner,
            parser=parser,
            queue=queue,
            audit=audit,
            limiter=limiter,
            clock=clock,
            metrics=metrics,
            settings=docs,
            security=settings.security,
            max_upload_bytes=settings.http.max_upload_bytes,
            signing_key=keys.signing_key,
            link_ttl_s=settings.storage.signed_url_ttl_s,
            public_base_url=str(settings.http.public_base_url),
            indexer=indexer,
        )
    )
    sources = SourceService(
        SourceDependencies(
            database=database,
            fetcher=fetcher,
            robots=RobotsCache(
                fetcher, user_agent=egress.user_agent, redis=redis_client, keys=redis_keys
            ),
            politeness=Politeness(limiter, interval_s=egress.per_domain_interval_s),
            reputation=default_reputation_model(),
            queue=queue,
            audit=audit,
            clock=clock,
            egress=egress,
            security=settings.security,
            metrics=metrics,
            limiter=limiter,
            parser=parser,
            indexer=indexer,
        )
    )
    knowledge = KnowledgeService(retriever, settings.retrieval)
    local = LocalProvider()
    local.register("knowledge.answer", extractive_answer)
    local.register("research.plan", local_plan)
    local.register("analysis.findings", local_analyst)
    local.register("verification.entailment", local_verifier)
    local.register("verification.contradictions", local_contradiction_judge)
    local.register("report.compose", local_report)
    local.register("report.critic", local_critic)
    local.register("monitor.assess", local_assessor)
    kill_switches = KillSwitchService(database, clock, audit=audit)
    providers: dict[str, Provider] = {
        "local": local,
        **(dict(llm_providers) if llm_providers is not None else create_providers(settings.llm)),
    }
    routing = routing or (
        load_routing(settings.llm.routing_file) if settings.llm.routing_file else default_routing()
    )
    gateway = LLMGateway(
        GatewayDependencies(
            routing=routing,
            providers=providers,
            local=local,
            ledger=Ledger(database, clock),
            breakers=BreakerRegistry(
                failure_threshold=settings.llm.breaker_failure_threshold,
                reset_timeout_s=settings.llm.breaker_reset_s,
            ),
            settings=settings.llm,
            metrics=metrics,
            clock=clock,
            kill_switches=kill_switches,
        )
    )
    prompts = PromptService(
        PromptRegistry.load(settings.llm.prompts_dir),
        database=database,
        audit=audit,
        environment=settings.environment.value,
        clock=clock,
    )
    search_provider = search or create_search_provider(
        settings.search, user_agent=egress.user_agent
    )
    authorizer = Authorizer(database)
    agents = AgentRuntime(
        gateway=gateway,
        prompts=prompts,
        database=database,
        kill_switches=kill_switches,
        audit=audit,
        clock=clock,
        metrics=metrics,
    )
    notifications = NotificationService(
        NotificationDependencies(
            database=database,
            mailer=mailer,
            clock=clock,
            settings=settings.notifications,
            public_base_url=str(settings.http.public_base_url),
        )
    )
    monitors = MonitorService(
        MonitorDependencies(
            database=database,
            queue=queue,
            sources=sources,
            search=search_provider,
            agents=agents,
            authorizer=authorizer,
            events=notifications,
            audit=audit,
            limiter=limiter,
            clock=clock,
            settings=settings.monitoring,
            allowed_ports=egress.allowed_ports,
        )
    )
    integrity = AuditIntegrity(
        IntegrityDependencies(
            database=database,
            audit=audit,
            events=notifications,
            clock=clock,
            metrics=metrics,
            settings=settings.security,
        )
    )
    security = SecurityCenterService(
        SecurityDependencies(
            database=database,
            audit=audit,
            kill_switches=kill_switches,
            integrity=integrity,
            events=notifications,
            limiter=limiter,
            clock=clock,
            metrics=metrics,
            known_targets={
                "agent": frozenset(spec.name for spec in AGENTS),
                "tool": frozenset(TOOLS),
                "provider": PROVIDER_NAMES,
            },
        )
    )
    exports = ExportService(
        ExportDependencies(
            database=database,
            blobs=SealedStore(storage, keys.encryption),
            queue=queue,
            audit=audit,
            events=notifications,
            limiter=limiter,
            clock=clock,
            settings=settings.platform,
        )
    )
    container = Container(
        settings=settings,
        role=role,
        clock=clock,
        metrics=metrics,
        database=database,
        redis=redis_client,
        redis_keys=redis_keys,
        keys=keys,
        mailer=mailer,
        limiter=limiter,
        hasher=hasher,
        tokens=tokens,
        audit=audit,
        sessions=sessions,
        auth=AuthService(
            AuthDependencies(
                database=database,
                hasher=hasher,
                tokens=tokens,
                encryption=keys.encryption,
                pepper=keys.api_key_pepper,
                audit=audit,
                mailer=mailer,
                limiter=limiter,
                sessions=sessions,
                clock=clock,
                auth=settings.auth,
                email=settings.email,
            )
        ),
        authorizer=authorizer,
        organizations=OrganizationService(
            TenancyDependencies(
                database=database,
                audit=audit,
                mailer=mailer,
                limiter=limiter,
                clock=clock,
                auth=settings.auth,
                email=settings.email,
                default_plan=settings.platform.default_plan,
            )
        ),
        projects=ProjectService(database=database, audit=audit, clock=clock),
        api_keys=ApiKeyService(
            ApiKeyDependencies(
                database=database,
                audit=audit,
                limiter=limiter,
                clock=clock,
                pepper=keys.api_key_pepper,
            )
        ),
        queue=queue,
        idempotency=idempotency,
        research=ResearchService(
            ResearchDependencies(
                database=database,
                queue=queue,
                audit=audit,
                idempotency=idempotency,
                limiter=limiter,
                clock=clock,
                settings=settings.research,
            )
        ),
        fetcher=fetcher,
        search=search_provider,
        sources=sources,
        storage=storage,
        scanner=scanner,
        parser=parser,
        documents=documents,
        embedder=embedder,
        indexer=indexer,
        knowledge=knowledge,
        gateway=gateway,
        prompts=prompts,
        answers=AnswerService(
            AnswerDependencies(
                knowledge=knowledge, gateway=gateway, prompts=prompts, limiter=limiter
            )
        ),
        llm_providers=providers,
        kill_switches=kill_switches,
        results=ResultsService(database, audit=audit, limiter=limiter, settings=settings.reports),
        agents=agents,
        notifications=notifications,
        monitors=monitors,
        integrity=integrity,
        security=security,
        exports=exports,
        dashboard=DashboardService(database, clock),
        retention=Retention(database, audit, storage, clock, settings.platform),
        lifecycle=OrganizationLifecycle(database, audit, storage, clock, settings.platform),
    )
    for definition in [
        *research_tasks(timeout_s=settings.research.job_timeout_s),
        *source_tasks(),
        *document_tasks(process_timeout_s=int(docs.parse_timeout_s + docs.clamav_timeout_s + 60)),
        *monitoring_tasks(),
        *platform_tasks(),
    ]:
        container.tasks.register(definition)
    container.research_pipeline = ResearchPipeline(
        stages(container) if stages is not None else research_stages(container),
        database=database,
        audit=audit,
        clock=clock,
        events=notifications,
        metrics=metrics,
    )
    return container


def fetch_policy(egress: EgressSettings) -> FetchPolicy:
    return FetchPolicy(
        user_agent=egress.user_agent,
        connect_timeout_s=egress.connect_timeout_s,
        read_timeout_s=egress.read_timeout_s,
        total_timeout_s=egress.total_timeout_s,
        max_redirects=egress.max_redirects,
        max_bytes=egress.max_response_bytes,
        max_decompression_ratio=egress.max_decompression_ratio,
        allowed_ports=egress.allowed_ports,
    )


def create_providers(llm: LLMSettings) -> dict[str, Provider]:
    """Remote providers that have credentials or an endpoint configured."""
    providers: dict[str, Provider] = {}
    if llm.anthropic_api_key is not None:
        from argus.modules.llm.providers.claude import ClaudeProvider

        providers["anthropic"] = ClaudeProvider(
            llm.anthropic_api_key.get_secret_value(),
            base_url=str(llm.anthropic_base_url) if llm.anthropic_base_url else None,
            timeout_s=llm.request_timeout_s,
            refusal_fallback=llm.anthropic_refusal_fallback,
        )
    if llm.openai_api_key is not None or llm.openai_base_url is not None:
        from argus.modules.llm.providers.openai_compatible import (
            OpenAICompatibleProvider,
        )

        providers["openai"] = OpenAICompatibleProvider(
            llm.openai_api_key.get_secret_value() if llm.openai_api_key else None,
            base_url=str(llm.openai_base_url) if llm.openai_base_url else None,
            timeout_s=llm.request_timeout_s,
        )
    return providers
