/**
 * Classification of records against the AI / agent stack.
 *
 * Why a curated taxonomy instead of a text search: the obvious approach is to
 * grep descriptions for "ray", "dify", "agent". That is unusable - "ray"
 * matches array, "dify" matches modify, "agent" matches user agent. Precision
 * comes from matching structured fields first:
 *
 *   packages  GitHub advisories carry real package names ("vllm", "mlflow",
 *             "@modelcontextprotocol/sdk"). Exact matches, so no false hits.
 *   vendors   KEV and EUVD carry a vendor ("Ray-Project", "BerriAI").
 *   prose     Last resort for NVD-only records, which have neither. Every
 *             pattern here is word-bounded, and ambiguous names must appear
 *             with a qualifier - "ray serve", never a bare "ray".
 */

export const STACK_CATEGORIES = [
  { id: 'inference', name: 'Inference & serving', blurb: 'Model servers, runtimes and LLM gateways' },
  { id: 'agents', name: 'Agent frameworks', blurb: 'Orchestration, tool-calling and workflow builders' },
  { id: 'mcp', name: 'MCP & tool servers', blurb: 'Model Context Protocol SDKs, servers and transports' },
  { id: 'retrieval', name: 'Vector & retrieval', blurb: 'Vector databases and retrieval pipelines' },
  { id: 'mlops', name: 'Training & MLOps', blurb: 'Experiment tracking, pipelines and compute clusters' },
  { id: 'runtime', name: 'Runtimes & formats', blurb: 'Tensor libraries, model formats and loaders' },
  { id: 'apps', name: 'Apps & interfaces', blurb: 'Chat UIs, notebooks and app frameworks' },
];

export const STACK_CATEGORY_IDS = STACK_CATEGORIES.map((c) => c.id);

const categoryNames = new Map(STACK_CATEGORIES.map((c) => [c.id, c.name]));

/**
 * One entry per project worth tracking. `packages` and `vendors` are compared
 * as whole strings; `prose` is only consulted when neither is present on the
 * record.
 */
const SUBJECTS = [
  // --- Inference, serving and gateways ---
  { name: 'vLLM', category: 'inference', packages: ['vllm'], prose: /\bvllm\b/i },
  { name: 'Ollama', category: 'inference', packages: ['ollama'], prose: /\bollama\b/i },
  { name: 'llama.cpp', category: 'inference', packages: ['llama-cpp-python'], prose: /\bllama[.\- ]?cpp\b/i },
  { name: 'LiteLLM', category: 'inference', packages: ['litellm'], vendors: ['berriai'], prose: /\blitellm\b/i },
  { name: 'Text Generation Inference', short: 'TGI', category: 'inference', packages: ['text-generation-inference'], prose: /\btext[- ]generation[- ]inference\b/i },
  { name: 'Triton Inference Server', short: 'Triton', category: 'inference', prose: /\btriton inference server\b/i },
  { name: 'TorchServe', category: 'inference', packages: ['torchserve'], prose: /\btorchserve\b/i },
  { name: 'SGLang', category: 'inference', packages: ['sglang'], prose: /\bsglang\b/i },
  { name: 'LocalAI', category: 'inference', prose: /\blocalai\b/i },
  { name: 'Xinference', category: 'inference', packages: ['xinference'], prose: /\bxinference\b/i },
  { name: 'BentoML', category: 'inference', packages: ['bentoml'], prose: /\bbentoml\b/i },
  { name: 'KServe', category: 'inference', packages: ['kserve'], prose: /\bkserve\b/i },

  // --- Agent and orchestration frameworks ---
  { name: 'LangChain', category: 'agents', packages: ['langchain', 'langchain-core', 'langchain-community', 'langchain-experimental', 'langchainjs'], prose: /\blangchain\b/i },
  { name: 'LlamaIndex', category: 'agents', packages: ['llama-index', 'llamaindex'], prose: /\bllama[- ]?index\b/i },
  { name: 'CrewAI', category: 'agents', packages: ['crewai'], prose: /\bcrewai\b/i },
  { name: 'AutoGen', category: 'agents', packages: ['autogen', 'pyautogen', 'autogen-agentchat'], prose: /\bautogen\b/i },
  { name: 'Agno', category: 'agents', packages: ['agno'], prose: /\bagno\b/i },
  { name: 'Langflow', category: 'agents', packages: ['langflow'], prose: /\blangflow\b/i },
  { name: 'Flowise', category: 'agents', packages: ['flowise', 'flowise-ui'], prose: /\bflowise\b/i },
  { name: 'Dify', category: 'agents', packages: ['dify'], prose: /\bdify\b/i },
  { name: 'Haystack', category: 'agents', packages: ['haystack-ai', 'farm-haystack'], prose: /\bhaystack\b/i },
  { name: 'Semantic Kernel', category: 'agents', packages: ['semantic-kernel'], prose: /\bsemantic kernel\b/i },
  { name: 'DSPy', category: 'agents', packages: ['dspy', 'dspy-ai'], prose: /\bdspy\b/i },
  { name: 'PydanticAI', category: 'agents', packages: ['pydantic-ai', 'pydantic-ai-slim'], prose: /\bpydantic[- ]ai\b/i },
  { name: 'AutoGPT', category: 'agents', prose: /\bauto-?gpt\b/i },
  { name: 'MetaGPT', category: 'agents', packages: ['metagpt'], prose: /\bmetagpt\b/i },
  { name: 'n8n', category: 'agents', packages: ['n8n'], prose: /\bn8n\b/i },
  { name: 'OpenAI Agents SDK', category: 'agents', packages: ['openai-agents'], prose: /\bopenai agents sdk\b/i },
  { name: 'Strands Agents', category: 'agents', packages: ['strands-agents', 'strands-agents-tools'], prose: /\bstrands agents\b/i },

  // --- MCP: SDKs, servers and transports ---
  {
    name: 'Model Context Protocol',
    short: 'MCP',
    category: 'mcp',
    packages: ['mcp', 'fastmcp', 'fastmcp-slim', 'mcp-sanitizer'],
    // Covers the official SDK scope and the long tail of community servers,
    // which is where most of these advisories actually land.
    packagePatterns: [/^@modelcontextprotocol\//i, /(^|[/@\-])mcp[-_]/i, /[-_]mcp(-server)?$/i, /mcp[-_]server/i],
    prose: /\bmodel context protocol\b|\bmcp (server|client|transport|tool|host)s?\b/i,
  },

  // --- Vector stores and retrieval ---
  { name: 'Chroma', category: 'retrieval', packages: ['chromadb', 'chroma-core'], prose: /\bchromadb\b/i },
  { name: 'Qdrant', category: 'retrieval', packages: ['qdrant-client'], prose: /\bqdrant\b/i },
  { name: 'Weaviate', category: 'retrieval', packages: ['weaviate-client'], prose: /\bweaviate\b/i },
  { name: 'Milvus', category: 'retrieval', packages: ['pymilvus'], prose: /\bmilvus\b/i },
  { name: 'pgvector', category: 'retrieval', packages: ['pgvector'], prose: /\bpgvector\b/i },
  { name: 'FAISS', category: 'retrieval', packages: ['faiss', 'faiss-cpu', 'faiss-gpu'], prose: /\bfaiss\b/i },
  { name: 'LanceDB', category: 'retrieval', packages: ['lancedb'], prose: /\blancedb\b/i },
  { name: 'Marqo', category: 'retrieval', packages: ['marqo'], prose: /\bmarqo\b/i },
  { name: 'txtai', category: 'retrieval', packages: ['txtai'], prose: /\btxtai\b/i },
  { name: 'Danswer / Onyx', category: 'retrieval', packages: ['danswer', 'onyx'], prose: /\bdanswer\b/i },

  // --- Training, tracking and MLOps ---
  { name: 'MLflow', category: 'mlops', packages: ['mlflow', 'mlflow-skinny'], prose: /\bmlflow\b/i },
  { name: 'Kubeflow', category: 'mlops', packages: ['kfp', 'kubeflow'], prose: /\bkubeflow\b/i },
  // "ray" alone is hopeless in prose, so it needs a vendor or a qualifier.
  { name: 'Ray', category: 'mlops', packages: ['ray'], vendors: ['ray-project', 'anyscale'], prose: /\bray[- ]project\b|\bray (serve|tune|core|cluster|dashboard|job submission)\b|\banyscale\b/i },
  { name: 'Metaflow', category: 'mlops', packages: ['metaflow'], prose: /\bmetaflow\b/i },
  { name: 'Weights & Biases', category: 'mlops', packages: ['wandb'], prose: /\bweights? (and|&) biases\b|\bwandb\b/i },
  { name: 'ClearML', category: 'mlops', packages: ['clearml'], prose: /\bclearml\b/i },
  { name: 'DVC', category: 'mlops', packages: ['dvc'], prose: /\bdvc\b/i },
  { name: 'Determined', category: 'mlops', packages: ['determined'], prose: /\bdetermined ai\b/i },
  { name: 'Label Studio', category: 'mlops', packages: ['label-studio'], prose: /\blabel studio\b/i },
  { name: 'Hydra', category: 'mlops', packages: ['hydra-core'], prose: /\bhydra-core\b/i },
  { name: 'Amazon SageMaker', category: 'mlops', prose: /\bsagemaker\b/i },
  { name: 'Vertex AI', category: 'mlops', prose: /\bvertex ai\b/i },
  { name: 'Azure Machine Learning', short: 'Azure ML', category: 'mlops', prose: /\bazure machine learning\b/i },

  // --- Model runtimes and formats ---
  { name: 'PyTorch', category: 'runtime', packages: ['torch', 'pytorch', 'torchvision', 'torchaudio'], prose: /\bpytorch\b/i },
  { name: 'TensorFlow', category: 'runtime', packages: ['tensorflow', 'tensorflow-cpu', 'tensorflow-gpu'], prose: /\btensorflow\b/i },
  { name: 'Keras', category: 'runtime', packages: ['keras'], prose: /\bkeras\b/i },
  { name: 'ONNX', category: 'runtime', packages: ['onnx', 'onnxruntime', 'onnxruntime-gpu'], prose: /\bonnx\b/i },
  { name: 'JAX', category: 'runtime', packages: ['jax', 'jaxlib'] },
  { name: 'Transformers', category: 'runtime', packages: ['transformers'], prose: /\bhugging ?face transformers\b/i },
  // A bare "hugging face" shows up in unrelated bodies, so name the product.
  { name: 'Hugging Face', category: 'runtime', packages: ['huggingface-hub', 'huggingface_hub', 'datasets'], prose: /\bhugging ?face (hub|datasets)\b/i },
  { name: 'safetensors', category: 'runtime', packages: ['safetensors'], prose: /\bsafetensors\b/i },
  { name: 'GGUF', category: 'runtime', prose: /\bgguf\b/i },
  { name: 'MONAI', category: 'runtime', packages: ['monai'], prose: /\bmonai\b/i },
  { name: 'joblib', category: 'runtime', packages: ['joblib'], prose: /\bjoblib\b/i },

  // --- Apps and interfaces ---
  { name: 'Open WebUI', category: 'apps', packages: ['open-webui'], prose: /\bopen[- ]webui\b/i },
  { name: 'AnythingLLM', category: 'apps', prose: /\banythingllm\b/i },
  { name: 'LibreChat', category: 'apps', prose: /\blibrechat\b/i },
  { name: 'LobeChat', category: 'apps', prose: /\blobe[- ]?chat\b/i },
  { name: 'NextChat', category: 'apps', prose: /\bnextchat\b/i },
  { name: 'ComfyUI', category: 'apps', prose: /\bcomfyui\b/i },
  { name: 'Stable Diffusion WebUI', short: 'SD WebUI', category: 'apps', prose: /\bstable[- ]diffusion[- ]webui\b|\bautomatic1111\b/i },
  { name: 'text-generation-webui', category: 'apps', prose: /\btext[- ]generation[- ]webui\b/i },
  { name: 'Gradio', category: 'apps', packages: ['gradio'], prose: /\bgradio\b/i },
  { name: 'Streamlit', category: 'apps', packages: ['streamlit'], prose: /\bstreamlit\b/i },
  { name: 'Chainlit', category: 'apps', packages: ['chainlit'], prose: /\bchainlit\b/i },
  { name: 'Jupyter', category: 'apps', packages: ['jupyter', 'jupyterlab', 'notebook', 'jupyter-server', 'jupyter-core'], prose: /\bjupyter\b/i },
];

/** GitHub puts the ecosystem in `vendor`, so it is not a real vendor name. */
const ECOSYSTEMS = new Set(['pip', 'npm', 'go', 'maven', 'rubygems', 'rust', 'composer', 'nuget', 'pub', 'hex', 'swift', 'erlang', 'actions']);

function contextFor(record) {
  const packages = String(record.product ?? '')
    .split(',')
    .map((p) => p.trim().toLowerCase())
    .filter(Boolean);

  const rawVendor = String(record.vendor ?? '').toLowerCase();
  const vendor = rawVendor
    .split(',')
    .map((v) => v.trim())
    .filter((v) => v && !ECOSYSTEMS.has(v));

  return {
    packages,
    vendor,
    title: String(record.title ?? ''),
    body: `${record.title ?? ''} ${record.description ?? ''}`,
    structured: packages.length > 0 || vendor.length > 0,
  };
}

function matches(subject, ctx) {
  if (subject.packages?.some((p) => ctx.packages.includes(p))) return true;
  if (subject.packagePatterns?.some((re) => ctx.packages.some((p) => re.test(p)))) return true;
  if (subject.vendors?.some((v) => ctx.vendor.some((candidate) => candidate.includes(v)))) return true;
  if (!subject.prose) return false;

  // With no package or vendor to go on - an NVD-only record, in practice -
  // prose is all there is, so the whole description is fair game.
  if (!ctx.structured) return subject.prose.test(ctx.body);

  // Otherwise trust the structured fields for the affected component, but
  // still read the title: an advisory often names a second project there, as
  // "MLflow CrewAI autologging leaks API keys" does for a package of mlflow.
  return subject.prose.test(ctx.title);
}

/**
 * Tag a record with the parts of the AI stack it affects.
 * Returns null when it touches none, which is the common case.
 */
export function classifyStack(record) {
  const ctx = contextFor(record);
  const hits = SUBJECTS.filter((subject) => matches(subject, ctx));
  if (hits.length === 0) return null;

  const categories = [...new Set(hits.map((h) => h.category))].sort(
    (a, b) => STACK_CATEGORY_IDS.indexOf(a) - STACK_CATEGORY_IDS.indexOf(b),
  );

  return {
    categories,
    categoryNames: categories.map((id) => categoryNames.get(id)),
    // Full names stay searchable; labels are what the interface shows.
    subjects: [...new Set(hits.map((h) => h.name))].sort(),
    labels: [...new Set(hits.map((h) => h.short ?? h.name))].sort(),
  };
}

/** Everything the dashboard needs to render the facet. */
/**
 * The curated vocabulary, as suggestion candidates.
 *
 * A derived, plain-data view rather than SUBJECTS itself, which carries
 * RegExps and is not safe to hand to JSON. This is the layer that makes the
 * typeahead work with the database down: a few hundred strings already in the
 * process, no query, no cache.
 */
export const subjectSuggestions = () =>
  SUBJECTS.map(({ name, short, category, packages, vendors }) => ({
    value: name,
    short: short ?? null,
    category,
    packages: packages ?? [],
    vendors: vendors ?? [],
  }));

export const stackFacets = () => STACK_CATEGORIES.map(({ id, name, blurb }) => ({ id, name, blurb }));
