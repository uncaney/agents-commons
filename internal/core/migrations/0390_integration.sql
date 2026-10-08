-- 0390 integration data (SPEC-v2 1, 13.4): wave-6 wiring carries no new schema. The only data this
-- migration asserts is a refresh of the seeded top library aliases (lib_alias), so a fresh deploy
-- resolves the most common bare names before any agent confirms one. These complement the embedded
-- seedAliasList that know.Register inserts at boot; both paths are idempotent (ON CONFLICT) and both
-- mark the rows seeded=true, which ResolveLib trusts without an L2 confirmation. No row here is ever
-- user-supplied: every value is a curated eco:name pair. Non-seeded, agent-confirmed aliases and
-- their confirm counts are never touched.
--
-- Keys are `eco:name` with name already in the canonical form ParseKey produces (lowercase for npm,
-- crates, go, gem, docker; pypi uses '-' separators; maven/nuget keep case but none here need it).

INSERT INTO lib_alias (alias, key, seeded) VALUES
  -- JavaScript / npm
  ('react', 'npm:react', true),
  ('react-dom', 'npm:react-dom', true),
  ('next', 'npm:next', true),
  ('nextjs', 'npm:next', true),
  ('vue', 'npm:vue', true),
  ('nuxt', 'npm:nuxt', true),
  ('svelte', 'npm:svelte', true),
  ('sveltekit', 'npm:@sveltejs/kit', true),
  ('angular', 'npm:@angular/core', true),
  ('express', 'npm:express', true),
  ('fastify', 'npm:fastify', true),
  ('vite', 'npm:vite', true),
  ('webpack', 'npm:webpack', true),
  ('typescript', 'npm:typescript', true),
  ('eslint', 'npm:eslint', true),
  ('axios', 'npm:axios', true),
  ('lodash', 'npm:lodash', true),
  ('zod', 'npm:zod', true),
  ('tailwindcss', 'npm:tailwindcss', true),
  ('prisma', 'npm:prisma', true),
  -- Python / pypi
  ('requests', 'pypi:requests', true),
  ('numpy', 'pypi:numpy', true),
  ('pandas', 'pypi:pandas', true),
  ('flask', 'pypi:flask', true),
  ('django', 'pypi:django', true),
  ('fastapi', 'pypi:fastapi', true),
  ('pydantic', 'pypi:pydantic', true),
  ('sqlalchemy', 'pypi:sqlalchemy', true),
  ('pytest', 'pypi:pytest', true),
  ('scikit-learn', 'pypi:scikit-learn', true),
  ('sklearn', 'pypi:scikit-learn', true),
  ('torch', 'pypi:torch', true),
  ('pytorch', 'pypi:torch', true),
  ('transformers', 'pypi:transformers', true),
  ('httpx', 'pypi:httpx', true),
  -- Go
  ('pgx', 'go:github.com/jackc/pgx/v5', true),
  ('gin', 'go:github.com/gin-gonic/gin', true),
  ('echo', 'go:github.com/labstack/echo', true),
  ('cobra', 'go:github.com/spf13/cobra', true),
  ('testify', 'go:github.com/stretchr/testify', true),
  ('wazero', 'go:github.com/tetratelabs/wazero', true),
  -- Rust / crates
  ('tokio', 'crates:tokio', true),
  ('serde', 'crates:serde', true),
  ('clap', 'crates:clap', true),
  ('axum', 'crates:axum', true),
  ('reqwest', 'crates:reqwest', true),
  -- Ruby / gem
  ('rails', 'gem:rails', true),
  ('sinatra', 'gem:sinatra', true),
  -- Java / maven
  ('spring-boot', 'maven:org.springframework.boot/spring-boot', true),
  ('junit', 'maven:junit/junit', true),
  -- Containers / docker
  ('postgres', 'docker:postgres', true),
  ('redis', 'docker:redis', true),
  ('nginx', 'docker:nginx', true),
  ('node', 'docker:node', true),
  ('alpine', 'docker:alpine', true)
ON CONFLICT (alias) DO UPDATE
  SET key = EXCLUDED.key, seeded = true
  WHERE lib_alias.seeded;
