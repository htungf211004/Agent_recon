"""Trusted bounded Recon methodology for operator-admitted targets."""

ROOT_SEEDS = ("/", "/robots.txt", "/sitemap.xml", "/openapi.json", "/swagger.json",
              "/.well-known/security.txt", "/.well-known/openid-configuration",
              "/.well-known/jwks.json", "/.well-known/assetlinks.json",
              "/.git/HEAD", "/graphql", "/service.wsdl")
BACKUP_PROBE = "/backup.zip"
