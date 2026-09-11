# Fixture for static analysis. Do not execute these recipes.
dev: services
	pnpm dev

services:
	docker compose up -d

api:
	python -m atlas_api

clean:
	rm -rf .cache
