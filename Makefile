IMAGE=	ghcr.io/dnstapir/unbound:latest


all:

container:
	docker buildx bake --no-cache

version:
	docker run $(IMAGE) -V
