# SecuraIQ air-gap lab

Use this for an **owned / isolated** cluster or VM. It is a scaffold, not a certified air-gap product.

Low-storage cloud stack (AI in Docker, no host HuggingFace): [CLOUD-DOCKER.md](./CLOUD-DOCKER.md).

1. Build images on a connected host (`docker build -f Dockerfile.slim` / package scripts).
2. Export: `docker save securaiq:lab -o securaiq-lab.tar`
3. Transfer the tarball + `deploy/helm/securaiq` on removable media.
4. Import: `docker load -i securaiq-lab.tar` (or `ctr images import`).
5. Install: `helm install securaiq deploy/helm/securaiq`

Do **not** claim multi-AZ HA, commercial Helm support, or Apple notarize from this chart.
