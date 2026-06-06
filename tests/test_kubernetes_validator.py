from secscan.validators.kubernetes_validator import KubernetesValidator


def test_kubernetes_detects_privileged_container(tmp_path):
    manifest = tmp_path / "deployment.yml"

    manifest.write_text("""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: insecure-nginx
  template:
    metadata:
      labels:
        app: insecure-nginx
    spec:
      containers:
        - name: nginx
          image: nginx:latest
          securityContext:
            privileged: true
""")

    validator = KubernetesValidator()
    results = validator.validate(str(manifest))

    assert any(
        item.get("check") == "Privileged Container"
        for item in results["issues"]
    )
