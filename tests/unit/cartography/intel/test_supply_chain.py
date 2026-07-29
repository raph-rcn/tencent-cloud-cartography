from cartography.intel.supply_chain import extract_container_parent_image
from cartography.intel.supply_chain import extract_image_source_provenance
from cartography.intel.supply_chain import extract_workflow_path_from_ref
from cartography.intel.supply_chain import get_slsa_dependency_list
from cartography.intel.supply_chain import normalize_vcs_url


def test_get_slsa_dependency_list_supports_v02_and_v1() -> None:
    v02 = {"materials": [{"uri": "oci://example/base"}]}
    v1 = {"buildDefinition": {"resolvedDependencies": [{"uri": "oci://example/base"}]}}

    assert get_slsa_dependency_list(v02) == [{"uri": "oci://example/base"}]
    assert get_slsa_dependency_list(v1) == [{"uri": "oci://example/base"}]


def test_extract_container_parent_image_skips_dockerfile_frontend() -> None:
    predicate = {
        "buildDefinition": {
            "resolvedDependencies": [
                {
                    "uri": "pkg:docker/docker/dockerfile@1.9",
                    "digest": {"sha256": "ignored"},
                },
                {
                    "uri": "pkg:oci/public.ecr.aws/docker/library/python@3.12",
                    "digest": {"sha256": "a" * 64},
                },
            ],
        },
    }

    assert extract_container_parent_image(predicate) == {
        "parent_image_uri": "pkg:oci/public.ecr.aws/docker/library/python@3.12",
        "parent_image_digest": f"sha256:{'a' * 64}",
    }


def test_extract_image_source_provenance_supports_buildkit() -> None:
    predicate = {
        "metadata": {
            "https://mobyproject.org/buildkit@v1#metadata": {
                "vcs": {
                    "source": "git@github.com:example/aws-service.git",
                    "revision": "deadbeef",
                    "localdir:dockerfile": "container",
                },
            },
        },
        "buildDefinition": {
            "externalParameters": {"configSource": {"path": "Dockerfile"}},
        },
    }

    assert extract_image_source_provenance(predicate) == {
        "source_uri": "https://github.com/example/aws-service",
        "source_revision": "deadbeef",
        "source_file": "container/Dockerfile",
    }


def test_normalize_vcs_url_and_workflow_ref() -> None:
    assert (
        normalize_vcs_url("git@github.com:example/aws-service.git")
        == "https://github.com/example/aws-service"
    )
    assert (
        extract_workflow_path_from_ref(
            "example/aws-service/.github/workflows/publish.yml@refs/heads/main",
        )
        == ".github/workflows/publish.yml"
    )
