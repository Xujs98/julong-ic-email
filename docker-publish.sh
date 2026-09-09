#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${JULONG_IMAGE:-docker.io/qq1371446705/julong-ic-email}"
VERSION=""
PLATFORMS="${JULONG_PLATFORMS:-linux/amd64,linux/arm64}"
BUILDER="${JULONG_BUILDER:-}"
BUILDER_EXPLICIT=0
[[ -n "$BUILDER" ]] && BUILDER_EXPLICIT=1
PUSH=1
LATEST=1
DRY_RUN=0
PLATFORMS_SET=0

usage() {
  cat <<'HELP'
用法：
  ./docker-publish.sh [选项]

默认行为：使用 Docker Buildx 构建 linux/amd64、linux/arm64 镜像，并推送版本标签和 latest 标签。

选项：
  --local                 仅本地构建并加载镜像，不推送仓库
  --push                  构建并推送镜像（默认）
  --image IMAGE           镜像仓库地址，不带标签
  --tag TAG               版本标签，默认读取 internal/app/version.go 的 AppVersion
  --platforms LIST        Buildx 平台列表，默认 linux/amd64,linux/arm64
  --builder NAME          Buildx builder 名称，默认自动使用当前 Docker context 的 builder
  --no-latest             不额外更新 latest 标签
  --dry-run               只打印将执行的 Docker 命令，不连接 Docker daemon
  -h, --help              显示帮助

环境变量：
  JULONG_IMAGE、JULONG_VERSION、JULONG_PLATFORMS、JULONG_BUILDER

示例：
  ./docker-publish.sh
  ./docker-publish.sh --local
  ./docker-publish.sh --tag 2026.09.09.2 --no-latest
  JULONG_IMAGE=registry.example.com/team/julong-ic-email ./docker-publish.sh
HELP
}

die() {
  printf '错误：%s\n' "$*" >&2
  exit 1
}

log() {
  printf '[docker-publish] %s\n' "$*"
}

print_command() {
  printf '执行：'
  printf '%q ' "$@"
  printf '\n'
}

read_version() {
  local version_file="$ROOT_DIR/internal/app/version.go"
  [[ -f "$version_file" ]] || die "找不到 $version_file"
  sed -n 's/^[[:space:]]*AppVersion[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$version_file" | head -n 1
}

normalize_local_platform() {
  case "$1" in
    linux/x86_64) printf 'linux/amd64' ;;
    linux/aarch64) printf 'linux/arm64' ;;
    *) printf '%s' "$1" ;;
  esac
}

while (($# > 0)); do
  case "$1" in
    --local)
      PUSH=0
      ;;
    --push)
      PUSH=1
      ;;
    --image)
      (($# >= 2)) || die '--image 需要参数'
      IMAGE="$2"
      shift
      ;;
    --tag)
      (($# >= 2)) || die '--tag 需要参数'
      VERSION="$2"
      shift
      ;;
    --platforms)
      (($# >= 2)) || die '--platforms 需要参数'
      PLATFORMS="$2"
      PLATFORMS_SET=1
      shift
      ;;
    --builder)
      (($# >= 2)) || die '--builder 需要参数'
      BUILDER="$2"
      BUILDER_EXPLICIT=1
      shift
      ;;
    --no-latest)
      LATEST=0
      ;;
    --dry-run)
      DRY_RUN=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "未知参数：$1"
      ;;
  esac
  shift
done

if [[ -z "$VERSION" ]]; then
  VERSION="${JULONG_VERSION:-$(read_version)}"
fi

[[ "$IMAGE" != */ ]] || die '镜像仓库地址不能以 / 结尾'
[[ "$IMAGE" != *@* ]] || die '镜像仓库地址不能包含 digest，请使用仓库名并通过 --tag 指定标签'
last_image_component="${IMAGE##*/}"
[[ "$last_image_component" != *:* ]] || die '镜像仓库地址不要带已有标签，例如使用 registry/team/app 而不是 registry/team/app:latest'
[[ "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die "无效镜像标签：$VERSION"
[[ -n "$PLATFORMS" ]] || die '平台列表不能为空'
if ((DRY_RUN == 0)); then
  command -v docker >/dev/null 2>&1 || die '未找到 docker 命令'
  docker info >/dev/null 2>&1 || die 'Docker daemon 不可用，请先启动 Docker'
fi

if [[ -z "$BUILDER" ]]; then
  if ((DRY_RUN == 1)); then
    BUILDER='default'
  else
    docker_context="$(docker context show 2>/dev/null || true)"
    case "$docker_context" in
      desktop-linux|default)
        if docker buildx inspect "$docker_context" >/dev/null 2>&1; then
          BUILDER="$docker_context"
        fi
        ;;
    esac
    if [[ -z "$BUILDER" ]]; then
      BUILDER="$(docker buildx ls 2>/dev/null | sed -n 's/^\([^[:space:]]*\)\*[[:space:]].*/\1/p' | head -n 1)"
    fi
    [[ -n "$BUILDER" ]] || BUILDER='julong-publisher'
  fi
fi
[[ -n "$BUILDER" ]] || die 'builder 名称不能为空'

if ((PUSH == 0 && PLATFORMS_SET == 0)); then
  if ((DRY_RUN == 0)); then
    detected_platform="$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}' 2>/dev/null || true)"
    PLATFORMS="$(normalize_local_platform "${detected_platform:-linux/amd64}")"
  else
    PLATFORMS='linux/amd64'
  fi
fi

if ((PUSH == 0)) && [[ "$PLATFORMS" == *,* ]]; then
  die '--local 只能加载单个平台，请使用 --platforms linux/amd64 或 linux/arm64'
fi

VERSION_TAG="$IMAGE:$VERSION"
LATEST_TAG="$IMAGE:latest"
GIT_COMMIT="$(git -C "$ROOT_DIR" rev-parse --short=12 HEAD 2>/dev/null || printf 'unknown')"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

build_command=(
  docker buildx build
  --builder "$BUILDER"
  --platform "$PLATFORMS"
  --build-arg "APP_VERSION=$VERSION"
  --build-arg "APP_COMMIT=$GIT_COMMIT"
  --build-arg "APP_BUILT_AT=$BUILD_TIME"
  --label "org.opencontainers.image.source=https://github.com/Xujs98/julong-ic-email"
  --label "org.opencontainers.image.version=$VERSION"
  --label "org.opencontainers.image.revision=$GIT_COMMIT"
  --label "org.opencontainers.image.created=$BUILD_TIME"
  --tag "$VERSION_TAG"
)
if ((LATEST == 1)); then
  build_command+=(--tag "$LATEST_TAG")
fi
if ((PUSH == 1)); then
  build_command+=(--push)
else
  build_command+=(--load)
fi
build_command+=("$ROOT_DIR")

log "镜像：$VERSION_TAG"
log "平台：$PLATFORMS"
if ((PUSH == 1)); then
  log '模式：构建并推送'
else
  log '模式：本地构建并加载'
fi
print_command "${build_command[@]}"

if ((DRY_RUN == 1)); then
  exit 0
fi

if ! docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
  if ((BUILDER_EXPLICIT == 1)); then
    log "创建 Buildx builder：$BUILDER"
    docker buildx create --name "$BUILDER" --driver docker-container --use >/dev/null
  else
    die "找不到当前 Docker context 的 Buildx builder：$BUILDER，请使用 --builder 指定已有 builder"
  fi
fi
docker buildx inspect "$BUILDER" --bootstrap >/dev/null

log '开始构建 Docker 镜像'
"${build_command[@]}"
log 'Docker 镜像发布完成'
if ((PUSH == 1)); then
  log "已推送：$VERSION_TAG"
  if ((LATEST == 1)); then
    log "已推送：$LATEST_TAG"
  fi
else
  log "本地镜像：$VERSION_TAG"
fi
