#!/bin/sh
# InstantMesh クライアント インストーラ（Linux 専用）
#
# 使い方（ワンライナー）:
#   curl -fsSL https://raw.githubusercontent.com/instantmesh/instantmesh/main/install.sh | sh
#
# まず中身を確認したい場合（推奨）:
#   curl -fsSLO https://raw.githubusercontent.com/instantmesh/instantmesh/main/install.sh
#   less install.sh && sh install.sh
#
# 環境変数で挙動を上書きできます:
#   INSTANTMESH_VERSION  … 取得するリリースタグ（既定: latest）。例: v0.2.13
#   INSTANTMESH_BIN_DIR  … インストール先ディレクトリ（既定: /usr/local/bin）
#
# GitHub リリースの安定資産名 instant-mesh-client-linux-<amd64|arm64> を、
# releases/latest/download の固定 URL から取得して配置します（サーバーは対象外）。

set -eu

REPO="instantmesh/instantmesh"
BIN_NAME="instant-mesh-client"
VERSION="${INSTANTMESH_VERSION:-latest}"
BIN_DIR="${INSTANTMESH_BIN_DIR:-/usr/local/bin}"

info() { printf '\033[32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m警告:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31mエラー:\033[0m %s\n' "$*" >&2; exit 1; }

# 1. OS 判定（このインストーラは Linux 専用）
os="$(uname -s)"
[ "$os" = "Linux" ] || die "このインストーラは Linux 専用です（検出: $os）。Windows/macOS は docs/使い方.md を参照してください。"

# 2. アーキ判定 → GOARCH へマップ
arch="$(uname -m)"
case "$arch" in
	x86_64 | amd64) goarch="amd64" ;;
	aarch64 | arm64) goarch="arm64" ;;
	*) die "未対応のアーキテクチャです: $arch（対応: x86_64/amd64, aarch64/arm64）" ;;
esac

asset="${BIN_NAME}-linux-${goarch}"

# 3. ダウンロード URL（latest は GitHub の最新リリース固定リダイレクトを使う）
if [ "$VERSION" = "latest" ]; then
	url="https://github.com/${REPO}/releases/latest/download/${asset}"
else
	url="https://github.com/${REPO}/releases/download/${VERSION}/${asset}"
fi

# 4. ダウンローダを選択（curl / wget のどちらでも動く）
if command -v curl >/dev/null 2>&1; then
	dl() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
	dl() { wget -qO "$2" "$1"; }
else
	die "curl または wget が必要です。"
fi

# 5. 一時ファイルへ取得（失敗・中断時は必ず後始末）
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT INT TERM
info "ダウンロード中: ${url}"
dl "$url" "$tmp" || die "ダウンロードに失敗しました（バージョン名・ネットワークを確認してください）。"
[ -s "$tmp" ] || die "ダウンロードしたファイルが空です。"
chmod +x "$tmp"

# 6. 配置。既定 /usr/local/bin は root 実行（sudo instant-mesh-client）時の PATH に載るため既定にする。
#    書き込めなければ sudo を試し、それも無ければ ~/.local/bin へフォールバックする。
dest="${BIN_DIR}/${BIN_NAME}"
if mkdir -p "$BIN_DIR" 2>/dev/null && [ -w "$BIN_DIR" ]; then
	mv "$tmp" "$dest"
elif command -v sudo >/dev/null 2>&1; then
	info "${BIN_DIR} への配置に sudo を使用します。"
	sudo mkdir -p "$BIN_DIR"
	sudo mv "$tmp" "$dest"
else
	dest="${HOME}/.local/bin/${BIN_NAME}"
	warn "${BIN_DIR} に書き込めず sudo も無いため ${HOME}/.local/bin へインストールします。"
	warn "この場合 'sudo ${BIN_NAME}' で見つからないことがあります（絶対パス ${dest} で起動してください）。"
	mkdir -p "${HOME}/.local/bin"
	mv "$tmp" "$dest"
fi
# mv 済みなら tmp は消えているので、以降の EXIT trap の rm は無害な no-op。

info "インストール完了: ${dest}"

# 7. PATH に配置先が無ければ追加方法を案内する。
dest_dir="$(dirname "$dest")"
case ":${PATH}:" in
	*":${dest_dir}:"*) : ;;
	*)
		warn "${dest_dir} が PATH にありません。shell 設定に次を追加してください:"
		printf '  export PATH="%s:$PATH"\n' "$dest_dir" >&2
		;;
esac

cat <<EOF

InstantMesh クライアントをインストールしました。

起動方法:
  sudo ${BIN_NAME}                 # 既定 GUI モード（-tunnel が既定 true・仮想NIC のため root が必要）
  ${BIN_NAME} -tunnel=false        # 仮想NIC を張らずシグナリングのみ確認（root 不要）

GUI は Chromium 系ブラウザ（chromium/google-chrome/microsoft-edge 等）があればアプリ内ウィンドウで開き、
無ければ既定ブラウザにフォールバックします。root 実行時の Chromium の挙動など詳細は docs/使い方.md を参照してください。
EOF
