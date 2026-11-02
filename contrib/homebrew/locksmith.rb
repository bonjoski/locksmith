# typed: false
# frozen_string_literal: true

class Locksmith < Formula
  desc "Secure keychain-backed secrets manager with biometric authentication"
  homepage "https://github.com/bonjoski/locksmith"
  version "3.2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/bonjoski/locksmith/releases/download/v3.2.0/locksmith-darwin-arm64"
      sha256 "e3d0f29eddcfe7845b066259b4d33e6385437cb11cb21399c8f895e6816223ab"

      resource "summon-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.0/summon-locksmith-darwin-arm64"
        sha256 "b866accca8db6b8f7f2b754544419a3cd3e60aa8e04a01cf3d0b93cb7dce10c3"
      end

      resource "git-credential-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.0/git-credential-locksmith-darwin-arm64"
        sha256 "afe5761308a23c0b2aaa527af905432d76eabc2c52f135567dc9262f4f12788a"
      end

      resource "cockpit-arm64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.0/locksmith-cockpit-darwin-arm64"
        sha256 "61e5202d25f30cc490d2fcbaeee792bb8180c4223ce32aa9db26d7cb30680d39"
      end

      def install
        bin.install "locksmith-darwin-arm64" => "locksmith"
        resource("summon-arm64").stage do
          bin.install "summon-locksmith-darwin-arm64" => "summon-locksmith"
        end
        resource("git-credential-arm64").stage do
          bin.install "git-credential-locksmith-darwin-arm64" => "git-credential-locksmith"
        end
        resource("cockpit-arm64").stage do
          bin.install "locksmith-cockpit-darwin-arm64" => "locksmith-cockpit"
        end
      end
    else
      url "https://github.com/bonjoski/locksmith/releases/download/v3.2.0/locksmith-darwin-amd64"
      sha256 "6dadede767b195633f1be550da3e95fe4931e0e2e8983b7ecf3fac289ca6a954"

      resource "summon-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.0/summon-locksmith-darwin-amd64"
        sha256 "04c8f30fee6651aacf0b16065d2de07edc69671e786e2545fa660e52277b5f73"
      end

      resource "git-credential-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.0/git-credential-locksmith-darwin-amd64"
        sha256 "222cc2187840b7d9949d4731c2204345abbf2bc3a48de4e2e36da5e6627ccedd"
      end

      resource "cockpit-amd64" do
        url "https://github.com/bonjoski/locksmith/releases/download/v3.2.0/locksmith-cockpit-darwin-amd64"
        sha256 "3a0351db2ab4b52e1c681156f4944375a1a4afa2f310595e0381c7fb8317ae0c"
      end

      def install
        bin.install "locksmith-darwin-amd64" => "locksmith"
        resource("summon-amd64").stage do
          bin.install "summon-locksmith-darwin-amd64" => "summon-locksmith"
        end
        resource("git-credential-amd64").stage do
          bin.install "git-credential-locksmith-darwin-amd64" => "git-credential-locksmith"
        end
        resource("cockpit-amd64").stage do
          bin.install "locksmith-cockpit-darwin-amd64" => "locksmith-cockpit"
        end
      end
    end
  end

  on_linux do
    url "https://github.com/bonjoski/locksmith/archive/refs/tags/v2.9.0.tar.gz"
    sha256 "164a576940ee1e3d8fb33e3737a55116cd6c8b6aa096c1acd9bd6400841e157e"

    depends_on "go" => :build

    def install
      system "go", "build", *std_go_args(ldflags: "-s -w"), "./cmd/locksmith"
    end
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/locksmith --version 2>&1")
    assert_predicate bin/"locksmith-cockpit", :exist?
  end
end
